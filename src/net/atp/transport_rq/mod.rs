//! ATP-over-RaptorQ transport (v1): the *fast, robust* ATP data plane.
//!
//! Where [`crate::net::atp::transport_tcp`] moves bytes over a single reliable
//! TCP stream, this transport is built for saturating the pipe on a lossy,
//! high-latency internet path:
//!
//! - **Data plane = RaptorQ fountain symbols over UDP.** Each file entry is
//!   erasure-coded ([`crate::raptorq`], RFC 6330 systematic RaptorQ) into source
//!   plus repair symbols. Symbols are *fungible*: any `K (+ε)` of them recover
//!   the entry, from any socket, in any order. Loss is absorbed by repair
//!   symbols instead of head-of-line-blocking retransmits.
//! - **Multi-socket fan-out.** Symbols are sprayed round-robin across `N` UDP
//!   sockets so a single flow's congestion control / per-socket buffer does not
//!   cap throughput.
//! - **Reliable control plane = one TCP connection** reusing the canonical
//!   `AtpFrameCodec`: handshake (transfer id + receiver UDP port + coding
//!   params), the transfer manifest, fountain *NeedMore* feedback, and the final
//!   verified receipt.
//!
//! # Integrity (fail-closed, identical guarantee to `transport_tcp`)
//!
//! After decode, the receiver (1) checks every entry's SHA-256 against the
//! manifest and (2) rebuilds the deterministic flat
//! [`crate::atp::object::ObjectGraph`] and compares the flat Merkle root to the
//! manifest root. Only if both hold does it atomically write the destination and
//! report `committed = true`. Any mismatch, oversize entry, unreachable peer, or
//! undecodable transfer is a hard error.
//!
//! # Fountain feedback loop
//!
//! v1 uses a bounded request/response loop rather than a continuous concurrent
//! ARQ, which keeps it correct on the current runtime:
//!
//! 1. Sender sprays every entry's source symbols across the UDP sockets, plus
//!    optional initial repair symbols when `repair_overhead > 1.0`, then sends
//!    `ObjectComplete` on TCP.
//! 2. Receiver feeds arriving symbols into a per-entry [`DecodingPipeline`].
//!    On `ObjectComplete` it replies with either a `Proof` receipt (all entries
//!    decoded → verified + committed) or a `NeedMore` list of still-incomplete
//!    entry indices.
//! 3. For each `NeedMore` round the sender generates a *fresh* batch of repair
//!    symbols (higher ESI range — RaptorQ is rateless) for the listed entries
//!    and resprays. Bounded by `max_feedback_rounds`; exhausting them is a hard
//!    error, never a silent partial success.
//!
//! On a low-loss path the initial over-provision means round 0 succeeds; the
//! loop only engages under real loss, which the loopback loss-injection test
//! exercises deterministically.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Adaptive block-size / overhead / fan-out optimizer; see
/// `docs/atp_rq_adaptive_design.md`.
pub mod adaptive;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;

use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::cx::Cx;
use crate::decoding::{
    BlockDecodeJob, BlockDecodeOutcome, DecodingConfig, DecodingPipeline,
    DeferredSymbolAcceptResult, MissingSourceSymbol, SymbolAcceptResult, run_block_decode_job,
};
use crate::encoding::{EncodedSymbol, EncodingPipeline, MAX_SOURCE_BLOCKS, max_object_size};
use crate::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use crate::net::atp::datagram::beacons::{BeaconMeasurement, BeaconScheduler};
use crate::net::atp::datagram::congestion::{CongestionConfig, CongestionController};
use crate::net::atp::loss::detector::{AtpLossDetector, LossRecommendation};
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use crate::net::atp::transport_common::{
    EntryDigest, MultiObjectSplitConfig, StreamingError, flat_merkle_root_from_digests,
    hash_file_streaming, hex_encode, plan_multi_object_split,
};
use crate::net::{TcpListener, TcpStream, UdpBufferConfig, UdpOutboundDatagram, UdpSocket};
use crate::security::authenticated::AuthenticatedSymbol;
use crate::security::tag::TAG_SIZE;
use crate::security::{AuthenticationTag, SecurityContext};
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::symbol::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};
use adaptive::{AdaptiveController, AdaptivePolicy, BlockPlan, PathEstimate, PathSignalSample};

/// Protocol identifier carried in the handshake; bump on wire-incompatible
/// changes.
pub const ATP_RQ_PROTOCOL: u32 = 2;

/// Magic prefix on every UDP symbol datagram (`"ATRQ"`).
const SYMBOL_MAGIC: u32 = 0x4154_5251;

/// Default RaptorQ symbol payload size.
///
/// Kept small enough that one symbol plus the authenticated datagram header and
/// IPv4/UDP framing stays under a 1500-byte Ethernet MTU, while avoiding the
/// packet-rate tax of 1 KiB symbols on 100 Mbit links.
pub const DEFAULT_SYMBOL_SIZE: u16 = 1400;

/// Default source-block ceiling.
///
/// With 1400-byte symbols this bounds a block at ~5992 source symbols (well
/// under the RFC 6330 K=56403 cap) and lets a single entry span up to 256
/// blocks (SBN is a `u8`), i.e. up to ~2 GiB per encoded object at this default
/// block size. Larger logical files are split into ordered RaptorQ objects by
/// [`split_large_entries`] so each object's K stays bounded (E-12).
pub const DEFAULT_MAX_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// Target source-symbol count for the effective transfer block size.
///
/// RaptorQ's matrix work grows sharply with K. A K~512 block is small enough to
/// keep decode/repair work bounded on commodity fleet hosts while still sending
/// large enough UDP bursts to amortize control feedback.
const TARGET_SOURCE_SYMBOLS_PER_BLOCK: usize = 512;
/// Byte ceiling for the normal streaming block-size target.
const TARGET_STREAMING_BLOCK_BYTES: usize = 4 * 1024 * 1024;
/// Maximum encoded ATP-RQ symbols sent in one connected UDP batch per socket.
const RQ_SEND_BATCH_PER_SOCKET: usize = 32;
/// Maximum encoded ATP-RQ symbols queued globally before flushing all sockets.
const RQ_SEND_BATCH_GLOBAL_SYMBOLS: usize = 64;

/// Default round-0 repair multiplier.
///
/// The default keeps the fast source-first shape so trusted/lab RQ receivers can
/// repair sparse source-symbol holes directly before falling back to fountain
/// repair. Adaptive per-round FEC can still raise the sprayed repair overhead
/// without changing this receiver-side source-streaming gate.
pub const DEFAULT_REPAIR_OVERHEAD: f64 = 1.0;

/// Default number of UDP sockets the sender sprays across.
pub const DEFAULT_UDP_FANOUT: usize = 4;

/// Default ceiling on a single transfer's total bytes (receiver buffers + decode
/// matrices live in memory in v1).
pub const DEFAULT_MAX_TRANSFER_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum number of files a single transfer manifest may declare. This bounds
/// receiver bookkeeping derived from attacker-controlled control-plane JSON.
const MAX_MANIFEST_ENTRIES: usize = 4 * 1024 * 1024;

/// E-15 tree coalescing: files strictly smaller than this become candidates for
/// packing into a combined RaptorQ object. Files at or above it stay single-file
/// objects (they already amortize per-object overhead over enough bytes).
const PACK_THRESHOLD: u64 = 256 * 1024;

/// E-15 tree coalescing: target size for a combined RaptorQ object. The packer
/// greedily fills a pack with small files until adding the next would exceed this
/// (a pack always holds at least one file, so a lone file larger than the target
/// but smaller than [`PACK_THRESHOLD`] still forms its own pack). Roughly one
/// RaptorQ object's worth of bytes — large enough to collapse the per-object
/// runtime overhead, small enough that a lost symbol does not span the whole tree.
const PACK_TARGET: u64 = 8 * 1024 * 1024;

/// Default bound on fountain feedback rounds before failing closed.
pub const DEFAULT_MAX_FEEDBACK_ROUNDS: u32 = 16;

/// Default receiver-side quiet drain after each round-complete marker.
pub const DEFAULT_ROUND_TAIL_DRAIN_MS: u64 = 2;

/// Default source-retransmit feedback rounds.
///
/// Bounded sparse retransmit is default-on for the source-first path because
/// entry-level repair feedback otherwise re-sprays every block of a large file
/// when only a few systematic symbols are missing. After these early rounds the
/// transport falls back to fountain repair for bursty or non-sparse loss.
pub const DEFAULT_SOURCE_RETRANSMIT_ROUNDS: u32 = 2;

/// Hard cap on source-symbol retransmit requests in one feedback frame. Larger
/// loss bursts fall back to fountain repair rather than creating huge JSON
/// control messages.
pub const DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS: usize = 8192;

/// Default receiver-side quiet drain after each round-complete marker.
pub const DEFAULT_ROUND_TAIL_DRAIN: Duration = Duration::from_millis(DEFAULT_ROUND_TAIL_DRAIN_MS);

/// Cold-start aggregate sender pace before feedback evidence exists.
///
/// This is deliberately below a typical LAN burst and above the 100 Mbps rsync
/// baseline target. The pacer uses short symbol bursts with sleeps, so the
/// receiver can drain UDP continuously instead of absorbing a full parallel
/// encode burst in the kernel receive buffer.
const RQ_COLD_START_PACING_BPS: u64 = 16 * 1024 * 1024;
const RQ_MIN_PACING_BPS: u64 = 512 * 1024;
const RQ_MAX_PACING_BPS: u64 = 64 * 1024 * 1024;
const RQ_COLD_START_BURST_SYMBOLS: usize = 16;
const RQ_ADAPTIVE_BURST_SYMBOLS: usize = 32;
const RQ_PACING_MIN_PAUSE: Duration = Duration::from_micros(50);
const RQ_PACING_MAX_PAUSE: Duration = Duration::from_millis(250);
const RQ_ADAPTIVE_MIN_SAMPLES: u32 = 1;
const RQ_ASSUMED_DECODE_SYMBOLS_PER_S: f64 = 250_000.0;
const RQ_CODING_GAMMA: f64 = 1.5;
const RQ_LOSS_EMA_ALPHA: f64 = 0.35;
const RQ_BW_EMA_ALPHA: f64 = 0.35;
const RQ_BW_TROUGH_RECOVERY_ALPHA: f64 = 0.10;
const RQ_LOSS_BAR_MULTIPLIER: f64 = 1.75;
const RQ_PENDING_PRESSURE_LOSS_FLOOR: f64 = 0.05;
const RQ_REGIME_SHIFT_LOSS_DELTA: f64 = 0.20;
/// Keep mild-loss repair rounds from turning sparse feedback into a self-reinforcing crawl.
const RQ_MILD_LOSS_PACING_FLOOR_FRACTION: f64 = 0.50;
const RQ_MILD_LOSS_PACING_MAX_LOSS: f64 = 0.03;
const RQ_STALLED_REPAIR_PRESSURE_MIN: f64 = 0.50;
const RQ_STALLED_REPAIR_PAYLOAD_FRACTION_MAX: f64 = 0.50;
const RQ_SOURCE_FEC_FALLBACK_ALPHA: f64 = 1e-6;
const RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD: f64 = 0.50;
const RQ_SOURCE_FEC_FALLBACK_MIN_LOSS_BAR: f64 = 0.01;
const RQ_SOURCE_FEC_FALLBACK_MIN_OVERHEAD: f64 = 0.03;
/// Hard cap on the per-round fractional repair overhead taken from the controller's
/// wire-loss-driven `plan.overhead` (round_tuning). Without this, a round-0 spray that
/// over-paces a slow link self-inflicts high real loss, the wire-loss estimate clamps near
/// 0.9, and plan.overhead explodes (~9.4 ⇒ ~10.7× total), which both crushes the pacing rate
/// (base/(1+overhead)) and sprays ~10× the data. Bounding the fractional overhead at 1.0
/// (≤2× total) covers any realistic wire loss (≤~50%) in one repair round while preventing
/// the pathological blow-up. (MATRIX-12; bead atp-dataplane-redesign-317hxr.2.5.)
const RQ_MAX_ROUND_REPAIR_OVERHEAD: f64 = 1.0;

/// Packets pulled from the UDP socket per receive-pump turn.
///
/// Mirrors the native QUIC inbound pump batch width so RQ drains bursty symbol
/// sprays after one readiness wait instead of waking once per datagram.
const RQ_INBOUND_PUMP_BATCH: usize = 512;
/// Maximum full batches drained after the first ready batch in one pump turn.
const RQ_INBOUND_PUMP_MAX_DRAIN_BATCHES: usize = 64;
/// Hard ceiling on one entry's queued RQ repair-decode jobs.
///
/// A single large file is split into many independent bounded-K source blocks.
/// Let that one entry fan those block decoders across the machine; the receiver
/// pump remains async and the transfer-wide budget below reserves CPU/memory.
const RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY: usize = 48;
/// Hard ceiling on one transfer's queued RQ repair-decode jobs.
const RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD: usize = 48;
/// Minimum CPU cores left for the UDP/control receive pump and filesystem work.
const RQ_DECODE_MIN_CORES_RESERVED_FOR_IO: usize = 1;
/// Upper bound on CPU cores held back from RQ decode on large machines.
const RQ_DECODE_MAX_CORES_RESERVED_FOR_IO: usize = 4;
/// Soft memory envelope for queued RQ repair-decode jobs.
///
/// `BlockDecodeJob` owns a cloned symbol set plus matrix-solve workspace. The
/// width gate estimates that footprint from current block geometry and lowers
/// the effective transfer width before queued decoders can blow past the
/// MATRIX-5 receiver RSS target.
const RQ_DECODE_JOB_MEMORY_BUDGET_BYTES: usize = 96 * 1024 * 1024;
const RQ_DECODE_JOB_MEMORY_FLOOR_BYTES: usize = 1024 * 1024;
const RQ_DECODE_JOB_SYMBOL_MEMORY_MULTIPLIER: usize = 1;
/// RQ repair feedback is round/RTT-bound: do not reject symbols for an
/// undecoded block. Decoded blocks are cleared immediately after commit.
const RQ_REPAIR_RECEIVE_SYMBOL_CAP_PER_BLOCK: usize = usize::MAX;
/// Estimate at least this much extra repair headroom beyond K for one RQ receive block.
///
/// This is now a decode-job memory estimate only. The RQ receiver must not
/// reject repair symbols for an undecoded block, because MATRIX-5 showed that
/// retention bounding adds repair rounds and dominates wall time.
const RQ_REPAIR_SYMBOL_RETENTION_MIN_EXTRA: usize = 256;
/// Tiny quiet window used only after a full batch, matching the native QUIC pump.
const RQ_INBOUND_PUMP_DRAIN_GRACE: Duration = Duration::from_millis(1);

/// Process-unique suffix for RQ receive staging directories.
static RQ_STAGING_SEQ: AtomicU64 = AtomicU64::new(1);
const RQ_STAGING_CREATE_ATTEMPTS: u64 = 1024;

/// UDP datagram header size (magic + transfer tag + entry + sbn + esi + kind +
/// len), big-endian.
const DGRAM_HEADER: usize = 4 + 8 + 4 + 1 + 4 + 1 + 2;

/// UDP datagram header plus the authenticated-symbol tag.
const AUTH_DGRAM_HEADER: usize = DGRAM_HEADER + TAG_SIZE;

/// Opt-in stderr tracing for transport bring-up/diagnosis. Off unless the
/// `ATP_RQ_TRACE` env var is set, so the production path stays silent.
macro_rules! rqtrace {
    ($($arg:tt)*) => {
        if std::env::var_os("ATP_RQ_TRACE").is_some() {
            eprintln!("[atp-rq] {}", format!($($arg)*));
        }
    };
}

/// Transport tuning knobs.
#[derive(Debug, Clone)]
pub struct RqConfig {
    /// RaptorQ symbol payload size in bytes.
    pub symbol_size: u16,
    /// Maximum source-block size in bytes.
    pub max_block_size: usize,
    /// Extra repair fraction sprayed in round 0 (>= 1.0).
    pub repair_overhead: f64,
    /// Number of UDP sockets the sender sprays across.
    pub udp_fanout: usize,
    /// Maximum total bytes a single transfer may carry.
    pub max_transfer_bytes: u64,
    /// Maximum fountain feedback rounds before failing closed.
    pub max_feedback_rounds: u32,
    /// Receiver-side quiet window after each `ObjectComplete` frame.
    ///
    /// TCP can deliver the control-plane round marker before the receiver has
    /// drained all UDP symbols already queued in the kernel. This window lets
    /// the receiver consume that tail before it asks for repair symbols.
    pub round_tail_drain: Duration,
    /// Number of early feedback rounds that may request missing systematic
    /// source symbols instead of repair symbols when `repair_overhead <= 1.0`.
    ///
    /// Defaults to zero for WAN throughput. Positive values are intended for
    /// controlled lab or very low-loss links where sparse source retransmit is
    /// known to converge faster than constructing repair symbols.
    pub source_retransmit_rounds: u32,
    /// Maximum source-symbol retransmit requests in one feedback frame.
    ///
    /// `0` means unbounded, but only after `source_retransmit_rounds` explicitly
    /// opts the transport into source retransmit feedback.
    pub max_source_retransmit_requests: usize,
    /// Test-only: deterministically drop 1-in-N sprayed source symbols on the
    /// sender to exercise the repair/feedback path. 0 disables.
    pub debug_drop_one_in: u32,
    /// Optional per-symbol authentication context for UDP RaptorQ datagrams.
    ///
    /// When present, senders append a tag for each symbol and receivers verify
    /// every symbol before decoding. The TCP control channel and manifest still
    /// need their own authenticated transport to claim full anti-forgery.
    pub symbol_auth_context: Option<SecurityContext>,
    /// Explicit escape hatch for loopback/lab callers that run over a trusted
    /// transport and accept integrity-vs-manifest only.
    pub allow_unauthenticated_symbols: bool,
}

/// Public per-symbol authentication posture for ATP-over-RaptorQ.
///
/// This reports whether the UDP symbol plane is configured to verify tags. It
/// does not claim full Byzantine symbol-injection protection by itself because
/// the TCP control channel and manifest still need authenticated transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RqSymbolAuthMode {
    /// Symbols are signed and verified with a configured [`SecurityContext`].
    Authenticated,
    /// Symbols are deliberately unauthenticated on a trusted loopback/lab link.
    TrustedUnauthenticated,
    /// No auth context was configured and no explicit trusted opt-out was set.
    MissingAuthenticationContext,
}

impl Default for RqConfig {
    fn default() -> Self {
        Self {
            symbol_size: DEFAULT_SYMBOL_SIZE,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            repair_overhead: DEFAULT_REPAIR_OVERHEAD,
            udp_fanout: DEFAULT_UDP_FANOUT,
            max_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            max_feedback_rounds: DEFAULT_MAX_FEEDBACK_ROUNDS,
            round_tail_drain: DEFAULT_ROUND_TAIL_DRAIN,
            source_retransmit_rounds: DEFAULT_SOURCE_RETRANSMIT_ROUNDS,
            max_source_retransmit_requests: DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS,
            debug_drop_one_in: 0,
            symbol_auth_context: None,
            allow_unauthenticated_symbols: false,
        }
    }
}

impl RqConfig {
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
    pub fn symbol_auth_mode(&self) -> RqSymbolAuthMode {
        if self.symbol_auth_context.is_some() {
            return RqSymbolAuthMode::Authenticated;
        }
        if self.allow_unauthenticated_symbols {
            return RqSymbolAuthMode::TrustedUnauthenticated;
        }
        RqSymbolAuthMode::MissingAuthenticationContext
    }

    /// Validate that the symbol-auth posture is deliberate.
    pub fn validate_symbol_auth_mode(&self) -> Result<(), RqError> {
        self.symbol_auth_context().map(|_| ())
    }

    fn symbol_auth_context(&self) -> Result<Option<SecurityContext>, RqError> {
        if let Some(context) = &self.symbol_auth_context {
            return Ok(Some(context.clone()));
        }
        if self.allow_unauthenticated_symbols {
            return Ok(None);
        }
        Err(RqError::Authentication(
            "ATP RaptorQ transport requires symbol_auth_context; call \
             with_symbol_auth(...) or explicitly opt into \
             allow_unauthenticated_for_trusted_transport() for loopback/lab use"
                .to_string(),
        ))
    }
}

#[derive(Debug, Clone, Copy)]
struct RqRoundTuning {
    repair_overhead: f64,
    pacing: RqSprayPacing,
}

#[derive(Debug, Clone, Copy)]
struct RqSprayPacing {
    path_rate_bps: u64,
    datagram_bytes: u32,
    max_burst_size: u32,
    rtt: Option<Duration>,
    loss_detected: bool,
}

impl RqSprayPacing {
    fn cold_start(symbol_size: u16) -> Self {
        Self::from_rate(
            RQ_COLD_START_PACING_BPS,
            symbol_size,
            RQ_COLD_START_BURST_SYMBOLS,
            None,
            false,
        )
    }

    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    fn from_rate(
        rate_bytes_per_sec: u64,
        symbol_size: u16,
        burst_symbols: usize,
        rtt: Option<Duration>,
        loss_detected: bool,
    ) -> Self {
        let pacing_rate_bytes_per_sec =
            rate_bytes_per_sec.clamp(RQ_MIN_PACING_BPS, RQ_MAX_PACING_BPS);
        let symbol_bytes = u64::from(symbol_size.max(1))
            .saturating_add(u64::try_from(AUTH_DGRAM_HEADER).unwrap_or(u64::MAX));
        let datagram_bytes = u32::try_from(symbol_bytes).unwrap_or(u32::MAX).max(1);
        let path_rate_bps = pacing_rate_bytes_per_sec.saturating_mul(8);
        let max_burst_size = u32::try_from(burst_symbols.max(1))
            .unwrap_or(u32::MAX)
            .max(1);
        Self {
            path_rate_bps,
            datagram_bytes,
            max_burst_size,
            rtt,
            loss_detected,
        }
    }
}

struct RqSprayPacer {
    controller: CongestionController,
}

impl RqSprayPacer {
    fn new(pacing: RqSprayPacing) -> Self {
        let mut controller = CongestionController::new(CongestionConfig::default());
        controller.configure_for_path_rate(
            pacing.path_rate_bps,
            pacing.datagram_bytes,
            pacing.max_burst_size,
        );
        controller.update_congestion_feedback(pacing.rtt, pacing.loss_detected);
        Self { controller }
    }

    fn configure(&mut self, pacing: RqSprayPacing) {
        self.controller.configure_for_path_rate(
            pacing.path_rate_bps,
            pacing.datagram_bytes,
            pacing.max_burst_size,
        );
        self.controller
            .update_congestion_feedback(pacing.rtt, pacing.loss_detected);
    }

    async fn before_send(&mut self, cx: &Cx) -> Result<(), RqError> {
        loop {
            let now = Instant::now();
            if self.controller.try_consume_send_budget(now) {
                return Ok(());
            }
            let wait = self
                .controller
                .time_until_send_budget(now)
                .clamp(RQ_PACING_MIN_PAUSE, RQ_PACING_MAX_PAUSE);
            crate::time::sleep(cx.now(), wait).await;
            cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        }
    }
}

struct RqPendingSendBatch {
    by_socket: Vec<Vec<Vec<u8>>>,
    queued: usize,
}

impl RqPendingSendBatch {
    fn new(fanout: usize) -> Self {
        let fanout = fanout.max(1);
        Self {
            by_socket: (0..fanout).map(|_| Vec::new()).collect(),
            queued: 0,
        }
    }

    fn fanout(&self) -> usize {
        self.by_socket.len()
    }

    fn push(&mut self, socket_index: usize, payload: Vec<u8>) {
        let index = socket_index % self.fanout();
        self.by_socket[index].push(payload);
        self.queued += 1;
    }

    fn should_flush(&self) -> bool {
        self.queued >= RQ_SEND_BATCH_GLOBAL_SYMBOLS
            || self
                .by_socket
                .iter()
                .any(|payloads| payloads.len() >= RQ_SEND_BATCH_PER_SOCKET)
    }

    async fn flush(
        &mut self,
        sockets: &mut [UdpSocket],
        symbols_sent: &mut u64,
    ) -> Result<(), RqError> {
        debug_assert_eq!(self.by_socket.len(), sockets.len().max(1));
        if self.queued == 0 {
            return Ok(());
        }

        let symbols_before_flush = *symbols_sent;
        for (socket_index, payloads) in self.by_socket.iter_mut().enumerate() {
            if payloads.is_empty() {
                continue;
            }

            let socket = sockets.get_mut(socket_index).ok_or_else(|| {
                RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "RQ send batch socket index out of range",
                ))
            })?;
            let dst_addr = socket.peer_addr()?;
            let expected = payloads.len();
            let report = {
                let packets = payloads
                    .iter()
                    .map(|payload| UdpOutboundDatagram { dst_addr, payload })
                    .collect::<SmallVec<[_; RQ_SEND_BATCH_PER_SOCKET]>>();
                socket.send_batch_to(&packets).await?
            };

            *symbols_sent = symbols_sent
                .saturating_add(u64::try_from(report.packets_processed).unwrap_or(u64::MAX));
            if report.packets_processed != expected {
                let reason = report.error.unwrap_or_else(|| {
                    format!(
                        "partial RQ UDP send batch: sent {} of {expected}",
                        report.packets_processed
                    )
                });
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    reason,
                )));
            }

            payloads.clear();
        }

        self.queued = 0;
        if send_progress_crossed_yield_boundary(symbols_before_flush, *symbols_sent) {
            crate::runtime::yield_now().await;
        }
        Ok(())
    }

    #[cfg(test)]
    fn queued_count(&self) -> usize {
        self.queued
    }

    #[cfg(test)]
    fn socket_batch_len(&self, socket_index: usize) -> usize {
        self.by_socket[socket_index].len()
    }
}

fn send_progress_crossed_yield_boundary(before: u64, after: u64) -> bool {
    after > before && before / 64 != after / 64
}

struct RqAdaptiveSendState {
    controller: AdaptiveController,
    loss_detector: AtpLossDetector,
    beacons: BeaconScheduler,
    est: PathEstimate,
    symbol_size: u16,
    loss_ema: f64,
    pacing_loss_ema: f64,
    pacing_loss_bar: f64,
    loss_bar: f64,
    bw_ema_bps: f64,
    bw_trough_bps: f64,
    loss_pacing_cap_bps: Option<u64>,
    loss_fec_floor: f64,
    regime_shift: bool,
}

#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
impl RqAdaptiveSendState {
    fn new(seed: u64, config: &RqConfig, fanout: usize) -> Self {
        let fixed_k = fixed_block_k(config);
        let cores = std::thread::available_parallelism().map_or(4.0, |n| {
            f64::from(u32::try_from(n.get()).unwrap_or(u32::MAX))
        });
        let policy = AdaptivePolicy {
            cores,
            min_samples_to_activate: RQ_ADAPTIVE_MIN_SAMPLES,
            arm_grid_k: vec![fixed_k],
            arm_grid_fanout: vec![fanout.max(1)],
            ..AdaptivePolicy::default()
        };
        let est = PathEstimate {
            coding_ref_k: fixed_k,
            dec_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            enc_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            coding_gamma: RQ_CODING_GAMMA,
            ..PathEstimate::unknown()
        };
        let mut controller = AdaptiveController::new(policy, seed);
        controller.update_estimate(est);
        Self {
            controller,
            loss_detector: AtpLossDetector::new(),
            beacons: BeaconScheduler::new(seed, Instant::now()),
            est,
            symbol_size: config.symbol_size,
            loss_ema: 0.0,
            pacing_loss_ema: 0.0,
            pacing_loss_bar: 0.0,
            loss_bar: 0.0,
            bw_ema_bps: 0.0,
            bw_trough_bps: 0.0,
            loss_pacing_cap_bps: None,
            loss_fec_floor: 0.0,
            regime_shift: false,
        }
    }

    fn record_beacon_exchange(&mut self, control_wait: Duration) {
        let now = Instant::now();
        let measurement = BeaconMeasurement::with_rtt(duration_micros_u32(control_wait), 0);
        let _action = self.beacons.next_action(now, measurement);
        self.beacons.observe_probe_result(now, control_wait);
    }

    fn mark_control_peer_activity(&mut self) {
        self.beacons.mark_peer_activity(Instant::now());
    }

    fn next_control_keepalive_due(&mut self) -> bool {
        let measurement = self
            .beacons
            .latest_rtt()
            .map_or_else(BeaconMeasurement::empty, |rtt| {
                BeaconMeasurement::with_rtt(duration_micros_u32(rtt), 0)
            });
        self.beacons
            .next_action(Instant::now(), measurement)
            .is_some()
    }

    fn control_liveness_expired(&self) -> bool {
        self.beacons.peer_liveness_expired()
    }

    fn missed_control_probes(&self) -> u8 {
        self.beacons.missed_probes()
    }

    fn round_tuning(&mut self, config: &RqConfig) -> RqRoundTuning {
        let fixed = RqRoundTuning {
            repair_overhead: config.repair_overhead.max(1.0),
            pacing: RqSprayPacing::cold_start(config.symbol_size),
        };
        let Some(mut plan) = self.controller.next_block_plan(self.symbol_size) else {
            return fixed;
        };
        // Bound the wire-loss-driven overhead before it feeds either the repair budget or the
        // pacing rate, so a round-0 over-pace artifact can't blow it up to ~10× (MATRIX-12).
        plan.overhead = plan.overhead.min(RQ_MAX_ROUND_REPAIR_OVERHEAD);

        let mut repair_overhead = config
            .repair_overhead
            .max(1.0 + plan.overhead)
            .max(1.0 + self.loss_fec_floor);
        let mut rate = self.pacing_rate_for(plan);
        if let Some(cap) = self.loss_pacing_cap_bps {
            rate = rate.min(self.loss_pacing_cap_for_current_regime(cap));
        }
        if self.regime_shift || self.pacing_loss_bar >= RQ_REGIME_SHIFT_LOSS_DELTA {
            repair_overhead = repair_overhead.max(1.03);
            rate = rate.min(RQ_COLD_START_PACING_BPS / 2);
        }

        RqRoundTuning {
            repair_overhead,
            pacing: RqSprayPacing::from_rate(
                rate,
                config.symbol_size,
                RQ_ADAPTIVE_BURST_SYMBOLS,
                Some(duration_from_secs(self.est.rtt_s)),
                self.pacing_loss_ema > 0.0,
            ),
        }
    }

    fn source_fec_fallback_tuning(&mut self, config: &RqConfig) -> RqRoundTuning {
        let mut tuning = self.round_tuning(config);
        let k = fixed_block_k(config);
        let loss_bar = self.source_fec_fallback_loss_bar();
        let overhead = adaptive::overhead_for_target(
            k,
            loss_bar,
            RQ_SOURCE_FEC_FALLBACK_ALPHA,
            RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD,
        );
        tuning.repair_overhead = tuning
            .repair_overhead
            .max(1.0 + overhead)
            .max(1.0 + RQ_SOURCE_FEC_FALLBACK_MIN_OVERHEAD)
            // Bound the FEC-fallback budget the same as round_tuning: when the wire-loss
            // estimate is inflated by a round-0 over-pace artifact (loss_bar≈0.9),
            // overhead_for_target returns ~9.7 ⇒ ~10.7× and a single round sprays ~10× the
            // object (~518MB for 50M → 1.7GB recv RSS). Cap at ≤2× total so repair stays
            // bounded; convergence still completes in ~2 rounds for realistic loss (MATRIX-13).
            .min(1.0 + RQ_MAX_ROUND_REPAIR_OVERHEAD);
        tuning
    }

    fn source_fec_fallback_loss_bar(&self) -> f64 {
        let measured_loss = self.pacing_loss_ema.max(self.est.loss_p_hat);
        self.loss_bar
            .max(self.loss_ema)
            .max(measured_loss)
            .max(RQ_SOURCE_FEC_FALLBACK_MIN_LOSS_BAR)
    }

    fn observe_need_more(
        &mut self,
        config: &RqConfig,
        digests: &[EntryDigest],
        pending: &BTreeSet<u32>,
        sent_this_round: u64,
        received_this_round: u64,
        send_wall: Duration,
        control_wait: Duration,
        total_bytes: u64,
    ) {
        self.record_beacon_exchange(control_wait);

        let send_wall_s = finite_duration_s(send_wall);
        let rtt_s = finite_duration_s(control_wait);
        let pending_bytes = pending_bytes(digests, pending);
        let sent_symbols = sent_this_round.max(1);
        let pending_units = u64::try_from(pending.len()).unwrap_or(u64::MAX).max(1);
        let received_symbols = received_this_round.min(sent_symbols);
        let decode_pending_loss = (pending_units as f64 / sent_symbols as f64).clamp(0.0, 0.90);
        let wire_loss_hat = if sent_this_round == 0 {
            0.0
        } else {
            (1.0 - received_symbols as f64 / sent_symbols as f64).clamp(0.0, 0.90)
        };
        let byte_pressure = if total_bytes == 0 {
            0.0
        } else {
            (pending_bytes as f64 / total_bytes as f64).clamp(0.0, 1.0)
        };
        let pressure_loss = byte_pressure * RQ_PENDING_PRESSURE_LOSS_FLOOR;
        let repair_loss_hat = wire_loss_hat
            .max(decode_pending_loss)
            .max(pressure_loss)
            .clamp(0.0, 0.90);

        self.regime_shift = self.pacing_loss_ema > 0.0
            && wire_loss_hat > (self.pacing_loss_ema * 3.0 + RQ_REGIME_SHIFT_LOSS_DELTA);
        self.loss_ema = ema(self.loss_ema, repair_loss_hat, RQ_LOSS_EMA_ALPHA);
        self.pacing_loss_ema = ema(self.pacing_loss_ema, wire_loss_hat, RQ_LOSS_EMA_ALPHA);
        let raw_loss_bar = repair_loss_hat.max(self.loss_ema) * RQ_LOSS_BAR_MULTIPLIER;
        self.loss_bar = if self.loss_bar <= 0.0 {
            raw_loss_bar
        } else {
            ema(self.loss_bar, raw_loss_bar, RQ_LOSS_EMA_ALPHA).max(repair_loss_hat)
        }
        .clamp(0.0, 0.90);
        let raw_pacing_loss_bar = wire_loss_hat.max(self.pacing_loss_ema) * RQ_LOSS_BAR_MULTIPLIER;
        self.pacing_loss_bar = if self.pacing_loss_bar <= 0.0 {
            raw_pacing_loss_bar
        } else {
            ema(self.pacing_loss_bar, raw_pacing_loss_bar, RQ_LOSS_EMA_ALPHA).max(wire_loss_hat)
        }
        .clamp(0.0, 0.90);

        let symbol_payload_bytes = u64::from(config.symbol_size.max(1));
        let sent_payload_bytes = sent_symbols.saturating_mul(symbol_payload_bytes);
        let offered_bps = (sent_payload_bytes as f64 / send_wall_s).max(1.0);
        let useful_factor = (1.0 - wire_loss_hat * 0.5).clamp(0.25, 1.0);
        let bw_sample = offered_bps * useful_factor;
        let sent_payload_fraction = if pending_bytes == 0 {
            1.0
        } else {
            (sent_payload_bytes as f64 / pending_bytes as f64).clamp(0.0, 1.0)
        };
        let stalled_repair_sample = byte_pressure >= RQ_STALLED_REPAIR_PRESSURE_MIN
            && sent_payload_fraction < RQ_STALLED_REPAIR_PAYLOAD_FRACTION_MAX
            && wire_loss_hat <= RQ_MILD_LOSS_PACING_MAX_LOSS;
        if self.bw_ema_bps <= 0.0 || !stalled_repair_sample {
            self.bw_ema_bps = if self.bw_ema_bps <= 0.0 {
                bw_sample
            } else {
                ema(self.bw_ema_bps, bw_sample, RQ_BW_EMA_ALPHA)
            };
            self.update_bw_trough(bw_sample);
        }

        self.est = PathEstimate {
            rtt_s,
            loss_p_hat: self.pacing_loss_ema,
            loss_p_bar: self.loss_bar,
            bw_median_bps: self.bw_ema_bps,
            bw_trough_bps: self.bw_trough_bps.max(self.bw_ema_bps * 0.5),
            enc_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            dec_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            coding_ref_k: fixed_block_k(config),
            coding_gamma: RQ_CODING_GAMMA,
            samples: self.est.samples.saturating_add(1),
        };
        self.controller.update_estimate(self.est);

        let useful_bytes = received_symbols.saturating_mul(symbol_payload_bytes);
        let cwnd_bytes = (self.bw_ema_bps * rtt_s)
            .max(f64::from(config.symbol_size.max(1)))
            .ceil() as u64;
        self.loss_pacing_cap_bps = None;
        self.loss_fec_floor = 0.0;
        let lost_symbols = sent_symbols.saturating_sub(received_symbols);
        let loss_result = self.loss_detector.observe_datagram_loss_sample(
            sent_symbols,
            lost_symbols,
            Some(control_wait),
            sent_payload_bytes,
            cwnd_bytes,
        );
        let mild_wire_loss = wire_loss_hat <= RQ_MILD_LOSS_PACING_MAX_LOSS
            && self.pacing_loss_ema <= RQ_MILD_LOSS_PACING_MAX_LOSS;
        self.apply_loss_recommendations(&loss_result.recommendations, mild_wire_loss);
        self.controller.observe_path_signals(
            sent_symbols,
            received_symbols,
            send_wall_s,
            useful_bytes,
            config.symbol_size,
            PathSignalSample {
                smoothed_rtt_s: rtt_s,
                congestion_window_bytes: cwnd_bytes.max(u64::from(config.symbol_size.max(1))),
                loss_rate: wire_loss_hat,
            },
        );
    }

    fn apply_loss_recommendations(
        &mut self,
        recommendations: &[LossRecommendation],
        mild_wire_loss: bool,
    ) {
        for recommendation in recommendations {
            match recommendation {
                LossRecommendation::ReduceCongestionWindow { factor } => {
                    let cap = (self.bw_ema_bps * (*factor).clamp(0.1, 1.0)).ceil() as u64;
                    self.lower_pacing_cap(cap);
                }
                LossRecommendation::EnablePacing { rate } => {
                    let ema_cap = if self.bw_ema_bps > 0.0 {
                        (self.bw_ema_bps * 0.75).ceil() as u64
                    } else {
                        RQ_COLD_START_PACING_BPS / 2
                    };
                    self.lower_pacing_cap((*rate).max(ema_cap));
                }
                LossRecommendation::EnableFec { rate } => {
                    self.loss_fec_floor = self.loss_fec_floor.max((*rate).clamp(0.0, 0.50));
                }
                LossRecommendation::SwitchCongestionControl { .. } if !mild_wire_loss => {
                    self.regime_shift = true;
                    let cap = if self.bw_ema_bps > 0.0 {
                        (self.bw_ema_bps * 0.5).ceil() as u64
                    } else {
                        RQ_COLD_START_PACING_BPS / 2
                    };
                    self.lower_pacing_cap(cap);
                    self.loss_fec_floor = self.loss_fec_floor.max(0.03);
                }
                LossRecommendation::SwitchCongestionControl { .. } => {}
                LossRecommendation::IncreaseReorderingThreshold { .. } => {}
            }
        }
    }

    fn lower_pacing_cap(&mut self, cap_bps: u64) {
        let cap = cap_bps.clamp(RQ_MIN_PACING_BPS, RQ_MAX_PACING_BPS);
        self.loss_pacing_cap_bps = Some(
            self.loss_pacing_cap_bps
                .map_or(cap, |previous| previous.min(cap)),
        );
    }

    fn observe_probe_success(
        &mut self,
        config: &RqConfig,
        sent_this_round: u64,
        send_wall: Duration,
        control_wait: Duration,
    ) {
        self.record_beacon_exchange(control_wait);

        if sent_this_round == 0 {
            self.est = PathEstimate {
                rtt_s: finite_duration_s(control_wait),
                samples: self.est.samples.saturating_add(1),
                ..self.est
            };
            self.controller.update_estimate(self.est);
            return;
        }

        let send_wall_s = finite_duration_s(send_wall);
        let rtt_s = finite_duration_s(control_wait);
        let sent_payload_bytes =
            sent_this_round.saturating_mul(u64::from(config.symbol_size.max(1)));
        let bw_sample = (sent_payload_bytes as f64 / send_wall_s).max(1.0);
        self.bw_ema_bps = if self.bw_ema_bps <= 0.0 {
            bw_sample
        } else {
            ema(self.bw_ema_bps, bw_sample, RQ_BW_EMA_ALPHA)
        };
        self.update_bw_trough(bw_sample);
        self.loss_ema = ema(self.loss_ema, 0.0, RQ_LOSS_EMA_ALPHA);
        self.pacing_loss_ema = ema(self.pacing_loss_ema, 0.0, RQ_LOSS_EMA_ALPHA);
        self.loss_bar = ema(self.loss_bar, 0.0, RQ_LOSS_EMA_ALPHA);
        self.pacing_loss_bar = ema(self.pacing_loss_bar, 0.0, RQ_LOSS_EMA_ALPHA);
        self.loss_pacing_cap_bps = None;
        self.loss_fec_floor = 0.0;

        self.est = PathEstimate {
            rtt_s,
            loss_p_hat: self.pacing_loss_ema,
            loss_p_bar: self.loss_bar,
            bw_median_bps: self.bw_ema_bps,
            bw_trough_bps: self.bw_trough_bps.max(self.bw_ema_bps * 0.5),
            enc_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            dec_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            coding_ref_k: fixed_block_k(config),
            coding_gamma: RQ_CODING_GAMMA,
            samples: self.est.samples.saturating_add(1),
        };
        self.controller.update_estimate(self.est);

        let cwnd_bytes = (self.bw_ema_bps * rtt_s)
            .max(f64::from(config.symbol_size.max(1)))
            .ceil() as u64;
        self.controller.observe_path_signals(
            sent_this_round,
            sent_this_round,
            send_wall_s,
            sent_payload_bytes,
            config.symbol_size,
            PathSignalSample {
                smoothed_rtt_s: rtt_s,
                congestion_window_bytes: cwnd_bytes.max(u64::from(config.symbol_size.max(1))),
                loss_rate: 0.0,
            },
        );
    }

    fn pacing_rate_for(&self, plan: BlockPlan) -> u64 {
        let mut network_bps = if self.est.bw_median_bps > 0.0 {
            self.est.bw_median_bps.min(self.est.bw_trough_bps.max(1.0))
        } else {
            RQ_COLD_START_PACING_BPS as f64
        };
        if self.mild_loss_pacing_floor_applies() {
            network_bps = network_bps
                .max(RQ_COLD_START_PACING_BPS as f64 * RQ_MILD_LOSS_PACING_FLOOR_FRACTION);
        }
        let decode_bps =
            self.est.decode_symbols_per_s_at(plan.k) * f64::from(self.symbol_size.max(1));
        let base = network_bps.min(decode_bps.max(1.0));
        let rate = base / (1.0 + plan.overhead.max(0.0));
        rqtrace!(
            "pacing_rate_for: network_bps={:.0} decode_bps={:.0} base={:.0} overhead={:.4} rate={:.0} bw_median={:.0} bw_trough={:.0} mild_floor={}",
            network_bps,
            decode_bps,
            base,
            plan.overhead.max(0.0),
            rate,
            self.est.bw_median_bps,
            self.est.bw_trough_bps,
            self.mild_loss_pacing_floor_applies()
        );
        rate.ceil()
            .clamp(RQ_MIN_PACING_BPS as f64, RQ_MAX_PACING_BPS as f64) as u64
    }

    fn update_bw_trough(&mut self, bw_sample: f64) {
        if self.bw_trough_bps <= 0.0 || bw_sample < self.bw_trough_bps {
            self.bw_trough_bps = bw_sample;
        } else {
            self.bw_trough_bps = ema(self.bw_trough_bps, bw_sample, RQ_BW_TROUGH_RECOVERY_ALPHA)
                .min(self.bw_ema_bps.max(bw_sample));
        }
    }

    fn mild_loss_pacing_floor_applies(&self) -> bool {
        let pacing_loss = self.pacing_loss_ema;
        let has_repair_pressure = self.loss_bar > 0.0 || self.pacing_loss_bar > 0.0;
        !self.regime_shift
            && has_repair_pressure
            && pacing_loss <= RQ_MILD_LOSS_PACING_MAX_LOSS
            && self.est.bw_median_bps > 0.0
    }

    fn mild_loss_pacing_floor_bps(&self) -> u64 {
        (RQ_COLD_START_PACING_BPS as f64 * RQ_MILD_LOSS_PACING_FLOOR_FRACTION).ceil() as u64
    }

    fn loss_pacing_cap_for_current_regime(&self, cap: u64) -> u64 {
        if self.mild_loss_pacing_floor_applies() {
            cap.max(self.mild_loss_pacing_floor_bps())
        } else {
            cap
        }
    }
}

fn fixed_block_k(config: &RqConfig) -> u32 {
    let symbol_size = usize::from(config.symbol_size.max(1));
    let k = config.max_block_size.div_ceil(symbol_size).max(1);
    u32::try_from(k).unwrap_or(u32::MAX)
}

fn pending_bytes(digests: &[EntryDigest], pending: &BTreeSet<u32>) -> u64 {
    pending.iter().fold(0u64, |acc, index| {
        let Some(entry) = usize::try_from(*index)
            .ok()
            .and_then(|idx| digests.get(idx))
        else {
            return acc;
        };
        acc.saturating_add(entry.size)
    })
}

fn finite_duration_s(duration: Duration) -> f64 {
    duration.as_secs_f64().max(0.000_001)
}

fn duration_from_secs(seconds: f64) -> Duration {
    if seconds.is_finite() {
        Duration::from_secs_f64(seconds.clamp(0.000_001, 60.0))
    } else {
        Duration::from_micros(1)
    }
}

fn duration_micros_u32(duration: Duration) -> u32 {
    u32::try_from(duration.as_micros()).unwrap_or(u32::MAX)
}

fn ema(prev: f64, sample: f64, alpha: f64) -> f64 {
    prev.mul_add(1.0 - alpha, sample * alpha)
}

/// Errors from the ATP-over-RaptorQ transport.
#[derive(Debug, thiserror::Error)]
pub enum RqError {
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
    /// RaptorQ encode/decode error.
    #[error("coding error: {0}")]
    Coding(String),
    /// The fountain feedback loop ran out of rounds with entries still
    /// undecoded.
    #[error(
        "[ASUP-E801] transfer did not converge after {rounds} feedback rounds ({pending} entries still incomplete); if accepted symbols do not advance decode rank, see [ASUP-E805]"
    )]
    NoConvergence {
        /// Feedback rounds attempted.
        rounds: u32,
        /// Entries still undecoded.
        pending: usize,
    },
    /// Integrity verification failed (SHA-256 or merkle-root mismatch).
    #[error("integrity verification failed: {0}")]
    Integrity(String),
    /// Symbol authentication is missing, mismatched, or invalid.
    #[error("symbol authentication failed: {0}")]
    Authentication(String),
    /// The source path was invalid (missing, unsupported type).
    #[error("invalid source path: {0}")]
    Source(String),
    /// The transfer was cancelled via the capability context.
    #[error("transfer cancelled")]
    Cancelled,
}

// ─── Wire control payloads (JSON over TCP) ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Hello {
    protocol: u32,
    role: String,
    peer_id: String,
    symbol_size: u16,
    max_block_size: u64,
    #[serde(default)]
    symbol_auth: bool,
    /// Total payload bytes of the transfer. The receiver sizes its UDP recv buffer to absorb the
    /// sender's (now parallel-encoded) symbol burst so the CPU-bound decode can drain it without
    /// kernel drops. `serde(default)` keeps it tolerant of peers that do not send it.
    #[serde(default)]
    total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HelloAck {
    accepted: bool,
    peer_id: String,
    /// UDP port the receiver is listening on for symbol datagrams.
    udp_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// One logical file packed into a combined RaptorQ object (E-15 coalescing).
///
/// When [`ManifestEntry::members`] is non-empty the entry's content is the byte
/// concatenation of its members in `offset` order; the receiver splits the decoded
/// object back into the member files on commit. This amortizes the per-object
/// runtime overhead (decode pipeline / tasks / commit) that makes many-small-file
/// trees slow (profiled: ~81% runtime sync, 5.8× a same-byte single file).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackedMember {
    /// Path of this file relative to the transfer root.
    pub rel_path: String,
    /// Byte offset of this file within the combined object content.
    pub offset: u64,
    /// Byte length of this file.
    pub len: u64,
    /// Lowercase hex SHA-256 of this file's content (per-member integrity check).
    pub sha256_hex: String,
}

/// One ordered RaptorQ object shard of a larger logical file.
///
/// A fragmented entry's manifest `rel_path` names the encoded object, while
/// this metadata names the logical file that will be reassembled and committed
/// after all shards verify. `sha256_hex` is the whole logical file SHA-256, not
/// the per-shard object hash (that remains [`ManifestEntry::sha256_hex`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LargeObjectFragment {
    /// Logical file path relative to the transfer root.
    pub rel_path: String,
    /// Zero-based shard ordinal within the logical file.
    pub shard_index: u32,
    /// Total shard count for this logical file.
    pub shard_count: u32,
    /// Byte offset of this shard in the logical file.
    pub logical_offset: u64,
    /// Byte length carried by this shard.
    pub len: u64,
    /// Whole logical file size.
    pub logical_size: u64,
    /// Lowercase hex SHA-256 of the whole logical file.
    pub sha256_hex: String,
}

/// One file within a transfer manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Stable index within the transfer (manifest order).
    pub index: u32,
    /// Path relative to the transfer root.
    pub rel_path: String,
    /// Entry size in bytes.
    pub size: u64,
    /// Lowercase hex SHA-256 of the entry content.
    pub sha256_hex: String,
    /// Files packed into this entry (E-15 coalescing). Empty = a normal single-file
    /// entry whose content IS the file (prior wire format, byte-identical). Non-empty
    /// = this entry is a combined object and these members are extracted by offset on
    /// receive. `skip_serializing_if` keeps the no-packing wire byte-identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<PackedMember>,
    /// Large-file multi-object metadata. Present when this manifest entry is one
    /// ordered shard of a single logical file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<LargeObjectFragment>,
}

/// Transfer manifest carried in the `ObjectManifest` frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferManifest {
    /// Stable transfer identifier (hex).
    pub transfer_id: String,
    /// Name of the transfer root (file name or directory name).
    pub root_name: String,
    /// Whether the root is a directory (vs a single file).
    pub is_directory: bool,
    /// Total bytes across all entries.
    pub total_bytes: u64,
    /// Lowercase hex of `MerkleRoot::from_graph` over the flat object graph.
    pub merkle_root_hex: String,
    /// File entries in manifest order.
    pub entries: Vec<ManifestEntry>,
}

/// Receiver → sender fountain feedback: entries still needing more symbols.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NeedMore {
    /// Entry indices that have not yet decoded.
    pending: Vec<u32>,
    /// Sparse systematic source symbols missing from incomplete blocks.
    #[serde(default)]
    source_symbols: Vec<SourceSymbolRequest>,
    /// Matching RQ symbols observed by the receiver in the completed spray round.
    ///
    /// This is the pacing/loss signal: duplicates and symbols that fail to
    /// advance decode rank still prove the datagram arrived on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    round_symbols_observed: Option<u64>,
    /// Matching RQ symbols accepted into a decoder in the completed spray round.
    ///
    /// This remains diagnostic only; accepted symbols can stall on duplicate or
    /// dependent repair rows and must not be treated as packet loss.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    round_symbols_accepted: Option<u64>,
}

/// Request for retransmission of one systematic source symbol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct SourceSymbolRequest {
    entry: u32,
    sbn: u8,
    esi: u32,
}

/// Receipt returned by the receiver in the `Proof` frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiveReceipt {
    /// Whether the receiver atomically committed the transfer to its destination.
    pub committed: bool,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of files received.
    pub files: u32,
    /// Whether every entry's SHA-256 matched the manifest.
    pub sha_ok: bool,
    /// Whether the rebuilt merkle root matched the manifest.
    pub merkle_ok: bool,
    /// Total symbol datagrams the receiver accepted.
    pub symbols_accepted: u64,
    /// Fountain feedback rounds used.
    pub feedback_rounds: u32,
    /// Failure reason when `committed` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Absolute destination paths that were committed.
    pub committed_paths: Vec<String>,
}

/// Outcome of a successful [`send_path`] call.
#[derive(Debug, Clone)]
pub struct SendReport {
    /// Transfer identifier.
    pub transfer_id: String,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Number of files sent.
    pub files: u32,
    /// Total symbol datagrams emitted (across all feedback rounds).
    pub symbols_sent: u64,
    /// Fountain feedback rounds used.
    pub feedback_rounds: u32,
    /// Merkle root (hex) of the transfer.
    pub merkle_root_hex: String,
    /// The receiver's receipt.
    pub receipt: ReceiveReceipt,
    /// Peer control-plane address.
    pub peer: SocketAddr,
}

/// Outcome of a successful received transfer.
#[derive(Debug, Clone)]
pub struct ReceiveReport {
    /// Transfer identifier.
    pub transfer_id: String,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of files committed.
    pub files: u32,
    /// Whether the transfer was committed to the destination.
    pub committed: bool,
    /// Total symbol datagrams accepted.
    pub symbols_accepted: u64,
    /// Fountain feedback rounds used.
    pub feedback_rounds: u32,
    /// Absolute committed paths.
    pub committed_paths: Vec<PathBuf>,
    /// Peer control-plane address.
    pub peer: SocketAddr,
}

// ─── Frame transport over the TCP control stream ─────────────────────────────

struct FrameTransport<S> {
    stream: S,
    codec: AtpFrameCodec,
    rbuf: BytesMut,
    // A control frame that the spray-time drain (`service_rq_spray_control`) pulled but that is
    // NOT a KeepAlive — i.e. the receiver raced ahead and sent a terminal/feedback frame (Proof /
    // ObjectRequest) while the sender was still spraying. We stash it here instead of erroring so
    // the post-spray feedback loop's `recv()` returns it normally (fixes zz35zq: the fast-transfer
    // "unexpected frame: got Proof, expected KeepAlive while spraying" abort).
    stashed: Option<Frame>,
}

impl<S> FrameTransport<S>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    fn new(stream: S) -> Self {
        Self {
            stream,
            codec: AtpFrameCodec::new(),
            rbuf: BytesMut::new(),
            stashed: None,
        }
    }

    async fn send(&mut self, frame: &Frame) -> Result<(), RqError> {
        let bytes = frame
            .to_wire_bytes()
            .map_err(|e| RqError::Frame(e.to_string()))?;
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Frame, RqError> {
        // A frame deferred by the spray-time drain takes precedence (see `stashed`).
        if let Some(frame) = self.stashed.take() {
            return Ok(frame);
        }
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.rbuf)
                .map_err(|e| RqError::Frame(e.to_string()))?
            {
                return Ok(frame);
            }
            let mut tmp = vec![0u8; 65536];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed control connection mid-transfer",
                )));
            }
            self.rbuf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn try_recv_ready(&mut self) -> Result<Option<Frame>, RqError> {
        use std::future::poll_fn;
        use std::pin::Pin;
        use std::task::Poll;

        if let Some(frame) = self
            .codec
            .decode(&mut self.rbuf)
            .map_err(|e| RqError::Frame(e.to_string()))?
        {
            return Ok(Some(frame));
        }

        let mut tmp = [0u8; 4096];
        let ready = poll_fn(|task_cx| {
            let mut read_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.stream).poll_read(task_cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Ready(Ok(None)),
            }
        })
        .await?;

        let Some(n) = ready else {
            return Ok(None);
        };
        if n == 0 {
            return Err(RqError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed control connection mid-transfer",
            )));
        }
        self.rbuf.extend_from_slice(&tmp[..n]);
        self.codec
            .decode(&mut self.rbuf)
            .map_err(|e| RqError::Frame(e.to_string()))
    }
}

// ─── Helpers (entry walk + merkle, shared definition with transport_tcp) ─────

fn json_frame<T: Serialize>(ty: FrameType, value: &T) -> Result<Frame, RqError> {
    let payload = serde_json::to_vec(value).map_err(|e| RqError::Control(e.to_string()))?;
    Frame::new(ProtocolVersion::CURRENT, ty, payload).map_err(|e| RqError::Frame(e.to_string()))
}

fn parse_json<T: for<'de> Deserialize<'de>>(frame: &Frame) -> Result<T, RqError> {
    serde_json::from_slice(frame.payload()).map_err(|e| RqError::Control(e.to_string()))
}

fn parse_and_validate_manifest_frame(
    frame: &Frame,
    config: &RqConfig,
) -> Result<TransferManifest, RqError> {
    let manifest: TransferManifest = parse_json(frame)?;
    validate_manifest(&manifest, config)?;
    Ok(manifest)
}

/// Derive the per-entry RaptorQ [`ObjectId`] deterministically from the transfer
/// id and entry index, so sender and receiver agree without extra signaling.
fn entry_object_id(transfer_id: &str, index: u32) -> ObjectId {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.entry-object-id.v1\0");
    hasher.update(transfer_id.as_bytes());
    hasher.update(index.to_be_bytes());
    let d = hasher.finalize();
    let high = u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
    let low = u64::from_be_bytes([d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]]);
    ObjectId::new(high, low)
}

/// First 8 bytes of the transfer id hex, as a datagram-tag `u64` (cheap stray
/// packet filter — not a security boundary).
fn transfer_tag(transfer_id: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.tag.v1\0");
    hasher.update(transfer_id.as_bytes());
    let d = hasher.finalize();
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// Hash-pass buffer size for sender manifest construction. This bounds the
/// manifest pass independently of transfer size.
const RQ_STREAM_HASH_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone)]
struct RqSourceEntry {
    rel_path: String,
    abs_path: PathBuf,
    /// Byte offset in `abs_path` where this encoded object starts.
    source_offset: u64,
    /// Byte length of this encoded object. `None` means the whole file at
    /// `abs_path`, preserving the historical no-split path.
    source_len: Option<u64>,
    /// Logical files packed into this combined RaptorQ object (E-15 coalescing).
    /// Empty = a normal single-file entry whose content IS the file at `abs_path`
    /// (prior behavior, byte-identical wire). Non-empty = `abs_path` points at a
    /// temp file holding the concatenation of these members in `offset` order, and
    /// the receiver splits it back into the member files on commit.
    members: Vec<PackedMember>,
    /// Large-file multi-object metadata for this encoded object.
    fragment: Option<LargeObjectFragment>,
}

async fn collect_entries(root: &Path) -> Result<(String, bool, Vec<RqSourceEntry>), RqError> {
    let meta = crate::fs::metadata(root)
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", root.display())))?;
    let root_name = root.file_name().map_or_else(
        || "transfer".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );

    if meta.is_file() {
        return Ok((
            root_name.clone(),
            false,
            vec![RqSourceEntry {
                rel_path: root_name,
                abs_path: root.to_path_buf(),
                source_offset: 0,
                source_len: None,
                members: Vec::new(),
                fragment: None,
            }],
        ));
    }
    if meta.is_dir() {
        let mut entries = Vec::new();
        collect_dir(root, String::new(), &mut entries).await?;
        entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        return Ok((root_name, true, entries));
    }
    Err(RqError::Source(format!(
        "{}: not a regular file or directory",
        root.display()
    )))
}

fn collect_dir<'a>(
    dir: &'a Path,
    prefix: String,
    out: &'a mut Vec<RqSourceEntry>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RqError>> + Send + 'a>> {
    Box::pin(async move {
        let mut read_dir = crate::fs::read_dir(dir)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", dir.display())))?;
        let mut children: Vec<(String, PathBuf, bool)> = Vec::new();
        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", dir.display())))?
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let ft = entry
                .file_type()
                .await
                .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
            children.push((name, path, ft.is_dir()));
        }
        children.sort_by(|a, b| a.0.cmp(&b.0));

        for (name, path, is_dir) in children {
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if is_dir {
                collect_dir(&path, rel, out).await?;
            } else {
                out.push(RqSourceEntry {
                    rel_path: rel,
                    abs_path: path,
                    source_offset: 0,
                    source_len: None,
                    members: Vec::new(),
                    fragment: None,
                });
            }
        }
        Ok(())
    })
}

/// E-15 tree coalescing (send side): greedily pack sub-threshold files into fewer,
/// larger combined RaptorQ objects.
///
/// `entries` arrives in manifest (sorted `rel_path`) order. Files whose size is
/// `< PACK_THRESHOLD` are binned greedily, in order, into packs that hold at most
/// `PACK_TARGET.min(max_object_size(config.max_block_size))` bytes (a pack always
/// holds at least one file). A pack of **two or more** files is materialized as a
/// temp file holding the byte concatenation of
/// its members in order; the resulting [`RqSourceEntry`] points at that temp file
/// and carries the [`PackedMember`] offset/len/sha table. A pack of exactly one
/// file (a lone leftover small file, or a single small file with no neighbor) is
/// emitted unchanged (no temp, empty `members`) so it stays byte-identical to the
/// non-packing wire. Files `>= PACK_THRESHOLD` are always emitted unchanged.
///
/// Returns `(new_entries, logical_digests, tempdir)` where `logical_digests` holds
/// one [`EntryDigest`] per **logical file** (members flattened) — the input to the
/// LOGICAL merkle root. For the no-packing case `logical_digests` equals the
/// per-file digests the caller would have computed itself, so the merkle root is
/// byte-identical to prior transfers. `tempdir` (if any) owns every materialized
/// pack temp file and MUST be kept alive until the spray loop has finished reading
/// them; dropping it removes the temp files.
///
/// # Errors
///
/// Returns [`RqError::Source`] if a source file cannot be hashed or a pack temp
/// file cannot be created/written.
async fn pack_small_files(
    entries: Vec<RqSourceEntry>,
    config: &RqConfig,
) -> Result<
    (
        Vec<RqSourceEntry>,
        Vec<EntryDigest>,
        Option<tempfile::TempDir>,
    ),
    RqError,
> {
    let mut hash_buf = vec![0u8; RQ_STREAM_HASH_BUFFER_SIZE];
    // Packed objects are intentionally not split by E-12, so a pack must stay
    // inside the configured one-object SBN envelope. If a single small file is
    // larger than this cap it remains unpacked and `split_large_entries` handles
    // it as ranged objects.
    let symbol_size = usize::from(config.symbol_size.max(1));
    let pack_target = PACK_TARGET.min(
        u64::try_from(max_object_size(config.max_block_size.max(symbol_size))).unwrap_or(u64::MAX),
    );

    // Group consecutive small files into packs. Each `Vec<usize>` is a list of
    // indices into `entries` (the original sorted order is preserved so member
    // offsets and the logical-digest order are deterministic).
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    let mut current_bytes: u64 = 0;
    for (idx, entry) in entries.iter().enumerate() {
        // Hash here purely to learn the size cheaply? No — hashing twice would
        // double the disk read. Instead size is read from metadata; the content
        // sha is computed once below (for packed members) or by the caller's
        // per-object loop (for unpacked entries via the temp/real abs_path).
        let size = crate::fs::metadata(&entry.abs_path)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", entry.abs_path.display())))?
            .len();
        if size >= PACK_THRESHOLD {
            // Flush any in-progress small-file group, then emit this large file
            // as its own (unpacked) singleton group.
            if !current.is_empty() {
                groups.push(std::mem::take(&mut current));
                current_bytes = 0;
            }
            groups.push(vec![idx]);
            continue;
        }
        // Small file: would adding it overflow the current pack? Start a fresh
        // pack if so (but never split a pack to empty — a single oversized-for-
        // -target small file still forms its own pack).
        if !current.is_empty() && current_bytes.saturating_add(size) > pack_target {
            groups.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current.push(idx);
        current_bytes = current_bytes.saturating_add(size);
    }
    if !current.is_empty() {
        groups.push(current);
    }

    // If no group holds 2+ files, packing would do nothing useful. Return the
    // entries unchanged and compute per-file logical digests (byte-identical to
    // the caller's prior per-file digest pass).
    let packs_anything = groups.iter().any(|g| g.len() >= 2);
    if !packs_anything {
        let mut logical_digests = Vec::with_capacity(entries.len());
        for entry in &entries {
            let (size, content_id, content_sha256) =
                hash_file_streaming(&entry.abs_path, &mut hash_buf)
                    .await
                    .map_err(|e| RqError::Source(e.into_message()))?;
            logical_digests.push(EntryDigest {
                rel_path: entry.rel_path.clone(),
                size,
                content_id,
                content_sha256,
            });
        }
        return Ok((entries, logical_digests, None));
    }

    let tempdir = tempfile::Builder::new()
        .prefix(".atp-rq-pack-")
        .tempdir()
        .map_err(RqError::Io)?;

    let mut new_entries: Vec<RqSourceEntry> = Vec::with_capacity(groups.len());
    let mut logical_digests: Vec<EntryDigest> = Vec::with_capacity(entries.len());

    for (pack_idx, group) in groups.iter().enumerate() {
        if group.len() < 2 {
            // Singleton (a lone small file or a >= threshold file): emit unchanged
            // and push its own logical digest. Byte-identical to today.
            let entry = &entries[group[0]];
            let (size, content_id, content_sha256) =
                hash_file_streaming(&entry.abs_path, &mut hash_buf)
                    .await
                    .map_err(|e| RqError::Source(e.into_message()))?;
            logical_digests.push(EntryDigest {
                rel_path: entry.rel_path.clone(),
                size,
                content_id,
                content_sha256,
            });
            new_entries.push(entry.clone());
            continue;
        }

        // 2+ small files → materialize a combined object.
        let pack_path = tempdir.path().join(format!("pack-{pack_idx}"));
        let mut pack_file = crate::fs::File::create(&pack_path)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", pack_path.display())))?;
        let mut members: Vec<PackedMember> = Vec::with_capacity(group.len());
        let mut offset: u64 = 0;
        for &member_idx in group {
            let entry = &entries[member_idx];
            // Hash the member with the SAME streaming helper the rest of the
            // transport uses, so its size / content_id / sha are byte-identical
            // to a non-packed transfer of the same file.
            let (len, content_id, content_sha256) =
                hash_file_streaming(&entry.abs_path, &mut hash_buf)
                    .await
                    .map_err(|e| RqError::Source(e.into_message()))?;
            // Copy the member bytes into the pack temp file at the running offset.
            let mut src = crate::fs::File::open(&entry.abs_path)
                .await
                .map_err(|e| RqError::Source(format!("{}: {e}", entry.abs_path.display())))?;
            loop {
                let (returned, n) = src
                    .read_into_vec(std::mem::take(&mut hash_buf))
                    .await
                    .map_err(|e| RqError::Source(format!("{}: {e}", entry.abs_path.display())))?;
                hash_buf = returned;
                if n == 0 {
                    break;
                }
                pack_file
                    .write_all(&hash_buf[..n])
                    .await
                    .map_err(|e| RqError::Source(format!("{}: {e}", pack_path.display())))?;
            }
            members.push(PackedMember {
                rel_path: entry.rel_path.clone(),
                offset,
                len,
                sha256_hex: hex_encode(&content_sha256),
            });
            logical_digests.push(EntryDigest {
                rel_path: entry.rel_path.clone(),
                size: len,
                content_id,
                content_sha256,
            });
            offset = offset.saturating_add(len);
        }
        pack_file
            .flush()
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", pack_path.display())))?;
        drop(pack_file);

        new_entries.push(RqSourceEntry {
            rel_path: format!(".atp-pack-{pack_idx}"),
            abs_path: pack_path,
            source_offset: 0,
            source_len: None,
            members,
            fragment: None,
        });
    }

    Ok((new_entries, logical_digests, Some(tempdir)))
}

/// Split large unpacked entries into ordered RaptorQ objects while preserving the
/// logical file digest list used for the transfer merkle root.
async fn split_large_entries(
    entries: Vec<RqSourceEntry>,
    logical_digests: &[EntryDigest],
    config: &RqConfig,
) -> Result<Vec<RqSourceEntry>, RqError> {
    let symbol_size = usize::from(config.symbol_size.max(1));
    let block_size = config.max_block_size.max(symbol_size);
    let split_config =
        MultiObjectSplitConfig::new(u64::try_from(block_size).map_err(|_| {
            RqError::Coding(format!("max_block_size does not fit u64: {block_size}"))
        })?);

    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        if !entry.members.is_empty() {
            out.push(entry);
            continue;
        }

        let size = crate::fs::metadata(&entry.abs_path)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", entry.abs_path.display())))?
            .len();
        let plan = plan_multi_object_split(size, split_config)
            .map_err(|e| RqError::Coding(e.to_string()))?;
        if !plan.is_split() {
            out.push(entry);
            continue;
        }

        let logical_digest = logical_digests
            .iter()
            .find(|digest| digest.rel_path == entry.rel_path)
            .ok_or_else(|| {
                RqError::Coding(format!(
                    "large-entry split missing logical digest for {}",
                    entry.rel_path
                ))
            })?;
        let shard_count = u32::try_from(plan.shard_count()).map_err(|_| {
            RqError::Coding(format!(
                "large-entry split produced too many shards for {}",
                entry.rel_path
            ))
        })?;
        let whole_sha256_hex = hex_encode(&logical_digest.content_sha256);
        for shard in plan.shards {
            let object_rel_path = format!(".atp-fragment-{}-{}", out.len(), shard.shard_index);
            out.push(RqSourceEntry {
                rel_path: object_rel_path,
                abs_path: entry.abs_path.clone(),
                source_offset: shard.logical_offset,
                source_len: Some(shard.len),
                members: Vec::new(),
                fragment: Some(LargeObjectFragment {
                    rel_path: entry.rel_path.clone(),
                    shard_index: shard.shard_index,
                    shard_count,
                    logical_offset: shard.logical_offset,
                    len: shard.len,
                    logical_size: plan.logical_size,
                    sha256_hex: whole_sha256_hex.clone(),
                }),
            });
        }
    }

    Ok(out)
}

/// Reduce an attacker-controlled `root_name` to a single safe path component
/// joined under `dest_dir`.
///
/// `manifest.root_name` arrives off the wire, and `Path::join` *replaces* the
/// base when its argument is absolute, so `dest_dir.join(&root_name)` with an
/// absolute (or separator-bearing) `root_name` would escape the destination
/// directory entirely — `crate::fs::write_atomic` validates with
/// `allow_absolute = true`, so it would not catch an absolute target. Senders
/// already set `root_name` to a bare file name (see `collect_entries`), so
/// collapsing to the final path component is loss-free for legitimate
/// transfers while fully containing hostile ones (matches `transport_tcp`).
fn safe_base_for_root_name(dest_dir: &Path, root_name: &str) -> Result<PathBuf, RqError> {
    if root_name.is_empty() {
        return Err(RqError::Source("manifest root_name is empty".to_string()));
    }
    let component = Path::new(root_name)
        .file_name()
        .ok_or_else(|| RqError::Source(format!("unsafe manifest root_name: {root_name}")))?;
    // `file_name()` never yields `.`/`..`/separators, but guard defensively
    // in case of platform-specific surprises.
    let component_str = component.to_string_lossy();
    if component_str == "."
        || component_str == ".."
        || component_str.contains('/')
        || component_str.contains('\\')
    {
        return Err(RqError::Source(format!(
            "unsafe manifest root_name: {root_name}"
        )));
    }
    Ok(dest_dir.join(component))
}

/// Validate an incoming transfer manifest before allocating per-entry decoders.
///
/// The manifest is fully controlled by the peer. `total_bytes` alone is not a
/// sufficient memory bound because each entry size also drives RaptorQ decoder
/// metadata and each entry creates receiver bookkeeping.
fn validate_manifest(manifest: &TransferManifest, config: &RqConfig) -> Result<(), RqError> {
    if manifest.transfer_id.is_empty()
        || manifest.transfer_id.len() > 64
        || !manifest
            .transfer_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric())
    {
        return Err(RqError::Frame(format!(
            "unsafe manifest transfer_id: {}",
            manifest.transfer_id
        )));
    }
    if manifest.total_bytes > config.max_transfer_bytes {
        return Err(RqError::TooLarge {
            size: manifest.total_bytes,
            max: config.max_transfer_bytes,
        });
    }
    validate_manifest_sha256_hex("manifest merkle_root_hex", &manifest.merkle_root_hex)?;
    if manifest.entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(RqError::Frame(format!(
            "manifest declares {} entries (max {MAX_MANIFEST_ENTRIES})",
            manifest.entries.len()
        )));
    }
    let single_file_fragmented = !manifest.is_directory
        && !manifest.entries.is_empty()
        && manifest
            .entries
            .iter()
            .all(|entry| entry.fragment.is_some());
    if !manifest.is_directory && manifest.entries.len() != 1 && !single_file_fragmented {
        return Err(RqError::Frame(format!(
            "single-file transfer manifest declares {} entries",
            manifest.entries.len()
        )));
    }

    #[derive(Debug)]
    struct FragmentGroupValidation {
        logical_size: u64,
        shard_count: u32,
        sha256_hex: String,
        shards: Vec<(u32, u64, u64)>,
    }

    let mut seen_object_rel_paths: BTreeSet<String> = BTreeSet::new();
    let mut seen_logical_rel_paths: BTreeSet<String> = BTreeSet::new();
    let mut fragment_groups: BTreeMap<String, FragmentGroupValidation> = BTreeMap::new();
    let declared_total =
        manifest
            .entries
            .iter()
            .enumerate()
            .try_fold(0u64, |acc, (position, entry)| {
                let expected = u32::try_from(position).map_err(|_| {
                    RqError::Frame("manifest contains too many indexed entries".to_string())
                })?;
                if entry.index != expected {
                    return Err(RqError::Frame(format!(
                        "manifest entry index {} does not match position {expected}",
                        entry.index
                    )));
                }
                validate_manifest_rel_path(&entry.rel_path)?;
                if !seen_object_rel_paths.insert(entry.rel_path.clone()) {
                    return Err(RqError::Frame(format!(
                        "duplicate manifest rel_path: {}",
                        entry.rel_path
                    )));
                }
                validate_manifest_sha256_hex("manifest entry sha256_hex", &entry.sha256_hex)?;
                if let Some(fragment) = &entry.fragment {
                    if !entry.members.is_empty() {
                        return Err(RqError::Frame(format!(
                            "manifest entry {} cannot be both packed and fragmented",
                            entry.rel_path
                        )));
                    }
                    validate_manifest_rel_path(&fragment.rel_path)?;
                    validate_manifest_sha256_hex(
                        "manifest fragment sha256_hex",
                        &fragment.sha256_hex,
                    )?;
                    if fragment.shard_count == 0 || fragment.shard_index >= fragment.shard_count {
                        return Err(RqError::Frame(format!(
                            "fragment {} has invalid shard {}/{}",
                            fragment.rel_path, fragment.shard_index, fragment.shard_count
                        )));
                    }
                    if fragment.len != entry.size {
                        return Err(RqError::Frame(format!(
                            "fragment {} len {} does not match object {} size {}",
                            fragment.rel_path, fragment.len, entry.rel_path, entry.size
                        )));
                    }
                    let end = fragment
                        .logical_offset
                        .checked_add(fragment.len)
                        .ok_or_else(|| {
                            RqError::Frame(format!(
                                "fragment {} byte range overflows",
                                fragment.rel_path
                            ))
                        })?;
                    if end > fragment.logical_size {
                        return Err(RqError::Frame(format!(
                            "fragment {} range ends at {end} beyond logical size {}",
                            fragment.rel_path, fragment.logical_size
                        )));
                    }
                    let group = fragment_groups.entry(fragment.rel_path.clone()).or_insert_with(
                        || FragmentGroupValidation {
                            logical_size: fragment.logical_size,
                            shard_count: fragment.shard_count,
                            sha256_hex: fragment.sha256_hex.clone(),
                            shards: Vec::new(),
                        },
                    );
                    if group.logical_size != fragment.logical_size
                        || group.shard_count != fragment.shard_count
                        || group.sha256_hex != fragment.sha256_hex
                    {
                        return Err(RqError::Frame(format!(
                            "fragment {} metadata is inconsistent across shards",
                            fragment.rel_path
                        )));
                    }
                    group
                        .shards
                        .push((fragment.shard_index, fragment.logical_offset, fragment.len));
                } else if entry.members.is_empty()
                    && !seen_logical_rel_paths.insert(entry.rel_path.clone())
                {
                    return Err(RqError::Frame(format!(
                        "duplicate logical rel_path: {}",
                        entry.rel_path
                    )));
                }
                // E-15: a packed object carries a member offset table. Validate it
                // off the wire (member paths, contiguity, and that the member lens
                // tile the object exactly) so a hostile/malformed packed manifest
                // fails closed before any decoder is allocated. The synthetic object
                // `rel_path` (`.atp-pack-N`) is never committed; the member logical
                // paths are what land on disk and must be unique + safe.
                if !entry.members.is_empty() {
                    let mut expected_offset = 0u64;
                    for member in &entry.members {
                        validate_manifest_rel_path(&member.rel_path)?;
                        validate_manifest_sha256_hex(
                            "manifest packed member sha256_hex",
                            &member.sha256_hex,
                        )?;
                        if !seen_logical_rel_paths.insert(member.rel_path.clone()) {
                            return Err(RqError::Frame(format!(
                                "duplicate packed member rel_path: {}",
                                member.rel_path
                            )));
                        }
                        if member.offset != expected_offset {
                            return Err(RqError::Frame(format!(
                                "packed member {} offset {} is not contiguous (expected {expected_offset})",
                                member.rel_path, member.offset
                            )));
                        }
                        expected_offset = expected_offset.checked_add(member.len).ok_or_else(|| {
                            RqError::Frame(format!(
                                "packed member {} length overflow",
                                member.rel_path
                            ))
                        })?;
                    }
                    if expected_offset != entry.size {
                        return Err(RqError::Frame(format!(
                            "packed members cover {expected_offset} bytes but object {} declares {}",
                            entry.rel_path, entry.size
                        )));
                    }
                }
                acc.checked_add(entry.size).ok_or_else(|| {
                    RqError::Frame("manifest declared size sum overflows u64".to_string())
                })
            })?;
    if declared_total > config.max_transfer_bytes {
        return Err(RqError::TooLarge {
            size: declared_total,
            max: config.max_transfer_bytes,
        });
    }
    if single_file_fragmented && fragment_groups.len() != 1 {
        return Err(RqError::Frame(format!(
            "single-file fragmented manifest declares {} logical files",
            fragment_groups.len()
        )));
    }
    for (rel_path, group) in fragment_groups {
        if !seen_logical_rel_paths.insert(rel_path.clone()) {
            return Err(RqError::Frame(format!(
                "duplicate logical rel_path: {rel_path}"
            )));
        }
        if group.shards.len() != usize::try_from(group.shard_count).unwrap_or(usize::MAX) {
            return Err(RqError::Frame(format!(
                "fragment {rel_path} declares {} shards but manifest carries {}",
                group.shard_count,
                group.shards.len()
            )));
        }
        let mut shards = group.shards;
        shards.sort_by_key(|(shard_index, _, _)| *shard_index);
        let mut expected_offset = 0u64;
        for (position, (shard_index, offset, len)) in shards.iter().enumerate() {
            if *shard_index != u32::try_from(position).unwrap_or(u32::MAX) {
                return Err(RqError::Frame(format!(
                    "fragment {rel_path} has non-contiguous shard index {shard_index}"
                )));
            }
            if *offset != expected_offset {
                return Err(RqError::Frame(format!(
                    "fragment {rel_path} offset {offset} is not contiguous (expected {expected_offset})"
                )));
            }
            expected_offset = expected_offset.checked_add(*len).ok_or_else(|| {
                RqError::Frame(format!("fragment {rel_path} length sum overflows"))
            })?;
        }
        if expected_offset != group.logical_size {
            return Err(RqError::Frame(format!(
                "fragment {rel_path} shards cover {expected_offset} bytes but logical size is {}",
                group.logical_size
            )));
        }
    }
    Ok(())
}

fn validate_manifest_sha256_hex(label: &str, value: &str) -> Result<(), RqError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RqError::Frame(format!("{label} must be 64 hex characters")));
    }
    Ok(())
}

fn validate_manifest_rel_path(rel: &str) -> Result<(), RqError> {
    if rel.is_empty() || rel.starts_with('/') || rel.starts_with('\\') {
        return Err(RqError::Source(format!("unsafe manifest rel_path: {rel}")));
    }
    for component in rel.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains('\\')
            || component.contains(':')
        {
            return Err(RqError::Source(format!("unsafe manifest rel_path: {rel}")));
        }
    }
    Ok(())
}

/// Join `base` with a forward-slash relative path, rejecting any component that
/// would escape `base`.
fn join_relative(base: &Path, rel: &str) -> Result<PathBuf, RqError> {
    let mut out = base.to_path_buf();
    for component in rel.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || component.contains('\\') || component.contains(':') {
            return Err(RqError::Source(format!(
                "unsafe path component in entry: {rel}"
            )));
        }
        out.push(component);
    }
    Ok(out)
}

fn transfer_id_hex(merkle_root_hex: &str, total_bytes: u64, file_count: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.transfer-id.v1\0");
    hasher.update(merkle_root_hex.as_bytes());
    hasher.update(total_bytes.to_be_bytes());
    hasher.update((file_count as u64).to_be_bytes());
    hex_encode(&hasher.finalize()[..16])
}

// ─── UDP symbol datagram framing ─────────────────────────────────────────────

fn encode_symbol_datagram(
    tag: u64,
    entry: u32,
    sym: &Symbol,
    auth_tag: Option<&AuthenticationTag>,
) -> Vec<u8> {
    let data = sym.data();
    let auth_len = auth_tag.map_or(0, |_| TAG_SIZE);
    let mut out = Vec::with_capacity(DGRAM_HEADER + auth_len + data.len());
    out.extend_from_slice(&SYMBOL_MAGIC.to_be_bytes());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&entry.to_be_bytes());
    out.push(sym.id().sbn());
    out.extend_from_slice(&sym.id().esi().to_be_bytes());
    out.push(u8::from(sym.kind().is_repair()));
    out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
    if let Some(auth_tag) = auth_tag {
        out.extend_from_slice(auth_tag.as_bytes());
    }
    out.extend_from_slice(data);
    out
}

struct ParsedDatagram {
    entry: u32,
    sbn: u8,
    esi: u32,
    kind: SymbolKind,
    auth_tag: Option<AuthenticationTag>,
    payload_len: usize,
    header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolDatagramParseError {
    TruncatedHeader { len: usize, min: usize },
    BadMagic { found: u32 },
    WrongTransferTag { found: u64, expected: u64 },
    PayloadTooLarge { declared: usize, max: usize },
    TruncatedPayload { len: usize, min: usize },
}

fn parse_symbol_header_checked(
    buf: &[u8],
    expect_tag: u64,
    auth_required: bool,
    max_payload_len: Option<usize>,
) -> Result<ParsedDatagram, SymbolDatagramParseError> {
    let header_len = if auth_required {
        AUTH_DGRAM_HEADER
    } else {
        DGRAM_HEADER
    };
    if buf.len() < header_len {
        return Err(SymbolDatagramParseError::TruncatedHeader {
            len: buf.len(),
            min: header_len,
        });
    }

    let found_magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if found_magic != SYMBOL_MAGIC {
        return Err(SymbolDatagramParseError::BadMagic { found: found_magic });
    }

    let tag = u64::from_be_bytes([
        buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
    ]);
    if tag != expect_tag {
        return Err(SymbolDatagramParseError::WrongTransferTag {
            found: tag,
            expected: expect_tag,
        });
    }

    let entry = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let sbn = buf[16];
    let esi = u32::from_be_bytes([buf[17], buf[18], buf[19], buf[20]]);
    let kind = if buf[21] == 0 {
        SymbolKind::Source
    } else {
        SymbolKind::Repair
    };
    let payload_len = usize::from(u16::from_be_bytes([buf[22], buf[23]]));

    if let Some(max) = max_payload_len
        && payload_len > max
    {
        return Err(SymbolDatagramParseError::PayloadTooLarge {
            declared: payload_len,
            max,
        });
    }

    let auth_tag = if auth_required {
        let mut tag_bytes = [0u8; TAG_SIZE];
        tag_bytes.copy_from_slice(&buf[DGRAM_HEADER..AUTH_DGRAM_HEADER]);
        Some(AuthenticationTag::from_bytes(tag_bytes))
    } else {
        None
    };

    let min = header_len + payload_len;
    if buf.len() < min {
        return Err(SymbolDatagramParseError::TruncatedPayload {
            len: buf.len(),
            min,
        });
    }

    Ok(ParsedDatagram {
        entry,
        sbn,
        esi,
        kind,
        auth_tag,
        payload_len,
        header_len,
    })
}

fn parse_symbol_header(buf: &[u8], expect_tag: u64, auth_required: bool) -> Option<ParsedDatagram> {
    parse_symbol_header_checked(buf, expect_tag, auth_required, None).ok()
}

/// Fuzz-visible symbol-datagram parser result.
#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RqSymbolDatagramFuzzParse {
    /// Manifest entry index carried by the datagram.
    pub entry: u32,
    /// RaptorQ source-block number.
    pub sbn: u8,
    /// RaptorQ encoding-symbol id.
    pub esi: u32,
    /// Whether the datagram carries a repair symbol.
    pub is_repair: bool,
    /// Optional per-symbol authentication tag bytes.
    pub auth_tag: Option<[u8; TAG_SIZE]>,
    /// Offset where the symbol payload begins.
    pub payload_offset: usize,
    /// Declared symbol payload length.
    pub payload_len: usize,
}

/// Typed fuzz-visible parser error for ATP-over-RaptorQ UDP symbol datagrams.
#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RqSymbolDatagramFuzzError {
    /// The datagram ended before the required header.
    TruncatedHeader {
        /// Observed byte length.
        len: usize,
        /// Minimum required byte length.
        min: usize,
    },
    /// The magic prefix was not `ATRQ`.
    BadMagic {
        /// Observed magic value.
        found: u32,
    },
    /// The transfer tag did not match the expected transfer.
    WrongTransferTag {
        /// Observed transfer tag.
        found: u64,
        /// Expected transfer tag.
        expected: u64,
    },
    /// The declared payload length exceeds the fuzz harness budget.
    PayloadTooLarge {
        /// Declared payload length.
        declared: usize,
        /// Maximum payload length accepted by the harness.
        max: usize,
    },
    /// The datagram ended before the declared payload bytes.
    TruncatedPayload {
        /// Observed byte length.
        len: usize,
        /// Minimum required byte length.
        min: usize,
    },
}

#[cfg(any(test, feature = "fuzz"))]
impl From<SymbolDatagramParseError> for RqSymbolDatagramFuzzError {
    fn from(error: SymbolDatagramParseError) -> Self {
        match error {
            SymbolDatagramParseError::TruncatedHeader { len, min } => {
                Self::TruncatedHeader { len, min }
            }
            SymbolDatagramParseError::BadMagic { found } => Self::BadMagic { found },
            SymbolDatagramParseError::WrongTransferTag { found, expected } => {
                Self::WrongTransferTag { found, expected }
            }
            SymbolDatagramParseError::PayloadTooLarge { declared, max } => {
                Self::PayloadTooLarge { declared, max }
            }
            SymbolDatagramParseError::TruncatedPayload { len, min } => {
                Self::TruncatedPayload { len, min }
            }
        }
    }
}

/// Parse an ATP-over-RaptorQ UDP symbol datagram with typed errors for fuzzing.
#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
pub fn parse_symbol_datagram_for_fuzz(
    buf: &[u8],
    expect_tag: u64,
    auth_required: bool,
    max_payload_len: usize,
) -> Result<RqSymbolDatagramFuzzParse, RqSymbolDatagramFuzzError> {
    let parsed =
        parse_symbol_header_checked(buf, expect_tag, auth_required, Some(max_payload_len))?;
    Ok(RqSymbolDatagramFuzzParse {
        entry: parsed.entry,
        sbn: parsed.sbn,
        esi: parsed.esi,
        is_repair: parsed.kind.is_repair(),
        auth_tag: parsed.auth_tag.map(|tag| *tag.as_bytes()),
        payload_offset: parsed.header_len,
        payload_len: parsed.payload_len,
    })
}

// ─── Per-entry coding state ──────────────────────────────────────────────────

/// Compute the source-symbol count for an entry of `size` bytes given the
/// symbol size (`ceil(size / symbol_size)`, with a 1-symbol floor for empties).
#[cfg(test)]
fn source_symbol_count(size: u64, symbol_size: u16) -> usize {
    let s = u64::from(symbol_size.max(1));
    usize::try_from(size.div_ceil(s).max(1)).unwrap_or(usize::MAX)
}

#[cfg(test)]
fn max_block_source_symbol_count(size: u64, symbol_size: u16, max_block_size: usize) -> usize {
    if size == 0 {
        return 1;
    }
    let s = usize::from(symbol_size.max(1));
    let capped_block = usize::try_from(size)
        .unwrap_or(usize::MAX)
        .min(max_block_size.max(1));
    capped_block.div_ceil(s).max(1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EncodeAheadBlock {
    sbn: u8,
    start: usize,
    len: usize,
    k: usize,
}

#[derive(Debug)]
struct EncodeAheadSymbol {
    entry: u32,
    symbol: Symbol,
}

impl EncodeAheadSymbol {
    fn from_encoded(entry: u32, encoded: EncodedSymbol) -> Self {
        Self {
            entry,
            symbol: encoded.into_symbol(),
        }
    }
}

#[derive(Debug, Default)]
struct EncodeAheadRing {
    slot: Option<EncodeAheadSymbol>,
}

impl EncodeAheadRing {
    const CAPACITY: usize = 1;

    fn push(&mut self, symbol: EncodeAheadSymbol) -> Result<(), RqError> {
        if self.slot.is_some() {
            return Err(RqError::Coding(format!(
                "M={} encode-ahead ring is full",
                Self::CAPACITY
            )));
        }
        self.slot = Some(symbol);
        Ok(())
    }

    fn pop(&mut self) -> Option<EncodeAheadSymbol> {
        self.slot.take()
    }

    fn is_empty(&self) -> bool {
        self.slot.is_none()
    }
}

fn encode_ahead_blocks(
    bytes_len: usize,
    config: &RqConfig,
) -> Result<Vec<EncodeAheadBlock>, RqError> {
    let symbol_size = usize::from(config.symbol_size);
    if symbol_size == 0 {
        return Err(RqError::Coding(
            "invalid configuration: symbol_size must be non-zero".to_string(),
        ));
    }
    let max_block_size = config.max_block_size;
    if max_block_size == 0 {
        return Err(RqError::Coding(
            "invalid configuration: max_block_size must be non-zero".to_string(),
        ));
    }

    if bytes_len == 0 {
        return Ok(Vec::new());
    }

    let max_total = max_object_size(max_block_size);
    if bytes_len > max_total {
        return Err(RqError::TooLarge {
            size: u64::try_from(bytes_len).unwrap_or(u64::MAX),
            max: u64::try_from(max_total).unwrap_or(u64::MAX),
        });
    }

    let mut blocks = Vec::new();
    let mut start = 0usize;
    while start < bytes_len {
        if blocks.len() >= MAX_SOURCE_BLOCKS {
            return Err(RqError::TooLarge {
                size: u64::try_from(bytes_len).unwrap_or(u64::MAX),
                max: u64::try_from(max_total).unwrap_or(u64::MAX),
            });
        }
        let sbn = u8::try_from(blocks.len()).map_err(|_| {
            RqError::Coding("encode-ahead source block number overflow".to_string())
        })?;
        let len = (bytes_len - start).min(max_block_size);
        let k = len.div_ceil(symbol_size);
        blocks.push(EncodeAheadBlock { sbn, start, len, k });
        start += len;
    }

    Ok(blocks)
}

fn effective_transfer_max_block_size(
    config: &RqConfig,
    entries: &[EntryDigest],
) -> Result<usize, RqError> {
    let mut max_entry_len = 0usize;
    for entry in entries {
        let len = usize::try_from(entry.size).map_err(|_| RqError::TooLarge {
            size: entry.size,
            max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        })?;
        max_entry_len = max_entry_len.max(len);
    }
    effective_max_block_size_for_largest_entry(config, max_entry_len)
}

pub(in crate::net::atp) fn effective_max_block_size_for_largest_entry(
    config: &RqConfig,
    max_entry_len: usize,
) -> Result<usize, RqError> {
    let symbol_size = usize::from(config.symbol_size.max(1));
    let configured_max = config.max_block_size.max(symbol_size);
    // E-12: large logical files must be split into bounded RaptorQ objects before
    // this transfer-wide block size is chosen. If an unsplit entry still exceeds
    // the one-byte SBN envelope, fail closed instead of raising K and making lossy
    // huge-file decode quadratic.
    let max_supported = max_object_size(configured_max);
    if max_entry_len > max_supported {
        return Err(RqError::Coding(format!(
            "[ASUP-E803] ATP block-size planning failed: largest entry {max_entry_len} bytes exceeds supported max {max_supported} bytes"
        )));
    }

    let target = symbol_size
        .saturating_mul(TARGET_SOURCE_SYMBOLS_PER_BLOCK)
        .min(TARGET_STREAMING_BLOCK_BYTES);
    let min_for_block_limit = max_entry_len
        .div_ceil(MAX_SOURCE_BLOCKS)
        .max(symbol_size)
        .div_ceil(symbol_size)
        .saturating_mul(symbol_size);

    // For entries within `256 * configured_max` (<= ~2 GiB at defaults),
    // `min_for_block_limit <= configured_max`, so this preserves the bounded
    // streaming target while honoring the SBN envelope.
    Ok(target
        .max(min_for_block_limit)
        .min(configured_max)
        .max(symbol_size))
}

/// Sender-side encoder state for one entry. Holds only source metadata; each
/// encode-ahead block is read on demand so the sender never retains the whole
/// object in memory.
struct EntryEncoder {
    index: u32,
    object_id: ObjectId,
    abs_path: PathBuf,
    source_offset: usize,
    size: usize,
    /// Cumulative repair symbols already requested from the encoder, indexed by
    /// source block. Feedback rounds request more and send only the newly-minted
    /// ones at their TRUE encoder ESIs — a RaptorQ repair symbol's payload is
    /// bound to its ESI, so it must never be relabeled.
    repair_cursors: Vec<usize>,
}

/// Receiver-side decoder state for one entry.
struct EntryDecoder {
    index: u32,
    object_id: ObjectId,
    size: u64,
    /// `Option` so completed entries can drop decoder state after streaming all
    /// blocks to disk.
    pipeline: Option<DecodingPipeline>,
    complete: bool,
    staging_path: PathBuf,
    staging_created: bool,
    staging_file: Option<crate::fs::File>,
    staging_cursor: Option<u64>,
    staging_unflushed_bytes: usize,
    cache_staging_file: bool,
    bytes_written: u64,
    max_block_size: usize,
    source_streaming: bool,
    source_blocks: Vec<SourceBlockProgress>,
    pending_decodes: Vec<PendingDecode>,
}

struct PendingDecode {
    block_sbn: u8,
    handle: crate::runtime::TaskHandle<BlockDecodeOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeDispatch {
    Queued,
    NoProgress,
}

fn should_cache_entry_staging_file(entry_size: u64, manifest_entries: usize) -> bool {
    const MIN_BYTES: u64 = 1024 * 1024;
    const MAX_ENTRIES: usize = 128;

    // Keep a staging file handle hot only for large entries where per-symbol
    // open/seek/write dominates clean-link receiver intake. Small tree entries
    // use scoped opens so E-14's FD bound stays intact.
    entry_size >= MIN_BYTES && manifest_entries <= MAX_ENTRIES
}

fn entry_decode_width_budget(dec: &EntryDecoder, transfer_decode_width: usize) -> usize {
    let max_block_size = u64::try_from(dec.max_block_size.max(1)).unwrap_or(u64::MAX);
    let planned_blocks = usize::try_from(dec.size.div_ceil(max_block_size)).unwrap_or(usize::MAX);
    let block_count = dec.source_blocks.len().max(planned_blocks).max(1);
    block_count
        .min(RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY)
        .min(transfer_decode_width.max(1))
        .max(1)
}

fn can_spawn_parallel_decode(pending_decodes: usize, entry_decode_width: usize) -> bool {
    pending_decodes < entry_decode_width.max(1)
}

fn rq_decode_job_memory_estimate_bytes(max_block_size: usize, symbol_size: u16) -> usize {
    let retained_symbol_bytes = rq_max_buffered_symbols_per_block(max_block_size, symbol_size)
        .saturating_mul(usize::from(symbol_size.max(1)));
    retained_symbol_bytes
        .saturating_mul(RQ_DECODE_JOB_SYMBOL_MEMORY_MULTIPLIER)
        .max(RQ_DECODE_JOB_MEMORY_FLOOR_BYTES)
}

fn rq_decode_reserved_io_cores(available: usize) -> usize {
    if available <= 1 {
        return 0;
    }
    (available / 4)
        .clamp(
            RQ_DECODE_MIN_CORES_RESERVED_FOR_IO,
            RQ_DECODE_MAX_CORES_RESERVED_FOR_IO,
        )
        .min(available.saturating_sub(1))
}

fn rq_decode_core_limit_for_available(available: usize) -> usize {
    available
        .saturating_sub(rq_decode_reserved_io_cores(available))
        .max(1)
        .min(RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD)
}

fn rq_decode_width_budget(decoders: &[EntryDecoder], symbol_size: u16) -> usize {
    static CORE_LIMIT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let core_limit = *CORE_LIMIT.get_or_init(|| {
        let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        rq_decode_core_limit_for_available(available)
    });
    let max_block_size = decoders
        .iter()
        .map(|decoder| decoder.max_block_size)
        .max()
        .unwrap_or(DEFAULT_MAX_BLOCK_SIZE);
    let memory_limited = RQ_DECODE_JOB_MEMORY_BUDGET_BYTES
        .checked_div(rq_decode_job_memory_estimate_bytes(
            max_block_size,
            symbol_size,
        ))
        .unwrap_or(1)
        .max(1);
    core_limit.min(memory_limited).max(1)
}

fn block_decode_pending(dec: &EntryDecoder, block_sbn: u8) -> bool {
    dec.pending_decodes
        .iter()
        .any(|pending| pending.block_sbn == block_sbn)
}

fn rq_pending_decode_jobs(decoders: &[EntryDecoder]) -> usize {
    decoders
        .iter()
        .map(|decoder| decoder.pending_decodes.len())
        .sum()
}

fn source_streaming_block_ready_to_seed(dec: &EntryDecoder, sbn: usize) -> bool {
    let Some(block) = dec.source_blocks.get(sbn) else {
        return false;
    };
    if block.complete {
        return false;
    }
    let Ok(block_sbn) = u8::try_from(sbn) else {
        return false;
    };
    let Some(status) = dec
        .pipeline
        .as_ref()
        .and_then(|pipeline| pipeline.block_status(block_sbn))
    else {
        return false;
    };
    let unseeded_sources = block
        .received
        .iter()
        .zip(&block.pipeline_seeded)
        .filter(|(received, seeded)| **received && !**seeded)
        .count();

    status.symbols_received.saturating_add(unseeded_sources) >= block.k
}

fn source_seed_symbol_plan(
    dec: &EntryDecoder,
    sbn: usize,
    esi: usize,
    symbol_size: usize,
) -> Result<Option<(usize, usize, Option<AuthenticationTag>)>, RqError> {
    let Some(block) = dec.source_blocks.get(sbn) else {
        return Ok(None);
    };
    if esi >= block.k || !block.received[esi] || block.pipeline_seeded[esi] || block.complete {
        return Ok(None);
    }

    let Some(within_block) = esi.checked_mul(symbol_size) else {
        return Err(RqError::Coding(format!(
            "entry {} source seed offset overflow",
            dec.index
        )));
    };
    if within_block >= block.len {
        return Ok(None);
    }

    let take = symbol_size.min(block.len - within_block);
    Ok(Some((within_block, take, block.auth_tags[esi])))
}

fn rq_max_buffered_symbols_per_block(max_block_size: usize, symbol_size: u16) -> usize {
    let symbol_size = usize::from(symbol_size.max(1));
    let k = max_block_size.div_ceil(symbol_size).max(1);
    let repair_extra = k.max(RQ_REPAIR_SYMBOL_RETENTION_MIN_EXTRA);
    k.saturating_add(repair_extra)
}

#[derive(Debug)]
struct SourceBlockProgress {
    start: u64,
    len: usize,
    k: usize,
    received: Vec<bool>,
    pipeline_seeded: Vec<bool>,
    auth_tags: Vec<Option<AuthenticationTag>>,
    received_count: usize,
    complete: bool,
}

/// Best-effort backstop for receive staging directories.
///
/// The RQ receiver creates a per-transfer staging directory before it starts
/// accepting untrusted UDP symbols. Normal and error exits should not leave
/// hidden payload fragments under the destination, and cancellation can drop the
/// future before it reaches a cooperative return path. This mirrors the TCP
/// transport's staging guard.
struct RqStagingDirGuard {
    dir: PathBuf,
}

impl RqStagingDirGuard {
    fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl Drop for RqStagingDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ─── Public API: send ────────────────────────────────────────────────────────

/// Transfer the file or directory at `source` to `addr` (the receiver's TCP
/// control address) using RaptorQ symbols over UDP.
///
/// Returns the receiver's verified receipt. Fails closed on an unreachable peer,
/// a rejected handshake, a size-limit breach, a fountain loop that does not
/// converge, or a receiver integrity rejection.
pub async fn send_path(
    cx: &Cx,
    addr: SocketAddr,
    source: &Path,
    mut config: RqConfig,
    peer_id: &str,
) -> Result<SendReport, RqError> {
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();

    let (root_name, is_directory, raw_entries) = collect_entries(source).await?;
    // E-15: coalesce sub-threshold files into fewer/larger combined RaptorQ
    // objects. `entries` are the OBJECTS to spray (a packed entry's `abs_path`
    // points at a temp file holding the member concatenation); `logical_digests`
    // are the per-LOGICAL-FILE digests that drive the merkle root. For the
    // no-packing case `entries == raw_entries` and `logical_digests` equals the
    // per-file digests, so everything is byte-identical to a prior transfer. The
    // temp dir owns every pack temp file and must outlive the spray loop below.
    let (packed_entries, logical_digests, _pack_tempdir) =
        pack_small_files(raw_entries, &config).await?;
    let entries = split_large_entries(packed_entries, &logical_digests, &config).await?;

    let mut hash_buf = vec![0u8; RQ_STREAM_HASH_BUFFER_SIZE];
    // Per-OBJECT digests: size + sha of each entry's `abs_path` (the temp file for
    // packed entries). These feed the manifest entry size/sha (object-level verify)
    // and the effective block size — they describe the RaptorQ objects on the wire.
    let mut digests = Vec::with_capacity(entries.len());
    let mut total_bytes = 0u64;
    for entry in &entries {
        let (size, content_id, content_sha256) = hash_source_entry_streaming(entry, &mut hash_buf)
            .await
            .map_err(|e| RqError::Source(e.into_message()))?;
        total_bytes = total_bytes.checked_add(size).ok_or(RqError::TooLarge {
            size: u64::MAX,
            max: config.max_transfer_bytes,
        })?;
        if total_bytes > config.max_transfer_bytes {
            return Err(RqError::TooLarge {
                size: total_bytes,
                max: config.max_transfer_bytes,
            });
        }
        digests.push(EntryDigest {
            rel_path: entry.rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
    }
    config.max_block_size = effective_transfer_max_block_size(&config, &digests)?;

    // Merkle root is over the LOGICAL files (members flattened), identical on both
    // sides regardless of how files were packed into objects.
    let merkle_root_hex = flat_merkle_root_from_digests(&logical_digests);
    let manifest_entries: Vec<ManifestEntry> = entries
        .iter()
        .zip(digests.iter())
        .enumerate()
        .map(|(i, (entry, digest))| ManifestEntry {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            rel_path: digest.rel_path.clone(),
            size: digest.size,
            sha256_hex: hex_encode(&digest.content_sha256),
            members: entry.members.clone(),
            fragment: entry.fragment.clone(),
        })
        .collect();
    let packed_objects = manifest_entries
        .iter()
        .filter(|e| !e.members.is_empty())
        .count();
    rqtrace!(
        "sender: E-15 pack: {} logical files -> {} RaptorQ objects ({} packed)",
        logical_digests.len(),
        manifest_entries.len(),
        packed_objects
    );
    let transfer_id = transfer_id_hex(&merkle_root_hex, total_bytes, manifest_entries.len());
    let tag = transfer_tag(&transfer_id);
    let manifest = TransferManifest {
        transfer_id: transfer_id.clone(),
        root_name,
        is_directory,
        total_bytes,
        merkle_root_hex: merkle_root_hex.clone(),
        entries: manifest_entries,
    };

    // Control plane: TCP connect + handshake.
    let stream = TcpStream::connect(addr).await?;
    let peer = stream.peer_addr().unwrap_or(addr);
    let mut control = FrameTransport::new(stream);
    control
        .send(&json_frame(
            FrameType::Handshake,
            &Hello {
                protocol: ATP_RQ_PROTOCOL,
                role: "sender".to_string(),
                peer_id: peer_id.to_string(),
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size as u64,
                symbol_auth: symbol_auth_enabled,
                total_bytes,
            },
        )?)
        .await?;
    let ack_frame = control.recv().await?;
    if ack_frame.frame_type() != FrameType::HandshakeAck {
        return Err(RqError::Unexpected {
            got: ack_frame.frame_type(),
            expected: "HandshakeAck",
        });
    }
    let ack: HelloAck = parse_json(&ack_frame)?;
    if !ack.accepted {
        return Err(RqError::HandshakeRejected(
            ack.reason.unwrap_or_else(|| "no reason given".to_string()),
        ));
    }
    rqtrace!("sender: handshake ok, peer udp_port={}", ack.udp_port);

    // Data plane: open UDP sockets connected to the receiver's UDP endpoint.
    let udp_addr = SocketAddr::new(peer.ip(), ack.udp_port);
    let fanout = config.udp_fanout.max(1);
    let mut adaptive = RqAdaptiveSendState::new(tag, &config, fanout);
    let local_unspec = if peer.ip().is_ipv4() {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    let mut sockets: Vec<UdpSocket> = Vec::with_capacity(fanout);
    for _ in 0..fanout {
        let sock = UdpSocket::bind(SocketAddr::new(local_unspec, 0)).await?;
        sock.connect(udp_addr).await?;
        // Large send buffer absorbs bursts so the spray loop does not busy-spin
        // on `ENOBUFS`/`WouldBlock` (UDP sockets epoll-report writable even when
        // the send buffer is full).
        let _ = sock.tune_buffers(UdpBufferConfig {
            send_buffer_bytes: Some(16 * 1024 * 1024),
            recv_buffer_bytes: None,
        });
        sockets.push(sock);
    }

    let mut encoders: Vec<EntryEncoder> = Vec::with_capacity(entries.len());
    for (i, (entry, digest)) in entries.iter().zip(digests.iter()).enumerate() {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let size = usize::try_from(digest.size).map_err(|_| RqError::TooLarge {
            size: digest.size,
            max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        })?;
        let source_offset =
            usize::try_from(entry.source_offset).map_err(|_| RqError::TooLarge {
                size: entry.source_offset,
                max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
            })?;
        encoders.push(EntryEncoder {
            index,
            object_id: entry_object_id(&transfer_id, index),
            abs_path: entry.abs_path.clone(),
            source_offset,
            size,
            repair_cursors: Vec::new(),
        });
    }

    // Send the manifest, then spray round 0 (source + optional overhead repair).
    control
        .send(&json_frame(FrameType::ObjectManifest, &manifest)?)
        .await?;

    let mut symbols_sent: u64 = 0;
    let mut rr = 0usize;
    let mut dropper = 0u32;
    let mut feedback_rounds = 0u32;
    let mut source_fec_fallback_active = false;

    // Parallel per-block encode is on by default, but only while the transfer is small enough that
    // the receiver's recv buffer can absorb the burst (see PARALLEL_ENCODE_MAX_BYTES); larger
    // transfers fall back to the sequential encode-paced spray to avoid overrunning the decoder.
    let parallel_encode = total_bytes <= PARALLEL_ENCODE_MAX_BYTES;

    // Round 0: every entry, source symbols plus optional repair_overhead extra.
    let mut pending: BTreeSet<u32> = encoders.iter().map(|e| e.index).collect();
    let mut round_tuning = adaptive.round_tuning(&config);
    // One token bucket owns the whole transfer. Recreating it per source/repair
    // spray would grant a fresh burst each time and overflow rate-capped qdiscs.
    let mut pacer = RqSprayPacer::new(round_tuning.pacing);
    let mut round_started = Instant::now();
    let mut round_symbols_start = symbols_sent;
    spray_round(
        cx,
        &mut control,
        &mut adaptive,
        &mut sockets,
        &mut rr,
        &mut symbols_sent,
        &mut dropper,
        tag,
        &mut encoders,
        &pending,
        &config,
        &mut pacer,
        &round_tuning,
        symbol_auth.as_ref(),
        /* with_source */ true,
        parallel_encode,
    )
    .await?;
    let mut round_send_wall = round_started.elapsed();
    rqtrace!("sender: round 0 sprayed, symbols_sent={symbols_sent}");

    // Feedback loop.
    loop {
        let control_wait_started = Instant::now();
        control
            .send(
                &Frame::empty(FrameType::ObjectComplete)
                    .map_err(|e| RqError::Frame(e.to_string()))?,
            )
            .await?;
        rqtrace!("sender: sent ObjectComplete, awaiting reply");
        let reply = control.recv().await?;
        let control_wait = control_wait_started.elapsed();
        let sent_this_round = symbols_sent.saturating_sub(round_symbols_start);
        rqtrace!("sender: got reply {:?}", reply.frame_type());
        match reply.frame_type() {
            FrameType::Proof => {
                adaptive.observe_probe_success(
                    &config,
                    sent_this_round,
                    round_send_wall,
                    control_wait,
                );
                let receipt: ReceiveReceipt = parse_json(&reply)?;
                let _ = control
                    .send(
                        &Frame::empty(FrameType::Close)
                            .map_err(|e| RqError::Frame(e.to_string()))?,
                    )
                    .await;
                if !receipt.committed {
                    return Err(RqError::Integrity(
                        receipt
                            .reason
                            .clone()
                            .unwrap_or_else(|| "receiver did not commit".to_string()),
                    ));
                }
                return Ok(SendReport {
                    transfer_id,
                    bytes_sent: total_bytes,
                    files: u32::try_from(logical_digests.len()).unwrap_or(u32::MAX),
                    symbols_sent,
                    feedback_rounds,
                    merkle_root_hex,
                    receipt,
                    peer,
                });
            }
            FrameType::KeepAlive => {
                adaptive.mark_control_peer_activity();
            }
            FrameType::ObjectRequest => {
                let need: NeedMore = parse_json(&reply)?;
                feedback_rounds += 1;
                if feedback_rounds > config.max_feedback_rounds {
                    return Err(RqError::NoConvergence {
                        rounds: feedback_rounds,
                        pending: need.pending.len(),
                    });
                }
                let source_symbols = need.source_symbols;
                pending = need.pending.into_iter().collect();
                let fallback_received = sent_this_round.saturating_sub(
                    u64::try_from(pending.len())
                        .unwrap_or(u64::MAX)
                        .min(sent_this_round),
                );
                let received_this_round = need
                    .round_symbols_observed
                    .or(need.round_symbols_accepted)
                    .unwrap_or(fallback_received)
                    .min(sent_this_round);
                if pending.is_empty() {
                    // Receiver says nothing pending but did not send Proof yet;
                    // loop again to fetch the Proof.
                    continue;
                }
                adaptive.observe_need_more(
                    &config,
                    &digests,
                    &pending,
                    sent_this_round,
                    received_this_round,
                    round_send_wall,
                    control_wait,
                    total_bytes,
                );
                let source_fec_fallback_trigger = source_retransmit_needs_fec_fallback(
                    &config,
                    feedback_rounds,
                    source_symbols.len(),
                );
                source_fec_fallback_active |= source_fec_fallback_trigger;
                round_tuning = if source_fec_fallback_active {
                    adaptive.source_fec_fallback_tuning(&config)
                } else {
                    adaptive.round_tuning(&config)
                };
                pacer.configure(round_tuning.pacing);
                rqtrace!(
                    "sender: NeedMore round={feedback_rounds} pending={} source_requests={} sent_this_round={} received_this_round={} send_wall_ms={} control_wait_ms={} repair_overhead={:.4} path_rate_bps={} repair_loss_ema={:.4} pacing_loss_ema={:.4} repair_loss_bar={:.4} pacing_loss_bar={:.4} fec_fallback={}",
                    pending.len(),
                    source_symbols.len(),
                    sent_this_round,
                    received_this_round,
                    round_send_wall.as_millis(),
                    control_wait.as_millis(),
                    round_tuning.repair_overhead,
                    round_tuning.pacing.path_rate_bps,
                    adaptive.loss_ema,
                    adaptive.pacing_loss_ema,
                    adaptive.loss_bar,
                    adaptive.pacing_loss_bar,
                    source_fec_fallback_active,
                );
                if source_symbols.is_empty() {
                    round_started = Instant::now();
                    round_symbols_start = symbols_sent;
                    // Fresh repair symbols (true encoder ESIs, via the
                    // cumulative cursor in each EntryEncoder) for the
                    // still-pending entries.
                    spray_round(
                        cx,
                        &mut control,
                        &mut adaptive,
                        &mut sockets,
                        &mut rr,
                        &mut symbols_sent,
                        &mut dropper,
                        tag,
                        &mut encoders,
                        &pending,
                        &config,
                        &mut pacer,
                        &round_tuning,
                        symbol_auth.as_ref(),
                        /* with_source */ false,
                        parallel_encode,
                    )
                    .await?;
                    round_send_wall = round_started.elapsed();
                } else {
                    round_started = Instant::now();
                    round_symbols_start = symbols_sent;
                    spray_source_requests(
                        cx,
                        &mut control,
                        &mut adaptive,
                        &mut sockets,
                        &mut rr,
                        &mut symbols_sent,
                        &mut dropper,
                        tag,
                        &encoders,
                        &source_symbols,
                        &config,
                        &mut pacer,
                        symbol_auth.as_ref(),
                    )
                    .await?;
                    if source_fec_fallback_active {
                        spray_round(
                            cx,
                            &mut control,
                            &mut adaptive,
                            &mut sockets,
                            &mut rr,
                            &mut symbols_sent,
                            &mut dropper,
                            tag,
                            &mut encoders,
                            &pending,
                            &config,
                            &mut pacer,
                            &round_tuning,
                            symbol_auth.as_ref(),
                            /* with_source */ false,
                            parallel_encode,
                        )
                        .await?;
                    }
                    round_send_wall = round_started.elapsed();
                }
            }
            other => {
                return Err(RqError::Unexpected {
                    got: other,
                    expected: "Proof | NeedMore | KeepAlive",
                });
            }
        }
    }
}

/// Legacy ceiling for per-round repair increments.
///
/// This preserves the old high-loss convergence cap while letting clean-link
/// feedback rounds avoid spraying a fixed K/4 parity burst for a sparse tail.
fn max_feedback_repair_batch_per_block(block_source_n: usize) -> usize {
    (block_source_n / 4).max(16)
}

fn adaptive_feedback_repair_batch_per_block(block_source_n: usize, repair_overhead: f64) -> usize {
    if repair_overhead <= 1.0 {
        return 1;
    }

    let matched = ((block_source_n as f64) * (repair_overhead - 1.0)).ceil() as usize;
    matched
        .max(1)
        .min(max_feedback_repair_batch_per_block(block_source_n))
}

fn initial_repair_target_per_block(block_source_n: usize, repair_overhead: f64) -> usize {
    if repair_overhead <= 1.0 {
        0
    } else {
        ((block_source_n as f64) * (repair_overhead - 1.0)).ceil() as usize
    }
}

fn repair_target_for_feedback_round(
    block_source_n: usize,
    already: usize,
    repair_overhead: f64,
) -> usize {
    let calibrated_total = initial_repair_target_per_block(block_source_n, repair_overhead);
    if calibrated_total > already {
        calibrated_total
    } else {
        already + adaptive_feedback_repair_batch_per_block(block_source_n, repair_overhead)
    }
}

fn source_retransmit_request_limit(config: &RqConfig, feedback_round: u32) -> Option<usize> {
    if config.repair_overhead <= 1.0
        && config.source_retransmit_rounds > 0
        && feedback_round <= config.source_retransmit_rounds
    {
        Some(config.max_source_retransmit_requests)
    } else {
        None
    }
}

fn source_retransmit_needs_fec_fallback(
    config: &RqConfig,
    feedback_round: u32,
    requested_sources: usize,
) -> bool {
    if config.repair_overhead > 1.0 || config.source_retransmit_rounds == 0 {
        return false;
    }
    let saturated_request = config.max_source_retransmit_requests != 0
        && requested_sources >= config.max_source_retransmit_requests;
    saturated_request || feedback_round >= config.source_retransmit_rounds
}

/// Above this total transfer size the parallel per-block encode is disabled and the sequential
/// (encode-paced) spray is used instead. The receiver sizes its UDP recv buffer to absorb the
/// parallel sender's burst, but that buffer is clamped near `net.core.rmem_max`; once a transfer
/// exceeds what the buffer can hold, an unpaced parallel burst would overrun the CPU-bound decoder
/// and trigger a feedback-round explosion. Below the cap the burst is absorbed and the encode
/// parallelism is a pure win. Parallel decode + a rate-paced encode-ahead ring are what lift this
/// cap for very large objects.
const PARALLEL_ENCODE_MAX_BYTES: u64 = 112 * 1024 * 1024;

/// Upper bound on the number of source blocks we fan out across the blocking pool in one round.
/// Above this the manual block enumeration would risk diverging from the canonical encoder's `u8`
/// SBN envelope, so we fall back to the sequential encode-paced spray.
const MAX_RAPTORQ_SOURCE_BLOCKS: usize = 256;

/// Whether a round-0 (`with_source`) spray should fan its per-block RaptorQ solves out across the
/// runtime blocking pool. We parallelize only multi-block objects (a single/empty block would only
/// pay pool-dispatch latency and lose the small-object latency win), only while `parallel_encode`
/// is on (the transfer fits under [`PARALLEL_ENCODE_MAX_BYTES`]), and only within the `u8` SBN
/// envelope.
fn should_parallel_encode_source_blocks(block_count: usize, parallel_encode: bool) -> bool {
    parallel_encode && block_count > 1 && block_count <= MAX_RAPTORQ_SOURCE_BLOCKS
}

/// Encode one RaptorQ source block (its `K` source symbols plus `repair_count` repair symbols) into
/// an owned `Vec<Symbol>`.
///
/// Runs on the blocking pool for [`spray_round`]'s parallel per-block encode.
/// [`EncodingPipeline::encode_single_block_with_repair`] preserves the exact object/SBN/ESI layout
/// the sequential per-block path would have produced for `sbn`, so the emitted symbols are
/// byte-identical regardless of which thread minted them — the speedup is a pure throughput
/// isomorphism (decode is order-independent and the receiver verifies sha256 + merkle). The error
/// is stringified because the closure crosses the `spawn_blocking` boundary, where the return type
/// need only be `Send`.
fn encode_block_symbols(
    cfg: &crate::config::EncodingConfig,
    object_id: ObjectId,
    sbn: u8,
    data: &[u8],
    repair_count: usize,
) -> Result<Vec<Symbol>, String> {
    let pool = SymbolPool::new(PoolConfig::default());
    let mut pipeline = EncodingPipeline::new(cfg.clone(), pool);
    let mut out = Vec::new();
    for encoded in pipeline.encode_single_block_with_repair(object_id, sbn, data, repair_count) {
        out.push(encoded.map_err(|e| e.to_string())?.into_symbol());
    }
    Ok(out)
}

/// Spray one round of symbols for the `pending` entries across the UDP sockets.
///
/// Round 0 (`with_source`) sends every block's source symbols plus optional
/// `repair_overhead` extra repair. Feedback rounds send only *newly minted*
/// repair symbols, identified per block by the encoder's own (sbn, esi) — the
/// repair payload is bound to its ESI, so it is emitted verbatim and never
/// relabeled. Per-block repair cursors advance so each round's repair is fresh
/// for every source block in a pending entry.
#[allow(clippy::too_many_arguments)]
async fn spray_round<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    adaptive: &mut RqAdaptiveSendState,
    sockets: &mut [UdpSocket],
    rr: &mut usize,
    symbols_sent: &mut u64,
    dropper: &mut u32,
    tag: u64,
    encoders: &mut [EntryEncoder],
    pending: &BTreeSet<u32>,
    config: &RqConfig,
    pacer: &mut RqSprayPacer,
    round_tuning: &RqRoundTuning,
    symbol_auth: Option<&SecurityContext>,
    with_source: bool,
    parallel_encode: bool,
) -> Result<(), RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    for enc in encoders.iter_mut().filter(|e| pending.contains(&e.index)) {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let mut ring = EncodeAheadRing::default();
        let blocks = encode_ahead_blocks(enc.size, config)?;
        if enc.repair_cursors.len() > blocks.len() {
            enc.repair_cursors.truncate(blocks.len());
        }
        if enc.repair_cursors.len() < blocks.len() {
            enc.repair_cursors.resize(blocks.len(), 0);
        }

        let use_parallel_source_encode =
            with_source && should_parallel_encode_source_blocks(blocks.len(), parallel_encode);
        if use_parallel_source_encode {
            // Parallel per-block encode on the runtime blocking pool. Each RaptorQ source block
            // solves independently, so for multi-block objects we fan the K-symbol solves across
            // cores instead of grinding them one-at-a-time on a single core (the measured
            // large-file bottleneck: ~99% of one core for an 8 MiB / K=8192 block). Blocks are
            // encoded and sprayed in SBN order, so the wire output is byte-identical to the
            // sequential path — a pure throughput isomorphism (decode is order-independent; the
            // receiver verifies sha256 + merkle). Bounded BATCHES (degree = host parallelism) cap
            // peak symbol RAM at ~`par_batch` blocks; each batch is joined before the next
            // checkpoint so a cancelled region drains every encode task (no strands).
            let enc_cfg = crate::config::EncodingConfig {
                repair_overhead: round_tuning.repair_overhead,
                max_block_size: config.max_block_size,
                symbol_size: config.symbol_size,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            };
            let par_batch = std::thread::available_parallelism()
                .map_or(4, std::num::NonZeroUsize::get)
                .clamp(2, 64);
            for window_start in (0..blocks.len()).step_by(par_batch) {
                cx.checkpoint().map_err(|_| RqError::Cancelled)?;
                let window_end = (window_start + par_batch).min(blocks.len());
                let window = &blocks[window_start..window_end];
                let mut handles = Vec::with_capacity(window.len());
                for (window_offset, block) in window.iter().enumerate() {
                    // Disk reads are cheap relative to the RaptorQ solve, so read each block's
                    // source range here and hand the owned bytes to the pool task.
                    let read_start =
                        enc.source_offset.checked_add(block.start).ok_or_else(|| {
                            RqError::Coding("encode source range offset overflow".to_string())
                        })?;
                    let block_bytes =
                        read_source_range(&enc.abs_path, read_start, block.len).await?;
                    let object_id = enc.object_id;
                    let sbn = block.sbn;
                    let block_index = window_start + window_offset;
                    let repair =
                        initial_repair_target_per_block(block.k, round_tuning.repair_overhead);
                    let cfg = enc_cfg.clone();
                    let handle = cx
                        .spawn_blocking(move |_child| {
                            encode_block_symbols(&cfg, object_id, sbn, &block_bytes, repair)
                        })
                        .map_err(|e| RqError::Coding(format!("encode spawn failed: {e:?}")))?;
                    handles.push((block_index, repair, handle));
                }
                for (block_index, target_repair, mut handle) in handles {
                    let syms = match handle.join(cx).await {
                        Ok(Ok(syms)) => syms,
                        Ok(Err(e)) => return Err(RqError::Coding(e)),
                        Err(join_err) => {
                            return Err(RqError::Coding(format!(
                                "encode task failed: {join_err:?}"
                            )));
                        }
                    };
                    send_symbol_datagrams(
                        cx,
                        control,
                        adaptive,
                        sockets,
                        rr,
                        symbols_sent,
                        dropper,
                        tag,
                        enc.index,
                        &syms,
                        config,
                        pacer,
                        symbol_auth,
                    )
                    .await?;
                    enc.repair_cursors[block_index] = target_repair;
                }
            }
        } else {
            for (block_index, block) in blocks.iter().enumerate() {
                // Cumulative repair count requested from the encoder for this
                // block. The encoder always yields repair symbols at
                // deterministic ESIs starting at the block's K'; requesting
                // more just extends the tail. We skip the already-sent repair
                // symbols for this block and emit the rest at their TRUE ESIs.
                let already = enc.repair_cursors[block_index];
                let target_repair = if with_source {
                    initial_repair_target_per_block(block.k, round_tuning.repair_overhead)
                } else {
                    repair_target_for_feedback_round(block.k, already, round_tuning.repair_overhead)
                };
                let repair_count = target_repair.saturating_sub(already);
                if !with_source && repair_count == 0 {
                    enc.repair_cursors[block_index] = target_repair;
                    continue;
                }

                // The encoder's `Symbol` output owns its payload buffer, so buffers
                // allocated from `SymbolPool` are consumed rather than returned to
                // the pool. Keep the M=1 encode-ahead path unpooled; round sizing,
                // UDP pacing, and receiver-side limits own memory pressure.
                let pool = SymbolPool::new(PoolConfig::default());
                let mut pipeline = EncodingPipeline::new(
                    crate::config::EncodingConfig {
                        repair_overhead: round_tuning.repair_overhead,
                        max_block_size: config.max_block_size,
                        symbol_size: config.symbol_size,
                        encoding_parallelism: 1,
                        decoding_parallelism: 1,
                    },
                    pool,
                );
                let read_start = enc.source_offset.checked_add(block.start).ok_or_else(|| {
                    RqError::Coding("encode source range offset overflow".to_string())
                })?;
                let block_bytes = read_source_range(&enc.abs_path, read_start, block.len).await?;

                let mut send_batch = RqPendingSendBatch::new(sockets.len());
                if with_source {
                    for encoded in pipeline.encode_single_block_with_repair(
                        enc.object_id,
                        block.sbn,
                        &block_bytes,
                        target_repair,
                    ) {
                        let encoded = encoded.map_err(|e| RqError::Coding(e.to_string()))?;
                        ring.push(EncodeAheadSymbol::from_encoded(enc.index, encoded))?;
                        let produced = ring.pop().expect("M=1 ring drains immediately");
                        queue_symbol_datagram(
                            cx,
                            control,
                            adaptive,
                            sockets,
                            rr,
                            symbols_sent,
                            dropper,
                            tag,
                            produced.entry,
                            &produced.symbol,
                            config,
                            pacer,
                            symbol_auth,
                            &mut send_batch,
                        )
                        .await?;
                        debug_assert!(ring.is_empty());
                    }
                } else {
                    for encoded in pipeline.encode_single_block_repair_range(
                        enc.object_id,
                        block.sbn,
                        &block_bytes,
                        already,
                        repair_count,
                    ) {
                        let encoded = encoded.map_err(|e| RqError::Coding(e.to_string()))?;
                        ring.push(EncodeAheadSymbol::from_encoded(enc.index, encoded))?;
                        let produced = ring.pop().expect("M=1 ring drains immediately");
                        queue_symbol_datagram(
                            cx,
                            control,
                            adaptive,
                            sockets,
                            rr,
                            symbols_sent,
                            dropper,
                            tag,
                            produced.entry,
                            &produced.symbol,
                            config,
                            pacer,
                            symbol_auth,
                            &mut send_batch,
                        )
                        .await?;
                        debug_assert!(ring.is_empty());
                    }
                }
                send_batch.flush(sockets, symbols_sent).await?;
                service_rq_spray_control(cx, control, adaptive).await?;
                enc.repair_cursors[block_index] = target_repair;
            }
        }
    }
    Ok(())
}

async fn hash_source_entry_streaming(
    entry: &RqSourceEntry,
    buf: &mut [u8],
) -> Result<(u64, crate::atp::object::ObjectId, [u8; 32]), StreamingError> {
    if entry.source_offset == 0 && entry.source_len.is_none() {
        return hash_file_streaming(&entry.abs_path, buf).await;
    }
    let len = entry.source_len.ok_or_else(|| {
        StreamingError::new(format!(
            "{}: ranged source entry missing source_len",
            entry.abs_path.display()
        ))
    })?;
    hash_file_range_streaming(&entry.abs_path, entry.source_offset, len, buf).await
}

async fn hash_file_range_streaming(
    path: &Path,
    offset: u64,
    len: u64,
    buf: &mut [u8],
) -> Result<(u64, crate::atp::object::ObjectId, [u8; 32]), StreamingError> {
    let mut file = crate::fs::File::open(path)
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", path.display())))?;
    file.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", path.display())))?;

    let mut sha = Sha256::new();
    let mut cid = crate::atp::object::ContentId::streaming();
    let mut remaining = len;
    let mut size = 0u64;
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
        let n = file
            .read(&mut buf[..want])
            .await
            .map_err(|e| StreamingError::new(format!("{}: {e}", path.display())))?;
        if n == 0 {
            return Err(StreamingError::new(format!(
                "{}: short read while hashing source range offset={offset} len={len}",
                path.display()
            )));
        }
        sha.update(&buf[..n]);
        cid.update(&buf[..n]);
        let n_u64 = n as u64;
        remaining -= n_u64;
        size = size.saturating_add(n_u64);
    }

    Ok((
        size,
        crate::atp::object::ObjectId::content(cid.finalize()),
        sha.finalize().into(),
    ))
}

async fn read_source_range(path: &Path, offset: usize, len: usize) -> Result<Vec<u8>, RqError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let offset_u64 = u64::try_from(offset).map_err(|_| {
        RqError::Coding(format!(
            "{}: source range offset does not fit u64: {offset}",
            path.display()
        ))
    })?;
    let mut file = crate::fs::File::open(path)
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
    file.seek(std::io::SeekFrom::Start(offset_u64))
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes)
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
async fn spray_source_requests<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    adaptive: &mut RqAdaptiveSendState,
    sockets: &mut [UdpSocket],
    rr: &mut usize,
    symbols_sent: &mut u64,
    dropper: &mut u32,
    tag: u64,
    encoders: &[EntryEncoder],
    requests: &[SourceSymbolRequest],
    config: &RqConfig,
    pacer: &mut RqSprayPacer,
    symbol_auth: Option<&SecurityContext>,
) -> Result<(), RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut send_batch = RqPendingSendBatch::new(sockets.len());
    for request in requests {
        let enc = encoders
            .iter()
            .find(|enc| enc.index == request.entry)
            .ok_or_else(|| {
                RqError::Coding(format!(
                    "receiver requested source symbol for unknown entry {}",
                    request.entry
                ))
            })?;
        let sym = source_symbol_for_request(enc, *request, config).await?;

        queue_symbol_datagram(
            cx,
            control,
            adaptive,
            sockets,
            rr,
            symbols_sent,
            dropper,
            tag,
            enc.index,
            &sym,
            config,
            pacer,
            symbol_auth,
            &mut send_batch,
        )
        .await?;
    }
    send_batch.flush(sockets, symbols_sent).await?;
    service_rq_spray_control(cx, control, adaptive).await?;
    rqtrace!(
        "sender: retransmitted {} requested source symbols",
        requests.len()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_symbol_datagrams<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    adaptive: &mut RqAdaptiveSendState,
    sockets: &mut [UdpSocket],
    rr: &mut usize,
    symbols_sent: &mut u64,
    dropper: &mut u32,
    tag: u64,
    entry: u32,
    symbols: &[Symbol],
    config: &RqConfig,
    pacer: &mut RqSprayPacer,
    symbol_auth: Option<&SecurityContext>,
) -> Result<(), RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut send_batch = RqPendingSendBatch::new(sockets.len());
    for sym in symbols {
        queue_symbol_datagram(
            cx,
            control,
            adaptive,
            sockets,
            rr,
            symbols_sent,
            dropper,
            tag,
            entry,
            sym,
            config,
            pacer,
            symbol_auth,
            &mut send_batch,
        )
        .await?;
    }
    send_batch.flush(sockets, symbols_sent).await?;
    service_rq_spray_control(cx, control, adaptive).await
}

#[allow(clippy::too_many_arguments)]
async fn queue_symbol_datagram<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    adaptive: &mut RqAdaptiveSendState,
    sockets: &mut [UdpSocket],
    rr: &mut usize,
    symbols_sent: &mut u64,
    dropper: &mut u32,
    tag: u64,
    entry: u32,
    sym: &Symbol,
    config: &RqConfig,
    pacer: &mut RqSprayPacer,
    symbol_auth: Option<&SecurityContext>,
    send_batch: &mut RqPendingSendBatch,
) -> Result<(), RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;
    if config.debug_drop_one_in > 0 {
        *dropper = dropper.wrapping_add(1);
        if *dropper % config.debug_drop_one_in == 0 {
            return Ok(());
        }
    }

    pacer.before_send(cx).await?;
    let auth = symbol_auth.map(|ctx| ctx.sign_symbol(sym));
    let dgram =
        encode_symbol_datagram(tag, entry, sym, auth.as_ref().map(AuthenticatedSymbol::tag));
    let fanout = send_batch.fanout();
    let socket_index = *rr % fanout;
    *rr = rr.wrapping_add(1);
    send_batch.push(socket_index, dgram);
    if send_batch.should_flush() {
        send_batch.flush(sockets, symbols_sent).await?;
        service_rq_spray_control(cx, control, adaptive).await?;
    }
    Ok(())
}

async fn service_rq_spray_control<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    adaptive: &mut RqAdaptiveSendState,
) -> Result<(), RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;
    while let Some(frame) = control.try_recv_ready().await? {
        match frame.frame_type() {
            FrameType::KeepAlive => adaptive.mark_control_peer_activity(),
            FrameType::Close => {
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed control during RQ spray",
                )));
            }
            // The receiver converged (or wants more) and sent a terminal/feedback frame while we
            // are still spraying — a fast-transfer race. Do NOT error: stash the frame so the
            // post-spray feedback loop's `recv()` handles it (Proof -> finalize, ObjectRequest ->
            // next round). Stop draining now; remaining sprayed symbols are harmless (the receiver
            // ignores extras and the sha256+merkle commit gate still verifies). Fixes zz35zq.
            _ => {
                control.stashed = Some(frame);
                break;
            }
        }
    }

    if adaptive.next_control_keepalive_due() {
        let frame =
            Frame::empty(FrameType::KeepAlive).map_err(|err| RqError::Frame(err.to_string()))?;
        control.send(&frame).await?;
    }

    if adaptive.control_liveness_expired() {
        return Err(RqError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "peer liveness expired during RQ spray after {} missed beacon probes",
                adaptive.missed_control_probes()
            ),
        )));
    }

    Ok(())
}

async fn source_symbol_for_request(
    enc: &EntryEncoder,
    request: SourceSymbolRequest,
    config: &RqConfig,
) -> Result<Symbol, RqError> {
    if request.entry != enc.index {
        return Err(RqError::Coding(format!(
            "source request entry mismatch: request={}, encoder={}",
            request.entry, enc.index
        )));
    }
    let symbol_size = usize::from(config.symbol_size.max(1));
    let block_start = usize::from(request.sbn)
        .checked_mul(config.max_block_size)
        .ok_or_else(|| RqError::Coding("source request block offset overflow".to_string()))?;
    if block_start >= enc.size {
        return Err(RqError::Coding(format!(
            "source request block {} outside entry {} ({} bytes)",
            request.sbn, enc.index, enc.size
        )));
    }

    let block_len = config.max_block_size.min(enc.size - block_start);
    let block_k = block_len.div_ceil(symbol_size).max(1);
    let esi = usize::try_from(request.esi)
        .map_err(|_| RqError::Coding("source request ESI does not fit usize".to_string()))?;
    if esi >= block_k {
        return Err(RqError::Coding(format!(
            "source request esi {} outside entry {} block {} K={}",
            request.esi, enc.index, request.sbn, block_k
        )));
    }

    let start = block_start + esi * symbol_size;
    let end = (start + symbol_size).min(block_start + block_len);
    let mut buffer = vec![0u8; symbol_size];
    if start < end {
        let read_start = enc
            .source_offset
            .checked_add(start)
            .ok_or_else(|| RqError::Coding("source request range offset overflow".to_string()))?;
        let bytes = read_source_range(&enc.abs_path, read_start, end - start).await?;
        buffer[..bytes.len()].copy_from_slice(&bytes);
    }
    Ok(Symbol::new(
        SymbolId::new(enc.object_id, request.sbn, request.esi),
        buffer,
        SymbolKind::Source,
    ))
}

// ─── Public API: receive ─────────────────────────────────────────────────────

/// Accept exactly one transfer (one control connection) on `control_listener`,
/// receiving symbols on a freshly-bound UDP socket, write to `dest_dir`, verify,
/// and return a report.
pub async fn receive_once(
    cx: &Cx,
    control_listener: &TcpListener,
    udp_bind_ip: &str,
    dest_dir: &Path,
    config: RqConfig,
    peer_id: &str,
) -> Result<ReceiveReport, RqError> {
    let (stream, peer) = control_listener.accept().await?;
    receive_connection(cx, stream, peer, udp_bind_ip, dest_dir, config, peer_id).await
}

/// Drive a single accepted control connection through the receive protocol.
pub async fn receive_connection(
    cx: &Cx,
    stream: TcpStream,
    peer: SocketAddr,
    udp_bind_ip: &str,
    dest_dir: &Path,
    config: RqConfig,
    peer_id: &str,
) -> Result<ReceiveReport, RqError> {
    let mut control = FrameTransport::new(stream);
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();

    // Handshake.
    let hello_frame = control.recv().await?;
    if hello_frame.frame_type() != FrameType::Handshake {
        return Err(RqError::Unexpected {
            got: hello_frame.frame_type(),
            expected: "Handshake",
        });
    }
    let hello: Hello = parse_json(&hello_frame)?;
    let accepted = hello.protocol == ATP_RQ_PROTOCOL && hello.symbol_auth == symbol_auth_enabled;

    // Bind the UDP data socket before acking so the sender can spray immediately.
    // Build an owned `SocketAddr` (Copy + 'static) so it satisfies
    // `UdpSocket::bind`'s `'static` address bound and handles IPv6 correctly.
    let bind_ip: std::net::IpAddr = udp_bind_ip
        .parse()
        .map_err(|e| RqError::Source(format!("invalid UDP bind ip '{udp_bind_ip}': {e}")))?;
    let mut udp = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    // Size the receive buffer to ABSORB the sender's symbol burst: the sender now encodes blocks in
    // parallel (F3) and can spray them faster than the CPU-bound decode drains, so we set the buffer
    // to the transfer size plus headroom, clamped to a generous cap (the kernel further caps at
    // net.core.rmem_max). For a transfer that fits, the whole burst lands in the buffer with no
    // kernel drops and the decoder drains at its own pace — turning the parallel encode into a
    // wall-clock win instead of a feedback-round explosion. `total_bytes == 0` (older peers that did
    // not advertise it) falls back to the prior fixed 16 MiB.
    let recv_buf_bytes = if hello.total_bytes == 0 {
        16 * 1024 * 1024
    } else {
        usize::try_from(hello.total_bytes.saturating_add(32 * 1024 * 1024))
            .unwrap_or(usize::MAX)
            .clamp(16 * 1024 * 1024, 120 * 1024 * 1024)
    };
    let _ = udp.tune_buffers(UdpBufferConfig {
        recv_buffer_bytes: Some(recv_buf_bytes),
        send_buffer_bytes: None,
    });
    let udp_port = udp.local_addr()?.port();

    control
        .send(&json_frame(
            FrameType::HandshakeAck,
            &HelloAck {
                accepted,
                peer_id: peer_id.to_string(),
                udp_port,
                reason: if accepted {
                    None
                } else if hello.protocol != ATP_RQ_PROTOCOL {
                    Some(format!(
                        "unsupported protocol {} (this peer speaks {ATP_RQ_PROTOCOL})",
                        hello.protocol
                    ))
                } else if hello.symbol_auth != symbol_auth_enabled {
                    Some(format!(
                        "symbol authentication mismatch: sender={}, receiver={symbol_auth_enabled}",
                        hello.symbol_auth
                    ))
                } else {
                    Some("handshake rejected".to_string())
                },
            },
        )?)
        .await?;
    if !accepted {
        return Err(RqError::HandshakeRejected(
            if hello.protocol != ATP_RQ_PROTOCOL {
                format!("unsupported protocol {}", hello.protocol)
            } else if hello.symbol_auth != symbol_auth_enabled {
                format!(
                    "symbol authentication mismatch: sender={}, receiver={symbol_auth_enabled}",
                    hello.symbol_auth
                )
            } else {
                "handshake rejected".to_string()
            },
        ));
    }

    // Manifest.
    let manifest_frame = control.recv().await?;
    if manifest_frame.frame_type() != FrameType::ObjectManifest {
        return Err(RqError::Unexpected {
            got: manifest_frame.frame_type(),
            expected: "ObjectManifest",
        });
    }
    let manifest = parse_and_validate_manifest_frame(&manifest_frame, &config)?;
    let symbol_size = hello.symbol_size;
    let receiver_max_block_size = usize::try_from(hello.max_block_size).map_err(|_| {
        RqError::Frame(format!(
            "peer max_block_size {} does not fit usize",
            hello.max_block_size
        ))
    })?;
    let staging_dir = create_receive_staging_dir(dest_dir, &manifest.transfer_id).await?;
    let _staging_guard = RqStagingDirGuard::new(staging_dir.clone());
    let source_streaming = config.repair_overhead <= 1.0 && config.source_retransmit_rounds > 0;

    // Per-entry decoders.
    let mut decoders: Vec<EntryDecoder> = manifest
        .entries
        .iter()
        .map(|e| {
            let object_id = entry_object_id(&manifest.transfer_id, e.index);
            let dconfig = DecodingConfig {
                symbol_size,
                max_block_size: receiver_max_block_size,
                repair_overhead: config.repair_overhead,
                min_overhead: 0,
                // RQ repair rows are round-critical: dropping an undecoded
                // block's repair symbols makes the sender re-spray another
                // round. Keep them until block completion; mark_block_complete
                // clears the block immediately after decode.
                max_buffered_symbols: RQ_REPAIR_RECEIVE_SYMBOL_CAP_PER_BLOCK,
                block_timeout: std::time::Duration::from_secs(0),
                verify_auth: symbol_auth_enabled,
            };
            let mut pipeline = if let Some(context) = &symbol_auth {
                DecodingPipeline::with_auth(dconfig, context.clone())
            } else {
                DecodingPipeline::new(dconfig)
            };
            let params = object_params_for(object_id, e.size, symbol_size, hello.max_block_size);
            // set_object_params failure is a metadata bug, surfaced on first feed.
            if let Err(err) = pipeline.set_object_params(params) {
                rqtrace!(
                    "receiver: entry {} set_object_params FAILED: {err:?} (size={}, blocks={}, k={})",
                    e.index,
                    e.size,
                    params.source_blocks,
                    params.symbols_per_block
                );
            }
            let source_blocks =
                source_block_progress_for(e.size, receiver_max_block_size, symbol_size);
            let entry_source_streaming = source_streaming && source_blocks.is_some();
            EntryDecoder {
                index: e.index,
                object_id,
                size: e.size,
                pipeline: Some(pipeline),
                complete: e.size == 0,
                staging_path: staging_dir.join(e.index.to_string()),
                staging_created: false,
                staging_file: None,
                staging_cursor: None,
                staging_unflushed_bytes: 0,
                cache_staging_file: should_cache_entry_staging_file(
                    e.size,
                    manifest.entries.len(),
                ),
                bytes_written: 0,
                max_block_size: receiver_max_block_size,
                source_streaming: entry_source_streaming,
                source_blocks: source_blocks.unwrap_or_default(),
                pending_decodes: Vec::new(),
            }
        })
        .collect();

    let tag = transfer_tag(&manifest.transfer_id);
    let mut symbols_accepted: u64 = 0;
    let mut round_stats = RqDatagramRoundStats::default();
    let mut feedback_rounds: u32 = 0;
    let trace_receiver_intake = std::env::var_os("ATP_RQ_TRACE").is_some();
    let datagram_header_len = if symbol_auth_enabled {
        AUTH_DGRAM_HEADER
    } else {
        DGRAM_HEADER
    };
    let mut rbuf = vec![0u8; usize::from(symbol_size) + datagram_header_len + 64];

    // Drive: alternate between draining UDP symbols and responding to the
    // sender's ObjectComplete on the control channel. We pump UDP between
    // control messages by racing a short-bounded recv against control readiness.
    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;

        // First, drain any control message that is ready (ObjectComplete ends a
        // spray round). We do a blocking control.recv() because the sender only
        // sends ObjectComplete after finishing a spray round, and we have been
        // consuming UDP concurrently via the pump below.
        //
        // To keep v1 correct on the current runtime without a select primitive,
        // we structure it as: pump UDP until the control frame arrives.
        let frame = pump_until_control(
            cx,
            &mut control,
            &mut udp,
            tag,
            symbol_auth_enabled,
            symbol_auth.as_ref(),
            &mut rbuf,
            &mut decoders,
            symbol_size,
            &mut symbols_accepted,
            &mut round_stats,
            trace_receiver_intake,
        )
        .await?;
        rqtrace!(
            "receiver: pump returned {:?}, symbols_accepted={symbols_accepted}",
            frame.frame_type()
        );

        match frame.frame_type() {
            FrameType::ObjectComplete => {
                let drained = drain_round_tail(
                    cx,
                    &mut udp,
                    tag,
                    symbol_auth_enabled,
                    symbol_auth.as_ref(),
                    &mut rbuf,
                    config.round_tail_drain,
                    &mut decoders,
                    symbol_size,
                    &mut symbols_accepted,
                    &mut round_stats,
                    trace_receiver_intake,
                )
                .await?;
                if drained > 0 {
                    rqtrace!("receiver: tail-drained {drained} datagrams after ObjectComplete");
                }
                let completed_decodes = join_all_pending_decodes(cx, &mut decoders).await?;
                if completed_decodes > 0 {
                    rqtrace!(
                        "receiver: finalized {completed_decodes} pending decode job(s) after ObjectComplete"
                    );
                }

                let pending: Vec<u32> = decoders
                    .iter()
                    .filter(|d| !d.complete)
                    .map(|d| d.index)
                    .collect();
                rqtrace!(
                    "receiver: ObjectComplete; {} of {} entries still pending round_symbols_observed={} round_symbols_accepted={} intake_payload_bytes={} intake_micros={} intake_symbols_per_s={} intake_bytes_per_s={} parse_micros={} feed_micros={} recv_micros={} drain_micros={}",
                    pending.len(),
                    decoders.len(),
                    round_stats.observed,
                    round_stats.accepted,
                    round_stats.payload_bytes,
                    round_stats.intake_micros(),
                    round_stats.intake_symbols_per_s(),
                    round_stats.intake_bytes_per_s(),
                    round_stats.parse_micros,
                    round_stats.feed_micros,
                    round_stats.recv_micros,
                    round_stats.drain_micros
                );

                if pending.is_empty() {
                    // Verify + commit + Proof.
                    let receipt = verify_and_commit(
                        &manifest,
                        &mut decoders,
                        dest_dir,
                        symbols_accepted,
                        feedback_rounds,
                    )
                    .await?;
                    control
                        .send(&json_frame(FrameType::Proof, &receipt)?)
                        .await?;
                    for _ in 0..4 {
                        match control.recv().await {
                            Ok(frame) if frame.frame_type() == FrameType::Close => break,
                            Ok(frame)
                                if matches!(
                                    frame.frame_type(),
                                    FrameType::ObjectComplete | FrameType::KeepAlive
                                ) =>
                            {
                                rqtrace!(
                                    "receiver: draining late {:?} while waiting for sender Close",
                                    frame.frame_type()
                                );
                            }
                            Ok(frame) => {
                                rqtrace!(
                                    "receiver: expected sender Close after Proof, got {:?}",
                                    frame.frame_type()
                                );
                                break;
                            }
                            Err(err) => {
                                rqtrace!("receiver: sender Close after Proof unavailable: {err}");
                                break;
                            }
                        }
                    }
                    if !receipt.committed {
                        return Err(RqError::Integrity(
                            receipt
                                .reason
                                .unwrap_or_else(|| "verification failed".to_string()),
                        ));
                    }
                    let committed_paths: Vec<PathBuf> =
                        receipt.committed_paths.iter().map(PathBuf::from).collect();
                    return Ok(ReceiveReport {
                        transfer_id: manifest.transfer_id,
                        bytes_received: receipt.bytes_received,
                        files: receipt.files,
                        committed: true,
                        symbols_accepted,
                        feedback_rounds,
                        committed_paths,
                        peer,
                    });
                }

                // Ask for more symbols for the pending entries.
                feedback_rounds += 1;
                if feedback_rounds > config.max_feedback_rounds {
                    let receipt = ReceiveReceipt {
                        committed: false,
                        bytes_received: 0,
                        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
                        sha_ok: false,
                        merkle_ok: false,
                        symbols_accepted,
                        feedback_rounds,
                        reason: Some(format!(
                            "no convergence after {feedback_rounds} rounds, {} entries pending",
                            pending.len()
                        )),
                        committed_paths: Vec::new(),
                    };
                    let _ = control.send(&json_frame(FrameType::Proof, &receipt)?).await;
                    return Err(RqError::NoConvergence {
                        rounds: feedback_rounds,
                        pending: pending.len(),
                    });
                }
                let source_symbols = source_retransmit_request_limit(&config, feedback_rounds)
                    .map_or_else(Vec::new, |limit| collect_source_requests(&decoders, limit));
                if trace_receiver_intake {
                    let progress = source_progress_for_pending(&decoders, &pending);
                    rqtrace!(
                        "receiver: NeedMore round={feedback_rounds} pending={} source_requests={} round_symbols_observed={} round_symbols_accepted={} symbols_accepted={} intake_payload_bytes={} intake_micros={} intake_symbols_per_s={} intake_bytes_per_s={} parse_micros={} feed_micros={} recv_micros={} drain_micros={} source_received={}/{} pending_decode_jobs={} rank={}/{} rank_deficit={} rank_blocks={}",
                        pending.len(),
                        source_symbols.len(),
                        round_stats.observed,
                        round_stats.accepted,
                        symbols_accepted,
                        round_stats.payload_bytes,
                        round_stats.intake_micros(),
                        round_stats.intake_symbols_per_s(),
                        round_stats.intake_bytes_per_s(),
                        round_stats.parse_micros,
                        round_stats.feed_micros,
                        round_stats.recv_micros,
                        round_stats.drain_micros,
                        progress.source_received,
                        progress.source_needed,
                        progress.pending_decode_jobs,
                        progress.rank,
                        progress.rank_columns,
                        progress.rank_deficit,
                        progress.rank_blocks,
                    );
                }

                control
                    .send(&json_frame(
                        FrameType::ObjectRequest,
                        &NeedMore {
                            pending,
                            source_symbols,
                            round_symbols_observed: Some(round_stats.observed),
                            round_symbols_accepted: Some(round_stats.accepted),
                        },
                    )?)
                    .await?;
                round_stats = RqDatagramRoundStats::default();
            }
            FrameType::KeepAlive => {
                control
                    .send(
                        &Frame::empty(FrameType::KeepAlive)
                            .map_err(|e| RqError::Frame(e.to_string()))?,
                    )
                    .await?;
            }
            FrameType::Close => {
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "sender closed control before transfer completed",
                )));
            }
            other => {
                return Err(RqError::Unexpected {
                    got: other,
                    expected: "ObjectComplete | KeepAlive",
                });
            }
        }
    }
}

/// Feed one received symbol into an entry's decoding pipeline. Returns true if
/// the symbol was a well-formed candidate the pipeline accepted or considered
/// (used only for the accepted-datagram counter, not correctness).
fn source_block_progress_for(
    size: u64,
    max_block_size: usize,
    symbol_size: u16,
) -> Option<Vec<SourceBlockProgress>> {
    if size == 0 {
        return Some(Vec::new());
    }

    let mut blocks = Vec::new();
    let mut start = 0u64;
    let block_size = u64::try_from(max_block_size.max(1)).unwrap_or(u64::MAX);
    let symbol_size = u64::from(symbol_size.max(1));
    while start < size {
        if blocks.len() >= MAX_SOURCE_BLOCKS {
            return None;
        }
        let remaining = size - start;
        let len_u64 = remaining.min(block_size);
        let len = usize::try_from(len_u64).ok()?;
        let k = usize::try_from(len_u64.div_ceil(symbol_size)).ok()?.max(1);
        blocks.push(SourceBlockProgress {
            start,
            len,
            k,
            received: vec![false; k],
            pipeline_seeded: vec![false; k],
            auth_tags: vec![None; k],
            received_count: 0,
            complete: false,
        });
        start = start.checked_add(len_u64)?;
    }
    Some(blocks)
}

fn collect_source_requests(decoders: &[EntryDecoder], limit: usize) -> Vec<SourceSymbolRequest> {
    let mut requests = Vec::new();
    for decoder in decoders {
        if decoder.complete {
            continue;
        }
        if decoder.source_streaming {
            for (sbn, block) in decoder.source_blocks.iter().enumerate() {
                if block.complete {
                    continue;
                }
                for (esi, received) in block.received.iter().enumerate() {
                    if *received {
                        continue;
                    }
                    if limit != 0 && requests.len() >= limit {
                        return requests;
                    }
                    let Ok(esi) = u32::try_from(esi) else {
                        break;
                    };
                    requests.push(SourceSymbolRequest {
                        entry: decoder.index,
                        sbn: u8::try_from(sbn).unwrap_or(u8::MAX),
                        esi,
                    });
                }
            }
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
            |MissingSourceSymbol { sbn, esi }| SourceSymbolRequest {
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

#[derive(Debug, Default, Clone, Copy)]
struct PendingDecodeProgress {
    source_received: usize,
    source_needed: usize,
    pending_decode_jobs: usize,
    rank: usize,
    rank_columns: usize,
    rank_deficit: usize,
    rank_blocks: usize,
}

fn source_progress_for_pending(
    decoders: &[EntryDecoder],
    pending: &[u32],
) -> PendingDecodeProgress {
    let mut progress = PendingDecodeProgress::default();
    for decoder in decoders
        .iter()
        .filter(|decoder| pending.contains(&decoder.index))
    {
        progress.pending_decode_jobs = progress
            .pending_decode_jobs
            .saturating_add(decoder.pending_decodes.len());
        for (sbn, block) in decoder.source_blocks.iter().enumerate() {
            progress.source_received = progress
                .source_received
                .saturating_add(block.received_count);
            progress.source_needed = progress.source_needed.saturating_add(block.k);
            let Some(sbn) = u8::try_from(sbn).ok() else {
                continue;
            };
            let Some(status) = decoder
                .pipeline
                .as_ref()
                .and_then(|pipeline| pipeline.block_status(sbn))
            else {
                continue;
            };
            let Some(rank) = status.rank else {
                continue;
            };
            let deficit = status.rank_deficit.unwrap_or(0);
            progress.rank = progress.rank.saturating_add(rank);
            progress.rank_columns = progress
                .rank_columns
                .saturating_add(rank.saturating_add(deficit));
            progress.rank_deficit = progress.rank_deficit.saturating_add(deficit);
            progress.rank_blocks = progress.rank_blocks.saturating_add(1);
        }
    }
    progress
}

async fn feed_symbol_with_cx(
    cx: &Cx,
    dec: &mut EntryDecoder,
    parsed: &ParsedDatagram,
    payload: &[u8],
    symbol_size: u16,
    symbol_auth: Option<&SecurityContext>,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<bool, RqError> {
    if dec.complete {
        return Ok(false);
    }
    if payload.len() != usize::from(symbol_size) {
        // RaptorQ symbols are fixed-size; ignore malformed/truncated payloads.
        // (The final block's short tail is zero-padded by the encoder, so all
        // emitted symbols are symbol_size bytes.)
        return Ok(false);
    }
    let mut pipeline_auth = None;
    if dec.source_streaming && parsed.kind.is_source() {
        if let Some(tag) = parsed.auth_tag {
            let Some(context) = symbol_auth else {
                return Ok(false);
            };
            let sym = Symbol::new(
                SymbolId::new(dec.object_id, parsed.sbn, parsed.esi),
                payload.to_vec(),
                parsed.kind,
            );
            let mut auth = AuthenticatedSymbol::from_parts(sym, tag);
            if context.verify_authenticated_symbol(&mut auth).is_err() {
                rqtrace!(
                    "receiver: entry {} rejected source-streamed sbn={} esi={} auth tag",
                    dec.index,
                    parsed.sbn,
                    parsed.esi
                );
                return Ok(false);
            }
            if auth.is_verified() {
                return persist_source_symbol(dec, parsed, payload, symbol_size).await;
            }
            pipeline_auth = Some(auth);
        } else if symbol_auth.is_some() {
            return Ok(false);
        } else {
            return persist_source_symbol(dec, parsed, payload, symbol_size).await;
        }
    }
    if dec.pipeline.is_none() {
        return Ok(false);
    }
    let auth = if let Some(auth) = pipeline_auth {
        auth
    } else {
        let sym = Symbol::new(
            SymbolId::new(dec.object_id, parsed.sbn, parsed.esi),
            payload.to_vec(),
            parsed.kind,
        );
        if let Some(tag) = parsed.auth_tag {
            AuthenticatedSymbol::from_parts(sym, tag)
        } else {
            AuthenticatedSymbol::new_unauthenticated(sym)
        }
    };
    let result = dec
        .pipeline
        .as_mut()
        .expect("checked above")
        .feed_streaming_block_deferred(auth);
    let accepted = match result {
        Ok(DeferredSymbolAcceptResult::Decode(job)) => {
            let _ = dispatch_decode_job(
                cx,
                dec,
                job,
                "received repair/source symbol",
                allow_spawn_decode,
                transfer_decode_width,
            )
            .await?;
            true
        }
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted {
            received,
            needed,
        })) => {
            if received >= needed || received % 64 == 0 {
                rqtrace!(
                    "receiver: entry {} accepted sbn={} esi={} kind={:?} received={} needed={}",
                    dec.index,
                    parsed.sbn,
                    parsed.esi,
                    parsed.kind,
                    received,
                    needed
                );
            }
            true
        }
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::DecodingStarted {
            block_sbn,
        })) => {
            rqtrace!(
                "receiver: entry {} started decode block {} via esi={} kind={:?}",
                dec.index,
                block_sbn,
                parsed.esi,
                parsed.kind
            );
            true
        }
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::BlockComplete {
            block_sbn,
            data,
        })) => {
            persist_decoded_block(dec, block_sbn, &data).await?;
            // `persist_decoded_block` may have already completed the entry via the source-block
            // tracker (mixed source+FEC, E-9). Otherwise fall back to the pipeline's own view
            // (the all-FEC / non-source-streaming path).
            if dec.complete
                || dec
                    .pipeline
                    .as_ref()
                    .is_some_and(DecodingPipeline::is_complete)
            {
                dec.complete = true;
                dec.pipeline = None;
            }
            rqtrace!(
                "receiver: entry {} completed block {} via esi={} kind={:?}",
                dec.index,
                block_sbn,
                parsed.esi,
                parsed.kind
            );
            true
        }
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Duplicate)) => {
            rqtrace!(
                "receiver: entry {} duplicate sbn={} esi={} kind={:?}",
                dec.index,
                parsed.sbn,
                parsed.esi,
                parsed.kind
            );
            false
        }
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(reason))) => {
            rqtrace!(
                "receiver: entry {} rejected sbn={} esi={} kind={:?} reason={:?}",
                dec.index,
                parsed.sbn,
                parsed.esi,
                parsed.kind,
                reason
            );
            false
        }
        Err(err) => {
            rqtrace!(
                "receiver: entry {} feed error sbn={} esi={} kind={:?}: {err}",
                dec.index,
                parsed.sbn,
                parsed.esi,
                parsed.kind
            );
            false
        }
    };
    if accepted && dec.source_streaming && parsed.kind.is_repair() {
        seed_source_streaming_pipeline(
            cx,
            dec,
            parsed.sbn,
            symbol_size,
            symbol_auth,
            allow_spawn_decode,
            transfer_decode_width,
        )
        .await?;
    }
    Ok(accepted)
}

#[cfg(test)]
async fn feed_symbol(
    dec: &mut EntryDecoder,
    parsed: &ParsedDatagram,
    payload: &[u8],
    symbol_size: u16,
    symbol_auth: Option<&SecurityContext>,
) -> Result<bool, RqError> {
    let cx = Cx::for_testing();
    let accepted = feed_symbol_with_cx(
        &cx,
        dec,
        parsed,
        payload,
        symbol_size,
        symbol_auth,
        true,
        RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD,
    )
    .await?;
    while !dec.pending_decodes.is_empty() {
        let _ = join_one_pending_decode(&cx, dec).await?;
    }
    Ok(accepted)
}

async fn dispatch_decode_job(
    cx: &Cx,
    dec: &mut EntryDecoder,
    job: BlockDecodeJob,
    trigger: &'static str,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<DecodeDispatch, RqError> {
    let block_sbn = job.sbn();
    let _ = drain_ready_entry_decodes(cx, dec).await?;
    if block_decode_pending(dec, block_sbn) {
        rqtrace!(
            "receiver: entry {} dropped duplicate decode job for block {} from {trigger}",
            dec.index,
            block_sbn
        );
        return Ok(DecodeDispatch::Queued);
    }

    if !allow_spawn_decode {
        let joined = join_one_pending_decode(cx, dec).await?;
        rqtrace!(
            "receiver: entry {} joined {joined} pending decode job(s) before queueing block {} from {trigger} because transfer decode width is saturated",
            dec.index,
            block_sbn
        );
        if dec.complete || dec.pipeline.is_none() || block_decode_pending(dec, block_sbn) {
            return Ok(DecodeDispatch::NoProgress);
        }
    }

    let entry_decode_width = entry_decode_width_budget(dec, transfer_decode_width);
    if !can_spawn_parallel_decode(dec.pending_decodes.len(), entry_decode_width) {
        let joined = join_one_pending_decode(cx, dec).await?;
        rqtrace!(
            "receiver: entry {} joined {joined} pending decode job(s) before queueing block {} from {trigger} (entry_cap={entry_decode_width})",
            dec.index,
            block_sbn
        );
        if dec.complete || dec.pipeline.is_none() || block_decode_pending(dec, block_sbn) {
            return Ok(DecodeDispatch::NoProgress);
        }
    }

    let retry_job = job.clone();
    match cx.spawn_blocking(move |_child| run_block_decode_job(job)) {
        Ok(handle) => {
            dec.pending_decodes
                .push(PendingDecode { block_sbn, handle });
            rqtrace!(
                "receiver: entry {} queued parallel decode block {} from {trigger}",
                dec.index,
                block_sbn
            );
            Ok(DecodeDispatch::Queued)
        }
        Err(crate::runtime::state::SpawnError::RuntimeUnavailable) => {
            let _ = finalize_decode_outcome(
                cx,
                dec,
                run_block_decode_job(retry_job),
                false,
                transfer_decode_width,
            )
            .await?;
            rqtrace!(
                "receiver: entry {} ran decode block {} inline from {trigger} because no runtime spawn gateway is available",
                dec.index,
                block_sbn
            );
            Ok(DecodeDispatch::NoProgress)
        }
        Err(err) => {
            let joined = join_one_pending_decode(cx, dec).await?;
            rqtrace!(
                "receiver: entry {} joined {joined} pending decode job(s) after spawn denial for block {} from {trigger}: {err:?}",
                dec.index,
                block_sbn
            );
            if dec.complete || dec.pipeline.is_none() || block_decode_pending(dec, block_sbn) {
                return Ok(DecodeDispatch::NoProgress);
            }
            match cx.spawn_blocking(move |_child| run_block_decode_job(retry_job)) {
                Ok(handle) => {
                    dec.pending_decodes
                        .push(PendingDecode { block_sbn, handle });
                    rqtrace!(
                        "receiver: entry {} queued parallel decode block {} from {trigger} after spawn-denial backpressure",
                        dec.index,
                        block_sbn
                    );
                    Ok(DecodeDispatch::Queued)
                }
                Err(retry_err) => {
                    rqtrace!(
                        "receiver: entry {} deferred decode block {} from {trigger} after repeated spawn denial: {retry_err:?}",
                        dec.index,
                        block_sbn
                    );
                    if let Some(pipeline) = dec.pipeline.as_mut() {
                        pipeline.cancel_decode_job(block_sbn);
                    }
                    Ok(DecodeDispatch::NoProgress)
                }
            }
        }
    }
}

async fn seed_source_streaming_pipeline(
    cx: &Cx,
    dec: &mut EntryDecoder,
    target_sbn: u8,
    symbol_size: u16,
    symbol_auth: Option<&SecurityContext>,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<(), RqError> {
    if dec.pipeline.is_none() {
        return Ok(());
    }
    if block_decode_pending(dec, target_sbn) {
        return Ok(());
    }
    let symbol_size = usize::from(symbol_size);
    let target_sbn_index = usize::from(target_sbn);
    if !source_streaming_block_ready_to_seed(dec, target_sbn_index) {
        return Ok(());
    }
    flush_cached_entry_staging_file(dec).await?;
    let Some(mut reader) = crate::fs::File::open(&dec.staging_path).await.ok() else {
        return Ok(());
    };

    // Seed only the repair block and only once retained repair equations plus staged source
    // symbols can reach K. This keeps lossy transfers from retaining source payloads for many
    // partially-repaired blocks while still feeding the same symbols before decode.
    if dec.source_blocks[target_sbn_index].complete {
        return Ok(());
    }

    let sbn = target_sbn_index;
    let k = dec.source_blocks[sbn].k;
    let block_start = dec.source_blocks[sbn].start;
    let block_len = dec.source_blocks[sbn].len;
    let mut source_block = vec![0u8; block_len];
    reader.seek(std::io::SeekFrom::Start(block_start)).await?;
    reader.read_exact(&mut source_block).await?;

    for esi in 0..k {
        let Some((within_block, take, auth_tag)) =
            source_seed_symbol_plan(dec, sbn, esi, symbol_size)?
        else {
            continue;
        };
        let mut payload = vec![0u8; symbol_size];
        payload[..take].copy_from_slice(&source_block[within_block..within_block + take]);

        let sbn_u8 = u8::try_from(sbn).map_err(|_| {
            RqError::Coding(format!("entry {} source seed SBN overflow", dec.index))
        })?;
        let esi_u32 = u32::try_from(esi).map_err(|_| {
            RqError::Coding(format!("entry {} source seed ESI overflow", dec.index))
        })?;
        let symbol = Symbol::new(
            SymbolId::new(dec.object_id, sbn_u8, esi_u32),
            payload,
            SymbolKind::Source,
        );
        let auth_symbol = if symbol_auth.is_some() {
            let tag = auth_tag.ok_or_else(|| {
                RqError::Authentication(format!(
                    "entry {} source seed missing verified auth tag for sbn={sbn} esi={esi}",
                    dec.index
                ))
            })?;
            AuthenticatedSymbol::from_parts(symbol, tag)
        } else {
            AuthenticatedSymbol::new_unauthenticated(symbol)
        };
        let result = dec
            .pipeline
            .as_mut()
            .expect("checked above")
            .feed_streaming_block_deferred(auth_symbol);
        if result.is_ok() {
            dec.source_blocks[sbn].pipeline_seeded[esi] = true;
        }
        match result {
            Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::BlockComplete {
                block_sbn,
                data,
            })) => {
                persist_decoded_block(dec, block_sbn, &data).await?;
                // `persist_decoded_block` may have completed the entry (mixed source+FEC, E-9)
                // and already dropped the pipeline; stop seeding so the next loop iteration does
                // not touch a `None` pipeline.
                if dec.complete
                    || dec
                        .pipeline
                        .as_ref()
                        .is_some_and(DecodingPipeline::is_complete)
                {
                    dec.complete = true;
                    dec.pipeline = None;
                    return Ok(());
                }
            }
            Ok(DeferredSymbolAcceptResult::Immediate(_)) => {}
            Ok(DeferredSymbolAcceptResult::Decode(job)) => {
                match dispatch_decode_job(
                    cx,
                    dec,
                    job,
                    "source-streaming repair seed",
                    allow_spawn_decode,
                    transfer_decode_width,
                )
                .await?
                {
                    DecodeDispatch::Queued => return Ok(()),
                    DecodeDispatch::NoProgress => {}
                }
            }
            Err(err) => {
                rqtrace!(
                    "receiver: entry {} source seed error sbn={} esi={}: {err}",
                    dec.index,
                    sbn,
                    esi
                );
            }
        }
    }

    Ok(())
}

async fn persist_source_symbol(
    dec: &mut EntryDecoder,
    parsed: &ParsedDatagram,
    payload: &[u8],
    symbol_size: u16,
) -> Result<bool, RqError> {
    let sbn = usize::from(parsed.sbn);
    if sbn >= dec.source_blocks.len() {
        return Ok(false);
    }
    let Ok(esi) = usize::try_from(parsed.esi) else {
        return Ok(false);
    };
    let symbol_size = usize::from(symbol_size);
    let Some(within_block) = esi.checked_mul(symbol_size) else {
        return Err(RqError::Coding(format!(
            "entry {} source symbol offset overflow",
            dec.index
        )));
    };

    let (offset, take) = {
        let block = &dec.source_blocks[sbn];
        if block.complete || esi >= block.k || block.received[esi] || within_block >= block.len {
            return Ok(false);
        }
        let take = symbol_size.min(block.len - within_block);
        let offset = block
            .start
            .checked_add(u64::try_from(within_block).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                RqError::Coding(format!("entry {} source symbol offset overflow", dec.index))
            })?;
        (offset, take)
    };

    write_entry_staging_range(dec, offset, &payload[..take]).await?;

    let completed_now = {
        let block = &mut dec.source_blocks[sbn];
        if block.received[esi] {
            return Ok(false);
        }
        block.received[esi] = true;
        block.auth_tags[esi] = parsed.auth_tag;
        block.received_count = block.received_count.saturating_add(1);
        if block.received_count == block.k {
            block.complete = true;
            dec.bytes_written = dec
                .bytes_written
                .checked_add(u64::try_from(block.len).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    RqError::Coding(format!("entry {} byte counter overflow", dec.index))
                })?;
            true
        } else {
            false
        }
    };

    if completed_now {
        rqtrace!(
            "receiver: entry {} completed source-streamed block {}",
            dec.index,
            parsed.sbn
        );
    }
    if dec.source_blocks.iter().all(|block| block.complete) {
        dec.complete = true;
        dec.pipeline = None;
        close_cached_entry_staging_file(dec).await?;
    }
    Ok(true)
}

async fn open_entry_staging_file(dec: &mut EntryDecoder) -> Result<crate::fs::File, RqError> {
    if let Some(parent) = dec.staging_path.parent() {
        crate::fs::create_dir_all(parent).await?;
    }

    if dec.staging_created {
        return Ok(crate::fs::File::options()
            .read(true)
            .write(true)
            .open(&dec.staging_path)
            .await?);
    }

    let file = crate::fs::File::create_new(&dec.staging_path)
        .await
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                RqError::Frame(format!(
                    "staging file already exists for entry {}",
                    dec.index
                ))
            } else {
                RqError::Io(err)
            }
        })?;
    file.set_len(dec.size).await?;
    dec.staging_created = true;
    Ok(file)
}

async fn close_cached_entry_staging_file(dec: &mut EntryDecoder) -> Result<(), RqError> {
    if let Some(mut file) = dec.staging_file.take() {
        file.flush().await?;
    }
    dec.staging_cursor = None;
    dec.staging_unflushed_bytes = 0;
    Ok(())
}

async fn flush_cached_entry_staging_file(dec: &mut EntryDecoder) -> Result<(), RqError> {
    if let Some(file) = dec.staging_file.as_mut() {
        file.flush().await?;
    }
    dec.staging_unflushed_bytes = 0;
    Ok(())
}

async fn write_entry_staging_range(
    dec: &mut EntryDecoder,
    offset: u64,
    data: &[u8],
) -> Result<(), RqError> {
    if dec.cache_staging_file {
        if dec.staging_file.is_none() {
            let file = open_entry_staging_file(dec).await?;
            dec.staging_file = Some(file);
            dec.staging_cursor = None;
            dec.staging_unflushed_bytes = 0;
        }

        let expected_cursor = dec.staging_cursor;
        let next_cursor = offset
            .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                RqError::Coding(format!("entry {} staging cursor overflow", dec.index))
            })?;
        // Clean ATP-RQ transfers arrive mostly as contiguous source symbols.
        // Flush cached staging writes in chunks so large entries avoid
        // per-symbol open/seek/write/flush overhead without holding dirty data
        // unboundedly.
        const SOURCE_STAGE_BUFFER_BYTES: usize = 256 * 1024;
        let unflushed_bytes = dec.staging_unflushed_bytes.saturating_add(data.len());
        let should_flush = unflushed_bytes >= SOURCE_STAGE_BUFFER_BYTES;
        {
            let file = dec
                .staging_file
                .as_mut()
                .expect("staging file opened above");
            if expected_cursor != Some(offset) {
                file.seek(std::io::SeekFrom::Start(offset)).await?;
            }
            file.write_all(data).await?;
            if should_flush {
                file.flush().await?;
            }
        }
        dec.staging_cursor = Some(next_cursor);
        dec.staging_unflushed_bytes = if should_flush { 0 } else { unflushed_bytes };
        return Ok(());
    }

    let mut file = open_entry_staging_file(dec).await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    file.write_all(data).await?;
    file.flush().await?;
    Ok(())
}

async fn create_receive_staging_dir(
    dest_dir: &Path,
    transfer_id: &str,
) -> Result<PathBuf, RqError> {
    for _ in 0..RQ_STAGING_CREATE_ATTEMPTS {
        let staging_seq = RQ_STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
        let staging_dir = dest_dir.join(format!(".atp-rq-staging-{transfer_id}-{staging_seq}"));
        match crate::fs::create_dir(&staging_dir).await {
            Ok(()) => return Ok(staging_dir),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(RqError::Io(err)),
        }
    }

    Err(RqError::Frame(format!(
        "unable to create unique receiver staging directory for transfer {transfer_id}"
    )))
}

async fn reject_destination_symlink_prefix(base: &Path, out_path: &Path) -> Result<(), RqError> {
    let rel = out_path.strip_prefix(base).map_err(|_| {
        RqError::Source(format!(
            "destination path {} is outside safe base {}",
            out_path.display(),
            base.display()
        ))
    })?;

    let mut current = base.to_path_buf();
    reject_existing_symlink(&current).await?;
    for component in rel.components() {
        let Component::Normal(component) = component else {
            return Err(RqError::Source(format!(
                "unsafe destination component in {}",
                out_path.display()
            )));
        };
        current.push(component);
        reject_existing_symlink(&current).await?;
    }
    Ok(())
}

async fn reject_existing_symlink(path: &Path) -> Result<(), RqError> {
    match crate::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_symlink() => Err(RqError::Source(format!(
            "destination path crosses existing symlink: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(RqError::Io(err)),
    }
}

async fn persist_decoded_block(
    dec: &mut EntryDecoder,
    block_sbn: u8,
    data: &[u8],
) -> Result<(), RqError> {
    let block_size = u64::try_from(dec.max_block_size).map_err(|_| {
        RqError::Coding(format!(
            "entry {} max_block_size does not fit u64: {}",
            dec.index, dec.max_block_size
        ))
    })?;
    let offset = u64::from(block_sbn)
        .checked_mul(block_size)
        .ok_or_else(|| RqError::Coding(format!("entry {} block offset overflow", dec.index)))?;
    let end = offset
        .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
        .ok_or_else(|| RqError::Coding(format!("entry {} block end overflow", dec.index)))?;
    if end > dec.size {
        return Err(RqError::Frame(format!(
            "decoded block {} for entry {} overruns declared size {}",
            block_sbn, dec.index, dec.size
        )));
    }

    write_entry_staging_range(dec, offset, data).await?;
    // E-9 fix: `source_blocks[sbn].complete` is the single source of truth for both completion
    // and byte accounting. A block decoded via FEC here can LATER also receive its final source
    // symbols via retransmit; if we do not mark it complete now, `persist_source_symbol` would
    // count this block's bytes a SECOND time (its `received_count == k` path), driving
    // `bytes_written` past the entry size and causing `verify_and_commit` to FALSELY reject a
    // byte-correct transfer as a "per-entry SHA-256 mismatch". Count the block exactly once and
    // mark it done so any late source symbol for it is ignored by `persist_source_symbol`.
    let block_idx = usize::from(block_sbn);
    let already_complete = dec
        .source_blocks
        .get(block_idx)
        .is_some_and(|block| block.complete);
    if !already_complete {
        dec.bytes_written = dec
            .bytes_written
            .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| RqError::Coding(format!("entry {} byte counter overflow", dec.index)))?;
    }
    if let Some(block) = dec.source_blocks.get_mut(block_idx) {
        block.complete = true;
    }
    // When every source block is on disk (via source OR FEC) the entry is complete. This unifies
    // the previously-desynced completion trackers (`source_blocks[].complete` vs
    // `pipeline.is_complete()`) for the mixed source+FEC case, which is what NEITHER tracker fired
    // for before (→ the bad-regime non-convergence). Empty `source_blocks` = non-source-streaming
    // path, whose completion is still owned by `pipeline.is_complete()` at the call sites.
    if !dec.source_blocks.is_empty() && dec.source_blocks.iter().all(|block| block.complete) {
        dec.complete = true;
        dec.pipeline = None;
        close_cached_entry_staging_file(dec).await?;
    }
    Ok(())
}

fn object_params_for(
    object_id: ObjectId,
    size: u64,
    symbol_size: u16,
    max_block_size: u64,
) -> ObjectParams {
    let max_block = usize::try_from(max_block_size).unwrap_or(DEFAULT_MAX_BLOCK_SIZE);
    let s = usize::from(symbol_size.max(1));
    let total = usize::try_from(size).unwrap_or(0);
    // Mirror the encoder's block plan: greedy max_block_size chunks.
    let mut blocks = 0u16;
    let mut max_k = 0usize;
    if total > 0 {
        let mut offset = 0usize;
        while offset < total {
            let len = (total - offset).min(max_block.max(1));
            let k = len.div_ceil(s);
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

/// Read the byte range a packed member occupies from its staging file.
///
/// Thin `u64` wrapper over [`read_source_range`] for [`PackedMember`] offsets;
/// fails closed if the offset/length overflow `usize` or the staging file is
/// shorter than `offset + len` (a short read).
///
/// # Errors
///
/// Returns [`RqError::Coding`] on an out-of-range offset/length, or
/// [`RqError::Source`] on a seek/read failure.
async fn read_member_range(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, RqError> {
    let offset = usize::try_from(offset).map_err(|_| {
        RqError::Coding(format!(
            "{}: packed member offset does not fit usize: {offset}",
            path.display()
        ))
    })?;
    let len = usize::try_from(len).map_err(|_| {
        RqError::Coding(format!(
            "{}: packed member length does not fit usize: {len}",
            path.display()
        ))
    })?;
    read_source_range(path, offset, len).await
}

#[derive(Debug, Clone)]
struct LargeObjectCommitShard {
    staging_path: PathBuf,
    fragment: LargeObjectFragment,
}

async fn hash_large_object_fragments(
    shards: &[LargeObjectCommitShard],
    buf: &mut [u8],
) -> Result<(u64, crate::atp::object::ObjectId, [u8; 32]), RqError> {
    let mut sha = Sha256::new();
    let mut cid = crate::atp::object::ContentId::streaming();
    let mut total = 0u64;
    for shard in shards {
        let mut file = crate::fs::File::open(&shard.staging_path)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", shard.staging_path.display())))?;
        let mut remaining = shard.fragment.len;
        while remaining > 0 {
            let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = file
                .read(&mut buf[..want])
                .await
                .map_err(|e| RqError::Source(format!("{}: {e}", shard.staging_path.display())))?;
            if n == 0 {
                return Err(RqError::Source(format!(
                    "{}: short read while hashing fragment {}",
                    shard.staging_path.display(),
                    shard.fragment.rel_path
                )));
            }
            sha.update(&buf[..n]);
            cid.update(&buf[..n]);
            let n_u64 = n as u64;
            remaining -= n_u64;
            total = total.saturating_add(n_u64);
        }
    }
    Ok((
        total,
        crate::atp::object::ObjectId::content(cid.finalize()),
        sha.finalize().into(),
    ))
}

async fn write_large_object_fragments(
    shards: &[LargeObjectCommitShard],
    out_path: &Path,
    buf: &mut [u8],
) -> Result<(), RqError> {
    let mut out = crate::fs::File::create(out_path).await?;
    for shard in shards {
        let mut file = crate::fs::File::open(&shard.staging_path)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", shard.staging_path.display())))?;
        let mut remaining = shard.fragment.len;
        while remaining > 0 {
            let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = file
                .read(&mut buf[..want])
                .await
                .map_err(|e| RqError::Source(format!("{}: {e}", shard.staging_path.display())))?;
            if n == 0 {
                return Err(RqError::Source(format!(
                    "{}: short read while committing fragment {}",
                    shard.staging_path.display(),
                    shard.fragment.rel_path
                )));
            }
            out.write_all(&buf[..n]).await?;
            remaining -= n as u64;
        }
    }
    out.flush().await?;
    Ok(())
}

/// Verify every entry (SHA-256 + rebuilt merkle root) and, on success, atomically
/// write them to `dest_dir`.
///
/// E-15: an entry with non-empty `members` is a combined RaptorQ object; its
/// staging file is split into the member byte ranges, each member is verified
/// against its own SHA-256, and on commit the member files (not the packed
/// object) are written into place. The merkle root is rebuilt over the LOGICAL
/// files (members flattened), matching the sender's logical root. Verification is
/// fully separated from commit so a sha/merkle mismatch writes NOTHING.
async fn verify_and_commit(
    manifest: &TransferManifest,
    decoders: &mut [EntryDecoder],
    dest_dir: &Path,
    symbols_accepted: u64,
    feedback_rounds: u32,
) -> Result<ReceiveReceipt, RqError> {
    for d in decoders.iter_mut() {
        close_cached_entry_staging_file(d).await?;
        if d.size == 0 && !d.staging_created {
            let mut file = open_entry_staging_file(d).await?;
            file.flush().await?;
        }
    }

    let mut sha_ok = true;
    let mut received: u64 = 0;
    // `logical_digests` holds one digest per LOGICAL file (members flattened) and
    // drives the merkle check, matching the sender's logical root.
    let mut logical_digests: Vec<EntryDigest> = Vec::with_capacity(manifest.entries.len());
    // One commit plan per entry: rename the staging file (unpacked) or split it
    // into member files (packed). Built only during verification; nothing is
    // written until the sha+merkle gate passes.
    enum EntryCommit {
        /// Unpacked entry: rename its staging file to a single destination.
        Rename {
            rel_path: String,
            staging_path: PathBuf,
        },
        /// Packed entry: split the staging file into member byte ranges.
        Split {
            staging_path: PathBuf,
            members: Vec<PackedMember>,
        },
        /// Large-file entry split into ordered RaptorQ objects: reassemble the
        /// shard staging files into one logical destination file.
        Fragments {
            rel_path: String,
            shards: Vec<LargeObjectCommitShard>,
        },
    }
    let mut commits: Vec<EntryCommit> = Vec::with_capacity(manifest.entries.len());
    let mut fragment_groups: BTreeMap<String, Vec<LargeObjectCommitShard>> = BTreeMap::new();
    let mut logical_files: u64 = 0;
    let mut hash_buf = vec![0u8; RQ_STREAM_HASH_BUFFER_SIZE];
    for e in &manifest.entries {
        let Some(decoder) = decoders.iter().find(|d| d.index == e.index) else {
            sha_ok = false;
            continue;
        };
        // Gate on the CONTENT-ADDRESSED truth (actual file size + SHA-256, checked just below),
        // NOT on the `bytes_written` side counter. `bytes_written` is kept for diagnostics but is
        // not load-bearing for the commit decision: a byte-correct file with a transiently
        // miscounted counter must commit (E-9 false-rejection). An incomplete or incorrect file is
        // still rejected by the size+hash check that follows — that is the authoritative gate.
        if !decoder.complete {
            sha_ok = false;
        }
        // Object-level integrity: the staging file's size + SHA-256 must match the
        // manifest entry. This applies to packed objects too (the concatenation).
        let (size, content_id, content_sha256) =
            hash_file_streaming(&decoder.staging_path, &mut hash_buf)
                .await
                .map_err(|e| RqError::Source(e.into_message()))?;
        received = received.saturating_add(size);
        if size != e.size || hex_encode(&content_sha256) != e.sha256_hex {
            sha_ok = false;
        }

        if let Some(fragment) = &e.fragment {
            fragment_groups
                .entry(fragment.rel_path.clone())
                .or_default()
                .push(LargeObjectCommitShard {
                    staging_path: decoder.staging_path.clone(),
                    fragment: fragment.clone(),
                });
        } else if e.members.is_empty() {
            // Normal single-file entry: its content IS the file (byte-identical to
            // the prior wire). Its own digest is the logical digest; rename on commit.
            logical_digests.push(EntryDigest {
                rel_path: e.rel_path.clone(),
                size,
                content_id,
                content_sha256,
            });
            logical_files = logical_files.saturating_add(1);
            commits.push(EntryCommit::Rename {
                rel_path: e.rel_path.clone(),
                staging_path: decoder.staging_path.clone(),
            });
        } else {
            // E-15 packed object: split the staging file into member byte ranges,
            // verify each member's own SHA-256, and build a per-member logical
            // digest. The packed object itself is not committed.
            for member in &e.members {
                let bytes =
                    read_member_range(&decoder.staging_path, member.offset, member.len).await?;
                let member_sha: [u8; 32] = Sha256::digest(&bytes).into();
                if hex_encode(&member_sha) != member.sha256_hex {
                    sha_ok = false;
                }
                let member_content_id = crate::atp::object::ObjectId::content(
                    crate::atp::object::ContentId::from_bytes(&bytes),
                );
                logical_digests.push(EntryDigest {
                    rel_path: member.rel_path.clone(),
                    size: member.len,
                    content_id: member_content_id,
                    content_sha256: member_sha,
                });
                logical_files = logical_files.saturating_add(1);
            }
            commits.push(EntryCommit::Split {
                staging_path: decoder.staging_path.clone(),
                members: e.members.clone(),
            });
        }
    }

    for (rel_path, mut shards) in fragment_groups {
        shards.sort_by_key(|shard| shard.fragment.shard_index);
        let (size, content_id, content_sha256) =
            hash_large_object_fragments(&shards, &mut hash_buf).await?;
        let Some(first) = shards.first() else {
            sha_ok = false;
            continue;
        };
        if size != first.fragment.logical_size
            || hex_encode(&content_sha256) != first.fragment.sha256_hex
        {
            sha_ok = false;
        }
        logical_digests.push(EntryDigest {
            rel_path: rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
        logical_files = logical_files.saturating_add(1);
        commits.push(EntryCommit::Fragments { rel_path, shards });
    }

    let merkle_ok = flat_merkle_root_from_digests(&logical_digests) == manifest.merkle_root_hex;

    let committed = sha_ok && merkle_ok;
    let mut committed_paths: Vec<String> = Vec::new();
    if committed {
        // `root_name` is attacker-controlled off the wire; collapse it to a
        // single safe component so a hostile (absolute / separator-bearing)
        // value cannot escape `dest_dir`.
        let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;

        // Resolve every LOGICAL destination path, rejecting any symlink prefix,
        // before writing anything.
        enum CommitWrite {
            Rename {
                staging_path: PathBuf,
                out_path: PathBuf,
            },
            Member {
                staging_path: PathBuf,
                offset: u64,
                len: u64,
                out_path: PathBuf,
            },
            Fragments {
                shards: Vec<LargeObjectCommitShard>,
                out_path: PathBuf,
            },
        }
        let mut writes: Vec<CommitWrite> = Vec::with_capacity(logical_digests.len());
        for commit in &commits {
            match commit {
                EntryCommit::Rename {
                    rel_path,
                    staging_path,
                } => {
                    let out_path = if manifest.is_directory {
                        join_relative(&base, rel_path)?
                    } else {
                        base.clone()
                    };
                    writes.push(CommitWrite::Rename {
                        staging_path: staging_path.clone(),
                        out_path,
                    });
                }
                EntryCommit::Split {
                    staging_path,
                    members,
                } => {
                    // A packed object only ever occurs inside a directory transfer
                    // (the single-file path never packs), so members join under base.
                    for member in members {
                        let out_path = join_relative(&base, &member.rel_path)?;
                        writes.push(CommitWrite::Member {
                            staging_path: staging_path.clone(),
                            offset: member.offset,
                            len: member.len,
                            out_path,
                        });
                    }
                }
                EntryCommit::Fragments { rel_path, shards } => {
                    let out_path = if manifest.is_directory {
                        join_relative(&base, rel_path)?
                    } else {
                        base.clone()
                    };
                    writes.push(CommitWrite::Fragments {
                        shards: shards.clone(),
                        out_path,
                    });
                }
            }
        }

        for write in &writes {
            let out_path = match write {
                CommitWrite::Rename { out_path, .. }
                | CommitWrite::Member { out_path, .. }
                | CommitWrite::Fragments { out_path, .. } => out_path,
            };
            reject_destination_symlink_prefix(&base, out_path).await?;
        }

        for write in writes {
            match write {
                CommitWrite::Rename {
                    staging_path,
                    out_path,
                } => {
                    if let Some(parent) = out_path.parent() {
                        crate::fs::create_dir_all(parent).await?;
                    }
                    crate::fs::rename(&staging_path, &out_path).await?;
                    committed_paths.push(out_path.display().to_string());
                }
                CommitWrite::Member {
                    staging_path,
                    offset,
                    len,
                    out_path,
                } => {
                    if let Some(parent) = out_path.parent() {
                        crate::fs::create_dir_all(parent).await?;
                    }
                    // Re-read the verified member byte range from the packed staging
                    // file and write it into place (the packed object is consumed,
                    // not renamed). Members are bounded by PACK_TARGET, so this is
                    // O(member) memory.
                    let bytes = read_member_range(&staging_path, offset, len).await?;
                    crate::fs::write(&out_path, &bytes).await?;
                    committed_paths.push(out_path.display().to_string());
                }
                CommitWrite::Fragments { shards, out_path } => {
                    if let Some(parent) = out_path.parent() {
                        crate::fs::create_dir_all(parent).await?;
                    }
                    write_large_object_fragments(&shards, &out_path, &mut hash_buf).await?;
                    committed_paths.push(out_path.display().to_string());
                }
            }
        }
    }

    Ok(ReceiveReceipt {
        committed,
        bytes_received: received,
        files: u32::try_from(logical_files).unwrap_or(u32::MAX),
        sha_ok,
        merkle_ok,
        symbols_accepted,
        feedback_rounds,
        reason: if committed {
            None
        } else if !sha_ok {
            Some("per-entry SHA-256 mismatch".to_string())
        } else {
            Some("merkle-root mismatch".to_string())
        },
        committed_paths,
    })
}

fn parse_symbol_datagram_payload(
    buf: &[u8],
    n: usize,
    tag: u64,
    auth_required: bool,
) -> Option<(ParsedDatagram, &[u8])> {
    let parsed = parse_symbol_header(&buf[..n], tag, auth_required)?;
    let start = parsed.header_len;
    let end = start + parsed.payload_len;
    if end > n {
        return None;
    }
    Some((parsed, &buf[start..end]))
}

#[derive(Debug, Default, Clone, Copy)]
struct RqDatagramIngest {
    observed: bool,
    accepted: bool,
    payload_bytes: u64,
    // Per-symbol receiver-intake stage timing (LEVER-R1): the clean-link wall
    // is the receiver's ~13 MB/s intake rate, not the sender. Auth verification,
    // decode feed/dispatch, and staging writes currently land in feed_micros.
    parse_micros: u64,
    feed_micros: u64,
}

#[derive(Debug, Default, Clone, Copy)]
struct RqDatagramRoundStats {
    observed: u64,
    accepted: u64,
    payload_bytes: u64,
    // LEVER-R1 receiver-intake throughput instrumentation (sums over the round).
    parse_micros: u64,
    feed_micros: u64,
    recv_micros: u64,
    drain_micros: u64,
}

impl RqDatagramRoundStats {
    fn record(&mut self, ingest: RqDatagramIngest) {
        if ingest.observed {
            self.observed = self.observed.saturating_add(1);
            self.payload_bytes = self.payload_bytes.saturating_add(ingest.payload_bytes);
        }
        if ingest.accepted {
            self.accepted = self.accepted.saturating_add(1);
        }
        self.parse_micros = self.parse_micros.saturating_add(ingest.parse_micros);
        self.feed_micros = self.feed_micros.saturating_add(ingest.feed_micros);
    }

    fn merge(&mut self, other: Self) {
        self.observed = self.observed.saturating_add(other.observed);
        self.accepted = self.accepted.saturating_add(other.accepted);
        self.payload_bytes = self.payload_bytes.saturating_add(other.payload_bytes);
        self.parse_micros = self.parse_micros.saturating_add(other.parse_micros);
        self.feed_micros = self.feed_micros.saturating_add(other.feed_micros);
        self.recv_micros = self.recv_micros.saturating_add(other.recv_micros);
        self.drain_micros = self.drain_micros.saturating_add(other.drain_micros);
    }

    fn record_recv_elapsed(&mut self, elapsed: Duration) {
        self.recv_micros = self
            .recv_micros
            .saturating_add(duration_micros_saturating(elapsed));
    }

    fn record_tail_drain_elapsed(&mut self, elapsed: Duration) {
        self.drain_micros = self
            .drain_micros
            .saturating_add(duration_micros_saturating(elapsed));
    }

    fn intake_micros(self) -> u64 {
        self.parse_micros.saturating_add(self.feed_micros)
    }

    fn intake_symbols_per_s(self) -> u64 {
        rate_per_second(self.observed, self.intake_micros())
    }

    fn intake_bytes_per_s(self) -> u64 {
        rate_per_second(self.payload_bytes, self.intake_micros())
    }
}

fn duration_micros_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn elapsed_micros_since(started: Option<Instant>) -> u64 {
    started.map_or(0, |instant| duration_micros_saturating(instant.elapsed()))
}

fn rate_per_second(units: u64, elapsed_micros: u64) -> u64 {
    if elapsed_micros == 0 {
        return 0;
    }
    let rate = u128::from(units).saturating_mul(1_000_000) / u128::from(elapsed_micros);
    u64::try_from(rate).unwrap_or(u64::MAX)
}

async fn feed_datagram_to_decoders(
    cx: &Cx,
    buf: &[u8],
    n: usize,
    tag: u64,
    auth_required: bool,
    symbol_auth: Option<&SecurityContext>,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    trace_intake: bool,
) -> Result<RqDatagramIngest, RqError> {
    let parse_start = trace_intake.then(Instant::now);
    let parsed_opt = parse_symbol_datagram_payload(buf, n, tag, auth_required);
    let parse_micros = elapsed_micros_since(parse_start);
    let Some((parsed, payload)) = parsed_opt else {
        return Ok(RqDatagramIngest::default());
    };
    let Some(pos) = decoders.iter().position(|d| d.index == parsed.entry) else {
        return Ok(RqDatagramIngest::default());
    };
    let decode_width_budget = rq_decode_width_budget(decoders, symbol_size);
    let mut pending_decode_jobs = rq_pending_decode_jobs(decoders);
    if pending_decode_jobs >= decode_width_budget {
        let _ = drain_ready_decodes(cx, decoders).await?;
        pending_decode_jobs = rq_pending_decode_jobs(decoders);
    }
    let allow_spawn_decode = pending_decode_jobs < decode_width_budget;
    let feed_start = trace_intake.then(Instant::now);
    let accepted = feed_symbol_with_cx(
        cx,
        &mut decoders[pos],
        &parsed,
        payload,
        symbol_size,
        symbol_auth,
        allow_spawn_decode,
        decode_width_budget,
    )
    .await?;
    let feed_micros = elapsed_micros_since(feed_start);
    Ok(RqDatagramIngest {
        observed: true,
        accepted,
        payload_bytes: u64::try_from(payload.len()).unwrap_or(u64::MAX),
        parse_micros,
        feed_micros,
    })
}

async fn feed_datagram_batch_to_decoders(
    cx: &Cx,
    batch: &crate::net::UdpRecvBatch,
    tag: u64,
    auth_required: bool,
    symbol_auth: Option<&SecurityContext>,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    trace_intake: bool,
) -> Result<RqDatagramRoundStats, RqError> {
    let mut stats = RqDatagramRoundStats::default();
    for packet in &batch.packets {
        stats.record(
            feed_datagram_to_decoders(
                cx,
                &packet.payload,
                packet.payload.len(),
                tag,
                auth_required,
                symbol_auth,
                decoders,
                symbol_size,
                trace_intake,
            )
            .await?,
        );
    }
    let _ = drain_ready_decodes(cx, decoders).await?;
    Ok(stats)
}

async fn apply_decode_result(
    dec: &mut EntryDecoder,
    result: SymbolAcceptResult,
    decode_elapsed: Duration,
) -> Result<bool, RqError> {
    match result {
        SymbolAcceptResult::BlockComplete { block_sbn, data } => {
            persist_decoded_block(dec, block_sbn, &data).await?;
            if dec.complete
                || dec
                    .pipeline
                    .as_ref()
                    .is_some_and(DecodingPipeline::is_complete)
            {
                dec.complete = true;
                dec.pipeline = None;
            }
            rqtrace!(
                "receiver: entry {} completed parallel decode block {} decode_ms={}",
                dec.index,
                block_sbn,
                decode_elapsed.as_millis()
            );
            Ok(true)
        }
        SymbolAcceptResult::Rejected(reason) => {
            rqtrace!(
                "receiver: entry {} parallel decode rejected reason={reason:?} decode_ms={}",
                dec.index,
                decode_elapsed.as_millis()
            );
            Ok(false)
        }
        SymbolAcceptResult::Accepted { .. }
        | SymbolAcceptResult::DecodingStarted { .. }
        | SymbolAcceptResult::Duplicate => Ok(false),
    }
}

async fn finalize_decode_outcome(
    cx: &Cx,
    dec: &mut EntryDecoder,
    outcome: BlockDecodeOutcome,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<bool, RqError> {
    let Some(pipeline) = dec.pipeline.as_mut() else {
        return Ok(false);
    };
    let decode_elapsed = outcome.elapsed();
    match pipeline.finish_decode_job_deferred(outcome) {
        DeferredSymbolAcceptResult::Immediate(result) => {
            apply_decode_result(dec, result, decode_elapsed).await
        }
        DeferredSymbolAcceptResult::Decode(job) => {
            let block_sbn = job.sbn();
            rqtrace!(
                "receiver: entry {} requeued stale parallel decode block {} decode_ms={}",
                dec.index,
                block_sbn,
                decode_elapsed.as_millis()
            );
            queue_stale_decode_retry(cx, dec, job, allow_spawn_decode, transfer_decode_width)
                .await?;
            Ok(false)
        }
    }
}

async fn queue_stale_decode_retry(
    cx: &Cx,
    dec: &mut EntryDecoder,
    job: BlockDecodeJob,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<(), RqError> {
    let block_sbn = job.sbn();
    if dec.complete || dec.pipeline.is_none() {
        return Ok(());
    }
    if block_decode_pending(dec, block_sbn) {
        return Ok(());
    }

    let entry_decode_width = entry_decode_width_budget(dec, transfer_decode_width);
    if !allow_spawn_decode
        || !can_spawn_parallel_decode(dec.pending_decodes.len(), entry_decode_width)
    {
        if let Some(pipeline) = dec.pipeline.as_mut() {
            pipeline.cancel_decode_job(block_sbn);
        }
        rqtrace!(
            "receiver: entry {} deferred stale decode retry for block {} because decode width is saturated (entry_cap={entry_decode_width})",
            dec.index,
            block_sbn
        );
        return Ok(());
    }

    let inline_job = job.clone();
    match cx.spawn_blocking(move |_child| run_block_decode_job(job)) {
        Ok(handle) => {
            dec.pending_decodes
                .push(PendingDecode { block_sbn, handle });
            Ok(())
        }
        Err(crate::runtime::state::SpawnError::RuntimeUnavailable) => {
            let outcome = run_block_decode_job(inline_job);
            let decode_elapsed = outcome.elapsed();
            let Some(pipeline) = dec.pipeline.as_mut() else {
                return Ok(());
            };
            let result = pipeline.finish_decode_job(outcome);
            let _ = apply_decode_result(dec, result, decode_elapsed).await?;
            Ok(())
        }
        Err(err) => {
            if let Some(pipeline) = dec.pipeline.as_mut() {
                pipeline.cancel_decode_job(block_sbn);
            }
            rqtrace!(
                "receiver: entry {} deferred stale decode retry for block {} after spawn denial: {err:?}",
                dec.index,
                block_sbn
            );
            Ok(())
        }
    }
}

async fn drain_ready_decodes(cx: &Cx, decoders: &mut [EntryDecoder]) -> Result<u64, RqError> {
    let mut completed = 0u64;
    for dec in decoders {
        completed = completed.saturating_add(drain_ready_entry_decodes(cx, dec).await?);
    }
    Ok(completed)
}

async fn join_all_pending_decodes(cx: &Cx, decoders: &mut [EntryDecoder]) -> Result<u64, RqError> {
    let mut completed = 0u64;
    for dec in decoders {
        while let Some(mut pending) = dec.pending_decodes.pop() {
            completed = completed.saturating_add(join_pending_decode(cx, dec, &mut pending).await?);
        }
    }
    Ok(completed)
}

async fn drain_ready_entry_decodes(cx: &Cx, dec: &mut EntryDecoder) -> Result<u64, RqError> {
    let mut completed = 0u64;
    let mut i = 0usize;
    while i < dec.pending_decodes.len() {
        if !dec.pending_decodes[i].handle.is_finished() {
            i += 1;
            continue;
        }
        let mut pending = dec.pending_decodes.swap_remove(i);
        completed = completed.saturating_add(join_pending_decode(cx, dec, &mut pending).await?);
    }
    Ok(completed)
}

async fn join_one_pending_decode(cx: &Cx, dec: &mut EntryDecoder) -> Result<u64, RqError> {
    let Some(mut pending) = dec.pending_decodes.pop() else {
        return Ok(0);
    };
    join_pending_decode(cx, dec, &mut pending).await
}

async fn join_pending_decode(
    cx: &Cx,
    dec: &mut EntryDecoder,
    pending: &mut PendingDecode,
) -> Result<u64, RqError> {
    let block_sbn = pending.block_sbn;
    let outcome = pending.handle.join(cx).await.map_err(|join_err| {
        RqError::Coding(format!(
            "decode task failed for entry {} block {}: {join_err:?}",
            dec.index, block_sbn
        ))
    })?;
    if finalize_decode_outcome(
        cx,
        dec,
        outcome,
        true,
        RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD,
    )
    .await?
    {
        Ok(1)
    } else {
        Ok(0)
    }
}

/// Pump UDP symbol datagrams into the decoders until a control frame arrives.
///
/// The sender finishes a spray round and *then* sends `ObjectComplete` on TCP,
/// so by interleaving `udp.recv` with `control.recv` we absorb the bulk symbols
/// and return as soon as the round's control marker lands. The UDP branch mirrors
/// native QUIC's `recv_batch_from` pump: one readiness-driven receive drains all
/// immediately-ready packets, then full batches get a bounded quiet-drain pass.
async fn pump_until_control<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    udp: &mut UdpSocket,
    tag: u64,
    auth_required: bool,
    symbol_auth: Option<&SecurityContext>,
    rbuf: &mut [u8],
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    symbols_accepted: &mut u64,
    round_stats: &mut RqDatagramRoundStats,
    trace_intake: bool,
) -> Result<Frame, RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    use std::future::{Future, poll_fn};
    use std::pin::Pin;
    use std::task::Poll;

    enum Ready {
        Control(usize),
        Udp(crate::net::UdpRecvBatch),
    }

    let packet_size = rbuf.len();
    let mut cbuf = vec![0u8; 65536];
    let mut pumped: u64 = 0;
    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let _ = drain_ready_decodes(cx, decoders).await?;

        // 1) First, non-blockingly drain whatever the control codec already has
        //    buffered (a prior read may have pulled the frame in with symbols).
        if let Some(frame) = control
            .codec
            .decode(&mut control.rbuf)
            .map_err(|e| RqError::Frame(e.to_string()))?
        {
            rqtrace!(
                "pump: returning {:?} after {pumped} udp datagrams",
                frame.frame_type()
            );
            return Ok(frame);
        }

        // 2) Poll both the control stream and a readiness-driven UDP batch.
        //    Whichever is ready makes progress; if only UDP is ready we keep
        //    pumping symbols. Both register their waker via task_cx, so the task
        //    parks until EITHER fd is ready — a biased two-way select.
        let recv_started = trace_intake.then(Instant::now);
        let ready = {
            let mut udp_batch = Box::pin(udp.recv_batch_from(RQ_INBOUND_PUMP_BATCH, packet_size));
            poll_fn(|task_cx| {
                // UDP first so bulk data drains promptly under load.
                match Future::poll(udp_batch.as_mut(), task_cx) {
                    Poll::Ready(Ok(batch)) => {
                        return Poll::Ready(Ok::<Ready, std::io::Error>(Ready::Udp(batch)));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
                let mut read_buf = ReadBuf::new(&mut cbuf);
                match Pin::new(&mut control.stream).poll_read(task_cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(Ready::Control(read_buf.filled().len()))),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?
        };
        let recv_elapsed = recv_started.map(|started| started.elapsed());

        match ready {
            Ready::Udp(batch) => {
                let mut received_len = batch.packets.len();
                let mut batches = 1usize;
                let mut stats = feed_datagram_batch_to_decoders(
                    cx,
                    &batch,
                    tag,
                    auth_required,
                    symbol_auth,
                    decoders,
                    symbol_size,
                    trace_intake,
                )
                .await?;
                if let Some(elapsed) = recv_elapsed {
                    stats.record_recv_elapsed(elapsed);
                }
                pumped = pumped.saturating_add(stats.observed);
                *symbols_accepted = (*symbols_accepted).saturating_add(stats.accepted);
                round_stats.merge(stats);
                let _ = drain_ready_decodes(cx, decoders).await?;

                while received_len == RQ_INBOUND_PUMP_BATCH {
                    if batches >= RQ_INBOUND_PUMP_MAX_DRAIN_BATCHES {
                        rqtrace!(
                            "pump: udp batch drain budget exhausted after {batches} batches and {pumped} accepted datagrams"
                        );
                        break;
                    }

                    let tail_recv_started = trace_intake.then(Instant::now);
                    let tail = match crate::time::timeout(
                        cx.now(),
                        RQ_INBOUND_PUMP_DRAIN_GRACE,
                        udp.recv_batch_from(RQ_INBOUND_PUMP_BATCH, packet_size),
                    )
                    .await
                    {
                        Ok(Ok(batch)) => batch,
                        Ok(Err(e)) => return Err(RqError::Io(e)),
                        Err(_elapsed) => break,
                    };
                    let tail_recv_elapsed = tail_recv_started.map(|started| started.elapsed());
                    received_len = tail.packets.len();
                    if received_len == 0 {
                        break;
                    }
                    let mut stats = feed_datagram_batch_to_decoders(
                        cx,
                        &tail,
                        tag,
                        auth_required,
                        symbol_auth,
                        decoders,
                        symbol_size,
                        trace_intake,
                    )
                    .await?;
                    if let Some(elapsed) = tail_recv_elapsed {
                        stats.record_tail_drain_elapsed(elapsed);
                    }
                    pumped = pumped.saturating_add(stats.observed);
                    *symbols_accepted = (*symbols_accepted).saturating_add(stats.accepted);
                    round_stats.merge(stats);
                    let _ = drain_ready_decodes(cx, decoders).await?;
                    batches = batches.saturating_add(1);
                }
            }
            Ready::Control(n) => {
                if n == 0 {
                    return Err(RqError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "control stream closed mid-transfer",
                    )));
                }
                control.rbuf.extend_from_slice(&cbuf[..n]);
                if let Some(frame) = control
                    .codec
                    .decode(&mut control.rbuf)
                    .map_err(|e| RqError::Frame(e.to_string()))?
                {
                    return Ok(frame);
                }
            }
        }
    }
}

/// Drain UDP symbols that raced behind the TCP round marker.
///
/// `ObjectComplete` only proves the sender has finished a spray round; it does
/// not prove the receiver has drained every datagram already queued locally. The
/// drain stops after a quiet window with no matching ATP-RQ symbol, with a hard
/// cap of 8x that window so stale or hostile UDP traffic cannot pin the task.
async fn drain_round_tail(
    cx: &Cx,
    udp: &mut UdpSocket,
    tag: u64,
    auth_required: bool,
    symbol_auth: Option<&SecurityContext>,
    rbuf: &mut [u8],
    quiet_window: Duration,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    symbols_accepted: &mut u64,
    round_stats: &mut RqDatagramRoundStats,
    trace_intake: bool,
) -> Result<u64, RqError> {
    if quiet_window.is_zero() {
        return Ok(0);
    }

    use std::future::poll_fn;
    use std::pin::Pin;
    use std::task::Poll;

    let mut quiet_sleep = crate::time::Sleep::after(cx.now_for_observability(), quiet_window);
    let hard_cap = quiet_window.saturating_mul(8).max(Duration::from_millis(1));
    let mut hard_sleep = crate::time::Sleep::after(cx.now_for_observability(), hard_cap);
    let mut drained = 0u64;

    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;

        let drain_started = trace_intake.then(Instant::now);
        let ready = poll_fn(|task_cx| {
            if Pin::new(&mut hard_sleep).poll(task_cx).is_ready() {
                return Poll::Ready(Ok::<Option<usize>, std::io::Error>(None));
            }

            match udp.poll_recv(task_cx, rbuf) {
                Poll::Ready(Ok(n)) => return Poll::Ready(Ok(Some(n))),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }

            if Pin::new(&mut quiet_sleep).poll(task_cx).is_ready() {
                return Poll::Ready(Ok(None));
            }

            Poll::Pending
        })
        .await?;
        let drain_elapsed = drain_started.map(|started| started.elapsed());

        let Some(n) = ready else {
            return Ok(drained);
        };

        let ingest = feed_datagram_to_decoders(
            cx,
            rbuf,
            n,
            tag,
            auth_required,
            symbol_auth,
            decoders,
            symbol_size,
            trace_intake,
        )
        .await?;
        if ingest.observed {
            drained += 1;
            round_stats.record(ingest);
            if let Some(elapsed) = drain_elapsed {
                round_stats.record_tail_drain_elapsed(elapsed);
            }
            if ingest.accepted {
                *symbols_accepted = (*symbols_accepted).saturating_add(1);
            }
            quiet_sleep.reset_after(cx.now_for_observability(), quiet_window);
        }
        let _ = drain_ready_decodes(cx, decoders).await?;

        if drained > 0 && drained % 512 == 0 {
            crate::runtime::yield_now().await;
        }
    }
}

/// Run a persistent accept loop, handling each control connection as one
/// receive.
///
/// Returns when the capability context is cancelled. Connection-level errors are
/// reported via `on_result` and do not stop the loop.
pub async fn serve<F>(
    cx: &Cx,
    control_listener: TcpListener,
    udp_bind_ip: String,
    dest_dir: PathBuf,
    config: RqConfig,
    peer_id: String,
    mut on_result: F,
) -> Result<(), RqError>
where
    F: FnMut(Result<ReceiveReport, RqError>),
{
    loop {
        if cx.is_cancel_requested() {
            return Ok(());
        }
        let (stream, peer) = control_listener.accept().await?;
        let result = receive_connection(
            cx,
            stream,
            peer,
            &udp_bind_ip,
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

    #[test]
    fn parallel_decode_spawn_gate_respects_matrix5_width_cap() {
        assert!(
            RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY <= RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD,
            "entry decode width must not exceed the transfer hard cap"
        );
        assert!(
            RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD >= 32,
            "MATRIX-5 repair decode must fan out on high-core receivers"
        );
        assert!(can_spawn_parallel_decode(
            0,
            RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY
        ));
        assert!(can_spawn_parallel_decode(
            RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY - 1,
            RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY
        ));
        assert!(!can_spawn_parallel_decode(
            RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY,
            RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY
        ));
    }

    #[test]
    fn decode_core_limit_keeps_parallelism_on_four_core_hosts() {
        assert_eq!(rq_decode_core_limit_for_available(1), 1);
        assert_eq!(rq_decode_core_limit_for_available(2), 1);
        assert_eq!(rq_decode_core_limit_for_available(4), 3);
        assert_eq!(rq_decode_core_limit_for_available(8), 6);
        assert_eq!(rq_decode_core_limit_for_available(16), 12);
        assert_eq!(
            rq_decode_core_limit_for_available(64),
            RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD
        );
    }

    #[test]
    fn rq_pacing_carries_path_rate_for_congestion_controller() {
        let pacing = RqSprayPacing::from_rate(
            RQ_COLD_START_PACING_BPS,
            1024,
            RQ_COLD_START_BURST_SYMBOLS,
            None,
            false,
        );
        let symbol_bytes =
            1024_u64.saturating_add(u64::try_from(AUTH_DGRAM_HEADER).unwrap_or(u64::MAX));

        assert_eq!(
            pacing.path_rate_bps,
            RQ_COLD_START_PACING_BPS.saturating_mul(8)
        );
        assert_eq!(pacing.datagram_bytes, u32::try_from(symbol_bytes).unwrap());
        assert_eq!(
            pacing.max_burst_size,
            u32::try_from(RQ_COLD_START_BURST_SYMBOLS).unwrap()
        );
    }

    fn rq_test_path_estimate(config: &RqConfig, bytes_per_second: f64) -> PathEstimate {
        PathEstimate {
            rtt_s: 0.050,
            loss_p_hat: 0.0,
            loss_p_bar: 0.0,
            bw_median_bps: bytes_per_second,
            bw_trough_bps: bytes_per_second,
            enc_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            dec_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            coding_ref_k: fixed_block_k(config),
            coding_gamma: RQ_CODING_GAMMA,
            samples: 1,
        }
    }

    fn rq_test_block_plan(config: &RqConfig) -> BlockPlan {
        BlockPlan {
            k: fixed_block_k(config),
            overhead: 0.0,
            fanout: 1,
        }
    }

    #[test]
    fn rq_pacing_preserves_measured_slow_link_without_loss() {
        let config = RqConfig::default();
        let mut state = RqAdaptiveSendState::new(7, &config, 1);
        let measured = 2_u64 * 1024 * 1024;
        state.est = rq_test_path_estimate(&config, measured as f64);

        let rate = state.pacing_rate_for(rq_test_block_plan(&config));

        assert_eq!(rate, measured);
    }

    #[test]
    fn rq_pacing_floors_mild_loss_collapse() {
        let config = RqConfig::default();
        let mut state = RqAdaptiveSendState::new(7, &config, 1);
        let collapsed = 42_u64 * 1024;
        state.est = rq_test_path_estimate(&config, collapsed as f64);
        state.loss_ema = 0.001;
        state.loss_bar = 0.01;
        state.pacing_loss_ema = 0.001;

        let rate = state.pacing_rate_for(rq_test_block_plan(&config));

        assert!(
            rate >= RQ_COLD_START_PACING_BPS / 2,
            "mild loss should not pace a repair round at {rate} B/s"
        );
        assert!(
            rate > collapsed.saturating_mul(100),
            "floor should break the self-reinforcing 42KB/s collapse"
        );
    }

    #[test]
    fn rq_pacing_floor_stays_off_for_regime_shift_loss() {
        let config = RqConfig::default();
        let mut state = RqAdaptiveSendState::new(7, &config, 1);
        let collapsed = 42_u64 * 1024;
        state.est = rq_test_path_estimate(&config, collapsed as f64);
        state.pacing_loss_ema = RQ_MILD_LOSS_PACING_MAX_LOSS * 2.0;
        state.loss_bar = RQ_REGIME_SHIFT_LOSS_DELTA;

        let rate = state.pacing_rate_for(rq_test_block_plan(&config));

        assert_eq!(rate, RQ_MIN_PACING_BPS);
    }

    #[test]
    fn rq_pacing_mild_loss_floor_overrides_stale_low_cap() {
        let config = RqConfig::default();
        let mut state = RqAdaptiveSendState::new(7, &config, 1);
        state.est = rq_test_path_estimate(&config, 32.0 * 1024.0 * 1024.0);
        state.controller.update_estimate(state.est);
        state.loss_ema = 0.01;
        state.loss_bar = 0.02;
        state.pacing_loss_ema = RQ_MILD_LOSS_PACING_MAX_LOSS / 2.0;
        state.loss_pacing_cap_bps = Some(RQ_COLD_START_PACING_BPS / 4);

        let tuning = state.round_tuning(&config);

        assert_eq!(
            tuning.pacing.path_rate_bps,
            state.mild_loss_pacing_floor_bps().saturating_mul(8),
            "stale mild-loss caps must not reintroduce the pacing crawl"
        );
    }

    #[test]
    fn rq_need_more_entry_pressure_does_not_create_congestion_cap() {
        let config = RqConfig {
            symbol_size: 1024,
            ..RqConfig::default()
        };
        let mut state = RqAdaptiveSendState::new(7, &config, 1);
        let total_bytes = 5_u64 * 1024 * 1024;
        let digests = [EntryDigest {
            rel_path: "large.bin".to_string(),
            size: total_bytes,
            content_id: crate::atp::object::ObjectId::content(
                crate::atp::object::ContentId::from_bytes(b"large.bin"),
            ),
            content_sha256: [0; 32],
        }];
        let pending = BTreeSet::from([0_u32]);
        let sent_symbols = total_bytes / u64::from(config.symbol_size);

        state.observe_need_more(
            &config,
            &digests,
            &pending,
            sent_symbols,
            sent_symbols.saturating_sub(1),
            Duration::from_secs(120),
            Duration::from_millis(50),
            total_bytes,
        );

        assert!(
            state.loss_bar >= RQ_PENDING_PRESSURE_LOSS_FLOOR,
            "large residual entry should still raise the FEC sizing floor"
        );
        assert!(
            state.pacing_loss_ema <= RQ_MILD_LOSS_PACING_MAX_LOSS,
            "entry-level residual pressure must not masquerade as pacing loss"
        );
        assert_eq!(
            state.est.loss_p_bar, state.loss_bar,
            "adaptive path estimate must preserve pending-aware FEC pressure"
        );
        assert!(
            state.pacing_loss_bar < state.loss_bar,
            "wire-loss pacing bar must remain below pending-aware FEC pressure"
        );
        assert_eq!(
            state.loss_pacing_cap_bps, None,
            "one residual pending entry must not manufacture a congestion cap"
        );
        let rate = state.pacing_rate_for(rq_test_block_plan(&config));
        assert!(
            rate >= RQ_COLD_START_PACING_BPS / 2,
            "mild residual repair should recover from the slow-sample floor, got {rate} B/s"
        );
    }

    #[test]
    fn rq_need_more_mild_wire_loss_keeps_pending_pressure_out_of_pacing() {
        let config = RqConfig {
            symbol_size: 1200,
            ..RqConfig::default()
        };
        let mut state = RqAdaptiveSendState::new(7, &config, 1);
        let total_bytes = 50_u64 * 1024 * 1024;
        let digests = [EntryDigest {
            rel_path: "large.bin".to_string(),
            size: total_bytes,
            content_id: crate::atp::object::ObjectId::content(
                crate::atp::object::ContentId::from_bytes(b"large.bin"),
            ),
            content_sha256: [0; 32],
        }];
        let pending = BTreeSet::from([0_u32]);

        for (sent_symbols, send_wall) in [
            (43_700_u64, Duration::from_millis(3_300)),
            (15_992, Duration::from_millis(12_300)),
            (15_992, Duration::from_millis(13_300)),
            (7_800, Duration::from_millis(12_000)),
            (7_800, Duration::from_millis(13_800)),
            (7_800, Duration::from_millis(15_000)),
        ] {
            let lost_symbols = sent_symbols.div_ceil(50);
            state.observe_need_more(
                &config,
                &digests,
                &pending,
                sent_symbols,
                sent_symbols.saturating_sub(lost_symbols),
                send_wall,
                Duration::from_millis(200),
                total_bytes,
            );
        }

        assert!(
            state.loss_bar >= RQ_PENDING_PRESSURE_LOSS_FLOOR,
            "pending pressure should remain available for FEC sizing"
        );
        assert!(
            state.pacing_loss_ema <= RQ_MILD_LOSS_PACING_MAX_LOSS,
            "2% receiver-observed wire loss should keep the mild pacing floor active"
        );
        assert!(
            state.mild_loss_pacing_floor_applies(),
            "entry-granular pending pressure must not disable the pacing floor"
        );
        assert_eq!(
            state.est.loss_p_bar, state.loss_bar,
            "PathEstimate loss bar must keep pending-aware FEC pressure for repair sizing"
        );
        assert!(
            state.pacing_loss_bar < state.loss_bar,
            "receiver-observed wire loss may stay mild while FEC pressure remains high"
        );
        assert!(
            state.pacing_rate_for(rq_test_block_plan(&config))
                >= state.mild_loss_pacing_floor_bps(),
            "stalled repair rounds must not drag pacing below the mild-loss floor"
        );
    }

    #[test]
    fn rq_need_more_broken_wire_loss_disables_mild_floor() {
        let config = RqConfig {
            symbol_size: 1200,
            ..RqConfig::default()
        };
        let mut state = RqAdaptiveSendState::new(7, &config, 1);
        let total_bytes = 50_u64 * 1024 * 1024;
        let digests = [EntryDigest {
            rel_path: "large.bin".to_string(),
            size: total_bytes,
            content_id: crate::atp::object::ObjectId::content(
                crate::atp::object::ContentId::from_bytes(b"large.bin"),
            ),
            content_sha256: [0; 32],
        }];
        let pending = BTreeSet::from([0_u32]);
        let sent_symbols = 43_700_u64;

        state.observe_need_more(
            &config,
            &digests,
            &pending,
            sent_symbols,
            sent_symbols.saturating_sub(sent_symbols.div_ceil(10)),
            Duration::from_millis(3_300),
            Duration::from_millis(200),
            total_bytes,
        );

        assert!(
            state.pacing_loss_ema > RQ_MILD_LOSS_PACING_MAX_LOSS,
            "10% receiver-observed wire loss should exceed the mild-loss threshold"
        );
        assert!(
            !state.mild_loss_pacing_floor_applies(),
            "broken-link wire loss must still allow conservative pacing"
        );
        assert!(
            state.loss_bar >= RQ_PENDING_PRESSURE_LOSS_FLOOR,
            "broken-link pending pressure should still size repair FEC"
        );
    }

    #[test]
    fn rq_pending_send_batch_groups_by_round_robin_socket() {
        let mut batch = RqPendingSendBatch::new(4);
        for i in 0..RQ_SEND_BATCH_GLOBAL_SYMBOLS {
            batch.push(i % 4, vec![u8::try_from(i).unwrap_or(u8::MAX)]);
        }

        assert_eq!(batch.queued_count(), RQ_SEND_BATCH_GLOBAL_SYMBOLS);
        assert!(batch.should_flush());
        assert_eq!(batch.socket_batch_len(0), RQ_SEND_BATCH_GLOBAL_SYMBOLS / 4);
        assert_eq!(batch.socket_batch_len(1), RQ_SEND_BATCH_GLOBAL_SYMBOLS / 4);
        assert_eq!(batch.socket_batch_len(2), RQ_SEND_BATCH_GLOBAL_SYMBOLS / 4);
        assert_eq!(batch.socket_batch_len(3), RQ_SEND_BATCH_GLOBAL_SYMBOLS / 4);
    }

    #[test]
    fn rq_pending_send_batch_flushes_on_single_socket_bound() {
        let mut batch = RqPendingSendBatch::new(4);
        for i in 0..RQ_SEND_BATCH_PER_SOCKET {
            batch.push(0, vec![u8::try_from(i).unwrap_or(u8::MAX)]);
        }

        assert_eq!(batch.queued_count(), RQ_SEND_BATCH_PER_SOCKET);
        assert!(batch.should_flush());
        assert_eq!(batch.socket_batch_len(0), RQ_SEND_BATCH_PER_SOCKET);
        assert_eq!(batch.socket_batch_len(1), 0);
    }

    #[test]
    fn rq_batched_send_yields_when_progress_crosses_boundary() {
        assert!(!send_progress_crossed_yield_boundary(0, 63));
        assert!(send_progress_crossed_yield_boundary(63, 64));
        assert!(send_progress_crossed_yield_boundary(60, 96));
        assert!(!send_progress_crossed_yield_boundary(64, 96));
    }

    #[test]
    fn rq_loss_recommendations_apply_advisory_caps_and_fec_floor() {
        let config = RqConfig::default();
        let mut state = RqAdaptiveSendState::new(7, &config, 1);
        state.bw_ema_bps = 10_000_000.0;

        state.apply_loss_recommendations(
            &[
                LossRecommendation::ReduceCongestionWindow { factor: 0.5 },
                LossRecommendation::EnableFec { rate: 0.10 },
                LossRecommendation::SwitchCongestionControl {
                    algorithm: "bbr".to_string(),
                },
            ],
            false,
        );

        assert_eq!(state.loss_pacing_cap_bps, Some(5_000_000));
        assert!(state.loss_fec_floor >= 0.10);
        assert!(state.regime_shift);
    }

    #[test]
    fn rq_feedback_bandwidth_uses_send_wall_not_feedback_wait() {
        let config = RqConfig::default();
        let mut state = RqAdaptiveSendState::new(23, &config, 1);
        let total_bytes = 5 * 1024 * 1024_u64;
        let sent_symbols = total_bytes.div_ceil(u64::from(config.symbol_size.max(1)));
        let digests = vec![EntryDigest {
            rel_path: "payload.bin".to_string(),
            size: total_bytes,
            content_id: crate::atp::object::ObjectId::content(
                crate::atp::object::ContentId::from_bytes(b"rq-feedback-bandwidth"),
            ),
            content_sha256: [0x42; 32],
        }];
        let pending = BTreeSet::from([0]);

        state.observe_need_more(
            &config,
            &digests,
            &pending,
            sent_symbols,
            sent_symbols,
            Duration::from_millis(300),
            Duration::from_secs(120),
            total_bytes,
        );

        assert!(
            state.bw_ema_bps > 8.0 * 1024.0 * 1024.0,
            "feedback timeout must not collapse a fast spray sample to {} B/s",
            state.bw_ema_bps
        );
    }

    /// In-process encode→feed→decode roundtrip at a chosen `(bytes, max_block)`,
    /// mirroring exactly how `spray_round` encodes and `feed_symbol` decodes —
    /// but with NO network — so a coding/params mismatch is isolated from the
    /// transport. Feeds source + a generous repair tail and asserts the block
    /// decodes back to the original bytes.
    fn coding_roundtrip(len: usize, max_block: usize, symbol_size: u16) -> bool {
        let bytes: Vec<u8> = (0..len)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let object_id = entry_object_id("test-transfer", 0);

        // Encode: source + repair (generous), like spray_round.
        let block_k = max_block.div_ceil(usize::from(symbol_size.max(1))).max(1);
        let repair = block_k; // 100% repair — far more than needed
        let pool = SymbolPool::new(PoolConfig::default());
        let mut enc = EncodingPipeline::new(
            crate::config::EncodingConfig {
                repair_overhead: 1.5,
                max_block_size: max_block,
                symbol_size,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            pool,
        );
        let symbols: Vec<Symbol> = enc
            .encode_with_repair(object_id, &bytes, repair)
            .map(|e| e.unwrap().into_symbol())
            .collect();

        // Decode: feed all symbols, like feed_symbol.
        let dconfig = DecodingConfig {
            symbol_size,
            max_block_size: max_block,
            repair_overhead: 1.5,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: std::time::Duration::from_secs(0),
            verify_auth: false,
        };
        let mut dec = DecodingPipeline::new(dconfig);
        let params = object_params_for(object_id, len as u64, symbol_size, max_block as u64);
        dec.set_object_params(params).expect("set_object_params");
        for s in symbols {
            let _ = dec.feed(AuthenticatedSymbol::new_unauthenticated(s));
        }
        if !dec.is_complete() {
            return false;
        }
        let mut out = dec.into_data().expect("into_data");
        out.truncate(len);
        out == bytes
    }

    #[test]
    fn coding_roundtrip_small_k_single_block() {
        // K = 64 (matches the loopback e2e regime).
        assert!(coding_roundtrip(60_000, 64 * 1024, 1024));
    }

    #[test]
    fn coding_roundtrip_k512_single_block() {
        // K = 512 single 8 MiB block — the default-config regime that the
        // cross-machine transfer exercised. Regression guard for the
        // never-converges bug.
        assert!(coding_roundtrip(512 * 1024, 8 * 1024 * 1024, 1024));
    }

    #[test]
    fn coding_roundtrip_multi_block_small_k() {
        // Three 64 KiB blocks at K=64 exercises SBN routing, per-block decode,
        // and final cross-block assembly without making the normal unit lane
        // pay the K=1024 matrix cost of the historical fleet repro.
        assert!(coding_roundtrip(3 * 64 * 1024, 64 * 1024, 1024));
    }

    #[test]
    fn default_k_multiblock_metadata_is_accepted_by_decoder() {
        // Regression guard for br-asupersync-c8m8ha: the default-ish multi-block
        // shape used to fail at set_object_params before any network I/O. Keep
        // this as metadata-only coverage so the guard stays cheap and stable.
        let len = 3 * 1024 * 1024;
        let max_block = 1024 * 1024;
        let symbol_size = 1024;
        let object_id = entry_object_id("test-transfer", 0);
        let dconfig = DecodingConfig {
            symbol_size,
            max_block_size: max_block,
            repair_overhead: 1.5,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: std::time::Duration::from_secs(0),
            verify_auth: false,
        };
        let mut dec = DecodingPipeline::new(dconfig);
        let params = object_params_for(object_id, len as u64, symbol_size, max_block as u64);
        assert_eq!(params.source_blocks, 3);
        assert_eq!(params.symbols_per_block, 1024);
        dec.set_object_params(params)
            .expect("default-ish multi-block params must match decoder plan");
    }

    #[test]
    fn safe_base_for_root_name_contains_hostile_inputs() {
        // Regression guard: a malicious sender controls `root_name` off the
        // wire. It must never escape `dest_dir`, even when absolute or
        // separator-bearing (Path::join replaces the base for absolute args).
        let dest = Path::new("/dst");
        assert_eq!(
            safe_base_for_root_name(dest, "payload").unwrap(),
            dest.join("payload")
        );
        // Absolute root_name would otherwise replace the base via Path::join;
        // collapse to the final component instead.
        assert_eq!(
            safe_base_for_root_name(dest, "/etc/cron.d/evil").unwrap(),
            dest.join("evil")
        );
        assert_eq!(
            safe_base_for_root_name(dest, "../../etc/passwd").unwrap(),
            dest.join("passwd")
        );
        assert!(safe_base_for_root_name(dest, "").is_err());
        assert!(safe_base_for_root_name(dest, "/").is_err());
        assert!(safe_base_for_root_name(dest, "..").is_err());
    }

    fn manifest_with(entries: Vec<ManifestEntry>, total_bytes: u64) -> TransferManifest {
        TransferManifest {
            transfer_id: "rqtransfer1".to_string(),
            root_name: "payload".to_string(),
            is_directory: true,
            total_bytes,
            merkle_root_hex: "0".repeat(64),
            entries,
        }
    }

    fn manifest_entry(index: u32, size: u64) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: format!("f{index}"),
            size,
            sha256_hex: "0".repeat(64),
            members: Vec::new(),
            fragment: None,
        }
    }

    #[test]
    fn manifest_entry_members_serde_backward_compat() {
        // E-15 S1: a pre-packing manifest entry (no `members`) must deserialize to empty
        // members AND re-serialize WITHOUT a `members` field, so the no-packing wire stays
        // byte-identical to before E-15.
        let old_json = r#"{"index":0,"rel_path":"f0","size":10,"sha256_hex":"00"}"#;
        let parsed: ManifestEntry =
            serde_json::from_str(old_json).expect("deserialize pre-packing entry");
        assert!(parsed.members.is_empty(), "missing members => empty");
        let reser = serde_json::to_string(&parsed).expect("serialize");
        assert!(
            !reser.contains("members"),
            "empty members must be skipped (byte-identical no-packing wire): {reser}"
        );
        // A packed entry round-trips with its member offset table intact.
        let packed = ManifestEntry {
            index: 1,
            rel_path: ".atp-pack-0".to_string(),
            size: 20,
            sha256_hex: "ab".repeat(32),
            members: vec![
                PackedMember {
                    rel_path: "dir/a".to_string(),
                    offset: 0,
                    len: 10,
                    sha256_hex: "aa".repeat(32),
                },
                PackedMember {
                    rel_path: "dir/b".to_string(),
                    offset: 10,
                    len: 10,
                    sha256_hex: "bb".repeat(32),
                },
            ],
            fragment: None,
        };
        let json = serde_json::to_string(&packed).expect("serialize packed");
        assert!(json.contains("members"), "packed entry serializes members");
        let back: ManifestEntry = serde_json::from_str(&json).expect("round-trip packed");
        assert_eq!(back, packed, "packed entry round-trips byte-identical");
    }

    #[test]
    fn validate_manifest_accepts_sane_bounds() {
        let manifest = manifest_with(vec![manifest_entry(0, 100), manifest_entry(1, 200)], 300);
        assert!(validate_manifest(&manifest, &RqConfig::default()).is_ok());
    }

    #[test]
    fn parse_manifest_frame_validates_before_receiver_state() {
        let mut entries = vec![manifest_entry(0, 10), manifest_entry(1, 20)];
        entries[1].rel_path = entries[0].rel_path.clone();
        let manifest = manifest_with(entries, 30);
        let frame = json_frame(FrameType::ObjectManifest, &manifest).expect("manifest frame");

        assert!(matches!(
            parse_and_validate_manifest_frame(&frame, &RqConfig::default()),
            Err(RqError::Frame(msg)) if msg.contains("duplicate manifest rel_path")
        ));
    }

    #[test]
    fn validate_manifest_rejects_lying_entry_size() {
        let manifest = manifest_with(vec![manifest_entry(0, u64::MAX)], 10);
        assert!(matches!(
            validate_manifest(&manifest, &RqConfig::default()),
            Err(RqError::TooLarge { .. })
        ));
    }

    #[test]
    fn validate_manifest_rejects_declared_sum_over_limit() {
        let config = RqConfig {
            max_transfer_bytes: 1000,
            ..RqConfig::default()
        };
        let manifest = manifest_with(vec![manifest_entry(0, 600), manifest_entry(1, 600)], 1200);
        assert!(matches!(
            validate_manifest(&manifest, &config),
            Err(RqError::TooLarge { .. })
        ));
    }

    #[test]
    fn validate_manifest_rejects_declared_sum_overflow() {
        let config = RqConfig {
            max_transfer_bytes: u64::MAX,
            ..RqConfig::default()
        };
        let manifest = manifest_with(
            vec![manifest_entry(0, u64::MAX), manifest_entry(1, 1)],
            u64::MAX,
        );
        assert!(matches!(
            validate_manifest(&manifest, &config),
            Err(RqError::Frame(msg)) if msg.contains("declared size sum overflows")
        ));
    }

    #[test]
    fn validate_manifest_rejects_single_file_with_multiple_entries() {
        let mut manifest = manifest_with(vec![manifest_entry(0, 10), manifest_entry(1, 20)], 30);
        manifest.is_directory = false;
        assert!(matches!(
            validate_manifest(&manifest, &RqConfig::default()),
            Err(RqError::Frame(msg)) if msg.contains("single-file transfer")
        ));
    }

    #[test]
    fn validate_manifest_rejects_duplicate_relative_paths() {
        let mut entries = vec![manifest_entry(0, 10), manifest_entry(1, 20)];
        entries[1].rel_path = entries[0].rel_path.clone();
        let manifest = manifest_with(entries, 30);
        assert!(matches!(
            validate_manifest(&manifest, &RqConfig::default()),
            Err(RqError::Frame(msg)) if msg.contains("duplicate manifest rel_path")
        ));
    }

    #[test]
    fn validate_manifest_rejects_nonsequential_indexes() {
        let manifest = manifest_with(vec![manifest_entry(0, 10), manifest_entry(7, 20)], 30);
        assert!(matches!(
            validate_manifest(&manifest, &RqConfig::default()),
            Err(RqError::Frame(msg)) if msg.contains("does not match position")
        ));
    }

    #[test]
    fn validate_manifest_rejects_unsafe_relative_paths() {
        for rel_path in [
            "",
            "/abs",
            "\\abs",
            "../escape",
            "a/../escape",
            "a//b",
            "a\\b",
            "c:drive",
        ] {
            let mut entry = manifest_entry(0, 10);
            entry.rel_path = rel_path.to_string();
            let manifest = manifest_with(vec![entry], 10);
            assert!(
                matches!(
                    validate_manifest(&manifest, &RqConfig::default()),
                    Err(RqError::Source(msg)) if msg.contains("unsafe manifest rel_path")
                ),
                "rel_path {rel_path:?} should fail closed"
            );
        }
    }

    #[test]
    fn validate_manifest_rejects_unsafe_transfer_id() {
        let long = "x".repeat(65);
        for transfer_id in ["", "../escape", "with/slash", "with-hyphen", long.as_str()] {
            let mut manifest = manifest_with(vec![manifest_entry(0, 10)], 10);
            manifest.transfer_id = transfer_id.to_string();
            assert!(
                matches!(
                    validate_manifest(&manifest, &RqConfig::default()),
                    Err(RqError::Frame(msg)) if msg.contains("unsafe manifest transfer_id")
                ),
                "transfer_id {transfer_id:?} should fail closed"
            );
        }
    }

    #[test]
    fn validate_manifest_rejects_malformed_hash_fields() {
        let mut bad_root = manifest_with(vec![manifest_entry(0, 10)], 10);
        bad_root.merkle_root_hex = "0".repeat(63);
        assert!(matches!(
            validate_manifest(&bad_root, &RqConfig::default()),
            Err(RqError::Frame(msg)) if msg.contains("manifest merkle_root_hex")
        ));

        let mut bad_entry = manifest_entry(0, 10);
        bad_entry.sha256_hex = "zz".repeat(32);
        assert!(matches!(
            validate_manifest(&manifest_with(vec![bad_entry], 10), &RqConfig::default()),
            Err(RqError::Frame(msg)) if msg.contains("manifest entry sha256_hex")
        ));

        let mut bad_fragment = ManifestEntry {
            index: 0,
            rel_path: ".atp-fragment-0-0".to_string(),
            size: 10,
            sha256_hex: "00".repeat(32),
            members: Vec::new(),
            fragment: Some(LargeObjectFragment {
                rel_path: "huge.bin".to_string(),
                shard_index: 0,
                shard_count: 1,
                logical_offset: 0,
                len: 10,
                logical_size: 10,
                sha256_hex: "f".repeat(63),
            }),
        };
        let mut fragment_manifest = manifest_with(vec![bad_fragment.clone()], 10);
        fragment_manifest.is_directory = false;
        assert!(matches!(
            validate_manifest(&fragment_manifest, &RqConfig::default()),
            Err(RqError::Frame(msg)) if msg.contains("manifest fragment sha256_hex")
        ));

        bad_fragment.fragment = None;
        bad_fragment.rel_path = ".atp-pack-0".to_string();
        bad_fragment.members = vec![PackedMember {
            rel_path: "packed/member".to_string(),
            offset: 0,
            len: 10,
            sha256_hex: "not-hex".to_string(),
        }];
        assert!(matches!(
            validate_manifest(&manifest_with(vec![bad_fragment], 10), &RqConfig::default()),
            Err(RqError::Frame(msg)) if msg.contains("manifest packed member sha256_hex")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rq_commit_rejects_existing_destination_symlink_prefix() {
        let dest = tempfile::tempdir().expect("dest dir");
        let outside = tempfile::tempdir().expect("outside dir");
        let base = dest.path().join("payload");
        std::fs::create_dir_all(&base).expect("create destination base");
        std::os::unix::fs::symlink(outside.path(), base.join("link"))
            .expect("create destination symlink");

        let bytes = b"must stay inside the RQ destination".to_vec();
        let staging_dir = dest.path().join(".atp-rq-test-staging");
        std::fs::create_dir_all(&staging_dir).expect("create staging dir");
        let staging_path = staging_dir.join("0");
        std::fs::write(&staging_path, &bytes).expect("write staged payload");

        let mut hash_buf = vec![0u8; RQ_STREAM_HASH_BUFFER_SIZE];
        let (size, content_id, content_sha256) =
            futures_lite::future::block_on(hash_file_streaming(&staging_path, &mut hash_buf))
                .expect("hash staged payload");
        let rel_path = "link/payload.txt".to_string();
        let sha256_hex = hex_encode(&content_sha256);
        let merkle_root_hex = flat_merkle_root_from_digests(&[EntryDigest {
            rel_path: rel_path.clone(),
            size,
            content_id,
            content_sha256,
        }]);
        let manifest = TransferManifest {
            transfer_id: "rqtransfer1".to_string(),
            root_name: "payload".to_string(),
            is_directory: true,
            total_bytes: size,
            merkle_root_hex,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path,
                size,
                sha256_hex,
                members: Vec::new(),
                fragment: None,
            }],
        };
        let mut decoders = vec![EntryDecoder {
            index: 0,
            object_id: entry_object_id(&manifest.transfer_id, 0),
            size,
            pipeline: None,
            complete: true,
            staging_path,
            staging_created: true,
            staging_file: None,
            staging_cursor: None,
            staging_unflushed_bytes: 0,
            cache_staging_file: false,
            bytes_written: size,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            source_streaming: false,
            source_blocks: Vec::new(),
            pending_decodes: Vec::new(),
        }];

        let err = futures_lite::future::block_on(verify_and_commit(
            &manifest,
            &mut decoders,
            dest.path(),
            0,
            0,
        ))
        .expect_err("commit must reject pre-existing symlink ancestors");
        assert!(
            matches!(err, RqError::Source(ref message) if message.contains("existing symlink")),
            "expected existing-symlink source error, got {err:?}"
        );
        assert!(
            !outside.path().join("payload.txt").exists(),
            "RQ commit must not follow a destination symlink outside dest_dir"
        );
    }

    #[test]
    fn datagram_roundtrips() {
        let sym = Symbol::new(
            SymbolId::new(ObjectId::new(1, 2), 3, 7),
            vec![9u8; 1024],
            SymbolKind::Repair,
        );
        let dg = encode_symbol_datagram(0xABCD, 42, &sym, None);
        let parsed = parse_symbol_header(&dg, 0xABCD, false).expect("parse");
        assert_eq!(parsed.entry, 42);
        assert_eq!(parsed.sbn, 3);
        assert_eq!(parsed.esi, 7);
        assert!(matches!(parsed.kind, SymbolKind::Repair));
        assert_eq!(parsed.auth_tag, None);
        assert_eq!(parsed.payload_len, 1024);
        assert_eq!(
            &dg[parsed.header_len..parsed.header_len + 1024],
            &[9u8; 1024]
        );
    }

    #[test]
    fn signed_datagram_roundtrips() {
        let ctx = SecurityContext::for_testing(99);
        let sym = Symbol::new(
            SymbolId::new(ObjectId::new(1, 2), 3, 7),
            vec![9u8; 1024],
            SymbolKind::Repair,
        );
        let auth = ctx.sign_symbol(&sym);
        let dg = encode_symbol_datagram(0xABCD, 42, &sym, Some(auth.tag()));
        let parsed = parse_symbol_header(&dg, 0xABCD, true).expect("parse signed");
        assert_eq!(parsed.entry, 42);
        assert_eq!(parsed.sbn, 3);
        assert_eq!(parsed.auth_tag, Some(*auth.tag()));
        assert_eq!(parsed.header_len, AUTH_DGRAM_HEADER);

        let mut received = AuthenticatedSymbol::from_parts(sym, parsed.auth_tag.expect("tag"));
        ctx.verify_authenticated_symbol(&mut received)
            .expect("tag verifies");
        assert!(received.is_verified());
    }

    fn source_streaming_test_decoder(
        object_id: ObjectId,
        staging_path: PathBuf,
        size: u64,
        symbol_size: u16,
    ) -> EntryDecoder {
        EntryDecoder {
            index: 0,
            object_id,
            size,
            pipeline: None,
            complete: false,
            staging_path,
            staging_created: false,
            staging_file: None,
            staging_cursor: None,
            staging_unflushed_bytes: 0,
            cache_staging_file: false,
            bytes_written: 0,
            max_block_size: usize::try_from(size).expect("test size fits usize"),
            source_streaming: true,
            source_blocks: source_block_progress_for(
                size,
                usize::try_from(size).expect("test size fits usize"),
                symbol_size,
            )
            .expect("test source blocks"),
            pending_decodes: Vec::new(),
        }
    }

    fn signed_source_payload(
        ctx: &SecurityContext,
        object_id: ObjectId,
        esi: u32,
        data: Vec<u8>,
        tag: Option<AuthenticationTag>,
    ) -> (ParsedDatagram, Vec<u8>) {
        let sym = Symbol::new(SymbolId::new(object_id, 0, esi), data, SymbolKind::Source);
        let signed = ctx.sign_symbol(&sym);
        let auth_tag = tag.as_ref().unwrap_or_else(|| signed.tag());
        let dg = encode_symbol_datagram(0xA77E, 0, &sym, Some(auth_tag));
        let parsed = parse_symbol_header(&dg, 0xA77E, true).expect("parse signed source datagram");
        let payload = dg[parsed.header_len..parsed.header_len + parsed.payload_len].to_vec();
        (parsed, payload)
    }

    #[test]
    fn signed_source_streaming_persists_after_hmac_verification() {
        let ctx = SecurityContext::for_testing(31337);
        let object_id = entry_object_id("signed-source-stream", 0);
        let symbol_size = 4u16;
        let dir = tempfile::tempdir().expect("tempdir");
        let staging_path = dir.path().join("entry0");
        let mut decoder = source_streaming_test_decoder(object_id, staging_path.clone(), 8, 4);

        let (first, first_payload) =
            signed_source_payload(&ctx, object_id, 0, vec![1, 2, 3, 4], None);
        let accepted = futures_lite::future::block_on(feed_symbol(
            &mut decoder,
            &first,
            &first_payload,
            symbol_size,
            Some(&ctx),
        ))
        .expect("feed first source symbol");
        assert!(accepted);
        assert!(!decoder.complete);
        assert!(decoder.staging_created);
        assert_eq!(
            std::fs::read(&staging_path).expect("read staged first source symbol"),
            vec![1, 2, 3, 4, 0, 0, 0, 0]
        );

        let (second, second_payload) =
            signed_source_payload(&ctx, object_id, 1, vec![5, 6, 7, 8], None);
        let accepted = futures_lite::future::block_on(feed_symbol(
            &mut decoder,
            &second,
            &second_payload,
            symbol_size,
            Some(&ctx),
        ))
        .expect("feed second source symbol");
        assert!(accepted);
        assert!(decoder.complete);
        assert_eq!(decoder.bytes_written, 8);

        assert_eq!(
            std::fs::read(staging_path).expect("read staged source stream"),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn source_streaming_large_entry_cache_reuses_and_closes_staging_file() {
        let object_id = entry_object_id("source-stream-cache", 0);
        let symbol_size = 4u16;
        let dir = tempfile::tempdir().expect("tempdir");
        let staging_path = dir.path().join("entry0");
        let mut decoder =
            source_streaming_test_decoder(object_id, staging_path.clone(), 8, symbol_size);
        decoder.cache_staging_file = true;

        let first = ParsedDatagram {
            entry: 0,
            sbn: 0,
            esi: 0,
            kind: SymbolKind::Source,
            auth_tag: None,
            payload_len: 4,
            header_len: 0,
        };
        assert!(
            futures_lite::future::block_on(persist_source_symbol(
                &mut decoder,
                &first,
                &[1, 2, 3, 4],
                symbol_size,
            ))
            .expect("persist first cached source symbol")
        );
        assert!(
            decoder.staging_file.is_some(),
            "large-entry source streaming should keep the staging file hot mid-block"
        );
        assert_eq!(decoder.staging_cursor, Some(4));
        assert_eq!(decoder.staging_unflushed_bytes, 4);

        let second = ParsedDatagram { esi: 1, ..first };
        assert!(
            futures_lite::future::block_on(persist_source_symbol(
                &mut decoder,
                &second,
                &[5, 6, 7, 8],
                symbol_size,
            ))
            .expect("persist second cached source symbol")
        );
        assert!(decoder.complete);
        assert!(
            decoder.staging_file.is_none(),
            "completed entries must release cached staging descriptors"
        );
        assert_eq!(decoder.staging_cursor, None);
        assert_eq!(decoder.staging_unflushed_bytes, 0);
        assert_eq!(
            std::fs::read(staging_path).expect("read cached source stream"),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn source_streaming_staging_cache_policy_is_bounded() {
        const MIN_BYTES: u64 = 1024 * 1024;
        const MAX_ENTRIES: usize = 128;

        assert!(should_cache_entry_staging_file(MIN_BYTES, MAX_ENTRIES));
        assert!(!should_cache_entry_staging_file(MIN_BYTES - 1, 1));
        assert!(!should_cache_entry_staging_file(MIN_BYTES, MAX_ENTRIES + 1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn e14_source_streaming_does_not_retain_one_staging_fd_per_entry() {
        fn fd_count() -> usize {
            std::fs::read_dir("/proc/self/fd")
                .expect("read /proc/self/fd")
                .count()
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let symbol_size = 1u16;
        let parsed = ParsedDatagram {
            entry: 0,
            sbn: 0,
            esi: 0,
            kind: SymbolKind::Source,
            auth_tag: None,
            payload_len: 1,
            header_len: 0,
        };
        let before = fd_count();
        let mut decoders: Vec<EntryDecoder> = (0..1500)
            .map(|idx| {
                source_streaming_test_decoder(
                    entry_object_id("e14-fd-bound", u32::try_from(idx).expect("test index fits")),
                    dir.path().join(idx.to_string()),
                    1,
                    symbol_size,
                )
            })
            .collect();

        for (idx, decoder) in decoders.iter_mut().enumerate() {
            let payload = [u8::try_from(idx % 251).expect("bounded byte")];
            assert!(
                futures_lite::future::block_on(persist_source_symbol(
                    decoder,
                    &parsed,
                    &payload,
                    symbol_size
                ))
                .expect("persist source symbol"),
                "entry {idx} source symbol should be accepted"
            );
            assert!(decoder.complete, "entry {idx} should complete");
            assert!(decoder.staging_created, "entry {idx} should have staging");
            assert_eq!(decoder.bytes_written, 1, "entry {idx} byte count");
        }

        let after = fd_count();
        assert!(
            after <= before + 64,
            "receiver retained too many staging FDs: before={before} after={after}"
        );
    }

    #[test]
    fn signed_source_streaming_rejects_bad_tag_before_persist() {
        let ctx = SecurityContext::for_testing(31338);
        let object_id = entry_object_id("signed-source-stream-bad-tag", 0);
        let symbol_size = 4u16;
        let dir = tempfile::tempdir().expect("tempdir");
        let staging_path = dir.path().join("entry0");
        let mut decoder =
            source_streaming_test_decoder(object_id, staging_path.clone(), 4, symbol_size);

        let good = ctx.sign_symbol(&Symbol::new(
            SymbolId::new(object_id, 0, 0),
            vec![1, 2, 3, 4],
            SymbolKind::Source,
        ));
        let mut bad_tag = *good.tag().as_bytes();
        bad_tag[0] ^= 0x80;
        let (parsed, payload) = signed_source_payload(
            &ctx,
            object_id,
            0,
            vec![1, 2, 3, 4],
            Some(AuthenticationTag::from_bytes(bad_tag)),
        );

        let accepted = futures_lite::future::block_on(feed_symbol(
            &mut decoder,
            &parsed,
            &payload,
            symbol_size,
            Some(&ctx),
        ))
        .expect("feed tampered source symbol");
        assert!(!accepted);
        assert!(!decoder.complete);
        assert_eq!(decoder.bytes_written, 0);
        assert!(!decoder.staging_created);
        assert!(!staging_path.exists());
    }

    #[test]
    fn signed_source_streaming_seeds_fec_decoder_from_staged_sources() {
        let ctx = SecurityContext::for_testing(31339);
        let object_id = entry_object_id("signed-source-stream-fec-seed", 0);
        let symbol_size = 4u16;
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let dir = tempfile::tempdir().expect("tempdir");
        let staging_path = dir.path().join("entry0");
        let mut decoder =
            source_streaming_test_decoder(object_id, staging_path.clone(), 8, symbol_size);
        let mut pipeline = DecodingPipeline::with_auth(
            DecodingConfig {
                symbol_size,
                max_block_size: 8,
                repair_overhead: 1.0,
                min_overhead: 0,
                max_buffered_symbols: 0,
                block_timeout: std::time::Duration::from_secs(0),
                verify_auth: true,
            },
            ctx.clone(),
        );
        pipeline
            .set_object_params(object_params_for(object_id, 8, symbol_size, 8))
            .expect("set object params");
        decoder.pipeline = Some(pipeline);

        let (first, first_payload) =
            signed_source_payload(&ctx, object_id, 0, data[..4].to_vec(), None);
        assert!(
            futures_lite::future::block_on(feed_symbol(
                &mut decoder,
                &first,
                &first_payload,
                symbol_size,
                Some(&ctx),
            ))
            .expect("feed first source")
        );
        assert!(!decoder.complete);
        assert_eq!(decoder.source_blocks[0].received_count, 1);
        assert!(!decoder.source_blocks[0].pipeline_seeded[0]);

        let pool = SymbolPool::new(PoolConfig::default());
        let mut encoder = EncodingPipeline::new(
            crate::config::EncodingConfig {
                repair_overhead: 1.0,
                max_block_size: 8,
                symbol_size,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            pool,
        );

        for encoded in encoder.encode_single_block_repair_range(object_id, 0, &data, 0, 4) {
            let sym = encoded.expect("repair encode").into_symbol();
            let auth = ctx.sign_symbol(&sym);
            let dg = encode_symbol_datagram(0xA77E, 0, &sym, Some(auth.tag()));
            let parsed = parse_symbol_header(&dg, 0xA77E, true).expect("parse signed repair");
            let payload = dg[parsed.header_len..parsed.header_len + parsed.payload_len].to_vec();
            let _ = futures_lite::future::block_on(feed_symbol(
                &mut decoder,
                &parsed,
                &payload,
                symbol_size,
                Some(&ctx),
            ))
            .expect("feed repair");
            if decoder.complete {
                break;
            }
        }

        assert!(decoder.complete, "repair fallback should finish the block");
        assert!(decoder.source_blocks[0].pipeline_seeded[0]);
        assert_eq!(
            std::fs::read(staging_path).expect("read repaired source stream"),
            data
        );
    }

    // E-9 regression: a block completed via FEC (persist_decoded_block) must not be counted a
    // second time when a late source retransmit for the same block arrives. Pre-fix, FEC left
    // source_blocks[sbn].complete=false, so the late source's received_count==k path added
    // block.len to bytes_written AGAIN → bytes_written != size → verify_and_commit falsely rejected
    // a BYTE-CORRECT transfer as "per-entry SHA-256 mismatch" (the bad-regime non-convergence).
    #[test]
    fn e9_single_block_fec_then_late_source_does_not_double_count() {
        let ctx = SecurityContext::for_testing(54321);
        let object_id = entry_object_id("e9-mixed-no-double-count", 0);
        let symbol_size = 4u16;
        let data = vec![10u8, 20, 30, 40, 50, 60, 70, 80]; // 8 bytes, k=2 @ symbol_size 4
        let dir = tempfile::tempdir().expect("tempdir");
        let staging_path = dir.path().join("entry0");
        let mut decoder =
            source_streaming_test_decoder(object_id, staging_path.clone(), 8, symbol_size);

        // One real source symbol arrives (esi=0): block not yet complete.
        let (p0, pl0) = signed_source_payload(&ctx, object_id, 0, data[..4].to_vec(), None);
        assert!(
            futures_lite::future::block_on(feed_symbol(
                &mut decoder,
                &p0,
                &pl0,
                symbol_size,
                Some(&ctx),
            ))
            .expect("feed source 0")
        );
        assert!(!decoder.complete);
        assert_eq!(decoder.source_blocks[0].received_count, 1);

        // FEC completes the block (decoder emits the full block).
        futures_lite::future::block_on(persist_decoded_block(&mut decoder, 0, &data))
            .expect("persist decoded block");
        assert!(
            decoder.complete,
            "FEC completion finishes the single-block entry"
        );
        assert_eq!(
            decoder.bytes_written, 8,
            "block counted exactly once after FEC"
        );
        assert!(
            decoder.source_blocks[0].complete,
            "FEC must mark the source block complete (E-9)"
        );

        // A LATE source retransmit for esi=1 arrives AFTER FEC completion. Pre-fix this drove
        // received_count to k and DOUBLE-counted bytes_written to 16. It must be ignored now.
        let (p1, pl1) = signed_source_payload(&ctx, object_id, 1, data[4..].to_vec(), None);
        let _ = futures_lite::future::block_on(feed_symbol(
            &mut decoder,
            &p1,
            &pl1,
            symbol_size,
            Some(&ctx),
        ));
        assert_eq!(
            decoder.bytes_written, 8,
            "late source must NOT double-count bytes_written (E-9)"
        );

        assert_eq!(std::fs::read(&staging_path).expect("read staged"), data);
    }

    // E-9 regression (multi-block MIXED completion — the realistic bad-regime case): block 0 via
    // FEC, block 1 via source, plus a late source retransmit for the already-FEC'd block 0. The
    // entry must complete with bytes_written == size (each block counted ONCE) and byte-identical
    // content. This directly exercises the source_blocks[sbn].complete guard that protects the
    // multi-block path (where dec.complete is still false after the first block, so feed_symbol's
    // dec.complete short-circuit does not hide the double-count).
    #[test]
    fn e9_multiblock_mixed_completion_counts_each_block_once() {
        let object_id = entry_object_id("e9-multiblock-mixed", 0);
        let symbol_size = 4u16;
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8]; // 8 bytes; max_block_size 4 -> 2 blocks, k=1 each
        let dir = tempfile::tempdir().expect("tempdir");
        let staging_path = dir.path().join("entry0");
        let mut decoder = EntryDecoder {
            index: 0,
            object_id,
            size: 8,
            pipeline: None,
            complete: false,
            staging_path: staging_path.clone(),
            staging_created: false,
            staging_file: None,
            staging_cursor: None,
            staging_unflushed_bytes: 0,
            cache_staging_file: false,
            bytes_written: 0,
            max_block_size: 4,
            source_streaming: true,
            source_blocks: source_block_progress_for(8, 4, symbol_size).expect("two source blocks"),
            pending_decodes: Vec::new(),
        };
        assert_eq!(decoder.source_blocks.len(), 2);

        // Block 0 completes via FEC.
        futures_lite::future::block_on(persist_decoded_block(&mut decoder, 0, &data[0..4]))
            .expect("persist decoded block 0");
        assert!(decoder.source_blocks[0].complete);
        assert!(!decoder.complete, "block 1 still pending");
        assert_eq!(decoder.bytes_written, 4);

        // A LATE source retransmit for the already-FEC'd block 0 must be ignored (no double count).
        let late = ParsedDatagram {
            entry: 0,
            sbn: 0,
            esi: 0,
            kind: SymbolKind::Source,
            auth_tag: None,
            payload_len: 4,
            header_len: 0,
        };
        let accepted = futures_lite::future::block_on(persist_source_symbol(
            &mut decoder,
            &late,
            &data[0..4],
            symbol_size,
        ))
        .expect("late source");
        assert!(
            !accepted,
            "late source for a completed block is ignored (E-9)"
        );
        assert_eq!(decoder.bytes_written, 4, "no double count for block 0");

        // Block 1 completes via source.
        let b1 = ParsedDatagram {
            entry: 0,
            sbn: 1,
            esi: 0,
            kind: SymbolKind::Source,
            auth_tag: None,
            payload_len: 4,
            header_len: 0,
        };
        assert!(
            futures_lite::future::block_on(persist_source_symbol(
                &mut decoder,
                &b1,
                &data[4..8],
                symbol_size
            ))
            .expect("block 1 source")
        );
        assert!(decoder.complete, "all blocks complete -> entry complete");
        assert_eq!(
            decoder.bytes_written, 8,
            "each block counted once; bytes_written == size"
        );

        assert_eq!(std::fs::read(&staging_path).expect("read staged"), data);
    }

    #[test]
    fn signed_datagram_feed_reaches_k512_decode_threshold() {
        let ctx = SecurityContext::for_testing(101);
        let object_id = entry_object_id("wire-k512", 0);
        let symbol_size = 1024u16;
        let max_block_size = DEFAULT_MAX_BLOCK_SIZE;
        let data: Vec<u8> = (0usize..512 * 1024)
            .map(|i: usize| (i.wrapping_mul(1_103_515_245) >> 16) as u8)
            .collect();

        let pool = SymbolPool::new(PoolConfig::default());
        let mut encoder = EncodingPipeline::new(
            crate::config::EncodingConfig {
                repair_overhead: DEFAULT_REPAIR_OVERHEAD,
                max_block_size,
                symbol_size,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            pool,
        );
        let params = object_params_for(
            object_id,
            data.len() as u64,
            symbol_size,
            max_block_size as u64,
        );
        let mut decoder = DecodingPipeline::with_auth(
            DecodingConfig {
                symbol_size,
                max_block_size,
                repair_overhead: DEFAULT_REPAIR_OVERHEAD,
                min_overhead: 0,
                max_buffered_symbols: 0,
                block_timeout: std::time::Duration::from_secs(0),
                verify_auth: true,
            },
            ctx.clone(),
        );
        decoder
            .set_object_params(params)
            .expect("set object params");

        for encoded in encoder.encode_with_repair(object_id, &data, 512) {
            let sym = encoded.expect("encode").into_symbol();
            if sym.kind().is_source() && sym.esi() < 33 {
                continue;
            }
            let auth = ctx.sign_symbol(&sym);
            let dg = encode_symbol_datagram(0xABCD, 0, &sym, Some(auth.tag()));
            let parsed = parse_symbol_header(&dg, 0xABCD, true).expect("parse signed datagram");
            let payload = &dg[parsed.header_len..parsed.header_len + parsed.payload_len];
            let received = Symbol::new(
                SymbolId::new(object_id, parsed.sbn, parsed.esi),
                payload.to_vec(),
                parsed.kind,
            );
            let result = decoder
                .feed(AuthenticatedSymbol::from_parts(
                    received,
                    parsed.auth_tag.expect("auth tag"),
                ))
                .expect("feed");
            if matches!(result, SymbolAcceptResult::BlockComplete { .. }) {
                break;
            }
        }

        assert!(
            decoder.is_complete(),
            "wire-parsed K=512 symbols must decode"
        );
        let mut out = decoder.into_data().expect("decoded data");
        out.truncate(data.len());
        assert_eq!(out, data);
    }

    #[test]
    fn signed_datagram_rejects_missing_tag() {
        let sym = Symbol::new(
            SymbolId::new(ObjectId::new(1, 2), 3, 7),
            vec![9u8; 1024],
            SymbolKind::Repair,
        );
        let dg = encode_symbol_datagram(0xABCD, 42, &sym, None);
        assert!(parse_symbol_header(&dg, 0xABCD, true).is_none());
    }

    #[test]
    fn default_config_requires_symbol_auth_or_trusted_mode() {
        let err = RqConfig::default()
            .symbol_auth_context()
            .expect_err("default config must fail closed");
        assert!(matches!(err, RqError::Authentication(_)));
        assert!(
            RqConfig::default()
                .allow_unauthenticated_for_trusted_transport()
                .symbol_auth_context()
                .expect("explicit trusted mode")
                .is_none()
        );
        assert!(
            RqConfig::default()
                .with_symbol_auth(SecurityContext::for_testing(7))
                .symbol_auth_context()
                .expect("explicit auth context")
                .is_some()
        );
    }

    #[test]
    fn datagram_rejects_wrong_tag() {
        let sym = Symbol::new(
            SymbolId::new(ObjectId::new(1, 2), 0, 0),
            vec![0u8; 8],
            SymbolKind::Source,
        );
        let dg = encode_symbol_datagram(0x1111, 0, &sym, None);
        assert!(parse_symbol_header(&dg, 0x2222, false).is_none());
    }

    #[test]
    fn datagram_rejects_bad_magic() {
        let mut dg = encode_symbol_datagram(
            0x1111,
            0,
            &Symbol::new(
                SymbolId::new(ObjectId::new(1, 2), 0, 0),
                vec![0u8; 8],
                SymbolKind::Source,
            ),
            None,
        );
        dg[0] ^= 0xFF;
        assert!(parse_symbol_header(&dg, 0x1111, false).is_none());
    }

    #[test]
    fn entry_object_id_is_deterministic_and_index_sensitive() {
        let a = entry_object_id("deadbeef", 0);
        let b = entry_object_id("deadbeef", 0);
        let c = entry_object_id("deadbeef", 1);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn source_symbol_count_has_floor_and_ceils() {
        assert_eq!(source_symbol_count(0, 1024), 1);
        assert_eq!(source_symbol_count(1, 1024), 1);
        assert_eq!(source_symbol_count(1024, 1024), 1);
        assert_eq!(source_symbol_count(1025, 1024), 2);
    }

    #[test]
    fn source_symbol_request_rebuilds_exact_source_payload() {
        let config = RqConfig {
            symbol_size: 512,
            max_block_size: 1024,
            ..RqConfig::default()
        };
        let bytes: Vec<u8> = (0..1500).map(|i| (i % 251) as u8).collect();
        let dir = tempfile::tempdir().expect("tempdir");
        let source_path = dir.path().join("source.bin");
        std::fs::write(&source_path, &bytes).expect("write source");
        let enc = EntryEncoder {
            index: 7,
            object_id: entry_object_id("source-request", 7),
            abs_path: source_path,
            source_offset: 0,
            size: bytes.len(),
            repair_cursors: Vec::new(),
        };

        let first_block_tail = futures_lite::future::block_on(source_symbol_for_request(
            &enc,
            SourceSymbolRequest {
                entry: 7,
                sbn: 0,
                esi: 1,
            },
            &config,
        ))
        .expect("source symbol");
        assert!(first_block_tail.kind().is_source());
        assert_eq!(first_block_tail.sbn(), 0);
        assert_eq!(first_block_tail.esi(), 1);
        assert_eq!(first_block_tail.data(), &bytes[512..1024]);

        let final_block = futures_lite::future::block_on(source_symbol_for_request(
            &enc,
            SourceSymbolRequest {
                entry: 7,
                sbn: 1,
                esi: 0,
            },
            &config,
        ))
        .expect("final source symbol");
        assert_eq!(&final_block.data()[..476], &bytes[1024..]);
        assert!(final_block.data()[476..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn default_repair_overhead_is_source_first() {
        assert_eq!(
            initial_repair_target_per_block(512, DEFAULT_REPAIR_OVERHEAD),
            0
        );
    }

    #[test]
    fn source_first_initial_repair_target_is_zero() {
        assert_eq!(initial_repair_target_per_block(512, 1.0), 0);
    }

    #[test]
    fn source_first_feedback_repair_batch_is_minimal() {
        assert_eq!(repair_target_for_feedback_round(512, 0, 1.0), 1);
        assert_eq!(repair_target_for_feedback_round(512, 7, 1.0), 8);
    }

    #[test]
    fn feedback_repair_batch_is_rate_matched_and_capped() {
        assert_eq!(repair_target_for_feedback_round(512, 16, 1.03), 32);
        assert_eq!(repair_target_for_feedback_round(512, 256, 1.50), 384);
    }

    #[test]
    fn source_retransmit_is_bounded_by_default_in_source_first_mode() {
        let config = RqConfig {
            repair_overhead: 1.0,
            ..RqConfig::default()
        };

        assert_eq!(
            source_retransmit_request_limit(&config, 1),
            Some(DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS)
        );
        assert_eq!(
            source_retransmit_request_limit(&config, DEFAULT_SOURCE_RETRANSMIT_ROUNDS),
            Some(DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS)
        );
        assert_eq!(
            source_retransmit_request_limit(&config, DEFAULT_SOURCE_RETRANSMIT_ROUNDS + 1),
            None
        );
    }

    #[test]
    fn source_retransmit_requires_explicit_round_budget() {
        let config = RqConfig {
            repair_overhead: 1.0,
            source_retransmit_rounds: 2,
            max_source_retransmit_requests: 17,
            ..RqConfig::default()
        };

        assert_eq!(source_retransmit_request_limit(&config, 1), Some(17));
        assert_eq!(source_retransmit_request_limit(&config, 2), Some(17));
        assert_eq!(source_retransmit_request_limit(&config, 3), None);
    }

    #[test]
    fn source_retransmit_does_not_override_proactive_repair_mode() {
        let config = RqConfig {
            repair_overhead: 1.001,
            source_retransmit_rounds: 2,
            max_source_retransmit_requests: 17,
            ..RqConfig::default()
        };

        assert_eq!(source_retransmit_request_limit(&config, 1), None);
    }

    #[test]
    fn source_retransmit_falls_back_to_fec_when_saturated_or_final_round() {
        let config = RqConfig {
            repair_overhead: 1.0,
            source_retransmit_rounds: 2,
            max_source_retransmit_requests: 17,
            ..RqConfig::default()
        };

        assert!(!source_retransmit_needs_fec_fallback(&config, 1, 0));
        assert!(!source_retransmit_needs_fec_fallback(&config, 1, 16));
        assert!(source_retransmit_needs_fec_fallback(&config, 1, 17));
        assert!(source_retransmit_needs_fec_fallback(&config, 2, 1));
        assert!(source_retransmit_needs_fec_fallback(&config, 2, 0));
        assert!(source_retransmit_needs_fec_fallback(&config, 3, 0));
    }

    #[test]
    fn source_retransmit_fec_fallback_uses_adaptive_overhead() {
        let config = RqConfig {
            symbol_size: 1024,
            max_block_size: 512 * 1024,
            repair_overhead: 1.0,
            ..RqConfig::default()
        };
        let mut state = RqAdaptiveSendState::new(99, &config, 4);
        state.loss_ema = 0.03;
        state.loss_bar = 0.05;
        state.pacing_loss_ema = 0.05;
        state.est.loss_p_hat = 0.05;

        let tuning = state.source_fec_fallback_tuning(&config);
        let expected = adaptive::overhead_for_target(
            fixed_block_k(&config),
            0.05,
            RQ_SOURCE_FEC_FALLBACK_ALPHA,
            RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD,
        );

        assert!(
            tuning.repair_overhead >= 1.0 + expected,
            "fallback must apply adaptive FEC overhead: got {}, expected at least {}",
            tuning.repair_overhead,
            1.0 + expected
        );
    }

    #[test]
    fn source_fec_fallback_preserves_clean_link_batching_floor() {
        let config = RqConfig {
            symbol_size: 1024,
            max_block_size: 512 * 1024,
            repair_overhead: 1.0,
            ..RqConfig::default()
        };
        let mut state = RqAdaptiveSendState::new(101, &config, 4);
        state.loss_ema = 0.0;
        state.loss_bar = 0.0;
        state.pacing_loss_ema = 0.0;
        state.est.loss_p_hat = 0.0;

        let tuning = state.source_fec_fallback_tuning(&config);

        assert_eq!(
            state.source_fec_fallback_loss_bar(),
            RQ_SOURCE_FEC_FALLBACK_MIN_LOSS_BAR
        );
        assert!(
            tuning.repair_overhead >= 1.0 + RQ_SOURCE_FEC_FALLBACK_MIN_OVERHEAD,
            "clean-link fallback must preserve batching floor after E-RESYNC-16: got {}",
            tuning.repair_overhead
        );
    }

    #[test]
    fn source_fec_fallback_keeps_near_clean_batching_floor() {
        let config = RqConfig {
            symbol_size: 1024,
            max_block_size: 512 * 1024,
            repair_overhead: 1.0,
            ..RqConfig::default()
        };
        let mut state = RqAdaptiveSendState::new(102, &config, 4);
        state.loss_ema = 0.001;
        state.loss_bar = 0.001;
        state.pacing_loss_ema = 0.001;
        state.est.loss_p_hat = 0.001;

        let tuning = state.source_fec_fallback_tuning(&config);
        let expected = adaptive::overhead_for_target(
            fixed_block_k(&config),
            RQ_SOURCE_FEC_FALLBACK_MIN_LOSS_BAR,
            RQ_SOURCE_FEC_FALLBACK_ALPHA,
            RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD,
        );

        assert_eq!(
            state.source_fec_fallback_loss_bar(),
            RQ_SOURCE_FEC_FALLBACK_MIN_LOSS_BAR
        );
        assert!(tuning.repair_overhead >= 1.0 + expected);
        assert!(
            tuning.repair_overhead >= 1.0 + RQ_SOURCE_FEC_FALLBACK_MIN_OVERHEAD,
            "near-clean fallback should batch repair symbols, got {}",
            tuning.repair_overhead
        );
    }

    #[test]
    fn proactive_initial_repair_target_ceilings_extra_fraction() {
        assert_eq!(initial_repair_target_per_block(512, 1.15), 77);
        assert_eq!(initial_repair_target_per_block(1, 1.01), 1);
    }

    #[test]
    fn effective_block_size_preserves_k512_streaming_target_for_normal_files() {
        let config = RqConfig::default();
        let symbol_size = usize::from(config.symbol_size);
        assert_eq!(config.symbol_size, DEFAULT_SYMBOL_SIZE);

        let expected_target = symbol_size
            .saturating_mul(TARGET_SOURCE_SYMBOLS_PER_BLOCK)
            .min(TARGET_STREAMING_BLOCK_BYTES)
            .min(config.max_block_size);
        assert_eq!(
            expected_target.div_ceil(symbol_size),
            TARGET_SOURCE_SYMBOLS_PER_BLOCK,
            "default streaming target must stay at K512 even after symbol-size changes"
        );

        let effective = effective_max_block_size_for_largest_entry(&config, 10 * 1024 * 1024)
            .expect("10MiB should fit");
        assert_eq!(effective, expected_target);
        assert_eq!(
            max_block_source_symbol_count(10 * 1024 * 1024, config.symbol_size, effective),
            TARGET_SOURCE_SYMBOLS_PER_BLOCK
        );
    }

    #[test]
    fn effective_block_size_grows_from_k512_only_to_fit_sbn_limit() {
        let config = RqConfig::default();
        let one_gib: usize = 1024 * 1024 * 1024;
        let symbol_size = usize::from(config.symbol_size);
        let streaming_target = symbol_size
            .saturating_mul(TARGET_SOURCE_SYMBOLS_PER_BLOCK)
            .min(TARGET_STREAMING_BLOCK_BYTES);
        assert_eq!(
            streaming_target.div_ceil(symbol_size),
            TARGET_SOURCE_SYMBOLS_PER_BLOCK,
            "fixture starts from the default K512 streaming target"
        );
        let min_symbol_aligned_block = one_gib
            .div_ceil(MAX_SOURCE_BLOCKS)
            .max(symbol_size)
            .div_ceil(symbol_size)
            .saturating_mul(symbol_size);
        let effective = effective_max_block_size_for_largest_entry(&config, one_gib)
            .expect("1GiB should fit default transfer geometry");
        assert_eq!(
            effective, min_symbol_aligned_block,
            "large entries should grow only enough to fit the u8 SBN limit"
        );
        assert!(
            effective > streaming_target,
            "this fixture must exercise SBN-limit growth beyond the normal streaming target"
        );
        assert!(
            one_gib.div_ceil(effective - symbol_size) > MAX_SOURCE_BLOCKS,
            "one symbol-aligned step smaller should exceed the SBN wire limit"
        );
        assert_eq!(one_gib.div_ceil(effective), MAX_SOURCE_BLOCKS);
    }

    #[test]
    fn effective_block_size_rejects_unsplit_huge_entries() {
        // E-12: a 5 GiB logical file must be split into multiple bounded
        // RaptorQ objects before this helper runs. If an unsplit object reaches
        // this point, fail closed instead of growing K above the configured max.
        let config = RqConfig::default();
        let symbol_size = usize::from(config.symbol_size);
        let five_gib: usize = 5 * 1024 * 1024 * 1024;
        assert!(matches!(
            effective_max_block_size_for_largest_entry(&config, five_gib),
            Err(RqError::Coding(msg)) if msg.starts_with("[ASUP-E803]")
        ));

        // Entries within the configured 2 GiB default ceiling are unaffected (byte-identical).
        let one_gib: usize = 1024 * 1024 * 1024;
        assert_eq!(
            effective_max_block_size_for_largest_entry(&config, one_gib).unwrap(),
            one_gib
                .div_ceil(MAX_SOURCE_BLOCKS)
                .max(symbol_size)
                .div_ceil(symbol_size)
                .saturating_mul(symbol_size)
        );

        // One byte beyond the configured object ceiling fails closed unless it
        // has first been split into multiple objects.
        let ceiling = config.max_block_size.saturating_mul(MAX_SOURCE_BLOCKS);
        assert!(matches!(
            effective_max_block_size_for_largest_entry(&config, ceiling + 1),
            Err(RqError::Coding(msg)) if msg.starts_with("[ASUP-E803]")
        ));
    }

    #[test]
    fn max_block_source_symbols_uses_effective_block_not_entry_size() {
        let config = RqConfig::default();
        let symbol_size = usize::from(config.symbol_size);
        let effective_k512_block = symbol_size * TARGET_SOURCE_SYMBOLS_PER_BLOCK;
        assert_eq!(
            max_block_source_symbol_count(
                10 * 1024 * 1024,
                config.symbol_size,
                effective_k512_block
            ),
            TARGET_SOURCE_SYMBOLS_PER_BLOCK
        );
        assert_eq!(
            max_block_source_symbol_count(
                10 * 1024 * 1024,
                config.symbol_size,
                DEFAULT_MAX_BLOCK_SIZE
            ),
            DEFAULT_MAX_BLOCK_SIZE.div_ceil(symbol_size)
        );
    }

    fn m1_test_encoding_config(config: &RqConfig) -> crate::config::EncodingConfig {
        crate::config::EncodingConfig {
            repair_overhead: config.repair_overhead,
            max_block_size: config.max_block_size,
            symbol_size: config.symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        }
    }

    fn symbol_fingerprint(symbol: &Symbol) -> (u8, u32, SymbolKind, Vec<u8>) {
        (
            symbol.id().sbn(),
            symbol.id().esi(),
            symbol.kind(),
            symbol.data().to_vec(),
        )
    }

    fn collect_monolithic_symbols(
        object_id: ObjectId,
        bytes: &[u8],
        config: &RqConfig,
        repair_count: usize,
    ) -> Vec<(u8, u32, SymbolKind, Vec<u8>)> {
        let mut pipeline = EncodingPipeline::new(
            m1_test_encoding_config(config),
            SymbolPool::new(PoolConfig::default()),
        );
        pipeline
            .encode_with_repair(object_id, bytes, repair_count)
            .map(|encoded| {
                let encoded = encoded.expect("monolithic encode succeeds");
                symbol_fingerprint(encoded.symbol())
            })
            .collect()
    }

    fn collect_m1_source_symbols(
        object_id: ObjectId,
        bytes: &[u8],
        config: &RqConfig,
        repair_count: usize,
    ) -> Vec<(u8, u32, SymbolKind, Vec<u8>)> {
        let mut symbols = Vec::new();
        for block in encode_ahead_blocks(bytes.len(), config).expect("block plan") {
            let mut pipeline = EncodingPipeline::new(
                m1_test_encoding_config(config),
                SymbolPool::new(PoolConfig::default()),
            );
            for encoded in pipeline.encode_single_block_with_repair(
                object_id,
                block.sbn,
                &bytes[block.start..block.start + block.len],
                repair_count,
            ) {
                let encoded = encoded.expect("M=1 source encode succeeds");
                symbols.push(symbol_fingerprint(encoded.symbol()));
            }
        }
        symbols
    }

    fn collect_monolithic_repair_symbols(
        object_id: ObjectId,
        bytes: &[u8],
        config: &RqConfig,
        first_repair: usize,
        repair_count: usize,
    ) -> Vec<(u8, u32, SymbolKind, Vec<u8>)> {
        let mut pipeline = EncodingPipeline::new(
            m1_test_encoding_config(config),
            SymbolPool::new(PoolConfig::default()),
        );
        pipeline
            .encode_repair_range(object_id, bytes, first_repair, repair_count)
            .map(|encoded| {
                let encoded = encoded.expect("monolithic repair encode succeeds");
                symbol_fingerprint(encoded.symbol())
            })
            .collect()
    }

    fn collect_m1_repair_symbols(
        object_id: ObjectId,
        bytes: &[u8],
        config: &RqConfig,
        first_repair: usize,
        repair_count: usize,
    ) -> Vec<(u8, u32, SymbolKind, Vec<u8>)> {
        let mut symbols = Vec::new();
        for block in encode_ahead_blocks(bytes.len(), config).expect("block plan") {
            let mut pipeline = EncodingPipeline::new(
                m1_test_encoding_config(config),
                SymbolPool::new(PoolConfig::default()),
            );
            for encoded in pipeline.encode_single_block_repair_range(
                object_id,
                block.sbn,
                &bytes[block.start..block.start + block.len],
                first_repair,
                repair_count,
            ) {
                let encoded = encoded.expect("M=1 repair encode succeeds");
                symbols.push(symbol_fingerprint(encoded.symbol()));
            }
        }
        symbols
    }

    #[test]
    fn encode_ahead_ring_is_single_slot_fifo() {
        let mut ring = EncodeAheadRing::default();
        assert_eq!(EncodeAheadRing::CAPACITY, 1);

        let object_id = ObjectId::new_for_test(0xF204);
        let first = EncodeAheadSymbol {
            entry: 7,
            symbol: Symbol::new(
                SymbolId::new(object_id, 0, 0),
                vec![1, 2, 3],
                SymbolKind::Source,
            ),
        };
        let second = EncodeAheadSymbol {
            entry: 8,
            symbol: Symbol::new(
                SymbolId::new(object_id, 0, 1),
                vec![4, 5, 6],
                SymbolKind::Source,
            ),
        };

        ring.push(first).expect("first symbol fits");
        assert!(matches!(
            ring.push(second),
            Err(RqError::Coding(message)) if message.contains("ring is full")
        ));

        let popped = ring.pop().expect("first symbol queued");
        assert_eq!(popped.entry, 7);
        assert_eq!(popped.symbol.id().esi(), 0);
        assert!(ring.is_empty());
    }

    #[test]
    fn encode_ahead_blocks_match_monolithic_block_geometry() {
        let config = RqConfig {
            symbol_size: 4,
            max_block_size: 6,
            ..RqConfig::default()
        };

        assert_eq!(
            encode_ahead_blocks(13, &config).expect("block plan"),
            vec![
                EncodeAheadBlock {
                    sbn: 0,
                    start: 0,
                    len: 6,
                    k: 2,
                },
                EncodeAheadBlock {
                    sbn: 1,
                    start: 6,
                    len: 6,
                    k: 2,
                },
                EncodeAheadBlock {
                    sbn: 2,
                    start: 12,
                    len: 1,
                    k: 1,
                },
            ]
        );
        assert!(
            encode_ahead_blocks(0, &config)
                .expect("empty plan")
                .is_empty()
        );

        let small_blocks = RqConfig {
            symbol_size: 8,
            max_block_size: 3,
            ..RqConfig::default()
        };
        assert_eq!(
            encode_ahead_blocks(7, &small_blocks).expect("small block plan"),
            vec![
                EncodeAheadBlock {
                    sbn: 0,
                    start: 0,
                    len: 3,
                    k: 1,
                },
                EncodeAheadBlock {
                    sbn: 1,
                    start: 3,
                    len: 3,
                    k: 1,
                },
                EncodeAheadBlock {
                    sbn: 2,
                    start: 6,
                    len: 1,
                    k: 1,
                },
            ]
        );
    }

    #[test]
    fn read_source_range_reassembles_original_bytes_on_demand() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("payload.bin");
        let bytes: Vec<u8> = (0..257).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &bytes).expect("write payload");

        let mut reassembled = Vec::new();
        for (offset, len) in [(0, 17), (17, 64), (81, 128), (209, 48)] {
            let chunk = futures_lite::future::block_on(read_source_range(&path, offset, len))
                .expect("read source chunk");
            reassembled.extend_from_slice(&chunk);
        }

        assert_eq!(reassembled, bytes);
    }

    #[test]
    fn read_source_range_fails_closed_on_truncated_source() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, b"short").expect("write payload");

        let err = futures_lite::future::block_on(read_source_range(&path, 2, 8))
            .expect_err("range past EOF must fail");
        assert!(
            matches!(&err, RqError::Source(message) if message.contains("payload.bin")),
            "expected source-path error, got {err:?}"
        );
    }

    #[test]
    fn source_block_progress_covers_complete_entries_or_disables_streaming() {
        let progress = source_block_progress_for(5, 2, 2).expect("complete block table");
        assert_eq!(progress.len(), 3);
        assert_eq!(
            progress
                .iter()
                .map(|block| (block.start, block.len, block.k, block.received.len()))
                .collect::<Vec<_>>(),
            vec![(0, 2, 1, 1), (2, 2, 1, 1), (4, 1, 1, 1)]
        );

        let too_many_blocks = u64::try_from(MAX_SOURCE_BLOCKS + 1).unwrap_or(u64::MAX);
        assert!(
            source_block_progress_for(too_many_blocks, 1, 1).is_none(),
            "source streaming must fall back to the decoder when the SBN envelope is incomplete"
        );
    }

    #[test]
    fn m1_encode_ahead_source_and_initial_repair_is_byte_identical() {
        let config = RqConfig {
            symbol_size: 4,
            max_block_size: 6,
            repair_overhead: 1.0,
            ..RqConfig::default()
        };
        let object_id = ObjectId::new_for_test(0xF202);
        let bytes = b"abcdefghijklmnopq";

        assert_eq!(
            collect_m1_source_symbols(object_id, bytes, &config, 2),
            collect_monolithic_symbols(object_id, bytes, &config, 2)
        );
    }

    #[test]
    fn m1_encode_ahead_repair_range_is_byte_identical() {
        let config = RqConfig {
            symbol_size: 4,
            max_block_size: 6,
            repair_overhead: 1.0,
            ..RqConfig::default()
        };
        let object_id = ObjectId::new_for_test(0xF203);
        let bytes = b"repair-rounds-span-blocks";

        assert_eq!(
            collect_m1_repair_symbols(object_id, bytes, &config, 1, 3),
            collect_monolithic_repair_symbols(object_id, bytes, &config, 1, 3)
        );
    }

    #[test]
    fn object_params_match_block_plan() {
        // 3 MiB with 8 MiB blocks => 1 block; 1024-byte symbols => K=3072.
        let p = object_params_for(ObjectId::new(0, 0), 3 * 1024 * 1024, 1024, 8 * 1024 * 1024);
        assert_eq!(p.source_blocks, 1);
        assert_eq!(p.symbols_per_block, 3072);
        // 20 MiB with 8 MiB blocks => 3 blocks (8+8+4).
        let p2 = object_params_for(ObjectId::new(0, 0), 20 * 1024 * 1024, 1024, 8 * 1024 * 1024);
        assert_eq!(p2.source_blocks, 3);
        assert_eq!(p2.symbols_per_block, 8192);
    }

    // ─── E-12 large-entry multi-object split ───────────────────────────────

    fn digest_for_bytes(rel_path: &str, bytes: &[u8]) -> EntryDigest {
        EntryDigest {
            rel_path: rel_path.to_string(),
            size: bytes.len() as u64,
            content_id: crate::atp::object::ObjectId::content(
                crate::atp::object::ContentId::from_bytes(bytes),
            ),
            content_sha256: Sha256::digest(bytes).into(),
        }
    }

    fn fragment_entry(
        index: u32,
        object_rel_path: &str,
        object_bytes: &[u8],
        fragment: LargeObjectFragment,
    ) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: object_rel_path.to_string(),
            size: object_bytes.len() as u64,
            sha256_hex: hex_encode(&Sha256::digest(object_bytes)),
            members: Vec::new(),
            fragment: Some(fragment),
        }
    }

    #[test]
    fn split_large_entries_plans_bounded_ranged_objects() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
        let entry = source_entry(dir.path(), "huge.bin", &bytes);
        let logical = vec![digest_for_bytes("huge.bin", &bytes)];
        let config = RqConfig {
            symbol_size: 1,
            max_block_size: 1,
            ..RqConfig::default()
        };

        let split =
            futures_lite::future::block_on(split_large_entries(vec![entry], &logical, &config))
                .expect("split large entry");

        assert_eq!(split.len(), 3, "600 bytes at 256-byte objects => 3 shards");
        assert_eq!(split[0].source_offset, 0);
        assert_eq!(split[0].source_len, Some(256));
        assert_eq!(split[1].source_offset, 256);
        assert_eq!(split[1].source_len, Some(256));
        assert_eq!(split[2].source_offset, 512);
        assert_eq!(split[2].source_len, Some(88));
        for (idx, shard) in split.iter().enumerate() {
            let fragment = shard.fragment.as_ref().expect("fragment metadata");
            assert_eq!(fragment.rel_path, "huge.bin");
            assert_eq!(fragment.shard_index, idx as u32);
            assert_eq!(fragment.shard_count, 3);
            assert_eq!(fragment.logical_size, bytes.len() as u64);
            assert_eq!(fragment.sha256_hex, hex_encode(&Sha256::digest(&bytes)));
        }

        let mut buf = vec![0u8; 64];
        let (range_size, _, range_sha) =
            futures_lite::future::block_on(hash_source_entry_streaming(&split[1], &mut buf))
                .expect("range hash");
        assert_eq!(range_size, 256);
        let expected_range_sha: [u8; 32] = Sha256::digest(&bytes[256..512]).into();
        assert_eq!(range_sha, expected_range_sha);
    }

    #[test]
    fn validate_manifest_accepts_and_bounds_fragment_table() {
        let whole = b"abcdefghijklmnopqrstuvwxyz".to_vec();
        let a = &whole[..10];
        let b = &whole[10..];
        let whole_sha = hex_encode(&Sha256::digest(&whole));
        let entries = vec![
            fragment_entry(
                0,
                ".atp-fragment-0-0",
                a,
                LargeObjectFragment {
                    rel_path: "huge.bin".to_string(),
                    shard_index: 0,
                    shard_count: 2,
                    logical_offset: 0,
                    len: a.len() as u64,
                    logical_size: whole.len() as u64,
                    sha256_hex: whole_sha.clone(),
                },
            ),
            fragment_entry(
                1,
                ".atp-fragment-0-1",
                b,
                LargeObjectFragment {
                    rel_path: "huge.bin".to_string(),
                    shard_index: 1,
                    shard_count: 2,
                    logical_offset: a.len() as u64,
                    len: b.len() as u64,
                    logical_size: whole.len() as u64,
                    sha256_hex: whole_sha,
                },
            ),
        ];
        let manifest = TransferManifest {
            transfer_id: "rqtransfer1".to_string(),
            root_name: "huge.bin".to_string(),
            is_directory: false,
            total_bytes: whole.len() as u64,
            merkle_root_hex: flat_merkle_root_from_digests(&[digest_for_bytes("huge.bin", &whole)]),
            entries,
        };
        assert!(validate_manifest(&manifest, &RqConfig::default()).is_ok());

        let mut gapped = manifest.clone();
        gapped.entries[0]
            .fragment
            .as_mut()
            .expect("fragment")
            .logical_size += 1;
        gapped.entries[1]
            .fragment
            .as_mut()
            .expect("fragment")
            .logical_offset += 1;
        gapped.entries[1]
            .fragment
            .as_mut()
            .expect("fragment")
            .logical_size += 1;
        assert!(matches!(
            validate_manifest(&gapped, &RqConfig::default()),
            Err(RqError::Frame(m)) if m.contains("not contiguous")
        ));
    }

    #[test]
    fn verify_and_commit_reassembles_fragmented_file() {
        let dest = tempfile::tempdir().expect("dest dir");
        let staging_dir = dest.path().join(".atp-rq-fragment-staging");
        std::fs::create_dir_all(&staging_dir).expect("staging dir");

        let a = b"first fragment ".to_vec();
        let b = b"second fragment".to_vec();
        let mut whole = Vec::new();
        whole.extend_from_slice(&a);
        whole.extend_from_slice(&b);
        let a_path = staging_dir.join("0");
        let b_path = staging_dir.join("1");
        std::fs::write(&a_path, &a).expect("write first shard");
        std::fs::write(&b_path, &b).expect("write second shard");

        let whole_sha = hex_encode(&Sha256::digest(&whole));
        let manifest = TransferManifest {
            transfer_id: "rqtransfer1".to_string(),
            root_name: "huge.bin".to_string(),
            is_directory: false,
            total_bytes: whole.len() as u64,
            merkle_root_hex: flat_merkle_root_from_digests(&[digest_for_bytes("huge.bin", &whole)]),
            entries: vec![
                fragment_entry(
                    0,
                    ".atp-fragment-0-0",
                    &a,
                    LargeObjectFragment {
                        rel_path: "huge.bin".to_string(),
                        shard_index: 0,
                        shard_count: 2,
                        logical_offset: 0,
                        len: a.len() as u64,
                        logical_size: whole.len() as u64,
                        sha256_hex: whole_sha.clone(),
                    },
                ),
                fragment_entry(
                    1,
                    ".atp-fragment-0-1",
                    &b,
                    LargeObjectFragment {
                        rel_path: "huge.bin".to_string(),
                        shard_index: 1,
                        shard_count: 2,
                        logical_offset: a.len() as u64,
                        len: b.len() as u64,
                        logical_size: whole.len() as u64,
                        sha256_hex: whole_sha,
                    },
                ),
            ],
        };
        let mut decoders = vec![
            EntryDecoder {
                index: 0,
                object_id: entry_object_id(&manifest.transfer_id, 0),
                size: a.len() as u64,
                pipeline: None,
                complete: true,
                staging_path: a_path,
                staging_created: true,
                staging_file: None,
                staging_cursor: None,
                staging_unflushed_bytes: 0,
                cache_staging_file: false,
                bytes_written: a.len() as u64,
                max_block_size: DEFAULT_MAX_BLOCK_SIZE,
                source_streaming: false,
                source_blocks: Vec::new(),
                pending_decodes: Vec::new(),
            },
            EntryDecoder {
                index: 1,
                object_id: entry_object_id(&manifest.transfer_id, 1),
                size: b.len() as u64,
                pipeline: None,
                complete: true,
                staging_path: b_path,
                staging_created: true,
                staging_file: None,
                staging_cursor: None,
                staging_unflushed_bytes: 0,
                cache_staging_file: false,
                bytes_written: b.len() as u64,
                max_block_size: DEFAULT_MAX_BLOCK_SIZE,
                source_streaming: false,
                source_blocks: Vec::new(),
                pending_decodes: Vec::new(),
            },
        ];

        let receipt = futures_lite::future::block_on(verify_and_commit(
            &manifest,
            &mut decoders,
            dest.path(),
            0,
            0,
        ))
        .expect("verify fragmented file");

        assert!(receipt.committed, "fragmented transfer must commit");
        assert!(receipt.sha_ok);
        assert!(receipt.merkle_ok);
        assert_eq!(receipt.files, 1);
        assert_eq!(std::fs::read(dest.path().join("huge.bin")).unwrap(), whole);
    }

    // ─── E-15 tree coalescing (pack / split) ───────────────────────────────

    fn source_entry(dir: &Path, rel: &str, bytes: &[u8]) -> RqSourceEntry {
        let abs = dir.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&abs, bytes).expect("write source file");
        RqSourceEntry {
            rel_path: rel.to_string(),
            abs_path: abs,
            source_offset: 0,
            source_len: None,
            members: Vec::new(),
            fragment: None,
        }
    }

    #[test]
    fn pack_small_files_records_offsets_lens_and_member_sha() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Three small files (< PACK_THRESHOLD) -> one combined object.
        let a = vec![0xAAu8; 100];
        let b = vec![0xBBu8; 250];
        let c = vec![0xCCu8; 7];
        let entries = vec![
            source_entry(dir.path(), "d/a", &a),
            source_entry(dir.path(), "d/b", &b),
            source_entry(dir.path(), "z/c", &c),
        ];

        let config = RqConfig::default();
        let (packed, logical_digests, tempdir) =
            futures_lite::future::block_on(pack_small_files(entries, &config)).expect("pack");
        let _tempdir = tempdir.expect("a pack temp dir was produced");

        assert_eq!(
            packed.len(),
            1,
            "three small files coalesce into one object"
        );
        let pack = &packed[0];
        assert_eq!(pack.rel_path, ".atp-pack-0");
        assert_eq!(pack.members.len(), 3);

        // Members appear in sorted (manifest) order with contiguous offsets.
        assert_eq!(pack.members[0].rel_path, "d/a");
        assert_eq!(pack.members[0].offset, 0);
        assert_eq!(pack.members[0].len, 100);
        assert_eq!(pack.members[1].rel_path, "d/b");
        assert_eq!(pack.members[1].offset, 100);
        assert_eq!(pack.members[1].len, 250);
        assert_eq!(pack.members[2].rel_path, "z/c");
        assert_eq!(pack.members[2].offset, 350);
        assert_eq!(pack.members[2].len, 7);

        // Per-member sha matches the file content.
        assert_eq!(pack.members[0].sha256_hex, hex_encode(&Sha256::digest(&a)));
        assert_eq!(pack.members[1].sha256_hex, hex_encode(&Sha256::digest(&b)));
        assert_eq!(pack.members[2].sha256_hex, hex_encode(&Sha256::digest(&c)));

        // The temp object is the concatenation in offset order.
        let on_disk = std::fs::read(&pack.abs_path).expect("read pack object");
        let mut expected = Vec::new();
        expected.extend_from_slice(&a);
        expected.extend_from_slice(&b);
        expected.extend_from_slice(&c);
        assert_eq!(on_disk, expected, "pack object is the member concatenation");

        // Logical digests cover every logical file (members flattened).
        assert_eq!(logical_digests.len(), 3);
        let logical_root = flat_merkle_root_from_digests(&logical_digests);
        // Same set of {rel_path, content} -> same root as the unpacked files.
        let direct: Vec<EntryDigest> = [("d/a", &a), ("d/b", &b), ("z/c", &c)]
            .into_iter()
            .map(|(rel, bytes)| EntryDigest {
                rel_path: rel.to_string(),
                size: bytes.len() as u64,
                content_id: crate::atp::object::ObjectId::content(
                    crate::atp::object::ContentId::from_bytes(bytes),
                ),
                content_sha256: Sha256::digest(bytes).into(),
            })
            .collect();
        assert_eq!(
            logical_root,
            flat_merkle_root_from_digests(&direct),
            "logical merkle root is invariant to packing"
        );
    }

    #[test]
    fn pack_small_files_leaves_large_files_unpacked_and_root_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Two files >= PACK_THRESHOLD: neither is packed, nothing materialized.
        let big1 = vec![1u8; PACK_THRESHOLD as usize];
        let big2 = vec![2u8; PACK_THRESHOLD as usize + 13];
        let entries = vec![
            source_entry(dir.path(), "big1", &big1),
            source_entry(dir.path(), "big2", &big2),
        ];

        let config = RqConfig::default();
        let (packed, logical_digests, tempdir) =
            futures_lite::future::block_on(pack_small_files(entries, &config)).expect("pack");
        assert!(tempdir.is_none(), "no packing => no temp dir");
        assert_eq!(packed.len(), 2);
        assert!(packed.iter().all(|e| e.members.is_empty()));
        assert_eq!(packed[0].rel_path, "big1");
        assert_eq!(packed[1].rel_path, "big2");
        assert_eq!(logical_digests.len(), 2);
        // Byte-identical to the per-file digest path the caller would build.
        assert_eq!(logical_digests[0].size, big1.len() as u64);
        assert_eq!(logical_digests[1].size, big2.len() as u64);
    }

    #[test]
    fn pack_small_files_single_small_file_is_not_packed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let entries = vec![source_entry(dir.path(), "only", b"tiny")];
        let config = RqConfig::default();
        let (packed, logical_digests, tempdir) =
            futures_lite::future::block_on(pack_small_files(entries, &config)).expect("pack");
        assert!(tempdir.is_none(), "a lone small file is not packed");
        assert_eq!(packed.len(), 1);
        assert!(packed[0].members.is_empty());
        assert_eq!(packed[0].rel_path, "only");
        assert_eq!(logical_digests.len(), 1);
    }

    #[test]
    fn pack_small_files_respects_configured_object_ceiling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let too_large_for_one_object = vec![0xA5u8; MAX_SOURCE_BLOCKS + 44];
        let tail = vec![0x5Au8; 20];
        let entries = vec![
            source_entry(dir.path(), "needs-split", &too_large_for_one_object),
            source_entry(dir.path(), "tail", &tail),
        ];
        let config = RqConfig {
            symbol_size: 1,
            max_block_size: 1,
            ..RqConfig::default()
        };

        let (packed, logical_digests, tempdir) =
            futures_lite::future::block_on(pack_small_files(entries, &config)).expect("pack");

        assert!(
            tempdir.is_none(),
            "packing must not create an unsplittable object above the configured ceiling"
        );
        assert_eq!(packed.len(), 2);
        assert!(packed.iter().all(|entry| entry.members.is_empty()));

        let split =
            futures_lite::future::block_on(split_large_entries(packed, &logical_digests, &config))
                .expect("E-12 split after E-15 pack cap");
        assert_eq!(
            split
                .iter()
                .filter(|entry| entry.fragment.is_some())
                .count(),
            2,
            "the over-ceiling small file remains available for ranged object splitting"
        );
        assert!(split.iter().all(|entry| entry.members.is_empty()));
    }

    /// End-to-end (in-process) split: build a packed manifest + a staging file
    /// holding the member concatenation, then verify_and_commit must split it
    /// into the member files on disk, byte-identical.
    #[test]
    fn verify_and_commit_splits_packed_object_into_members() {
        let dest = tempfile::tempdir().expect("dest dir");
        let staging_dir = dest.path().join(".atp-rq-test-staging");
        std::fs::create_dir_all(&staging_dir).expect("staging dir");

        let a = b"first-member-bytes".to_vec();
        let b = b"second member, a little longer".to_vec();
        let mut object = Vec::new();
        object.extend_from_slice(&a);
        object.extend_from_slice(&b);
        let staging_path = staging_dir.join("0");
        std::fs::write(&staging_path, &object).expect("write packed staging object");

        let members = vec![
            PackedMember {
                rel_path: "dir/a.txt".to_string(),
                offset: 0,
                len: a.len() as u64,
                sha256_hex: hex_encode(&Sha256::digest(&a)),
            },
            PackedMember {
                rel_path: "dir/sub/b.txt".to_string(),
                offset: a.len() as u64,
                len: b.len() as u64,
                sha256_hex: hex_encode(&Sha256::digest(&b)),
            },
        ];

        // Merkle root over the LOGICAL files (what the sender computes).
        let logical: Vec<EntryDigest> = [("dir/a.txt", &a), ("dir/sub/b.txt", &b)]
            .into_iter()
            .map(|(rel, bytes)| EntryDigest {
                rel_path: rel.to_string(),
                size: bytes.len() as u64,
                content_id: crate::atp::object::ObjectId::content(
                    crate::atp::object::ContentId::from_bytes(bytes),
                ),
                content_sha256: Sha256::digest(bytes).into(),
            })
            .collect();
        let merkle_root_hex = flat_merkle_root_from_digests(&logical);
        let object_sha = hex_encode(&Sha256::digest(&object));

        let manifest = TransferManifest {
            transfer_id: "rqtransfer1".to_string(),
            root_name: "payload".to_string(),
            is_directory: true,
            total_bytes: object.len() as u64,
            merkle_root_hex,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: ".atp-pack-0".to_string(),
                size: object.len() as u64,
                sha256_hex: object_sha,
                members,
                fragment: None,
            }],
        };
        let mut decoders = vec![EntryDecoder {
            index: 0,
            object_id: entry_object_id(&manifest.transfer_id, 0),
            size: object.len() as u64,
            pipeline: None,
            complete: true,
            staging_path,
            staging_created: true,
            staging_file: None,
            staging_cursor: None,
            staging_unflushed_bytes: 0,
            cache_staging_file: false,
            bytes_written: object.len() as u64,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            source_streaming: false,
            source_blocks: Vec::new(),
            pending_decodes: Vec::new(),
        }];

        let receipt = futures_lite::future::block_on(verify_and_commit(
            &manifest,
            &mut decoders,
            dest.path(),
            0,
            0,
        ))
        .expect("verify_and_commit");

        assert!(
            receipt.committed,
            "packed transfer must commit: {receipt:?}"
        );
        assert!(receipt.sha_ok);
        assert!(receipt.merkle_ok);
        assert_eq!(receipt.files, 2, "two LOGICAL files delivered");

        let out_a = dest.path().join("payload/dir/a.txt");
        let out_b = dest.path().join("payload/dir/sub/b.txt");
        assert_eq!(std::fs::read(&out_a).expect("member a"), a);
        assert_eq!(std::fs::read(&out_b).expect("member b"), b);
        // The synthetic packed object name must not appear on disk.
        assert!(!dest.path().join("payload/.atp-pack-0").exists());
    }

    #[test]
    fn validate_manifest_checks_packed_member_table() {
        // A well-formed packed manifest entry is accepted.
        let good_members = vec![
            PackedMember {
                rel_path: "dir/a".to_string(),
                offset: 0,
                len: 10,
                sha256_hex: "aa".repeat(32),
            },
            PackedMember {
                rel_path: "dir/b".to_string(),
                offset: 10,
                len: 5,
                sha256_hex: "bb".repeat(32),
            },
        ];
        let ok_entry = ManifestEntry {
            index: 0,
            rel_path: ".atp-pack-0".to_string(),
            size: 15,
            sha256_hex: "cc".repeat(32),
            members: good_members.clone(),
            fragment: None,
        };
        assert!(
            validate_manifest(&manifest_with(vec![ok_entry], 15), &RqConfig::default()).is_ok()
        );

        // Non-contiguous offsets fail closed.
        let mut gap = good_members.clone();
        gap[1].offset = 11;
        let entry = ManifestEntry {
            index: 0,
            rel_path: ".atp-pack-0".to_string(),
            size: 15,
            sha256_hex: "cc".repeat(32),
            members: gap,
            fragment: None,
        };
        assert!(matches!(
            validate_manifest(&manifest_with(vec![entry], 15), &RqConfig::default()),
            Err(RqError::Frame(m)) if m.contains("not contiguous")
        ));

        // Member lengths must tile the object exactly.
        let entry = ManifestEntry {
            index: 0,
            rel_path: ".atp-pack-0".to_string(),
            size: 99,
            sha256_hex: "cc".repeat(32),
            members: good_members.clone(),
            fragment: None,
        };
        assert!(matches!(
            validate_manifest(&manifest_with(vec![entry], 99), &RqConfig::default()),
            Err(RqError::Frame(m)) if m.contains("members cover")
        ));

        // An unsafe member rel_path fails closed.
        let mut evil = good_members;
        evil[1].rel_path = "../escape".to_string();
        let entry = ManifestEntry {
            index: 0,
            rel_path: ".atp-pack-0".to_string(),
            size: 15,
            sha256_hex: "cc".repeat(32),
            members: evil,
            fragment: None,
        };
        assert!(matches!(
            validate_manifest(&manifest_with(vec![entry], 15), &RqConfig::default()),
            Err(RqError::Source(m)) if m.contains("unsafe manifest rel_path")
        ));
    }

    /// A corrupted member sha must fail closed: nothing is committed/written.
    #[test]
    fn verify_and_commit_rejects_packed_object_with_wrong_member_sha() {
        let dest = tempfile::tempdir().expect("dest dir");
        let staging_dir = dest.path().join(".atp-rq-test-staging");
        std::fs::create_dir_all(&staging_dir).expect("staging dir");

        let a = b"member-one".to_vec();
        let b = b"member-two".to_vec();
        let mut object = Vec::new();
        object.extend_from_slice(&a);
        object.extend_from_slice(&b);
        let staging_path = staging_dir.join("0");
        std::fs::write(&staging_path, &object).expect("write packed staging object");

        // Build a correct logical merkle root, but lie about member b's sha so
        // the per-member check fails (object sha + merkle stay self-consistent).
        let logical: Vec<EntryDigest> = [("a.txt", &a), ("b.txt", &b)]
            .into_iter()
            .map(|(rel, bytes)| EntryDigest {
                rel_path: rel.to_string(),
                size: bytes.len() as u64,
                content_id: crate::atp::object::ObjectId::content(
                    crate::atp::object::ContentId::from_bytes(bytes),
                ),
                content_sha256: Sha256::digest(bytes).into(),
            })
            .collect();
        let merkle_root_hex = flat_merkle_root_from_digests(&logical);

        let manifest = TransferManifest {
            transfer_id: "rqtransfer1".to_string(),
            root_name: "payload".to_string(),
            is_directory: true,
            total_bytes: object.len() as u64,
            merkle_root_hex,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: ".atp-pack-0".to_string(),
                size: object.len() as u64,
                sha256_hex: hex_encode(&Sha256::digest(&object)),
                members: vec![
                    PackedMember {
                        rel_path: "a.txt".to_string(),
                        offset: 0,
                        len: a.len() as u64,
                        sha256_hex: hex_encode(&Sha256::digest(&a)),
                    },
                    PackedMember {
                        rel_path: "b.txt".to_string(),
                        offset: a.len() as u64,
                        len: b.len() as u64,
                        // WRONG sha for member b.
                        sha256_hex: "ff".repeat(32),
                    },
                ],
                fragment: None,
            }],
        };
        let mut decoders = vec![EntryDecoder {
            index: 0,
            object_id: entry_object_id(&manifest.transfer_id, 0),
            size: object.len() as u64,
            pipeline: None,
            complete: true,
            staging_path,
            staging_created: true,
            staging_file: None,
            staging_cursor: None,
            staging_unflushed_bytes: 0,
            cache_staging_file: false,
            bytes_written: object.len() as u64,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            source_streaming: false,
            source_blocks: Vec::new(),
            pending_decodes: Vec::new(),
        }];

        let receipt = futures_lite::future::block_on(verify_and_commit(
            &manifest,
            &mut decoders,
            dest.path(),
            0,
            0,
        ))
        .expect("verify_and_commit returns a receipt");

        assert!(!receipt.committed, "wrong member sha must fail closed");
        assert!(!receipt.sha_ok);
        // Nothing written into place.
        assert!(!dest.path().join("payload/a.txt").exists());
        assert!(!dest.path().join("payload/b.txt").exists());
    }
}
