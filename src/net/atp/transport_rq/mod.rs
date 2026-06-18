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

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Adaptive block-size / overhead / fan-out optimizer; see
/// `docs/atp_rq_adaptive_design.md`.
pub mod adaptive;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::cx::Cx;
use crate::decoding::{DecodingConfig, DecodingPipeline, MissingSourceSymbol, SymbolAcceptResult};
use crate::encoding::{EncodedSymbol, EncodingPipeline, MAX_SOURCE_BLOCKS, max_object_size};
use crate::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use crate::net::atp::datagram::beacons::{BeaconMeasurement, BeaconScheduler};
use crate::net::atp::datagram::congestion::{CongestionConfig, CongestionController};
use crate::net::atp::loss::detector::{AtpLossDetector, LossRecommendation};
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use crate::net::atp::transport_common::{
    EntryDigest, flat_merkle_root_from_digests, hash_file_streaming, hex_encode,
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
/// With 1 KiB symbols this bounds a block at ~8192 source symbols (well under
/// the RFC 6330 K=56403 cap) and lets a single entry span up to 256 blocks (SBN
/// is a `u8`), i.e. up to ~2 GiB per entry.
pub const DEFAULT_MAX_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// Target source-symbol count for the effective transfer block size.
///
/// RaptorQ's matrix work grows sharply with K. A K~512 block is small enough to
/// keep decode/repair work bounded on commodity fleet hosts while still sending
/// large enough UDP bursts to amortize control feedback. For very large files,
/// the effective block size grows only as much as required to stay within the
/// 256-block SBN wire limit.
const TARGET_SOURCE_SYMBOLS_PER_BLOCK: usize = 512;
/// Byte ceiling for the normal streaming block-size target. Larger blocks are
/// allowed only when the 256-block SBN wire limit requires them.
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
const RQ_LOSS_BAR_MULTIPLIER: f64 = 1.75;
const RQ_PENDING_PRESSURE_LOSS_FLOOR: f64 = 0.05;
const RQ_REGIME_SHIFT_LOSS_DELTA: f64 = 0.20;
const RQ_SOURCE_FEC_FALLBACK_ALPHA: f64 = 1e-6;
const RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD: f64 = 0.50;

/// Packets pulled from the UDP socket per receive-pump turn.
///
/// Mirrors the native QUIC inbound pump batch width so RQ drains bursty symbol
/// sprays after one readiness wait instead of waking once per datagram.
const RQ_INBOUND_PUMP_BATCH: usize = 512;
/// Maximum full batches drained after the first ready batch in one pump turn.
const RQ_INBOUND_PUMP_MAX_DRAIN_BATCHES: usize = 64;
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
    max_rate_per_sec: u32,
    max_burst_size: u32,
    min_send_interval: Duration,
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
        rate_bps: u64,
        symbol_size: u16,
        burst_symbols: usize,
        rtt: Option<Duration>,
        loss_detected: bool,
    ) -> Self {
        let pacing_rate_bps = rate_bps.clamp(RQ_MIN_PACING_BPS, RQ_MAX_PACING_BPS);
        let symbol_bytes = u64::from(symbol_size.max(1))
            .saturating_add(u64::try_from(AUTH_DGRAM_HEADER).unwrap_or(u64::MAX));
        let max_rate_per_sec = pacing_rate_bps
            .div_ceil(symbol_bytes.max(1))
            .clamp(1, u64::from(u32::MAX)) as u32;
        let max_burst_size = u32::try_from(burst_symbols.max(1))
            .unwrap_or(u32::MAX)
            .max(1);
        Self {
            max_rate_per_sec,
            max_burst_size,
            min_send_interval: Duration::ZERO,
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
        controller.configure_token_bucket(
            pacing.max_rate_per_sec,
            pacing.max_burst_size,
            pacing.min_send_interval,
        );
        controller.update_congestion_feedback(pacing.rtt, pacing.loss_detected);
        Self { controller }
    }

    fn configure(&mut self, pacing: RqSprayPacing) {
        self.controller.configure_token_bucket(
            pacing.max_rate_per_sec,
            pacing.max_burst_size,
            pacing.min_send_interval,
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
                    .collect::<Vec<_>>();
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

    fn round_tuning(&mut self, config: &RqConfig) -> RqRoundTuning {
        let fixed = RqRoundTuning {
            repair_overhead: config.repair_overhead.max(1.0),
            pacing: RqSprayPacing::cold_start(config.symbol_size),
        };
        let Some(plan) = self.controller.next_block_plan(self.symbol_size) else {
            return fixed;
        };

        let mut repair_overhead = config
            .repair_overhead
            .max(1.0 + plan.overhead)
            .max(1.0 + self.loss_fec_floor);
        let mut rate = self.pacing_rate_for(plan);
        if let Some(cap) = self.loss_pacing_cap_bps {
            rate = rate.min(cap);
        }
        if self.regime_shift || self.loss_bar >= RQ_REGIME_SHIFT_LOSS_DELTA {
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
                self.loss_ema > 0.0,
            ),
        }
    }

    fn source_fec_fallback_tuning(&mut self, config: &RqConfig) -> RqRoundTuning {
        let mut tuning = self.round_tuning(config);
        let k = fixed_block_k(config);
        let loss_bar = self.loss_bar.max(self.loss_ema).max(0.01);
        let overhead = adaptive::overhead_for_target(
            k,
            loss_bar,
            RQ_SOURCE_FEC_FALLBACK_ALPHA,
            RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD,
        );
        tuning.repair_overhead = tuning.repair_overhead.max(1.0 + overhead).max(1.03);
        tuning
    }

    fn observe_need_more(
        &mut self,
        config: &RqConfig,
        digests: &[EntryDigest],
        pending: &BTreeSet<u32>,
        sent_this_round: u64,
        round_wall: Duration,
        control_wait: Duration,
        total_bytes: u64,
    ) {
        self.record_beacon_exchange(control_wait);

        let round_wall_s = finite_duration_s(round_wall);
        let rtt_s = finite_duration_s(control_wait);
        let pending_bytes = pending_bytes(digests, pending);
        let sent_symbols = sent_this_round.max(1);
        let pending_units = u64::try_from(pending.len()).unwrap_or(u64::MAX).max(1);
        let pending_loss = (pending_units as f64 / sent_symbols as f64).clamp(0.0, 1.0);
        let byte_pressure = if total_bytes == 0 {
            0.0
        } else {
            (pending_bytes as f64 / total_bytes as f64).clamp(0.0, 1.0)
        };
        let pressure_loss = byte_pressure * RQ_PENDING_PRESSURE_LOSS_FLOOR;
        let loss_hat = pending_loss.max(pressure_loss).clamp(0.0, 0.90);

        self.regime_shift =
            self.loss_ema > 0.0 && loss_hat > (self.loss_ema * 3.0 + RQ_REGIME_SHIFT_LOSS_DELTA);
        self.loss_ema = ema(self.loss_ema, loss_hat, RQ_LOSS_EMA_ALPHA);
        let raw_loss_bar = loss_hat.max(self.loss_ema) * RQ_LOSS_BAR_MULTIPLIER;
        self.loss_bar = if self.loss_bar <= 0.0 {
            raw_loss_bar
        } else {
            ema(self.loss_bar, raw_loss_bar, RQ_LOSS_EMA_ALPHA).max(loss_hat)
        }
        .clamp(0.0, 0.90);

        let symbol_payload_bytes = u64::from(config.symbol_size.max(1));
        let sent_payload_bytes = sent_symbols.saturating_mul(symbol_payload_bytes);
        let offered_bps = (sent_payload_bytes as f64 / round_wall_s).max(1.0);
        let useful_factor = (1.0 - byte_pressure * 0.5).clamp(0.25, 1.0);
        let bw_sample = offered_bps * useful_factor;
        self.bw_ema_bps = if self.bw_ema_bps <= 0.0 {
            bw_sample
        } else {
            ema(self.bw_ema_bps, bw_sample, RQ_BW_EMA_ALPHA)
        };
        self.bw_trough_bps = if self.bw_trough_bps <= 0.0 {
            bw_sample
        } else {
            self.bw_trough_bps.min(bw_sample)
        };

        self.est = PathEstimate {
            rtt_s,
            loss_p_hat: self.loss_ema,
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

        let received = ((sent_symbols as f64) * (1.0 - loss_hat)).max(0.0) as u64;
        let useful_bytes = ((sent_payload_bytes as f64) * (1.0 - loss_hat)).max(0.0) as u64;
        let cwnd_bytes = (self.bw_ema_bps * rtt_s)
            .max(f64::from(config.symbol_size.max(1)))
            .ceil() as u64;
        self.loss_pacing_cap_bps = None;
        self.loss_fec_floor = 0.0;
        let lost_symbols = ((sent_symbols as f64) * loss_hat).ceil() as u64;
        let loss_result = self.loss_detector.observe_datagram_loss_sample(
            sent_symbols,
            lost_symbols,
            Some(control_wait),
            sent_payload_bytes,
            cwnd_bytes,
        );
        self.apply_loss_recommendations(&loss_result.recommendations);
        self.controller.observe_path_signals(
            sent_symbols,
            received,
            round_wall_s,
            useful_bytes,
            config.symbol_size,
            PathSignalSample {
                smoothed_rtt_s: rtt_s,
                congestion_window_bytes: cwnd_bytes.max(u64::from(config.symbol_size.max(1))),
                loss_rate: loss_hat,
            },
        );
    }

    fn apply_loss_recommendations(&mut self, recommendations: &[LossRecommendation]) {
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
                LossRecommendation::SwitchCongestionControl { .. } => {
                    self.regime_shift = true;
                    let cap = if self.bw_ema_bps > 0.0 {
                        (self.bw_ema_bps * 0.5).ceil() as u64
                    } else {
                        RQ_COLD_START_PACING_BPS / 2
                    };
                    self.lower_pacing_cap(cap);
                    self.loss_fec_floor = self.loss_fec_floor.max(0.03);
                }
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
        round_wall: Duration,
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

        let round_wall_s = finite_duration_s(round_wall);
        let rtt_s = finite_duration_s(control_wait);
        let sent_payload_bytes =
            sent_this_round.saturating_mul(u64::from(config.symbol_size.max(1)));
        let bw_sample = (sent_payload_bytes as f64 / round_wall_s).max(1.0);
        self.bw_ema_bps = if self.bw_ema_bps <= 0.0 {
            bw_sample
        } else {
            ema(self.bw_ema_bps, bw_sample, RQ_BW_EMA_ALPHA)
        };
        self.bw_trough_bps = if self.bw_trough_bps <= 0.0 {
            bw_sample
        } else {
            self.bw_trough_bps.min(bw_sample)
        };
        self.loss_ema = ema(self.loss_ema, 0.0, RQ_LOSS_EMA_ALPHA);
        self.loss_bar = ema(self.loss_bar, 0.0, RQ_LOSS_EMA_ALPHA);
        self.loss_pacing_cap_bps = None;
        self.loss_fec_floor = 0.0;

        self.est = PathEstimate {
            rtt_s,
            loss_p_hat: self.loss_ema,
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
            round_wall_s,
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
        let network_bps = if self.est.bw_median_bps > 0.0 {
            self.est.bw_median_bps.min(self.est.bw_trough_bps.max(1.0))
        } else {
            RQ_COLD_START_PACING_BPS as f64
        };
        let decode_bps =
            self.est.decode_symbols_per_s_at(plan.k) * f64::from(self.symbol_size.max(1));
        let base = network_bps.min(decode_bps.max(1.0));
        let rate = base / (1.0 + plan.overhead.max(0.0));
        rate.ceil()
            .clamp(RQ_MIN_PACING_BPS as f64, RQ_MAX_PACING_BPS as f64) as u64
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
    /// RaptorQ encode/decode error.
    #[error("coding error: {0}")]
    Coding(String),
    /// The fountain feedback loop ran out of rounds with entries still
    /// undecoded.
    #[error(
        "transfer did not converge after {rounds} feedback rounds ({pending} entries still incomplete)"
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
}

// ─── Helpers (entry walk + merkle, shared definition with transport_tcp) ─────

fn json_frame<T: Serialize>(ty: FrameType, value: &T) -> Result<Frame, RqError> {
    let payload = serde_json::to_vec(value).map_err(|e| RqError::Control(e.to_string()))?;
    Frame::new(ProtocolVersion::CURRENT, ty, payload).map_err(|e| RqError::Frame(e.to_string()))
}

fn parse_json<T: for<'de> Deserialize<'de>>(frame: &Frame) -> Result<T, RqError> {
    serde_json::from_slice(frame.payload()).map_err(|e| RqError::Control(e.to_string()))
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
                });
            }
        }
        Ok(())
    })
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
    if manifest.entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(RqError::Frame(format!(
            "manifest declares {} entries (max {MAX_MANIFEST_ENTRIES})",
            manifest.entries.len()
        )));
    }
    if !manifest.is_directory && manifest.entries.len() != 1 {
        return Err(RqError::Frame(format!(
            "single-file transfer manifest declares {} entries",
            manifest.entries.len()
        )));
    }

    let mut seen_rel_paths = BTreeSet::new();
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
                if !seen_rel_paths.insert(entry.rel_path.as_str()) {
                    return Err(RqError::Frame(format!(
                        "duplicate manifest rel_path: {}",
                        entry.rel_path
                    )));
                }
                Ok(acc.saturating_add(entry.size))
            })?;
    if declared_total > config.max_transfer_bytes {
        return Err(RqError::TooLarge {
            size: declared_total,
            max: config.max_transfer_bytes,
        });
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
    let max_supported = max_object_size(configured_max);
    if max_entry_len > max_supported {
        return Err(RqError::TooLarge {
            size: max_entry_len as u64,
            max: max_supported as u64,
        });
    }

    let target = symbol_size
        .saturating_mul(TARGET_SOURCE_SYMBOLS_PER_BLOCK)
        .min(TARGET_STREAMING_BLOCK_BYTES);
    let min_for_block_limit = max_entry_len
        .div_ceil(MAX_SOURCE_BLOCKS)
        .max(symbol_size)
        .div_ceil(symbol_size)
        .saturating_mul(symbol_size);

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
    file: Option<crate::fs::File>,
    bytes_written: u64,
    max_block_size: usize,
    source_streaming: bool,
    source_blocks: Vec<SourceBlockProgress>,
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

    let (root_name, is_directory, entries) = collect_entries(source).await?;
    let mut hash_buf = vec![0u8; RQ_STREAM_HASH_BUFFER_SIZE];
    let mut digests = Vec::with_capacity(entries.len());
    let mut total_bytes = 0u64;
    for entry in &entries {
        let (size, content_id, content_sha256) =
            hash_file_streaming(&entry.abs_path, &mut hash_buf)
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

    let merkle_root_hex = flat_merkle_root_from_digests(&digests);
    let manifest_entries: Vec<ManifestEntry> = digests
        .iter()
        .enumerate()
        .map(|(i, digest)| ManifestEntry {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            rel_path: digest.rel_path.clone(),
            size: digest.size,
            sha256_hex: hex_encode(&digest.content_sha256),
        })
        .collect();
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

    let mut encoders: Vec<EntryEncoder> = entries
        .iter()
        .zip(digests.iter())
        .enumerate()
        .map(|(i, (entry, digest))| {
            let index = u32::try_from(i).unwrap_or(u32::MAX);
            let size = usize::try_from(digest.size).unwrap_or(usize::MAX);
            EntryEncoder {
                index,
                object_id: entry_object_id(&transfer_id, index),
                abs_path: entry.abs_path.clone(),
                size,
                repair_cursors: Vec::new(),
            }
        })
        .collect();

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
        let round_wall = round_started.elapsed();
        let sent_this_round = symbols_sent.saturating_sub(round_symbols_start);
        rqtrace!("sender: got reply {:?}", reply.frame_type());
        match reply.frame_type() {
            FrameType::Proof => {
                adaptive.observe_probe_success(&config, sent_this_round, round_wall, control_wait);
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
                    files: u32::try_from(entries.len()).unwrap_or(u32::MAX),
                    symbols_sent,
                    feedback_rounds,
                    merkle_root_hex,
                    receipt,
                    peer,
                });
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
                    round_wall,
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
                if source_symbols.is_empty() {
                    round_started = Instant::now();
                    round_symbols_start = symbols_sent;
                    // Fresh repair symbols (true encoder ESIs, via the
                    // cumulative cursor in each EntryEncoder) for the
                    // still-pending entries.
                    spray_round(
                        cx,
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
                } else {
                    round_started = Instant::now();
                    round_symbols_start = symbols_sent;
                    spray_source_requests(
                        cx,
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
                }
            }
            other => {
                return Err(RqError::Unexpected {
                    got: other,
                    expected: "Proof | NeedMore",
                });
            }
        }
    }
}

/// Per-round repair batch size: how many *additional* repair symbols (per block)
/// each feedback round mints. A generous batch keeps convergence fast under loss.
fn repair_batch_per_block(config: &RqConfig) -> usize {
    let block_k = config
        .max_block_size
        .div_ceil(usize::from(config.symbol_size.max(1)))
        .max(1);
    (block_k / 4).max(16)
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
    fallback_batch: usize,
    repair_overhead: f64,
) -> usize {
    let calibrated_total = initial_repair_target_per_block(block_source_n, repair_overhead);
    if calibrated_total > already {
        calibrated_total
    } else {
        already + fallback_batch.max(1)
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
async fn spray_round(
    cx: &Cx,
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
) -> Result<(), RqError> {
    let batch = repair_batch_per_block(config);
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
                    let block_bytes =
                        read_source_range(&enc.abs_path, block.start, block.len).await?;
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
                    repair_target_for_feedback_round(
                        block.k,
                        already,
                        batch,
                        round_tuning.repair_overhead,
                    )
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
                let block_bytes = read_source_range(&enc.abs_path, block.start, block.len).await?;

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
                enc.repair_cursors[block_index] = target_repair;
            }
        }
    }
    Ok(())
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
async fn spray_source_requests(
    cx: &Cx,
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
) -> Result<(), RqError> {
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
    rqtrace!(
        "sender: retransmitted {} requested source symbols",
        requests.len()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_symbol_datagrams(
    cx: &Cx,
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
) -> Result<(), RqError> {
    let mut send_batch = RqPendingSendBatch::new(sockets.len());
    for sym in symbols {
        queue_symbol_datagram(
            cx,
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
    send_batch.flush(sockets, symbols_sent).await
}

#[allow(clippy::too_many_arguments)]
async fn queue_symbol_datagram(
    cx: &Cx,
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
) -> Result<(), RqError> {
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
        let bytes = read_source_range(&enc.abs_path, start, end - start).await?;
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
    let manifest: TransferManifest = parse_json(&manifest_frame)?;
    validate_manifest(&manifest, &config)?;
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
                max_buffered_symbols: 0,
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
                file: None,
                bytes_written: 0,
                max_block_size: receiver_max_block_size,
                source_streaming: entry_source_streaming,
                source_blocks: source_blocks.unwrap_or_default(),
            }
        })
        .collect();

    let tag = transfer_tag(&manifest.transfer_id);
    let mut symbols_accepted: u64 = 0;
    let mut feedback_rounds: u32 = 0;
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
                )
                .await?;
                if drained > 0 {
                    rqtrace!("receiver: tail-drained {drained} datagrams after ObjectComplete");
                }

                let pending: Vec<u32> = decoders
                    .iter()
                    .filter(|d| !d.complete)
                    .map(|d| d.index)
                    .collect();
                rqtrace!(
                    "receiver: ObjectComplete; {} of {} entries still pending",
                    pending.len(),
                    decoders.len()
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

                control
                    .send(&json_frame(
                        FrameType::ObjectRequest,
                        &NeedMore {
                            pending,
                            source_symbols,
                        },
                    )?)
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
                    expected: "ObjectComplete",
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

async fn feed_symbol(
    dec: &mut EntryDecoder,
    parsed: &ParsedDatagram,
    payload: &[u8],
    symbol_size: u16,
    symbol_auth: Option<&SecurityContext>,
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
    if dec.source_streaming && parsed.kind.is_repair() {
        seed_source_streaming_pipeline(dec, symbol_size, symbol_auth).await?;
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
        .feed_streaming_block(auth);
    match result {
        Ok(SymbolAcceptResult::Accepted { received, needed }) => {
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
            Ok(true)
        }
        Ok(SymbolAcceptResult::DecodingStarted { block_sbn }) => {
            rqtrace!(
                "receiver: entry {} started decode block {} via esi={} kind={:?}",
                dec.index,
                block_sbn,
                parsed.esi,
                parsed.kind
            );
            Ok(true)
        }
        Ok(SymbolAcceptResult::BlockComplete { block_sbn, data }) => {
            persist_decoded_block(dec, block_sbn, &data).await?;
            if dec
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
            Ok(true)
        }
        Ok(SymbolAcceptResult::Duplicate) => {
            rqtrace!(
                "receiver: entry {} duplicate sbn={} esi={} kind={:?}",
                dec.index,
                parsed.sbn,
                parsed.esi,
                parsed.kind
            );
            Ok(false)
        }
        Ok(SymbolAcceptResult::Rejected(reason)) => {
            rqtrace!(
                "receiver: entry {} rejected sbn={} esi={} kind={:?} reason={:?}",
                dec.index,
                parsed.sbn,
                parsed.esi,
                parsed.kind,
                reason
            );
            Ok(false)
        }
        Err(err) => {
            rqtrace!(
                "receiver: entry {} feed error sbn={} esi={} kind={:?}: {err}",
                dec.index,
                parsed.sbn,
                parsed.esi,
                parsed.kind
            );
            Ok(false)
        }
    }
}

async fn seed_source_streaming_pipeline(
    dec: &mut EntryDecoder,
    symbol_size: u16,
    symbol_auth: Option<&SecurityContext>,
) -> Result<(), RqError> {
    if dec.pipeline.is_none() {
        return Ok(());
    }
    let symbol_size = usize::from(symbol_size);
    let Some(mut reader) = crate::fs::File::open(&dec.staging_path).await.ok() else {
        return Ok(());
    };

    for sbn in 0..dec.source_blocks.len() {
        if dec.source_blocks[sbn].complete {
            continue;
        }

        let k = dec.source_blocks[sbn].k;
        for esi in 0..k {
            if !dec.source_blocks[sbn].received[esi] || dec.source_blocks[sbn].pipeline_seeded[esi]
            {
                continue;
            }

            let Some(within_block) = esi.checked_mul(symbol_size) else {
                return Err(RqError::Coding(format!(
                    "entry {} source seed offset overflow",
                    dec.index
                )));
            };
            if within_block >= dec.source_blocks[sbn].len {
                continue;
            }

            let take = symbol_size.min(dec.source_blocks[sbn].len - within_block);
            let offset = dec.source_blocks[sbn]
                .start
                .checked_add(u64::try_from(within_block).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    RqError::Coding(format!("entry {} source seed offset overflow", dec.index))
                })?;
            let mut payload = vec![0u8; symbol_size];
            reader.seek(std::io::SeekFrom::Start(offset)).await?;
            reader.read_exact(&mut payload[..take]).await?;

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
                let tag = dec.source_blocks[sbn].auth_tags[esi].ok_or_else(|| {
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
                .feed_streaming_block(auth_symbol);
            dec.source_blocks[sbn].pipeline_seeded[esi] = true;
            match result {
                Ok(SymbolAcceptResult::BlockComplete { block_sbn, data }) => {
                    persist_decoded_block(dec, block_sbn, &data).await?;
                    if dec
                        .pipeline
                        .as_ref()
                        .is_some_and(DecodingPipeline::is_complete)
                    {
                        dec.complete = true;
                        dec.pipeline = None;
                        return Ok(());
                    }
                }
                Ok(_) => {}
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

    ensure_entry_staging_file(dec).await?;
    let Some(file) = dec.file.as_mut() else {
        return Err(RqError::Frame(format!(
            "internal: no staging file for entry {}",
            dec.index
        )));
    };
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    file.write_all(&payload[..take]).await?;

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
    }
    Ok(true)
}

async fn ensure_entry_staging_file(dec: &mut EntryDecoder) -> Result<(), RqError> {
    if dec.file.is_some() {
        return Ok(());
    }
    if let Some(parent) = dec.staging_path.parent() {
        crate::fs::create_dir_all(parent).await?;
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
    dec.file = Some(file);
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

    ensure_entry_staging_file(dec).await?;
    let Some(file) = dec.file.as_mut() else {
        return Err(RqError::Frame(format!(
            "internal: no staging file for entry {}",
            dec.index
        )));
    };
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    file.write_all(data).await?;
    dec.bytes_written = dec
        .bytes_written
        .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
        .ok_or_else(|| RqError::Coding(format!("entry {} byte counter overflow", dec.index)))?;
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

/// Verify every entry (SHA-256 + rebuilt merkle root) and, on success, atomically
/// write them to `dest_dir`.
async fn verify_and_commit(
    manifest: &TransferManifest,
    decoders: &mut [EntryDecoder],
    dest_dir: &Path,
    symbols_accepted: u64,
    feedback_rounds: u32,
) -> Result<ReceiveReceipt, RqError> {
    for d in decoders.iter_mut() {
        if d.size == 0 && d.file.is_none() {
            ensure_entry_staging_file(d).await?;
        }
        if let Some(mut file) = d.file.take() {
            file.flush().await?;
        }
    }

    let mut sha_ok = true;
    let mut received: u64 = 0;
    let mut digests: Vec<EntryDigest> = Vec::with_capacity(manifest.entries.len());
    let mut staging_paths: Vec<PathBuf> = Vec::with_capacity(manifest.entries.len());
    let mut hash_buf = vec![0u8; RQ_STREAM_HASH_BUFFER_SIZE];
    for e in &manifest.entries {
        let Some(decoder) = decoders.iter().find(|d| d.index == e.index) else {
            sha_ok = false;
            continue;
        };
        if !decoder.complete || decoder.bytes_written != e.size {
            sha_ok = false;
        }
        let (size, content_id, content_sha256) =
            hash_file_streaming(&decoder.staging_path, &mut hash_buf)
                .await
                .map_err(|e| RqError::Source(e.into_message()))?;
        received = received.saturating_add(size);
        if size != e.size || hex_encode(&content_sha256) != e.sha256_hex {
            sha_ok = false;
        }
        digests.push(EntryDigest {
            rel_path: e.rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
        staging_paths.push(decoder.staging_path.clone());
    }

    let merkle_ok = flat_merkle_root_from_digests(&digests) == manifest.merkle_root_hex;

    let committed = sha_ok && merkle_ok;
    let mut committed_paths: Vec<String> = Vec::new();
    if committed {
        // `root_name` is attacker-controlled off the wire; collapse it to a
        // single safe component so a hostile (absolute / separator-bearing)
        // value cannot escape `dest_dir`.
        let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
        let commit_targets: Vec<(&ManifestEntry, &PathBuf, PathBuf)> = manifest
            .entries
            .iter()
            .zip(staging_paths.iter())
            .map(|(entry, staging_path)| {
                let out_path = if manifest.is_directory {
                    join_relative(&base, &entry.rel_path)?
                } else {
                    base.clone()
                };
                Ok((entry, staging_path, out_path))
            })
            .collect::<Result<_, RqError>>()?;

        for (_, _, out_path) in &commit_targets {
            reject_destination_symlink_prefix(&base, out_path).await?;
        }

        for (_, staging_path, out_path) in commit_targets {
            if let Some(parent) = out_path.parent() {
                crate::fs::create_dir_all(parent).await?;
            }
            crate::fs::rename(staging_path, &out_path).await?;
            committed_paths.push(out_path.display().to_string());
        }
    }

    Ok(ReceiveReceipt {
        committed,
        bytes_received: received,
        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
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

async fn feed_datagram_to_decoders(
    buf: &[u8],
    n: usize,
    tag: u64,
    auth_required: bool,
    symbol_auth: Option<&SecurityContext>,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
) -> Result<bool, RqError> {
    let Some((parsed, payload)) = parse_symbol_datagram_payload(buf, n, tag, auth_required) else {
        return Ok(false);
    };
    let Some(pos) = decoders.iter().position(|d| d.index == parsed.entry) else {
        return Ok(false);
    };
    feed_symbol(
        &mut decoders[pos],
        &parsed,
        payload,
        symbol_size,
        symbol_auth,
    )
    .await
}

async fn feed_datagram_batch_to_decoders(
    batch: &crate::net::UdpRecvBatch,
    tag: u64,
    auth_required: bool,
    symbol_auth: Option<&SecurityContext>,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
) -> Result<u64, RqError> {
    let mut accepted = 0u64;
    for packet in &batch.packets {
        if feed_datagram_to_decoders(
            &packet.payload,
            packet.payload.len(),
            tag,
            auth_required,
            symbol_auth,
            decoders,
            symbol_size,
        )
        .await?
        {
            accepted = accepted.saturating_add(1);
        }
    }
    Ok(accepted)
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

        match ready {
            Ready::Udp(batch) => {
                let mut received_len = batch.packets.len();
                let mut batches = 1usize;
                let accepted = feed_datagram_batch_to_decoders(
                    &batch,
                    tag,
                    auth_required,
                    symbol_auth,
                    decoders,
                    symbol_size,
                )
                .await?;
                pumped = pumped.saturating_add(accepted);
                *symbols_accepted = (*symbols_accepted).saturating_add(accepted);

                while received_len == RQ_INBOUND_PUMP_BATCH {
                    if batches >= RQ_INBOUND_PUMP_MAX_DRAIN_BATCHES {
                        rqtrace!(
                            "pump: udp batch drain budget exhausted after {batches} batches and {pumped} accepted datagrams"
                        );
                        break;
                    }

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
                    received_len = tail.packets.len();
                    if received_len == 0 {
                        break;
                    }
                    let accepted = feed_datagram_batch_to_decoders(
                        &tail,
                        tag,
                        auth_required,
                        symbol_auth,
                        decoders,
                        symbol_size,
                    )
                    .await?;
                    pumped = pumped.saturating_add(accepted);
                    *symbols_accepted = (*symbols_accepted).saturating_add(accepted);
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

        let Some(n) = ready else {
            return Ok(drained);
        };

        if feed_datagram_to_decoders(
            rbuf,
            n,
            tag,
            auth_required,
            symbol_auth,
            decoders,
            symbol_size,
        )
        .await?
        {
            drained += 1;
            *symbols_accepted = (*symbols_accepted).saturating_add(1);
            quiet_sleep.reset_after(cx.now_for_observability(), quiet_window);
        }

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
    fn rq_pacing_converts_byte_rate_to_token_bucket_datagrams() {
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
            pacing.max_rate_per_sec,
            u32::try_from(RQ_COLD_START_PACING_BPS.div_ceil(symbol_bytes)).unwrap()
        );
        assert_eq!(
            pacing.max_burst_size,
            u32::try_from(RQ_COLD_START_BURST_SYMBOLS).unwrap()
        );
        assert_eq!(pacing.min_send_interval, Duration::ZERO);
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

        state.apply_loss_recommendations(&[
            LossRecommendation::ReduceCongestionWindow { factor: 0.5 },
            LossRecommendation::EnableFec { rate: 0.10 },
            LossRecommendation::SwitchCongestionControl {
                algorithm: "bbr".to_string(),
            },
        ]);

        assert_eq!(state.loss_pacing_cap_bps, Some(5_000_000));
        assert!(state.loss_fec_floor >= 0.10);
        assert!(state.regime_shift);
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
        }
    }

    #[test]
    fn validate_manifest_accepts_sane_bounds() {
        let manifest = manifest_with(vec![manifest_entry(0, 100), manifest_entry(1, 200)], 300);
        assert!(validate_manifest(&manifest, &RqConfig::default()).is_ok());
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
            }],
        };
        let mut decoders = vec![EntryDecoder {
            index: 0,
            object_id: entry_object_id(&manifest.transfer_id, 0),
            size,
            pipeline: None,
            complete: true,
            staging_path,
            file: None,
            bytes_written: size,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            source_streaming: false,
            source_blocks: Vec::new(),
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
            file: None,
            bytes_written: 0,
            max_block_size: usize::try_from(size).expect("test size fits usize"),
            source_streaming: true,
            source_blocks: source_block_progress_for(
                size,
                usize::try_from(size).expect("test size fits usize"),
                symbol_size,
            )
            .expect("test source blocks"),
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
        assert!(decoder.file.is_some());

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

        drop(decoder.file.take());
        assert_eq!(
            std::fs::read(staging_path).expect("read staged source stream"),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
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
        assert!(decoder.file.is_none());
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
        drop(decoder.file.take());
        assert_eq!(
            std::fs::read(staging_path).expect("read repaired source stream"),
            data
        );
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
    fn proactive_initial_repair_target_ceilings_extra_fraction() {
        assert_eq!(initial_repair_target_per_block(512, 1.15), 77);
        assert_eq!(initial_repair_target_per_block(1, 1.01), 1);
    }

    #[test]
    fn effective_block_size_uses_streaming_target_for_normal_files() {
        let config = RqConfig::default();
        let symbol_size = usize::from(config.symbol_size);
        let expected_target = symbol_size
            .saturating_mul(TARGET_SOURCE_SYMBOLS_PER_BLOCK)
            .min(TARGET_STREAMING_BLOCK_BYTES)
            .min(config.max_block_size);
        let effective = effective_max_block_size_for_largest_entry(&config, 10 * 1024 * 1024)
            .expect("10MiB should fit");
        assert_eq!(effective, expected_target);
        assert_eq!(
            max_block_source_symbol_count(10 * 1024 * 1024, config.symbol_size, effective),
            expected_target.div_ceil(symbol_size)
        );
    }

    #[test]
    fn effective_block_size_grows_only_to_fit_sbn_limit() {
        let config = RqConfig::default();
        let one_gib: usize = 1024 * 1024 * 1024;
        let symbol_size = usize::from(config.symbol_size);
        let streaming_target = symbol_size
            .saturating_mul(TARGET_SOURCE_SYMBOLS_PER_BLOCK)
            .min(TARGET_STREAMING_BLOCK_BYTES);
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
    fn max_block_source_symbols_uses_effective_block_not_entry_size() {
        assert_eq!(
            max_block_source_symbol_count(10 * 1024 * 1024, 1024, 512 * 1024),
            512
        );
        assert_eq!(
            max_block_source_symbol_count(10 * 1024 * 1024, 1024, 8 * 1024 * 1024),
            8192
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
}
