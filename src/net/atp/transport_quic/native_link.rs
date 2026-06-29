//! Real native-QUIC connect/accept + 1-RTT UDP data-plane pump for ATP-over-QUIC.
//!
//! This module is the wiring that turns [`super::send_path`] / the native receive
//! entry from a fail-closed scaffold into an actual transfer over a real UDP
//! socket. It composes three already-landed, separately-proven pieces — none of
//! which previously talked to each other in production — entirely over their
//! public APIs, so no peer-owned Phase-A file
//! (`connection.rs`/`connection_manager.rs`/`managed_endpoint.rs`) is modified:
//!
//! 1. [`QuicHandshakeDriver`] runs the genuine `rustls::quic` TLS-1.3 handshake
//!    over a [`QuicUdpEndpoint`] (real WebPKI server-identity verification, no
//!    insecure skip-verify), yielding a [`RustlsQuicCryptoProvider`] holding the
//!    derived 1-RTT keys.
//! 2. [`AtpPacketProtection::from_provider`] adopts those handshake-derived keys
//!    for the data plane (AEAD protect/unprotect + anti-replay), with no key
//!    re-derivation.
//! 3. [`NativeQuicConnection`] is driven to `Established` and produces/consumes
//!    application STREAM (control) + DATAGRAM (RaptorQ symbol) frames via
//!    `generate_frames` / `process_packet_payload`. A [`QuicLink`] pump protects
//!    each generated 1-RTT packet, sends it over UDP, and unprotects received
//!    packets back into the connection.
//!
//! The reliable ATP control protocol (Hello / manifest / NeedMore / Proof /
//! Close) and the fountain feedback loop are the existing `super::` native
//! helpers; this module only adds the async UDP pump that drives them, because
//! the in-memory loopback driver ([`super`]'s tests) moves frames synchronously
//! between two in-process connections, which cannot do real async socket I/O.
//!
//! # 1-RTT wire framing (no-claim boundary)
//!
//! The handshake itself uses canonical protected long-header Initial/Handshake
//! packets (the driver's responsibility). The 1-RTT data plane here uses a
//! deliberately simplified short packet: a 9-byte clear header
//! (`0x40 | key_phase`, then the full 8-byte packet number, big-endian) used as
//! AEAD associated data, followed by `ciphertext || tag`. This mirrors the
//! handshake driver's explicit "both ends are asupersync, no QUIC header
//! protection" simplification. It is therefore **not** wire-interoperable with a
//! generic QUIC stack (no header protection, no truncated packet numbers, no
//! connection-ID demux on the short header) and is scoped to ATP-over-QUIC where
//! both peers run this code. A wire-conformant short header + header protection
//! + multi-connection demux is separate Phase-A/Phase-D work.
//!
//! # Loss posture (no-claim boundary)
//!
//! RaptorQ + the fountain feedback loop tolerate symbol-DATAGRAM loss
//! end-to-end. The reliable control STREAM has bounded, ATP-specific
//! retransmission for NeedMore and terminal Proof frames; full generic QUIC loss
//! recovery remains out of scope for this pump. Deterministic symbol loss for
//! tests is injected before a symbol is sprayed ([`QuicConfig::debug_drop_one_in`]).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};
use sha2::{Digest, Sha256};

use crate::bytes::{Bytes, BytesMut};
use crate::cx::Cx;
use crate::io::{AsyncReadExt, AsyncWriteExt};
use crate::net::atp::datagram::beacons::{BeaconMeasurement, BeaconScheduler};
use crate::net::atp::datagram::congestion::{
    CongestionConfig, CongestionController, DatagramRateConfig, DatagramRateController,
    DatagramRateDecision, DatagramRateSample,
};
use crate::net::atp::protocol::frames::{Frame, FrameType};
use crate::net::atp::protocol::quic_frames::QuicFrame;
use crate::net::atp::quic::packet_protection::{
    AtpPacketProtection, AtpPacketProtectionConfig, PacketUnprotectionRequest,
};
use crate::net::atp::transport_common::{
    EntryDigest, flat_merkle_root_from_digests, hash_file_streaming, hex_encode,
};
use crate::net::quic_core::ConnectionId;
use crate::net::quic_native::handshake_driver::{
    ATP_QUIC_ALPN, HandshakeLevel, QuicHandshakeDriver, client_handshake_over_udp,
};
use crate::net::quic_native::tls::{
    PacketProtectionRequest, PacketProtectionSpace, ProtectedPacket, ProtectionProof,
    RustlsQuicCryptoProvider, TranscriptHash,
};
use crate::net::quic_native::{
    AckRange as NativeAckRange, NativeQuicConnection, NativeQuicConnectionConfig,
    NativeQuicConnectionError, OutgoingPacket, PacketNumberSpace, QuicTransportMachine,
    QuicUdpEndpoint, QuicUdpEndpointConfig, ReceivedPacket, StreamId, StreamRole, StreamTableError,
};
use crate::net::{UDP_MAX_GSO_SEGMENTS, UdpSendBatchStrategy};
use crate::security::tag::TAG_SIZE;
use crate::security::{AuthenticatedSymbol, SecurityContext};
use crate::types::outcome::Outcome;
use crate::types::symbol::{Symbol, SymbolId, SymbolKind};

use super::{
    NativeQuicFrameTransport, QuicBlockRepairRequest, QuicConfig, QuicControlReply,
    QuicEntryEncoder, QuicHello, QuicHelloAck, QuicNeedMore, QuicPreparedSource,
    QuicSourceSymbolRequest, QuicSprayPacingDecision, QuicTransportError, ReceiveReceipt,
    ReceiveReport, SendReport, TransferManifest,
};

/// Shared QUIC Initial Destination Connection ID for ATP-over-QUIC.
///
/// RFC 9001 §5.2 derives the (non-secret) Initial-space keys from the client's
/// original DCID; both peers must agree on it to derive matching Initial keys.
/// Initial keys protect only integrity against off-path tampering — the real
/// transfer confidentiality/authenticity comes from the ECDHE-derived
/// Handshake/1-RTT keys — so a fixed protocol constant here weakens nothing.
/// Using a constant (rather than peeking the first packet's header) means the
/// current accept path is single-connection-per-port; per-connection DCID demux
/// over a shared port is Phase-D work.
const ATP_QUIC_INITIAL_DCID: &[u8] = &[0xA7, 0x9C, 0x10, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6];
/// Client source connection ID carried in the client's handshake long headers.
const ATP_QUIC_CLIENT_SCID: &[u8] = &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
/// Server source connection ID carried in the server's handshake long headers.
const ATP_QUIC_SERVER_SCID: &[u8] = &[0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];
/// Process-unique counter for QUIC receive staging directories.
static QUIC_STAGING_SEQ: AtomicU64 = AtomicU64::new(0);
/// Keep one staged output descriptor hot only for large entries where repeated
/// block-level open/seek/write/flush dominates receiver intake.
const QUIC_STAGING_FILE_CACHE_MIN_BYTES: u64 = 1024 * 1024;
/// Bound cached descriptors so tree transfers with many files do not retain one
/// file handle per entry.
const QUIC_STAGING_FILE_CACHE_MAX_ENTRIES: usize = 128;
/// Flush cached staged writes in bounded chunks. This matches the RQ staging
/// cache envelope and keeps dirty data bounded while avoiding per-block flushes.
const QUIC_STAGE_BUFFER_BYTES: usize = 256 * 1024;

fn send_native_keep_alive(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    _control: &mut NativeQuicFrameTransport,
) -> Result<(), QuicTransportError> {
    conn.queue_ping(cx)?;
    Ok(())
}

async fn send_and_flush_native_keep_alive(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
) -> Result<(), QuicTransportError> {
    send_native_keep_alive(cx, &mut link.conn, control)?;
    link.flush(cx).await?;
    Ok(())
}

/// RAII backstop for the native QUIC receiver staging directory.
///
/// Cooperative success and error paths remove the directory asynchronously and
/// disarm this guard. If the receive future is hard-dropped before it reaches
/// those paths, this bounded synchronous cleanup prevents partial decoded blocks
/// from leaking under the destination.
struct QuicStagingDirGuard {
    dir: PathBuf,
    armed: bool,
}

impl QuicStagingDirGuard {
    fn new(dir: PathBuf) -> Self {
        Self { dir, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for QuicStagingDirGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// Bytes of the simplified 1-RTT data-plane header (flags + 8-byte packet number).
const ONE_RTT_HEADER_LEN: usize = 9;
/// QUIC AES-128-GCM authentication tag length.
const ONE_RTT_TAG_LEN: usize = 16;
/// QUIC short-header fixed bit (bit 6); set on every 1-RTT data-plane packet.
const ONE_RTT_FIXED_BIT: u8 = 0x40;
/// QUIC short-header key-phase bit (bit 2).
const ONE_RTT_KEY_PHASE_BIT: u8 = 0x04;
/// Packet-credit-sized recovery telemetry charge for one simplified ATP 1-RTT data packet.
///
/// ATP's RaptorQ repair loop, not QUIC stream retransmission, owns data
/// recovery. The native QUIC recovery machine is still useful as a packet-loss
/// signal, but its NewReno cwnd is not the data-plane admission authority:
/// erasures within the FEC budget must be handled by the fountain pacer instead
/// of a TCP-style 2x-MSS floor. Charge each symbol packet as a small virtual
/// credit so ACK/loss telemetry remains useful without throttling RaptorQ repair.
const QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES: u64 = 16;
/// Match the RQ raw-datagram pacer wait envelope: short enough for high-rate
/// clean paths, bounded enough that cancellation/liveness checkpoints keep
/// making progress under constrained lossy paths.
const QUIC_DATA_PLANE_PACER_MIN_PAUSE: Duration = Duration::from_micros(50);
const QUIC_DATA_PLANE_PACER_MAX_PAUSE: Duration = Duration::from_millis(250);

/// UDP max packet size for the link's endpoint.
///
/// The ATP-over-QUIC data plane intentionally uses large UDP datagrams on the
/// hermetic netns/veth benchmark links. Keep this as a jumbo endpoint envelope,
/// not a 1500-byte path-MTU estimate: lossy encrypted runs can coalesce an ACK or
/// small control frame with an otherwise near-full 1-RTT DATAGRAM packet, so a
/// self-imposed 16 KiB receiver cap rejected valid packets a few bytes over the
/// old bound before the fountain loop could recover.
const ATP_QUIC_UDP_MAX_PACKET: usize = 65_535;

/// Bytes added around each encoded 1-RTT payload before it is handed to UDP.
const ONE_RTT_PACKET_OVERHEAD: usize = ONE_RTT_HEADER_LEN + ONE_RTT_TAG_LEN;
/// Reserved bytes below the endpoint cap for ACK/control-frame coalescing slack.
const ONE_RTT_COALESCED_CONTROL_HEADROOM: usize = 64;
/// Loss-free encrypted sprays batch several full protected packets per UDP
/// send so Linux UDP_SEGMENT can amortize syscall cost above the packet-fill
/// layer. Lossy paths keep the pacing burst unchanged.
const QUIC_CLEAN_GSO_PACKETS_PER_FLUSH: usize = 4;
/// Keep the clean GSO spray batch below `NativeQuicConnection`'s bounded
/// outbound DATAGRAM queue (currently 256) so batching never drops queued
/// symbols before `flush()` drains them.
const QUIC_CLEAN_GSO_MAX_FLUSH_SYMBOLS: usize = 255;
/// Minimum clean-link spray burst in symbols (MATRIX-108 / bead 839ykg).
///
/// The RTT-derived `max_burst_symbols` collapses to ~2 on a low-latency
/// encrypted path (one symbol per protected packet ⇒ `packet_width≈1` ⇒ a
/// `packet_width × QUIC_CLEAN_GSO_PACKETS_PER_FLUSH` floor of only ~4), so the
/// send flushes tiny bursts and pays per-flush QUIC packet-protection cost on
/// every couple of symbols — capping the encrypted send at ~5 MB/s instead of
/// its ~24 MiB/s budget. Match the rq path's 16–32 symbol burst
/// (`RQ_ADAPTIVE_BURST_SYMBOLS`) on clean links so a flush amortizes that work;
/// the post-burst byte-paced sleep keeps the average rate at the budget.
const QUIC_CLEAN_SPRAY_BURST_FLOOR_SYMBOLS: usize = 32;

/// Loss ceiling below which a spray uses the clean coalescing/burst-floor path
/// (amortize per-flush QUIC packet-protection over a 32-symbol burst) instead of
/// the per-symbol lossy path. A strict `<= f64::EPSILON` gate left the encrypted
/// near-clean path — which measures a trace of startup/handshake loss — in the
/// per-symbol branch, so the QUIC_CLEAN_SPRAY_BURST_FLOOR_SYMBOLS floor (008e9c7e1)
/// never engaged and the send stayed at ~2 symbols/flush, ~5 MB/s (MATRIX-109).
/// `bad` (2%) and `broken` (10%) stay above this ceiling and keep per-symbol
/// pacing to preserve loss granularity on constrained links.
const QUIC_CLEAN_SPRAY_MAX_LOSS_RATE: f64 = 0.01;
/// Clean jumbo coalescing is for low-loss, low-RTT LAN-style paths. On the
/// 50M/bad encrypted cell the handshake RTT is ~80ms; treating that as clean
/// packed 54 symbols into one ~63 KiB UDP datagram, so one shaped-link packet
/// loss erased a whole symbol group and stalled recovery behind cwnd.
const QUIC_CLEAN_COALESCING_MAX_RTT_S: f64 = 0.050;
/// Keep native ATP-QUIC symbol packets loss-granular until the lossy convergence
/// gate is banked. The current recovery RTT is a synthetic pump clock sample,
/// not a trustworthy wall-clock path RTT, so an RTT-based clean gate can still
/// misclassify the 50M/bad cell as jumbo-safe.
const QUIC_NATIVE_CLEAN_JUMBO_COALESCING_ENABLED: bool = false;

/// Upper bound for symbols handed from the RQ producer loop to the QUIC sender
/// pump in one in-process turn on lossy paths. Clean paths may hand off the
/// whole bounded flush window so they do not split one GSO-ready burst into
/// multiple scheduler-visible producer/sender turns.
const QUIC_LOSSY_SPRAY_HANDOFF_MAX_SYMBOLS: usize = 64;

/// Fixed socket buffer budget for the native ATP-QUIC link. This is intentionally
/// a constant envelope, not proportional to object size, so large transfers cannot
/// force process/object-sized buffering while loopback proof runs avoid kernel
/// receive-buffer drops during one-round RaptorQ sprays.
const ATP_QUIC_UDP_SOCKET_BUFFER: usize = 16 * 1024 * 1024;

/// Packets pulled from the socket per inbound pump. Each received UDP packet is
/// copied through packet protection, frame decode, and the application DATAGRAM
/// queue before the symbol decoder can consume it, so the batch width is part of
/// the native link's memory envelope. Full batches trigger a bounded quiet-drain
/// loop below so large bursts are drained before the receiver waits on control.
const INBOUND_PUMP_BATCH: usize = 512;
/// Maximum full receive batches drained in one pump turn. This preserves the
/// F1.1 drain-until-empty behavior for ordinary bursts while bounding a single
/// turn under sustained peer flooding.
const INBOUND_PUMP_MAX_DRAIN_BATCHES: usize = 64;
/// Receiver symbol batches fed before giving the UDP socket another immediate
/// drain chance. Keeping this at one prevents a full userspace DATAGRAM queue
/// from monopolizing the receive task while the kernel socket buffer is filling.
const RECEIVER_SYMBOL_DRAIN_BATCHES_PER_SOCKET_POLL: usize = 1;
/// After the first full batch, wait only a tiny quiet window for the next batch.
/// `UdpSocket::recv_batch_from` drains immediately-ready datagrams internally;
/// this grace covers the full-batch case where the kernel may still have more
/// packets queued without charging a full idle timeout to every drain attempt.
const INBOUND_PUMP_DRAIN_GRACE: Duration = Duration::from_millis(1);
/// Headroom for 1-RTT short-header, AEAD tag, and STREAM frame varints when
/// sizing recovery-governed STREAM packets. `NativeQuicConnection` already
/// reserves 32 frame bytes internally, so this must stay below the small cwnd
/// tail observed at the 2400-byte floor.
const QUIC_STREAM_PACKET_OVERHEAD_BUDGET: u64 = 48;
/// Bytes of source STREAM payload queued before giving the socket pump a turn.
/// GOOD source-stream sends stay inside the native QUIC packet envelope: larger
/// packets amplified loss tails on shaped netns links, while this envelope keeps
/// the repair tail small and avoids IP fragmentation.
const QUIC_SOURCE_STREAM_FLUSH_BYTES: u64 = 512 * 1024;
const QUIC_SOURCE_STREAM_PACKET_BYTES: usize = 8 * 1024;
const QUIC_SOURCE_STREAM_REPAIR_LOSS_MULTIPLIER: f64 = 4.0;

fn source_stream_max_frame_bytes() -> usize {
    one_rtt_max_payload_for_udp_packet(QUIC_SOURCE_STREAM_PACKET_BYTES).max(1)
}

fn source_stream_pacing_interval(frame_bytes: usize, pacing_rate_bps: u64) -> Duration {
    let bytes = u128::try_from(frame_bytes.max(1)).unwrap_or(u128::MAX);
    let rate = u128::from(pacing_rate_bps.max(1));
    let nanos = bytes
        .saturating_mul(1_000_000_000)
        .saturating_add(rate.saturating_sub(1))
        / rate;
    Duration::from_nanos(u64::try_from(nanos.max(1)).unwrap_or(u64::MAX))
}

/// Control-plane PTO. When the receiver is awaiting repair after a NeedMore and the link goes idle,
/// the NeedMore (receiver->sender) or the repair round (sender->receiver) was likely lost on the wire
/// — ATP control rides best-effort 1-RTT here, so under real-internet loss a single dropped NeedMore
/// otherwise deadlocks both sides until the full idle timeout. Re-send the NeedMore on this interval
/// instead; this is what lets cross-machine transfers converge through control-frame loss.
const NEEDMORE_PTO: Duration = Duration::from_millis(1500);
/// Fast retry cadence for GOOD-regime source STREAM recovery. This is scoped
/// away from NeedMore/fountain control so lossy DATAGRAM convergence keeps its
/// conservative round-boundary behavior.
const SOURCE_STREAM_PTO: Duration = Duration::from_millis(200);
const QUIC_LOSS_TARGET_PROGRESS_STALL_RATIO: f64 = 0.50;
const QUIC_LOSS_TARGET_PROGRESS_LOSS_MARGIN: f64 = 0.01;
const QUIC_LOSS_TARGET_DELIVERY_BACKOFF_HEADROOM: f64 = 1.25;
const QUIC_STILL_VIABLE_FEEDBACK_GRACE_ROUNDS: u32 = 8;
/// Bounded terminal Proof retransmits. This uses STREAM-offset requeue, not a
/// duplicate higher-offset Proof, so it fills the receiver->sender stream gap
/// that otherwise leaves the sender waiting until its idle timeout.
const TERMINAL_PROOF_RETRANSMIT_ATTEMPTS: u32 = 4;
/// Quiet window that ends a receiver symbol round after at least one symbol was
/// accepted without seeing ObjectComplete. It intentionally matches the
/// control-plane PTO: encrypted/coalesced sprays can have short paced gaps, and
/// cutting a round sooner makes the receiver emit stale zero-`round_symbols_sent`
/// NeedMore frames before the sender has actually completed the spray.
const ROUND_PROGRESS_IDLE_GRACE: Duration = NEEDMORE_PTO;
/// Minimum NeedMore re-sends while awaiting one round's repair before giving up.
///
/// The live budget is derived from [`QuicConfig::idle_timeout`], so explicit
/// short-timeout tests still fail fast while the default encrypted lossy lane
/// gets a larger convergence window.
const MIN_NEEDMORE_PTO_ATTEMPTS: u32 = 1;

fn needmore_pto_attempt_budget(idle_timeout: Duration) -> u32 {
    let pto_millis = NEEDMORE_PTO.as_millis().max(1);
    let idle_millis = idle_timeout.as_millis().max(pto_millis);
    let attempts = idle_millis.div_ceil(pto_millis);
    u32::try_from(attempts)
        .unwrap_or(u32::MAX)
        .max(MIN_NEEDMORE_PTO_ATTEMPTS)
}

/// Opt-in stderr tracing for ATP/RQ benchmark diagnosis. Reuses the existing
/// ATP_RQ_TRACE switch so matrix runs can grep one trace stream across RQ and
/// QUIC transports.
macro_rules! quic_rqtrace {
    ($($arg:tt)*) => {
        if std::env::var_os("ATP_RQ_TRACE").is_some() {
            eprintln!("[ATP_RQ_TRACE] [atp-quic] {}", format!($($arg)*));
        }
    };
}

fn trace_quic_flush_coalescing(
    cx: &Cx,
    packets: usize,
    datagram_frames: usize,
    observed_max_datagram_frames_per_packet: usize,
    configured_max_symbol_frames_per_packet: usize,
    plaintext_payload_bytes: usize,
    protected_udp_bytes: usize,
    native_send_batch_used: bool,
    gso_send_used: bool,
    fallback_used: bool,
) {
    if packets == 0 || std::env::var_os("ATP_RQ_TRACE").is_none() {
        return;
    }
    let avg_datagram_frames_per_packet_x100 = datagram_frames.saturating_mul(100) / packets.max(1);
    let packets_s = packets.to_string();
    let datagram_frames_s = datagram_frames.to_string();
    let observed_max_datagram_frames_per_packet_s =
        observed_max_datagram_frames_per_packet.to_string();
    let configured_max_symbol_frames_per_packet_s =
        configured_max_symbol_frames_per_packet.to_string();
    let avg_datagram_frames_per_packet_x100_s = avg_datagram_frames_per_packet_x100.to_string();
    let plaintext_payload_bytes_s = plaintext_payload_bytes.to_string();
    let protected_udp_bytes_s = protected_udp_bytes.to_string();
    let native_send_batch_used_s = native_send_batch_used.to_string();
    let gso_send_used_s = gso_send_used.to_string();
    let fallback_used_s = fallback_used.to_string();
    cx.trace_with_fields(
        "atp_quic.sender.flush_coalescing",
        &[
            ("packets", packets_s.as_str()),
            ("datagram_frames", datagram_frames_s.as_str()),
            (
                "observed_max_datagram_frames_per_packet",
                observed_max_datagram_frames_per_packet_s.as_str(),
            ),
            (
                "configured_max_symbol_frames_per_packet",
                configured_max_symbol_frames_per_packet_s.as_str(),
            ),
            (
                "avg_datagram_frames_per_packet_x100",
                avg_datagram_frames_per_packet_x100_s.as_str(),
            ),
            (
                "plaintext_payload_bytes",
                plaintext_payload_bytes_s.as_str(),
            ),
            ("protected_udp_bytes", protected_udp_bytes_s.as_str()),
            ("native_send_batch_used", native_send_batch_used_s.as_str()),
            ("gso_send_used", gso_send_used_s.as_str()),
            ("fallback_used", fallback_used_s.as_str()),
        ],
    );
    quic_rqtrace!(
        "sender: flush_coalescing packets={} datagram_frames={} observed_max_datagrams_per_packet={} configured_max_symbol_frames_per_packet={} avg_datagrams_per_packet_x100={} plaintext_payload_bytes={} protected_udp_bytes={} native_send_batch_used={} gso_send_used={} fallback_used={}",
        packets,
        datagram_frames,
        observed_max_datagram_frames_per_packet,
        configured_max_symbol_frames_per_packet,
        avg_datagram_frames_per_packet_x100,
        plaintext_payload_bytes,
        protected_udp_bytes,
        native_send_batch_used,
        gso_send_used,
        fallback_used,
    );
}

fn trace_quic_symbol_handoff(
    cx: &Cx,
    symbols: usize,
    encoded_bytes: usize,
    queue_before: usize,
    queue_after: usize,
    flush_symbol_limit: usize,
    flushed_packets: usize,
    pacing_rate_bps: u64,
) {
    if symbols == 0 || std::env::var_os("ATP_RQ_TRACE").is_none() {
        return;
    }
    let symbols_s = symbols.to_string();
    let encoded_bytes_s = encoded_bytes.to_string();
    let queue_before_s = queue_before.to_string();
    let queue_after_s = queue_after.to_string();
    let flush_symbol_limit_s = flush_symbol_limit.to_string();
    let flushed_packets_s = flushed_packets.to_string();
    let pacing_rate_bps_s = pacing_rate_bps.to_string();
    cx.trace_with_fields(
        "atp_quic.sender.symbol_handoff",
        &[
            ("symbols", symbols_s.as_str()),
            ("encoded_bytes", encoded_bytes_s.as_str()),
            ("queue_before", queue_before_s.as_str()),
            ("queue_after", queue_after_s.as_str()),
            ("flush_symbol_limit", flush_symbol_limit_s.as_str()),
            ("flushed_packets", flushed_packets_s.as_str()),
            ("pacing_rate_bps", pacing_rate_bps_s.as_str()),
        ],
    );
    quic_rqtrace!(
        "sender: symbol_handoff symbols={} encoded_bytes={} queue_before={} queue_after={} flush_symbol_limit={} flushed_packets={} pacing_rate_bps={}",
        symbols,
        encoded_bytes,
        queue_before,
        queue_after,
        flush_symbol_limit,
        flushed_packets,
        pacing_rate_bps,
    );
}

fn need_more_repair_symbol_count(need: &QuicNeedMore) -> u64 {
    need.repair_blocks.iter().fold(0u64, |acc, request| {
        acc.saturating_add(u64::from(request.symbols))
    })
}

fn need_more_requested_symbol_count(need: &QuicNeedMore) -> u64 {
    need_more_repair_symbol_count(need)
        .saturating_add(u64::try_from(need.source_symbols.len()).unwrap_or(u64::MAX))
}

fn infer_missing_round_complete_symbols(
    expected_round: u32,
    observed_symbols: u64,
    last_need: Option<&QuicNeedMore>,
) -> u64 {
    last_need
        .filter(|need| need.feedback_round == expected_round)
        .map(need_more_requested_symbol_count)
        .unwrap_or(observed_symbols)
        .max(observed_symbols)
}

fn trace_inferred_round_complete_symbols(
    cx: &Cx,
    expected_round: u32,
    observed_symbols: u64,
    inferred_symbols: u64,
) {
    let expected_round_s = expected_round.to_string();
    let observed_symbols_s = observed_symbols.to_string();
    let inferred_symbols_s = inferred_symbols.to_string();
    cx.trace_with_fields(
        "atp_quic.receive.inferred_round_complete_symbols",
        &[
            ("round", expected_round_s.as_str()),
            ("round_symbols_observed", observed_symbols_s.as_str()),
            ("round_symbols_sent", inferred_symbols_s.as_str()),
        ],
    );
    quic_rqtrace!(
        "receiver: inferred ObjectComplete round={} round_symbols_observed={} round_symbols_sent={}",
        expected_round,
        observed_symbols,
        inferred_symbols,
    );
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn loss_compensated_repair_target(base_deficit_symbols: u64, loss_fraction: Option<f64>) -> u64 {
    if base_deficit_symbols == 0 {
        return 0;
    }
    let Some(loss) = loss_fraction.filter(|loss| loss.is_finite()) else {
        return base_deficit_symbols;
    };
    if loss <= 0.0 {
        return base_deficit_symbols;
    }
    let effective_loss = loss
        .max(super::QUIC_FEEDBACK_REPAIR_LOSS_ENABLE_MIN)
        .min(super::QUIC_FEEDBACK_REPAIR_MAX_OVERHEAD);
    let compensated_loss = (effective_loss
        * (1.0 + super::QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_FRACTION)
        + super::QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_MIN)
        .clamp(0.0, 0.90);
    let delivery_fraction = (1.0 - compensated_loss).max(0.10);
    ((base_deficit_symbols as f64) / delivery_fraction).ceil() as u64
}

fn need_more_base_deficit_symbols(need: &QuicNeedMore, requested_repair_symbols: u64) -> u64 {
    need.repair_base_deficit_symbols
        .unwrap_or(requested_repair_symbols)
}

fn need_more_loss_compensated_target_symbols(
    need: &QuicNeedMore,
    base_deficit_symbols: u64,
) -> u64 {
    need.repair_loss_compensated_target_symbols
        .unwrap_or_else(|| {
            loss_compensated_repair_target(base_deficit_symbols, need.round_loss_fraction)
        })
}

fn delivery_loss_compensated_repair_blocks(
    requests: &[QuicBlockRepairRequest],
    sender_delivery_loss: Option<f64>,
) -> Vec<QuicBlockRepairRequest> {
    let Some(loss) = sender_delivery_loss.filter(|loss| loss.is_finite() && *loss > 0.0) else {
        return requests.to_vec();
    };
    requests
        .iter()
        .map(|request| {
            let target = loss_compensated_repair_target(u64::from(request.symbols), Some(loss))
                .min(u64::from(u32::MAX));
            QuicBlockRepairRequest {
                symbols: u32::try_from(target).unwrap_or(u32::MAX),
                ..*request
            }
        })
        .collect()
}

fn repair_block_symbol_count(requests: &[QuicBlockRepairRequest]) -> u64 {
    requests.iter().fold(0u64, |acc, request| {
        acc.saturating_add(u64::from(request.symbols))
    })
}

fn next_feedback_round_or_no_convergence(
    feedback_rounds: u32,
    max_feedback_rounds: u32,
    pending_entries: usize,
) -> Result<u32, QuicTransportError> {
    let fail_closed_rounds = still_viable_feedback_fail_closed_rounds(max_feedback_rounds);
    if pending_entries > 0 && feedback_rounds >= fail_closed_rounds {
        return Err(QuicTransportError::NoConvergence {
            rounds: feedback_rounds,
            pending: pending_entries,
        });
    }
    Ok(feedback_rounds.saturating_add(1))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SentControlStreamFrame {
    stream: StreamId,
    offset: u64,
}

#[derive(Debug, Clone)]
struct ReceivedSourceStreamFrame {
    offset: u64,
    data: Bytes,
    fin: bool,
}

fn acked_packet_ranges_from_frames(
    frames: &[QuicFrame],
) -> Result<Vec<NativeAckRange>, NativeQuicConnectionError> {
    let mut ranges = Vec::new();
    for frame in frames {
        if let QuicFrame::Ack {
            largest_acknowledged,
            first_ack_range,
            ack_ranges,
            ..
        } = frame
        {
            ranges.extend(ack_frame_packet_ranges(
                largest_acknowledged.value(),
                first_ack_range.value(),
                ack_ranges,
            )?);
        }
    }
    Ok(ranges)
}

fn ack_frame_packet_ranges(
    largest_acknowledged: u64,
    first_ack_range: u64,
    ack_ranges: &[crate::net::atp::protocol::quic_frames::AckRange],
) -> Result<Vec<NativeAckRange>, NativeQuicConnectionError> {
    let first_smallest = largest_acknowledged.checked_sub(first_ack_range).ok_or(
        NativeQuicConnectionError::InvalidState("ACK first range exceeds largest packet number"),
    )?;
    let mut ranges = vec![
        NativeAckRange::new(largest_acknowledged, first_smallest).ok_or(
            NativeQuicConnectionError::InvalidState("invalid ACK first range"),
        )?,
    ];
    let mut previous_smallest = first_smallest;

    for range in ack_ranges {
        let next_largest = previous_smallest
            .checked_sub(range.gap.value().saturating_add(2))
            .ok_or(NativeQuicConnectionError::InvalidState(
                "ACK range gap underflowed packet number space",
            ))?;
        let next_smallest = next_largest
            .checked_sub(range.ack_range_length.value())
            .ok_or(NativeQuicConnectionError::InvalidState(
                "ACK range length exceeds largest packet number",
            ))?;
        ranges.push(
            NativeAckRange::new(next_largest, next_smallest)
                .ok_or(NativeQuicConnectionError::InvalidState("invalid ACK range"))?,
        );
        previous_smallest = next_smallest;
    }

    Ok(ranges)
}

fn packet_in_ack_ranges(packet_number: u64, ranges: &[NativeAckRange]) -> bool {
    ranges
        .iter()
        .any(|range| packet_number >= range.smallest && packet_number <= range.largest)
}

const QUIC_SOURCE_STREAM_FAST_RETRANSMIT_PACKET_THRESHOLD: u64 = 3;
const QUIC_SOURCE_STREAM_FAST_RETRANSMIT_MAX_PACKETS: usize = 4;
const QUIC_SOURCE_STREAM_COMPLETION_PTO_MAX_FRAMES: usize = 4;

fn packet_lost_by_ack_gap(packet_number: u64, acked_ranges: &[NativeAckRange]) -> bool {
    let Some(largest_acked) = acked_ranges.iter().map(|range| range.largest).max() else {
        return false;
    };
    packet_number.saturating_add(QUIC_SOURCE_STREAM_FAST_RETRANSMIT_PACKET_THRESHOLD)
        <= largest_acked
        && !packet_in_ack_ranges(packet_number, acked_ranges)
}

fn dedup_stream_frames_for_retransmit(
    mut frames: Vec<SentControlStreamFrame>,
) -> Vec<SentControlStreamFrame> {
    frames.sort_by_key(|frame| (frame.stream.0, frame.offset));
    frames.dedup();
    frames
}

fn tail_stream_frames_for_retransmit(
    frames: &[SentControlStreamFrame],
    max_frames: usize,
) -> Vec<SentControlStreamFrame> {
    if frames.is_empty() {
        return Vec::new();
    }
    let start = frames.len().saturating_sub(max_frames.max(1));
    dedup_stream_frames_for_retransmit(frames[start..].to_vec())
}

struct NativeQuicSpraySymbol {
    symbol: Symbol,
    entry: u32,
    auth_tag: Option<[u8; TAG_SIZE]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NeedMorePtoMode {
    RetransmitRecorded,
    SendFresh,
}

fn need_more_pto_mode(need_frames: &[SentControlStreamFrame]) -> NeedMorePtoMode {
    if need_frames.is_empty() {
        NeedMorePtoMode::SendFresh
    } else {
        NeedMorePtoMode::RetransmitRecorded
    }
}

fn feedback_round_for_need_or_no_convergence(
    feedback_rounds: u32,
    max_feedback_rounds: u32,
    requested_feedback_round: u32,
    pending_entries: usize,
) -> Result<(u32, u32), QuicTransportError> {
    let next_feedback_round = feedback_rounds.saturating_add(1);
    let response_feedback_round = if requested_feedback_round == 0 {
        next_feedback_round
    } else {
        requested_feedback_round
    };
    let fail_closed_rounds = still_viable_feedback_fail_closed_rounds(max_feedback_rounds);
    if pending_entries > 0 && response_feedback_round > fail_closed_rounds {
        return Err(QuicTransportError::NoConvergence {
            rounds: feedback_rounds,
            pending: pending_entries,
        });
    }
    Ok((
        feedback_rounds.max(response_feedback_round),
        response_feedback_round,
    ))
}

fn still_viable_feedback_fail_closed_rounds(max_feedback_rounds: u32) -> u32 {
    max_feedback_rounds.saturating_add(QUIC_STILL_VIABLE_FEEDBACK_GRACE_ROUNDS)
}

fn send_native_object_complete_for_round(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    round: u32,
    round_symbols_sent: u64,
) -> Result<(), QuicTransportError> {
    control.send_json(
        cx,
        conn,
        FrameType::ObjectComplete,
        &super::QuicRoundComplete {
            round,
            round_symbols_sent,
        },
    )
}

fn trace_stale_round_complete(cx: &Cx, expected_round: u32, got: &super::QuicRoundComplete) {
    let expected_round_s = expected_round.to_string();
    let got_round_s = got.round.to_string();
    let got_symbols_s = got.round_symbols_sent.to_string();
    cx.trace_with_fields(
        "atp_quic.receive.stale_round_complete",
        &[
            ("expected_round", expected_round_s.as_str()),
            ("got_round", got_round_s.as_str()),
            ("round_symbols_sent", got_symbols_s.as_str()),
        ],
    );
    quic_rqtrace!(
        "receiver: stale ObjectComplete expected_round={} got_round={} round_symbols_sent={}",
        expected_round,
        got.round,
        got.round_symbols_sent,
    );
}

fn trace_native_repair_accounting(
    cx: &Cx,
    direction: &'static str,
    feedback_round: u32,
    base_deficit_symbols: u64,
    requested_repair_symbols: u64,
    loss_compensated_target_symbols: u64,
    emitted_repair_symbols: Option<u64>,
    need: &QuicNeedMore,
) {
    let feedback_round_s = feedback_round.to_string();
    let base_deficit_symbols_s = base_deficit_symbols.to_string();
    let requested_repair_symbols_s = requested_repair_symbols.to_string();
    let loss_compensated_target_symbols_s = loss_compensated_target_symbols.to_string();
    let emitted_repair_symbols_s = emitted_repair_symbols
        .map(|value| value.to_string())
        .unwrap_or_else(|| "pending".to_string());
    let gap_to_target_symbols = emitted_repair_symbols
        .map(|emitted| loss_compensated_target_symbols.saturating_sub(emitted))
        .unwrap_or_else(|| loss_compensated_target_symbols.saturating_sub(requested_repair_symbols))
        .to_string();
    let round_loss_fraction_s = format!("{:.6}", need.round_loss_fraction.unwrap_or(0.0));
    let repair_blocks_s = need.repair_blocks.len().to_string();
    let source_requests_s = need.source_symbols.len().to_string();
    cx.trace_with_fields(
        "atp_quic.repair_accounting",
        &[
            ("transport", "quic"),
            ("direction", direction),
            ("feedback_round", feedback_round_s.as_str()),
            ("base_deficit_symbols", base_deficit_symbols_s.as_str()),
            (
                "requested_repair_symbols",
                requested_repair_symbols_s.as_str(),
            ),
            (
                "loss_compensated_target_symbols",
                loss_compensated_target_symbols_s.as_str(),
            ),
            ("emitted_repair_symbols", emitted_repair_symbols_s.as_str()),
            ("gap_to_target_symbols", gap_to_target_symbols.as_str()),
            ("round_loss_fraction", round_loss_fraction_s.as_str()),
            ("repair_blocks", repair_blocks_s.as_str()),
            ("source_requests", source_requests_s.as_str()),
        ],
    );
}

async fn send_native_proof_until_close(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
    receipt: &ReceiveReceipt,
    config: &QuicConfig,
) -> Result<(), QuicTransportError> {
    super::send_native_proof(cx, &mut link.conn, control, receipt)?;
    link.flush(cx).await?;
    let proof_frames = link.last_flushed_stream_frames();

    let max_attempts =
        TERMINAL_PROOF_RETRANSMIT_ATTEMPTS.min(needmore_pto_attempt_budget(config.idle_timeout));
    let mut attempts = 0u32;
    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        if let Some(frame) = control.try_recv(cx, &mut link.conn)? {
            match frame.frame_type() {
                FrameType::Close => return Ok(()),
                FrameType::KeepAlive | FrameType::ObjectComplete => continue,
                FrameType::ObjectRequest => {
                    link.retransmit_stream_frames(cx, &proof_frames, "terminal_proof_request")
                        .await?;
                    continue;
                }
                got => {
                    return Err(QuicTransportError::Unexpected {
                        got,
                        expected: "Close | KeepAlive | ObjectComplete | ObjectRequest",
                    });
                }
            }
        }

        link.flush(cx).await?;
        if link.pump_inbound_for(cx, NEEDMORE_PTO).await? > 0 {
            continue;
        }
        if attempts >= max_attempts {
            return Ok(());
        }
        attempts = attempts.saturating_add(1);
        quic_rqtrace!(
            "receiver: Proof PTO retransmit attempt={} max_attempts={} stream_frames={} committed={} feedback_rounds={} symbols_accepted={}",
            attempts,
            max_attempts,
            proof_frames.len(),
            receipt.committed,
            receipt.feedback_rounds,
            receipt.symbols_accepted,
        );
        link.retransmit_stream_frames(cx, &proof_frames, "terminal_proof_pto")
            .await?;
    }
}

fn same_need_more_request_shape(left: &QuicNeedMore, right: &QuicNeedMore) -> bool {
    left.feedback_round == right.feedback_round
        && left.pending == right.pending
        && left.repair_blocks == right.repair_blocks
        && left.source_symbols == right.source_symbols
}

fn drop_duplicate_need_more_frames(
    pending: &mut VecDeque<Frame>,
    served_need: &QuicNeedMore,
) -> Result<usize, QuicTransportError> {
    let mut retained = VecDeque::with_capacity(pending.len());
    let mut dropped = 0usize;
    while let Some(frame) = pending.pop_front() {
        if frame.frame_type() == FrameType::ObjectRequest {
            let queued = super::parse_json::<QuicNeedMore>(&frame)?;
            if same_need_more_request_shape(&queued, served_need) {
                dropped = dropped.saturating_add(1);
                continue;
            }
        }
        retained.push_back(frame);
    }
    *pending = retained;
    Ok(dropped)
}

fn repair_block_trace_summary(requests: &[QuicBlockRepairRequest]) -> String {
    const MAX_DETAIL_BLOCKS: usize = 16;
    let mut max_symbols = 0u32;
    let mut parts = Vec::new();
    for request in requests.iter().take(MAX_DETAIL_BLOCKS) {
        max_symbols = max_symbols.max(request.symbols);
        parts.push(format!(
            "{}:{}:{}",
            request.entry, request.sbn, request.symbols
        ));
    }
    for request in requests.iter().skip(MAX_DETAIL_BLOCKS) {
        max_symbols = max_symbols.max(request.symbols);
    }
    if requests.len() > MAX_DETAIL_BLOCKS {
        parts.push(format!("+{}more", requests.len() - MAX_DETAIL_BLOCKS));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        format!("max={} [{}]", max_symbols, parts.join(","))
    }
}

fn trace_repair_block_deficits(direction: &str, round: u32, requests: &[QuicBlockRepairRequest]) {
    if std::env::var_os("ATP_RQ_TRACE").is_none() {
        return;
    }
    for request in requests {
        eprintln!(
            "[ATP_RQ_TRACE] [atp-quic] {direction}: NeedMoreBlock round={round} entry={} sbn={} requested_symbols={}",
            request.entry, request.sbn, request.symbols
        );
    }
}

/// Monotonic data-plane clock step (microseconds) fed to the connection per pump
/// operation. The transfer's correctness does not depend on real time; this only
/// keeps the connection's loss/ACK bookkeeping monotonic.
const CLOCK_STEP_MICROS: u64 = 1_000;

/// Client-side TLS material for a native QUIC connection.
///
/// Built by the caller via [`crate::net::quic_native::handshake_driver::client_config`]
/// (or any TLS-1.3 `rustls::ClientConfig` advertising the ATP-over-QUIC ALPN) and
/// the server name to verify. There is no insecure skip-verify path: the
/// configured roots gate the handshake.
#[derive(Clone)]
pub struct QuicClientTls {
    /// Server name verified against the presented certificate (WebPKI).
    pub server_name: ServerName<'static>,
    /// TLS-1.3 client configuration (root trust + ALPN).
    pub config: Arc<ClientConfig>,
}

impl std::fmt::Debug for QuicClientTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicClientTls")
            .field("server_name", &self.server_name)
            .field("config", &"<rustls::ClientConfig>")
            .finish()
    }
}

/// Server-side TLS material for a native QUIC connection.
///
/// Built by the caller via [`crate::net::quic_native::handshake_driver::server_config`]
/// (or any TLS-1.3 `rustls::ServerConfig` presenting a certificate chain and key
/// and advertising the ATP-over-QUIC ALPN).
#[derive(Clone)]
pub struct QuicServerTls {
    /// TLS-1.3 server configuration (certificate chain + private key + ALPN).
    pub config: Arc<ServerConfig>,
}

impl std::fmt::Debug for QuicServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicServerTls")
            .field("config", &"<rustls::ServerConfig>")
            .finish()
    }
}

/// Convert an [`AtpPacketProtection`] outcome into a transport result.
fn protection_result<T>(
    outcome: Outcome<T, crate::net::atp::protocol::outcome::AtpError>,
) -> Result<T, QuicTransportError> {
    match outcome {
        Outcome::Ok(value) => Ok(value),
        Outcome::Err(err) => Err(QuicTransportError::Quic(format!(
            "packet protection: {err:?}"
        ))),
        Outcome::Cancelled(_) => Err(QuicTransportError::Cancelled),
        Outcome::Panicked(_) => Err(QuicTransportError::Quic(
            "packet protection panicked".to_string(),
        )),
    }
}

fn map_udp_error(err: crate::net::quic_native::QuicUdpEndpointError) -> QuicTransportError {
    match err {
        crate::net::quic_native::QuicUdpEndpointError::Cancelled => QuicTransportError::Cancelled,
        other => QuicTransportError::Quic(format!("udp endpoint: {other}")),
    }
}

fn map_tls_error(err: crate::net::quic_native::QuicTlsError) -> QuicTransportError {
    QuicTransportError::Quic(format!("quic handshake: {err}"))
}

/// Encode the simplified 1-RTT data-plane header for `packet_number`.
fn encode_one_rtt_header(packet_number: u64) -> [u8; ONE_RTT_HEADER_LEN] {
    let mut header = [0u8; ONE_RTT_HEADER_LEN];
    header[0] = ONE_RTT_FIXED_BIT; // key_phase 0
    header[1..].copy_from_slice(&packet_number.to_be_bytes());
    header
}

/// Decode a received 1-RTT data-plane packet into `(key_phase, packet_number,
/// header_bytes, ciphertext, tag)`. Returns `None` for any packet that is not a
/// well-formed short-header 1-RTT packet (e.g. a late handshake long-header
/// retransmit), which the caller silently drops, matching QUIC semantics.
fn decode_one_rtt_packet(
    packet: &[u8],
) -> Option<(bool, u64, &[u8], &[u8], [u8; ONE_RTT_TAG_LEN])> {
    if packet.len() < ONE_RTT_HEADER_LEN + ONE_RTT_TAG_LEN {
        return None;
    }
    let flags = packet[0];
    // A 1-RTT short header has the QUIC fixed bit (0x40) set and the long-header
    // form bit (0x80) clear. Reject long-header packets (e.g. a late handshake
    // retransmit arriving on this socket) up front, consistent with
    // `is_long_header`, rather than relying on AEAD failure to drop them.
    if flags & 0x80 != 0 || flags & ONE_RTT_FIXED_BIT == 0 {
        return None;
    }
    let key_phase = flags & ONE_RTT_KEY_PHASE_BIT != 0;
    let mut pn_bytes = [0u8; 8];
    pn_bytes.copy_from_slice(&packet[1..ONE_RTT_HEADER_LEN]);
    let packet_number = u64::from_be_bytes(pn_bytes);
    let header = &packet[..ONE_RTT_HEADER_LEN];
    let body = &packet[ONE_RTT_HEADER_LEN..];
    let tag_offset = body.len() - ONE_RTT_TAG_LEN;
    let mut tag = [0u8; ONE_RTT_TAG_LEN];
    tag.copy_from_slice(&body[tag_offset..]);
    let ciphertext = &body[..tag_offset];
    Some((key_phase, packet_number, header, ciphertext, tag))
}

struct PendingOneRttPacket {
    packet_number: u64,
    header: [u8; ONE_RTT_HEADER_LEN],
    protected: ProtectedPacket,
}

enum DecodedInboundPacket {
    OneRtt(PendingOneRttPacket),
    NonOneRtt,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct IngestPacketsReport {
    packets_consumed: usize,
    one_rtt_packets_processed: usize,
    receive_backpressure: bool,
}

fn decode_protected_one_rtt_packet(
    provider_kind: &'static str,
    packet: &ReceivedPacket,
) -> Option<PendingOneRttPacket> {
    let (key_phase, packet_number, header, ciphertext, tag) = decode_one_rtt_packet(&packet.data)?;
    let mut header_bytes = [0u8; ONE_RTT_HEADER_LEN];
    header_bytes.copy_from_slice(header);
    Some(PendingOneRttPacket {
        packet_number,
        header: header_bytes,
        protected: ProtectedPacket {
            space: PacketProtectionSpace::OneRtt,
            key_phase,
            packet_number,
            ciphertext: ciphertext.to_vec(),
            tag,
            proof: ProtectionProof {
                provider_kind,
                space: PacketProtectionSpace::OneRtt,
                key_phase,
                generation: 0,
                transcript_hash: TranscriptHash::from_bytes([0u8; 32]),
                failure_code: None,
            },
        },
    })
}

fn one_rtt_max_payload_for_udp_packet(max_udp_packet: usize) -> usize {
    max_udp_packet
        .saturating_sub(ONE_RTT_PACKET_OVERHEAD)
        .saturating_sub(ONE_RTT_COALESCED_CONTROL_HEADROOM)
}

fn coalesced_datagram_frames_per_packet(
    max_app_payload: usize,
    datagram_frame_len: usize,
) -> usize {
    (max_app_payload / datagram_frame_len.max(1)).max(1)
}

fn frame_is_ack_eliciting_for_recovery(frame: &QuicFrame) -> bool {
    !matches!(
        frame,
        QuicFrame::Padding { .. } | QuicFrame::Ack { .. } | QuicFrame::ConnectionClose { .. }
    )
}

fn frames_have_datagram(frames: &[QuicFrame]) -> bool {
    frames
        .iter()
        .any(|frame| matches!(frame, QuicFrame::Datagram { .. }))
}

fn frames_require_quic_recovery_in_flight(frames: &[QuicFrame]) -> bool {
    frames.iter().any(|frame| {
        frame_is_ack_eliciting_for_recovery(frame) && !matches!(frame, QuicFrame::Datagram { .. })
    })
}

fn data_plane_packet_accounting_bytes(packet_len: usize) -> u64 {
    u64::try_from(packet_len)
        .unwrap_or(u64::MAX)
        .clamp(1, QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DataPlaneCwndTelemetry {
    bytes_in_flight: u64,
    congestion_window: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DataPlaneFlushAdmission {
    max_frame_bytes: usize,
    cwnd_telemetry: Option<DataPlaneCwndTelemetry>,
}

fn data_plane_cwnd_telemetry(
    transport: &crate::net::quic_native::QuicTransportMachine,
    pending_datagrams: usize,
) -> Option<DataPlaneCwndTelemetry> {
    if pending_datagrams == 0 || transport.can_send(QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES) {
        return None;
    }
    Some(DataPlaneCwndTelemetry {
        bytes_in_flight: transport.bytes_in_flight(),
        congestion_window: transport.congestion_window_bytes(),
    })
}

fn data_plane_flush_admission(
    transport: &crate::net::quic_native::QuicTransportMachine,
    pending_datagrams: usize,
    spray_frame_payload_limit: usize,
    max_app_payload: usize,
) -> DataPlaneFlushAdmission {
    DataPlaneFlushAdmission {
        max_frame_bytes: if pending_datagrams > 0 {
            spray_frame_payload_limit
        } else {
            max_app_payload
        },
        cwnd_telemetry: data_plane_cwnd_telemetry(transport, pending_datagrams),
    }
}

fn data_plane_packet_uses_paced_recovery(frames: &[QuicFrame]) -> bool {
    frames_have_datagram(frames) && !frames_require_quic_recovery_in_flight(frames)
}

fn source_stream_packet_uses_paced_recovery(
    frames: &[QuicFrame],
    source_stream: Option<StreamId>,
) -> bool {
    let Some(source_stream) = source_stream else {
        return false;
    };
    let mut has_source_stream_data = false;
    for frame in frames {
        match frame {
            QuicFrame::Stream { stream_id, .. } if stream_id.value() == source_stream.0 => {
                has_source_stream_data = true;
            }
            frame if frame_is_ack_eliciting_for_recovery(frame) => return false,
            _ => {}
        }
    }
    has_source_stream_data
}

fn packet_uses_paced_recovery(frames: &[QuicFrame], source_stream: Option<StreamId>) -> bool {
    data_plane_packet_uses_paced_recovery(frames)
        || source_stream_packet_uses_paced_recovery(frames, source_stream)
}

fn packet_tracks_recovery_in_flight(frames: &[QuicFrame], source_stream: Option<StreamId>) -> bool {
    !packet_uses_paced_recovery(frames, source_stream)
        && frames.iter().any(frame_is_ack_eliciting_for_recovery)
}

fn trace_quic_data_plane_cwnd_telemetry(
    cx: &Cx,
    pending_datagrams: usize,
    telemetry: DataPlaneCwndTelemetry,
) {
    if std::env::var_os("ATP_RQ_TRACE").is_none() {
        return;
    }
    let pending_datagrams_s = pending_datagrams.to_string();
    let bytes_in_flight_s = telemetry.bytes_in_flight.to_string();
    let congestion_window_s = telemetry.congestion_window.to_string();
    cx.trace_with_fields(
        "atp_quic.sender.data_plane_cwnd_telemetry",
        &[
            ("pending_datagrams", pending_datagrams_s.as_str()),
            ("bytes_in_flight", bytes_in_flight_s.as_str()),
            ("congestion_window", congestion_window_s.as_str()),
            ("admission", "pacer"),
        ],
    );
    quic_rqtrace!(
        "sender: data_plane_cwnd_telemetry pending_datagrams={} bytes_in_flight={} congestion_window={} admission=pacer",
        pending_datagrams,
        telemetry.bytes_in_flight,
        telemetry.congestion_window,
    );
}

fn trace_quic_data_plane_loss_timeout(
    cx: &Cx,
    pending_datagrams: usize,
    lost_packets: usize,
    lost_bytes: u64,
    bytes_in_flight: u64,
    congestion_window: u64,
    pto_count: u32,
) {
    let pending_datagrams_s = pending_datagrams.to_string();
    let lost_packets_s = lost_packets.to_string();
    let lost_bytes_s = lost_bytes.to_string();
    let bytes_in_flight_s = bytes_in_flight.to_string();
    let congestion_window_s = congestion_window.to_string();
    let pto_count_s = pto_count.to_string();
    cx.trace_with_fields(
        "atp_quic.sender.data_plane_loss_timeout",
        &[
            ("pending_datagrams", pending_datagrams_s.as_str()),
            ("lost_packets", lost_packets_s.as_str()),
            ("lost_bytes", lost_bytes_s.as_str()),
            ("bytes_in_flight", bytes_in_flight_s.as_str()),
            ("congestion_window", congestion_window_s.as_str()),
            ("pto_count", pto_count_s.as_str()),
        ],
    );
    quic_rqtrace!(
        "sender: data_plane_loss_timeout pending_datagrams={} lost_packets={} lost_bytes={} bytes_in_flight={} congestion_window={} pto_count={}",
        pending_datagrams,
        lost_packets,
        lost_bytes,
        bytes_in_flight,
        congestion_window,
        pto_count,
    );
}

fn trace_quic_data_plane_pacer_limited(
    cx: &Cx,
    pending_datagrams: usize,
    wait: Duration,
    pacing_rate_bps: u64,
    bytes_in_flight: u64,
    congestion_window: u64,
) {
    if std::env::var_os("ATP_RQ_TRACE").is_none() {
        return;
    }
    let pending_datagrams_s = pending_datagrams.to_string();
    let wait_micros_s = wait.as_micros().to_string();
    let pacing_rate_bps_s = pacing_rate_bps.to_string();
    let bytes_in_flight_s = bytes_in_flight.to_string();
    let congestion_window_s = congestion_window.to_string();
    cx.trace_with_fields(
        "atp_quic.sender.data_plane_pacer_limited",
        &[
            ("pending_datagrams", pending_datagrams_s.as_str()),
            ("wait_micros", wait_micros_s.as_str()),
            ("pacing_rate_bps", pacing_rate_bps_s.as_str()),
            ("bytes_in_flight", bytes_in_flight_s.as_str()),
            ("congestion_window", congestion_window_s.as_str()),
            ("admission", "pacer"),
        ],
    );
    quic_rqtrace!(
        "sender: data_plane_pacer_limited pending_datagrams={} wait_micros={} pacing_rate_bps={} bytes_in_flight={} congestion_window={} admission=pacer",
        pending_datagrams,
        wait.as_micros(),
        pacing_rate_bps,
        bytes_in_flight,
        congestion_window,
    );
}

fn promote_source_stream_pacing(
    pacing: &mut QuicSprayPacingDecision,
    config: &QuicConfig,
    symbol_datagram_frame_len: usize,
) {
    if config.bwlimit_bps.is_none() && super::quic_near_clean_source_stream_enabled(config, pacing)
    {
        let max_rate = super::QUIC_RELIABLE_SOURCE_STREAM_MAX_PACING_BPS;
        if pacing.pacing_rate_bps < max_rate {
            pacing.pacing_rate_bps = max_rate;
            super::update_quic_pacing_pause(
                pacing,
                symbol_datagram_frame_len,
                config.max_spray_symbols_per_flush,
            );
        }
    }
}

fn queued_fountain_feedback_count(pending: &VecDeque<Frame>) -> usize {
    pending
        .iter()
        .filter(|frame| {
            matches!(
                frame.frame_type(),
                FrameType::ObjectRequest | FrameType::Proof
            )
        })
        .count()
}

fn trace_quic_initial_spray_cut_for_feedback(
    cx: &Cx,
    sent_symbols: u64,
    queued_feedback: usize,
    pending_datagrams: usize,
    bytes_in_flight: u64,
    congestion_window: u64,
    entry_index: u32,
    sbn: u8,
    repair_cursor: usize,
) {
    let sent_symbols_s = sent_symbols.to_string();
    let queued_feedback_s = queued_feedback.to_string();
    let pending_datagrams_s = pending_datagrams.to_string();
    let bytes_in_flight_s = bytes_in_flight.to_string();
    let congestion_window_s = congestion_window.to_string();
    let entry_index_s = entry_index.to_string();
    let sbn_s = sbn.to_string();
    let repair_cursor_s = repair_cursor.to_string();
    cx.trace_with_fields(
        "atp_quic.sender.initial_spray_feedback_cut",
        &[
            ("sent_symbols", sent_symbols_s.as_str()),
            ("queued_feedback", queued_feedback_s.as_str()),
            ("pending_datagrams", pending_datagrams_s.as_str()),
            ("bytes_in_flight", bytes_in_flight_s.as_str()),
            ("congestion_window", congestion_window_s.as_str()),
            ("entry", entry_index_s.as_str()),
            ("sbn", sbn_s.as_str()),
            ("repair_cursor", repair_cursor_s.as_str()),
        ],
    );
    quic_rqtrace!(
        "sender: initial_spray_feedback_cut sent_symbols={} queued_feedback={} pending_datagrams={} bytes_in_flight={} congestion_window={} entry={} sbn={} repair_cursor={}",
        sent_symbols,
        queued_feedback,
        pending_datagrams,
        bytes_in_flight,
        congestion_window,
        entry_index,
        sbn,
        repair_cursor,
    );
}

/// Native ATP-QUIC data-plane send authority.
///
/// QUIC recovery remains useful as ACK/loss/RTT telemetry, but its NewReno cwnd
/// floors at `2*MSS` on random loss. MATRIX-132 showed that this strangles the
/// RaptorQ fountain below rsync on the 50M/bad cell. Spend one token per symbol
/// before handing it to the QUIC DATAGRAM queue; the connection's cwnd is still
/// sampled, but no longer decides whether fountain symbols may leave.
struct NativeDataPlanePacer {
    controller: CongestionController,
    symbol_frame_bytes: u32,
    pacing_rate_bps: u64,
    byte_pacer_next_send_at: Option<Instant>,
    byte_pacer_burst_bytes: usize,
    byte_pacer_burst_remaining: usize,
}

impl NativeDataPlanePacer {
    fn new(symbol_frame_len: usize, burst_symbols: usize, rate_bytes_per_sec: u64) -> Self {
        let symbol_frame_bytes = u32::try_from(symbol_frame_len.max(1))
            .unwrap_or(u32::MAX)
            .max(1);
        let mut pacer = Self {
            controller: CongestionController::new(CongestionConfig::default()),
            symbol_frame_bytes,
            pacing_rate_bps: rate_bytes_per_sec.max(1),
            byte_pacer_next_send_at: None,
            byte_pacer_burst_bytes: symbol_frame_len.max(1).saturating_mul(burst_symbols.max(1)),
            byte_pacer_burst_remaining: 0,
        };
        pacer.controller.configure_for_path_rate(
            pacer.pacing_rate_bps.saturating_mul(8).max(1),
            pacer.symbol_frame_bytes,
            u32::try_from(burst_symbols.max(1)).unwrap_or(u32::MAX),
        );
        pacer
    }

    fn configure(&mut self, pacing: &QuicSprayPacingDecision) {
        self.pacing_rate_bps = pacing.pacing_rate_bps.max(1);
        self.byte_pacer_next_send_at = None;
        let symbol_frame_bytes = usize::try_from(self.symbol_frame_bytes)
            .unwrap_or(usize::MAX)
            .max(1);
        self.byte_pacer_burst_bytes =
            symbol_frame_bytes.saturating_mul(pacing.max_burst_symbols.max(1));
        self.byte_pacer_burst_remaining = 0;
        self.controller.configure_for_path_rate(
            self.pacing_rate_bps.saturating_mul(8).max(1),
            self.symbol_frame_bytes,
            u32::try_from(pacing.max_burst_symbols.max(1)).unwrap_or(u32::MAX),
        );
        self.controller.update_congestion_feedback(
            data_plane_pacer_rtt(pacing),
            pacing.congestion_loss_rate > 0.0,
        );
    }

    fn configure_with_shared_decision(
        &mut self,
        pacing: &QuicSprayPacingDecision,
        shared_decision: Option<DatagramRateDecision>,
    ) {
        self.configure(pacing);
        if let Some(decision) = shared_decision {
            self.controller.configure_from_rate_decision(
                decision,
                self.symbol_frame_bytes,
                u32::try_from(pacing.max_burst_symbols.max(1)).unwrap_or(u32::MAX),
            );
        }
    }

    fn configure_source_stream(&mut self, pacing: &QuicSprayPacingDecision) {
        self.configure(pacing);
        self.byte_pacer_burst_bytes = self
            .byte_pacer_burst_bytes
            .max(source_stream_max_frame_bytes())
            .max(usize::try_from(QUIC_SOURCE_STREAM_FLUSH_BYTES).unwrap_or(usize::MAX));
        self.byte_pacer_burst_remaining = 0;
        self.byte_pacer_next_send_at = None;
    }

    async fn before_send(
        &mut self,
        cx: &Cx,
        pending_datagrams: usize,
        bytes_in_flight: u64,
        congestion_window: u64,
    ) -> Result<(), QuicTransportError> {
        loop {
            let now = Instant::now();
            if self.controller.try_consume_send_budget(now) {
                return Ok(());
            }
            let wait = self.controller.time_until_send_budget(now).clamp(
                QUIC_DATA_PLANE_PACER_MIN_PAUSE,
                QUIC_DATA_PLANE_PACER_MAX_PAUSE,
            );
            trace_quic_data_plane_pacer_limited(
                cx,
                pending_datagrams,
                wait,
                self.pacing_rate_bps,
                bytes_in_flight,
                congestion_window,
            );
            crate::time::sleep(cx.now(), wait).await;
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        }
    }

    async fn before_send_bytes(
        &mut self,
        cx: &Cx,
        frame_bytes: usize,
        pending_datagrams: usize,
        bytes_in_flight: u64,
        congestion_window: u64,
    ) -> Result<(), QuicTransportError> {
        while let Some(next_send_at) = self.byte_pacer_next_send_at {
            let now = Instant::now();
            if now >= next_send_at {
                break;
            }
            let wait = next_send_at.duration_since(now).clamp(
                QUIC_DATA_PLANE_PACER_MIN_PAUSE,
                QUIC_DATA_PLANE_PACER_MAX_PAUSE,
            );
            trace_quic_data_plane_pacer_limited(
                cx,
                pending_datagrams,
                wait,
                self.pacing_rate_bps,
                bytes_in_flight,
                congestion_window,
            );
            crate::time::sleep(cx.now(), wait).await;
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        }

        let now = Instant::now();
        let pacer_bytes = frame_bytes.max(1);
        if self.byte_pacer_burst_remaining == 0 {
            self.byte_pacer_burst_remaining = self.byte_pacer_burst_bytes.max(pacer_bytes);
        }
        self.byte_pacer_burst_remaining =
            self.byte_pacer_burst_remaining.saturating_sub(pacer_bytes);
        if self.byte_pacer_burst_remaining == 0 {
            let interval = source_stream_pacing_interval(
                self.byte_pacer_burst_bytes.max(pacer_bytes),
                self.pacing_rate_bps,
            );
            self.byte_pacer_next_send_at = Some(now.checked_add(interval).unwrap_or(now));
        }
        Ok(())
    }
}

fn data_plane_pacer_rtt(pacing: &QuicSprayPacingDecision) -> Option<Duration> {
    if pacing.path_rtt_s.is_finite() && pacing.path_rtt_s > 0.0 {
        Some(Duration::from_secs_f64(pacing.path_rtt_s))
    } else {
        None
    }
}

fn coalesced_spray_flush_symbol_limit(
    pacing_burst_symbols: usize,
    max_symbol_frames_per_packet: usize,
    max_flush_symbols: usize,
    path_loss_rate: f64,
    clean_packet_batch_target: usize,
) -> usize {
    let flush_cap = max_flush_symbols.max(1);
    let packet_width = max_symbol_frames_per_packet.max(1);
    let burst = if path_loss_rate < QUIC_CLEAN_SPRAY_MAX_LOSS_RATE {
        // Loss-free encrypted sprays are dominated by per-packet QUIC work.
        // Queue multiple full protected packets, then sleep by byte count so
        // average pacing stays unchanged while UDP GSO has work to batch.
        let packet_floor = packet_width
            .saturating_mul(clean_packet_batch_target.max(1))
            .min(flush_cap);
        pacing_burst_symbols
            .max(1)
            .max(packet_floor)
            .max(QUIC_CLEAN_SPRAY_BURST_FLOOR_SYMBOLS)
            .min(flush_cap)
    } else {
        pacing_burst_symbols.max(1).min(flush_cap)
    };
    let full_packet_multiple = (burst / packet_width).saturating_mul(packet_width);
    if full_packet_multiple == 0 {
        burst
    } else {
        full_packet_multiple
    }
}

fn quic_clean_spray_coalescing_allowed(pacing: &QuicSprayPacingDecision) -> bool {
    QUIC_NATIVE_CLEAN_JUMBO_COALESCING_ENABLED
        && pacing.path_loss_rate < QUIC_CLEAN_SPRAY_MAX_LOSS_RATE
        && pacing.path_rtt_s.is_finite()
        && pacing.path_rtt_s > 0.0
        && pacing.path_rtt_s <= QUIC_CLEAN_COALESCING_MAX_RTT_S
}

fn clean_gso_flush_symbol_cap(
    max_spray_symbols_per_flush: usize,
    max_symbol_frames_per_packet: usize,
) -> usize {
    let base_cap = max_spray_symbols_per_flush.max(1);
    let packet_width = max_symbol_frames_per_packet.max(1);
    if base_cap < packet_width {
        base_cap
    } else if base_cap == super::DEFAULT_MAX_SPRAY_SYMBOLS_PER_FLUSH {
        base_cap
            .saturating_mul(QUIC_CLEAN_GSO_PACKETS_PER_FLUSH)
            .min(QUIC_CLEAN_GSO_MAX_FLUSH_SYMBOLS)
    } else {
        base_cap
    }
}

fn spray_handoff_symbol_limit_for(
    flush_symbols: usize,
    pending_outbound_datagrams: usize,
    path_loss_rate: f64,
) -> usize {
    let flush_symbols = flush_symbols.max(1);
    let remaining = flush_symbols.saturating_sub(pending_outbound_datagrams);
    let max_handoff = if path_loss_rate < QUIC_CLEAN_SPRAY_MAX_LOSS_RATE {
        flush_symbols
    } else {
        QUIC_LOSSY_SPRAY_HANDOFF_MAX_SYMBOLS
    };
    remaining.clamp(1, max_handoff)
}

fn quic_gso_send_strategy(packets: &[OutgoingPacket]) -> UdpSendBatchStrategy {
    let gso_segment_bytes = packets
        .iter()
        .map(|packet| packet.data.len())
        .max()
        .unwrap_or(1)
        .clamp(1, usize::from(u16::MAX));
    UdpSendBatchStrategy {
        gso_segment_bytes,
        max_gso_segments: QUIC_CLEAN_GSO_PACKETS_PER_FLUSH.min(UDP_MAX_GSO_SEGMENTS),
        ..UdpSendBatchStrategy::default()
    }
}

fn quic_varint_len(value: usize) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

fn symbol_datagram_frame_len(symbol_size: u16, envelope_header_len: usize) -> usize {
    let payload_len = usize::from(symbol_size.max(1)).saturating_add(envelope_header_len);
    // ATP DATAGRAM frames are encoded as 0x31 (type + explicit length + payload)
    // so many frames can be carried in one protected 1-RTT packet.
    1usize
        .saturating_add(quic_varint_len(payload_len))
        .saturating_add(payload_len)
}

fn inbound_udp_packet_receive_limit(
    remaining_datagram_capacity: usize,
    max_datagram_frames_per_packet: usize,
) -> usize {
    INBOUND_PUMP_BATCH.min(remaining_datagram_capacity / max_datagram_frames_per_packet.max(1))
}

/// An established native QUIC connection plus everything needed to drive its
/// 1-RTT application data plane over a real UDP socket.
pub struct QuicLink {
    conn: NativeQuicConnection,
    endpoint: QuicUdpEndpoint,
    protection: AtpPacketProtection,
    peer: SocketAddr,
    role: StreamRole,
    /// Local short-header packet number fallback for packets not tracked by recovery.
    send_pn: u64,
    /// Monotonic data-plane clock fed to the connection.
    clock: u64,
    /// Max application payload that fits one 1-RTT packet under the endpoint MTU.
    max_app_payload: usize,
    /// Expected upper bound on ATP symbol DATAGRAM frames one received UDP
    /// packet may enqueue before the symbol decoder gets a turn to drain them.
    max_datagram_frames_per_packet: usize,
    /// Auth-posture-aware symbol DATAGRAM frame width used to align paced
    /// sender flushes to full protected packets.
    max_symbol_frames_per_packet: usize,
    /// Current symbol DATAGRAM frames allowed per protected spray packet.
    spray_max_datagram_frames_per_packet: usize,
    /// Configured upper bound on symbols queued before a protected packet flush.
    max_spray_symbols_per_flush: usize,
    symbol_datagram_frame_len: usize,
    data_plane_pacer: NativeDataPlanePacer,
    pending_received_packets: VecDeque<ReceivedPacket>,
    sender_handoff: QuicSenderHandoffStats,
    idle_timeout: Duration,
    beacons: BeaconScheduler,
    pending_control_frames: VecDeque<Frame>,
    last_flushed_stream_frames: Vec<SentControlStreamFrame>,
    in_flight_stream_frames: BTreeMap<u64, Vec<SentControlStreamFrame>>,
    latest_stream_ack_ranges: Vec<NativeAckRange>,
    received_source_stream_frames: VecDeque<ReceivedSourceStreamFrame>,
    paced_source_stream: Option<StreamId>,
    udp_packets_received: u64,
    one_rtt_packets_ingested: u64,
    non_one_rtt_packets_dropped: u64,
    unprotect_packets_dropped: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct QuicSenderHandoffStats {
    symbols_queued: u64,
    enqueue_micros: u128,
    max_pending_before_enqueue: usize,
    max_pending_after_enqueue: usize,
    queue_full_flushes: u64,
    liveness_polls: u64,
    liveness_micros: u128,
    flushes: u64,
    generated_packets: u64,
    datagram_frames: u64,
    generate_micros: u128,
    protect_micros: u128,
    udp_send_micros: u128,
    max_pending_before_flush: usize,
    max_datagrams_per_plain_packet: usize,
}

impl QuicSenderHandoffStats {
    fn has_symbol_work(&self) -> bool {
        self.symbols_queued > 0 || self.flushes > 0 || self.queue_full_flushes > 0
    }

    fn record_enqueue(
        &mut self,
        queued: usize,
        pending_before: usize,
        pending_after: usize,
        elapsed: Duration,
    ) {
        self.symbols_queued = self
            .symbols_queued
            .saturating_add(u64::try_from(queued).unwrap_or(u64::MAX));
        self.enqueue_micros = self.enqueue_micros.saturating_add(elapsed.as_micros());
        self.max_pending_before_enqueue = self.max_pending_before_enqueue.max(pending_before);
        self.max_pending_after_enqueue = self.max_pending_after_enqueue.max(pending_after);
    }

    fn record_queue_full_flush(&mut self, liveness_elapsed: Duration) {
        self.queue_full_flushes = self.queue_full_flushes.saturating_add(1);
        self.liveness_polls = self.liveness_polls.saturating_add(1);
        self.liveness_micros = self
            .liveness_micros
            .saturating_add(liveness_elapsed.as_micros());
    }

    fn record_flush(
        &mut self,
        packets: usize,
        datagram_frames: usize,
        pending_before: usize,
        max_datagrams_per_plain_packet: usize,
        generate_elapsed: Duration,
        protect_elapsed: Duration,
        udp_send_elapsed: Duration,
    ) {
        self.flushes = self.flushes.saturating_add(1);
        self.generated_packets = self
            .generated_packets
            .saturating_add(u64::try_from(packets).unwrap_or(u64::MAX));
        self.datagram_frames = self
            .datagram_frames
            .saturating_add(u64::try_from(datagram_frames).unwrap_or(u64::MAX));
        self.generate_micros = self
            .generate_micros
            .saturating_add(generate_elapsed.as_micros());
        self.protect_micros = self
            .protect_micros
            .saturating_add(protect_elapsed.as_micros());
        self.udp_send_micros = self
            .udp_send_micros
            .saturating_add(udp_send_elapsed.as_micros());
        self.max_pending_before_flush = self.max_pending_before_flush.max(pending_before);
        self.max_datagrams_per_plain_packet = self
            .max_datagrams_per_plain_packet
            .max(max_datagrams_per_plain_packet);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeReceiveTraceCounters {
    udp_packets_received: u64,
    one_rtt_packets_ingested: u64,
    non_one_rtt_packets_dropped: u64,
    unprotect_packets_dropped: u64,
    datagrams_received: u64,
    datagrams_dropped_on_receive: u64,
    pending_datagrams: usize,
    pending_received_packets: usize,
    inbound_datagram_capacity: usize,
    inbound_datagram_available: usize,
    inbound_pump_batch_limit: usize,
    udp_recv_buffer_requested: Option<usize>,
    udp_recv_buffer_applied: Option<usize>,
    udp_kernel_rx_queue_bytes: Option<u64>,
    udp_kernel_drops: Option<u64>,
}

impl NativeReceiveTraceCounters {
    fn capture(link: &QuicLink) -> Self {
        let socket = NativeUdpReceiveDiagnostics::capture(&link.endpoint);
        Self {
            udp_packets_received: link.udp_packets_received,
            one_rtt_packets_ingested: link.one_rtt_packets_ingested,
            non_one_rtt_packets_dropped: link.non_one_rtt_packets_dropped,
            unprotect_packets_dropped: link.unprotect_packets_dropped,
            datagrams_received: link.conn.datagrams_received(),
            datagrams_dropped_on_receive: link.conn.datagrams_dropped_on_receive(),
            pending_datagrams: link.conn.pending_datagram_count(),
            pending_received_packets: link.pending_received_packets.len(),
            inbound_datagram_capacity: link.conn.inbound_datagram_capacity(),
            inbound_datagram_available: link.conn.inbound_datagram_remaining_capacity(),
            inbound_pump_batch_limit: INBOUND_PUMP_BATCH,
            udp_recv_buffer_requested: socket.recv_buffer_requested,
            udp_recv_buffer_applied: socket.recv_buffer_applied,
            udp_kernel_rx_queue_bytes: socket.kernel_rx_queue_bytes,
            udp_kernel_drops: socket.kernel_drops,
        }
    }

    fn trace_decoded(
        &self,
        cx: &Cx,
        transfer_id: &str,
        symbols_accepted: u64,
        feedback_rounds: u32,
        decode_stats: &super::QuicDecodeStats,
    ) {
        let symbols_accepted_text = symbols_accepted.to_string();
        let feedback_rounds_text = feedback_rounds.to_string();
        let decode_count_text = decode_stats.decode_count.to_string();
        let decode_micros_text = decode_stats.decode_micros.to_string();
        let udp_packets_received_text = self.udp_packets_received.to_string();
        let one_rtt_packets_ingested_text = self.one_rtt_packets_ingested.to_string();
        let non_one_rtt_packets_dropped_text = self.non_one_rtt_packets_dropped.to_string();
        let unprotect_packets_dropped_text = self.unprotect_packets_dropped.to_string();
        let datagrams_received_text = self.datagrams_received.to_string();
        let datagrams_dropped_on_receive_text = self.datagrams_dropped_on_receive.to_string();
        let pending_datagrams_text = self.pending_datagrams.to_string();
        let pending_received_packets_text = self.pending_received_packets.to_string();
        let inbound_datagram_capacity_text = self.inbound_datagram_capacity.to_string();
        let inbound_datagram_available_text = self.inbound_datagram_available.to_string();
        let inbound_pump_batch_limit_text = self.inbound_pump_batch_limit.to_string();
        let udp_recv_buffer_requested_text = option_usize_trace(self.udp_recv_buffer_requested);
        let udp_recv_buffer_applied_text = option_usize_trace(self.udp_recv_buffer_applied);
        let udp_kernel_rx_queue_bytes_text = option_u64_trace(self.udp_kernel_rx_queue_bytes);
        let udp_kernel_drops_text = option_u64_trace(self.udp_kernel_drops);
        cx.trace_with_fields(
            "atp_quic.receive.decoded",
            &[
                ("symbols_accepted", symbols_accepted_text.as_str()),
                ("feedback_rounds", feedback_rounds_text.as_str()),
                ("decode_count", decode_count_text.as_str()),
                ("decode_micros", decode_micros_text.as_str()),
                ("datagrams_received", datagrams_received_text.as_str()),
                (
                    "datagrams_dropped_on_receive",
                    datagrams_dropped_on_receive_text.as_str(),
                ),
                ("pending_datagrams", pending_datagrams_text.as_str()),
                ("reorder_occupancy", pending_datagrams_text.as_str()),
                (
                    "pending_received_packets",
                    pending_received_packets_text.as_str(),
                ),
                ("transfer_id", transfer_id),
            ],
        );
        cx.trace_with_fields(
            "atp_quic.receive.socket",
            &[
                ("udp_packets_received", udp_packets_received_text.as_str()),
                (
                    "one_rtt_packets_ingested",
                    one_rtt_packets_ingested_text.as_str(),
                ),
                (
                    "non_one_rtt_packets_dropped",
                    non_one_rtt_packets_dropped_text.as_str(),
                ),
                (
                    "unprotect_packets_dropped",
                    unprotect_packets_dropped_text.as_str(),
                ),
                (
                    "inbound_datagram_capacity",
                    inbound_datagram_capacity_text.as_str(),
                ),
                (
                    "inbound_datagram_available",
                    inbound_datagram_available_text.as_str(),
                ),
                (
                    "inbound_pump_batch_limit",
                    inbound_pump_batch_limit_text.as_str(),
                ),
                (
                    "udp_recv_buffer_requested",
                    udp_recv_buffer_requested_text.as_str(),
                ),
                (
                    "udp_recv_buffer_applied",
                    udp_recv_buffer_applied_text.as_str(),
                ),
                (
                    "udp_kernel_rx_queue_bytes",
                    udp_kernel_rx_queue_bytes_text.as_str(),
                ),
                ("udp_kernel_drops", udp_kernel_drops_text.as_str()),
                ("transfer_id", transfer_id),
            ],
        );
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct NativeUdpReceiveDiagnostics {
    recv_buffer_requested: Option<usize>,
    recv_buffer_applied: Option<usize>,
    kernel_rx_queue_bytes: Option<u64>,
    kernel_drops: Option<u64>,
}

impl NativeUdpReceiveDiagnostics {
    fn capture(endpoint: &QuicUdpEndpoint) -> Self {
        let buffer_report = endpoint.buffer_report();
        let kernel = linux_udp_proc_receive_stats(endpoint.local_addr());
        Self {
            recv_buffer_requested: buffer_report.requested_recv_buffer_bytes,
            recv_buffer_applied: buffer_report.applied_recv_buffer_bytes,
            kernel_rx_queue_bytes: kernel.map(|stats| stats.rx_queue_bytes),
            kernel_drops: kernel.map(|stats| stats.drops),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinuxUdpProcReceiveStats {
    rx_queue_bytes: u64,
    drops: u64,
}

fn option_usize_trace(value: Option<usize>) -> String {
    value.map_or_else(|| "unknown".to_string(), |value| value.to_string())
}

fn option_u64_trace(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_string(), |value| value.to_string())
}

#[cfg(target_os = "linux")]
fn linux_udp_proc_receive_stats(local_addr: SocketAddr) -> Option<LinuxUdpProcReceiveStats> {
    std::fs::read_to_string("/proc/net/udp")
        .ok()
        .and_then(|table| linux_udp_proc_receive_stats_from_table(&table, local_addr))
        .or_else(|| {
            std::fs::read_to_string("/proc/net/udp6")
                .ok()
                .and_then(|table| linux_udp_proc_receive_stats_from_table(&table, local_addr))
        })
}

#[cfg(not(target_os = "linux"))]
fn linux_udp_proc_receive_stats(_local_addr: SocketAddr) -> Option<LinuxUdpProcReceiveStats> {
    None
}

#[cfg(target_os = "linux")]
fn linux_udp_proc_receive_stats_from_table(
    table: &str,
    local_addr: SocketAddr,
) -> Option<LinuxUdpProcReceiveStats> {
    table.lines().skip(1).find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let local = *fields.get(1)?;
        let queues = *fields.get(4)?;
        if !linux_udp_proc_local_matches(local, local_addr) {
            return None;
        }
        let (_, rx_queue_hex) = queues.split_once(':')?;
        let rx_queue_bytes = u64::from_str_radix(rx_queue_hex, 16).ok()?;
        let drops = fields.last()?.parse::<u64>().ok()?;
        Some(LinuxUdpProcReceiveStats {
            rx_queue_bytes,
            drops,
        })
    })
}

#[cfg(target_os = "linux")]
fn linux_udp_proc_local_matches(proc_local: &str, local_addr: SocketAddr) -> bool {
    let Some((addr_hex, port_hex)) = proc_local.split_once(':') else {
        return false;
    };
    let Ok(port) = u16::from_str_radix(port_hex, 16) else {
        return false;
    };
    if port != local_addr.port() {
        return false;
    }
    match local_addr.ip() {
        IpAddr::V4(ip) => ip.is_unspecified() || parse_linux_udp_proc_ipv4(addr_hex) == Some(ip),
        IpAddr::V6(ip) => ip.is_unspecified() || addr_hex.len() == 32,
    }
}

#[cfg(target_os = "linux")]
fn parse_linux_udp_proc_ipv4(addr_hex: &str) -> Option<Ipv4Addr> {
    if addr_hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(addr_hex, 16).ok()?;
    Some(Ipv4Addr::from(raw.to_le_bytes()))
}

fn native_quic_path_signal_with_observed_loss(
    transport: &QuicTransportMachine,
    observed_loss: f64,
) -> super::QuicPathSignalSample {
    let mut path = super::quic_path_signal_from_transport(transport);
    // MATRIX-132: raw QUIC DATAGRAM loss is expected inside the FEC budget. Keep
    // NewReno loss/cwnd observable through telemetry, but let the data-plane
    // pacer react to sender-observed fountain delivery loss instead.
    path.loss_rate = if observed_loss.is_finite() {
        observed_loss.clamp(0.0, 0.90)
    } else {
        0.0
    };
    path.clamped()
}

impl QuicLink {
    fn protection_config() -> AtpPacketProtectionConfig {
        AtpPacketProtectionConfig {
            // Per-packet proof logging on the data-plane hot path is pure overhead;
            // the structured per-frame trace lives in the ATP_QUIC_TRACE hook.
            enable_proof_logging: false,
            ..AtpPacketProtectionConfig::default()
        }
    }

    /// Local socket address (useful for the connecting client to learn its port).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr()
    }

    fn mark_peer_activity(&mut self) {
        self.beacons.mark_peer_activity(Instant::now());
    }

    fn beacon_measurement(&self) -> BeaconMeasurement {
        self.beacons
            .latest_rtt()
            .map_or_else(BeaconMeasurement::empty, |rtt| {
                BeaconMeasurement::with_rtt(u32::try_from(rtt.as_micros()).unwrap_or(u32::MAX), 0)
            })
    }

    fn inbound_receive_packet_limit(&self) -> usize {
        inbound_udp_packet_receive_limit(
            self.conn.inbound_datagram_remaining_capacity(),
            self.max_datagram_frames_per_packet,
        )
    }

    fn queue_received_packets(&mut self, packets: impl IntoIterator<Item = ReceivedPacket>) {
        self.pending_received_packets.extend(packets);
    }

    fn push_front_received_packets(&mut self, packets: &[ReceivedPacket]) {
        for packet in packets.iter().rev() {
            self.pending_received_packets.push_front(packet.clone());
        }
    }

    fn take_pending_received_packets(&mut self, limit: usize) -> Vec<ReceivedPacket> {
        let take = limit.min(self.pending_received_packets.len());
        let mut packets = Vec::with_capacity(take);
        for _ in 0..take {
            if let Some(packet) = self.pending_received_packets.pop_front() {
                packets.push(packet);
            }
        }
        packets
    }

    fn reset_sender_handoff_trace(&mut self) {
        self.sender_handoff = QuicSenderHandoffStats::default();
    }

    fn trace_sender_handoff_summary(&mut self, cx: &Cx, phase: &'static str, symbols: u64) {
        let stats = self.sender_handoff;
        if !stats.has_symbol_work() {
            return;
        }

        let symbols_s = symbols.to_string();
        let symbols_queued_s = stats.symbols_queued.to_string();
        let enqueue_micros_s = stats.enqueue_micros.to_string();
        let max_pending_before_enqueue_s = stats.max_pending_before_enqueue.to_string();
        let max_pending_after_enqueue_s = stats.max_pending_after_enqueue.to_string();
        let queue_full_flushes_s = stats.queue_full_flushes.to_string();
        let liveness_polls_s = stats.liveness_polls.to_string();
        let liveness_micros_s = stats.liveness_micros.to_string();
        let flushes_s = stats.flushes.to_string();
        let generated_packets_s = stats.generated_packets.to_string();
        let datagram_frames_s = stats.datagram_frames.to_string();
        let generate_micros_s = stats.generate_micros.to_string();
        let protect_micros_s = stats.protect_micros.to_string();
        let udp_send_micros_s = stats.udp_send_micros.to_string();
        let max_pending_before_flush_s = stats.max_pending_before_flush.to_string();
        let max_datagrams_per_plain_packet_s = stats.max_datagrams_per_plain_packet.to_string();

        cx.trace_with_fields(
            "atp_quic.sender.symbol_handoff_summary",
            &[
                ("phase", phase),
                ("symbols", symbols_s.as_str()),
                ("symbols_queued", symbols_queued_s.as_str()),
                ("enqueue_micros", enqueue_micros_s.as_str()),
                (
                    "max_pending_before_enqueue",
                    max_pending_before_enqueue_s.as_str(),
                ),
                (
                    "max_pending_after_enqueue",
                    max_pending_after_enqueue_s.as_str(),
                ),
                ("queue_full_flushes", queue_full_flushes_s.as_str()),
                ("liveness_polls", liveness_polls_s.as_str()),
                ("liveness_micros", liveness_micros_s.as_str()),
                ("flushes", flushes_s.as_str()),
                ("generated_packets", generated_packets_s.as_str()),
                ("datagram_frames", datagram_frames_s.as_str()),
                ("generate_micros", generate_micros_s.as_str()),
                ("protect_micros", protect_micros_s.as_str()),
                ("udp_send_micros", udp_send_micros_s.as_str()),
                (
                    "max_pending_before_flush",
                    max_pending_before_flush_s.as_str(),
                ),
                (
                    "max_datagrams_per_plain_packet",
                    max_datagrams_per_plain_packet_s.as_str(),
                ),
            ],
        );
        quic_rqtrace!(
            "sender: symbol_handoff_summary phase={} symbols={} symbols_queued={} enqueue_micros={} queue_full_flushes={} liveness_micros={} flushes={} generated_packets={} datagram_frames={} generate_micros={} protect_micros={} udp_send_micros={} max_pending_before_enqueue={} max_pending_after_enqueue={} max_pending_before_flush={} max_datagrams_per_plain_packet={}",
            phase,
            symbols,
            stats.symbols_queued,
            stats.enqueue_micros,
            stats.queue_full_flushes,
            stats.liveness_micros,
            stats.flushes,
            stats.generated_packets,
            stats.datagram_frames,
            stats.generate_micros,
            stats.protect_micros,
            stats.udp_send_micros,
            stats.max_pending_before_enqueue,
            stats.max_pending_after_enqueue,
            stats.max_pending_before_flush,
            stats.max_datagrams_per_plain_packet,
        );
        self.reset_sender_handoff_trace();
    }

    fn paced_flush_symbol_limit(&self, pacing: &QuicSprayPacingDecision) -> usize {
        let clean_flush_cap = clean_gso_flush_symbol_cap(
            self.max_spray_symbols_per_flush,
            self.max_symbol_frames_per_packet,
        );
        let clean_coalescing = quic_clean_spray_coalescing_allowed(pacing);
        let max_flush_symbols = if clean_coalescing {
            clean_flush_cap
        } else {
            self.max_spray_symbols_per_flush
        };
        coalesced_spray_flush_symbol_limit(
            pacing.max_burst_symbols,
            self.max_symbol_frames_per_packet,
            max_flush_symbols,
            if clean_coalescing {
                pacing.path_loss_rate
            } else {
                QUIC_CLEAN_SPRAY_MAX_LOSS_RATE
            },
            QUIC_CLEAN_GSO_PACKETS_PER_FLUSH,
        )
    }

    fn update_spray_packet_coalescing(&mut self, pacing: &QuicSprayPacingDecision) {
        self.spray_max_datagram_frames_per_packet = if quic_clean_spray_coalescing_allowed(pacing) {
            self.max_symbol_frames_per_packet.max(1)
        } else {
            1
        };
    }

    fn spray_frame_payload_limit(&self) -> usize {
        let frame_budget = self
            .symbol_datagram_frame_len
            .saturating_mul(self.spray_max_datagram_frames_per_packet.max(1))
            .saturating_add(ONE_RTT_COALESCED_CONTROL_HEADROOM);
        frame_budget.clamp(
            self.symbol_datagram_frame_len.max(1),
            self.max_app_payload.max(1),
        )
    }

    async fn service_spray_liveness(
        &mut self,
        cx: &Cx,
        control: &mut NativeQuicFrameTransport,
    ) -> Result<(), QuicTransportError> {
        let _ = self.pump_inbound_for(cx, INBOUND_PUMP_DRAIN_GRACE).await?;
        self.service_decoded_spray_liveness(cx, control).await
    }

    async fn flush_until_outbound_datagrams_drained(
        &mut self,
        cx: &Cx,
        control: &mut NativeQuicFrameTransport,
        operation: &'static str,
    ) -> Result<usize, QuicTransportError> {
        let mut total_flushed = 0usize;
        let mut last_progress = Instant::now();

        loop {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            if self.conn.pending_outbound_datagram_count() == 0 {
                return Ok(total_flushed);
            }

            let before = self.conn.pending_outbound_datagram_count();
            let flushed = self.flush(cx).await?;
            total_flushed = total_flushed.saturating_add(flushed);
            if self.conn.pending_outbound_datagram_count() == 0 {
                return Ok(total_flushed);
            }

            let pumped = self.pump_inbound_for(cx, NEEDMORE_PTO).await?;
            self.service_decoded_spray_liveness(cx, control).await?;
            let after = self.conn.pending_outbound_datagram_count();
            if flushed > 0 || pumped > 0 || after < before {
                last_progress = Instant::now();
            } else {
                self.release_expired_data_plane_loss(cx, after)?;
                if self.conn.pending_outbound_datagram_count() == 0 {
                    return Ok(total_flushed);
                }
                if last_progress.elapsed() >= self.idle_timeout {
                    return Err(QuicTransportError::Timeout {
                        operation,
                        timeout: self.idle_timeout,
                    });
                }
            }
        }
    }

    async fn service_decoded_spray_liveness(
        &mut self,
        cx: &Cx,
        control: &mut NativeQuicFrameTransport,
    ) -> Result<(), QuicTransportError> {
        while let Some(frame) = control.try_recv(cx, &mut self.conn)? {
            match frame.frame_type() {
                FrameType::KeepAlive => self.mark_peer_activity(),
                FrameType::ObjectRequest | FrameType::Proof => {
                    self.mark_peer_activity();
                    self.pending_control_frames.push_back(frame);
                }
                got => {
                    return Err(QuicTransportError::Unexpected {
                        got,
                        expected: "KeepAlive | ObjectRequest | Proof while spraying",
                    });
                }
            }
        }

        let measurement = self.beacon_measurement();
        if self
            .beacons
            .next_action(Instant::now(), measurement)
            .is_some()
        {
            send_native_keep_alive(cx, &mut self.conn, control)?;
            self.flush(cx).await?;
        }

        if self.beacons.peer_liveness_expired() {
            return Err(QuicTransportError::Timeout {
                operation: "spray peer liveness",
                timeout: self.idle_timeout,
            });
        }

        Ok(())
    }

    async fn drop_duplicate_need_more_resends(
        &mut self,
        cx: &Cx,
        control: &mut NativeQuicFrameTransport,
        served_need: &QuicNeedMore,
    ) -> Result<usize, QuicTransportError> {
        self.service_spray_liveness(cx, control).await?;
        let dropped =
            drop_duplicate_need_more_frames(&mut self.pending_control_frames, served_need)?;
        if dropped > 0 {
            let dropped_text = dropped.to_string();
            let queued_text = self.pending_control_frames.len().to_string();
            let requested_text = need_more_repair_symbol_count(served_need).to_string();
            cx.trace_with_fields(
                "atp_quic.sender.drop_duplicate_need_more",
                &[
                    ("dropped", dropped_text.as_str()),
                    ("queued_after_drop", queued_text.as_str()),
                    ("requested_repair_symbols", requested_text.as_str()),
                ],
            );
            quic_rqtrace!(
                "sender: dropped_duplicate_need_more dropped={} queued_after_drop={} requested_repair_symbols={}",
                dropped,
                self.pending_control_frames.len(),
                need_more_repair_symbol_count(served_need),
            );
        }
        Ok(dropped)
    }

    fn release_expired_data_plane_loss(
        &mut self,
        cx: &Cx,
        pending_datagrams: usize,
    ) -> Result<(), QuicTransportError> {
        let Some(deadline) = self.conn.pto_deadline_micros(cx, self.clock)? else {
            return Ok(());
        };
        if deadline > self.clock {
            return Ok(());
        }

        let event = self.conn.on_loss_timeout_expired(
            cx,
            PacketNumberSpace::ApplicationData,
            self.clock,
        )?;
        if event.lost_packets > 0 {
            trace_quic_data_plane_loss_timeout(
                cx,
                pending_datagrams,
                event.lost_packets,
                event.lost_bytes,
                self.conn.transport().bytes_in_flight(),
                self.conn.transport().congestion_window_bytes(),
                self.conn.transport().pto_count(),
            );
        }
        Ok(())
    }

    fn expire_app_data_loss_timeout(
        &mut self,
        cx: &Cx,
        operation: &'static str,
    ) -> Result<usize, QuicTransportError> {
        let Some(deadline) = self.conn.pto_deadline_micros(cx, self.clock)? else {
            return Ok(0);
        };
        self.clock = self.clock.max(deadline);
        let event = self.conn.on_loss_timeout_expired(
            cx,
            PacketNumberSpace::ApplicationData,
            self.clock,
        )?;
        if event.lost_packets > 0 {
            quic_rqtrace!(
                "sender: app_data_loss_timeout operation={} lost_packets={} lost_bytes={} bytes_in_flight={} congestion_window={} pto_count={}",
                operation,
                event.lost_packets,
                event.lost_bytes,
                self.conn.transport().bytes_in_flight(),
                self.conn.transport().congestion_window_bytes(),
                self.conn.transport().pto_count(),
            );
        }
        Ok(event.lost_packets)
    }

    /// Drain all currently-pending application frames, protect each into a 1-RTT
    /// packet, and send the batch over UDP. Returns the number of packets sent.
    async fn flush(&mut self, cx: &Cx) -> Result<usize, QuicTransportError> {
        struct PlainOneRttPacket {
            packet_number: u64,
            header: [u8; ONE_RTT_HEADER_LEN],
            payload: BytesMut,
            stream_frames: Vec<SentControlStreamFrame>,
        }

        let pending_before_flush = self.conn.pending_outbound_datagram_count();
        let generate_started = Instant::now();
        let mut plain_packets = Vec::new();
        let mut flushed_stream_frames = Vec::new();
        let mut datagram_frames = 0usize;
        let mut max_datagram_frames_per_plain_packet = 0usize;
        let mut plaintext_payload_bytes = 0usize;
        loop {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            let pending_datagrams = self.conn.pending_outbound_datagram_count();
            let admission = if self.role == StreamRole::Client && pending_datagrams > 0 {
                self.release_expired_data_plane_loss(cx, pending_datagrams)?;
                let admission = data_plane_flush_admission(
                    self.conn.transport(),
                    pending_datagrams,
                    self.spray_frame_payload_limit(),
                    self.max_app_payload,
                );
                if let Some(telemetry) = admission.cwnd_telemetry {
                    trace_quic_data_plane_cwnd_telemetry(cx, pending_datagrams, telemetry);
                }
                admission
            } else {
                data_plane_flush_admission(
                    self.conn.transport(),
                    pending_datagrams,
                    self.spray_frame_payload_limit(),
                    self.max_app_payload,
                )
            };
            let paced_source_stream_pending = pending_datagrams == 0
                && self
                    .paced_source_stream
                    .is_some_and(|stream| self.conn.has_pending_stream_frames_for(stream));
            let max_frame_bytes = if paced_source_stream_pending {
                admission
                    .max_frame_bytes
                    .min(source_stream_max_frame_bytes())
            } else if pending_datagrams == 0 && self.conn.has_pending_stream_frames() {
                let transport = self.conn.transport();
                let available = transport
                    .congestion_window_bytes()
                    .saturating_sub(transport.bytes_in_flight());
                if available <= QUIC_STREAM_PACKET_OVERHEAD_BUDGET {
                    break;
                }
                admission
                    .max_frame_bytes
                    .min(source_stream_max_frame_bytes())
                    .min(
                        usize::try_from(
                            available.saturating_sub(QUIC_STREAM_PACKET_OVERHEAD_BUDGET),
                        )
                        .unwrap_or(usize::MAX),
                    )
            } else {
                admission.max_frame_bytes
            };
            if max_frame_bytes == 0 {
                break;
            }
            if paced_source_stream_pending {
                let source_stream = self
                    .paced_source_stream
                    .expect("paced source stream checked above");
                let frame_bytes =
                    usize::try_from(self.conn.pending_stream_data_bytes_for(source_stream))
                        .unwrap_or(usize::MAX)
                        .min(max_frame_bytes)
                        .max(1);
                let bytes_in_flight = self.conn.transport().bytes_in_flight();
                let congestion_window = self.conn.transport().congestion_window_bytes();
                self.data_plane_pacer
                    .before_send_bytes(
                        cx,
                        frame_bytes,
                        self.conn.pending_stream_frame_count(),
                        bytes_in_flight,
                        congestion_window,
                    )
                    .await?;
            }
            let frames = if paced_source_stream_pending {
                let source_stream = self
                    .paced_source_stream
                    .expect("paced source stream checked above");
                self.conn.generate_stream_frames_for(
                    cx,
                    PacketNumberSpace::ApplicationData,
                    source_stream,
                    max_frame_bytes,
                )?
            } else {
                self.conn.generate_frames(
                    cx,
                    PacketNumberSpace::ApplicationData,
                    max_frame_bytes,
                )?
            };
            if frames.is_empty() {
                break;
            }
            let mut packet_stream_frames = Vec::new();
            for frame in &frames {
                if let crate::net::atp::protocol::quic_frames::QuicFrame::Stream {
                    stream_id,
                    offset,
                    ..
                } = frame
                {
                    let stream_frame = SentControlStreamFrame {
                        stream: StreamId(stream_id.value()),
                        offset: offset.map_or(0, |offset| offset.value()),
                    };
                    flushed_stream_frames.push(stream_frame);
                    packet_stream_frames.push(stream_frame);
                }
            }
            let packet_datagram_frames = frames
                .iter()
                .filter(|frame| {
                    matches!(
                        frame,
                        crate::net::atp::protocol::quic_frames::QuicFrame::Datagram { .. }
                    )
                })
                .count();
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload)?;
            let packet_len = ONE_RTT_HEADER_LEN
                .saturating_add(payload.len())
                .saturating_add(ONE_RTT_TAG_LEN);
            let packet_number = if self.role == StreamRole::Client {
                self.clock = self.clock.saturating_add(CLOCK_STEP_MICROS);
                let ack_eliciting = frames.iter().any(frame_is_ack_eliciting_for_recovery);
                let uses_paced_recovery =
                    packet_uses_paced_recovery(&frames, self.paced_source_stream);
                let tracks_quic_recovery =
                    packet_tracks_recovery_in_flight(&frames, self.paced_source_stream);
                let accounting_bytes = if uses_paced_recovery {
                    data_plane_packet_accounting_bytes(packet_len)
                } else {
                    u64::try_from(packet_len).unwrap_or(u64::MAX).max(1)
                };
                let packet_number = if uses_paced_recovery {
                    self.conn.on_packet_sent(
                        cx,
                        PacketNumberSpace::ApplicationData,
                        accounting_bytes,
                        ack_eliciting,
                        false,
                        self.clock,
                    )?
                } else {
                    self.conn.on_packet_sent(
                        cx,
                        PacketNumberSpace::ApplicationData,
                        accounting_bytes,
                        ack_eliciting,
                        tracks_quic_recovery,
                        self.clock,
                    )?
                };
                self.send_pn = self.send_pn.max(packet_number.saturating_add(1));
                packet_number
            } else {
                let packet_number = self.send_pn;
                self.send_pn = self.send_pn.saturating_add(1);
                packet_number
            };
            datagram_frames = datagram_frames.saturating_add(packet_datagram_frames);
            max_datagram_frames_per_plain_packet =
                max_datagram_frames_per_plain_packet.max(packet_datagram_frames);
            plaintext_payload_bytes = plaintext_payload_bytes.saturating_add(payload.len());
            let header = encode_one_rtt_header(packet_number);
            plain_packets.push(PlainOneRttPacket {
                packet_number,
                header,
                payload,
                stream_frames: packet_stream_frames,
            });
        }
        let generate_elapsed = generate_started.elapsed();
        let count = plain_packets.len();
        if !plain_packets.is_empty() {
            let protect_started = Instant::now();
            let requests = plain_packets
                .iter()
                .map(|packet| PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: packet.packet_number,
                    associated_data: packet.header.as_slice(),
                    payload: packet.payload.as_ref(),
                })
                .collect::<Vec<_>>();
            let protected_packets =
                protection_result(self.protection.protect_packets(cx, &requests))?;
            let protect_elapsed = protect_started.elapsed();
            let mut packets = Vec::with_capacity(protected_packets.len());
            for (plain, protected) in plain_packets.iter().zip(protected_packets) {
                debug_assert_eq!(protected.packet_number, plain.packet_number);
                let mut data = Vec::with_capacity(
                    ONE_RTT_HEADER_LEN + protected.ciphertext.len() + ONE_RTT_TAG_LEN,
                );
                data.extend_from_slice(&plain.header);
                data.extend_from_slice(&protected.ciphertext);
                data.extend_from_slice(&protected.tag);
                if data.len() > ATP_QUIC_UDP_MAX_PACKET {
                    return Err(QuicTransportError::Quic(format!(
                        "protected 1-RTT packet too large: {} bytes > {} limit",
                        data.len(),
                        ATP_QUIC_UDP_MAX_PACKET
                    )));
                }
                packets.push(OutgoingPacket {
                    dst_addr: self.peer,
                    data,
                    send_time: None,
                });
            }
            let send_strategy = quic_gso_send_strategy(&packets);
            let udp_send_started = Instant::now();
            let report = self
                .endpoint
                .send_batch_with_strategy(cx, &packets, send_strategy)
                .await
                .map_err(map_udp_error)?;
            let udp_send_elapsed = udp_send_started.elapsed();
            if let Some(error) = report.error {
                return Err(QuicTransportError::Quic(format!(
                    "udp endpoint sent {} of {} QUIC packets before error: {error}",
                    report.packets_processed, count
                )));
            }
            if report.packets_processed != count {
                return Err(QuicTransportError::Quic(format!(
                    "udp endpoint sent {} of {} QUIC packets without reporting an error",
                    report.packets_processed, count
                )));
            }
            for plain in &plain_packets {
                if !plain.stream_frames.is_empty() {
                    self.in_flight_stream_frames
                        .insert(plain.packet_number, plain.stream_frames.clone());
                }
            }
            trace_quic_flush_coalescing(
                cx,
                count,
                datagram_frames,
                max_datagram_frames_per_plain_packet,
                self.max_symbol_frames_per_packet,
                plaintext_payload_bytes,
                report.bytes_processed,
                report.native_send_batch_used,
                report.gso_send_used,
                report.fallback_used,
            );
            self.sender_handoff.record_flush(
                count,
                datagram_frames,
                pending_before_flush,
                max_datagram_frames_per_plain_packet,
                generate_elapsed,
                protect_elapsed,
                udp_send_elapsed,
            );
        }
        self.last_flushed_stream_frames = flushed_stream_frames;
        Ok(count)
    }

    fn last_flushed_stream_frames(&self) -> Vec<SentControlStreamFrame> {
        self.last_flushed_stream_frames.clone()
    }

    fn record_received_source_stream_frames(&mut self, frames: &[QuicFrame]) {
        let Some(source_stream) = self.paced_source_stream else {
            return;
        };

        for frame in frames {
            let QuicFrame::Stream {
                stream_id,
                offset,
                data,
                fin,
            } = frame
            else {
                continue;
            };
            if stream_id.value() != source_stream.0 || (data.is_empty() && !*fin) {
                continue;
            }
            self.received_source_stream_frames
                .push_back(ReceivedSourceStreamFrame {
                    offset: offset.map_or(0, |offset| offset.value()),
                    data: data.clone(),
                    fin: *fin,
                });
        }
    }

    fn drain_received_source_stream_frames(&mut self) -> Vec<ReceivedSourceStreamFrame> {
        self.received_source_stream_frames.drain(..).collect()
    }

    fn apply_source_stream_ack_ranges(
        &mut self,
        cx: &Cx,
        acked_ranges: &[NativeAckRange],
    ) -> Result<(usize, usize), QuicTransportError> {
        let _ = cx;
        if acked_ranges.is_empty() || self.in_flight_stream_frames.is_empty() {
            return Ok((0, 0));
        }
        self.latest_stream_ack_ranges = acked_ranges.to_vec();
        let before = self.in_flight_stream_frames.len();
        self.in_flight_stream_frames
            .retain(|packet_number, _frames| !packet_in_ack_ranges(*packet_number, acked_ranges));
        let removed = before.saturating_sub(self.in_flight_stream_frames.len());
        Ok((removed, 0))
    }

    fn drain_ack_gap_lost_stream_frames_for_retransmit(
        &mut self,
        acked_ranges: &[NativeAckRange],
    ) -> Vec<SentControlStreamFrame> {
        if acked_ranges.is_empty() || self.in_flight_stream_frames.is_empty() {
            return Vec::new();
        }

        let mut retained = BTreeMap::new();
        let mut lost = Vec::new();
        let mut lost_packets = 0usize;
        for (packet_number, frames) in std::mem::take(&mut self.in_flight_stream_frames) {
            if lost_packets < QUIC_SOURCE_STREAM_FAST_RETRANSMIT_MAX_PACKETS
                && packet_lost_by_ack_gap(packet_number, acked_ranges)
            {
                lost_packets = lost_packets.saturating_add(1);
                lost.extend(frames);
            } else {
                retained.insert(packet_number, frames);
            }
        }
        self.in_flight_stream_frames = retained;
        dedup_stream_frames_for_retransmit(lost)
    }

    fn drain_in_flight_stream_frames_for_retransmit(&mut self) -> Vec<SentControlStreamFrame> {
        if self.in_flight_stream_frames.is_empty() {
            return Vec::new();
        }
        let frames = std::mem::take(&mut self.in_flight_stream_frames)
            .into_values()
            .flatten()
            .collect::<Vec<_>>();
        dedup_stream_frames_for_retransmit(frames)
    }

    fn pending_fountain_feedback_count(&self) -> usize {
        queued_fountain_feedback_count(&self.pending_control_frames)
    }

    fn has_pending_fountain_feedback(&self) -> bool {
        self.pending_fountain_feedback_count() > 0
    }

    async fn retransmit_stream_frames(
        &mut self,
        cx: &Cx,
        frames: &[SentControlStreamFrame],
        reason: &'static str,
    ) -> Result<usize, QuicTransportError> {
        if frames.is_empty() {
            return Ok(0);
        }
        for frame in frames {
            self.conn
                .requeue_sent_stream_frame(cx, frame.stream, frame.offset)?;
        }
        let retransmitted = self.flush(cx).await?;
        let frames_s = frames.len().to_string();
        let packets_s = retransmitted.to_string();
        cx.trace_with_fields(
            "atp_quic.control_stream.retransmit",
            &[
                ("reason", reason),
                ("stream_frames", frames_s.as_str()),
                ("packets", packets_s.as_str()),
            ],
        );
        quic_rqtrace!(
            "sender: stream_retransmit reason={} stream_frames={} packets={}",
            reason,
            frames.len(),
            retransmitted
        );
        Ok(retransmitted)
    }

    fn process_unprotected_one_rtt_packet(
        &mut self,
        cx: &Cx,
        packet_number: u64,
        plaintext: &[u8],
    ) -> Result<bool, QuicTransportError> {
        let required_datagram_slots = self.max_datagram_frames_per_packet.max(1);
        let available_datagram_slots = self.conn.inbound_datagram_remaining_capacity();
        if available_datagram_slots < required_datagram_slots {
            let packet_number_text = packet_number.to_string();
            let required_text = required_datagram_slots.to_string();
            let available_text = available_datagram_slots.to_string();
            let pending_datagrams_text = self.conn.pending_datagram_count().to_string();
            let pending_received_packets_text = self.pending_received_packets.len().to_string();
            cx.trace_with_fields(
                "atp_quic.receive.datagram_queue_backpressure",
                &[
                    ("reason", "insufficient_slots_for_packet"),
                    ("packet_number", packet_number_text.as_str()),
                    ("required_datagram_slots", required_text.as_str()),
                    ("available_datagram_slots", available_text.as_str()),
                    ("pending_datagrams", pending_datagrams_text.as_str()),
                    (
                        "pending_received_packets",
                        pending_received_packets_text.as_str(),
                    ),
                ],
            );
            self.mark_peer_activity();
            return Ok(false);
        }
        let decoded_frames = NativeQuicConnection::decode_frames(plaintext)?;
        let acked_stream_ranges = acked_packet_ranges_from_frames(&decoded_frames)?;
        self.clock = self.clock.saturating_add(CLOCK_STEP_MICROS);
        match self.conn.process_packet_payload(
            cx,
            PacketNumberSpace::ApplicationData,
            packet_number,
            plaintext,
            self.clock,
        ) {
            Ok(()) => {
                self.apply_source_stream_ack_ranges(cx, &acked_stream_ranges)?;
                self.record_received_source_stream_frames(&decoded_frames);
                self.one_rtt_packets_ingested = self.one_rtt_packets_ingested.saturating_add(1);
                self.mark_peer_activity();
                Ok(true)
            }
            Err(NativeQuicConnectionError::DatagramReceiveQueueFull { capacity }) => {
                let packet_number_text = packet_number.to_string();
                let capacity_text = capacity.to_string();
                let pending_datagrams_text = self.conn.pending_datagram_count().to_string();
                let pending_received_packets_text = self.pending_received_packets.len().to_string();
                let datagrams_received_text = self.conn.datagrams_received().to_string();
                let datagrams_dropped_on_receive_text =
                    self.conn.datagrams_dropped_on_receive().to_string();
                cx.trace_with_fields(
                    "atp_quic.receive.datagram_queue_backpressure",
                    &[
                        ("packet_number", packet_number_text.as_str()),
                        ("capacity", capacity_text.as_str()),
                        ("pending_datagrams", pending_datagrams_text.as_str()),
                        (
                            "pending_received_packets",
                            pending_received_packets_text.as_str(),
                        ),
                        ("datagrams_received", datagrams_received_text.as_str()),
                        (
                            "datagrams_dropped_on_receive",
                            datagrams_dropped_on_receive_text.as_str(),
                        ),
                    ],
                );
                self.mark_peer_activity();
                Ok(false)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Feed a batch of already-received packets (e.g. 1-RTT data that arrived at
    /// the server while it was still completing the handshake) into the connection.
    async fn ingest_packets(
        &mut self,
        cx: &Cx,
        packets: &[ReceivedPacket],
    ) -> Result<IngestPacketsReport, QuicTransportError> {
        let provider_kind = self.protection.provider_kind();
        let decoded = packets
            .iter()
            .map(|packet| {
                decode_protected_one_rtt_packet(provider_kind, packet).map_or(
                    DecodedInboundPacket::NonOneRtt,
                    DecodedInboundPacket::OneRtt,
                )
            })
            .collect::<Vec<_>>();

        let requests = decoded
            .iter()
            .filter_map(|packet| match packet {
                DecodedInboundPacket::OneRtt(packet) => Some(PacketUnprotectionRequest {
                    packet: &packet.protected,
                    associated_data: &packet.header,
                }),
                DecodedInboundPacket::NonOneRtt => None,
            })
            .collect::<Vec<_>>();
        let unprotected = self
            .protection
            .unprotect_packets_parallel(cx, &requests)
            .await;

        let mut report = IngestPacketsReport::default();
        let mut unprotected = unprotected.into_iter();
        for (packet_index, packet) in decoded.iter().enumerate() {
            match packet {
                DecodedInboundPacket::OneRtt(packet) => match unprotected
                    .next()
                    .expect("one unprotect outcome per decoded 1-RTT packet")
                {
                    Outcome::Ok(unprotected) => {
                        if self.process_unprotected_one_rtt_packet(
                            cx,
                            packet.packet_number,
                            &unprotected.plaintext,
                        )? {
                            report.packets_consumed = packet_index.saturating_add(1);
                            report.one_rtt_packets_processed =
                                report.one_rtt_packets_processed.saturating_add(1);
                        } else {
                            report.receive_backpressure = true;
                            break;
                        }
                    }
                    // Undecryptable / replayed / stray packet: drop it (QUIC semantics).
                    Outcome::Err(_) | Outcome::Cancelled(_) | Outcome::Panicked(_) => {
                        self.unprotect_packets_dropped =
                            self.unprotect_packets_dropped.saturating_add(1);
                        report.packets_consumed = packet_index.saturating_add(1);
                    }
                },
                DecodedInboundPacket::NonOneRtt => {
                    self.non_one_rtt_packets_dropped =
                        self.non_one_rtt_packets_dropped.saturating_add(1);
                    report.packets_consumed = packet_index.saturating_add(1);
                }
            }
        }
        Ok(report)
    }

    async fn ingest_pending_received_packets(
        &mut self,
        cx: &Cx,
        limit: usize,
    ) -> Result<IngestPacketsReport, QuicTransportError> {
        let packets = self.take_pending_received_packets(limit);
        let report = self.ingest_packets(cx, &packets).await?;
        if report.receive_backpressure {
            self.push_front_received_packets(&packets[report.packets_consumed..]);
        }
        Ok(report)
    }

    fn trace_datagram_queue_needs_drain(&self, cx: &Cx, packets_processed: usize) {
        let pending_datagrams = self.conn.pending_datagram_count();
        let datagram_capacity = self.conn.inbound_datagram_capacity();
        let remaining_capacity = self.conn.inbound_datagram_remaining_capacity();
        let pending_datagrams_text = pending_datagrams.to_string();
        let datagram_capacity_text = datagram_capacity.to_string();
        let remaining_capacity_text = remaining_capacity.to_string();
        let packets_processed_text = packets_processed.to_string();
        let max_datagrams_per_packet_text = self.max_datagram_frames_per_packet.to_string();
        let pending_received_packets_text = self.pending_received_packets.len().to_string();
        cx.trace_with_fields(
            "atp_quic.receive.datagram_queue_needs_drain",
            &[
                ("pending_datagrams", pending_datagrams_text.as_str()),
                ("reorder_occupancy", pending_datagrams_text.as_str()),
                ("inbound_datagram_capacity", datagram_capacity_text.as_str()),
                (
                    "inbound_datagram_available",
                    remaining_capacity_text.as_str(),
                ),
                ("packets_processed", packets_processed_text.as_str()),
                (
                    "max_datagrams_per_packet",
                    max_datagrams_per_packet_text.as_str(),
                ),
                (
                    "pending_received_packets",
                    pending_received_packets_text.as_str(),
                ),
            ],
        );
    }

    /// Receive one batch of UDP packets, unprotect each, and feed the recovered
    /// 1-RTT frames into the connection. Waits at most `idle_timeout` for the
    /// first packet, then keeps draining short-quiet full batches until the
    /// socket appears empty or the per-turn drain budget is reached. Returns the
    /// number of packets successfully processed (undecryptable / non-1-RTT
    /// packets are silently dropped, per QUIC).
    async fn pump_inbound_for(
        &mut self,
        cx: &Cx,
        timeout: Duration,
    ) -> Result<usize, QuicTransportError> {
        self.pump_inbound_for_with_drain_budget(cx, timeout, INBOUND_PUMP_MAX_DRAIN_BATCHES)
            .await
    }

    async fn pump_inbound_for_with_drain_budget(
        &mut self,
        cx: &Cx,
        timeout: Duration,
        max_drain_batches: usize,
    ) -> Result<usize, QuicTransportError> {
        let mut total_processed = 0usize;
        let mut batches = 0usize;
        let mut next_timeout = timeout;
        let max_drain_batches = max_drain_batches.max(1);

        loop {
            let receive_limit = self.inbound_receive_packet_limit();
            if receive_limit == 0 {
                self.trace_datagram_queue_needs_drain(cx, total_processed);
                return Ok(total_processed);
            }
            if !self.pending_received_packets.is_empty() {
                let report = self
                    .ingest_pending_received_packets(cx, receive_limit)
                    .await?;
                total_processed = total_processed.saturating_add(report.one_rtt_packets_processed);
                if report.receive_backpressure {
                    self.trace_datagram_queue_needs_drain(cx, total_processed);
                    return Ok(total_processed);
                }
                continue;
            }
            let received = match crate::time::timeout(
                cx.now(),
                next_timeout,
                self.endpoint.receive_batch(cx, receive_limit),
            )
            .await
            {
                Ok(Ok(packets)) => packets,
                Ok(Err(err)) => return Err(map_udp_error(err)),
                Err(_elapsed) => return Ok(total_processed),
            };
            let received_len = received.len();
            if received_len == 0 {
                return Ok(total_processed);
            }
            self.udp_packets_received = self
                .udp_packets_received
                .saturating_add(u64::try_from(received_len).unwrap_or(u64::MAX));
            let report = self.ingest_packets(cx, &received).await?;
            total_processed = total_processed.saturating_add(report.one_rtt_packets_processed);
            if report.receive_backpressure {
                self.queue_received_packets(received.into_iter().skip(report.packets_consumed));
                self.trace_datagram_queue_needs_drain(cx, total_processed);
                return Ok(total_processed);
            }

            batches = batches.saturating_add(1);
            if received_len < receive_limit {
                return Ok(total_processed);
            }
            if batches >= max_drain_batches {
                let batches_s = batches.to_string();
                let max_batches_s = max_drain_batches.to_string();
                let total_processed_s = total_processed.to_string();
                cx.trace_with_fields(
                    "atp_quic.inbound_pump.drain_budget_exhausted",
                    &[
                        ("batches", batches_s.as_str()),
                        ("max_batches", max_batches_s.as_str()),
                        ("packets_processed", total_processed_s.as_str()),
                    ],
                );
                return Ok(total_processed);
            }
            next_timeout = INBOUND_PUMP_DRAIN_GRACE;
        }
    }

    async fn pump_inbound(&mut self, cx: &Cx) -> Result<usize, QuicTransportError> {
        self.pump_inbound_for(cx, self.idle_timeout).await
    }

    fn symbol_round_timeout(&self, timeout: Duration, symbols_accepted: u64) -> QuicTransportError {
        let socket = NativeUdpReceiveDiagnostics::capture(&self.endpoint);
        QuicTransportError::Quic(format!(
            "transport timeout during receive symbol round after {timeout:?}; \
             udp_packets_received={} one_rtt_packets_ingested={} \
             non_one_rtt_packets_dropped={} unprotect_packets_dropped={} \
             datagrams_received={} datagrams_dropped_on_receive={} \
             pending_datagrams={} pending_received_packets={} \
             udp_recv_buffer_requested={} udp_recv_buffer_applied={} \
             udp_kernel_rx_queue_bytes={} udp_kernel_drops={} \
             symbols_accepted={symbols_accepted}",
            self.udp_packets_received,
            self.one_rtt_packets_ingested,
            self.non_one_rtt_packets_dropped,
            self.unprotect_packets_dropped,
            self.conn.datagrams_received(),
            self.conn.datagrams_dropped_on_receive(),
            self.conn.pending_datagram_count(),
            self.pending_received_packets.len(),
            option_usize_trace(socket.recv_buffer_requested),
            option_usize_trace(socket.recv_buffer_applied),
            option_u64_trace(socket.kernel_rx_queue_bytes),
            option_u64_trace(socket.kernel_drops),
        ))
    }

    fn spray_pacing_decision(
        &self,
        config: &QuicConfig,
        aimd_cap_bps: Option<u64>,
        shared_decision: Option<DatagramRateDecision>,
        observed_loss: f64,
    ) -> QuicSprayPacingDecision {
        let mut config = config.clone();
        if let Some(cap) = aimd_cap_bps {
            config.bwlimit_bps = Some(config.bwlimit_bps.map_or(cap, |existing| existing.min(cap)));
        }
        let path = native_quic_path_signal_with_observed_loss(self.conn.transport(), observed_loss);
        let mut pacing = super::quic_spray_pacing_decision_from_config(&config, path);
        NativeQuicAimdPacer::apply_shared_decision_to_pacing(
            shared_decision,
            &mut pacing,
            self.symbol_datagram_frame_len,
            &config,
        );
        pacing
    }

    fn source_stream_pacing_decision(&self, config: &QuicConfig) -> QuicSprayPacingDecision {
        let mut pacing = self.spray_pacing_decision(config, None, None, config.round0_loss_target);
        promote_source_stream_pacing(&mut pacing, config, self.symbol_datagram_frame_len);
        pacing
    }

    fn spray_handoff_symbol_limit(&self, pacing: &QuicSprayPacingDecision) -> usize {
        spray_handoff_symbol_limit_for(
            self.paced_flush_symbol_limit(pacing),
            self.conn.pending_outbound_datagram_count(),
            pacing.path_loss_rate,
        )
    }

    async fn flush_symbol_queue_until_below_limit(
        &mut self,
        cx: &Cx,
        control: &mut NativeQuicFrameTransport,
        flush_symbols: usize,
        _pacing: &QuicSprayPacingDecision,
        flushes: &mut usize,
        flushed_packets: &mut usize,
        flush_elapsed: &mut Duration,
        liveness_elapsed: &mut Duration,
        _pause_elapsed: &mut Duration,
    ) -> Result<(), QuicTransportError> {
        while self.conn.pending_outbound_datagram_count() >= flush_symbols {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            let flush_start = Instant::now();
            let packets_flushed = self.flush(cx).await?;
            *flushed_packets = (*flushed_packets).saturating_add(packets_flushed);
            *flush_elapsed = (*flush_elapsed).saturating_add(flush_start.elapsed());
            *flushes = (*flushes).saturating_add(1);

            let liveness_start = Instant::now();
            self.service_spray_liveness(cx, control).await?;
            let liveness_poll_elapsed = liveness_start.elapsed();
            *liveness_elapsed = (*liveness_elapsed).saturating_add(liveness_poll_elapsed);
            self.sender_handoff
                .record_queue_full_flush(liveness_poll_elapsed);
            if self.has_pending_fountain_feedback() {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Spray a bounded symbol batch, flushing first whenever the paced outbound
    /// queue is full. MATRIX-112 showed the encrypted clean path parked mostly
    /// in futex/scheduler handoffs; this gives the RQ producer one batched
    /// handoff into the QUIC sender pump per flush window and traces the seam.
    async fn spray_symbol_batch(
        &mut self,
        cx: &Cx,
        control: &mut NativeQuicFrameTransport,
        tag: u64,
        symbols: &[NativeQuicSpraySymbol],
        pacing: &QuicSprayPacingDecision,
        shared_decision: Option<DatagramRateDecision>,
    ) -> Result<(), QuicTransportError> {
        if symbols.is_empty() {
            return Ok(());
        }

        let trace_start = Instant::now();
        self.update_spray_packet_coalescing(pacing);
        self.data_plane_pacer
            .configure_with_shared_decision(pacing, shared_decision);
        let flush_symbols = self.paced_flush_symbol_limit(pacing);
        let mut flushes = 0usize;
        let mut flushed_packets = 0usize;
        let mut flush_elapsed = Duration::ZERO;
        let mut liveness_elapsed = Duration::ZERO;
        let mut pause_elapsed = Duration::ZERO;
        let mut max_pending_before = self.conn.pending_outbound_datagram_count();

        if max_pending_before >= flush_symbols {
            self.flush_symbol_queue_until_below_limit(
                cx,
                control,
                flush_symbols,
                pacing,
                &mut flushes,
                &mut flushed_packets,
                &mut flush_elapsed,
                &mut liveness_elapsed,
                &mut pause_elapsed,
            )
            .await?;
        }

        let mut encoded_bytes = 0usize;
        let mut payloads = Vec::with_capacity(symbols.len());
        for item in symbols {
            let pending_datagrams = self
                .conn
                .pending_outbound_datagram_count()
                .saturating_add(payloads.len());
            let bytes_in_flight = self.conn.transport().bytes_in_flight();
            let congestion_window = self.conn.transport().congestion_window_bytes();
            self.data_plane_pacer
                .before_send(cx, pending_datagrams, bytes_in_flight, congestion_window)
                .await?;
            let payload =
                super::native_symbol_datagram(&item.symbol, tag, item.entry, item.auth_tag)?;
            encoded_bytes = encoded_bytes.saturating_add(payload.len());
            payloads.push(payload);
        }

        let pending_before_enqueue = self.conn.pending_outbound_datagram_count();
        max_pending_before = max_pending_before.max(pending_before_enqueue);
        let enqueue_start = Instant::now();
        let queued = super::send_native_symbol_batch(cx, &mut self.conn, payloads)?;
        if queued != symbols.len() {
            return Err(QuicTransportError::Quic(format!(
                "native QUIC symbol batch queued {queued} of {} payloads",
                symbols.len()
            )));
        }
        let pending_after_enqueue = self.conn.pending_outbound_datagram_count();
        self.sender_handoff.record_enqueue(
            queued,
            pending_before_enqueue,
            pending_after_enqueue,
            enqueue_start.elapsed(),
        );

        if pending_after_enqueue >= flush_symbols {
            self.flush_symbol_queue_until_below_limit(
                cx,
                control,
                flush_symbols,
                pacing,
                &mut flushes,
                &mut flushed_packets,
                &mut flush_elapsed,
                &mut liveness_elapsed,
                &mut pause_elapsed,
            )
            .await?;
        }

        trace_quic_symbol_handoff(
            cx,
            queued,
            encoded_bytes,
            pending_before_enqueue,
            pending_after_enqueue,
            flush_symbols,
            flushed_packets,
            pacing.pacing_rate_bps,
        );
        if std::env::var_os("ATP_RQ_TRACE").is_some() {
            let symbols_s = symbols.len().to_string();
            let flushes_s = flushes.to_string();
            let flushed_packets_s = flushed_packets.to_string();
            let flush_limit_s = flush_symbols.to_string();
            let max_pending_before_s = max_pending_before.to_string();
            let pending_after_s = self.conn.pending_outbound_datagram_count().to_string();
            let elapsed_micros_s = trace_start.elapsed().as_micros().to_string();
            let flush_micros_s = flush_elapsed.as_micros().to_string();
            let liveness_micros_s = liveness_elapsed.as_micros().to_string();
            let pause_micros_s = pause_elapsed.as_micros().to_string();
            cx.trace_with_fields(
                "atp_quic.sender.symbol_handoff_batch",
                &[
                    ("symbols", symbols_s.as_str()),
                    ("flushes", flushes_s.as_str()),
                    ("flushed_packets", flushed_packets_s.as_str()),
                    ("flush_symbol_limit", flush_limit_s.as_str()),
                    ("max_pending_before", max_pending_before_s.as_str()),
                    ("pending_after", pending_after_s.as_str()),
                    ("elapsed_micros", elapsed_micros_s.as_str()),
                    ("flush_micros", flush_micros_s.as_str()),
                    ("liveness_micros", liveness_micros_s.as_str()),
                    ("pause_micros", pause_micros_s.as_str()),
                ],
            );
            quic_rqtrace!(
                "sender-native: symbol_handoff_batch symbols={} flushes={} flushed_packets={} flush_symbol_limit={} max_pending_before={} pending_after={} elapsed_us={} flush_us={} liveness_us={} pause_us={}",
                symbols.len(),
                flushes,
                flushed_packets,
                flush_symbols,
                max_pending_before,
                self.conn.pending_outbound_datagram_count(),
                trace_start.elapsed().as_micros(),
                flush_elapsed.as_micros(),
                liveness_elapsed.as_micros(),
                pause_elapsed.as_micros(),
            );
        }
        Ok(())
    }

    async fn finish_paced_spray_round(
        &mut self,
        cx: &Cx,
        control: &mut NativeQuicFrameTransport,
        sent: u64,
        pacing: &QuicSprayPacingDecision,
    ) -> Result<(), QuicTransportError> {
        if sent == 0 {
            return Ok(());
        }

        let pending_symbols = self.conn.pending_outbound_datagram_count();
        self.flush_until_outbound_datagrams_drained(
            cx,
            control,
            "drain cwnd-gated spray before ObjectComplete",
        )
        .await?;

        let flush_symbol_limit = self.paced_flush_symbol_limit(pacing);
        let sent_s = sent.to_string();
        let pending_symbols_s = pending_symbols.to_string();
        let flush_symbol_limit_s = flush_symbol_limit.to_string();
        let max_symbol_frames_per_packet_s = self.max_symbol_frames_per_packet.to_string();
        let pause_after_burst_micros = Duration::ZERO.as_micros().to_string();
        let pacing_rate_bps = pacing.pacing_rate_bps.to_string();
        cx.trace_with_fields(
            "atp_quic.sender.final_paced_spray_flush",
            &[
                ("symbols", sent_s.as_str()),
                (
                    "pause_after_burst_micros",
                    pause_after_burst_micros.as_str(),
                ),
                ("pacing_rate_bps", pacing_rate_bps.as_str()),
                ("pending_symbols", pending_symbols_s.as_str()),
                ("flush_symbol_limit", flush_symbol_limit_s.as_str()),
                (
                    "max_symbol_frames_per_packet",
                    max_symbol_frames_per_packet_s.as_str(),
                ),
            ],
        );
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)
    }

    /// Pump inbound until a complete ATP control frame is available on `control`,
    /// flushing pending outbound (e.g. ACKs) between attempts. A full idle
    /// timeout of silence fails closed.
    async fn next_control_frame(
        &mut self,
        cx: &Cx,
        control: &mut NativeQuicFrameTransport,
        operation: &'static str,
    ) -> Result<Frame, QuicTransportError> {
        loop {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            if let Some(frame) = self.pending_control_frames.pop_front() {
                return Ok(frame);
            }
            if let Some(frame) = control.try_recv(cx, &mut self.conn)? {
                return Ok(frame);
            }
            self.flush(cx).await?;
            // `pump_inbound` waits up to a full idle window for the first packet;
            // it only returns 0 when that window elapsed with no traffic at all,
            // which means the peer has gone silent — fail closed. Any packets
            // (>0) loop back to re-check for a now-complete control frame.
            if self.pump_inbound(cx).await? == 0 {
                return Err(QuicTransportError::Timeout {
                    operation,
                    timeout: self.idle_timeout,
                });
            }
        }
    }

    async fn next_control_frame_with_stream_pto(
        &mut self,
        cx: &Cx,
        control: &mut NativeQuicFrameTransport,
        operation: &'static str,
        frames: &[SentControlStreamFrame],
        reason: &'static str,
    ) -> Result<Frame, QuicTransportError> {
        if frames.is_empty() && self.in_flight_stream_frames.is_empty() {
            return self.next_control_frame(cx, control, operation).await;
        }

        let max_attempts = needmore_pto_attempt_budget(self.idle_timeout);
        let pto = if reason == "source_stream_completion_pto" {
            SOURCE_STREAM_PTO
        } else {
            NEEDMORE_PTO
        };
        let mut attempts = 0u32;
        let mut last_retransmit = Instant::now();
        loop {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            if let Some(frame) = self.pending_control_frames.pop_front() {
                return Ok(frame);
            }
            if let Some(frame) = control.try_recv(cx, &mut self.conn)? {
                return Ok(frame);
            }
            self.flush(cx).await?;
            let pumped = self.pump_inbound_for(cx, pto).await?;
            if pumped > 0 && reason == "source_stream_completion_pto" {
                let latest_stream_ack_ranges = self.latest_stream_ack_ranges.clone();
                let retransmit_frames =
                    self.drain_ack_gap_lost_stream_frames_for_retransmit(&latest_stream_ack_ranges);
                if !retransmit_frames.is_empty() {
                    self.retransmit_stream_frames(
                        cx,
                        &retransmit_frames,
                        "source_stream_ack_gap_retransmit",
                    )
                    .await?;
                    last_retransmit = Instant::now();
                }
                continue;
            }
            if pumped > 0 && last_retransmit.elapsed() < pto {
                continue;
            }

            attempts = attempts.saturating_add(1);
            if attempts > max_attempts {
                return Err(QuicTransportError::Timeout {
                    operation,
                    timeout: self.idle_timeout,
                });
            }
            let latest_stream_ack_ranges = self.latest_stream_ack_ranges.clone();
            let mut retransmit_frames = if reason == "source_stream_completion_pto" {
                self.drain_ack_gap_lost_stream_frames_for_retransmit(&latest_stream_ack_ranges)
            } else {
                self.drain_in_flight_stream_frames_for_retransmit()
            };
            if retransmit_frames.is_empty() {
                retransmit_frames = if reason == "source_stream_completion_pto" {
                    tail_stream_frames_for_retransmit(
                        frames,
                        QUIC_SOURCE_STREAM_COMPLETION_PTO_MAX_FRAMES,
                    )
                } else {
                    frames.to_vec()
                };
            }
            self.retransmit_stream_frames(cx, &retransmit_frames, reason)
                .await?;
            last_retransmit = Instant::now();
        }
    }
}

/// Bind a `QuicUdpEndpoint` on `local`, tuned for the ATP-over-QUIC handshake.
async fn bind_endpoint(cx: &Cx, local: SocketAddr) -> Result<QuicUdpEndpoint, QuicTransportError> {
    let udp_config = QuicUdpEndpointConfig {
        max_packet_size: ATP_QUIC_UDP_MAX_PACKET,
        socket_recv_buffer_size: Some(ATP_QUIC_UDP_SOCKET_BUFFER),
        socket_send_buffer_size: Some(ATP_QUIC_UDP_SOCKET_BUFFER),
        // The endpoint batch ceiling governs how many packets a single
        // `receive_batch` may drain. It must be the *receiver* drain width, not
        // the sender's current paced spray burst: capping the receiver at a tiny
        // send threshold starves it on a real link where repairs may arrive in
        // bursts. `send_batch` only chunks by this value, so a larger ceiling is
        // strictly better for sends.
        max_batch_size: INBOUND_PUMP_BATCH,
        ..QuicUdpEndpointConfig::default()
    };
    QuicUdpEndpoint::bind(cx, local, udp_config)
        .await
        .map_err(map_udp_error)
}

/// Unspecified local bind address matching the family of `peer`.
fn unspecified_for(peer: SocketAddr) -> SocketAddr {
    match peer.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// Establish a [`QuicLink`] from a completed handshake driver and its endpoint.
fn link_from_handshake(
    cx: &Cx,
    driver: QuicHandshakeDriver,
    endpoint: QuicUdpEndpoint,
    peer: SocketAddr,
    role: StreamRole,
    config: &QuicConfig,
) -> Result<QuicLink, QuicTransportError> {
    if !driver.is_complete() || !driver.one_rtt_keys_installed() {
        return Err(QuicTransportError::Quic(
            "handshake completed without installed 1-RTT keys".to_string(),
        ));
    }
    // Let one protected UDP packet carry many RFC 9221 DATAGRAM frames while
    // keeping each RaptorQ symbol in its own DATAGRAM frame. This preserves
    // per-symbol loss granularity, but avoids the MATRIX-39 one-symbol-per-UDP
    // packet ceiling that throttled encrypted transfers to packet-rate speed.
    // The no-evict receive queue and inbound pump remain the burst bounds.
    let max_app_payload = one_rtt_max_payload_for_udp_packet(ATP_QUIC_UDP_MAX_PACKET);
    let max_datagram_frame_size = config.max_datagram_size.min(max_app_payload);
    // Use the smallest ATP symbol envelope this link may legitimately carry so
    // the receive batch bound remains safe for both auth postures.
    let symbol_frame_len =
        symbol_datagram_frame_len(config.symbol_size, super::ENVELOPE_HEADER_LEN);
    let max_datagram_frames_per_packet =
        coalesced_datagram_frames_per_packet(max_app_payload, symbol_frame_len);
    let send_envelope_header_len = if config.symbol_auth_context.is_some() {
        super::AUTH_ENVELOPE_HEADER_LEN
    } else {
        super::ENVELOPE_HEADER_LEN
    };
    let send_symbol_frame_len =
        symbol_datagram_frame_len(config.symbol_size, send_envelope_header_len);
    let max_symbol_frames_per_packet =
        coalesced_datagram_frames_per_packet(max_app_payload, send_symbol_frame_len);
    let stream_flow_limit = super::quic_native_stream_flow_limit(config);
    let conn_config = NativeQuicConnectionConfig {
        role,
        max_datagram_frame_size,
        send_window: stream_flow_limit,
        recv_window: stream_flow_limit,
        connection_send_limit: stream_flow_limit,
        connection_recv_limit: stream_flow_limit,
        ..NativeQuicConnectionConfig::default()
    };
    let mut conn = NativeQuicConnection::new(conn_config);
    conn.begin_handshake(cx)?;
    conn.on_handshake_keys_available(cx)?;
    conn.on_1rtt_keys_available(cx)?;
    if role == StreamRole::Client {
        // The driver verified the server certificate via WebPKI during the real
        // handshake; record that so the client may confirm (fail-closed otherwise).
        conn.record_verified_server_identity();
    }
    conn.on_handshake_confirmed(cx)?;
    if !conn.can_send_1rtt() {
        return Err(QuicTransportError::Quic(
            "connection did not reach a 1-RTT-capable established state".to_string(),
        ));
    }

    let provider: RustlsQuicCryptoProvider = driver.into_provider();
    let protection =
        AtpPacketProtection::from_provider(Box::new(provider), QuicLink::protection_config());

    Ok(QuicLink {
        conn,
        endpoint,
        protection,
        peer,
        role,
        send_pn: 0,
        clock: 0,
        max_app_payload,
        max_datagram_frames_per_packet,
        max_symbol_frames_per_packet,
        spray_max_datagram_frames_per_packet: max_symbol_frames_per_packet,
        max_spray_symbols_per_flush: config.max_spray_symbols_per_flush.max(1),
        symbol_datagram_frame_len: send_symbol_frame_len,
        data_plane_pacer: NativeDataPlanePacer::new(
            send_symbol_frame_len,
            config.max_spray_symbols_per_flush.max(1),
            config
                .bwlimit_bps
                .unwrap_or(super::QUIC_DEFAULT_COLD_START_PACING_BYTES_PER_S as u64),
        ),
        pending_received_packets: VecDeque::new(),
        idle_timeout: config.idle_timeout,
        beacons: BeaconScheduler::new(1, Instant::now()),
        pending_control_frames: VecDeque::new(),
        last_flushed_stream_frames: Vec::new(),
        in_flight_stream_frames: BTreeMap::new(),
        latest_stream_ack_ranges: Vec::new(),
        received_source_stream_frames: VecDeque::new(),
        paced_source_stream: None,
        udp_packets_received: 0,
        one_rtt_packets_ingested: 0,
        non_one_rtt_packets_dropped: 0,
        unprotect_packets_dropped: 0,
        sender_handoff: QuicSenderHandoffStats::default(),
    })
}

/// Connect to `addr` as a QUIC client: bind an ephemeral UDP socket, run the real
/// TLS-1.3 handshake (verifying the server identity), and return an established
/// [`QuicLink`].
async fn connect(
    cx: &Cx,
    addr: SocketAddr,
    client_tls: &QuicClientTls,
    config: &QuicConfig,
) -> Result<QuicLink, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    let mut endpoint = bind_endpoint(cx, unspecified_for(addr)).await?;
    let mut driver = QuicHandshakeDriver::client(
        client_tls.config.clone(),
        client_tls.server_name.clone(),
        ATP_QUIC_ALPN.to_vec(),
    )
    .map_err(map_tls_error)?;
    let dcid = ConnectionId::new(ATP_QUIC_INITIAL_DCID)
        .map_err(|err| QuicTransportError::Quic(format!("initial dcid: {err}")))?;
    let scid = ConnectionId::new(ATP_QUIC_CLIENT_SCID)
        .map_err(|err| QuicTransportError::Quic(format!("client scid: {err}")))?;
    match crate::time::timeout(
        cx.now(),
        config.handshake_timeout,
        client_handshake_over_udp(cx, &mut endpoint, addr, &mut driver, dcid, scid),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(map_tls_error(err)),
        Err(_elapsed) => {
            return Err(QuicTransportError::Timeout {
                operation: "quic client handshake",
                timeout: config.handshake_timeout,
            });
        }
    }
    link_from_handshake(cx, driver, endpoint, addr, StreamRole::Client, config)
}

/// Bound on handshake flights before giving up (mirrors the driver's own bound).
const HANDSHAKE_MAX_FLIGHTS: usize = 64;

/// True if a received UDP packet is a QUIC long-header packet (handshake), vs a
/// short-header 1-RTT data-plane packet. The long-header form bit is `0x80`.
fn is_long_header(data: &[u8]) -> bool {
    data.first().is_some_and(|byte| byte & 0x80 != 0)
}

/// Pump the driver's pending outbound handshake bytes and send each as a
/// protected long-header packet to `peer`. OneRtt-level post-handshake segments
/// belong to the data plane and are skipped (the data plane carries its own).
async fn send_server_handshake_flight(
    cx: &Cx,
    endpoint: &mut QuicUdpEndpoint,
    driver: &mut QuicHandshakeDriver,
    peer: SocketAddr,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    packet_number: &mut u64,
) -> Result<(), QuicTransportError> {
    let segments = driver.pump_outbound().map_err(map_tls_error)?;
    let mut packets = Vec::new();
    for segment in segments {
        if segment.level == HandshakeLevel::OneRtt {
            continue;
        }
        let data = driver
            .assemble_handshake_packet(&segment, dst_cid, src_cid, *packet_number)
            .map_err(map_tls_error)?;
        *packet_number = packet_number.saturating_add(1);
        packets.push(OutgoingPacket {
            dst_addr: peer,
            data,
            send_time: None,
        });
    }
    if !packets.is_empty() {
        endpoint
            .send_batch(cx, &packets)
            .await
            .map_err(map_udp_error)?;
    }
    Ok(())
}

/// Accept one QUIC client on a bound server `endpoint`: run the real TLS-1.3
/// handshake (presenting the server certificate) and return an established
/// [`QuicLink`] plus any 1-RTT data-plane packets that arrived before the
/// handshake completed (the client finishes the handshake first and may start
/// the data plane immediately).
///
/// This drives the accept-side handshake directly (rather than the driver's
/// `server_handshake_over_udp` helper) so it can tolerate those early
/// short-header 1-RTT packets — stashing them for replay — instead of failing
/// closed the way a handshake-only loop must when it sees a non-long-header
/// packet.
async fn accept(
    cx: &Cx,
    mut endpoint: QuicUdpEndpoint,
    server_tls: &QuicServerTls,
    config: &QuicConfig,
) -> Result<(QuicLink, Vec<ReceivedPacket>), QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    let mut driver = QuicHandshakeDriver::server(server_tls.config.clone(), ATP_QUIC_ALPN.to_vec())
        .map_err(map_tls_error)?;
    // RFC 9001 §5.2: Initial keys derive from the client's original DCID. Both
    // peers agree on the protocol constant (see ATP_QUIC_INITIAL_DCID).
    driver
        .install_initial_keys(ATP_QUIC_INITIAL_DCID)
        .map_err(map_tls_error)?;
    let server_scid = ConnectionId::new(ATP_QUIC_SERVER_SCID)
        .map_err(|err| QuicTransportError::Quic(format!("server scid: {err}")))?;

    let mut server_pn = 0u64;
    let mut peer: Option<(SocketAddr, ConnectionId)> = None;
    let mut early_data: Vec<ReceivedPacket> = Vec::new();

    for _ in 0..HANDSHAKE_MAX_FLIGHTS {
        if driver.is_complete() {
            break;
        }
        let received = match crate::time::timeout(
            cx.now(),
            config.accept_timeout,
            endpoint.receive_batch(cx, INBOUND_PUMP_BATCH),
        )
        .await
        {
            Ok(Ok(packets)) => packets,
            Ok(Err(err)) => return Err(map_udp_error(err)),
            Err(_elapsed) => {
                return Err(QuicTransportError::Timeout {
                    operation: "quic server accept handshake",
                    timeout: config.accept_timeout,
                });
            }
        };
        for packet in received {
            if is_long_header(&packet.data) {
                let client_cid = driver
                    .recv_handshake_packet(&packet.data)
                    .map_err(map_tls_error)?;
                if peer.is_none() {
                    peer = Some((packet.src_addr, client_cid));
                }
                if let Some((addr, dst_cid)) = peer {
                    send_server_handshake_flight(
                        cx,
                        &mut endpoint,
                        &mut driver,
                        addr,
                        dst_cid,
                        server_scid,
                        &mut server_pn,
                    )
                    .await?;
                }
            } else {
                // The client completed the handshake first and is already sending
                // 1-RTT data. Stash it; it is replayed into the link below.
                early_data.push(packet);
            }
        }
    }

    if !driver.is_complete() {
        return Err(QuicTransportError::Timeout {
            operation: "quic server accept handshake",
            timeout: config.accept_timeout,
        });
    }
    let (peer_addr, _peer_cid) = peer
        .ok_or_else(|| QuicTransportError::Quic("server handshake learned no peer".to_string()))?;
    let link = link_from_handshake(cx, driver, endpoint, peer_addr, StreamRole::Server, config)?;
    Ok((link, early_data))
}

// ─── Sender session ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct NativeQuicAimdPacer {
    controller: DatagramRateController,
    controller_config: DatagramRateConfig,
    last_decision: Option<DatagramRateDecision>,
    shared_cap_active: bool,
    sample_clock_micros: u64,
    last_round_symbols_sent: u64,
    last_round_pacing_rate_bps: u64,
    last_round_send_wall: Duration,
    last_round_rtt: Option<Duration>,
    last_round_loss_fraction: f64,
    last_pending_rank: Option<u64>,
    last_pending_rank_deficit: Option<u64>,
}

impl Default for NativeQuicAimdPacer {
    fn default() -> Self {
        let controller_config = quic_datagram_rate_config(&QuicConfig::default());
        Self {
            controller: DatagramRateController::new(controller_config),
            controller_config,
            last_decision: None,
            shared_cap_active: false,
            sample_clock_micros: 0,
            last_round_symbols_sent: 0,
            last_round_pacing_rate_bps: 0,
            last_round_send_wall: Duration::ZERO,
            last_round_rtt: None,
            last_round_loss_fraction: 0.0,
            last_pending_rank: None,
            last_pending_rank_deficit: None,
        }
    }
}

impl NativeQuicAimdPacer {
    fn cap_bps(&self) -> Option<u64> {
        self.shared_cap_active
            .then(|| {
                self.last_decision
                    .map(|decision| decision.pacing_bytes_per_s)
            })
            .flatten()
    }

    /// Sender-observed delivery loss from the last completed round. Used to seed
    /// `pacing.path_loss_rate` (Bug A, MATRIX-126) so the round-0 clean-link ramp
    /// disables after a high delivery loss instead of re-arming and flooding.
    fn observed_loss(&self) -> f64 {
        self.last_round_loss_fraction
    }

    fn shared_decision(&self) -> Option<DatagramRateDecision> {
        self.last_decision
    }

    fn apply_shared_decision_to_pacing(
        shared_decision: Option<DatagramRateDecision>,
        pacing: &mut QuicSprayPacingDecision,
        symbol_frame_len: usize,
        config: &QuicConfig,
    ) {
        let Some(decision) = shared_decision else {
            return;
        };
        let symbol_bytes = u64::try_from(symbol_frame_len.max(1))
            .unwrap_or(u64::MAX)
            .max(1);
        let fanout = config.datagram_fanout.max(1);
        let shared_rate = decision.pacing_bytes_per_s.max(1);
        pacing.pacing_rate_bps = pacing.pacing_rate_bps.min(shared_rate).max(1);
        let inflight_symbols = usize::try_from(
            decision
                .inflight_limit_bytes
                .checked_div(symbol_bytes)
                .unwrap_or(0)
                .max(1),
        )
        .unwrap_or(usize::MAX);
        let budget_symbols = usize::try_from(
            decision
                .send_budget_bytes
                .checked_div(symbol_bytes)
                .unwrap_or(0)
                .max(1),
        )
        .unwrap_or(usize::MAX);
        pacing.cwnd_symbols = inflight_symbols;
        pacing.cwnd_share_symbols = (inflight_symbols / fanout).max(1);
        pacing.burst_cap_share_symbols = pacing.burst_cap_share_symbols.min(budget_symbols).max(1);
        pacing.max_burst_symbols = pacing.max_burst_symbols.min(budget_symbols).max(1);
        pacing.path_cwnd_bytes = decision.inflight_limit_bytes.max(symbol_bytes);
        let sender_loss = f64::from(decision.sender_loss_fraction_ppm) / 1_000_000.0;
        pacing.path_loss_rate = pacing.path_loss_rate.max(sender_loss);
        pacing.congestion_loss_rate = pacing.congestion_loss_rate.max(sender_loss);
        if sender_loss > 0.0 {
            pacing.limiter = super::QuicSprayPacingLimiter::LossBackoff;
        }
        super::update_quic_pacing_pause(
            pacing,
            symbol_frame_len,
            config.max_spray_symbols_per_flush,
        );
        pacing.max_burst_symbols = pacing.max_burst_symbols.min(budget_symbols).max(1);
    }

    fn sender_delivery_loss_for_repair(&self, receiver_loss: Option<f64>) -> Option<f64> {
        if self.last_round_symbols_sent == 0 || !self.last_round_loss_fraction.is_finite() {
            return None;
        }
        let receiver_loss = receiver_loss
            .filter(|loss| loss.is_finite())
            .unwrap_or(0.0)
            .clamp(0.0, 0.90);
        let sender_loss = self.last_round_loss_fraction.clamp(0.0, 0.90);
        (sender_loss > receiver_loss + f64::EPSILON).then_some(sender_loss)
    }

    fn record_spray(&mut self, symbols_sent: u64, pacing_rate_bps: u64, send_wall: Duration) {
        self.last_round_symbols_sent = symbols_sent;
        self.last_round_pacing_rate_bps = pacing_rate_bps;
        self.last_round_send_wall = send_wall;
        self.last_round_rtt = None;
    }

    fn record_spray_with_pacing(
        &mut self,
        symbols_sent: u64,
        pacing: &QuicSprayPacingDecision,
        send_wall: Duration,
    ) {
        self.record_spray(symbols_sent, pacing.pacing_rate_bps, send_wall);
        self.last_round_rtt = duration_from_secs(pacing.path_rtt_s);
    }

    fn lossy_repair_feedback_enabled(config: &QuicConfig) -> bool {
        super::quic_loss_target_pacing_cap_bps(config).is_some()
    }

    fn last_round_send_wall_s(&self) -> f64 {
        self.last_round_send_wall.as_secs_f64().max(0.000_001)
    }

    fn round_payload_bps(&self, symbols: u64, config: &QuicConfig) -> f64 {
        symbols.saturating_mul(u64::from(config.symbol_size.max(1))) as f64
            / self.last_round_send_wall_s()
    }

    fn receiver_delivery_bps(&self, need: &QuicNeedMore, config: &QuicConfig) -> Option<f64> {
        need.round_symbols_observed
            .or(need.round_symbols_accepted)
            .map(|observed| {
                self.round_payload_bps(observed.min(self.last_round_symbols_sent), config)
            })
    }

    fn progress_delivery_bps(&mut self, config: &QuicConfig, need: &QuicNeedMore) -> Option<f64> {
        if !Self::lossy_repair_feedback_enabled(config) {
            self.last_pending_rank = need.pending_rank;
            self.last_pending_rank_deficit = need.pending_rank_deficit;
            return None;
        }
        let progress_accounted = need.pending_rank.is_some()
            || need.pending_rank_columns.is_some()
            || need.pending_rank_deficit.is_some()
            || need.pending_decode_jobs.is_some();
        let rank_delta = need.pending_rank.map(|rank| {
            let delta = self
                .last_pending_rank
                .map_or(rank, |previous| rank.saturating_sub(previous));
            self.last_pending_rank = Some(rank);
            delta
        });
        let deficit_delta = need.pending_rank_deficit.and_then(|deficit| {
            let delta = self
                .last_pending_rank_deficit
                .map(|previous| previous.saturating_sub(deficit));
            self.last_pending_rank_deficit = Some(deficit);
            delta
        });
        let progress_symbols = rank_delta.unwrap_or(0).max(deficit_delta.unwrap_or(0));
        if progress_symbols == 0 {
            progress_accounted.then_some(0.0)
        } else {
            Some(self.round_payload_bps(progress_symbols, config))
        }
    }

    fn progress_congestion_loss(
        config: &QuicConfig,
        progress_delivery_bps: f64,
        offered_bps: f64,
    ) -> Option<f64> {
        if !Self::lossy_repair_feedback_enabled(config)
            || !offered_bps.is_finite()
            || offered_bps <= 0.0
        {
            return None;
        }
        let delivery_ratio = (progress_delivery_bps / offered_bps).clamp(0.0, 1.0);
        if delivery_ratio >= QUIC_LOSS_TARGET_PROGRESS_STALL_RATIO {
            return None;
        }
        Some(
            (1.0 - delivery_ratio)
                .max(
                    super::quic_aimd_loss_decrease_threshold(config)
                        + QUIC_LOSS_TARGET_PROGRESS_LOSS_MARGIN,
                )
                .clamp(0.0, 0.90),
        )
    }

    fn ensure_controller_config(&mut self, config: &QuicConfig) {
        let desired = quic_datagram_rate_config(config);
        if desired != self.controller_config {
            self.controller = DatagramRateController::new(desired);
            self.controller_config = desired;
            self.last_decision = None;
            self.shared_cap_active = false;
            self.sample_clock_micros = 0;
        }
    }

    fn observe_shared_controller(
        &mut self,
        config: &QuicConfig,
        need: &QuicNeedMore,
        delivered_payload_bytes: u64,
        loss: f64,
    ) -> DatagramRateDecision {
        self.ensure_controller_config(config);
        let symbol_bytes = u64::from(config.symbol_size.max(1));
        let sent_payload_bytes = self
            .last_round_symbols_sent
            .saturating_mul(symbol_bytes.max(1));
        let lost_bytes = ((sent_payload_bytes as f64) * loss.clamp(0.0, 1.0))
            .ceil()
            .clamp(0.0, sent_payload_bytes as f64) as u64;
        let delivered_payload_bytes = delivered_payload_bytes.min(sent_payload_bytes);
        let bytes_in_flight = sent_payload_bytes.saturating_sub(delivered_payload_bytes);
        let receiver_credit_bytes = quic_need_more_receiver_credit_bytes(config, need);
        let receiver_window_bytes =
            receiver_credit_bytes.map(|credit| credit.saturating_add(bytes_in_flight));
        let rtt_micros = self
            .last_round_rtt
            .map(duration_micros_u64)
            .unwrap_or_else(|| duration_micros_u64(self.last_round_send_wall))
            .max(1);
        if self.sample_clock_micros == 0 {
            self.sample_clock_micros = 1;
            let _ = self.controller.observe(DatagramRateSample {
                now_micros: self.sample_clock_micros,
                sent_bytes: 1,
                acked_bytes: 1,
                lost_bytes: 0,
                bytes_in_flight: 0,
                rtt_micros: Some(rtt_micros),
                receiver_credit_bytes: None,
                receiver_window_bytes: None,
            });
        }
        let send_wall_micros = duration_micros_u64(self.last_round_send_wall).max(1);
        self.sample_clock_micros = self.sample_clock_micros.saturating_add(send_wall_micros);
        let sample = DatagramRateSample {
            now_micros: self.sample_clock_micros,
            sent_bytes: sent_payload_bytes,
            acked_bytes: delivered_payload_bytes,
            lost_bytes,
            bytes_in_flight,
            rtt_micros: Some(rtt_micros),
            receiver_credit_bytes,
            receiver_window_bytes,
        };
        let decision = self.controller.observe(sample);
        self.last_decision = Some(decision);
        decision
    }

    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    fn observe_need_more(&mut self, cx: &Cx, config: &QuicConfig, need: &QuicNeedMore) {
        let sent = self.last_round_symbols_sent;
        if sent == 0 {
            return;
        }
        // Sender-side DELIVERY loss: symbols sent vs symbols the receiver OBSERVED on
        // the wire. This is the only signal that sees QUEUE/WIRE DROPS. The receiver's
        // `round_loss_fraction` counts loss only AMONG ARRIVED symbols, so during a
        // ~98% queue overflow it reads ~0.0000 and AIMD never trips its backoff — the
        // sender keeps flooding the overflowing queue until PTO timeout / non-convergence
        // (MATRIX-123/124/125, bead asupersync-atp-dataplane-redesign-317hxr.2.5.1).
        // Drive AIMD from delivery loss; keep the receiver fraction only as a floor (it
        // can exceed delivery loss when arrived symbols are themselves corrupt/duplicate).
        let delivery_loss = need
            .round_symbols_observed
            .or(need.round_symbols_accepted)
            .map(|observed| {
                let observed = observed.min(sent);
                (1.0 - observed as f64 / sent as f64).clamp(0.0, 0.90)
            });
        let receiver_loss = need.round_loss_fraction.filter(|loss| loss.is_finite());
        let wire_loss = match (delivery_loss, receiver_loss) {
            (Some(delivered), Some(received)) => delivered.max(received),
            (Some(delivered), None) => delivered,
            (None, Some(received)) => received,
            (None, None) => 0.0,
        }
        .clamp(0.0, 0.90);
        let progress_delivery_bps = self.progress_delivery_bps(config, need);
        let offered_bps = self.round_payload_bps(sent, config).max(1.0);
        let progress_loss = progress_delivery_bps
            .and_then(|delivery_bps| {
                Self::progress_congestion_loss(config, delivery_bps, offered_bps)
            })
            .unwrap_or(0.0);
        let loss = wire_loss.max(progress_loss).clamp(0.0, 0.90);
        let receiver_delivery_bps = self.receiver_delivery_bps(need, config);
        let observed_delivery_bps = receiver_delivery_bps.or(progress_delivery_bps);
        let delivered_payload_bytes = observed_delivery_bps
            .map(|bps| {
                (bps * self.last_round_send_wall_s())
                    .ceil()
                    .clamp(0.0, u64::MAX as f64) as u64
            })
            .unwrap_or_else(|| {
                need.round_symbols_observed
                    .or(need.round_symbols_accepted)
                    .unwrap_or(0)
                    .min(sent)
                    .saturating_mul(u64::from(config.symbol_size.max(1)))
            });
        let decision = self.observe_shared_controller(config, need, delivered_payload_bytes, loss);
        self.last_round_loss_fraction =
            (f64::from(decision.sender_loss_fraction_ppm) / 1_000_000.0).max(loss);
        self.shared_cap_active =
            self.last_round_loss_fraction > super::quic_aimd_loss_decrease_threshold(config);

        let cap = self
            .cap_bps()
            .map_or_else(|| "none".to_string(), |cap| cap.to_string());
        let sent = sent.to_string();
        let observed = need
            .round_symbols_observed
            .or(need.round_symbols_accepted)
            .unwrap_or(0)
            .to_string();
        let loss = format!("{:.4}", self.last_round_loss_fraction);
        let progress_delivery = progress_delivery_bps
            .map(|bps| format!("{bps:.0}"))
            .unwrap_or_else(|| "none".to_string());
        let offered = format!("{offered_bps:.0}");
        let pending_rank = need.pending_rank.unwrap_or(0).to_string();
        let pending_rank_columns = need.pending_rank_columns.unwrap_or(0).to_string();
        let pending_rank_deficit = need.pending_rank_deficit.unwrap_or(0).to_string();
        let pending_decode_jobs = need.pending_decode_jobs.unwrap_or(0).to_string();
        let shared_pacing_bytes_per_s = decision.pacing_bytes_per_s.to_string();
        let shared_delivery_rate_bytes_per_s = decision.delivery_rate_bytes_per_s.to_string();
        let shared_sender_loss_fraction_ppm = decision.sender_loss_fraction_ppm.to_string();
        let shared_cwnd_bytes = decision.cwnd_bytes.to_string();
        let shared_inflight_limit_bytes = decision.inflight_limit_bytes.to_string();
        let shared_loss_limited = if decision.loss_limited {
            "true"
        } else {
            "false"
        };
        cx.trace_with_fields(
            "atp_quic.spray.aimd_feedback",
            &[
                ("round_symbols_sent", sent.as_str()),
                ("round_symbols_observed", observed.as_str()),
                ("round_loss_fraction", loss.as_str()),
                ("progress_delivery_bps", progress_delivery.as_str()),
                ("offered_bps", offered.as_str()),
                ("pending_rank", pending_rank.as_str()),
                ("pending_rank_columns", pending_rank_columns.as_str()),
                ("pending_rank_deficit", pending_rank_deficit.as_str()),
                ("pending_decode_jobs", pending_decode_jobs.as_str()),
                (
                    "shared_pacing_bytes_per_s",
                    shared_pacing_bytes_per_s.as_str(),
                ),
                (
                    "shared_delivery_rate_bytes_per_s",
                    shared_delivery_rate_bytes_per_s.as_str(),
                ),
                (
                    "shared_sender_loss_fraction_ppm",
                    shared_sender_loss_fraction_ppm.as_str(),
                ),
                ("shared_loss_limited", shared_loss_limited),
                ("shared_cwnd_bytes", shared_cwnd_bytes.as_str()),
                (
                    "shared_inflight_limit_bytes",
                    shared_inflight_limit_bytes.as_str(),
                ),
                ("aimd_cap_bps", cap.as_str()),
            ],
        );
    }
}

fn quic_datagram_rate_config(config: &QuicConfig) -> DatagramRateConfig {
    let initial = super::quic_loss_target_pacing_cap_bps(config)
        .unwrap_or(super::QUIC_DEFAULT_COLD_START_PACING_BYTES_PER_S as u64)
        .clamp(super::QUIC_AIMD_MIN_RATE_BPS, super::QUIC_AIMD_MAX_RATE_BPS);
    let max_pacing = super::quic_loss_target_pacing_cap_bps(config)
        .unwrap_or(super::QUIC_AIMD_MAX_RATE_BPS)
        .clamp(super::QUIC_AIMD_MIN_RATE_BPS, super::QUIC_AIMD_MAX_RATE_BPS);
    DatagramRateConfig {
        initial_pacing_bytes_per_s: initial,
        min_pacing_bytes_per_s: super::QUIC_AIMD_MIN_RATE_BPS,
        max_pacing_bytes_per_s: max_pacing,
        initial_cwnd_bytes: 256 * 1024,
        min_cwnd_bytes: 16 * 1024,
        max_cwnd_bytes: 16 * 1024 * 1024,
        pacing_gain: 1.0,
        cwnd_gain: 2.0,
        loss_backoff_threshold: super::quic_aimd_loss_decrease_threshold(config),
        loss_backoff_factor: super::QUIC_AIMD_MULTIPLICATIVE_DECREASE,
        loss_delivery_headroom: QUIC_LOSS_TARGET_DELIVERY_BACKOFF_HEADROOM,
        receiver_window_gain: 1.0,
        min_receiver_window_bytes: 16 * 1024,
        max_receiver_window_bytes: 16 * 1024 * 1024,
        min_rtt_window_micros: 10_000_000,
    }
}

fn duration_from_secs(seconds: f64) -> Option<Duration> {
    (seconds.is_finite() && seconds > 0.0).then(|| Duration::from_secs_f64(seconds))
}

fn duration_micros_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn quic_need_more_receiver_credit_bytes(config: &QuicConfig, need: &QuicNeedMore) -> Option<u64> {
    let symbol_bytes = u64::from(config.symbol_size.max(1));
    let requested = need_more_requested_symbol_count(need);
    let deficit = need
        .pending_rank_deficit
        .or(need.repair_base_deficit_symbols)
        .unwrap_or(0);
    let credit_symbols = deficit
        .saturating_mul(2)
        .max(requested)
        .max((!need.pending.is_empty()).then_some(32).unwrap_or(0));
    (credit_symbols > 0).then_some(credit_symbols.saturating_mul(symbol_bytes))
}

/// Spray a round of symbols for the `pending` entries over a live link, pacing on
/// the bounded outbound DATAGRAM queue. Mirrors `super::spray_native_symbol_round`
/// but interleaves real UDP flushes so a large object never drops symbols before
/// they reach the wire. `with_source` selects the initial source+repair spray vs
/// a repair-only batch.
async fn spray_round(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    pending: &std::collections::BTreeSet<u32>,
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
    with_source: bool,
    aimd: &mut NativeQuicAimdPacer,
) -> Result<u64, QuicTransportError> {
    let tag = super::transfer_tag(&manifest.transfer_id);
    let repair_batch = super::repair_batch_per_block(config);
    let drop_one_in = config.debug_drop_one_in;
    let mut pacing = link.spray_pacing_decision(
        config,
        aimd.cap_bps(),
        aimd.shared_decision(),
        aimd.observed_loss(),
    );
    let clean_ramp_max_pacing_bps = super::quic_round0_clean_ramp_max_pacing_bps(&pacing);
    let mut clean_ramp =
        super::quic_round0_clean_ramp_enabled(config, &pacing, with_source).then(|| {
            super::QuicRound0CleanPacingRamp::new_with_burst_cap(
                clean_ramp_max_pacing_bps,
                config.max_spray_symbols_per_flush,
            )
        });
    if clean_ramp.is_some() {
        quic_rqtrace!(
            "sender-native: round0_clean_pacing_ramp enabled start_rate_Bps={} step_bytes={} max_rate_Bps={} datagram_fanout={} datagram_frame_bytes={} burst_symbols={}",
            pacing.pacing_rate_bps,
            super::QUIC_ROUND0_CLEAN_RAMP_STEP_BYTES,
            clean_ramp_max_pacing_bps,
            config.datagram_fanout.max(1),
            link.symbol_datagram_frame_len,
            pacing.max_burst_symbols,
        );
    }
    pacing.trace_epoch(cx, u64::from(!with_source));
    link.reset_sender_handoff_trace();
    let send_start = Instant::now();
    let mut sent = 0u64;
    let mut sprayed = 0u64;
    let mut cursor_updates = Vec::new();
    let mut stopped_for_feedback = false;
    // Keep the native sender handoff continuous across source blocks; high-BDP
    // and future fanout paths need paced windows, not per-block partial flushes.
    let mut handoff_batch = Vec::with_capacity(link.spray_handoff_symbol_limit(&pacing));
    'entries: for index in pending {
        let Some(entry) = encoders.iter_mut().find(|entry| entry.index == *index) else {
            continue;
        };
        if with_source && link.has_pending_fountain_feedback() {
            stopped_for_feedback = true;
            break;
        }
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        for block_idx in 0..entry.block_count(config)? {
            if with_source && link.has_pending_fountain_feedback() {
                stopped_for_feedback = true;
                break 'entries;
            }
            let sbn = u8::try_from(block_idx).map_err(|_| {
                QuicTransportError::Integrity("source block index exceeded u8 range".to_string())
            })?;
            let block = entry.read_block(cx, sbn, config).await?;
            let already = entry.repair_cursor(sbn);
            let target_repair = if with_source {
                super::initial_repair_per_block(block.len(), config)
            } else {
                already.saturating_add(repair_batch)
            };
            let repair_count = target_repair.saturating_sub(already);
            if !with_source && repair_count == 0 {
                entry.set_repair_cursor(sbn, target_repair);
                continue;
            }
            let mut pipeline = super::encoding_pipeline(config);
            let object_id = entry.object_id;
            let entry_index = entry.index;
            let encoded = if with_source {
                super::EitherNativeEncoding::Source(pipeline.encode_single_block_with_repair(
                    object_id,
                    sbn,
                    &block,
                    target_repair,
                ))
            } else {
                super::EitherNativeEncoding::Repair(pipeline.encode_single_block_repair_range(
                    object_id,
                    sbn,
                    &block,
                    already,
                    repair_count,
                ))
            };
            let mut emitted_repair_symbols = 0usize;
            for encoded_symbol in encoded {
                let symbol = encoded_symbol
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                if symbol.kind().is_repair() {
                    emitted_repair_symbols = emitted_repair_symbols.saturating_add(1);
                }
                // Deterministic test-only symbol loss: skip on the initial spray only,
                // so the receiver must drive a repair round, and never on a repair round
                // (otherwise it could fail to converge). Control frames are unaffected.
                sprayed = sprayed.saturating_add(1);
                if with_source && drop_one_in > 0 && sprayed % u64::from(drop_one_in) == 0 {
                    continue;
                }
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol_tag(&symbol).as_bytes());
                handoff_batch.push(NativeQuicSpraySymbol {
                    symbol,
                    entry: entry_index,
                    auth_tag,
                });
                let handoff_limit = link.spray_handoff_symbol_limit(&pacing);
                if handoff_batch.len() >= handoff_limit {
                    link.spray_symbol_batch(
                        cx,
                        control,
                        tag,
                        &handoff_batch,
                        &pacing,
                        aimd.shared_decision(),
                    )
                    .await?;
                    let batch_len = u64::try_from(handoff_batch.len()).unwrap_or(u64::MAX);
                    sent = sent.saturating_add(batch_len);
                    for _ in 0..handoff_batch.len() {
                        if let Some(ramp) = &mut clean_ramp {
                            if let Some(report) =
                                ramp.observe_datagram(&mut pacing, link.symbol_datagram_frame_len)
                            {
                                quic_rqtrace!(
                                    "sender-native: round0_clean_rate_ramp sent_datagrams={} sent_bytes={} old_rate_Bps={} new_rate_Bps={} next_step_bytes={} max_rate_Bps={}",
                                    report.sent_datagrams,
                                    report.sent_bytes,
                                    report.old_rate_bps,
                                    report.new_rate_bps,
                                    report.next_step_bytes,
                                    report.max_rate_bps,
                                );
                            }
                        }
                    }
                    handoff_batch.clear();
                    handoff_batch.reserve(link.spray_handoff_symbol_limit(&pacing));
                    if with_source && link.has_pending_fountain_feedback() {
                        stopped_for_feedback = true;
                        break;
                    }
                }
            }
            if stopped_for_feedback {
                let repair_cursor =
                    already.saturating_add(emitted_repair_symbols.min(repair_count));
                cursor_updates.push((entry_index, sbn, repair_cursor));
                trace_quic_initial_spray_cut_for_feedback(
                    cx,
                    sent,
                    link.pending_fountain_feedback_count(),
                    link.conn.pending_outbound_datagram_count(),
                    link.conn.transport().bytes_in_flight(),
                    link.conn.transport().congestion_window_bytes(),
                    entry_index,
                    sbn,
                    repair_cursor,
                );
                break 'entries;
            }
            cursor_updates.push((entry_index, sbn, target_repair));
        }
    }
    if !stopped_for_feedback && !handoff_batch.is_empty() {
        link.spray_symbol_batch(
            cx,
            control,
            tag,
            &handoff_batch,
            &pacing,
            aimd.shared_decision(),
        )
        .await?;
        let batch_len = u64::try_from(handoff_batch.len()).unwrap_or(u64::MAX);
        sent = sent.saturating_add(batch_len);
        for _ in 0..handoff_batch.len() {
            if let Some(ramp) = &mut clean_ramp {
                if let Some(report) =
                    ramp.observe_datagram(&mut pacing, link.symbol_datagram_frame_len)
                {
                    quic_rqtrace!(
                        "sender-native: round0_clean_rate_ramp sent_datagrams={} sent_bytes={} old_rate_Bps={} new_rate_Bps={} next_step_bytes={} max_rate_Bps={}",
                        report.sent_datagrams,
                        report.sent_bytes,
                        report.old_rate_bps,
                        report.new_rate_bps,
                        report.next_step_bytes,
                        report.max_rate_bps,
                    );
                }
            }
        }
    }
    for (entry_index, sbn, target_repair) in cursor_updates {
        if let Some(entry) = encoders.iter_mut().find(|entry| entry.index == entry_index) {
            entry.set_repair_cursor(sbn, target_repair);
        }
    }
    aimd.record_spray_with_pacing(sent, &pacing, send_start.elapsed());
    link.finish_paced_spray_round(cx, control, sent, &pacing)
        .await?;
    Ok(sent)
}

/// Send the specific systematic source symbols a receiver requested, paced.
async fn spray_source_requests(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    encoders: &[QuicEntryEncoder],
    requests: &[QuicSourceSymbolRequest],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
    aimd: &mut NativeQuicAimdPacer,
) -> Result<u64, QuicTransportError> {
    let tag = super::transfer_tag(&manifest.transfer_id);
    let pacing = link.spray_pacing_decision(
        config,
        aimd.cap_bps(),
        aimd.shared_decision(),
        aimd.observed_loss(),
    );
    pacing.trace_epoch(cx, 2);
    link.reset_sender_handoff_trace();
    let send_start = Instant::now();
    let mut sent = 0u64;
    let mut handoff_batch = Vec::with_capacity(link.spray_handoff_symbol_limit(&pacing));
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
        let block = enc.read_block(cx, request.sbn, config).await?;
        let symbol_size = usize::from(config.symbol_size.max(1));
        let block_k = block.len().div_ceil(symbol_size).max(1);
        let esi = usize::try_from(request.esi).map_err(|_| {
            QuicTransportError::Integrity("source request ESI does not fit usize".to_string())
        })?;
        if esi >= block_k {
            return Err(QuicTransportError::Integrity(format!(
                "source request esi {} outside entry {} block {} K={block_k}",
                request.esi, enc.index, request.sbn
            )));
        }
        let start = esi * symbol_size;
        let end = (start + symbol_size).min(block.len());
        let mut buffer = vec![0u8; symbol_size];
        if start < end {
            buffer[..end - start].copy_from_slice(&block[start..end]);
        }
        let symbol = Symbol::new(
            crate::types::symbol::SymbolId::new(enc.object_id, request.sbn, request.esi),
            buffer,
            crate::types::symbol::SymbolKind::Source,
        );
        let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol_tag(&symbol).as_bytes());
        handoff_batch.push(NativeQuicSpraySymbol {
            symbol,
            entry: request.entry,
            auth_tag,
        });
        if handoff_batch.len() >= link.spray_handoff_symbol_limit(&pacing) {
            link.spray_symbol_batch(
                cx,
                control,
                tag,
                &handoff_batch,
                &pacing,
                aimd.shared_decision(),
            )
            .await?;
            sent = sent.saturating_add(u64::try_from(handoff_batch.len()).unwrap_or(u64::MAX));
            handoff_batch.clear();
            handoff_batch.reserve(link.spray_handoff_symbol_limit(&pacing));
        }
    }
    if !handoff_batch.is_empty() {
        link.spray_symbol_batch(
            cx,
            control,
            tag,
            &handoff_batch,
            &pacing,
            aimd.shared_decision(),
        )
        .await?;
        sent = sent.saturating_add(u64::try_from(handoff_batch.len()).unwrap_or(u64::MAX));
    }
    aimd.record_spray_with_pacing(sent, &pacing, send_start.elapsed());
    link.finish_paced_spray_round(cx, control, sent, &pacing)
        .await?;
    Ok(sent)
}

/// Send fresh repair symbols for the specific source blocks a receiver still lacks.
async fn spray_block_repair_requests(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    requests: &[QuicBlockRepairRequest],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
    aimd: &mut NativeQuicAimdPacer,
) -> Result<u64, QuicTransportError> {
    let tag = super::transfer_tag(&manifest.transfer_id);
    let pacing = link.spray_pacing_decision(
        config,
        aimd.cap_bps(),
        aimd.shared_decision(),
        aimd.observed_loss(),
    );
    pacing.trace_epoch(cx, 3);
    link.reset_sender_handoff_trace();
    let send_start = Instant::now();
    let mut sent = 0u64;
    let mut cursor_updates = Vec::with_capacity(requests.len());
    let mut handoff_batch = Vec::with_capacity(link.spray_handoff_symbol_limit(&pacing));
    for request in requests {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let Some(enc_index) = encoders
            .iter()
            .position(|entry| entry.index == request.entry)
        else {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested repair block for unknown entry {}",
                request.entry
            )));
        };
        let repair_count = usize::try_from(request.symbols).map_err(|_| {
            QuicTransportError::Integrity("repair symbol count does not fit usize".to_string())
        })?;
        let (block, already, target_repair, object_id, entry_index) = {
            let enc = &mut encoders[enc_index];
            let block = enc.read_block(cx, request.sbn, config).await?;
            let already = enc.repair_cursor(request.sbn);
            (
                block,
                already,
                already.saturating_add(repair_count),
                enc.object_id,
                enc.index,
            )
        };
        if entry_index != request.entry {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested repair block for unknown entry {}",
                request.entry
            )));
        }
        let mut pipeline = super::encoding_pipeline(config);
        let mut emitted_for_request = 0u64;
        for encoded in pipeline.encode_single_block_repair_range(
            object_id,
            request.sbn,
            &block,
            already,
            repair_count,
        ) {
            let symbol = encoded
                .map_err(|err| QuicTransportError::Control(err.to_string()))?
                .into_symbol();
            let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol_tag(&symbol).as_bytes());
            handoff_batch.push(NativeQuicSpraySymbol {
                symbol,
                entry: entry_index,
                auth_tag,
            });
            emitted_for_request = emitted_for_request.saturating_add(1);
            if handoff_batch.len() >= link.spray_handoff_symbol_limit(&pacing) {
                link.spray_symbol_batch(
                    cx,
                    control,
                    tag,
                    &handoff_batch,
                    &pacing,
                    aimd.shared_decision(),
                )
                .await?;
                sent = sent.saturating_add(u64::try_from(handoff_batch.len()).unwrap_or(u64::MAX));
                handoff_batch.clear();
                handoff_batch.reserve(link.spray_handoff_symbol_limit(&pacing));
            }
        }
        if emitted_for_request != u64::from(request.symbols) {
            return Err(QuicTransportError::Integrity(format!(
                "sender emitted {emitted_for_request} repair symbols for receiver-requested deficit {} on entry {} block {}",
                request.symbols, entry_index, request.sbn
            )));
        }
        cursor_updates.push((enc_index, request.sbn, target_repair));
        quic_rqtrace!(
            "sender: repair_block entry={} sbn={} requested_symbols={} emitted_symbols={} repair_cursor_before={} repair_cursor_after={} pacing_rate_bps={}",
            entry_index,
            request.sbn,
            request.symbols,
            emitted_for_request,
            already,
            target_repair,
            pacing.pacing_rate_bps,
        );
    }
    if !handoff_batch.is_empty() {
        link.spray_symbol_batch(
            cx,
            control,
            tag,
            &handoff_batch,
            &pacing,
            aimd.shared_decision(),
        )
        .await?;
        sent = sent.saturating_add(u64::try_from(handoff_batch.len()).unwrap_or(u64::MAX));
    }
    for (enc_index, sbn, target_repair) in cursor_updates {
        let Some(enc) = encoders.get_mut(enc_index) else {
            return Err(QuicTransportError::Integrity(
                "repair cursor update referenced missing encoder".to_string(),
            ));
        };
        enc.set_repair_cursor(sbn, target_repair);
    }
    aimd.record_spray_with_pacing(sent, &pacing, send_start.elapsed());
    link.finish_paced_spray_round(cx, control, sent, &pacing)
        .await?;
    Ok(sent)
}

/// Receiver `HandshakeAck` parse (mirrors `super::receive_native_sender_hello_ack`).
fn parse_hello_ack(frame: &Frame) -> Result<QuicHelloAck, QuicTransportError> {
    if frame.frame_type() != FrameType::HandshakeAck {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "HandshakeAck",
        });
    }
    let ack: QuicHelloAck = super::parse_json(frame)?;
    if !ack.accepted {
        return Err(QuicTransportError::HandshakeRejected(
            ack.reason
                .clone()
                .unwrap_or_else(|| "no reason given".to_string()),
        ));
    }
    Ok(ack)
}

async fn drive_native_source_stream_flush(
    cx: &Cx,
    link: &mut QuicLink,
    idle_timeout: Duration,
    drain_all: bool,
) -> Result<(), QuicTransportError> {
    let started = Instant::now();
    let mut last_progress = Instant::now();
    let mut made_progress = false;
    let mut recent_stream_frames = Vec::new();
    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let pending_frames = link.conn.pending_stream_frame_count();
        if pending_frames == 0 {
            return Ok(());
        }
        let pending_bytes = link.conn.pending_stream_data_bytes();
        let flushed = link.flush(cx).await?;
        made_progress |= flushed > 0;
        if flushed > 0 {
            last_progress = Instant::now();
            let frames = link.last_flushed_stream_frames();
            if !frames.is_empty() {
                recent_stream_frames = frames;
            }
        }
        quic_rqtrace!(
            "sender: native_source_stream_flush pending_frames={} pending_bytes={} flushed={} drain_all={} in_flight={} cwnd={}",
            pending_frames,
            pending_bytes,
            flushed,
            drain_all,
            link.conn.transport().bytes_in_flight(),
            link.conn.transport().congestion_window_bytes(),
        );
        if link.conn.pending_stream_frame_count() == 0 {
            return Ok(());
        }
        let pump_timeout = if flushed == 0 || !drain_all {
            INBOUND_PUMP_DRAIN_GRACE
        } else {
            Duration::ZERO
        };
        let pumped = link.pump_inbound_for(cx, pump_timeout).await?;
        if pumped > 0 {
            last_progress = Instant::now();
            let latest_stream_ack_ranges = link.latest_stream_ack_ranges.clone();
            let retransmit_frames =
                link.drain_ack_gap_lost_stream_frames_for_retransmit(&latest_stream_ack_ranges);
            if !retransmit_frames.is_empty() {
                let retransmitted = link
                    .retransmit_stream_frames(
                        cx,
                        &retransmit_frames,
                        "source_stream_ack_gap_retransmit",
                    )
                    .await?;
                if retransmitted > 0 {
                    last_progress = Instant::now();
                    recent_stream_frames = link.last_flushed_stream_frames();
                    continue;
                }
            }
        }
        if link.conn.pending_stream_frame_count() == 0 {
            return Ok(());
        }
        if !drain_all && made_progress {
            return Ok(());
        }
        if flushed == 0 && pumped == 0 && last_progress.elapsed() >= SOURCE_STREAM_PTO {
            let _ = link.expire_app_data_loss_timeout(cx, "flush QUIC source stream")?;
            let mut retransmit_frames = link.drain_in_flight_stream_frames_for_retransmit();
            if retransmit_frames.is_empty() {
                retransmit_frames = recent_stream_frames.clone();
            }
            if !retransmit_frames.is_empty() {
                let retransmitted = link
                    .retransmit_stream_frames(cx, &retransmit_frames, "source_stream_pto")
                    .await?;
                if retransmitted > 0 {
                    last_progress = Instant::now();
                    recent_stream_frames = link.last_flushed_stream_frames();
                    continue;
                }
            }
            last_progress = Instant::now();
        }
        if started.elapsed() >= idle_timeout {
            return Err(QuicTransportError::Timeout {
                operation: "flush QUIC source stream",
                timeout: idle_timeout,
            });
        }
    }
}

async fn send_native_source_stream_entries_pumped(
    cx: &Cx,
    link: &mut QuicLink,
    stream: StreamId,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    let max_chunk = link
        .max_app_payload
        .saturating_sub(usize::try_from(QUIC_STREAM_PACKET_OVERHEAD_BUDGET).unwrap_or(usize::MAX))
        .max(1);
    let flush_chunk = usize::try_from(QUIC_SOURCE_STREAM_FLUSH_BYTES).unwrap_or(usize::MAX);
    let mut buf = vec![0_u8; max_chunk.min(flush_chunk).max(1)];
    let mut streamed = 0u64;
    let mut queued_since_flush = 0u64;

    for entry in &prepared.entries {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        if entry.size == 0 {
            continue;
        }
        let mut file = crate::fs::File::open(&entry.abs_path)
            .await
            .map_err(|err| {
                QuicTransportError::Source(format!("{}: {err}", entry.abs_path.display()))
            })?;
        let mut hasher = Sha256::new();
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
                    "{} grew while streaming QUIC source bytes (read {read} bytes, manifest size {})",
                    entry.abs_path.display(),
                    entry.size
                )));
            }
            hasher.update(&buf[..n]);
            link.conn
                .write_stream_bytes(cx, stream, Bytes::copy_from_slice(&buf[..n]), false)?;
            let n_u64 = u64::try_from(n).unwrap_or(u64::MAX);
            streamed = streamed.saturating_add(n_u64);
            queued_since_flush = queued_since_flush.saturating_add(n_u64);
            if queued_since_flush >= QUIC_SOURCE_STREAM_FLUSH_BYTES {
                drive_native_source_stream_flush(cx, link, config.idle_timeout, false).await?;
                queued_since_flush = 0;
            }
        }
        if read != entry.size {
            return Err(QuicTransportError::Source(format!(
                "{} changed while streaming QUIC source bytes (read {read} bytes, manifest size {})",
                entry.abs_path.display(),
                entry.size
            )));
        }
        let got_sha = hex_encode(&hasher.finalize());
        if got_sha != entry.sha256_hex {
            return Err(QuicTransportError::Integrity(format!(
                "{} changed while streaming QUIC source bytes (sha256 {got_sha}, manifest {})",
                entry.abs_path.display(),
                entry.sha256_hex
            )));
        }
    }

    link.conn
        .write_stream_bytes(cx, stream, Bytes::new(), true)?;
    drive_native_source_stream_flush(cx, link, config.idle_timeout, true).await?;
    Ok(streamed)
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn source_stream_repair_tail_requests(
    manifest: &TransferManifest,
    config: &QuicConfig,
) -> Result<Vec<QuicBlockRepairRequest>, QuicTransportError> {
    let mut requests = Vec::new();
    for entry in &manifest.entries {
        for block_idx in 0..super::block_count_for_len(entry.size, config)? {
            let sbn = u8::try_from(block_idx).map_err(|_| QuicTransportError::TooLarge {
                size: entry.size,
                max: u64::try_from(config.max_block_size.max(1))
                    .unwrap_or(u64::MAX)
                    .saturating_mul(u64::from(u8::MAX) + 1),
            })?;
            let block_start = u64::from(sbn)
                .saturating_mul(u64::try_from(config.max_block_size.max(1)).unwrap_or(u64::MAX));
            let block_len = usize::try_from(
                entry
                    .size
                    .saturating_sub(block_start)
                    .min(u64::try_from(config.max_block_size.max(1)).unwrap_or(u64::MAX)),
            )
            .unwrap_or(usize::MAX);
            let block_source_symbols = block_len
                .min(config.max_block_size.max(1))
                .div_ceil(usize::from(config.symbol_size.max(1)))
                .max(1);
            let configured_overhead = (config.repair_overhead - 1.0).max(0.0);
            let loss_floor =
                config.round0_loss_target.max(0.0) * QUIC_SOURCE_STREAM_REPAIR_LOSS_MULTIPLIER;
            let repair_fraction = configured_overhead.max(loss_floor);
            let repair = ((block_source_symbols as f64) * repair_fraction).ceil() as usize;
            if repair == 0 {
                continue;
            }
            requests.push(QuicBlockRepairRequest {
                entry: entry.index,
                sbn,
                symbols: u32::try_from(repair).unwrap_or(u32::MAX),
            });
        }
    }
    Ok(requests)
}

/// Drive a full ATP-over-QUIC send over an established link: Hello, manifest,
/// initial symbol spray, then the fountain feedback loop until Proof or the
/// feedback-round budget is exhausted.
async fn run_sender_session(
    cx: &Cx,
    link: &mut QuicLink,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
    peer_id: &str,
) -> Result<SendReport, QuicTransportError> {
    let config = prepared.effective_config(config);
    let config = &config;
    config.validate()?;
    super::validate_quic_manifest(&prepared.manifest, config)?;
    let manifest = &prepared.manifest;
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();

    let mut control = NativeQuicFrameTransport::open(cx, &mut link.conn)?;
    let offered_source_stream =
        if super::quic_native_source_stream_enabled(manifest.total_bytes, config, &link.conn) {
            Some(link.conn.open_local_bidi(cx)?)
        } else {
            None
        };
    super::send_native_sender_hello(
        cx,
        &mut link.conn,
        &mut control,
        config,
        peer_id,
        symbol_auth_enabled,
        offered_source_stream,
        manifest.total_bytes,
    )?;
    link.flush(cx).await?;
    let hello_frames = link.last_flushed_stream_frames();
    let ack_frame = link
        .next_control_frame_with_stream_pto(
            cx,
            &mut control,
            "receive sender handshake ack",
            &hello_frames,
            "sender_hello_pto",
        )
        .await?;
    let ack = parse_hello_ack(&ack_frame)?;
    let source_stream = match (offered_source_stream, ack.source_stream) {
        (Some(stream), true) => Some(stream),
        (None, true) => {
            return Err(QuicTransportError::HandshakeRejected(
                "receiver accepted an unoffered QUIC source stream".to_string(),
            ));
        }
        _ => None,
    };

    super::send_native_manifest(cx, &mut link.conn, &mut control, manifest)?;
    link.flush(cx).await?;
    if let Some(source_stream) = source_stream {
        let previous_paced_source_stream = link.paced_source_stream.replace(source_stream);
        let source_pacing = link.source_stream_pacing_decision(config);
        source_pacing.trace_epoch(cx, 0);
        link.data_plane_pacer
            .configure_source_stream(&source_pacing);
        quic_rqtrace!(
            "sender: native_source_stream_pacing rate_bps={} burst_symbols={} burst_bytes={} frame_bytes={}",
            source_pacing.pacing_rate_bps,
            source_pacing.max_burst_symbols,
            link.data_plane_pacer.byte_pacer_burst_bytes,
            source_stream_max_frame_bytes(),
        );
        let source_result: Result<SendReport, QuicTransportError> = async {
            let mut encoders = super::encoders_from_prepared_source(cx, prepared, config).await?;
            let repair_tail_requests = source_stream_repair_tail_requests(manifest, config)?;
            let mut tail_aimd = NativeQuicAimdPacer::default();
            let bytes_streamed =
                send_native_source_stream_entries_pumped(cx, link, source_stream, prepared, config)
                    .await?;
            if bytes_streamed != manifest.total_bytes {
                return Err(QuicTransportError::Integrity(format!(
                    "source stream sent {bytes_streamed} bytes, expected {}",
                    manifest.total_bytes
                )));
            }
            quic_rqtrace!(
                "sender: native_source_stream sent bytes={} stream={}",
                bytes_streamed,
                source_stream.0
            );
            let repair_tail_symbols = if repair_tail_requests.is_empty() {
                0
            } else {
                spray_block_repair_requests(
                    cx,
                    link,
                    &mut control,
                    manifest,
                    &mut encoders,
                    &repair_tail_requests,
                    config,
                    symbol_auth.as_ref(),
                    &mut tail_aimd,
                )
                .await?
            };
            quic_rqtrace!(
                "sender: native_source_stream_repair_tail symbols={} blocks={}",
                repair_tail_symbols,
                repair_tail_requests.len()
            );
            let mut symbols_sent = repair_tail_symbols;
            let mut feedback_rounds = 0u32;
            send_native_object_complete_for_round(
                cx,
                &mut link.conn,
                &mut control,
                0,
                repair_tail_symbols,
            )?;
            link.flush(cx).await?;
            // Keep the source stream marked as ATP-paced through proof wait:
            // PTO retransmits of lost source STREAM frames must not fall back
            // under NewReno cwnd after the initial source send returns.
            let mut source_completion_frames = link.last_flushed_stream_frames();
            loop {
                cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
                let reply_frame = link
                    .next_control_frame_with_stream_pto(
                        cx,
                        &mut control,
                        "receive stream-source proof",
                        &source_completion_frames,
                        "source_stream_completion_pto",
                    )
                    .await?;
                match reply_frame.frame_type() {
                    FrameType::Proof => {
                        let receipt = super::parse_json::<ReceiveReceipt>(&reply_frame)?;
                        super::send_native_close(cx, &mut link.conn, &mut control)?;
                        link.flush(cx).await?;
                        if !receipt.committed {
                            return Err(QuicTransportError::Integrity(
                                receipt
                                    .reason
                                    .clone()
                                    .unwrap_or_else(|| "receiver did not commit".to_string()),
                            ));
                        }
                        return Ok(SendReport {
                            transfer_id: manifest.transfer_id.clone(),
                            bytes_sent: manifest.total_bytes,
                            files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
                            symbols_sent,
                            feedback_rounds,
                            merkle_root_hex: manifest.merkle_root_hex.clone(),
                            receipt,
                            peer: link.peer,
                        });
                    }
                    FrameType::KeepAlive => continue,
                    FrameType::ObjectRequest => {
                        let need = super::parse_json::<QuicNeedMore>(&reply_frame)?;
                        let (next_feedback_round, response_feedback_round) =
                            feedback_round_for_need_or_no_convergence(
                                feedback_rounds,
                                config.max_feedback_rounds,
                                need.feedback_round,
                                need.pending.len(),
                            )?;
                        tail_aimd.observe_need_more(cx, config, &need);
                        feedback_rounds = next_feedback_round;
                        let requested_repair_symbols = need_more_repair_symbol_count(&need);
                        let base_deficit_symbols =
                            need_more_base_deficit_symbols(&need, requested_repair_symbols);
                        let sender_delivery_loss_for_repair =
                            tail_aimd.sender_delivery_loss_for_repair(need.round_loss_fraction);
                        let loss_compensated_target_symbols =
                            loss_compensated_repair_target(
                                base_deficit_symbols,
                                need.round_loss_fraction,
                            );
                        let sender_loss_compensated_target_symbols =
                            sender_delivery_loss_for_repair
                                .map(|loss| {
                                    loss_compensated_repair_target(
                                        base_deficit_symbols,
                                        Some(loss),
                                    )
                                })
                                .unwrap_or(base_deficit_symbols);
                        let loss_compensated_target_symbols =
                            need_more_loss_compensated_target_symbols(&need, base_deficit_symbols)
                                .max(loss_compensated_target_symbols)
                                .max(sender_loss_compensated_target_symbols);
                        let repair_blocks_to_send = if need.repair_blocks.is_empty() {
                            Vec::new()
                        } else {
                            delivery_loss_compensated_repair_blocks(
                                &need.repair_blocks,
                                sender_delivery_loss_for_repair,
                            )
                        };
                        let repair_symbols_to_emit =
                            repair_block_symbol_count(&repair_blocks_to_send);
                        let loss_compensated_target_symbols =
                            loss_compensated_target_symbols.max(repair_symbols_to_emit);
                        let request_gap_to_target = need
                            .repair_request_gap_to_target_symbols
                            .unwrap_or_else(|| {
                                loss_compensated_target_symbols
                                    .saturating_sub(requested_repair_symbols)
                            });
                        let repair_detail = repair_block_trace_summary(&need.repair_blocks);
                        let sender_delivery_loss_for_repair_trace =
                            sender_delivery_loss_for_repair.unwrap_or(0.0);
                        quic_rqtrace!(
                            "sender: native_source_stream NeedMore round={feedback_rounds} pending={} repair_blocks={} base_deficit_symbols={} requested_repair_symbols={} repair_symbols_to_emit={} loss_compensated_target_symbols={} request_gap_to_target={} source_requests={} round_symbols_observed={} round_symbols_accepted={} round_loss_fraction={:.4} sender_delivery_loss_for_repair={:.4} max_feedback_rounds={} round_cap_exceeded={} repair_symbol_round_cap={} prior_total_symbols_sent={} prior_round_symbols_sent={} prior_pacing_rate_bps={} repair_blocks_detail={}",
                            need.pending.len(),
                            need.repair_blocks.len(),
                            base_deficit_symbols,
                            requested_repair_symbols,
                            repair_symbols_to_emit,
                            loss_compensated_target_symbols,
                            request_gap_to_target,
                            need.source_symbols.len(),
                            need.round_symbols_observed.unwrap_or(0),
                            need.round_symbols_accepted.unwrap_or(0),
                            need.round_loss_fraction.unwrap_or(0.0),
                            sender_delivery_loss_for_repair_trace,
                            config.max_feedback_rounds,
                            feedback_rounds > config.max_feedback_rounds,
                            super::MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
                            symbols_sent,
                            tail_aimd.last_round_symbols_sent,
                            tail_aimd.last_round_pacing_rate_bps,
                            repair_detail,
                        );
                        trace_repair_block_deficits(
                            "native_source_stream_sender",
                            feedback_rounds,
                            &need.repair_blocks,
                        );
                        super::trace_quic_sender_need_more(
                            cx,
                            feedback_rounds,
                            symbols_sent,
                            tail_aimd.last_round_symbols_sent,
                            &need,
                            config,
                            None,
                            tail_aimd.cap_bps(),
                        );
                        if need.pending.is_empty()
                            && need.repair_blocks.is_empty()
                            && need.source_symbols.is_empty()
                        {
                            super::trace_quic_sender_repair_round(
                                cx,
                                feedback_rounds,
                                super::quic_need_more_response_mode(&need),
                                symbols_sent,
                                0,
                                &need,
                            );
                            send_native_object_complete_for_round(
                                cx,
                                &mut link.conn,
                                &mut control,
                                response_feedback_round,
                                0,
                            )?;
                            link.flush(cx).await?;
                            source_completion_frames = link.last_flushed_stream_frames();
                            continue;
                        }
                        super::validate_need_more_feedback(manifest, config, &need)?;
                        let symbols_before = symbols_sent;
                        let response_mode = super::quic_need_more_response_mode(&need);
                        let sent = if !need.repair_blocks.is_empty() {
                            spray_block_repair_requests(
                                cx,
                                link,
                                &mut control,
                                manifest,
                                &mut encoders,
                                &repair_blocks_to_send,
                                config,
                                symbol_auth.as_ref(),
                                &mut tail_aimd,
                            )
                            .await?
                        } else if need.source_symbols.is_empty() {
                            let fallback_pending = need.pending.iter().copied().collect();
                            spray_round(
                                cx,
                                link,
                                &mut control,
                                manifest,
                                &mut encoders,
                                &fallback_pending,
                                config,
                                symbol_auth.as_ref(),
                                false,
                                &mut tail_aimd,
                            )
                            .await?
                        } else {
                            spray_source_requests(
                                cx,
                                link,
                                &mut control,
                                manifest,
                                &encoders,
                                &need.source_symbols,
                                config,
                                symbol_auth.as_ref(),
                                &mut tail_aimd,
                            )
                            .await?
                        };
                        if !need.repair_blocks.is_empty() && sent != repair_symbols_to_emit {
                            return Err(QuicTransportError::Integrity(format!(
                                "sender emitted {sent} repair symbols for loss-compensated repair target {repair_symbols_to_emit}"
                            )));
                        }
                        symbols_sent = symbols_sent.saturating_add(sent);
                        trace_native_repair_accounting(
                            cx,
                            "native_source_stream_sender",
                            feedback_rounds,
                            base_deficit_symbols,
                            requested_repair_symbols,
                            loss_compensated_target_symbols,
                            Some(sent),
                            &need,
                        );
                        super::trace_quic_sender_repair_round(
                            cx,
                            feedback_rounds,
                            response_mode,
                            symbols_before,
                            sent,
                            &need,
                        );
                        link.flush(cx).await?;
                        let handoff_phase = if need.repair_blocks.is_empty() {
                            "source_stream_source_requests"
                        } else {
                            "source_stream_repair_blocks"
                        };
                        link.trace_sender_handoff_summary(cx, handoff_phase, sent);
                        send_native_object_complete_for_round(
                            cx,
                            &mut link.conn,
                            &mut control,
                            response_feedback_round,
                            sent,
                        )?;
                        link.flush(cx).await?;
                        source_completion_frames = link.last_flushed_stream_frames();
                        if !need.repair_blocks.is_empty() {
                            let _ = link
                                .drop_duplicate_need_more_resends(cx, &mut control, &need)
                                .await?;
                        }
                    }
                    got => {
                        return Err(QuicTransportError::Unexpected {
                            got,
                            expected: "Proof | ObjectRequest | KeepAlive",
                        });
                    }
                }
            }
        }
        .await;
        link.paced_source_stream = previous_paced_source_stream;
        return source_result;
    }

    let mut encoders = super::encoders_from_prepared_source(cx, prepared, config).await?;
    let pending_all: std::collections::BTreeSet<u32> =
        encoders.iter().map(|entry| entry.index).collect();
    let mut aimd = NativeQuicAimdPacer::default();
    let mut symbols_sent = spray_round(
        cx,
        link,
        &mut control,
        manifest,
        &mut encoders,
        &pending_all,
        config,
        symbol_auth.as_ref(),
        true,
        &mut aimd,
    )
    .await?;
    // `spray_round` drains queued DATAGRAMs before returning so ObjectComplete
    // cannot overtake unsent symbols in the connection's outbound queues.
    link.trace_sender_handoff_summary(cx, "initial_source", symbols_sent);
    send_native_object_complete_for_round(cx, &mut link.conn, &mut control, 0, symbols_sent)?;
    link.flush(cx).await?;

    let mut feedback_rounds = 0u32;
    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let reply_frame = link
            .next_control_frame(cx, &mut control, "receive proof or fountain feedback")
            .await?;
        let reply = match reply_frame.frame_type() {
            FrameType::Proof => {
                QuicControlReply::Proof(super::parse_json::<ReceiveReceipt>(&reply_frame)?)
            }
            FrameType::ObjectRequest => {
                QuicControlReply::NeedMore(super::parse_json::<QuicNeedMore>(&reply_frame)?)
            }
            FrameType::KeepAlive => continue,
            got => {
                return Err(QuicTransportError::Unexpected {
                    got,
                    expected: "Proof | ObjectRequest | KeepAlive",
                });
            }
        };
        match reply {
            QuicControlReply::Proof(receipt) => {
                super::send_native_close(cx, &mut link.conn, &mut control)?;
                link.flush(cx).await?;
                if !receipt.committed {
                    return Err(QuicTransportError::Integrity(
                        receipt
                            .reason
                            .clone()
                            .unwrap_or_else(|| "receiver did not commit".to_string()),
                    ));
                }
                return Ok(SendReport {
                    transfer_id: manifest.transfer_id.clone(),
                    bytes_sent: manifest.total_bytes,
                    files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
                    symbols_sent,
                    feedback_rounds,
                    merkle_root_hex: manifest.merkle_root_hex.clone(),
                    receipt,
                    peer: link.peer,
                });
            }
            QuicControlReply::NeedMore(need) => {
                let (next_feedback_round, response_feedback_round) =
                    feedback_round_for_need_or_no_convergence(
                        feedback_rounds,
                        config.max_feedback_rounds,
                        need.feedback_round,
                        need.pending.len(),
                    )?;
                aimd.observe_need_more(cx, config, &need);
                feedback_rounds = next_feedback_round;
                let requested_repair_symbols = need_more_repair_symbol_count(&need);
                let base_deficit_symbols =
                    need_more_base_deficit_symbols(&need, requested_repair_symbols);
                let sender_delivery_loss_for_repair =
                    aimd.sender_delivery_loss_for_repair(need.round_loss_fraction);
                let loss_compensated_target_symbols =
                    loss_compensated_repair_target(base_deficit_symbols, need.round_loss_fraction);
                let sender_loss_compensated_target_symbols = sender_delivery_loss_for_repair
                    .map(|loss| loss_compensated_repair_target(base_deficit_symbols, Some(loss)))
                    .unwrap_or(base_deficit_symbols);
                let loss_compensated_target_symbols =
                    need_more_loss_compensated_target_symbols(&need, base_deficit_symbols)
                        .max(loss_compensated_target_symbols)
                        .max(sender_loss_compensated_target_symbols);
                let repair_blocks_to_send = if need.repair_blocks.is_empty() {
                    Vec::new()
                } else {
                    delivery_loss_compensated_repair_blocks(
                        &need.repair_blocks,
                        sender_delivery_loss_for_repair,
                    )
                };
                let repair_symbols_to_emit = repair_block_symbol_count(&repair_blocks_to_send);
                let loss_compensated_target_symbols =
                    loss_compensated_target_symbols.max(repair_symbols_to_emit);
                let request_gap_to_target = need
                    .repair_request_gap_to_target_symbols
                    .unwrap_or_else(|| {
                        loss_compensated_target_symbols.saturating_sub(requested_repair_symbols)
                    });
                let repair_detail = repair_block_trace_summary(&need.repair_blocks);
                let sender_delivery_loss_for_repair_trace =
                    sender_delivery_loss_for_repair.unwrap_or(0.0);
                quic_rqtrace!(
                    "sender: NeedMore round={feedback_rounds} pending={} repair_blocks={} base_deficit_symbols={} requested_repair_symbols={} repair_symbols_to_emit={} loss_compensated_target_symbols={} request_gap_to_target={} source_requests={} round_symbols_observed={} round_symbols_accepted={} round_loss_fraction={:.4} sender_delivery_loss_for_repair={:.4} max_feedback_rounds={} round_cap_exceeded={} repair_symbol_round_cap={} prior_total_symbols_sent={} prior_round_symbols_sent={} prior_pacing_rate_bps={} repair_blocks_detail={}",
                    need.pending.len(),
                    need.repair_blocks.len(),
                    base_deficit_symbols,
                    requested_repair_symbols,
                    repair_symbols_to_emit,
                    loss_compensated_target_symbols,
                    request_gap_to_target,
                    need.source_symbols.len(),
                    need.round_symbols_observed.unwrap_or(0),
                    need.round_symbols_accepted.unwrap_or(0),
                    need.round_loss_fraction.unwrap_or(0.0),
                    sender_delivery_loss_for_repair_trace,
                    config.max_feedback_rounds,
                    feedback_rounds > config.max_feedback_rounds,
                    super::MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
                    symbols_sent,
                    aimd.last_round_symbols_sent,
                    aimd.last_round_pacing_rate_bps,
                    repair_detail,
                );
                trace_repair_block_deficits("sender", feedback_rounds, &need.repair_blocks);
                super::trace_quic_sender_need_more(
                    cx,
                    feedback_rounds,
                    symbols_sent,
                    aimd.last_round_symbols_sent,
                    &need,
                    config,
                    None,
                    aimd.cap_bps(),
                );
                if need.pending.is_empty()
                    && need.repair_blocks.is_empty()
                    && need.source_symbols.is_empty()
                {
                    super::trace_quic_sender_repair_round(
                        cx,
                        feedback_rounds,
                        super::quic_need_more_response_mode(&need),
                        symbols_sent,
                        0,
                        &need,
                    );
                    send_native_object_complete_for_round(
                        cx,
                        &mut link.conn,
                        &mut control,
                        response_feedback_round,
                        0,
                    )?;
                    link.flush(cx).await?;
                    continue;
                }
                super::validate_need_more_feedback(manifest, config, &need)?;
                let symbols_before = symbols_sent;
                let response_mode = super::quic_need_more_response_mode(&need);
                let sent = if !need.repair_blocks.is_empty() {
                    spray_block_repair_requests(
                        cx,
                        link,
                        &mut control,
                        manifest,
                        &mut encoders,
                        &repair_blocks_to_send,
                        config,
                        symbol_auth.as_ref(),
                        &mut aimd,
                    )
                    .await?
                } else if need.source_symbols.is_empty() {
                    let fallback_pending = need.pending.iter().copied().collect();
                    spray_round(
                        cx,
                        link,
                        &mut control,
                        manifest,
                        &mut encoders,
                        &fallback_pending,
                        config,
                        symbol_auth.as_ref(),
                        false,
                        &mut aimd,
                    )
                    .await?
                } else {
                    spray_source_requests(
                        cx,
                        link,
                        &mut control,
                        manifest,
                        &encoders,
                        &need.source_symbols,
                        config,
                        symbol_auth.as_ref(),
                        &mut aimd,
                    )
                    .await?
                };
                if !need.repair_blocks.is_empty() && sent != repair_symbols_to_emit {
                    return Err(QuicTransportError::Integrity(format!(
                        "sender emitted {sent} repair symbols for loss-compensated repair target {repair_symbols_to_emit}"
                    )));
                }
                symbols_sent = symbols_sent.saturating_add(sent);
                trace_native_repair_accounting(
                    cx,
                    "sender",
                    feedback_rounds,
                    base_deficit_symbols,
                    requested_repair_symbols,
                    loss_compensated_target_symbols,
                    Some(sent),
                    &need,
                );
                super::trace_quic_sender_repair_round(
                    cx,
                    feedback_rounds,
                    response_mode,
                    symbols_before,
                    sent,
                    &need,
                );
                let emission_gap_to_target = loss_compensated_target_symbols.saturating_sub(sent);
                quic_rqtrace!(
                    "sender: repair_round round={feedback_rounds} emitted_symbols={sent} requested_repair_symbols={requested_repair_symbols} loss_compensated_target_symbols={loss_compensated_target_symbols} emission_gap_to_target={emission_gap_to_target} total_symbols_sent={symbols_sent} pacing_rate_bps={} max_feedback_rounds={} round_cap_enforced=false",
                    aimd.last_round_pacing_rate_bps,
                    config.max_feedback_rounds,
                );
                // Flush this round's repair/source symbols before ObjectComplete
                // (same ordering guarantee as the initial spray).
                link.flush(cx).await?;
                let handoff_phase = if need.repair_blocks.is_empty() {
                    "source_requests"
                } else {
                    "repair_blocks"
                };
                link.trace_sender_handoff_summary(cx, handoff_phase, sent);
                send_native_object_complete_for_round(
                    cx,
                    &mut link.conn,
                    &mut control,
                    response_feedback_round,
                    sent,
                )?;
                link.flush(cx).await?;
                if !need.repair_blocks.is_empty() {
                    let _ = link
                        .drop_duplicate_need_more_resends(cx, &mut control, &need)
                        .await?;
                }
            }
        }
    }
}

// ─── Receiver session ───────────────────────────────────────────────────────

struct QuicStagedEntryReceive {
    staging_path: PathBuf,
    created: bool,
    staging_file: Option<crate::fs::File>,
    staging_cursor: Option<u64>,
    staging_unflushed_bytes: usize,
    cache_staging_file: bool,
}

impl QuicStagedEntryReceive {
    fn new(staging_path: PathBuf, entry_size: u64, manifest_entries: usize) -> Self {
        Self {
            staging_path,
            created: false,
            staging_file: None,
            staging_cursor: None,
            staging_unflushed_bytes: 0,
            cache_staging_file: should_cache_quic_staging_file(entry_size, manifest_entries),
        }
    }

    async fn open_staging_file(
        &mut self,
        entry: &super::ManifestEntry,
    ) -> Result<crate::fs::File, QuicTransportError> {
        if let Some(parent) = self.staging_path.parent() {
            crate::fs::create_dir_all(parent).await?;
        }
        if self.created {
            return Ok(crate::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.staging_path)
                .await?);
        }
        let file = crate::fs::File::create_new(&self.staging_path)
            .await
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    QuicTransportError::Integrity(format!(
                        "staging file already exists for entry {}",
                        entry.index
                    ))
                } else {
                    QuicTransportError::from(err)
                }
            })?;
        file.set_len(entry.size).await?;
        self.created = true;
        Ok(file)
    }

    async fn write_block(
        &mut self,
        entry: &super::ManifestEntry,
        block_sbn: u8,
        data: &[u8],
        config: &QuicConfig,
    ) -> Result<(), QuicTransportError> {
        let offset = u64::from(block_sbn)
            .checked_mul(config.max_block_size as u64)
            .ok_or_else(|| {
                QuicTransportError::Integrity("decoded block offset overflow".to_string())
            })?;
        if offset >= entry.size && !data.is_empty() {
            return Err(QuicTransportError::Integrity(format!(
                "decoded block {block_sbn} starts outside entry {} ({} bytes)",
                entry.index, entry.size
            )));
        }
        let end = offset.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        if end > entry.size {
            return Err(QuicTransportError::Integrity(format!(
                "decoded block {block_sbn} overruns entry {}: end {end}, size {}",
                entry.index, entry.size
            )));
        }

        if self.cache_staging_file {
            if self.staging_file.is_none() {
                let file = self.open_staging_file(entry).await?;
                self.staging_file = Some(file);
                self.staging_cursor = None;
                self.staging_unflushed_bytes = 0;
            }

            let next_cursor = offset
                .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    QuicTransportError::Integrity(format!(
                        "entry {} staging cursor overflow",
                        entry.index
                    ))
                })?;
            let unflushed_bytes = self.staging_unflushed_bytes.saturating_add(data.len());
            let should_flush = unflushed_bytes >= QUIC_STAGE_BUFFER_BYTES;
            {
                let file = self.staging_file.as_mut().ok_or_else(|| {
                    QuicTransportError::Integrity(format!(
                        "entry {} staging file missing after open",
                        entry.index
                    ))
                })?;
                if self.staging_cursor != Some(offset) {
                    file.seek(std::io::SeekFrom::Start(offset)).await?;
                }
                file.write_all(data).await?;
                if should_flush {
                    file.flush().await?;
                }
            }
            self.staging_cursor = Some(next_cursor);
            self.staging_unflushed_bytes = if should_flush { 0 } else { unflushed_bytes };
            return Ok(());
        }

        let mut file = self.open_staging_file(entry).await?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        file.write_all(data).await?;
        file.flush().await?;
        Ok(())
    }

    async fn close_cached_staging_file(&mut self) -> Result<(), QuicTransportError> {
        if let Some(mut file) = self.staging_file.take() {
            file.flush().await?;
        }
        self.staging_cursor = None;
        self.staging_unflushed_bytes = 0;
        Ok(())
    }

    async fn flush_cached_staging_file(&mut self) -> Result<(), QuicTransportError> {
        if let Some(file) = self.staging_file.as_mut() {
            file.flush().await?;
        }
        self.staging_unflushed_bytes = 0;
        Ok(())
    }

    async fn ensure_created(
        &mut self,
        entry: &super::ManifestEntry,
    ) -> Result<(), QuicTransportError> {
        if self.created {
            return Ok(());
        }
        let _ = self.open_staging_file(entry).await?;
        Ok(())
    }
}

fn should_cache_quic_staging_file(entry_size: u64, manifest_entries: usize) -> bool {
    entry_size >= QUIC_STAGING_FILE_CACHE_MIN_BYTES
        && manifest_entries <= QUIC_STAGING_FILE_CACHE_MAX_ENTRIES
}

async fn flush_cached_quic_staging_files(
    staged: &mut [QuicStagedEntryReceive],
) -> Result<(), QuicTransportError> {
    for entry in staged {
        entry.flush_cached_staging_file().await?;
    }
    Ok(())
}

fn quic_staging_nonce_hex() -> Result<String, QuicTransportError> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|err| QuicTransportError::Quic(format!("generate staging nonce: {err}")))?;
    Ok(hex_encode(&nonce))
}

#[derive(Debug, Default, Clone, Copy)]
struct NativeReceiverIntakeStats {
    drain_calls: u64,
    symbols_observed: u64,
    symbols_accepted: u64,
    blocks_completed: u64,
    drain_micros: u64,
    pump_calls: u64,
    pump_packets: u64,
    pump_micros: u64,
    staging_write_count: u64,
    staging_write_bytes: u64,
    staging_write_micros: u64,
}

impl NativeReceiverIntakeStats {
    fn record_symbol_drain(
        &mut self,
        elapsed: Duration,
        observed: u64,
        accepted: u64,
        completed_blocks: usize,
    ) {
        self.drain_calls = self.drain_calls.saturating_add(1);
        self.symbols_observed = self.symbols_observed.saturating_add(observed);
        self.symbols_accepted = self.symbols_accepted.saturating_add(accepted);
        self.blocks_completed = self
            .blocks_completed
            .saturating_add(u64::try_from(completed_blocks).unwrap_or(u64::MAX));
        self.drain_micros = self
            .drain_micros
            .saturating_add(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
    }

    fn record_pump(&mut self, elapsed: Duration, packets: usize) {
        self.pump_calls = self.pump_calls.saturating_add(1);
        self.pump_packets = self
            .pump_packets
            .saturating_add(u64::try_from(packets).unwrap_or(u64::MAX));
        self.pump_micros = self
            .pump_micros
            .saturating_add(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
    }

    fn record_staging_write(&mut self, elapsed: Duration, bytes: usize) {
        self.staging_write_count = self.staging_write_count.saturating_add(1);
        self.staging_write_bytes = self
            .staging_write_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        self.staging_write_micros = self
            .staging_write_micros
            .saturating_add(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
    }

    fn record_completed_blocks(&mut self, completed_blocks: usize) {
        self.blocks_completed = self
            .blocks_completed
            .saturating_add(u64::try_from(completed_blocks).unwrap_or(u64::MAX));
    }

    fn trace_need_more(&self, cx: &Cx, round: u32, need: &QuicNeedMore) {
        let round = round.to_string();
        let pending = need.pending.len().to_string();
        let repair_blocks = need.repair_blocks.len().to_string();
        let repair_symbols = need
            .repair_blocks
            .iter()
            .fold(0u64, |acc, request| {
                acc.saturating_add(u64::from(request.symbols))
            })
            .to_string();
        let source_symbols = need.source_symbols.len().to_string();
        let round_symbols_observed = need.round_symbols_observed.unwrap_or(0).to_string();
        let round_symbols_accepted = need.round_symbols_accepted.unwrap_or(0).to_string();
        let round_loss_fraction = format!("{:.4}", need.round_loss_fraction.unwrap_or(0.0));
        let pending_rank = need.pending_rank.unwrap_or(0).to_string();
        let pending_rank_columns = need.pending_rank_columns.unwrap_or(0).to_string();
        let pending_rank_deficit = need.pending_rank_deficit.unwrap_or(0).to_string();
        let pending_decode_jobs = need.pending_decode_jobs.unwrap_or(0).to_string();
        let repair_block_requests = super::quic_repair_block_request_summary(&need.repair_blocks);
        let repair_symbol_round_cap = super::MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND.to_string();
        let repair_block_request_cap =
            super::MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND.to_string();
        let drain_calls = self.drain_calls.to_string();
        let symbols_observed = self.symbols_observed.to_string();
        let symbols_accepted = self.symbols_accepted.to_string();
        let blocks_completed = self.blocks_completed.to_string();
        let drain_micros = self.drain_micros.to_string();
        let pump_calls = self.pump_calls.to_string();
        let pump_packets = self.pump_packets.to_string();
        let pump_micros = self.pump_micros.to_string();
        let staging_write_count = self.staging_write_count.to_string();
        let staging_write_bytes = self.staging_write_bytes.to_string();
        let staging_write_micros = self.staging_write_micros.to_string();
        cx.trace_with_fields(
            "atp_quic.receive.need_more",
            &[
                ("round", round.as_str()),
                ("pending", pending.as_str()),
                ("repair_blocks", repair_blocks.as_str()),
                ("repair_symbols", repair_symbols.as_str()),
                ("source_symbols", source_symbols.as_str()),
                ("round_symbols_observed", round_symbols_observed.as_str()),
                ("round_symbols_accepted", round_symbols_accepted.as_str()),
                ("round_loss_fraction", round_loss_fraction.as_str()),
                ("pending_rank", pending_rank.as_str()),
                ("pending_rank_columns", pending_rank_columns.as_str()),
                ("pending_rank_deficit", pending_rank_deficit.as_str()),
                ("pending_decode_jobs", pending_decode_jobs.as_str()),
                ("repair_block_requests", repair_block_requests.as_str()),
                ("repair_symbol_round_cap", repair_symbol_round_cap.as_str()),
                (
                    "repair_block_request_cap",
                    repair_block_request_cap.as_str(),
                ),
                ("drain_calls", drain_calls.as_str()),
                ("symbols_observed", symbols_observed.as_str()),
                ("symbols_accepted", symbols_accepted.as_str()),
                ("blocks_completed", blocks_completed.as_str()),
                ("drain_micros", drain_micros.as_str()),
                ("pump_calls", pump_calls.as_str()),
                ("pump_packets", pump_packets.as_str()),
                ("pump_micros", pump_micros.as_str()),
                ("staging_write_count", staging_write_count.as_str()),
                ("staging_write_bytes", staging_write_bytes.as_str()),
                ("staging_write_micros", staging_write_micros.as_str()),
            ],
        );
    }

    fn trace_summary(&self, cx: &Cx, transfer_id: &str) {
        let drain_calls = self.drain_calls.to_string();
        let symbols_observed = self.symbols_observed.to_string();
        let symbols_accepted = self.symbols_accepted.to_string();
        let blocks_completed = self.blocks_completed.to_string();
        let drain_micros = self.drain_micros.to_string();
        let pump_calls = self.pump_calls.to_string();
        let pump_packets = self.pump_packets.to_string();
        let pump_micros = self.pump_micros.to_string();
        let staging_write_count = self.staging_write_count.to_string();
        let staging_write_bytes = self.staging_write_bytes.to_string();
        let staging_write_micros = self.staging_write_micros.to_string();
        cx.trace_with_fields(
            "atp_quic.receive.intake",
            &[
                ("transfer_id", transfer_id),
                ("drain_calls", drain_calls.as_str()),
                ("symbols_observed", symbols_observed.as_str()),
                ("symbols_accepted", symbols_accepted.as_str()),
                ("blocks_completed", blocks_completed.as_str()),
                ("drain_micros", drain_micros.as_str()),
                ("pump_calls", pump_calls.as_str()),
                ("pump_packets", pump_packets.as_str()),
                ("pump_micros", pump_micros.as_str()),
                ("staging_write_count", staging_write_count.as_str()),
                ("staging_write_bytes", staging_write_bytes.as_str()),
                ("staging_write_micros", staging_write_micros.as_str()),
            ],
        );
    }
}

async fn commit_staged_entries(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
    dest_dir: &Path,
    manifest: &TransferManifest,
    staged: &mut [QuicStagedEntryReceive],
    config: &QuicConfig,
) -> Result<(ReceiveReceipt, Vec<PathBuf>), QuicTransportError> {
    let mut read_buf = vec![0_u8; config.chunk_size.max(1)];
    let mut sha_ok = true;
    let mut digests = Vec::with_capacity(manifest.entries.len());
    for (entry, staged_entry) in manifest.entries.iter().zip(staged.iter_mut()) {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        send_and_flush_native_keep_alive(cx, link, control).await?;
        staged_entry.close_cached_staging_file().await?;
        staged_entry.ensure_created(entry).await?;
        let (size, content_id, content_sha256) =
            hash_file_streaming(&staged_entry.staging_path, &mut read_buf).await?;
        if size != entry.size || hex_encode(&content_sha256) != entry.sha256_hex {
            sha_ok = false;
        }
        digests.push(EntryDigest {
            rel_path: entry.rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
        send_and_flush_native_keep_alive(cx, link, control).await?;
    }

    let merkle_ok = flat_merkle_root_from_digests(&digests) == manifest.merkle_root_hex;
    let metadata_ok = super::manifest_metadata_commitment(manifest) == manifest.metadata_root_hex;
    let committed = sha_ok && merkle_ok && metadata_ok;
    let mut committed_paths = Vec::new();
    if committed {
        let base = super::quic_safe_base_for_root_name(dest_dir, &manifest.root_name)?;
        if manifest.is_directory && manifest.entries.is_empty() {
            super::reject_quic_destination_symlink_prefix(&base, &base).await?;
            crate::fs::create_dir_all(&base).await?;
            committed_paths.push(base.clone());
            send_and_flush_native_keep_alive(cx, link, control).await?;
        }
        for (entry, staged_entry) in manifest.entries.iter().zip(staged.iter_mut()) {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            send_and_flush_native_keep_alive(cx, link, control).await?;
            staged_entry.close_cached_staging_file().await?;
            let out_path = if manifest.is_directory {
                super::quic_join_relative(&base, &entry.rel_path)?
            } else {
                base.clone()
            };
            match super::commit_quic_metadata_entry(cx, &base, &out_path, entry, config).await? {
                super::QuicMetadataCommit::Committed => {
                    committed_paths.push(out_path);
                    send_and_flush_native_keep_alive(cx, link, control).await?;
                    continue;
                }
                super::QuicMetadataCommit::Skipped => continue,
                super::QuicMetadataCommit::Regular => {}
            }
            super::reject_quic_destination_symlink_prefix(&base, &out_path).await?;
            if let Some(parent) = out_path.parent() {
                crate::fs::create_dir_all(parent).await?;
            }
            crate::fs::rename(&staged_entry.staging_path, &out_path).await?;
            super::apply_quic_entry_metadata(cx, &out_path, entry).await?;
            committed_paths.push(out_path);
            send_and_flush_native_keep_alive(cx, link, control).await?;
        }
    }

    let bytes_received = digests
        .iter()
        .fold(0u64, |acc, digest| acc.saturating_add(digest.size));
    Ok((
        ReceiveReceipt {
            committed,
            bytes_received,
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
            } else {
                Some("metadata commitment mismatch".to_string())
            },
            committed_paths: committed_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
        },
        committed_paths,
    ))
}

#[allow(dead_code)]
async fn read_native_source_stream_chunk(
    cx: &Cx,
    link: &mut QuicLink,
    stream: StreamId,
    max_len: usize,
    idle_timeout: Duration,
) -> Result<Bytes, QuicTransportError> {
    loop {
        match link.conn.read_stream_bytes(cx, stream, max_len) {
            Ok(chunk) => {
                if !chunk.is_empty() || link.conn.is_stream_read_eof(stream)? {
                    return Ok(chunk);
                }
            }
            Err(NativeQuicConnectionError::StreamTable(StreamTableError::UnknownStream(
                unknown,
            ))) if unknown == stream => {}
            Err(err) => return Err(err.into()),
        }
        if link.pump_inbound_for(cx, idle_timeout).await? == 0 {
            return Err(QuicTransportError::Timeout {
                operation: "receive QUIC source stream",
                timeout: idle_timeout,
            });
        }
        let _ = link.flush(cx).await?;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SourceSymbolKey {
    entry: u32,
    sbn: u8,
    esi: u32,
}

#[derive(Debug, Clone, Copy)]
struct SourceStreamEntryPlan {
    entry: u32,
    stream_start: u64,
    size: u64,
}

impl SourceStreamEntryPlan {
    fn stream_end(self) -> u64 {
        self.stream_start.saturating_add(self.size)
    }
}

struct PartialSourceSymbol {
    data: Vec<u8>,
    received: Vec<bool>,
    received_count: usize,
}

impl PartialSourceSymbol {
    fn new(symbol_size: usize, expected_len: usize) -> Self {
        Self {
            data: vec![0; symbol_size],
            received: vec![false; expected_len],
            received_count: 0,
        }
    }

    fn push_fragment(
        &mut self,
        offset: usize,
        fragment: &[u8],
    ) -> Result<bool, QuicTransportError> {
        if offset.saturating_add(fragment.len()) > self.received.len() {
            return Err(QuicTransportError::Integrity(
                "source stream frame crossed a RaptorQ source-symbol boundary".to_string(),
            ));
        }
        for (idx, byte) in fragment.iter().enumerate() {
            let pos = offset + idx;
            if !self.received[pos] {
                self.data[pos] = *byte;
                self.received[pos] = true;
                self.received_count = self.received_count.saturating_add(1);
            }
        }
        Ok(self.received_count == self.received.len())
    }
}

struct NativeSourceStreamSymbolIntake {
    plans: Vec<SourceStreamEntryPlan>,
    partials: BTreeMap<SourceSymbolKey, PartialSourceSymbol>,
    fed: BTreeSet<SourceSymbolKey>,
    total_bytes: u64,
    fin_seen: bool,
}

impl NativeSourceStreamSymbolIntake {
    fn new(manifest: &TransferManifest) -> Result<Self, QuicTransportError> {
        let mut stream_start = 0u64;
        let mut plans = Vec::with_capacity(manifest.entries.len());
        for entry in &manifest.entries {
            plans.push(SourceStreamEntryPlan {
                entry: entry.index,
                stream_start,
                size: entry.size,
            });
            stream_start = stream_start.checked_add(entry.size).ok_or_else(|| {
                QuicTransportError::TooLarge {
                    size: manifest.total_bytes,
                    max: u64::MAX,
                }
            })?;
        }
        if stream_start != manifest.total_bytes {
            return Err(QuicTransportError::Integrity(format!(
                "source stream manifest total {} did not match entry sum {stream_start}",
                manifest.total_bytes
            )));
        }
        Ok(Self {
            plans,
            partials: BTreeMap::new(),
            fed: BTreeSet::new(),
            total_bytes: manifest.total_bytes,
            fin_seen: false,
        })
    }

    fn fin_seen(&self) -> bool {
        self.fin_seen
    }

    fn feed_stream_frame(
        &mut self,
        cx: &Cx,
        decoders: &mut [super::QuicEntryDecoder],
        config: &QuicConfig,
        decode_stats: &mut super::QuicDecodeStats,
        completed_backlog: &mut Vec<super::QuicDecodedBlock>,
        frame: &ReceivedSourceStreamFrame,
    ) -> Result<u64, QuicTransportError> {
        let frame_len = u64::try_from(frame.data.len()).unwrap_or(u64::MAX);
        let frame_end = frame.offset.checked_add(frame_len).ok_or_else(|| {
            QuicTransportError::Integrity("source stream frame offset overflow".to_string())
        })?;
        if frame_end > self.total_bytes {
            return Err(QuicTransportError::Integrity(format!(
                "source stream carried bytes beyond the manifest total: end={frame_end}, total={}",
                self.total_bytes
            )));
        }
        if frame.fin {
            if frame_end != self.total_bytes {
                return Err(QuicTransportError::Integrity(format!(
                    "source stream FIN at offset {frame_end}, expected {}",
                    self.total_bytes
                )));
            }
            self.fin_seen = true;
        }
        if frame.data.is_empty() {
            return Ok(0);
        }
        self.feed_global_bytes(
            cx,
            decoders,
            config,
            decode_stats,
            completed_backlog,
            frame.offset,
            frame.data.as_ref(),
        )
    }

    fn feed_global_bytes(
        &mut self,
        cx: &Cx,
        decoders: &mut [super::QuicEntryDecoder],
        config: &QuicConfig,
        decode_stats: &mut super::QuicDecodeStats,
        completed_backlog: &mut Vec<super::QuicDecodedBlock>,
        stream_offset: u64,
        bytes: &[u8],
    ) -> Result<u64, QuicTransportError> {
        let mut accepted = 0u64;
        let mut consumed = 0usize;
        while consumed < bytes.len() {
            let absolute = stream_offset
                .checked_add(u64::try_from(consumed).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    QuicTransportError::Integrity("source stream offset overflow".to_string())
                })?;
            let Some(plan) = self
                .plans
                .iter()
                .copied()
                .find(|plan| absolute >= plan.stream_start && absolute < plan.stream_end())
            else {
                return Err(QuicTransportError::Integrity(format!(
                    "source stream frame offset {absolute} outside manifest entries"
                )));
            };
            let entry_offset = absolute.saturating_sub(plan.stream_start);
            let available_in_entry =
                usize::try_from(plan.stream_end().saturating_sub(absolute)).unwrap_or(usize::MAX);
            let take = (bytes.len() - consumed).min(available_in_entry);
            accepted = accepted.saturating_add(self.feed_entry_bytes(
                cx,
                decoders,
                config,
                decode_stats,
                completed_backlog,
                plan,
                entry_offset,
                &bytes[consumed..consumed + take],
            )?);
            consumed += take;
        }
        Ok(accepted)
    }

    fn feed_entry_bytes(
        &mut self,
        cx: &Cx,
        decoders: &mut [super::QuicEntryDecoder],
        config: &QuicConfig,
        decode_stats: &mut super::QuicDecodeStats,
        completed_backlog: &mut Vec<super::QuicDecodedBlock>,
        plan: SourceStreamEntryPlan,
        entry_offset: u64,
        bytes: &[u8],
    ) -> Result<u64, QuicTransportError> {
        let symbol_size = usize::from(config.symbol_size.max(1));
        let symbol_size_u64 = u64::try_from(symbol_size).unwrap_or(u64::MAX);
        let max_block_size = u64::try_from(config.max_block_size.max(1)).unwrap_or(u64::MAX);
        let mut accepted = 0u64;
        let mut consumed = 0usize;
        while consumed < bytes.len() {
            let offset = entry_offset
                .checked_add(u64::try_from(consumed).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    QuicTransportError::Integrity("entry source stream offset overflow".to_string())
                })?;
            let block_index = offset / max_block_size;
            let sbn = u8::try_from(block_index).map_err(|_| QuicTransportError::TooLarge {
                size: plan.size,
                max: max_block_size.saturating_mul(u64::from(u8::MAX) + 1),
            })?;
            let block_start = block_index.saturating_mul(max_block_size);
            let block_len = plan.size.saturating_sub(block_start).min(max_block_size);
            let block_offset = offset.saturating_sub(block_start);
            let esi_u64 = block_offset / symbol_size_u64;
            let esi = u32::try_from(esi_u64).map_err(|_| {
                QuicTransportError::Integrity("source symbol ESI exceeded u32 range".to_string())
            })?;
            let symbol_offset_u64 = block_offset % symbol_size_u64;
            let symbol_start = esi_u64.saturating_mul(symbol_size_u64);
            let expected_len = usize::try_from(
                block_len
                    .saturating_sub(symbol_start)
                    .min(symbol_size_u64)
                    .max(1),
            )
            .unwrap_or(usize::MAX);
            let symbol_offset = usize::try_from(symbol_offset_u64).unwrap_or(usize::MAX);
            let available_in_symbol = expected_len.saturating_sub(symbol_offset);
            let take = (bytes.len() - consumed).min(available_in_symbol);
            if take == 0 {
                return Err(QuicTransportError::Integrity(
                    "source stream symbol split made no progress".to_string(),
                ));
            }
            accepted = accepted.saturating_add(self.feed_symbol_fragment(
                cx,
                decoders,
                config,
                decode_stats,
                completed_backlog,
                SourceSymbolKey {
                    entry: plan.entry,
                    sbn,
                    esi,
                },
                symbol_size,
                expected_len,
                symbol_offset,
                &bytes[consumed..consumed + take],
            )?);
            consumed += take;
        }
        Ok(accepted)
    }

    fn feed_symbol_fragment(
        &mut self,
        cx: &Cx,
        decoders: &mut [super::QuicEntryDecoder],
        config: &QuicConfig,
        decode_stats: &mut super::QuicDecodeStats,
        completed_backlog: &mut Vec<super::QuicDecodedBlock>,
        key: SourceSymbolKey,
        symbol_size: usize,
        expected_len: usize,
        symbol_offset: usize,
        fragment: &[u8],
    ) -> Result<u64, QuicTransportError> {
        if self.fed.contains(&key) {
            return Ok(0);
        }
        let complete = {
            let partial = self
                .partials
                .entry(key)
                .or_insert_with(|| PartialSourceSymbol::new(symbol_size, expected_len));
            partial.push_fragment(symbol_offset, fragment)?
        };
        if !complete {
            return Ok(0);
        }
        let partial = self.partials.remove(&key).ok_or_else(|| {
            QuicTransportError::Integrity("completed source symbol disappeared".to_string())
        })?;
        self.fed.insert(key);
        let decoder_index = decoders
            .iter()
            .position(|decoder| decoder.index == key.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "source stream symbol for unknown manifest entry {}",
                    key.entry
                ))
            })?;
        let symbol = Symbol::new(
            SymbolId::new(decoders[decoder_index].object_id, key.sbn, key.esi),
            partial.data,
            SymbolKind::Source,
        );
        let transfer_decode_width = super::quic_transfer_decode_width(decoders, config);
        let allow_spawn_decode = super::quic_pending_decode_jobs(decoders) < transfer_decode_width;
        let (accepted, decoded) = super::feed_authenticated_symbol_take_block_deferred(
            cx,
            &mut decoders[decoder_index],
            AuthenticatedSymbol::new_unauthenticated(symbol),
            config,
            decode_stats,
            allow_spawn_decode,
            transfer_decode_width,
        )?;
        if let Some(block) = decoded {
            completed_backlog.push(block);
        }
        Ok(u64::from(accepted))
    }
}

async fn drain_native_source_stream_tap_frames(
    cx: &Cx,
    link: &mut QuicLink,
    intake: &mut NativeSourceStreamSymbolIntake,
    decoders: &mut [super::QuicEntryDecoder],
    config: &QuicConfig,
    decode_stats: &mut super::QuicDecodeStats,
    completed_backlog: &mut Vec<super::QuicDecodedBlock>,
) -> Result<(usize, u64), QuicTransportError> {
    let frames = link.drain_received_source_stream_frames();
    let mut accepted = 0u64;
    for frame in &frames {
        accepted = accepted.saturating_add(intake.feed_stream_frame(
            cx,
            decoders,
            config,
            decode_stats,
            completed_backlog,
            frame,
        )?);
    }
    if !frames.is_empty() {
        let transfer_decode_width = super::quic_transfer_decode_width(decoders, config);
        let allow_spawn_decode = super::quic_pending_decode_jobs(decoders) < transfer_decode_width;
        completed_backlog.extend(
            super::drain_ready_quic_decodes_with_blocks(
                cx,
                decoders,
                config,
                decode_stats,
                allow_spawn_decode,
                transfer_decode_width,
            )
            .await?,
        );
    }
    Ok((frames.len(), accepted))
}

async fn receive_native_source_stream_entries_pumped(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
    stream: StreamId,
    manifest: &TransferManifest,
    staged: &mut [QuicStagedEntryReceive],
    decoders: &mut [super::QuicEntryDecoder],
    config: &QuicConfig,
) -> Result<(u64, u64, super::QuicDecodeStats), QuicTransportError> {
    let _ = stream;
    let mut intake = NativeSourceStreamSymbolIntake::new(manifest)?;
    let mut symbols_accepted = 0u64;
    let mut decode_stats = super::QuicDecodeStats::default();
    let mut intake_stats = NativeReceiverIntakeStats::default();
    let mut completed_backlog = Vec::new();
    let mut last_progress = Instant::now();
    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;

        let (stream_frames, stream_symbols) = drain_native_source_stream_tap_frames(
            cx,
            link,
            &mut intake,
            decoders,
            config,
            &mut decode_stats,
            &mut completed_backlog,
        )
        .await?;
        if stream_frames > 0 || stream_symbols > 0 {
            symbols_accepted = symbols_accepted.saturating_add(stream_symbols);
            last_progress = Instant::now();
        }

        let (observed, accepted) = drain_native_receiver_symbol_queue(
            cx,
            link,
            manifest,
            decoders,
            config,
            &mut decode_stats,
            &mut intake_stats,
            &mut completed_backlog,
            super::NativeSymbolDrainMode::ReadyOnly,
            RECEIVER_SYMBOL_DRAIN_BATCHES_PER_SOCKET_POLL,
        )
        .await?;
        if observed > 0 || accepted > 0 {
            symbols_accepted = symbols_accepted.saturating_add(accepted);
            last_progress = Instant::now();
            send_native_keep_alive(cx, &mut link.conn, control)?;
        }

        write_completed_native_blocks(
            cx,
            link,
            control,
            manifest,
            staged,
            config,
            &mut intake_stats,
            &mut completed_backlog,
        )
        .await?;
        if super::pending_entries(decoders).is_empty() && intake.fin_seen() {
            flush_cached_quic_staging_files(staged).await?;
            return Ok((manifest.total_bytes, symbols_accepted, decode_stats));
        }

        link.flush(cx).await?;
        let pump_started = Instant::now();
        let pumped_packets = link
            .pump_inbound_for_with_drain_budget(
                cx,
                SOURCE_STREAM_PTO,
                RECEIVER_SYMBOL_DRAIN_BATCHES_PER_SOCKET_POLL,
            )
            .await?;
        intake_stats.record_pump(pump_started.elapsed(), pumped_packets);
        if pumped_packets > 0 {
            last_progress = Instant::now();
            continue;
        }
        if last_progress.elapsed() >= config.idle_timeout {
            return Err(QuicTransportError::Timeout {
                operation: "receive QUIC source stream",
                timeout: config.idle_timeout,
            });
        }
    }
}

async fn drain_native_receiver_symbol_queue(
    cx: &Cx,
    link: &mut QuicLink,
    manifest: &TransferManifest,
    decoders: &mut [super::QuicEntryDecoder],
    config: &QuicConfig,
    decode_stats: &mut super::QuicDecodeStats,
    intake_stats: &mut NativeReceiverIntakeStats,
    completed_backlog: &mut Vec<super::QuicDecodedBlock>,
    drain_mode: super::NativeSymbolDrainMode,
    max_batches: usize,
) -> Result<(u64, u64), QuicTransportError> {
    let drain_started = Instant::now(); // ubs:ignore - monotonic intake timing, not crypto randomness
    let (observed, accepted, completed_blocks) = super::drain_native_symbol_datagrams_with_blocks(
        cx,
        &mut link.conn,
        manifest,
        decoders,
        config,
        decode_stats,
        drain_mode,
        max_batches,
    )
    .await?;
    intake_stats.record_symbol_drain(
        drain_started.elapsed(),
        observed,
        accepted,
        completed_blocks.len(),
    );
    completed_backlog.extend(completed_blocks);
    Ok((observed, accepted))
}

async fn join_native_receiver_decode_jobs(
    cx: &Cx,
    decoders: &mut [super::QuicEntryDecoder],
    config: &QuicConfig,
    decode_stats: &mut super::QuicDecodeStats,
    intake_stats: &mut NativeReceiverIntakeStats,
    completed_backlog: &mut Vec<super::QuicDecodedBlock>,
) -> Result<(), QuicTransportError> {
    let completed =
        super::join_native_symbol_decode_jobs_with_blocks(cx, decoders, config, decode_stats)
            .await?;
    intake_stats.record_completed_blocks(completed.len());
    completed_backlog.extend(completed);
    Ok(())
}

async fn pump_native_receiver_ready(
    cx: &Cx,
    link: &mut QuicLink,
    intake_stats: &mut NativeReceiverIntakeStats,
) -> Result<usize, QuicTransportError> {
    let pump_started = Instant::now(); // ubs:ignore - monotonic pump timing, not crypto randomness
    let pumped_packets = link
        .pump_inbound_for_with_drain_budget(
            cx,
            Duration::ZERO,
            RECEIVER_SYMBOL_DRAIN_BATCHES_PER_SOCKET_POLL,
        )
        .await?;
    intake_stats.record_pump(pump_started.elapsed(), pumped_packets);
    Ok(pumped_packets)
}

async fn write_completed_native_blocks(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    staged: &mut [QuicStagedEntryReceive],
    config: &QuicConfig,
    intake_stats: &mut NativeReceiverIntakeStats,
    completed_backlog: &mut Vec<super::QuicDecodedBlock>,
) -> Result<(), QuicTransportError> {
    for block in completed_backlog.drain(..) {
        send_and_flush_native_keep_alive(cx, link, control).await?;
        let entry = manifest
            .entries
            .iter()
            .find(|entry| entry.index == block.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "decoded block for unknown entry {}",
                    block.entry
                ))
            })?;
        let staged_entry = staged
            .get_mut(usize::try_from(block.entry).unwrap_or(usize::MAX))
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "decoded block for out-of-range entry {}",
                    block.entry
                ))
            })?;
        let write_started = Instant::now(); // ubs:ignore - monotonic staging timing, not crypto randomness
        staged_entry
            .write_block(entry, block.sbn, &block.data, config)
            .await?;
        intake_stats.record_staging_write(write_started.elapsed(), block.data.len());
        send_and_flush_native_keep_alive(cx, link, control).await?;
    }
    Ok(())
}

/// Drive a full ATP-over-QUIC receive over an established link: Hello+ack,
/// manifest, then symbol rounds with fountain feedback until every entry decodes,
/// then verify + atomic commit and return a [`ReceiveReport`].
async fn run_receiver_session(
    cx: &Cx,
    link: &mut QuicLink,
    dest_dir: &Path,
    config: &QuicConfig,
    peer_id: &str,
) -> Result<ReceiveReport, QuicTransportError> {
    config.validate()?;
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();
    let mut control = NativeQuicFrameTransport::for_stream(super::first_client_bidi_stream());

    // Hello + ack.
    let hello_frame = link
        .next_control_frame(cx, &mut control, "receive sender handshake")
        .await?;
    if hello_frame.frame_type() != FrameType::Handshake {
        return Err(QuicTransportError::Unexpected {
            got: hello_frame.frame_type(),
            expected: "Handshake",
        });
    }
    let hello: QuicHello = super::parse_json(&hello_frame)?;
    let reason = super::reject_hello_reason(&hello, config, symbol_auth_enabled);
    let accepted = reason.is_none();
    let accepted_source_stream = accepted
        && hello.source_stream
        && super::quic_native_source_stream_enabled(hello.total_bytes, config, &link.conn);
    let ack = QuicHelloAck {
        accepted,
        peer_id: peer_id.to_string(),
        source_stream: accepted_source_stream,
        reason: reason.clone(),
    };
    let ack_frame = super::json_frame(FrameType::HandshakeAck, &ack)?;
    control.send(cx, &mut link.conn, &ack_frame)?;
    link.flush(cx).await?;
    if let Some(reason) = reason {
        return Err(QuicTransportError::HandshakeRejected(reason));
    }
    let source_stream = if accepted_source_stream {
        super::source_stream_from_hello(&hello)?
    } else {
        None
    };

    // Manifest.
    let manifest_frame = link
        .next_control_frame(cx, &mut control, "receive transfer manifest")
        .await?;
    let manifest: TransferManifest =
        super::parse_json_frame(&manifest_frame, FrameType::ObjectManifest, "ObjectManifest")?;
    super::validate_quic_manifest(&manifest, config)?;
    link.flush(cx).await?;

    let mut decoders = super::decoders_from_manifest(&manifest, config)?;
    let staging_seq = QUIC_STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
    let staging_nonce = quic_staging_nonce_hex()?;
    let staging_dir = dest_dir.join(format!(
        ".atp-quic-staging-{}-{staging_nonce}-{staging_seq}",
        manifest.transfer_id
    ));
    // Reclaim any stale scratch directory before use. This mirrors the TCP
    // receiver and prevents stale entries or hostile symlinks under a reused
    // staging name from being trusted by the decoded-block writer.
    let _ = crate::fs::remove_dir_all(&staging_dir).await;
    crate::fs::create_dir_all(&staging_dir).await?;
    let mut staging_guard = QuicStagingDirGuard::new(staging_dir.clone());
    let mut staged = manifest
        .entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            QuicStagedEntryReceive::new(
                staging_dir.join(i.to_string()),
                entry.size,
                manifest.entries.len(),
            )
        })
        .collect::<Vec<_>>();
    if let Some(source_stream) = source_stream {
        let previous_paced_source_stream = link.paced_source_stream.replace(source_stream);
        let source_receive_result: Result<ReceiveReport, QuicTransportError> = async {
            if hello.total_bytes != manifest.total_bytes {
                return Err(QuicTransportError::Integrity(format!(
                    "source stream hello total_bytes {} did not match manifest total_bytes {}",
                    hello.total_bytes, manifest.total_bytes
                )));
            }
            if !super::quic_native_source_stream_enabled(manifest.total_bytes, config, &link.conn) {
                return Err(QuicTransportError::Integrity(format!(
                    "sender advertised QUIC source stream {} for a non-clean or oversized transfer",
                    source_stream.0
                )));
            }
            let (bytes_received, symbols_accepted, decode_stats) =
                receive_native_source_stream_entries_pumped(
                    cx,
                    link,
                    &mut control,
                    source_stream,
                    &manifest,
                    &mut staged,
                    &mut decoders,
                    config,
                )
                .await?;
            quic_rqtrace!(
                "receiver: native_source_stream received bytes={} stream={} symbols_accepted={} decode_count={}",
                bytes_received,
                source_stream.0,
                symbols_accepted,
                decode_stats.decode_count
            );
            let complete_frame = link
                .next_control_frame(cx, &mut control, "receive source-stream object-complete")
                .await?;
            if complete_frame.frame_type() != FrameType::ObjectComplete {
                return Err(QuicTransportError::Unexpected {
                    got: complete_frame.frame_type(),
                    expected: "ObjectComplete",
                });
            }
            let complete = super::parse_quic_round_complete(&complete_frame)?;
            if complete.round != 0 {
                return Err(QuicTransportError::Integrity(format!(
                    "source-stream ObjectComplete must be round=0, got round={} symbols={}",
                    complete.round, complete.round_symbols_sent
                )));
            }
            let (mut receipt, committed_paths) = commit_staged_entries(
                cx,
                link,
                &mut control,
                dest_dir,
                &manifest,
                &mut staged,
                config,
            )
            .await?;
            receipt.symbols_accepted = symbols_accepted;
            receipt.feedback_rounds = 0;
            receipt.decode_count = decode_stats.decode_count;
            receipt.decode_micros = decode_stats.decode_micros;
            send_native_proof_until_close(cx, link, &mut control, &receipt, config).await?;
            let _ = super::send_native_close(cx, &mut link.conn, &mut control);
            let _ = link.flush(cx).await;
            if !receipt.committed {
                return Err(QuicTransportError::Integrity(
                    receipt
                        .reason
                        .clone()
                        .unwrap_or_else(|| "receiver did not commit".to_string()),
                ));
            }
            Ok(ReceiveReport {
                transfer_id: manifest.transfer_id.clone(),
                bytes_received: receipt.bytes_received,
                files: receipt.files,
                committed: true,
                symbols_accepted: receipt.symbols_accepted,
                feedback_rounds: receipt.feedback_rounds,
                decode_count: receipt.decode_count,
                decode_micros: receipt.decode_micros,
                committed_paths,
                peer: link.peer,
            })
        }
        .await;
        link.paced_source_stream = previous_paced_source_stream;
        for staged_entry in &mut staged {
            let _ = staged_entry.close_cached_staging_file().await;
        }
        let _ = crate::fs::remove_dir_all(&staging_dir).await;
        staging_guard.disarm();
        return source_receive_result;
    }

    let mut symbols_accepted = 0u64;
    let mut feedback_rounds = 0u32;
    let mut decode_stats = super::QuicDecodeStats::default();
    let mut intake_stats = NativeReceiverIntakeStats::default();
    // Control-plane PTO state: the last NeedMore we sent, the STREAM offsets that
    // carried it, and how many times we have requeued those offsets while awaiting
    // this round's repair. This fills a missing STREAM gap instead of appending a
    // duplicate NeedMore behind bytes the peer cannot yet read.
    let mut last_need: Option<(QuicNeedMore, Vec<SentControlStreamFrame>)> = None;
    let mut needmore_pto_attempts = 0u32;
    let needmore_pto_max_attempts = needmore_pto_attempt_budget(config.idle_timeout);

    let receive_result: Result<ReceiveReport, QuicTransportError> = async {
        'rounds: loop {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            let mut round_symbols_observed = 0u64;
            let mut round_symbols_accepted = 0u64;
            // Drain symbols and wait for this round's ObjectComplete marker, pumping
            // the socket and draining the bounded inbound DATAGRAM queue each step so
            // no symbol is dropped while we wait. `pump_inbound` returns 0 only after a
            // full idle window with no traffic, which means the sender went silent. If
            // the round made progress, silence is enough to request repair for the
            // remaining gaps even when the best-effort ObjectComplete marker was lost.
            let expected_round_complete = feedback_rounds;
            let mut round_complete = super::QuicRoundComplete {
                round: expected_round_complete,
                ..super::QuicRoundComplete::default()
            };
            let mut completed_backlog = Vec::new();
            loop {
                let (observed, accepted) = drain_native_receiver_symbol_queue(
                    cx,
                    link,
                    &manifest,
                    &mut decoders,
                    config,
                    &mut decode_stats,
                    &mut intake_stats,
                    &mut completed_backlog,
                    super::NativeSymbolDrainMode::ReadyOnly,
                    RECEIVER_SYMBOL_DRAIN_BATCHES_PER_SOCKET_POLL,
                )
                .await?;
                round_symbols_observed = round_symbols_observed.saturating_add(observed);
                round_symbols_accepted = round_symbols_accepted.saturating_add(accepted);
                symbols_accepted = symbols_accepted.saturating_add(accepted);
                if observed > 0 {
                    // Repair (or spray) is flowing again — reset the control-PTO budget.
                    needmore_pto_attempts = 0;
                    send_native_keep_alive(cx, &mut link.conn, &mut control)?;
                }
                if pump_native_receiver_ready(cx, link, &mut intake_stats).await? > 0
                    || link.conn.pending_datagram_count() > 0
                {
                    continue;
                }
                write_completed_native_blocks(
                    cx,
                    link,
                    &mut control,
                    &manifest,
                    &mut staged,
                    config,
                    &mut intake_stats,
                    &mut completed_backlog,
                )
                .await?;
                if super::pending_entries(&decoders).is_empty() {
                    // Once all entries decode, Proof can complete the transfer even
                    // if the best-effort ObjectComplete control packet was dropped.
                    flush_cached_quic_staging_files(&mut staged).await?;
                    break 'rounds;
                }
                if let Some(frame) = control.try_recv(cx, &mut link.conn)? {
                    match frame.frame_type() {
                        FrameType::ObjectComplete => {
                            let complete = super::parse_quic_round_complete(&frame)?;
                            if complete.round != expected_round_complete {
                                trace_stale_round_complete(cx, expected_round_complete, &complete);
                                continue;
                            }
                            round_complete = complete;
                            if pump_native_receiver_ready(cx, link, &mut intake_stats).await? > 0
                                || link.conn.pending_datagram_count() > 0
                            {
                                continue;
                            }
                            join_native_receiver_decode_jobs(
                                cx,
                                &mut decoders,
                                config,
                                &mut decode_stats,
                                &mut intake_stats,
                                &mut completed_backlog,
                            )
                            .await?;
                            write_completed_native_blocks(
                                cx,
                                link,
                                &mut control,
                                &manifest,
                                &mut staged,
                                config,
                                &mut intake_stats,
                                &mut completed_backlog,
                            )
                            .await?;
                            break;
                        }
                        FrameType::KeepAlive => {
                            send_and_flush_native_keep_alive(cx, link, &mut control).await?;
                            continue;
                        }
                        got => {
                            return Err(QuicTransportError::Unexpected {
                                got,
                                expected: "ObjectComplete | KeepAlive",
                            });
                        }
                    }
                }
                link.flush(cx).await?;
                let round_made_progress = round_symbols_observed > 0;
                let pump_timeout = if round_made_progress {
                    ROUND_PROGRESS_IDLE_GRACE
                } else if last_need.is_some() {
                    // Awaiting a repair round after a NeedMore: poll on the short control-PTO interval
                    // so a lost NeedMore/repair self-heals quickly rather than stalling for idle_timeout.
                    NEEDMORE_PTO
                } else {
                    config.idle_timeout
                };
                let pump_started = Instant::now(); // ubs:ignore - monotonic pump timing, not crypto randomness
                let pumped_packets = link
                    .pump_inbound_for_with_drain_budget(
                        cx,
                        pump_timeout,
                        RECEIVER_SYMBOL_DRAIN_BATCHES_PER_SOCKET_POLL,
                    )
                    .await?;
                intake_stats.record_pump(pump_started.elapsed(), pumped_packets);
                if pumped_packets == 0 {
                    if link.conn.pending_datagram_count() > 0 {
                        continue;
                    }
                    if round_made_progress {
                        join_native_receiver_decode_jobs(
                            cx,
                            &mut decoders,
                            config,
                            &mut decode_stats,
                            &mut intake_stats,
                            &mut completed_backlog,
                        )
                        .await?;
                        write_completed_native_blocks(
                            cx,
                            link,
                            &mut control,
                            &manifest,
                            &mut staged,
                            config,
                            &mut intake_stats,
                            &mut completed_backlog,
                        )
                        .await?;
                        break;
                    }
                    // Idle with no progress. If we are awaiting a repair round, the NeedMore (or the
                    // repair) was lost on the wire. Requeue the same STREAM offsets instead of
                    // appending a fresh NeedMore each PTO: appending duplicates can leave an older lost
                    // duplicate ahead of the newer request and head-of-line block the sender forever.
                    if let Some((need, need_frames)) = last_need.as_ref() {
                        if needmore_pto_attempts < needmore_pto_max_attempts {
                            needmore_pto_attempts = needmore_pto_attempts.saturating_add(1);
                            let need = need.clone();
                            let need_frames = need_frames.clone();
                            quic_rqtrace!(
                                "receiver: NeedMore PTO retransmit round={} attempt={} pending={} repair_blocks={} requested_repair_symbols={} stream_frames={} max_attempts={}",
                                feedback_rounds,
                                needmore_pto_attempts,
                                need.pending.len(),
                                need.repair_blocks.len(),
                                need_more_repair_symbol_count(&need),
                                need_frames.len(),
                                needmore_pto_max_attempts,
                            );
                            match need_more_pto_mode(&need_frames) {
                                NeedMorePtoMode::SendFresh => {
                                    super::send_native_need_more(
                                        cx,
                                        &mut link.conn,
                                        &mut control,
                                        &need,
                                    )?;
                                    link.flush(cx).await?;
                                    if let Some((_, stored_need_frames)) = last_need.as_mut() {
                                        *stored_need_frames = link.last_flushed_stream_frames();
                                    }
                                }
                                NeedMorePtoMode::RetransmitRecorded => {
                                    link.retransmit_stream_frames(cx, &need_frames, "need_more_pto")
                                        .await?;
                                }
                            }
                            continue;
                        }
                    }
                    return Err(link.symbol_round_timeout(config.idle_timeout, symbols_accepted));
                }
            }

            flush_cached_quic_staging_files(&mut staged).await?;
            if round_complete.round_symbols_sent == 0 && round_symbols_observed > 0 {
                let inferred_symbols = infer_missing_round_complete_symbols(
                    expected_round_complete,
                    round_symbols_observed,
                    last_need.as_ref().map(|(need, _)| need),
                );
                if inferred_symbols > 0 {
                    trace_inferred_round_complete_symbols(
                        cx,
                        expected_round_complete,
                        round_symbols_observed,
                        inferred_symbols,
                    );
                    round_complete.round_symbols_sent = inferred_symbols;
                }
            }
            let pending = super::pending_entries(&decoders);
            if pending.is_empty() {
                break;
            }
            let next_feedback_round = next_feedback_round_or_no_convergence(
                feedback_rounds,
                config.max_feedback_rounds,
                pending.len(),
            )?;
            // Request fountain-robust FRESH repair (not fragile specific-source re-send). RaptorQ is
            // a fountain code: any K independent symbols decode a block, so fresh repair symbols
            // (new ESIs, generated via the sender's per-block repair cursor) fill a block's deficit
            // regardless of WHICH specific source symbols were lost — and they are always valid.
            // The old specific-source path (`source_symbols`) over-reported missing symbols (it
            // recomputes the deficit before the paced datagrams the reliable ObjectComplete raced
            // ahead of have settled) AND could request `esi >= block_k` for the last partial block,
            // which made the sender's `native_source_symbol_for_request` error out and die, so the
            // receiver idled to a timeout. `repair_blocks` routes the sender to fresh repair for
            // the incomplete source blocks only, so a single final block is not starved by complete
            // blocks in the same pending entry.
            let round_loss_fraction = super::receiver_round_loss_fraction(
                round_symbols_observed,
                round_complete.round_symbols_sent,
            );
            let (repair_blocks, repair_accounting) = super::block_repair_requests_with_accounting(
                &decoders,
                config,
                super::MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
                round_loss_fraction,
                next_feedback_round,
            );
            let progress = super::quic_pending_decode_progress(&decoders, &pending, config);
            let need = QuicNeedMore {
                feedback_round: next_feedback_round,
                pending,
                repair_blocks,
                source_symbols: Vec::new(),
                round_symbols_observed: Some(round_symbols_observed),
                round_loss_fraction,
                round_symbols_accepted: Some(round_symbols_accepted),
                repair_base_deficit_symbols: Some(repair_accounting.base_deficit_symbols),
                repair_loss_compensated_target_symbols: Some(
                    repair_accounting.loss_compensated_target_symbols,
                ),
                repair_request_gap_to_target_symbols: Some(
                    repair_accounting.request_gap_to_target_symbols,
                ),
                pending_rank: Some(progress.rank),
                pending_rank_columns: Some(progress.rank_columns),
                pending_rank_deficit: Some(progress.rank_deficit),
                pending_decode_jobs: Some(progress.pending_decode_jobs),
            };
            intake_stats.trace_need_more(cx, next_feedback_round, &need);
            let requested_repair_symbols = need_more_repair_symbol_count(&need);
            let base_deficit_symbols =
                need_more_base_deficit_symbols(&need, requested_repair_symbols);
            let loss_compensated_target_symbols =
                need_more_loss_compensated_target_symbols(&need, base_deficit_symbols);
            let request_gap_to_target = need
                .repair_request_gap_to_target_symbols
                .unwrap_or_else(|| {
                    loss_compensated_target_symbols.saturating_sub(requested_repair_symbols)
                });
            trace_native_repair_accounting(
                cx,
                "receiver",
                next_feedback_round,
                base_deficit_symbols,
                requested_repair_symbols,
                loss_compensated_target_symbols,
                None,
                &need,
            );
            let repair_detail = repair_block_trace_summary(&need.repair_blocks);
            quic_rqtrace!(
                "receiver: NeedMore round={} pending={} repair_blocks={} base_deficit_symbols={} requested_repair_symbols={} loss_compensated_target_symbols={} request_gap_to_target={} source_requests={} round_symbols_observed={} round_symbols_accepted={} round_symbols_sent={} round_loss_fraction={:.4} symbols_accepted={} max_feedback_rounds={} round_cap_exceeded={} repair_symbol_round_cap={} repair_blocks_detail={}",
                next_feedback_round,
                need.pending.len(),
                need.repair_blocks.len(),
                base_deficit_symbols,
                requested_repair_symbols,
                loss_compensated_target_symbols,
                request_gap_to_target,
                need.source_symbols.len(),
                round_symbols_observed,
                round_symbols_accepted,
                round_complete.round_symbols_sent,
                need.round_loss_fraction.unwrap_or(0.0),
                symbols_accepted,
                config.max_feedback_rounds,
                next_feedback_round > config.max_feedback_rounds,
                super::MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
                repair_detail,
            );
            trace_repair_block_deficits(
                "receiver",
                next_feedback_round,
                &need.repair_blocks,
            );
            super::send_native_need_more(cx, &mut link.conn, &mut control, &need)?;
            link.flush(cx).await?;
            let need_frames = link.last_flushed_stream_frames();
            // Remember it so the inner loop can re-send it on the control PTO if the repair round
            // does not arrive (lost NeedMore/repair); reset the per-round PTO budget.
            last_need = Some((need, need_frames));
            needmore_pto_attempts = 0;
            feedback_rounds = next_feedback_round;
        }

        NativeReceiveTraceCounters::capture(link).trace_decoded(
            cx,
            manifest.transfer_id.as_str(),
            symbols_accepted,
            feedback_rounds,
            &decode_stats,
        );
        intake_stats.trace_summary(cx, manifest.transfer_id.as_str());
        send_native_keep_alive(cx, &mut link.conn, &mut control)?;
        link.flush(cx).await?;
        let (mut receipt, committed_paths) = commit_staged_entries(
            cx,
            link,
            &mut control,
            dest_dir,
            &manifest,
            &mut staged,
            config,
        )
        .await?;
        receipt.symbols_accepted = symbols_accepted;
        receipt.feedback_rounds = feedback_rounds;
        receipt.decode_count = decode_stats.decode_count;
        receipt.decode_micros = decode_stats.decode_micros;
        send_native_proof_until_close(cx, link, &mut control, &receipt, config).await?;
        let _ = super::send_native_close(cx, &mut link.conn, &mut control);
        let _ = link.flush(cx).await;

        if !receipt.committed {
            return Err(QuicTransportError::Integrity(
                receipt
                    .reason
                    .clone()
                    .unwrap_or_else(|| "receiver did not commit".to_string()),
            ));
        }

        Ok(ReceiveReport {
            transfer_id: manifest.transfer_id.clone(),
            bytes_received: receipt.bytes_received,
            files: receipt.files,
            committed: true,
            symbols_accepted: receipt.symbols_accepted,
            feedback_rounds: receipt.feedback_rounds,
            decode_count: receipt.decode_count,
            decode_micros: receipt.decode_micros,
            committed_paths,
            peer: link.peer,
        })
    }
    .await;

    for staged_entry in &mut staged {
        let _ = staged_entry.close_cached_staging_file().await;
    }
    // Reclaim the staging directory on every exit path. A successful commit
    // renames each entry out (leaving an empty dir); a failed transfer leaves
    // orphaned partial blocks behind. Either way the receiver must not leak a
    // `.atp-quic-staging-*` directory into the destination — restoring the
    // cleanup that 2a3400567 dropped, caught by
    // atp_quic_real_udp_transfer_e2e::assert_no_staging_residue.
    let _ = crate::fs::remove_dir_all(&staging_dir).await;
    staging_guard.disarm();
    receive_result
}

// ─── Public entry points (called by mod.rs) ─────────────────────────────────

/// Connect to `addr` over real QUIC and transfer the already-prepared source.
/// Drives the full B2 sender coroutine over a real UDP socket.
///
/// `pub(crate)`: it consumes the crate-private prepared-source type and is only
/// reached through the public [`super::send_path`].
pub(crate) async fn send_prepared_over_udp(
    cx: &Cx,
    addr: SocketAddr,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
    peer_id: &str,
) -> Result<SendReport, QuicTransportError> {
    let config = prepared.effective_config(config);
    config.validate()?;
    let client_tls = config.client_tls.as_ref().ok_or_else(|| {
        QuicTransportError::Config(
            "ATP-over-QUIC send requires client TLS trust config; set QuicConfig::client_tls \
             (server name + root certificates) so the server identity can be verified"
                .to_string(),
        )
    })?;
    let mut link = connect(cx, addr, client_tls, &config).await?;
    run_sender_session(cx, &mut link, prepared, &config, peer_id).await
}

/// Accept one transfer on the pre-bound server `endpoint`, write it under
/// `dest_dir`, verify it, and return a report. Drives the full B3 receiver
/// coroutine over a real UDP socket.
pub async fn receive_on_endpoint(
    cx: &Cx,
    endpoint: QuicUdpEndpoint,
    dest_dir: &Path,
    config: &QuicConfig,
    peer_id: &str,
) -> Result<ReceiveReport, QuicTransportError> {
    config.validate()?;
    let server_tls = config.server_tls.as_ref().ok_or_else(|| {
        QuicTransportError::Config(
            "ATP-over-QUIC receive requires server TLS config; set QuicConfig::server_tls \
             (certificate chain + private key)"
                .to_string(),
        )
    })?;
    let (mut link, early_data) = accept(cx, endpoint, server_tls, &config).await?;
    // Replay any 1-RTT packets that raced ahead of the handshake's completion
    // (the client finishes first and may start the data plane immediately), so
    // the receiver session sees the sender's Hello / early symbols. Keep them in
    // the same bounded replay path as freshly received UDP packets instead of
    // bulk-ingesting before manifest parsing creates decoders.
    link.queue_received_packets(early_data);
    run_receiver_session(cx, &mut link, dest_dir, &config, peer_id).await
}

/// Bind a server UDP endpoint on `listen` for the native QUIC receive path.
pub async fn bind_server_endpoint(
    cx: &Cx,
    listen: SocketAddr,
) -> Result<QuicUdpEndpoint, QuicTransportError> {
    bind_endpoint(cx, listen).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Bytes;
    use crate::net::atp::protocol::quic_frames::QuicFrame;
    use crate::net::quic_native::{DEFAULT_MAX_PACKET_BYTES, StreamDirection};

    fn established_native_test_conn() -> NativeQuicConnection {
        let cx = Cx::for_testing();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin handshake");
        conn.on_handshake_keys_available(&cx)
            .expect("handshake keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        conn.record_verified_server_identity();
        conn.on_handshake_confirmed(&cx)
            .expect("handshake confirmed");
        conn
    }

    #[test]
    fn native_feedback_round_budget_allows_first_pending_round() {
        assert_eq!(
            next_feedback_round_or_no_convergence(0, 1, 1)
                .expect("first pending feedback round fits budget"),
            1
        );
    }

    #[test]
    fn native_feedback_round_budget_rejects_pending_round_after_cap() {
        assert_eq!(
            next_feedback_round_or_no_convergence(1, 1, 2)
                .expect("first still-viable grace round should not fast-fail"),
            2
        );
        let fail_closed_rounds = still_viable_feedback_fail_closed_rounds(1);
        let err = next_feedback_round_or_no_convergence(fail_closed_rounds, 1, 2)
            .expect_err("pending feedback beyond bounded grace fails closed");

        assert!(matches!(
            err,
            QuicTransportError::NoConvergence {
                rounds,
                pending: 2,
            } if rounds == fail_closed_rounds
        ));
    }

    #[test]
    fn native_feedback_round_budget_keeps_empty_feedback_out_of_no_convergence() {
        assert_eq!(
            next_feedback_round_or_no_convergence(1, 1, 0)
                .expect("empty feedback is not an incomplete-transfer convergence failure"),
            2
        );
    }

    #[test]
    fn native_quic_honors_explicit_symbol_auth_posture() {
        assert!(
            QuicConfig::default().symbol_auth_context().is_err(),
            "native QUIC must not silently rewrite missing symbol auth into a transport-auth opt-out"
        );

        let authenticated =
            QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(0xA7_50));
        assert!(
            authenticated
                .symbol_auth_context()
                .expect("authenticated native config")
                .is_some(),
            "explicit per-symbol auth remains active on the native QUIC path"
        );
    }

    #[test]
    fn native_sender_feedback_round_uses_receiver_round_identity() {
        assert_eq!(
            feedback_round_for_need_or_no_convergence(1, 8, 2, 1)
                .expect("next receiver-assigned round fits budget"),
            (2, 2)
        );
        assert_eq!(
            feedback_round_for_need_or_no_convergence(5, 8, 3, 1)
                .expect("duplicate older PTO round can be served without advancing the budget"),
            (5, 3)
        );
    }

    #[test]
    fn native_sender_feedback_round_rejects_pending_round_beyond_cap() {
        assert_eq!(
            feedback_round_for_need_or_no_convergence(8, 8, 9, 1)
                .expect("first still-viable sender grace round should not fast-fail"),
            (9, 9)
        );
        let fail_closed_rounds = still_viable_feedback_fail_closed_rounds(8);
        let err = feedback_round_for_need_or_no_convergence(
            fail_closed_rounds,
            8,
            fail_closed_rounds.saturating_add(1),
            1,
        )
        .expect_err("receiver-assigned round beyond bounded grace fails closed");

        assert!(matches!(
            err,
            QuicTransportError::NoConvergence {
                rounds,
                pending: 1,
            } if rounds == fail_closed_rounds
        ));
    }

    #[test]
    fn native_receiver_infers_missing_repair_round_complete_symbols_from_last_need() {
        let need = QuicNeedMore {
            feedback_round: 7,
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 3,
                symbols: 5,
            }],
            source_symbols: vec![
                QuicSourceSymbolRequest {
                    entry: 0,
                    sbn: 3,
                    esi: 11,
                },
                QuicSourceSymbolRequest {
                    entry: 0,
                    sbn: 3,
                    esi: 12,
                },
            ],
            ..QuicNeedMore::default()
        };

        assert_eq!(
            infer_missing_round_complete_symbols(7, 4, Some(&need)),
            7,
            "missing ObjectComplete on the active repair round uses the requested symbol count"
        );
        assert_eq!(
            infer_missing_round_complete_symbols(7, 9, Some(&need)),
            9,
            "the observed count remains a lower bound when more symbols arrive than requested"
        );
        assert_eq!(
            infer_missing_round_complete_symbols(6, 4, Some(&need)),
            4,
            "stale/out-of-round NeedMore state does not contaminate another round"
        );
    }

    #[test]
    fn quic_aimd_backs_off_on_queue_drop_with_blind_receiver_loss() {
        // MATRIX-123/124/125 (bead asupersync-atp-dataplane-redesign-317hxr.2.5.1):
        // during a ~98% queue overflow the receiver's round_loss_fraction reads ~0
        // (it counts loss only among ARRIVED symbols). The sender-side delivery loss
        // (sent vs observed) must drive AIMD so the cap backs off instead of flooding
        // the overflowing queue until PTO timeout.
        let cx = Cx::for_testing();
        let config = QuicConfig {
            max_spray_symbols_per_flush: 64,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };
        let mut aimd = NativeQuicAimdPacer::default();
        aimd.record_spray(1000, 50_000_000, Duration::from_millis(1));
        let need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            round_symbols_observed: Some(20), // only 2% arrived -> 98% dropped
            round_loss_fraction: Some(0.0),   // receiver blind to the drop
            ..QuicNeedMore::default()
        };
        aimd.observe_need_more(&cx, &config, &need);
        assert!(
            aimd.last_round_loss_fraction >= 0.5,
            "sender-side delivery loss must surface the queue drop, got {}",
            aimd.last_round_loss_fraction
        );
        assert!(
            aimd.cap_bps().is_some(),
            "a ~98% drop must trip the AIMD multiplicative-decrease cap (no flood)"
        );
        let cap = aimd
            .cap_bps()
            .expect("severe sender-observed delivery loss should arm the shared cap");
        let half_cold_start = ((super::super::QUIC_DEFAULT_COLD_START_PACING_BYTES_PER_S
            * super::super::QUIC_AIMD_MULTIPLICATIVE_DECREASE)
            .ceil()) as u64;
        assert!(
            cap <= half_cold_start,
            "severe sender-observed delivery loss must cut below half-rate, got {cap}"
        );
        let conn = established_native_test_conn();
        let lossy = super::super::quic_spray_pacing_decision_from_config(
            &config,
            native_quic_path_signal_with_observed_loss(conn.transport(), aimd.observed_loss()),
        );
        assert_eq!(
            lossy.limiter,
            super::super::QuicSprayPacingLimiter::LossBackoff,
            "sender-side delivery loss must shape the next pacing decision, not only trace metadata"
        );
        assert!(
            !super::super::quic_round0_clean_ramp_enabled(&config, &lossy, true),
            "Bug A: sender-side delivery loss must keep the clean ramp from re-arming"
        );
        // Clean delivery (observed ~= sent) must NOT spuriously back off.
        let mut clean = NativeQuicAimdPacer::default();
        clean.record_spray(1000, 50_000_000, Duration::from_millis(1));
        let clean_need = QuicNeedMore {
            feedback_round: 1,
            round_symbols_observed: Some(1000),
            round_loss_fraction: Some(0.0),
            ..QuicNeedMore::default()
        };
        clean.observe_need_more(&cx, &config, &clean_need);
        assert!(
            clean.last_round_loss_fraction <= f64::EPSILON,
            "full delivery must register ~0 loss, got {}",
            clean.last_round_loss_fraction
        );
    }

    #[test]
    fn matrix164_native_quic_shared_rate_decision_caps_next_pacing_epoch() {
        let cx = Cx::for_testing();
        let config = QuicConfig {
            symbol_size: 1200,
            max_spray_symbols_per_flush: 128,
            round0_loss_target: 0.10,
            datagram_fanout: 1,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };
        let mut aimd = NativeQuicAimdPacer::default();
        aimd.record_spray(10_000, 64 * 1024 * 1024, Duration::from_secs(1));
        let need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            round_symbols_observed: Some(1_000),
            round_loss_fraction: Some(0.0),
            ..QuicNeedMore::default()
        };

        aimd.observe_need_more(&cx, &config, &need);
        let decision = aimd
            .shared_decision()
            .expect("NeedMore should feed the shared datagram controller");
        assert!(
            decision.sender_loss_fraction_ppm >= 900_000,
            "shared controller must see sender-side queue overflow"
        );
        assert!(
            decision.bytes_in_flight > 0,
            "sender-observed queue loss must leave outstanding bytes in the shared controller"
        );
        assert!(
            decision.loss_limited,
            "sender-observed overflow must put the shared controller in loss backoff"
        );

        let conn = established_native_test_conn();
        let mut pacing = super::super::quic_spray_pacing_decision_from_config(
            &config,
            native_quic_path_signal_with_observed_loss(conn.transport(), 0.0),
        );
        let uncapped_rate = pacing.pacing_rate_bps;
        let uncapped_burst = pacing.max_burst_symbols;
        NativeQuicAimdPacer::apply_shared_decision_to_pacing(
            Some(decision),
            &mut pacing,
            usize::from(config.symbol_size.max(1)),
            &config,
        );

        let symbol_bytes = u64::from(config.symbol_size.max(1));
        let budget_symbols = usize::try_from(
            decision
                .send_budget_bytes
                .checked_div(symbol_bytes)
                .unwrap_or(0)
                .max(1),
        )
        .unwrap_or(usize::MAX);
        assert!(
            pacing.pacing_rate_bps <= decision.pacing_bytes_per_s,
            "native QUIC pacing must consume the shared controller rate cap"
        );
        assert!(
            pacing.pacing_rate_bps <= uncapped_rate,
            "shared controller may only tighten the native pacing epoch"
        );
        assert!(
            pacing.max_burst_symbols <= budget_symbols,
            "native QUIC burst must respect shared cwnd/receiver send budget"
        );
        assert!(
            pacing.max_burst_symbols <= uncapped_burst,
            "shared controller may only tighten the native burst epoch"
        );
        assert_eq!(
            pacing.limiter,
            super::super::QuicSprayPacingLimiter::LossBackoff,
            "sender-side overflow must disable the clean/unbounded pacing path"
        );
    }

    #[test]
    fn quic_native_aimd_drops_rate_and_bounds_inflight_on_ten_percent_loss() {
        let cx = Cx::for_testing();
        let config = QuicConfig {
            symbol_size: 1200,
            max_spray_symbols_per_flush: 128,
            datagram_fanout: 1,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };
        let mut aimd = NativeQuicAimdPacer::default();
        aimd.record_spray(10_000, 64 * 1024 * 1024, Duration::from_secs(1));
        let need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            round_symbols_observed: Some(9_000),
            round_loss_fraction: Some(0.0),
            ..QuicNeedMore::default()
        };

        let conn = established_native_test_conn();
        let mut pacing = super::super::quic_spray_pacing_decision_from_config(
            &config,
            native_quic_path_signal_with_observed_loss(conn.transport(), 0.0),
        );
        let uncapped_rate = pacing.pacing_rate_bps;
        let uncapped_burst = pacing.max_burst_symbols;

        aimd.observe_need_more(&cx, &config, &need);
        let decision = aimd
            .shared_decision()
            .expect("10% sender-observed loss should feed the shared controller");
        assert!(
            decision.sender_loss_fraction_ppm >= 100_000,
            "shared controller must see the injected sender-side loss"
        );
        assert!(
            decision.bytes_in_flight > 0,
            "10% sender-observed loss should bound outstanding bytes"
        );
        assert!(
            decision.loss_limited,
            "10% unexpected sender loss should put the shared controller in loss backoff"
        );

        NativeQuicAimdPacer::apply_shared_decision_to_pacing(
            Some(decision),
            &mut pacing,
            usize::from(config.symbol_size.max(1)),
            &config,
        );

        let symbol_bytes = u64::from(config.symbol_size.max(1));
        let budget_symbols = usize::try_from(
            decision
                .send_budget_bytes
                .checked_div(symbol_bytes)
                .unwrap_or(0)
                .max(1),
        )
        .unwrap_or(usize::MAX);
        assert!(
            pacing.pacing_rate_bps < uncapped_rate,
            "native QUIC shared controller must drop rate under injected loss"
        );
        assert!(
            pacing.max_burst_symbols <= budget_symbols,
            "native QUIC shared controller must cap burst by cwnd/receiver budget"
        );
        assert!(
            pacing.max_burst_symbols <= uncapped_burst,
            "native QUIC shared controller may only tighten burst after loss"
        );
        assert_eq!(
            pacing.limiter,
            super::super::QuicSprayPacingLimiter::LossBackoff,
            "injected sender-side loss must gate the next pacing epoch"
        );
    }

    #[test]
    fn quic_aimd_backs_off_when_rank_progress_stalls_despite_zero_loss() {
        let cx = Cx::for_testing();
        let config = QuicConfig {
            symbol_size: 1200,
            round0_loss_target: 0.10,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };

        let mut stalled = NativeQuicAimdPacer::default();
        stalled.record_spray(10_000, 50_000_000, Duration::from_millis(800));
        let stalled_need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            round_symbols_observed: Some(10_000),
            round_symbols_accepted: Some(10_000),
            round_loss_fraction: Some(0.0),
            pending_rank: Some(100),
            pending_rank_columns: Some(43_700),
            pending_rank_deficit: Some(43_600),
            pending_decode_jobs: Some(0),
            ..QuicNeedMore::default()
        };
        stalled.observe_need_more(&cx, &config, &stalled_need);
        let stalled_decision = stalled
            .shared_decision()
            .expect("rank-progress feedback should feed the shared controller");
        assert!(
            stalled_decision.loss_limited,
            "rank-progress loss must still put the shared controller in loss backoff"
        );
        assert!(
            stalled.last_round_loss_fraction
                > super::super::quic_aimd_loss_decrease_threshold(&config),
            "rank-progress stall must override underreported receiver arrival loss"
        );
        assert!(
            stalled.cap_bps().is_some(),
            "stalled rank progress should arm a shared-controller rate cap"
        );

        let mut healthy = NativeQuicAimdPacer::default();
        healthy.record_spray(10_000, 50_000_000, Duration::from_millis(1_000));
        let healthy_need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            round_symbols_observed: Some(10_000),
            round_symbols_accepted: Some(10_000),
            round_loss_fraction: Some(0.0),
            pending_rank: Some(8_500),
            pending_rank_columns: Some(43_700),
            pending_rank_deficit: Some(35_200),
            pending_decode_jobs: Some(0),
            ..QuicNeedMore::default()
        };
        healthy.observe_need_more(&cx, &config, &healthy_need);
        assert_eq!(
            healthy.last_round_loss_fraction, 0.0,
            "healthy rank progress should not manufacture congestion loss"
        );
        assert_eq!(
            healthy.cap_bps(),
            None,
            "healthy rank progress should keep the native QUIC cap unarmed"
        );
    }

    #[test]
    fn native_sender_observed_loss_shapes_pacing_decision_not_only_trace_field() {
        // MATRIX-127: observed delivery loss must be present before the pacing
        // decision is computed. Updating only `path_loss_rate` after the fact disables
        // the clean-ramp flag but leaves rate, burst, pause, and limiter on stale
        // zero-loss math.
        let conn = established_native_test_conn();
        let config = QuicConfig {
            max_spray_symbols_per_flush: 64,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };

        let clean = super::super::quic_spray_pacing_decision_from_config(
            &config,
            native_quic_path_signal_with_observed_loss(conn.transport(), 0.0),
        );
        let lossy = super::super::quic_spray_pacing_decision_from_config(
            &config,
            native_quic_path_signal_with_observed_loss(conn.transport(), 0.90),
        );

        assert_eq!(
            lossy.limiter,
            super::super::QuicSprayPacingLimiter::LossBackoff
        );
        assert!(
            lossy.pacing_rate_bps < clean.pacing_rate_bps,
            "sender-observed loss must reduce the computed pacing rate: clean={clean:?} lossy={lossy:?}"
        );
        assert!(
            lossy.max_burst_symbols <= clean.max_burst_symbols,
            "sender-observed loss must not leave burst sizing on the stale clean path: clean={clean:?} lossy={lossy:?}"
        );
        assert!(
            !super::super::quic_round0_clean_ramp_enabled(&config, &lossy, true),
            "sender-observed delivery loss must also block clean-ramp eligibility"
        );
    }

    #[test]
    fn native_data_plane_path_signal_preserves_cwnd_as_telemetry() {
        let conn = established_native_test_conn();
        let native_cwnd = conn.transport().congestion_window_bytes();

        let clean = native_quic_path_signal_with_observed_loss(conn.transport(), 0.0);
        assert_eq!(
            clean.congestion_window_bytes, native_cwnd,
            "MATRIX-132: native cwnd must remain honest telemetry, not a synthesized data-plane window"
        );
        assert_eq!(clean.loss_rate, 0.0);

        let lossy = native_quic_path_signal_with_observed_loss(conn.transport(), 0.42);
        assert_eq!(lossy.congestion_window_bytes, native_cwnd);
        assert_eq!(lossy.loss_rate, 0.42);
    }

    #[test]
    fn source_stream_packet_budget_allows_cwnd_floor_tail_progress() {
        let observed_tail_bytes = 95u64;

        assert!(
            QUIC_STREAM_PACKET_OVERHEAD_BUDGET >= ONE_RTT_PACKET_OVERHEAD as u64,
            "source STREAM packet budget must cover 1-RTT header/tag bytes"
        );
        assert!(
            observed_tail_bytes.saturating_sub(QUIC_STREAM_PACKET_OVERHEAD_BUDGET) > 32,
            "MATRIX-148: source STREAM flushing must leave enough frame budget to emit a tiny frame at the cwnd floor"
        );
    }

    #[test]
    fn native_data_plane_recovery_accounting_uses_packet_units_for_jumbo_udp() {
        let cx = Cx::for_testing();
        assert_eq!(data_plane_packet_accounting_bytes(0), 1);
        assert_eq!(
            data_plane_packet_accounting_bytes(512),
            QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES
        );
        assert_eq!(
            data_plane_packet_accounting_bytes(ATP_QUIC_UDP_MAX_PACKET),
            QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES
        );

        let datagram = QuicFrame::Datagram {
            data: Bytes::from_static(b"symbol"),
        };
        assert!(frames_have_datagram(core::slice::from_ref(&datagram)));
        assert!(frame_is_ack_eliciting_for_recovery(&datagram));
        assert!(!frames_have_datagram(&[QuicFrame::Ping]));
        assert!(!frame_is_ack_eliciting_for_recovery(&QuicFrame::Padding {
            length: 1
        }));

        let mut conn = established_native_test_conn();
        let initial_cwnd = conn.transport().congestion_window_bytes();
        let initial_packet_credits = initial_cwnd / QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES;
        assert!(initial_packet_credits >= 700);

        for idx in 0..initial_packet_credits {
            assert!(
                conn.transport()
                    .can_send(QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES),
                "packet {idx} should fit before cwnd fills"
            );
            let pn = conn
                .on_packet_sent(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    data_plane_packet_accounting_bytes(ATP_QUIC_UDP_MAX_PACKET),
                    true,
                    true,
                    (idx + 1) * CLOCK_STEP_MICROS,
                )
                .expect("jumbo ATP packet should charge one recovery unit");
            assert_eq!(pn, idx);
        }

        assert_eq!(conn.transport().bytes_in_flight(), initial_cwnd);
        assert!(
            !conn
                .transport()
                .can_send(QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES),
            "initial cwnd should be full after ATP packet-credit charges"
        );
        assert_eq!(
            data_plane_cwnd_telemetry(conn.transport(), 0),
            None,
            "empty data-plane queues must not emit cwnd telemetry"
        );
        let cwnd_telemetry = data_plane_cwnd_telemetry(conn.transport(), 3)
            .expect("full native cwnd should be visible as telemetry");
        assert_eq!(cwnd_telemetry.bytes_in_flight, initial_cwnd);
        assert_eq!(cwnd_telemetry.congestion_window, initial_cwnd);
        let admission =
            data_plane_flush_admission(conn.transport(), 3, 1_200, ATP_QUIC_UDP_MAX_PACKET);
        assert_eq!(
            admission.max_frame_bytes, 1_200,
            "MATRIX-132: cwnd telemetry must not switch ATP DATAGRAM flushes to the control-only path"
        );
        assert_eq!(
            admission.cwnd_telemetry,
            Some(cwnd_telemetry),
            "native QUIC cwnd remains observable while the RaptorQ pacer owns admission"
        );
        let overflow_accounting = data_plane_packet_accounting_bytes(ATP_QUIC_UDP_MAX_PACKET);
        assert!(
            data_plane_packet_uses_paced_recovery(core::slice::from_ref(&datagram)),
            "pure ATP DATAGRAM packets must use the RaptorQ data-plane pacer as send authority"
        );
        assert!(
            !packet_tracks_recovery_in_flight(core::slice::from_ref(&datagram), None),
            "pure ATP DATAGRAM packets must not require NewReno admission"
        );
        let overflow_pn = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                overflow_accounting,
                true,
                false,
                (initial_packet_credits + 1) * CLOCK_STEP_MICROS,
            )
            .expect("MATRIX-132: ATP pacer, not QUIC cwnd, admits the next DATAGRAM");
        assert_eq!(overflow_pn, initial_packet_credits);
        assert_eq!(
            conn.transport().bytes_in_flight(),
            initial_cwnd,
            "telemetry-only DATAGRAM sends must not grow QUIC bytes_in_flight past cwnd"
        );

        let ack_range =
            crate::net::quic_native::AckRange::new(initial_packet_credits, 0).expect("ack range");
        conn.on_ack_ranges(
            &cx,
            PacketNumberSpace::ApplicationData,
            &[ack_range],
            0,
            20 * CLOCK_STEP_MICROS,
        )
        .expect("ack range should clear tracked in-flight packets");
        assert_eq!(conn.transport().bytes_in_flight(), 0);
        assert!(
            conn.transport()
                .can_send(QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES),
            "ACK feedback should reopen native recovery cwnd"
        );
    }

    #[test]
    fn native_data_plane_admission_is_pacer_not_newreno_cwnd() {
        let cx = Cx::for_testing();
        let datagram = QuicFrame::Datagram {
            data: Bytes::from_static(b"symbol"),
        };
        assert!(frame_is_ack_eliciting_for_recovery(&datagram));
        assert!(!frames_require_quic_recovery_in_flight(
            core::slice::from_ref(&datagram)
        ));
        assert!(frames_require_quic_recovery_in_flight(&[QuicFrame::Ping]));

        let mut conn = established_native_test_conn();
        let initial_cwnd = conn.transport().congestion_window_bytes();
        let initial_packet_credits = initial_cwnd / QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES;
        assert!(initial_packet_credits > 0);
        for idx in 0..initial_packet_credits {
            conn.on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES,
                true,
                true,
                (idx + 1) * CLOCK_STEP_MICROS,
            )
            .expect("setup packet should fit before cwnd fills");
        }
        assert_eq!(conn.transport().bytes_in_flight(), initial_cwnd);
        assert!(
            !conn
                .transport()
                .can_send(QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES)
        );

        let datagram_accounting = data_plane_packet_accounting_bytes(ATP_QUIC_UDP_MAX_PACKET);
        assert!(data_plane_packet_uses_paced_recovery(
            core::slice::from_ref(&datagram)
        ));
        let datagram_pn = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                datagram_accounting,
                true,
                false,
                (initial_packet_credits + 1) * CLOCK_STEP_MICROS,
            )
            .expect("pure ATP DATAGRAM packet admission is owned by the spray pacer");
        assert_eq!(datagram_pn, initial_packet_credits);
        assert_eq!(
            conn.transport().bytes_in_flight(),
            initial_cwnd,
            "pure ATP DATAGRAM packets stay packet-number visible but bypass NewReno in-flight admission"
        );

        let control_err = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1,
                true,
                frames_require_quic_recovery_in_flight(&[QuicFrame::Ping]),
                (initial_packet_credits + 2) * CLOCK_STEP_MICROS,
            )
            .expect_err("reliable/control packets must remain NewReno governed");
        assert!(matches!(
            control_err,
            NativeQuicConnectionError::CongestionLimited { .. }
        ));
    }

    #[test]
    fn native_source_stream_bulk_admission_is_pacer_not_newreno_cwnd() {
        let cx = Cx::for_testing();
        let source_stream = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 1);
        let other_stream = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 3);
        let source_frame = QuicFrame::Stream {
            stream_id: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(
                source_stream.0,
            ),
            offset: None,
            data: Bytes::from_static(b"source"),
            fin: false,
        };
        let other_frame = QuicFrame::Stream {
            stream_id: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(
                other_stream.0,
            ),
            offset: None,
            data: Bytes::from_static(b"control"),
            fin: false,
        };

        assert!(source_stream_packet_uses_paced_recovery(
            core::slice::from_ref(&source_frame),
            Some(source_stream)
        ));
        assert!(!packet_tracks_recovery_in_flight(
            core::slice::from_ref(&source_frame),
            Some(source_stream)
        ));
        assert!(!source_stream_packet_uses_paced_recovery(
            core::slice::from_ref(&other_frame),
            Some(source_stream)
        ));
        assert!(packet_tracks_recovery_in_flight(
            core::slice::from_ref(&other_frame),
            Some(source_stream)
        ));
        let mixed_source_and_control = [source_frame.clone(), QuicFrame::Ping];
        assert!(!source_stream_packet_uses_paced_recovery(
            &mixed_source_and_control,
            Some(source_stream)
        ));
        assert!(packet_tracks_recovery_in_flight(
            &mixed_source_and_control,
            Some(source_stream)
        ));

        let mut conn = established_native_test_conn();
        let initial_cwnd = conn.transport().congestion_window_bytes();
        let initial_packet_credits = initial_cwnd / QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES;
        for idx in 0..initial_packet_credits {
            conn.on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES,
                true,
                true,
                (idx + 1) * CLOCK_STEP_MICROS,
            )
            .expect("setup packet should fill the native recovery cwnd");
        }
        assert_eq!(conn.transport().bytes_in_flight(), initial_cwnd);
        assert!(!conn.transport().can_send(1));

        let source_accounting = data_plane_packet_accounting_bytes(source_stream_max_frame_bytes());
        let source_tracks_in_flight = packet_tracks_recovery_in_flight(
            core::slice::from_ref(&source_frame),
            Some(source_stream),
        );
        let pn = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                source_accounting,
                true,
                source_tracks_in_flight,
                (initial_packet_credits + 1) * CLOCK_STEP_MICROS,
            )
            .expect("marked source STREAM packet should use ATP-paced admission");
        assert_eq!(pn, initial_packet_credits);
        assert_eq!(
            conn.transport().bytes_in_flight(),
            initial_cwnd,
            "bulk source STREAM packets must not grow NewReno bytes_in_flight past cwnd"
        );
    }

    #[test]
    fn native_source_stream_pacing_uses_stream_ceiling_for_good_path() {
        let good_config = QuicConfig {
            round0_loss_target: super::super::QUIC_RELIABLE_SOURCE_STREAM_MAX_LOSS_TARGET,
            max_spray_symbols_per_flush: 54,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };
        let mut pacing = QuicSprayPacingDecision {
            max_burst_symbols: 4,
            pause_after_burst: Duration::from_millis(1),
            pacing_rate_bps: super::super::QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS,
            cwnd_symbols: 4,
            cwnd_share_symbols: 4,
            burst_cap_share_symbols: 4,
            loss_backoff: 1.0,
            responsiveness_backoff: 1.0,
            path_rtt_s: 0.025,
            path_cwnd_bytes: 12_000,
            path_loss_rate: super::super::QUIC_RELIABLE_SOURCE_STREAM_MAX_LOSS_TARGET,
            fec_loss_budget: 0.0,
            congestion_loss_rate: 0.0,
            limiter: super::super::QuicSprayPacingLimiter::PacingRate,
        };
        promote_source_stream_pacing(&mut pacing, &good_config, 1200);

        assert_eq!(
            pacing.pacing_rate_bps,
            super::super::QUIC_RELIABLE_SOURCE_STREAM_MAX_PACING_BPS,
            "GOOD source STREAM pacing must not inherit the lower DATAGRAM clean-ramp cap"
        );

        let capped_config = QuicConfig {
            bwlimit_bps: Some(super::super::QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS),
            ..good_config
        };
        let mut capped = pacing;
        capped.pacing_rate_bps = super::super::QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS;
        promote_source_stream_pacing(&mut capped, &capped_config, 1200);
        assert_eq!(
            capped.pacing_rate_bps,
            super::super::QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS,
            "operator bandwidth caps must still bound source STREAM pacing"
        );
    }

    #[test]
    fn native_source_stream_repair_tail_has_good_loss_floor() {
        let config = QuicConfig {
            repair_overhead: 1.0,
            round0_loss_target: super::super::QUIC_RELIABLE_SOURCE_STREAM_MAX_LOSS_TARGET,
            symbol_size: 1141,
            max_block_size: 512 * 1024,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };
        let manifest = TransferManifest {
            transfer_id: "goodtail".to_string(),
            root_name: "goodtail.bin".to_string(),
            is_directory: false,
            total_bytes: 1024 * 1024,
            merkle_root_hex: "00".repeat(32),
            metadata_root_hex: None,
            delta_manifest: None,
            entries: vec![crate::net::atp::transport_tcp::ManifestEntry {
                index: 0,
                rel_path: "goodtail.bin".to_string(),
                size: 1024 * 1024,
                sha256_hex: "11".repeat(32),
                metadata: None,
            }],
        };

        let requests =
            source_stream_repair_tail_requests(&manifest, &config).expect("tail requests");

        assert_eq!(requests.len(), 2);
        assert!(
            requests.iter().all(|request| request.symbols == 2),
            "GOOD source-stream tail should not collapse to zero when CLI repair_overhead is 1.0"
        );
    }

    #[test]
    fn quic_sender_delivery_loss_compensates_blind_repair_requests() {
        // MATRIX-127: Bug B/A made AIMD see sender-side delivery loss, but repair
        // sizing must use that same signal. Otherwise a receiver with
        // round_loss_fraction=0.0 still asks for the raw deficit only, even after a
        // massive queue drop.
        let cx = Cx::for_testing();
        let config = QuicConfig::default().allow_unauthenticated_for_trusted_transport();
        let mut aimd = NativeQuicAimdPacer::default();
        aimd.record_spray(1_000, 50_000_000, Duration::from_millis(1));
        let need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 0,
                symbols: 100,
            }],
            round_symbols_observed: Some(20),
            round_loss_fraction: Some(0.0),
            ..QuicNeedMore::default()
        };

        aimd.observe_need_more(&cx, &config, &need);
        let sender_loss = aimd.sender_delivery_loss_for_repair(need.round_loss_fraction);
        assert!(
            sender_loss.is_some_and(|loss| loss >= 0.5),
            "sender-side delivery loss should dominate blind receiver loss: {sender_loss:?}"
        );
        let expanded = delivery_loss_compensated_repair_blocks(&need.repair_blocks, sender_loss);
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].entry, 0);
        assert_eq!(expanded[0].sbn, 0);
        assert!(
            expanded[0].symbols > need.repair_blocks[0].symbols,
            "sender-side delivery loss should inflate repair symbols from {} to {}, not leave the raw deficit",
            need.repair_blocks[0].symbols,
            expanded[0].symbols,
        );

        assert!(
            aimd.sender_delivery_loss_for_repair(Some(0.90)).is_none(),
            "do not double-compensate when the receiver loss signal is already at least as high"
        );
    }

    #[test]
    fn native_keep_alive_uses_ping_not_ordered_control_stream() {
        let cx = Cx::for_testing();
        let mut conn = established_native_test_conn();
        let mut control = NativeQuicFrameTransport::open(&cx, &mut conn).expect("control stream");

        send_native_keep_alive(&cx, &mut conn, &mut control).expect("queue native keepalive");
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("keepalive frame should generate");

        assert_eq!(frames, vec![QuicFrame::Ping]);
    }

    #[test]
    fn native_receiver_progress_idle_grace_covers_control_pto() {
        assert_eq!(
            ROUND_PROGRESS_IDLE_GRACE, NEEDMORE_PTO,
            "receiver must not emit stale NeedMore before one control PTO elapses"
        );
    }

    #[test]
    fn queued_fountain_feedback_count_ignores_liveness_and_round_markers() {
        fn empty_frame(ty: FrameType) -> Frame {
            Frame::new(
                crate::net::atp::protocol::frames::ProtocolVersion::CURRENT,
                ty,
                Vec::new(),
            )
            .expect("valid empty test frame")
        }

        let pending = VecDeque::from([
            empty_frame(FrameType::KeepAlive),
            empty_frame(FrameType::ObjectComplete),
            empty_frame(FrameType::ObjectRequest),
            empty_frame(FrameType::Proof),
        ]);

        assert_eq!(queued_fountain_feedback_count(&pending), 2);
    }

    #[test]
    fn one_rtt_header_round_trips() {
        for pn in [0u64, 1, 41, 255, 65_536, u64::from(u32::MAX), u64::MAX] {
            let header = encode_one_rtt_header(pn);
            // Build a minimal packet: header + 1 ciphertext byte + tag.
            let mut packet = header.to_vec();
            packet.push(0xAB);
            packet.extend_from_slice(&[0u8; ONE_RTT_TAG_LEN]);
            let (key_phase, decoded_pn, decoded_header, ciphertext, tag) =
                decode_one_rtt_packet(&packet).expect("decodes");
            assert!(!key_phase);
            assert_eq!(decoded_pn, pn);
            assert_eq!(decoded_header, &header);
            assert_eq!(ciphertext, &[0xAB]);
            assert_eq!(tag, [0u8; ONE_RTT_TAG_LEN]);
        }
    }

    #[test]
    fn decode_rejects_non_one_rtt_or_truncated_packets() {
        // Too short for header + tag.
        assert!(decode_one_rtt_packet(&[0x40, 0, 0]).is_none());
        // Long-header (fixed bit clear): a stray handshake packet.
        let mut long = vec![0x80];
        long.extend_from_slice(&[0u8; ONE_RTT_HEADER_LEN + ONE_RTT_TAG_LEN]);
        assert!(decode_one_rtt_packet(&long).is_none());
    }

    #[test]
    fn one_rtt_payload_budget_accounts_for_udp_overhead_and_control_headroom() {
        let legacy_cap = 16 * 1024;
        assert_eq!(
            one_rtt_max_payload_for_udp_packet(legacy_cap)
                + ONE_RTT_PACKET_OVERHEAD
                + ONE_RTT_COALESCED_CONTROL_HEADROOM,
            legacy_cap
        );
        assert_eq!(
            one_rtt_max_payload_for_udp_packet(ATP_QUIC_UDP_MAX_PACKET)
                + ONE_RTT_PACKET_OVERHEAD
                + ONE_RTT_COALESCED_CONTROL_HEADROOM,
            ATP_QUIC_UDP_MAX_PACKET
        );
        let protected_len =
            one_rtt_max_payload_for_udp_packet(ATP_QUIC_UDP_MAX_PACKET) + ONE_RTT_PACKET_OVERHEAD;
        assert!(protected_len < ATP_QUIC_UDP_MAX_PACKET);
        assert_eq!(
            ATP_QUIC_UDP_MAX_PACKET - protected_len,
            ONE_RTT_COALESCED_CONTROL_HEADROOM
        );
        assert_eq!(
            one_rtt_max_payload_for_udp_packet(ONE_RTT_PACKET_OVERHEAD - 1),
            0
        );
        assert_eq!(
            source_stream_max_frame_bytes(),
            one_rtt_max_payload_for_udp_packet(QUIC_SOURCE_STREAM_PACKET_BYTES),
            "ATP-paced source STREAM packets should use the configured native QUIC envelope"
        );
        assert_eq!(
            QUIC_SOURCE_STREAM_PACKET_BYTES,
            8 * 1024,
            "GOOD source STREAM packets should use the middle envelope, not the native MTU floor or jumbo UDP ceiling"
        );
        assert!(
            source_stream_max_frame_bytes() > DEFAULT_MAX_PACKET_BYTES,
            "source STREAM middle envelope should reduce receiver packet rate below the native MTU floor"
        );
        assert!(
            QUIC_SOURCE_STREAM_FLUSH_BYTES
                > u64::try_from(source_stream_max_frame_bytes()).unwrap(),
            "source STREAM flush windows should contain multiple native-envelope packets"
        );
        let interval = source_stream_pacing_interval(
            QUIC_SOURCE_STREAM_FLUSH_BYTES as usize,
            64 * 1024 * 1024,
        );
        assert!(
            (Duration::from_millis(7)..=Duration::from_millis(9)).contains(&interval),
            "source STREAM flush bursts should pace near the reliable-stream ceiling"
        );
        let pacing = QuicSprayPacingDecision {
            max_burst_symbols: 4,
            pause_after_burst: Duration::from_millis(1),
            pacing_rate_bps: 24 * 1024 * 1024,
            cwnd_symbols: 4,
            cwnd_share_symbols: 4,
            burst_cap_share_symbols: 4,
            loss_backoff: 1.0,
            responsiveness_backoff: 1.0,
            path_rtt_s: 0.025,
            path_cwnd_bytes: 12_000,
            path_loss_rate: 0.001,
            fec_loss_budget: 0.0,
            congestion_loss_rate: 0.0,
            limiter: super::super::QuicSprayPacingLimiter::PacingRate,
        };
        let mut pacer = NativeDataPlanePacer::new(1200, 4, pacing.pacing_rate_bps);
        pacer.configure(&pacing);
        assert_eq!(pacer.byte_pacer_burst_bytes, 4 * 1200);
        pacer.configure_source_stream(&pacing);
        assert_eq!(
            pacer.byte_pacer_burst_bytes,
            usize::try_from(QUIC_SOURCE_STREAM_FLUSH_BYTES).unwrap(),
            "source STREAM byte pacing should burst by the producer flush window, not symbol burst"
        );
        let first_packet = source_stream_max_frame_bytes();
        let second_packet = source_stream_max_frame_bytes();
        let packet_budget_before = pacer.byte_pacer_burst_remaining;
        let cx = Cx::for_testing();
        futures_lite::future::block_on(async {
            pacer
                .before_send_bytes(&cx, first_packet, 0, 0, 0)
                .await
                .expect("first source STREAM packet should consume byte budget");
            pacer
                .before_send_bytes(&cx, second_packet, 0, 0, 0)
                .await
                .expect("second source STREAM packet should consume byte budget");
        });
        assert_eq!(packet_budget_before, 0);
        assert_eq!(
            pacer.byte_pacer_burst_remaining,
            usize::try_from(QUIC_SOURCE_STREAM_FLUSH_BYTES)
                .unwrap()
                .saturating_sub(first_packet)
                .saturating_sub(second_packet),
            "source STREAM pacing must charge actual frame bytes, not rounded symbol units"
        );
    }

    #[test]
    fn one_rtt_payload_budget_coalesces_many_default_symbol_datagrams() {
        let symbol_envelope_len =
            usize::from(super::super::DEFAULT_SYMBOL_SIZE) + super::super::AUTH_ENVELOPE_HEADER_LEN;
        let mut encoded = BytesMut::new();
        QuicFrame::Datagram {
            data: Bytes::from(vec![0u8; symbol_envelope_len]),
        }
        .encode(&mut encoded)
        .expect("encode datagram frame");
        assert_eq!(
            encoded.len(),
            symbol_datagram_frame_len(
                super::super::DEFAULT_SYMBOL_SIZE,
                super::super::AUTH_ENVELOPE_HEADER_LEN,
            )
        );

        let max_app_payload = one_rtt_max_payload_for_udp_packet(ATP_QUIC_UDP_MAX_PACKET);
        let coalesced_symbols =
            coalesced_datagram_frames_per_packet(max_app_payload, encoded.len());

        assert!(
            coalesced_symbols >= 50,
            "one 1-RTT UDP packet should carry roughly MATRIX-39's ~53 symbol DATAGRAM frames"
        );
        assert!(encoded.len().saturating_mul(coalesced_symbols) <= max_app_payload);
        assert!(
            encoded
                .len()
                .saturating_mul(coalesced_symbols.saturating_add(1))
                > max_app_payload
        );
    }

    #[test]
    fn clean_spray_flush_limit_preserves_explicit_low_caps() {
        assert_eq!(
            coalesced_spray_flush_symbol_limit(54, 51, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            51,
            "raw caps below the GSO expansion still align to one full protected packet"
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(1, 51, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            51,
            "raw caps below the GSO expansion still amortize to one protected packet"
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(50, 51, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            51
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(128, 51, 256, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            204
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(256, 51, 256, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            255
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(0, 51, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            51
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(54, 0, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            54
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(2, 60, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            54,
            "configured flush cap still bounds packet fill when one packet can hold more"
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(2, 51, 16, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            16,
            "operator burst cap remains the hard queueing envelope"
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(2, 1, 64, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            QUIC_CLEAN_SPRAY_BURST_FLOOR_SYMBOLS,
            "MATRIX-108: the encrypted clean path (one symbol per protected packet, \
             RTT-derived burst ≈ 2) floors to the rq-parity burst so a flush amortizes \
             QUIC packet protection and fills the send budget instead of ~5 MB/s"
        );
    }

    #[test]
    fn clean_coalescing_requires_low_loss_and_low_rtt() {
        let mut pacing = QuicSprayPacingDecision {
            max_burst_symbols: 2,
            pause_after_burst: Duration::from_millis(1),
            pacing_rate_bps: 12_000_000,
            cwnd_symbols: 10,
            cwnd_share_symbols: 10,
            burst_cap_share_symbols: 10,
            loss_backoff: 1.0,
            responsiveness_backoff: 1.0,
            path_rtt_s: 0.025,
            path_cwnd_bytes: 12_000,
            path_loss_rate: 0.0,
            fec_loss_budget: 0.0,
            congestion_loss_rate: 0.0,
            limiter: super::super::QuicSprayPacingLimiter::PacingRate,
        };
        assert!(
            !quic_clean_spray_coalescing_allowed(&pacing),
            "native ATP-QUIC keeps loss-granular symbol packets until lossy convergence is banked"
        );

        pacing.path_rtt_s = 0.0;
        assert!(
            !quic_clean_spray_coalescing_allowed(&pacing),
            "unknown RTT must stay on per-symbol packets until a clean path is measured"
        );

        pacing.path_rtt_s = 0.080;
        assert!(
            !quic_clean_spray_coalescing_allowed(&pacing),
            "50M/bad encrypted should not pack a full symbol group into one jumbo UDP packet"
        );

        pacing.path_rtt_s = 0.025;
        pacing.path_loss_rate = QUIC_CLEAN_SPRAY_MAX_LOSS_RATE;
        assert!(!quic_clean_spray_coalescing_allowed(&pacing));
    }

    #[test]
    fn clean_gso_flush_cap_batches_full_protected_packets_when_default_cap_allows_one() {
        assert_eq!(
            clean_gso_flush_symbol_cap(54, 54),
            54 * QUIC_CLEAN_GSO_PACKETS_PER_FLUSH
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(
                1,
                54,
                clean_gso_flush_symbol_cap(54, 54),
                0.0,
                QUIC_CLEAN_GSO_PACKETS_PER_FLUSH
            ),
            54 * QUIC_CLEAN_GSO_PACKETS_PER_FLUSH
        );
        assert_eq!(
            clean_gso_flush_symbol_cap(16, 54),
            16,
            "operator caps below one packet remain hard caps"
        );
        assert_eq!(
            clean_gso_flush_symbol_cap(128, 54),
            128,
            "explicit operator caps above one packet remain explicit"
        );
    }

    #[test]
    fn clean_handoff_limit_fills_gso_flush_window() {
        let flush_window = 54 * QUIC_CLEAN_GSO_PACKETS_PER_FLUSH;
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, 0, 0.0),
            flush_window,
            "MATRIX-112: clean encrypted sends hand one full GSO-ready flush window \
             to the QUIC sender instead of splitting it into 64-symbol scheduler turns"
        );
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, 54, 0.0),
            flush_window - 54,
            "pending DATAGRAMs still reduce the next handoff to the remaining flush window"
        );
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, flush_window, 0.0),
            1,
            "a full queue reports the minimum nudge so the caller flushes before enqueueing more"
        );
    }

    #[test]
    fn lossy_handoff_limit_preserves_bounded_scheduler_turns() {
        let flush_window = 54 * QUIC_CLEAN_GSO_PACKETS_PER_FLUSH;
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, 0, 0.02),
            QUIC_LOSSY_SPRAY_HANDOFF_MAX_SYMBOLS,
            "lossy paths keep the old conservative per-turn handoff cap"
        );
        assert_eq!(
            spray_handoff_symbol_limit_for(32, 0, 0.02),
            32,
            "small lossy pacing bursts are still limited by the paced flush window"
        );
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, flush_window - 10, 0.02),
            10,
            "pending DATAGRAMs can shrink the lossy handoff below the cap"
        );
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, 0, QUIC_CLEAN_SPRAY_MAX_LOSS_RATE),
            QUIC_LOSSY_SPRAY_HANDOFF_MAX_SYMBOLS,
            "the clean fast path remains below the documented loss ceiling"
        );
    }

    #[test]
    fn lossy_spray_flush_limit_preserves_pacing_burst() {
        let loss = QUIC_CLEAN_SPRAY_MAX_LOSS_RATE;
        assert_eq!(
            coalesced_spray_flush_symbol_limit(1, 51, 54, loss, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            1
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(50, 51, 54, loss, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            50
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(54, 51, 54, loss, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            51
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(
                128,
                51,
                256,
                loss,
                QUIC_CLEAN_GSO_PACKETS_PER_FLUSH
            ),
            102
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(0, 51, 54, loss, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            1
        );
    }

    #[test]
    fn quic_gso_send_strategy_uses_full_protected_packet_segments() {
        let peer = "127.0.0.1:9000".parse().unwrap();
        let packets = vec![
            OutgoingPacket {
                dst_addr: peer,
                data: vec![0; ATP_QUIC_UDP_MAX_PACKET],
                send_time: None,
            };
            QUIC_CLEAN_GSO_PACKETS_PER_FLUSH
        ];

        let strategy = quic_gso_send_strategy(&packets);
        assert_eq!(strategy.gso_segment_bytes, ATP_QUIC_UDP_MAX_PACKET);
        assert_eq!(strategy.max_gso_segments, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH);
    }

    #[test]
    fn inbound_receive_limit_reserves_slots_for_coalesced_datagrams() {
        assert_eq!(inbound_udp_packet_receive_limit(0, 64), 0);
        assert_eq!(inbound_udp_packet_receive_limit(63, 64), 0);
        assert_eq!(inbound_udp_packet_receive_limit(64, 64), 1);
        assert_eq!(inbound_udp_packet_receive_limit(4096, 64), 64);
        assert_eq!(
            inbound_udp_packet_receive_limit(usize::MAX, 64),
            INBOUND_PUMP_BATCH
        );
        let max_app_payload = one_rtt_max_payload_for_udp_packet(ATP_QUIC_UDP_MAX_PACKET);
        let default_frame_len = symbol_datagram_frame_len(
            super::super::DEFAULT_SYMBOL_SIZE,
            super::super::ENVELOPE_HEADER_LEN,
        );
        let default_frames =
            coalesced_datagram_frames_per_packet(max_app_payload, default_frame_len);
        let default_limit = inbound_udp_packet_receive_limit(4096, default_frames);
        assert!(default_limit > 0);
        assert!(default_limit.saturating_mul(default_frames) <= 4096);
    }

    #[test]
    fn quic_endpoint_packet_budget_accepts_matrix37_lossy_overshoot() {
        // MATRIX-37 encrypted lossy cells failed deterministically at 16 KiB + 1..6
        // bytes when ACK/control frames were coalesced with near-full 1-RTT data.
        let legacy_cap = 16 * 1024;
        let observed_overshoot = legacy_cap + 6;

        assert!(observed_overshoot > legacy_cap);
        assert!(observed_overshoot <= ATP_QUIC_UDP_MAX_PACKET);
    }

    #[test]
    fn native_receive_decoded_trace_includes_receiver_counters() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(8)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_log_collector(collector.clone());
        let counters = NativeReceiveTraceCounters {
            udp_packets_received: 17,
            one_rtt_packets_ingested: 16,
            non_one_rtt_packets_dropped: 1,
            unprotect_packets_dropped: 2,
            datagrams_received: 12,
            datagrams_dropped_on_receive: 0,
            pending_datagrams: 3,
            pending_received_packets: 2,
            inbound_datagram_capacity: 4096,
            inbound_datagram_available: 4093,
            inbound_pump_batch_limit: INBOUND_PUMP_BATCH,
            udp_recv_buffer_requested: Some(16 * 1024 * 1024),
            udp_recv_buffer_applied: Some(32 * 1024 * 1024),
            udp_kernel_rx_queue_bytes: Some(4096),
            udp_kernel_drops: Some(7),
        };
        let decode_stats = crate::net::atp::transport_quic::QuicDecodeStats {
            decode_count: 4,
            decode_micros: 55,
        };

        counters.trace_decoded(&cx, "transfer-g3", 99, 2, &decode_stats);

        let entries = collector.peek();
        let entry = entries
            .iter()
            .find(|entry| entry.message() == "atp_quic.receive.decoded")
            .expect("receive decoded trace entry");
        assert_eq!(entry.level(), crate::observability::LogLevel::Trace);
        assert_eq!(entry.get_field("transfer_id"), Some("transfer-g3"));
        assert_eq!(entry.get_field("symbols_accepted"), Some("99"));
        assert_eq!(entry.get_field("feedback_rounds"), Some("2"));
        assert_eq!(entry.get_field("decode_count"), Some("4"));
        assert_eq!(entry.get_field("decode_micros"), Some("55"));
        assert_eq!(entry.get_field("datagrams_received"), Some("12"));
        assert_eq!(entry.get_field("datagrams_dropped_on_receive"), Some("0"));
        assert_eq!(entry.get_field("pending_datagrams"), Some("3"));
        assert_eq!(entry.get_field("reorder_occupancy"), Some("3"));
        assert_eq!(entry.get_field("pending_received_packets"), Some("2"));
        let socket_entry = entries
            .iter()
            .find(|entry| entry.message() == "atp_quic.receive.socket")
            .expect("receive socket trace entry");
        assert_eq!(socket_entry.level(), crate::observability::LogLevel::Trace);
        assert_eq!(socket_entry.get_field("transfer_id"), Some("transfer-g3"));
        assert_eq!(socket_entry.get_field("udp_packets_received"), Some("17"));
        assert_eq!(
            socket_entry.get_field("one_rtt_packets_ingested"),
            Some("16")
        );
        assert_eq!(
            socket_entry.get_field("non_one_rtt_packets_dropped"),
            Some("1")
        );
        assert_eq!(
            socket_entry.get_field("unprotect_packets_dropped"),
            Some("2")
        );
        assert_eq!(
            socket_entry.get_field("inbound_datagram_capacity"),
            Some("4096")
        );
        assert_eq!(
            socket_entry.get_field("inbound_datagram_available"),
            Some("4093")
        );
        assert_eq!(
            socket_entry.get_field("inbound_pump_batch_limit"),
            Some("512")
        );
        assert_eq!(
            socket_entry.get_field("udp_recv_buffer_requested"),
            Some("16777216")
        );
        assert_eq!(
            socket_entry.get_field("udp_recv_buffer_applied"),
            Some("33554432")
        );
        assert_eq!(
            socket_entry.get_field("udp_kernel_rx_queue_bytes"),
            Some("4096")
        );
        assert_eq!(socket_entry.get_field("udp_kernel_drops"), Some("7"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_udp_proc_receive_stats_parses_rx_queue_and_drops() {
        let table = "\
  sl  local_address rem_address   st tx_queue:rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  7: 0100007F:9C40 00000000:0000 07 00000000:00001000 00:00000000 00000000  1000        0 12345 2 0000000000000000 17
";
        let local: SocketAddr = "127.0.0.1:40000".parse().expect("local addr");
        let stats = linux_udp_proc_receive_stats_from_table(table, local)
            .expect("synthetic udp row should match local socket");

        assert_eq!(
            stats,
            LinuxUdpProcReceiveStats {
                rx_queue_bytes: 4096,
                drops: 17,
            }
        );
    }

    #[test]
    fn sender_drops_exact_duplicate_need_more_resends_only() {
        let served = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 1,
                symbols: 7,
            }],
            source_symbols: Vec::new(),
            round_symbols_observed: Some(90),
            round_loss_fraction: Some(0.10),
            round_symbols_accepted: Some(88),
            ..QuicNeedMore::default()
        };
        let same_request_different_telemetry = QuicNeedMore {
            round_symbols_observed: Some(42),
            round_loss_fraction: Some(0.42),
            round_symbols_accepted: Some(37),
            ..served.clone()
        };
        let changed_feedback_round = QuicNeedMore {
            feedback_round: 2,
            ..served.clone()
        };
        let changed = QuicNeedMore {
            repair_blocks: vec![QuicBlockRepairRequest {
                symbols: 3,
                ..served.repair_blocks[0]
            }],
            round_symbols_observed: Some(7),
            round_loss_fraction: Some(0.0),
            round_symbols_accepted: Some(7),
            ..served.clone()
        };
        let mut pending = VecDeque::from([
            super::super::json_frame(FrameType::ObjectRequest, &served)
                .expect("duplicate need-more"),
            super::super::json_frame(FrameType::ObjectRequest, &same_request_different_telemetry)
                .expect("duplicate need-more with fresh telemetry"),
            Frame::empty(FrameType::Proof).expect("proof frame"),
            super::super::json_frame(FrameType::ObjectRequest, &changed_feedback_round)
                .expect("next-round same-shape need-more"),
            super::super::json_frame(FrameType::ObjectRequest, &changed)
                .expect("changed need-more"),
            super::super::json_frame(FrameType::ObjectRequest, &served)
                .expect("duplicate need-more"),
        ]);

        let dropped = drop_duplicate_need_more_frames(&mut pending, &served)
            .expect("duplicate filter parses queued feedback");

        assert_eq!(dropped, 3);
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0].frame_type(), FrameType::Proof);
        assert_eq!(pending[1].frame_type(), FrameType::ObjectRequest);
        assert_eq!(pending[2].frame_type(), FrameType::ObjectRequest);
        let retained =
            super::super::parse_json::<QuicNeedMore>(&pending[1]).expect("retained need-more");
        assert_eq!(retained, changed_feedback_round);
        let retained =
            super::super::parse_json::<QuicNeedMore>(&pending[2]).expect("retained need-more");
        assert_eq!(retained, changed);
    }

    #[test]
    fn need_more_pto_retransmits_recorded_offsets_without_appending() {
        assert_eq!(need_more_pto_mode(&[]), NeedMorePtoMode::SendFresh);
        let recorded = [SentControlStreamFrame {
            stream: StreamId(0),
            offset: 4096,
        }];
        assert_eq!(
            need_more_pto_mode(&recorded),
            NeedMorePtoMode::RetransmitRecorded
        );
    }

    #[test]
    fn source_stream_ack_ranges_extract_sparse_packet_ranges() {
        let ack = QuicFrame::Ack {
            largest_acknowledged: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(10),
            ack_delay: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(0),
            ack_range_count: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(1),
            first_ack_range: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(2),
            ack_ranges: vec![crate::net::atp::protocol::quic_frames::AckRange {
                gap: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(1),
                ack_range_length: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(1),
            }],
            ecn_counts: None,
        };

        let ranges = acked_packet_ranges_from_frames(&[ack]).expect("ACK ranges decode");

        assert_eq!(
            ranges,
            vec![
                NativeAckRange::new(10, 8).expect("first ACK range"),
                NativeAckRange::new(5, 4).expect("second ACK range"),
            ]
        );
        assert!(packet_in_ack_ranges(10, &ranges));
        assert!(packet_in_ack_ranges(8, &ranges));
        assert!(packet_in_ack_ranges(4, &ranges));
        assert!(!packet_in_ack_ranges(7, &ranges));
        assert!(!packet_in_ack_ranges(11, &ranges));
        assert!(packet_lost_by_ack_gap(6, &ranges));
        assert!(packet_lost_by_ack_gap(7, &ranges));
        assert!(!packet_lost_by_ack_gap(8, &ranges));
        assert!(!packet_lost_by_ack_gap(10, &ranges));
        assert!(!packet_lost_by_ack_gap(11, &ranges));
    }

    #[test]
    fn source_stream_retransmit_frames_are_sorted_and_deduplicated() {
        let stream = StreamId(4);
        let frames = vec![
            SentControlStreamFrame {
                stream,
                offset: 4096,
            },
            SentControlStreamFrame {
                stream,
                offset: 1024,
            },
            SentControlStreamFrame {
                stream,
                offset: 4096,
            },
            SentControlStreamFrame {
                stream: StreamId(8),
                offset: 0,
            },
        ];

        assert_eq!(
            dedup_stream_frames_for_retransmit(frames),
            vec![
                SentControlStreamFrame {
                    stream,
                    offset: 1024,
                },
                SentControlStreamFrame {
                    stream,
                    offset: 4096,
                },
                SentControlStreamFrame {
                    stream: StreamId(8),
                    offset: 0,
                },
            ]
        );
    }

    #[test]
    fn source_stream_completion_pto_retransmits_only_tail_frames() {
        let stream = StreamId(4);
        let frames = (0..8)
            .map(|idx| SentControlStreamFrame {
                stream,
                offset: idx * 1024,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            tail_stream_frames_for_retransmit(
                &frames,
                QUIC_SOURCE_STREAM_COMPLETION_PTO_MAX_FRAMES,
            ),
            vec![
                SentControlStreamFrame {
                    stream,
                    offset: 4096,
                },
                SentControlStreamFrame {
                    stream,
                    offset: 5120,
                },
                SentControlStreamFrame {
                    stream,
                    offset: 6144,
                },
                SentControlStreamFrame {
                    stream,
                    offset: 7168,
                },
            ],
            "completion PTO should not replay the whole final source-stream flush window"
        );
    }

    #[test]
    fn sender_retains_need_more_with_changed_pending_or_source_shape() {
        let served = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 1,
                symbols: 7,
            }],
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 0,
                sbn: 1,
                esi: 4,
            }],
            round_symbols_observed: Some(90),
            round_loss_fraction: Some(0.10),
            round_symbols_accepted: Some(88),
            ..QuicNeedMore::default()
        };
        let changed_pending = QuicNeedMore {
            pending: vec![1],
            ..served.clone()
        };
        let changed_source = QuicNeedMore {
            source_symbols: vec![QuicSourceSymbolRequest {
                esi: 5,
                ..served.source_symbols[0]
            }],
            ..served.clone()
        };
        let mut pending = VecDeque::from([
            super::super::json_frame(FrameType::ObjectRequest, &served)
                .expect("duplicate need-more"),
            super::super::json_frame(FrameType::ObjectRequest, &changed_pending)
                .expect("changed pending need-more"),
            super::super::json_frame(FrameType::ObjectRequest, &changed_source)
                .expect("changed source need-more"),
        ]);

        let dropped = drop_duplicate_need_more_frames(&mut pending, &served)
            .expect("duplicate filter parses queued feedback");

        assert_eq!(dropped, 1);
        assert_eq!(pending.len(), 2);
        let retained_pending = super::super::parse_json::<QuicNeedMore>(&pending[0])
            .expect("retained pending need-more");
        let retained_source = super::super::parse_json::<QuicNeedMore>(&pending[1])
            .expect("retained source need-more");
        assert_eq!(retained_pending, changed_pending);
        assert_eq!(retained_source, changed_source);
    }

    #[test]
    fn needmore_pto_attempt_budget_tracks_configured_idle_timeout() {
        assert_eq!(
            needmore_pto_attempt_budget(Duration::from_secs(60)),
            40,
            "the old default maps to the historical 60s PTO window"
        );
        assert_eq!(
            needmore_pto_attempt_budget(super::super::DEFAULT_IDLE_TIMEOUT),
            240,
            "the encrypted-lossy default gives repair rounds a 360s PTO window"
        );
        assert_eq!(
            needmore_pto_attempt_budget(Duration::from_millis(100)),
            MIN_NEEDMORE_PTO_ATTEMPTS,
            "short-timeout tests still fail fast instead of inheriting the production budget"
        );
    }

    fn quic_staging_test_entry(size: u64) -> crate::net::atp::transport_quic::ManifestEntry {
        crate::net::atp::transport_quic::ManifestEntry {
            index: 0,
            rel_path: "entry.bin".to_string(),
            size,
            sha256_hex: "0".repeat(64),
            metadata: None,
        }
    }

    #[test]
    fn native_receiver_intake_trace_records_pump_feed_and_staging_work() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(8)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_log_collector(collector.clone());
        let mut stats = NativeReceiverIntakeStats::default();
        stats.record_symbol_drain(Duration::from_micros(11), 9, 7, 2);
        stats.record_pump(Duration::from_micros(13), 5);
        stats.record_staging_write(Duration::from_micros(17), 1024);
        stats.trace_summary(&cx, "transfer-intake");

        let entries = collector.peek();
        let entry = entries
            .iter()
            .find(|entry| entry.message() == "atp_quic.receive.intake")
            .expect("receive intake trace entry");
        assert_eq!(entry.get_field("transfer_id"), Some("transfer-intake"));
        assert_eq!(entry.get_field("drain_calls"), Some("1"));
        assert_eq!(entry.get_field("symbols_observed"), Some("9"));
        assert_eq!(entry.get_field("symbols_accepted"), Some("7"));
        assert_eq!(entry.get_field("blocks_completed"), Some("2"));
        assert_eq!(entry.get_field("drain_micros"), Some("11"));
        assert_eq!(entry.get_field("pump_calls"), Some("1"));
        assert_eq!(entry.get_field("pump_packets"), Some("5"));
        assert_eq!(entry.get_field("pump_micros"), Some("13"));
        assert_eq!(entry.get_field("staging_write_count"), Some("1"));
        assert_eq!(entry.get_field("staging_write_bytes"), Some("1024"));
        assert_eq!(entry.get_field("staging_write_micros"), Some("17"));
    }

    #[test]
    fn quic_staging_cache_policy_is_bounded() {
        assert!(should_cache_quic_staging_file(
            QUIC_STAGING_FILE_CACHE_MIN_BYTES,
            QUIC_STAGING_FILE_CACHE_MAX_ENTRIES
        ));
        assert!(!should_cache_quic_staging_file(
            QUIC_STAGING_FILE_CACHE_MIN_BYTES - 1,
            1
        ));
        assert!(!should_cache_quic_staging_file(
            QUIC_STAGING_FILE_CACHE_MIN_BYTES,
            QUIC_STAGING_FILE_CACHE_MAX_ENTRIES + 1
        ));
    }

    #[test]
    fn quic_staging_large_entry_cache_reuses_and_closes_file() {
        let temp = tempfile::tempdir().expect("temp dir");
        let staging_path = temp.path().join("entry0");
        let entry = quic_staging_test_entry(QUIC_STAGING_FILE_CACHE_MIN_BYTES);
        let config = QuicConfig {
            max_block_size: 4,
            ..QuicConfig::default()
        };
        let mut staged = QuicStagedEntryReceive::new(staging_path.clone(), entry.size, 1);

        futures_lite::future::block_on(staged.write_block(&entry, 0, &[1, 2, 3, 4], &config))
            .expect("write first cached block");
        assert!(staged.staging_file.is_some());
        assert_eq!(staged.staging_cursor, Some(4));
        assert_eq!(staged.staging_unflushed_bytes, 4);

        futures_lite::future::block_on(staged.write_block(&entry, 1, &[5, 6, 7, 8], &config))
            .expect("write second cached block");
        assert!(staged.staging_file.is_some());
        assert_eq!(staged.staging_cursor, Some(8));
        assert_eq!(staged.staging_unflushed_bytes, 8);

        futures_lite::future::block_on(staged.close_cached_staging_file())
            .expect("close cached staging file");
        assert!(staged.staging_file.is_none());
        assert_eq!(staged.staging_cursor, None);
        assert_eq!(staged.staging_unflushed_bytes, 0);

        let mut file = std::fs::File::open(staging_path).expect("open staged file");
        let mut prefix = [0u8; 8];
        std::io::Read::read_exact(&mut file, &mut prefix).expect("read staged prefix");
        assert_eq!(prefix, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn quic_staging_dir_guard_reclaims_on_hard_drop_unless_disarmed() {
        let temp = tempfile::tempdir().expect("temp dir");
        let armed = temp.path().join(".atp-quic-staging-guard-armed");
        std::fs::create_dir_all(&armed).expect("create armed staging dir");
        {
            let _guard = QuicStagingDirGuard::new(armed.clone());
        }
        assert!(
            !armed.exists(),
            "armed QuicStagingDirGuard must reclaim staging dir on drop"
        );

        let disarmed = temp.path().join(".atp-quic-staging-guard-disarmed");
        std::fs::create_dir_all(&disarmed).expect("create disarmed staging dir");
        {
            let mut guard = QuicStagingDirGuard::new(disarmed.clone());
            guard.disarm();
        }
        assert!(
            disarmed.exists(),
            "disarmed QuicStagingDirGuard must leave cooperative cleanup to the caller"
        );
    }

    #[test]
    fn quic_cached_staging_file_flushes_round_boundary_without_closing() {
        let temp = tempfile::tempdir().expect("temp dir");
        let staging_path = temp.path().join("entry0");
        let entry = quic_staging_test_entry(8);
        let config = QuicConfig {
            max_block_size: 4,
            ..QuicConfig::default()
        };
        let mut staged = QuicStagedEntryReceive::new(staging_path.clone(), entry.size, 1);
        staged.cache_staging_file = true;

        futures_lite::future::block_on(staged.write_block(&entry, 0, &[1, 2, 3, 4], &config))
            .expect("write first decoded block");
        assert!(
            staged.staging_file.is_some(),
            "large-entry QUIC receive should keep the staging descriptor hot"
        );
        assert_eq!(staged.staging_cursor, Some(4));
        assert_eq!(staged.staging_unflushed_bytes, 4);

        futures_lite::future::block_on(staged.flush_cached_staging_file())
            .expect("round-boundary flush");
        assert!(
            staged.staging_file.is_some(),
            "round-boundary flush should preserve the hot descriptor"
        );
        assert_eq!(staged.staging_cursor, Some(4));
        assert_eq!(staged.staging_unflushed_bytes, 0);

        futures_lite::future::block_on(staged.write_block(&entry, 1, &[5, 6, 7, 8], &config))
            .expect("write second decoded block");
        assert_eq!(staged.staging_cursor, Some(8));

        futures_lite::future::block_on(staged.close_cached_staging_file())
            .expect("close cached descriptor");
        assert!(staged.staging_file.is_none());
        assert_eq!(staged.staging_cursor, None);
        assert_eq!(staged.staging_unflushed_bytes, 0);
        assert_eq!(
            std::fs::read(staging_path).expect("read staged bytes"),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
    }
}
