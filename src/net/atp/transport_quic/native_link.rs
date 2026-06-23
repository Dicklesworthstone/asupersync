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
//! end-to-end. The reliable control STREAM, however, is **not** retransmitted by
//! this pump (QUIC loss recovery for stream frames is not wired here), so the
//! control plane currently assumes a low-loss path (loopback / LAN). The pump
//! never injects loss into packets carrying control STREAM bytes; deterministic
//! symbol loss for tests is injected before a symbol is sprayed
//! ([`QuicConfig::debug_drop_one_in`]), so the control channel stays intact.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};

use crate::bytes::BytesMut;
use crate::cx::Cx;
use crate::io::AsyncWriteExt;
use crate::net::atp::datagram::beacons::{BeaconMeasurement, BeaconScheduler};
use crate::net::atp::protocol::frames::{Frame, FrameType};
use crate::net::atp::quic::packet_protection::{AtpPacketProtection, AtpPacketProtectionConfig};
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
    NativeQuicConnection, NativeQuicConnectionConfig, OutgoingPacket, PacketNumberSpace,
    QuicUdpEndpoint, QuicUdpEndpointConfig, ReceivedPacket, StreamRole,
};
use crate::security::SecurityContext;
use crate::security::tag::TAG_SIZE;
use crate::types::outcome::Outcome;
use crate::types::symbol::Symbol;

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
    control: &mut NativeQuicFrameTransport,
) -> Result<(), QuicTransportError> {
    let frame = Frame::empty(FrameType::KeepAlive)
        .map_err(|err| QuicTransportError::Frame(err.to_string()))?;
    control.send(cx, conn, &frame)
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
/// After the first full batch, wait only a tiny quiet window for the next batch.
/// `UdpSocket::recv_batch_from` drains immediately-ready datagrams internally;
/// this grace covers the full-batch case where the kernel may still have more
/// packets queued without charging a full idle timeout to every drain attempt.
const INBOUND_PUMP_DRAIN_GRACE: Duration = Duration::from_millis(1);

/// Quiet window that ends a receiver symbol round after at least one symbol was
/// accepted. This must be much shorter than the sender's Proof/NeedMore timeout
/// so feedback reaches the sender before it gives up, while still giving the UDP
/// pump room to drain a burst between paced sender flushes.
const ROUND_PROGRESS_IDLE_GRACE: Duration = Duration::from_millis(250);

/// Control-plane PTO. When the receiver is awaiting repair after a NeedMore and the link goes idle,
/// the NeedMore (receiver->sender) or the repair round (sender->receiver) was likely lost on the wire
/// — ATP control rides best-effort 1-RTT here, so under real-internet loss a single dropped NeedMore
/// otherwise deadlocks both sides until the full idle timeout. Re-send the NeedMore on this interval
/// instead; this is what lets cross-machine transfers converge through control-frame loss.
const NEEDMORE_PTO: Duration = Duration::from_millis(1500);
/// Max NeedMore re-sends while awaiting one round's repair before giving up
/// (`NEEDMORE_PTO * MAX_NEEDMORE_PTO` is the effective per-round idle budget).
const MAX_NEEDMORE_PTO: u32 = 40;

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

fn need_more_repair_symbol_count(need: &QuicNeedMore) -> u64 {
    need.repair_blocks.iter().fold(0u64, |acc, request| {
        acc.saturating_add(u64::from(request.symbols))
    })
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
            if queued == *served_need {
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
    /// Monotonic outbound 1-RTT packet number.
    send_pn: u64,
    /// Monotonic data-plane clock fed to the connection.
    clock: u64,
    /// Max application payload that fits one 1-RTT packet under the endpoint MTU.
    max_app_payload: usize,
    /// Expected upper bound on ATP symbol DATAGRAM frames one received UDP
    /// packet may enqueue before the symbol decoder gets a turn to drain them.
    max_datagram_frames_per_packet: usize,
    idle_timeout: Duration,
    beacons: BeaconScheduler,
    pending_control_frames: VecDeque<Frame>,
    udp_packets_received: u64,
    one_rtt_packets_ingested: u64,
    non_one_rtt_packets_dropped: u64,
    unprotect_packets_dropped: u64,
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
    inbound_datagram_capacity: usize,
    inbound_datagram_available: usize,
    inbound_pump_batch_limit: usize,
}

impl NativeReceiveTraceCounters {
    fn capture(link: &QuicLink) -> Self {
        Self {
            udp_packets_received: link.udp_packets_received,
            one_rtt_packets_ingested: link.one_rtt_packets_ingested,
            non_one_rtt_packets_dropped: link.non_one_rtt_packets_dropped,
            unprotect_packets_dropped: link.unprotect_packets_dropped,
            datagrams_received: link.conn.datagrams_received(),
            datagrams_dropped_on_receive: link.conn.datagrams_dropped_on_receive(),
            pending_datagrams: link.conn.pending_datagram_count(),
            inbound_datagram_capacity: link.conn.inbound_datagram_capacity(),
            inbound_datagram_available: link.conn.inbound_datagram_remaining_capacity(),
            inbound_pump_batch_limit: INBOUND_PUMP_BATCH,
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
        let inbound_datagram_capacity_text = self.inbound_datagram_capacity.to_string();
        let inbound_datagram_available_text = self.inbound_datagram_available.to_string();
        let inbound_pump_batch_limit_text = self.inbound_pump_batch_limit.to_string();
        cx.trace_with_fields(
            "atp_quic.receive.decoded",
            &[
                ("transfer_id", transfer_id),
                ("symbols_accepted", symbols_accepted_text.as_str()),
                ("feedback_rounds", feedback_rounds_text.as_str()),
                ("decode_count", decode_count_text.as_str()),
                ("decode_micros", decode_micros_text.as_str()),
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
                ("datagrams_received", datagrams_received_text.as_str()),
                (
                    "datagrams_dropped_on_receive",
                    datagrams_dropped_on_receive_text.as_str(),
                ),
                ("pending_datagrams", pending_datagrams_text.as_str()),
                ("reorder_occupancy", pending_datagrams_text.as_str()),
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
            ],
        );
    }
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

    async fn service_spray_liveness(
        &mut self,
        cx: &Cx,
        control: &mut NativeQuicFrameTransport,
    ) -> Result<(), QuicTransportError> {
        let _ = self.pump_inbound_for(cx, INBOUND_PUMP_DRAIN_GRACE).await?;
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

    /// Drain all currently-pending application frames, protect each into a 1-RTT
    /// packet, and send the batch over UDP. Returns the number of packets sent.
    async fn flush(&mut self, cx: &Cx) -> Result<usize, QuicTransportError> {
        let mut packets = Vec::new();
        loop {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            let frames = self.conn.generate_frames(
                cx,
                PacketNumberSpace::ApplicationData,
                self.max_app_payload,
            )?;
            if frames.is_empty() {
                break;
            }
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload)?;
            let packet_number = self.send_pn;
            self.send_pn = self.send_pn.saturating_add(1);
            let header = encode_one_rtt_header(packet_number);
            let protected = protection_result(
                self.protection
                    .protect_packet(
                        cx,
                        PacketProtectionRequest {
                            space: PacketProtectionSpace::OneRtt,
                            key_phase: false,
                            packet_number,
                            associated_data: &header,
                            payload: &payload,
                        },
                    )
                    .await,
            )?;
            let mut data = Vec::with_capacity(
                ONE_RTT_HEADER_LEN + protected.ciphertext.len() + ONE_RTT_TAG_LEN,
            );
            data.extend_from_slice(&header);
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
        let count = packets.len();
        if !packets.is_empty() {
            let report = self
                .endpoint
                .send_batch(cx, &packets)
                .await
                .map_err(map_udp_error)?;
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
        }
        Ok(count)
    }

    /// Unprotect and process a single received UDP packet as a 1-RTT data-plane
    /// packet. Returns `true` if it was a valid, decryptable 1-RTT packet that was
    /// fed into the connection; non-1-RTT or undecryptable/replayed packets are
    /// silently dropped (QUIC semantics) and return `false`.
    async fn ingest_packet(
        &mut self,
        cx: &Cx,
        packet: &ReceivedPacket,
    ) -> Result<bool, QuicTransportError> {
        let Some((key_phase, packet_number, header, ciphertext, tag)) =
            decode_one_rtt_packet(&packet.data)
        else {
            self.non_one_rtt_packets_dropped = self.non_one_rtt_packets_dropped.saturating_add(1);
            return Ok(false);
        };
        let protected = ProtectedPacket {
            space: PacketProtectionSpace::OneRtt,
            key_phase,
            packet_number,
            ciphertext: ciphertext.to_vec(),
            tag,
            proof: ProtectionProof {
                provider_kind: self.protection.provider_kind(),
                space: PacketProtectionSpace::OneRtt,
                key_phase,
                generation: 0,
                transcript_hash: TranscriptHash::from_bytes([0u8; 32]),
                failure_code: None,
            },
        };
        let unprotected = match self
            .protection
            .unprotect_packet(cx, &protected, header)
            .await
        {
            Outcome::Ok(value) => value,
            // Undecryptable / replayed / stray packet: drop it (QUIC semantics).
            Outcome::Err(_) | Outcome::Cancelled(_) | Outcome::Panicked(_) => {
                self.unprotect_packets_dropped = self.unprotect_packets_dropped.saturating_add(1);
                return Ok(false);
            }
        };
        self.clock = self.clock.saturating_add(CLOCK_STEP_MICROS);
        self.conn.process_packet_payload(
            cx,
            PacketNumberSpace::ApplicationData,
            packet_number,
            &unprotected.plaintext,
            self.clock,
        )?;
        self.one_rtt_packets_ingested = self.one_rtt_packets_ingested.saturating_add(1);
        self.mark_peer_activity();
        Ok(true)
    }

    /// Feed a batch of already-received packets (e.g. 1-RTT data that arrived at
    /// the server while it was still completing the handshake) into the connection.
    async fn ingest_packets(
        &mut self,
        cx: &Cx,
        packets: &[ReceivedPacket],
    ) -> Result<usize, QuicTransportError> {
        let mut processed = 0usize;
        for packet in packets {
            if self.ingest_packet(cx, packet).await? {
                processed = processed.saturating_add(1);
            }
        }
        Ok(processed)
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
        let mut total_processed = 0usize;
        let mut batches = 0usize;
        let mut next_timeout = timeout;

        loop {
            let pending_datagrams = self.conn.pending_datagram_count();
            let datagram_capacity = self.conn.inbound_datagram_capacity();
            let remaining_capacity = self.conn.inbound_datagram_remaining_capacity();
            let receive_limit = self.inbound_receive_packet_limit();
            if receive_limit == 0 {
                let pending_datagrams_text = pending_datagrams.to_string();
                let datagram_capacity_text = datagram_capacity.to_string();
                let remaining_capacity_text = remaining_capacity.to_string();
                let total_processed_text = total_processed.to_string();
                let max_datagrams_per_packet_text = self.max_datagram_frames_per_packet.to_string();
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
                        ("packets_processed", total_processed_text.as_str()),
                        (
                            "max_datagrams_per_packet",
                            max_datagrams_per_packet_text.as_str(),
                        ),
                    ],
                );
                return Ok(total_processed);
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
            total_processed =
                total_processed.saturating_add(self.ingest_packets(cx, &received).await?);

            batches = batches.saturating_add(1);
            if received_len < receive_limit {
                return Ok(total_processed);
            }
            if batches >= INBOUND_PUMP_MAX_DRAIN_BATCHES {
                let batches_s = batches.to_string();
                let total_processed_s = total_processed.to_string();
                cx.trace_with_fields(
                    "atp_quic.inbound_pump.drain_budget_exhausted",
                    &[
                        ("batches", batches_s.as_str()),
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
        QuicTransportError::Quic(format!(
            "transport timeout during receive symbol round after {timeout:?}; \
             udp_packets_received={} one_rtt_packets_ingested={} \
             non_one_rtt_packets_dropped={} unprotect_packets_dropped={} \
             datagrams_received={} datagrams_dropped_on_receive={} \
             pending_datagrams={} symbols_accepted={symbols_accepted}",
            self.udp_packets_received,
            self.one_rtt_packets_ingested,
            self.non_one_rtt_packets_dropped,
            self.unprotect_packets_dropped,
            self.conn.datagrams_received(),
            self.conn.datagrams_dropped_on_receive(),
            self.conn.pending_datagram_count(),
        ))
    }

    fn spray_pacing_decision(
        &self,
        config: &QuicConfig,
        aimd_cap_bps: Option<u64>,
    ) -> QuicSprayPacingDecision {
        let mut config = config.clone();
        if let Some(cap) = aimd_cap_bps {
            config.bwlimit_bps = Some(config.bwlimit_bps.map_or(cap, |existing| existing.min(cap)));
        }
        super::quic_spray_pacing_decision_from_transport(&config, self.conn.transport())
    }

    /// Spray one symbol, flushing first if the paced outbound queue is full.
    async fn spray_symbol(
        &mut self,
        cx: &Cx,
        control: &mut NativeQuicFrameTransport,
        symbol: &Symbol,
        tag: u64,
        entry: u32,
        auth_tag: Option<[u8; TAG_SIZE]>,
        pacing: &QuicSprayPacingDecision,
    ) -> Result<(), QuicTransportError> {
        if self.conn.pending_outbound_datagram_count() >= pacing.max_burst_symbols {
            self.flush(cx).await?;
            self.service_spray_liveness(cx, control).await?;
            crate::time::sleep(cx.now(), pacing.pause_after_burst).await;
        }
        super::send_native_symbol(cx, &mut self.conn, symbol, tag, entry, auth_tag)
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
    // Use the smallest ATP symbol envelope this link may legitimately carry
    // (trusted unauthenticated mode) so the receive batch bound remains safe for
    // both auth postures.
    let symbol_frame_len =
        symbol_datagram_frame_len(config.symbol_size, super::ENVELOPE_HEADER_LEN);
    let max_datagram_frames_per_packet =
        coalesced_datagram_frames_per_packet(max_app_payload, symbol_frame_len);
    let conn_config = NativeQuicConnectionConfig {
        role,
        max_datagram_frame_size,
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
        send_pn: 0,
        clock: 0,
        max_app_payload,
        max_datagram_frames_per_packet,
        idle_timeout: config.idle_timeout,
        beacons: BeaconScheduler::new(1, Instant::now()),
        pending_control_frames: VecDeque::new(),
        udp_packets_received: 0,
        one_rtt_packets_ingested: 0,
        non_one_rtt_packets_dropped: 0,
        unprotect_packets_dropped: 0,
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

#[derive(Debug, Default)]
struct NativeQuicAimdPacer {
    cap_bps: Option<u64>,
    last_round_symbols_sent: u64,
    last_round_pacing_rate_bps: u64,
    last_round_loss_fraction: f64,
}

impl NativeQuicAimdPacer {
    fn cap_bps(&self) -> Option<u64> {
        self.cap_bps
    }

    fn record_spray(&mut self, symbols_sent: u64, pacing_rate_bps: u64) {
        self.last_round_symbols_sent = symbols_sent;
        self.last_round_pacing_rate_bps = pacing_rate_bps;
    }

    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    fn observe_need_more(&mut self, cx: &Cx, need: &QuicNeedMore) {
        let sent = self.last_round_symbols_sent;
        if sent == 0 {
            return;
        }
        let loss = need
            .round_loss_fraction
            .filter(|loss| loss.is_finite())
            .unwrap_or_else(|| {
                let observed = need
                    .round_symbols_observed
                    .or(need.round_symbols_accepted)
                    .unwrap_or(0)
                    .min(sent);
                (1.0 - observed as f64 / sent as f64).clamp(0.0, 0.90)
            })
            .clamp(0.0, 0.90);
        self.last_round_loss_fraction = loss;
        if loss > super::QUIC_AIMD_LOSS_DECREASE_THRESHOLD {
            let base = self
                .cap_bps
                .unwrap_or(self.last_round_pacing_rate_bps)
                .max(super::QUIC_AIMD_MIN_RATE_BPS);
            let reduced = (base as f64 * super::QUIC_AIMD_MULTIPLICATIVE_DECREASE).ceil() as u64;
            self.cap_bps =
                Some(reduced.clamp(super::QUIC_AIMD_MIN_RATE_BPS, super::QUIC_AIMD_MAX_RATE_BPS));
        } else if loss <= super::QUIC_AIMD_CLEAN_INCREASE_THRESHOLD
            && let Some(cap) = self.cap_bps
        {
            self.cap_bps = Some(
                cap.saturating_add(super::QUIC_AIMD_ADDITIVE_INCREASE_BYTES_PER_S)
                    .clamp(super::QUIC_AIMD_MIN_RATE_BPS, super::QUIC_AIMD_MAX_RATE_BPS),
            );
        }

        let cap = self
            .cap_bps
            .map_or_else(|| "none".to_string(), |cap| cap.to_string());
        let sent = sent.to_string();
        let observed = need
            .round_symbols_observed
            .or(need.round_symbols_accepted)
            .unwrap_or(0)
            .to_string();
        let loss = format!("{:.4}", self.last_round_loss_fraction);
        cx.trace_with_fields(
            "atp_quic.spray.aimd_feedback",
            &[
                ("round_symbols_sent", sent.as_str()),
                ("round_symbols_observed", observed.as_str()),
                ("round_loss_fraction", loss.as_str()),
                ("aimd_cap_bps", cap.as_str()),
            ],
        );
    }
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
    let pacing = link.spray_pacing_decision(config, aimd.cap_bps());
    pacing.trace_epoch(cx, u64::from(!with_source));
    let mut sent = 0u64;
    let mut sprayed = 0u64;
    for index in pending {
        let Some(entry) = encoders.iter_mut().find(|entry| entry.index == *index) else {
            continue;
        };
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        for block_idx in 0..entry.block_count(config)? {
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
            for encoded_symbol in encoded {
                let symbol = encoded_symbol
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                // Deterministic test-only symbol loss: skip on the initial spray only,
                // so the receiver must drive a repair round, and never on a repair round
                // (otherwise it could fail to converge). Control frames are unaffected.
                sprayed = sprayed.saturating_add(1);
                if with_source && drop_one_in > 0 && sprayed % u64::from(drop_one_in) == 0 {
                    continue;
                }
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
                link.spray_symbol(cx, control, &symbol, tag, entry_index, auth_tag, &pacing)
                    .await?;
                sent = sent.saturating_add(1);
            }
            entry.set_repair_cursor(sbn, target_repair);
        }
    }
    aimd.record_spray(sent, pacing.pacing_rate_bps);
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
    let pacing = link.spray_pacing_decision(config, aimd.cap_bps());
    pacing.trace_epoch(cx, 2);
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
        let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
        link.spray_symbol(cx, control, &symbol, tag, request.entry, auth_tag, &pacing)
            .await?;
        sent = sent.saturating_add(1);
    }
    aimd.record_spray(sent, pacing.pacing_rate_bps);
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
    let pacing = link.spray_pacing_decision(config, aimd.cap_bps());
    pacing.trace_epoch(cx, 3);
    let mut sent = 0u64;
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
        let mut pipeline = super::encoding_pipeline(config);
        let object_id = enc.object_id;
        let entry_index = enc.index;
        let sent_before_request = sent;
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
            let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
            link.spray_symbol(cx, control, &symbol, tag, entry_index, auth_tag, &pacing)
                .await?;
            sent = sent.saturating_add(1);
        }
        let emitted_for_request = sent.saturating_sub(sent_before_request);
        if emitted_for_request != u64::from(request.symbols) {
            return Err(QuicTransportError::Integrity(format!(
                "sender emitted {emitted_for_request} repair symbols for receiver-requested deficit {} on entry {} block {}",
                request.symbols, entry_index, request.sbn
            )));
        }
        enc.set_repair_cursor(request.sbn, target_repair);
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
    aimd.record_spray(sent, pacing.pacing_rate_bps);
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
    super::send_native_sender_hello(
        cx,
        &mut link.conn,
        &mut control,
        config,
        peer_id,
        symbol_auth_enabled,
    )?;
    link.flush(cx).await?;
    let ack_frame = link
        .next_control_frame(cx, &mut control, "receive sender handshake ack")
        .await?;
    let _ack = parse_hello_ack(&ack_frame)?;

    let mut encoders = super::encoders_from_prepared_source(cx, prepared, config).await?;
    super::send_native_manifest(cx, &mut link.conn, &mut control, manifest)?;
    link.flush(cx).await?;

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
    // Push every sprayed symbol onto the wire BEFORE the ObjectComplete marker so
    // the (in-order, loopback/LAN) receiver drains all of this round's symbols
    // before it reads ObjectComplete and assembles. `generate_frames` emits the
    // ObjectComplete STREAM frame ahead of queued DATAGRAMs within a single flush,
    // so without this split a >1-batch spray would assemble prematurely and force
    // a needless feedback round.
    link.flush(cx).await?;
    super::send_native_object_complete(cx, &mut link.conn, &mut control, symbols_sent)?;
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
                aimd.observe_need_more(cx, &need);
                feedback_rounds = feedback_rounds.saturating_add(1);
                let requested_repair_symbols = need_more_repair_symbol_count(&need);
                let repair_detail = repair_block_trace_summary(&need.repair_blocks);
                quic_rqtrace!(
                    "sender: NeedMore round={feedback_rounds} pending={} repair_blocks={} requested_repair_symbols={} source_requests={} round_symbols_observed={} round_symbols_accepted={} round_loss_fraction={:.4} max_feedback_rounds={} round_cap_exceeded={} repair_symbol_round_cap={} prior_total_symbols_sent={} prior_round_symbols_sent={} prior_pacing_rate_bps={} repair_blocks_detail={}",
                    need.pending.len(),
                    need.repair_blocks.len(),
                    requested_repair_symbols,
                    need.source_symbols.len(),
                    need.round_symbols_observed.unwrap_or(0),
                    need.round_symbols_accepted.unwrap_or(0),
                    need.round_loss_fraction.unwrap_or(0.0),
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
                    super::send_native_object_complete(cx, &mut link.conn, &mut control, 0)?;
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
                        &need.repair_blocks,
                        config,
                        symbol_auth.as_ref(),
                        &mut aimd,
                    )
                    .await?
                } else if need.source_symbols.is_empty() {
                    return Err(QuicTransportError::Integrity(
                        "receiver NeedMore listed pending entries without targeted repair/source deficits"
                            .to_string(),
                    ));
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
                if !need.repair_blocks.is_empty() && sent != requested_repair_symbols {
                    return Err(QuicTransportError::Integrity(format!(
                        "sender emitted {sent} repair symbols for receiver-requested deficit {requested_repair_symbols}"
                    )));
                }
                symbols_sent = symbols_sent.saturating_add(sent);
                super::trace_quic_sender_repair_round(
                    cx,
                    feedback_rounds,
                    response_mode,
                    symbols_before,
                    sent,
                    &need,
                );
                quic_rqtrace!(
                    "sender: repair_round round={feedback_rounds} emitted_symbols={sent} requested_repair_symbols={requested_repair_symbols} total_symbols_sent={symbols_sent} pacing_rate_bps={} max_feedback_rounds={} round_cap_enforced=false",
                    aimd.last_round_pacing_rate_bps,
                    config.max_feedback_rounds,
                );
                // Flush this round's repair/source symbols before ObjectComplete
                // (same ordering guarantee as the initial spray).
                link.flush(cx).await?;
                super::send_native_object_complete(cx, &mut link.conn, &mut control, sent)?;
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
    fn record_symbol_drain(&mut self, elapsed: Duration, accepted: u64, completed_blocks: usize) {
        self.drain_calls = self.drain_calls.saturating_add(1);
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
        let repair_block_requests = super::quic_repair_block_request_summary(&need.repair_blocks);
        let repair_symbol_round_cap = super::MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND.to_string();
        let repair_block_request_cap =
            super::MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND.to_string();
        let drain_calls = self.drain_calls.to_string();
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
                ("repair_block_requests", repair_block_requests.as_str()),
                ("repair_symbol_round_cap", repair_symbol_round_cap.as_str()),
                (
                    "repair_block_request_cap",
                    repair_block_request_cap.as_str(),
                ),
                ("drain_calls", drain_calls.as_str()),
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
    let ack = QuicHelloAck {
        accepted,
        peer_id: peer_id.to_string(),
        reason: reason.clone(),
    };
    let ack_frame = super::json_frame(FrameType::HandshakeAck, &ack)?;
    control.send(cx, &mut link.conn, &ack_frame)?;
    link.flush(cx).await?;
    if let Some(reason) = reason {
        return Err(QuicTransportError::HandshakeRejected(reason));
    }

    // Manifest.
    let manifest_frame = link
        .next_control_frame(cx, &mut control, "receive transfer manifest")
        .await?;
    let manifest: TransferManifest =
        super::parse_json_frame(&manifest_frame, FrameType::ObjectManifest, "ObjectManifest")?;
    super::validate_quic_manifest(&manifest, config)?;

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
    let mut symbols_accepted = 0u64;
    let mut feedback_rounds = 0u32;
    let mut decode_stats = super::QuicDecodeStats::default();
    let mut intake_stats = NativeReceiverIntakeStats::default();
    // Control-plane PTO state: the last NeedMore we sent and how many times we have re-sent it while
    // awaiting this round's repair. Lets a lost control frame self-heal instead of deadlocking.
    let mut last_need: Option<QuicNeedMore> = None;
    let mut needmore_pto_attempts = 0u32;

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
            let mut round_complete = super::QuicRoundComplete::default();
            loop {
                let drain_started = Instant::now(); // ubs:ignore - monotonic intake timing, not crypto randomness
                let (observed, accepted, completed_blocks) =
                    super::drain_native_symbol_datagrams_with_blocks(
                        cx,
                        &mut link.conn,
                        &manifest,
                        &mut decoders,
                        config,
                        &mut decode_stats,
                    )
                    .await?;
                round_symbols_observed = round_symbols_observed.saturating_add(observed);
                round_symbols_accepted = round_symbols_accepted.saturating_add(accepted);
                intake_stats.record_symbol_drain(
                    drain_started.elapsed(),
                    accepted,
                    completed_blocks.len(),
                );
                symbols_accepted = symbols_accepted.saturating_add(accepted);
                if observed > 0 {
                    // Repair (or spray) is flowing again — reset the control-PTO budget.
                    needmore_pto_attempts = 0;
                    send_and_flush_native_keep_alive(cx, link, &mut control).await?;
                }
                for block in completed_blocks {
                    send_and_flush_native_keep_alive(cx, link, &mut control).await?;
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
                    send_and_flush_native_keep_alive(cx, link, &mut control).await?;
                }
                if super::pending_entries(&decoders).is_empty() {
                    // Once all entries decode, Proof can complete the transfer even
                    // if the best-effort ObjectComplete control packet was dropped.
                    flush_cached_quic_staging_files(&mut staged).await?;
                    break 'rounds;
                }
                if link.conn.pending_datagram_count() > 0 {
                    continue;
                }
                if let Some(frame) = control.try_recv(cx, &mut link.conn)? {
                    match frame.frame_type() {
                        FrameType::ObjectComplete => {
                            round_complete = super::parse_quic_round_complete(&frame)?;
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
                let pumped_packets = link.pump_inbound_for(cx, pump_timeout).await?;
                intake_stats.record_pump(pump_started.elapsed(), pumped_packets);
                if pumped_packets == 0 {
                    if link.conn.pending_datagram_count() > 0 {
                        continue;
                    }
                    if round_made_progress {
                        break;
                    }
                    // Idle with no progress. If we are awaiting a repair round, the NeedMore (or the
                    // repair) was lost on the wire — re-send the NeedMore (control PTO) up to a budget
                    // before giving up, so cross-machine transfers converge through control-frame loss.
                    if let Some(need) = last_need.as_ref() {
                        if needmore_pto_attempts < MAX_NEEDMORE_PTO {
                            needmore_pto_attempts = needmore_pto_attempts.saturating_add(1);
                            quic_rqtrace!(
                                "receiver: NeedMore PTO resend round={} attempt={} pending={} repair_blocks={} requested_repair_symbols={} max_attempts={}",
                                feedback_rounds,
                                needmore_pto_attempts,
                                need.pending.len(),
                                need.repair_blocks.len(),
                                need_more_repair_symbol_count(need),
                                MAX_NEEDMORE_PTO,
                            );
                            super::send_native_need_more(cx, &mut link.conn, &mut control, need)?;
                            link.flush(cx).await?;
                            continue;
                        }
                    }
                    return Err(link.symbol_round_timeout(config.idle_timeout, symbols_accepted));
                }
            }

            flush_cached_quic_staging_files(&mut staged).await?;
            let pending = super::pending_entries(&decoders);
            if pending.is_empty() {
                break;
            }
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
            let repair_blocks = super::block_repair_requests(
                &decoders,
                config,
                super::MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
                round_loss_fraction,
            );
            let need = QuicNeedMore {
                pending,
                repair_blocks,
                source_symbols: Vec::new(),
                round_symbols_observed: Some(round_symbols_observed),
                round_loss_fraction,
                round_symbols_accepted: Some(round_symbols_accepted),
            };
            intake_stats.trace_need_more(cx, feedback_rounds.saturating_add(1), &need);
            let requested_repair_symbols = need_more_repair_symbol_count(&need);
            let repair_detail = repair_block_trace_summary(&need.repair_blocks);
            quic_rqtrace!(
                "receiver: NeedMore round={} pending={} repair_blocks={} requested_repair_symbols={} source_requests={} round_symbols_observed={} round_symbols_accepted={} round_symbols_sent={} round_loss_fraction={:.4} symbols_accepted={} max_feedback_rounds={} round_cap_exceeded={} repair_symbol_round_cap={} repair_blocks_detail={}",
                feedback_rounds.saturating_add(1),
                need.pending.len(),
                need.repair_blocks.len(),
                requested_repair_symbols,
                need.source_symbols.len(),
                round_symbols_observed,
                round_symbols_accepted,
                round_complete.round_symbols_sent,
                need.round_loss_fraction.unwrap_or(0.0),
                symbols_accepted,
                config.max_feedback_rounds,
                feedback_rounds.saturating_add(1) > config.max_feedback_rounds,
                super::MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
                repair_detail,
            );
            trace_repair_block_deficits(
                "receiver",
                feedback_rounds.saturating_add(1),
                &need.repair_blocks,
            );
            super::send_native_need_more(cx, &mut link.conn, &mut control, &need)?;
            link.flush(cx).await?;
            // Remember it so the inner loop can re-send it on the control PTO if the repair round
            // does not arrive (lost NeedMore/repair); reset the per-round PTO budget.
            last_need = Some(need);
            needmore_pto_attempts = 0;
            feedback_rounds = feedback_rounds.saturating_add(1);
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
        super::send_native_proof(cx, &mut link.conn, &mut control, &receipt)?;
        link.flush(cx).await?;
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
    let server_tls = config.server_tls.as_ref().ok_or_else(|| {
        QuicTransportError::Config(
            "ATP-over-QUIC receive requires server TLS config; set QuicConfig::server_tls \
             (certificate chain + private key)"
                .to_string(),
        )
    })?;
    let (mut link, early_data) = accept(cx, endpoint, server_tls, config).await?;
    // Replay any 1-RTT packets that raced ahead of the handshake's completion
    // (the client finishes first and may start the data plane immediately), so
    // the receiver session sees the sender's Hello / early symbols.
    if !early_data.is_empty() {
        link.ingest_packets(cx, &early_data).await?;
    }
    run_receiver_session(cx, &mut link, dest_dir, config, peer_id).await
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
            inbound_datagram_capacity: 4096,
            inbound_datagram_available: 4093,
            inbound_pump_batch_limit: INBOUND_PUMP_BATCH,
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
        assert_eq!(entry.get_field("udp_packets_received"), Some("17"));
        assert_eq!(entry.get_field("one_rtt_packets_ingested"), Some("16"));
        assert_eq!(entry.get_field("non_one_rtt_packets_dropped"), Some("1"));
        assert_eq!(entry.get_field("unprotect_packets_dropped"), Some("2"));
        assert_eq!(entry.get_field("datagrams_received"), Some("12"));
        assert_eq!(entry.get_field("datagrams_dropped_on_receive"), Some("0"));
        assert_eq!(entry.get_field("pending_datagrams"), Some("3"));
        assert_eq!(entry.get_field("reorder_occupancy"), Some("3"));
        assert_eq!(entry.get_field("inbound_datagram_capacity"), Some("4096"));
        assert_eq!(entry.get_field("inbound_datagram_available"), Some("4093"));
        assert_eq!(entry.get_field("inbound_pump_batch_limit"), Some("512"));
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
            super::json_frame(FrameType::ObjectRequest, &served).expect("duplicate need-more"),
            Frame::empty(FrameType::Proof).expect("proof frame"),
            super::json_frame(FrameType::ObjectRequest, &changed).expect("changed need-more"),
            super::json_frame(FrameType::ObjectRequest, &served).expect("duplicate need-more"),
        ]);

        let dropped = drop_duplicate_need_more_frames(&mut pending, &served)
            .expect("duplicate filter parses queued feedback");

        assert_eq!(dropped, 2);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].frame_type(), FrameType::Proof);
        assert_eq!(pending[1].frame_type(), FrameType::ObjectRequest);
        let retained = super::parse_json::<QuicNeedMore>(&pending[1]).expect("retained need-more");
        assert_eq!(retained, changed);
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
        stats.record_symbol_drain(Duration::from_micros(11), 7, 2);
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
