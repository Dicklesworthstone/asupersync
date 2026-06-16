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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};

use crate::bytes::BytesMut;
use crate::cx::Cx;
use crate::io::AsyncWriteExt;
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
    NativeQuicFrameTransport, QuicConfig, QuicControlReply, QuicEntryEncoder, QuicHello,
    QuicHelloAck, QuicNeedMore, QuicPreparedSource, QuicSourceSymbolRequest, QuicTransportError,
    ReceiveReceipt, ReceiveReport, SendReport, TransferManifest,
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

/// Bytes of the simplified 1-RTT data-plane header (flags + 8-byte packet number).
const ONE_RTT_HEADER_LEN: usize = 9;
/// QUIC AES-128-GCM authentication tag length.
const ONE_RTT_TAG_LEN: usize = 16;
/// QUIC short-header fixed bit (bit 6); set on every 1-RTT data-plane packet.
const ONE_RTT_FIXED_BIT: u8 = 0x40;
/// QUIC short-header key-phase bit (bit 2).
const ONE_RTT_KEY_PHASE_BIT: u8 = 0x04;

/// UDP max packet size for the link's endpoint. Large enough that the server's
/// full Handshake flight (certificate chain) fits one loopback packet — the
/// handshake driver assumes in-order contiguous CRYPTO without fragmentation.
/// 1-RTT data packets are far smaller. Real-internet path-MTU + CRYPTO
/// fragmentation is follow-up work.
const ATP_QUIC_UDP_MAX_PACKET: usize = 16 * 1024;

/// Fixed socket buffer budget for the native ATP-QUIC link. This is intentionally
/// a constant envelope, not proportional to object size, so large transfers cannot
/// force process/object-sized buffering while loopback proof runs avoid kernel
/// receive-buffer drops during one-round RaptorQ sprays.
const ATP_QUIC_UDP_SOCKET_BUFFER: usize = 16 * 1024 * 1024;

/// Packets pulled from the socket per inbound pump. The receiver session drains
/// the connection's bounded (`MAX_INBOUND_DATAGRAMS` = 256) inbound DATAGRAM
/// queue to empty at the top of every loop iteration *before* pumping again, so a
/// pump may safely ingest up to the full queue depth without drop-oldest losses.
/// Sized to the queue depth (not a small constant like 32) so a real cross-machine
/// sender spraying thousands of symbols per round is drained fast enough to keep
/// up with the wire instead of overflowing the kernel receive buffer — on a real
/// link an 8–32-packet drain falls hopelessly behind and decodes nothing.
const INBOUND_PUMP_BATCH: usize = 256;

/// Flush the outbound 1-RTT packets before a full endpoint batch accumulates.
/// Large sprays otherwise run far ahead of the receiver and bury the control
/// marker behind hundreds of DATAGRAM packets on loopback UDP.
const SPRAY_FLUSH_THRESHOLD: usize = 8;
/// Wall-clock pause after each spray flush. A cooperative yield is not enough on
/// all RCH workers because the receiver runs in a separate runtime thread and
/// the sender can still refill the UDP socket faster than loopback drains it.
const SPRAY_FLUSH_PAUSE: Duration = Duration::from_millis(1);

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
    idle_timeout: Duration,
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
            Outcome::Err(_) | Outcome::Cancelled(_) | Outcome::Panicked(_) => return Ok(false),
        };
        self.clock = self.clock.saturating_add(CLOCK_STEP_MICROS);
        self.conn.process_packet_payload(
            cx,
            PacketNumberSpace::ApplicationData,
            packet_number,
            &unprotected.plaintext,
            self.clock,
        )?;
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
    /// first packet. Returns the number of packets successfully processed
    /// (undecryptable / non-1-RTT packets are silently dropped, per QUIC).
    async fn pump_inbound(&mut self, cx: &Cx) -> Result<usize, QuicTransportError> {
        let received = match crate::time::timeout(
            cx.now(),
            self.idle_timeout,
            self.endpoint.receive_batch(cx, INBOUND_PUMP_BATCH),
        )
        .await
        {
            Ok(Ok(packets)) => packets,
            Ok(Err(err)) => return Err(map_udp_error(err)),
            Err(_elapsed) => return Ok(0),
        };
        self.ingest_packets(cx, &received).await
    }

    /// Spray one symbol, flushing first if the bounded outbound queue is full.
    async fn spray_symbol(
        &mut self,
        cx: &Cx,
        symbol: &Symbol,
        tag: u64,
        entry: u32,
        auth_tag: Option<[u8; TAG_SIZE]>,
    ) -> Result<(), QuicTransportError> {
        if self.conn.pending_outbound_datagram_count() >= SPRAY_FLUSH_THRESHOLD {
            self.flush(cx).await?;
            crate::time::sleep(cx.now(), SPRAY_FLUSH_PAUSE).await;
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
        // `receive_batch` may drain. It must be the *receiver* drain width
        // (`INBOUND_PUMP_BATCH`), NOT the send-pacing `SPRAY_FLUSH_THRESHOLD`:
        // capping the receiver at 8 packets/pump starves it on a real link where
        // the sender sprays thousands of symbols per round. `send_batch` only
        // chunks by this value, so a larger ceiling is strictly better for sends.
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
    let conn_config = NativeQuicConnectionConfig {
        role,
        max_datagram_frame_size: config.max_datagram_size,
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

    // Cap each 1-RTT data packet to carry at most one symbol DATAGRAM (plus a
    // little control headroom). This keeps loss granularity per-symbol (the
    // point of RFC 9221 DATAGRAMs) and, crucially, bounds how many symbols a
    // single inbound pump can queue, so the connection's 256-deep inbound
    // DATAGRAM queue cannot overflow between drains. `symbol_size` is bounded by
    // `max_datagram_size` via `QuicConfig::validate`, so this stays well under
    // the endpoint MTU. Large control frames are split across packets and
    // reassembled by the frame codec.
    let one_datagram = usize::from(config.symbol_size)
        .saturating_add(super::AUTH_ENVELOPE_HEADER_LEN)
        .saturating_add(16);
    let max_app_payload =
        one_datagram.min(ATP_QUIC_UDP_MAX_PACKET - ONE_RTT_HEADER_LEN - ONE_RTT_TAG_LEN);

    Ok(QuicLink {
        conn,
        endpoint,
        protection,
        peer,
        send_pn: 0,
        clock: 0,
        max_app_payload,
        idle_timeout: config.idle_timeout,
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

/// Spray a round of symbols for the `pending` entries over a live link, pacing on
/// the bounded outbound DATAGRAM queue. Mirrors `super::spray_native_symbol_round`
/// but interleaves real UDP flushes so a large object never drops symbols before
/// they reach the wire. `with_source` selects the initial source+repair spray vs
/// a repair-only batch.
async fn spray_round(
    cx: &Cx,
    link: &mut QuicLink,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    pending: &std::collections::BTreeSet<u32>,
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
    with_source: bool,
) -> Result<u64, QuicTransportError> {
    let tag = super::transfer_tag(&manifest.transfer_id);
    let repair_batch = super::repair_batch_per_block(config);
    let drop_one_in = config.debug_drop_one_in;
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
                link.spray_symbol(cx, &symbol, tag, entry_index, auth_tag)
                    .await?;
                sent = sent.saturating_add(1);
            }
            entry.set_repair_cursor(sbn, target_repair);
        }
    }
    Ok(sent)
}

/// Send the specific systematic source symbols a receiver requested, paced.
async fn spray_source_requests(
    cx: &Cx,
    link: &mut QuicLink,
    manifest: &TransferManifest,
    encoders: &[QuicEntryEncoder],
    requests: &[QuicSourceSymbolRequest],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let tag = super::transfer_tag(&manifest.transfer_id);
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
        link.spray_symbol(cx, &symbol, tag, request.entry, auth_tag)
            .await?;
        sent = sent.saturating_add(1);
    }
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
    let mut symbols_sent = spray_round(
        cx,
        link,
        manifest,
        &mut encoders,
        &pending_all,
        config,
        symbol_auth.as_ref(),
        true,
    )
    .await?;
    // Push every sprayed symbol onto the wire BEFORE the ObjectComplete marker so
    // the (in-order, loopback/LAN) receiver drains all of this round's symbols
    // before it reads ObjectComplete and assembles. `generate_frames` emits the
    // ObjectComplete STREAM frame ahead of queued DATAGRAMs within a single flush,
    // so without this split a >1-batch spray would assemble prematurely and force
    // a needless feedback round.
    link.flush(cx).await?;
    super::send_native_object_complete(cx, &mut link.conn, &mut control)?;
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
            got => {
                return Err(QuicTransportError::Unexpected {
                    got,
                    expected: "Proof | ObjectRequest",
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
                let _ = symbols_sent;
                return Ok(SendReport {
                    transfer_id: manifest.transfer_id.clone(),
                    bytes_sent: manifest.total_bytes,
                    files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
                    merkle_root_hex: manifest.merkle_root_hex.clone(),
                    receipt,
                    peer: link.peer,
                });
            }
            QuicControlReply::NeedMore(need) => {
                feedback_rounds = feedback_rounds.saturating_add(1);
                if feedback_rounds > config.max_feedback_rounds {
                    return Err(QuicTransportError::NoConvergence {
                        rounds: feedback_rounds,
                        pending: need.pending.len(),
                    });
                }
                if need.pending.is_empty() && need.source_symbols.is_empty() {
                    super::send_native_object_complete(cx, &mut link.conn, &mut control)?;
                    link.flush(cx).await?;
                    continue;
                }
                for entry in &need.pending {
                    if !manifest.entries.iter().any(|m| m.index == *entry) {
                        return Err(QuicTransportError::Integrity(format!(
                            "receiver requested repair for unknown entry {entry}"
                        )));
                    }
                }
                let pending: std::collections::BTreeSet<u32> =
                    need.pending.iter().copied().collect();
                for request in &need.source_symbols {
                    if !pending.contains(&request.entry) {
                        return Err(QuicTransportError::Integrity(format!(
                            "receiver requested source symbol for non-pending entry {}",
                            request.entry
                        )));
                    }
                }
                let sent = if need.source_symbols.is_empty() {
                    spray_round(
                        cx,
                        link,
                        manifest,
                        &mut encoders,
                        &pending,
                        config,
                        symbol_auth.as_ref(),
                        false,
                    )
                    .await?
                } else {
                    spray_source_requests(
                        cx,
                        link,
                        manifest,
                        &encoders,
                        &need.source_symbols,
                        config,
                        symbol_auth.as_ref(),
                    )
                    .await?
                };
                symbols_sent = symbols_sent.saturating_add(sent);
                // Flush this round's repair/source symbols before ObjectComplete
                // (same ordering guarantee as the initial spray).
                link.flush(cx).await?;
                super::send_native_object_complete(cx, &mut link.conn, &mut control)?;
                link.flush(cx).await?;
            }
        }
    }
}

// ─── Receiver session ───────────────────────────────────────────────────────

struct QuicStagedEntryReceive {
    staging_path: PathBuf,
    created: bool,
}

impl QuicStagedEntryReceive {
    fn new(staging_path: PathBuf) -> Self {
        Self {
            staging_path,
            created: false,
        }
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
        if let Some(parent) = self.staging_path.parent() {
            crate::fs::create_dir_all(parent).await?;
        }
        let mut file = crate::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&self.staging_path)
            .await?;
        if !self.created {
            file.set_len(entry.size).await?;
            self.created = true;
        }
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        file.write_all(data).await?;
        file.flush().await?;
        Ok(())
    }

    async fn ensure_created(&mut self, size: u64) -> Result<(), QuicTransportError> {
        if self.created {
            return Ok(());
        }
        if let Some(parent) = self.staging_path.parent() {
            crate::fs::create_dir_all(parent).await?;
        }
        let file = crate::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&self.staging_path)
            .await?;
        file.set_len(size).await?;
        self.created = true;
        Ok(())
    }
}

async fn commit_staged_entries(
    cx: &Cx,
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
        staged_entry.ensure_created(entry.size).await?;
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
    }

    let merkle_ok = flat_merkle_root_from_digests(&digests) == manifest.merkle_root_hex;
    let committed = sha_ok && merkle_ok;
    let mut committed_paths = Vec::new();
    if committed {
        let base = super::quic_safe_base_for_root_name(dest_dir, &manifest.root_name)?;
        for (entry, staged_entry) in manifest.entries.iter().zip(staged.iter()) {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            let out_path = if manifest.is_directory {
                super::quic_join_relative(&base, &entry.rel_path)?
            } else {
                base.clone()
            };
            if let Some(parent) = out_path.parent() {
                crate::fs::create_dir_all(parent).await?;
            }
            crate::fs::rename(&staged_entry.staging_path, &out_path).await?;
            committed_paths.push(out_path);
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
            reason: if committed {
                None
            } else if !sha_ok {
                Some("per-entry SHA-256 mismatch".to_string())
            } else {
                Some("merkle-root mismatch".to_string())
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
    let staging_dir = dest_dir.join(format!(
        ".atp-quic-staging-{}-{}-{staging_seq}",
        manifest.transfer_id,
        std::process::id()
    ));
    crate::fs::create_dir_all(&staging_dir).await?;
    let mut staged = manifest
        .entries
        .iter()
        .enumerate()
        .map(|(i, _)| QuicStagedEntryReceive::new(staging_dir.join(i.to_string())))
        .collect::<Vec<_>>();
    let mut symbols_accepted = 0u64;
    let mut feedback_rounds = 0u32;

    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        // Drain symbols and wait for this round's ObjectComplete marker, pumping
        // the socket and draining the bounded inbound DATAGRAM queue each step so
        // no symbol is dropped while we wait. `pump_inbound` returns 0 only after a
        // full idle window with no traffic, which means the sender went silent.
        loop {
            let (accepted, completed_blocks) = super::drain_native_symbol_datagrams_with_blocks(
                &mut link.conn,
                &manifest,
                &mut decoders,
                config,
            )?;
            symbols_accepted = symbols_accepted.saturating_add(accepted);
            for block in completed_blocks {
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
                staged_entry
                    .write_block(entry, block.sbn, &block.data, config)
                    .await?;
            }
            if let Some(frame) = control.try_recv(cx, &mut link.conn)? {
                if frame.frame_type() != FrameType::ObjectComplete {
                    return Err(QuicTransportError::Unexpected {
                        got: frame.frame_type(),
                        expected: "ObjectComplete",
                    });
                }
                break;
            }
            link.flush(cx).await?;
            if link.pump_inbound(cx).await? == 0 {
                return Err(QuicTransportError::Timeout {
                    operation: "receive symbol round",
                    timeout: config.idle_timeout,
                });
            }
        }

        let pending = super::pending_entries(&decoders);
        if pending.is_empty() {
            break;
        }
        if feedback_rounds >= config.max_feedback_rounds {
            return Err(QuicTransportError::NoConvergence {
                rounds: feedback_rounds,
                pending: pending.len(),
            });
        }
        let need = QuicNeedMore {
            pending,
            source_symbols: super::source_symbol_requests(&decoders, 2048),
        };
        super::send_native_need_more(cx, &mut link.conn, &mut control, &need)?;
        link.flush(cx).await?;
        feedback_rounds = feedback_rounds.saturating_add(1);
    }

    let symbols_accepted_text = symbols_accepted.to_string();
    let feedback_rounds_text = feedback_rounds.to_string();
    cx.trace_with_fields(
        "atp_quic.receive.decoded",
        &[
            ("transfer_id", manifest.transfer_id.as_str()),
            ("symbols_accepted", symbols_accepted_text.as_str()),
            ("feedback_rounds", feedback_rounds_text.as_str()),
        ],
    );
    let (receipt, committed_paths) =
        commit_staged_entries(cx, dest_dir, &manifest, &mut staged, config).await?;
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
        transfer_id: manifest.transfer_id,
        bytes_received: receipt.bytes_received,
        files: receipt.files,
        committed: true,
        committed_paths,
        peer: link.peer,
    })
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
    let client_tls = config.client_tls.as_ref().ok_or_else(|| {
        QuicTransportError::Config(
            "ATP-over-QUIC send requires client TLS trust config; set QuicConfig::client_tls \
             (server name + root certificates) so the server identity can be verified"
                .to_string(),
        )
    })?;
    let mut link = connect(cx, addr, client_tls, config).await?;
    run_sender_session(cx, &mut link, prepared, config, peer_id).await
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
}
