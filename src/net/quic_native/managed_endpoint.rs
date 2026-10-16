//! Managed QUIC endpoint with integrated connection routing and timer scheduling.
//!
//! This module provides the complete ATP native QUIC endpoint that combines:
//! - UDP packet I/O (QuicUdpEndpoint)
//! - Connection-ID routing (ConnectionRouter)
//! - Timer scheduling (QuicTimerScheduler)
//! - Connection lifecycle management
//!
//! It represents the deployable QUIC endpoint that ATP can use for object transfer.

use crate::cx::Cx;
use crate::net::quic_core::ConnectionId;
use crate::net::quic_native::ReceivedPacket;
use crate::net::quic_native::connection_manager::{
    AcceptedNativeQuicConnection, QuicCancelWake, RoutedOutgoingPacket,
};
use crate::net::quic_native::{
    ConnectionRouter, ConnectionRouterError, ConnectionRouterStats, NativeQuicConnectionConfig,
    OutgoingPacket, QuicTimerScheduler, QuicUdpEndpoint, QuicUdpEndpointConfig,
    QuicUdpEndpointError, RoutingResult,
};
use std::collections::VecDeque;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Instant;

#[cfg(feature = "tls")]
use super::handshake_driver::{HandshakeLevel, QuicHandshakeDriver};
#[cfg(feature = "tls")]
use crate::net::quic_core::{LongPacketType, ProtectedHeaderPrefix};

#[cfg(feature = "tls")]
const ACCEPT_PTO: std::time::Duration = std::time::Duration::from_millis(1500);
#[cfg(feature = "tls")]
const ACCEPT_MAX_FLIGHTS: usize = 64;
#[cfg(feature = "tls")]
const ACCEPT_MAX_PACKETS: usize = 1024;
#[cfg(feature = "tls")]
const ACCEPT_MAX_BYTES: usize = 2 * 1024 * 1024;
#[cfg(feature = "tls")]
const ACCEPT_MIN_INITIAL_BYTES: usize = 1200;
#[cfg(feature = "tls")]
const ACCEPT_CID_ATTEMPTS: usize = 16;
/// A Retry token is echoed within one round trip by a real client.
#[cfg(feature = "tls")]
const RETRY_TOKEN_LIFETIME: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(feature = "tls")]
const RETRY_TOKEN_VERSION: u8 = 1;
#[cfg(feature = "tls")]
const RETRY_TOKEN_MAC_LEN: usize = 16;
/// Retry is stateless, so one that finds the send batch full is lost until
/// the client's PTO (1.5 s). Retries get this many queue slots beyond the
/// batch. Each is smaller than the Initial that caused it.
#[cfg(feature = "tls")]
const RETRY_QUEUE_SLACK: usize = 64;

/// When automatic admission answers a client Initial with a stateless Retry
/// (RFC 9000 section 8.1.2) instead of creating handshake state.
///
/// A Retry makes the client prove it receives datagrams at its source address
/// before the server keeps anything for it. Spoofed Initials never return the
/// token, so they cannot hold admission slots that validated clients need.
#[cfg(feature = "tls")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryPolicy {
    /// Retry once pending handshakes fill half of the admission capacity. When
    /// capacity is full, an address-validated client displaces the oldest
    /// handshake whose address is not yet validated.
    #[default]
    UnderPressure,
    /// Retry every Initial that does not carry a valid token.
    Always,
    /// Never Retry. Spoofed Initials can then hold every admission slot until
    /// their handshake deadline.
    Never,
}

/// Retry token key, never printed.
#[cfg(feature = "tls")]
struct RetrySecret([u8; 32]);

#[cfg(feature = "tls")]
impl std::fmt::Debug for RetrySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetrySecret(..)")
    }
}

// A send-side resource shortage parks sends for the HTTP and remote
// listeners' 2ms base delay, doubling per consecutive failure to a 64ms cap.
const SEND_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_millis(2);
const SEND_BACKOFF_MAX_SHIFT: u32 = 5;

/// Kernel resource shortages that recover while the socket stays open.
///
/// Inspect native codes because ENOBUFS has no stable `ErrorKind`. The loop
/// delays the retry, so a persistent shortage cannot busy-spin.
fn send_error_is_resource_shortage(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::OutOfMemory
    ) {
        return true;
    }

    #[cfg(unix)]
    {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOBUFS | libc::ENOMEM | libc::EMFILE | libc::ENFILE)
        )
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
        matches!(error.raw_os_error(), Some(WSAEMFILE | WSAENOBUFS))
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Only an error the OS reported for a send can blame its destination.
/// Errors the endpoint synthesizes from local validation never retire a peer.
fn send_error_blames_destination(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    error.raw_os_error().is_some()
        && matches!(
            error.kind(),
            ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::AddrNotAvailable
                | ErrorKind::InvalidInput
                | ErrorKind::HostUnreachable
                | ErrorKind::NetworkUnreachable
                | ErrorKind::PermissionDenied
        )
}

#[cfg(feature = "tls")]
fn accept_error(reason: impl std::fmt::Display) -> ManagedEndpointError {
    ManagedEndpointError::InvalidConfig(format!("authenticated accept: {reason}"))
}

#[cfg(feature = "tls")]
fn accept_completion_error(error: super::NativeQuicUdpConnectionError) -> ManagedEndpointError {
    match error {
        super::NativeQuicUdpConnectionError::Cancelled => ManagedEndpointError::Cancelled,
        other => accept_error(other),
    }
}

#[cfg(feature = "tls")]
fn accept_router_error(error: ConnectionRouterError) -> ManagedEndpointError {
    match error {
        ConnectionRouterError::Cancelled => ManagedEndpointError::Cancelled,
        other => other.into(),
    }
}

#[cfg(feature = "tls")]
struct PendingAuthenticatedAccept {
    driver: QuicHandshakeDriver,
    peer: SocketAddr,
    initial_cid: ConnectionId,
    local_cid: ConnectionId,
    required_alpn: Vec<u8>,
    packet_number: u64,
    received_packets: usize,
    flights: usize,
    next_pto: Instant,
    expires: Instant,
    last_flight: Vec<OutgoingPacket>,
    /// What each `last_flight` packet carries, so a PTO rebuilds it under a
    /// new packet number instead of resending the protected bytes.
    last_flight_plan: Vec<AdmissionFlightPacket>,
    last_flight_dst_cid: ConnectionId,
    outbound: VecDeque<OutgoingPacket>,
    outstanding_packets: usize,
    outstanding_bytes: usize,
    socket_pending_bytes: usize,
    authenticated_received_bytes: u64,
    sent_bytes: u64,
    address_validated: bool,
    peer_max_udp_payload_size: Option<u64>,
    early: Vec<ReceivedPacket>,
    early_bytes: usize,
    final_ack_queued: bool,
    /// Created by automatic admission, so no owner awaits its receipt.
    automatic: bool,
}

#[cfg(feature = "tls")]
enum AdmissionFlightPacket {
    Crypto {
        segment: super::handshake_driver::HandshakeSegment,
        offset: u64,
    },
    FinalAck,
}

#[cfg(feature = "tls")]
#[derive(Debug)]
struct AuthenticatedAcceptResult {
    initial_cid: ConnectionId,
    local_cid: ConnectionId,
    result: Result<ConnectionId, ManagedEndpointError>,
}

#[cfg(feature = "tls")]
struct AuthenticatedServerPolicy {
    tls: Arc<rustls::ServerConfig>,
    transport_parameters: crate::net::quic_core::TransportParameters,
    required_alpn: Vec<u8>,
}

#[cfg(feature = "tls")]
impl std::fmt::Debug for AuthenticatedServerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedServerPolicy")
            .field("required_alpn", &self.required_alpn)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "tls")]
impl std::fmt::Debug for PendingAuthenticatedAccept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingAuthenticatedAccept")
            .field("peer", &self.peer)
            .field("local_cid", &self.local_cid)
            .field("received_packets", &self.received_packets)
            .field("outstanding_packets", &self.outstanding_packets)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "tls")]
impl PendingAuthenticatedAccept {
    fn owns_packet(&self, packet: &ReceivedPacket) -> bool {
        Self::packet_matches(packet, self.initial_cid, self.local_cid)
    }

    fn packet_matches(
        packet: &ReceivedPacket,
        initial_cid: ConnectionId,
        local_cid: ConnectionId,
    ) -> bool {
        let long = packet.data.first().is_some_and(|byte| byte & 0x80 != 0);
        let length = if long { 0 } else { local_cid.len() };
        // Only the header-protection-invariant prefix is readable on the
        // wire (RFC 9001 §5.4); it carries everything routing needs.
        ProtectedHeaderPrefix::decode(&packet.data, length).is_ok_and(|header| match header {
            ProtectedHeaderPrefix::Long(header) => {
                header.dst_cid == initial_cid || header.dst_cid == local_cid
            }
            // Exhaustive match keeps the crate compiling (E0004). This
            // admission owns a server TLS driver; Retry travels server-to-
            // client, so a matching dst_cid is not authority to feed it into
            // this pending server handshake. Client-side routing still uses
            // dst_cid in connection_manager.
            ProtectedHeaderPrefix::Retry(_) => false,
            ProtectedHeaderPrefix::Short { dst_cid, .. } => dst_cid == local_cid,
        })
    }

    fn check_flight(&self, packets: &[OutgoingPacket]) -> Result<usize, ManagedEndpointError> {
        let bytes = packets
            .iter()
            .try_fold(0usize, |sum, packet| sum.checked_add(packet.data.len()))
            .ok_or_else(|| accept_error("outbound byte overflow"))?;
        if packets.len() > ACCEPT_MAX_PACKETS.saturating_sub(self.outstanding_packets)
            || bytes > ACCEPT_MAX_BYTES.saturating_sub(self.outstanding_bytes)
        {
            return Err(accept_error("outbound flight bound exhausted"));
        }
        Ok(bytes)
    }

    /// The CONNECTION_CLOSE that reports a TLS refusal to the client
    /// (CRYPTO_ERROR, RFC 9001 section 4.8), cut to what the RFC 9000 section
    /// 8.1 anti-amplification limit still allows. Empty when TLS raised no
    /// alert.
    fn crypto_error_close(&mut self) -> Vec<OutgoingPacket> {
        let mut packets = self.driver.assemble_crypto_error_close(
            self.peer,
            self.local_cid,
            &mut self.packet_number,
        );
        let mut allowance = if self.address_validated {
            u64::MAX
        } else {
            self.authenticated_received_bytes
                .saturating_mul(3)
                .saturating_sub(self.sent_bytes)
        };
        let mut fits = 0;
        for packet in &packets {
            let bytes = packet.data.len() as u64;
            if bytes > allowance {
                break;
            }
            allowance -= bytes;
            fits += 1;
        }
        packets.truncate(fits);
        packets
    }

    fn queue_flight(&mut self, packets: &[OutgoingPacket]) -> Result<(), ManagedEndpointError> {
        let bytes = self.check_flight(packets)?;
        self.outstanding_packets += packets.len();
        self.outstanding_bytes += bytes;
        self.outbound.extend(packets.iter().cloned());
        Ok(())
    }

    /// Resend the flight's CRYPTO offsets and bytes in new packets. RFC 9000
    /// section 12.3 forbids reusing a packet number, and a peer that already
    /// processed the first copy suppresses an exact duplicate.
    fn retransmit(&mut self) -> Result<(), ManagedEndpointError> {
        let mut packets = Vec::with_capacity(self.last_flight_plan.len());
        for planned in &self.last_flight_plan {
            let data = match planned {
                AdmissionFlightPacket::Crypto { segment, offset } => {
                    self.driver.assemble_handshake_packet_at(
                        segment,
                        *offset,
                        self.last_flight_dst_cid,
                        self.local_cid,
                        self.packet_number,
                    )
                }
                AdmissionFlightPacket::FinalAck => self.driver.assemble_final_handshake_ack(
                    self.last_flight_dst_cid,
                    self.local_cid,
                    self.packet_number,
                ),
            }
            .map_err(accept_error)?;
            self.packet_number = self
                .packet_number
                .checked_add(1)
                .ok_or_else(|| accept_error("packet number exhausted"))?;
            packets.push(OutgoingPacket {
                dst_addr: self.peer,
                data,
                send_time: None,
            });
        }
        let bytes = self.check_flight(&packets)?;
        self.outstanding_packets += packets.len();
        self.outstanding_bytes += bytes;
        self.outbound.extend(packets.iter().cloned());
        self.last_flight = packets;
        Ok(())
    }

    fn can_queue(&self, bytes: usize) -> bool {
        self.address_validated
            || (bytes as u64).saturating_add(self.socket_pending_bytes as u64)
                <= self
                    .authenticated_received_bytes
                    .saturating_mul(3)
                    .saturating_sub(self.sent_bytes)
    }

    fn sent(&mut self, bytes: usize) {
        self.outstanding_packets -= 1;
        self.outstanding_bytes -= bytes;
        self.socket_pending_bytes -= bytes;
        self.sent_bytes = self.sent_bytes.saturating_add(bytes as u64);
    }

    fn retain_early_packet(&mut self, packet: ReceivedPacket) -> Result<(), ManagedEndpointError> {
        if self.early.len() == ACCEPT_MAX_PACKETS
            || packet.data.len() > ACCEPT_MAX_BYTES.saturating_sub(self.early_bytes)
        {
            return Err(accept_error("early application packet bound exhausted"));
        }
        self.early_bytes += packet.data.len();
        self.early.push(packet);
        Ok(())
    }

    fn receive(
        &mut self,
        packet: ReceivedPacket,
        max_packet_size: usize,
        now: Instant,
    ) -> Result<(), ManagedEndpointError> {
        if packet.src_addr != self.peer {
            return Ok(());
        }
        if self.received_packets == ACCEPT_MAX_PACKETS {
            return Err(accept_error("received packet bound exhausted"));
        }
        // Anything that has not authenticated is discarded, never fatal
        // (RFC 9000 §12.2): the peer's address is spoofable by anyone who saw
        // the cleartext Initial, so an oversized, malformed, bit-flipped or
        // forged datagram must not end an admission a real peer is still
        // driving, and must not consume the accepted-packet bound either.
        if packet.data.len() > max_packet_size {
            return Ok(());
        }
        let long = packet.data.first().is_some_and(|byte| byte & 0x80 != 0);
        let length = if long { 0 } else { self.local_cid.len() };
        let Ok(header) = ProtectedHeaderPrefix::decode(&packet.data, length) else {
            return Ok(());
        };
        if matches!(header, ProtectedHeaderPrefix::Retry(_)) {
            // Defensive role check for direct callers as well as owns_packet.
            // Retry supplies neither authenticated input credit nor TLS work.
            return Ok(());
        }
        if let ProtectedHeaderPrefix::Short { .. } = header {
            if self.driver.peer_connection_id().is_none() {
                return Ok(());
            }
            self.retain_early_packet(packet)?;
            self.received_packets += 1;
            return Ok(());
        }
        let ProtectedHeaderPrefix::Long(header) = header else {
            unreachable!()
        };
        if header.version != 1
            || !matches!(
                header.packet_type,
                LongPacketType::Initial | LongPacketType::Handshake
            )
            || (header.packet_type == LongPacketType::Handshake && header.dst_cid != self.local_cid)
        {
            return Ok(());
        }
        let (peer_cid, consumed) = match self.driver.recv_handshake_packet_with_consumed(&packet.data) {
            Ok(accepted) => accepted,
            Err(error)
                if super::handshake_driver::is_stale_handshake_packet_error(&error)
                    || super::handshake_driver::is_unauthenticated_handshake_packet_error(
                        &error,
                    ) =>
            {
                return Ok(());
            }
            Err(error) => {
                // Only a datagram that authenticated reaches this arm, so its
                // bytes fund the close that reports a TLS refusal.
                self.authenticated_received_bytes = self
                    .authenticated_received_bytes
                    .saturating_add(packet.data.len() as u64);
                return Err(accept_error(error));
            }
        };
        // Only an authenticated packet counts toward the accepted bound.
        self.received_packets += 1;
        // An Initial's publicly derivable keys do not prove return reachability.
        // Until a valid Handshake packet does, only successfully authenticated
        // received bytes fund output, including every actual PTO retransmission.
        self.authenticated_received_bytes = self
            .authenticated_received_bytes
            .saturating_add(packet.data.len() as u64);
        // RFC 9000 section 8.1: only an authenticated Handshake packet proves
        // the address. The datagram's first packet may be a Handshake packet
        // that was skipped for want of keys while a coalesced Initial
        // authenticated.
        self.address_validated |= self.driver.has_authenticated_handshake_packet();
        // A short-header packet can follow the client's Finished in the same
        // UDP datagram (RFC 9000 section 12.2). TLS consumes only the long-
        // header prefix. Preserve the exact remaining ciphertext for the
        // authenticated router instead of losing the first application data.
        // Padding, malformed trailers and packets for another CID are not
        // admitted. The router still performs AEAD/replay checks after handoff.
        let tail = &packet.data[consumed..];
        if matches!(
            ProtectedHeaderPrefix::decode(tail, self.local_cid.len()),
            Ok(ProtectedHeaderPrefix::Short { dst_cid, .. }) if dst_cid == self.local_cid
        ) {
            if self.early.len() == ACCEPT_MAX_PACKETS
                || tail.len() > ACCEPT_MAX_BYTES.saturating_sub(self.early_bytes)
            {
                return Err(accept_error("early application packet bound exhausted"));
            }
            self.retain_early_packet(ReceivedPacket {
                src_addr: packet.src_addr,
                data: tail.to_vec(),
                receive_time: packet.receive_time,
                transmit_time: packet.transmit_time,
            })?;
        }
        // The peer's receive ceiling constrains our output, not our local
        // receive buffer. Until ClientHello parameters are available, retain
        // QUIC's minimum supported datagram size as the conservative send cap.
        if self.peer_max_udp_payload_size.is_none() {
            if let Some(bytes) = self.driver.peer_transport_parameters() {
                if bytes.len() > ACCEPT_MAX_BYTES {
                    return Err(accept_error(
                        "peer transport parameter byte bound exhausted",
                    ));
                }
                let parameters = crate::net::quic_core::TransportParameters::decode(bytes)
                    .map_err(accept_error)?;
                self.peer_max_udp_payload_size =
                    Some(parameters.max_udp_payload_size.unwrap_or(65_527));
            }
        }
        let send_packet_size = self
            .peer_max_udp_payload_size
            .map_or(max_packet_size.min(ACCEPT_MIN_INITIAL_BYTES), |peer_max| {
                max_packet_size.min(usize::try_from(peer_max).unwrap_or(usize::MAX))
            });
        let segments = self.driver.pump_outbound().map_err(accept_error)?;
        let plaintext_bytes = segments
            .iter()
            .filter(|segment| segment.level != HandshakeLevel::OneRtt)
            .try_fold(0usize, |total, segment| {
                total.checked_add(segment.data.len())
            })
            .ok_or_else(|| accept_error("TLS plaintext flight byte overflow"))?;
        if plaintext_bytes > ACCEPT_MAX_BYTES {
            return Err(accept_error("TLS plaintext flight byte bound exhausted"));
        }
        // Leave room for full 20-byte source/destination CIDs, maximal CRYPTO
        // offset/length varints, long-header length, packet number and AEAD tag.
        // The driver advances per-space CRYPTO offsets across these segments.
        let chunk_bytes = send_packet_size
            .checked_sub(128)
            .filter(|size| *size != 0)
            .ok_or_else(|| accept_error("datagram bound cannot encode a TLS flight"))?;
        let mut packets = Vec::new();
        let mut plan = Vec::new();
        let mut bytes = 0usize;
        for segment in segments {
            if segment.level == HandshakeLevel::OneRtt {
                continue;
            }
            for chunk in segment.data.chunks(chunk_bytes) {
                if packets.len() == ACCEPT_MAX_PACKETS {
                    return Err(accept_error("TLS flight packet bound exhausted"));
                }
                let segment = super::handshake_driver::HandshakeSegment {
                    level: segment.level,
                    data: chunk.to_vec(),
                };
                let offset = self.driver.next_crypto_offset(segment.level);
                let data = self
                    .driver
                    .assemble_handshake_packet(
                        &segment,
                        peer_cid,
                        self.local_cid,
                        self.packet_number,
                    )
                    .map_err(accept_error)?;
                self.packet_number = self
                    .packet_number
                    .checked_add(1)
                    .ok_or_else(|| accept_error("packet number exhausted"))?;
                bytes = bytes
                    .checked_add(data.len())
                    .ok_or_else(|| accept_error("flight byte overflow"))?;
                if data.len() > send_packet_size || bytes > ACCEPT_MAX_BYTES {
                    return Err(accept_error("TLS flight bound exhausted"));
                }
                packets.push(OutgoingPacket {
                    dst_addr: self.peer,
                    data,
                    send_time: None,
                });
                plan.push(AdmissionFlightPacket::Crypto { segment, offset });
            }
        }
        let final_ack = self.driver.is_complete() && !self.final_ack_queued;
        if final_ack {
            let data = self
                .driver
                .assemble_final_handshake_ack(peer_cid, self.local_cid, self.packet_number)
                .map_err(accept_error)?;
            self.packet_number = self
                .packet_number
                .checked_add(1)
                .ok_or_else(|| accept_error("packet number exhausted"))?;
            bytes = bytes
                .checked_add(data.len())
                .ok_or_else(|| accept_error("flight byte overflow"))?;
            if packets.len() == ACCEPT_MAX_PACKETS
                || data.len() > send_packet_size
                || bytes > ACCEPT_MAX_BYTES
            {
                return Err(accept_error("TLS final ACK bound exhausted"));
            }
            packets.push(OutgoingPacket {
                dst_addr: self.peer,
                data,
                send_time: None,
            });
            plan.push(AdmissionFlightPacket::FinalAck);
        }
        if !packets.is_empty() {
            self.flights += 1;
            if self.flights > ACCEPT_MAX_FLIGHTS {
                return Err(accept_error("handshake flight bound exhausted"));
            }
            self.queue_flight(&packets)?;
            self.final_ack_queued |= final_ack;
            self.last_flight = packets;
            self.last_flight_plan = plan;
            self.last_flight_dst_cid = peer_cid;
            self.next_pto = now
                .checked_add(ACCEPT_PTO)
                .ok_or_else(|| accept_error("PTO overflow"))?;
        }
        Ok(())
    }
}

/// Complete managed QUIC endpoint with connection routing and timer integration.
#[derive(Debug)]
pub struct ManagedQuicEndpoint {
    /// UDP endpoint for packet I/O.
    udp_endpoint: QuicUdpEndpoint,
    /// Connection router for packet dispatch.
    connection_router: ConnectionRouter,
    /// Timer scheduler for connection events.
    timer_scheduler: QuicTimerScheduler,
    /// Configuration for this endpoint.
    config: ManagedEndpointConfig,
    /// Whether the endpoint is shutting down.
    shutting_down: bool,
    /// Packets stay owned by the endpoint until the socket acknowledges a sent prefix.
    pending_outgoing: VecDeque<RoutedOutgoingPacket>,
    /// Receive ownership survives cancellation and preserves handshake-buffered
    /// application packets ahead of fresh socket input.
    pending_incoming: VecDeque<ManagedIncomingPacket>,
    /// An imported authenticated socket cannot create an unauthenticated route
    /// merely because another datagram resembles an Initial packet.
    authenticated_only: bool,
    #[cfg(feature = "tls")]
    pending_authenticated_accept: VecDeque<PendingAuthenticatedAccept>,
    #[cfg(feature = "tls")]
    authenticated_accept_result: VecDeque<AuthenticatedAcceptResult>,
    /// Pending handshakes and unconsumed terminal receipts share this ceiling.
    #[cfg(feature = "tls")]
    authenticated_accept_limit: usize,
    #[cfg(feature = "tls")]
    authenticated_accept_closed: bool,
    /// Explicit authority to create TLS admissions from unknown Initials.
    #[cfg(feature = "tls")]
    authenticated_server: Option<AuthenticatedServerPolicy>,
    /// Original Initial aliases stay reserved while their authenticated route
    /// exists, even after its completion receipt has been consumed.
    #[cfg(feature = "tls")]
    authenticated_initial_routes: Vec<(ConnectionId, ConnectionId)>,
    #[cfg(feature = "tls")]
    prefer_accept_output: bool,
    #[cfg(feature = "tls")]
    retry_policy: RetryPolicy,
    /// Keys Retry tokens; drawn when automatic admission is configured.
    #[cfg(feature = "tls")]
    retry_secret: RetrySecret,
    /// Origin of the coarse token clock: the first admission decision after
    /// `retry_secret` was drawn.
    #[cfg(feature = "tls")]
    retry_epoch: Option<Instant>,
    /// Alternate ready read/write batches; timers and cancellation always get a turn.
    prefer_send: bool,
    /// A send-side resource shortage parks sends until this deadline, while
    /// receives, timers and the application keep running.
    send_backoff_until: Option<Instant>,
    /// Consecutive resource-shortage send failures, for the capped delay.
    send_backoff_streak: u32,
}

enum EndpointEvent<T> {
    Packets(Vec<ReceivedPacket>),
    RetainedPackets,
    Sent(std::io::Result<crate::net::quic_native::BatchResult>),
    Timer(Instant),
    ApplicationTurn,
    ApplicationComplete(T),
}

#[derive(Debug)]
struct ManagedIncomingPacket {
    packet: ReceivedPacket,
    needs_clock_stamp: bool,
}

struct ManagedShutdownCleanup<'a>(&'a mut ManagedQuicEndpoint);

impl Drop for ManagedShutdownCleanup<'_> {
    fn drop(&mut self) {
        self.0.connection_router.discard_all();
        #[cfg(feature = "tls")]
        self.0.authenticated_initial_routes.clear();
        self.0.pending_outgoing.clear();
        self.0.pending_incoming.clear();
        self.0.timer_scheduler.cancel_pending();
        self.0.udp_endpoint.retire_io();
    }
}

struct ManagedApplicationRegistration(Option<Arc<ManagedApplicationWake>>);

impl Drop for ManagedApplicationRegistration {
    fn drop(&mut self) {
        if let Some(wake) = &self.0 {
            let retired = wake
                .parent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            // A retained application readiness source may outlive this loop.
            // Detach its parent on return, error, unwind, and future drop.
            // RawWaker destruction must run outside the registration lock.
            drop(retired);
        }
    }
}

#[derive(Debug)]
struct ManagedApplicationWake {
    ready: AtomicBool,
    parent: std::sync::Mutex<Option<Arc<Waker>>>,
}

impl ManagedApplicationWake {
    fn register_parent(&self, parent: &Waker) {
        let current = self
            .parent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(Arc::clone);
        if current.as_ref().is_some_and(|old| old.will_wake(parent)) {
            return;
        }
        // RawWaker clone/drop callbacks execute outside this lock. The lock
        // only moves Arc ownership, including when the driver changes tasks.
        let next = Arc::new(parent.clone());
        let old = self
            .parent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(next);
        drop(old);
    }
}

impl Wake for ManagedApplicationWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.store(true, Ordering::Release);
        let parent = self
            .parent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(Arc::clone);
        if let Some(parent) = parent {
            parent.wake_by_ref();
        }
    }
}

/// Configuration for the managed QUIC endpoint.
#[derive(Debug, Clone)]
pub struct ManagedEndpointConfig {
    /// UDP endpoint configuration.
    pub udp_config: QuicUdpEndpointConfig,
    /// QUIC connection configuration template.
    pub connection_config: NativeQuicConnectionConfig,
    /// Whether this endpoint acts as a server (accepts connections).
    pub is_server: bool,
    /// Local idle timeout in microseconds. Zero disables this local limit.
    /// A finite authenticated QUIC timeout can shorten but never extend it;
    /// all idle periods allow at least three probe intervals.
    pub connection_idle_timeout_micros: u64,
    /// Maximum number of concurrent connections.
    pub max_connections: usize,
    /// Packet processing batch size.
    pub packet_batch_size: usize,
}

impl Default for ManagedEndpointConfig {
    fn default() -> Self {
        Self {
            udp_config: QuicUdpEndpointConfig::default(),
            connection_config: NativeQuicConnectionConfig::default(),
            is_server: false,
            connection_idle_timeout_micros: 30_000_000, // 30 seconds
            max_connections: 1000,
            packet_batch_size: 32,
        }
    }
}

/// Errors from managed endpoint operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedEndpointError {
    /// Operation was cancelled via Cx.
    Cancelled,
    /// UDP endpoint error.
    UdpEndpoint(String),
    /// Connection routing error.
    ConnectionRouter(ConnectionRouterError),
    /// Endpoint is shutting down.
    ShuttingDown,
    /// Configuration error.
    InvalidConfig(String),
    /// Maximum connections limit reached.
    MaxConnectionsReached { limit: usize },
}

impl From<QuicUdpEndpointError> for ManagedEndpointError {
    fn from(e: QuicUdpEndpointError) -> Self {
        Self::UdpEndpoint(e.to_string())
    }
}

impl From<ConnectionRouterError> for ManagedEndpointError {
    fn from(e: ConnectionRouterError) -> Self {
        Self::ConnectionRouter(e)
    }
}

impl std::fmt::Display for ManagedEndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::UdpEndpoint(msg) => write!(f, "UDP endpoint error: {msg}"),
            Self::ConnectionRouter(err) => write!(f, "connection router error: {err}"),
            Self::ShuttingDown => write!(f, "endpoint is shutting down"),
            Self::InvalidConfig(msg) => write!(f, "invalid configuration: {msg}"),
            Self::MaxConnectionsReached { limit } => {
                write!(f, "maximum connections reached: {limit}")
            }
        }
    }
}

impl std::error::Error for ManagedEndpointError {}

impl ManagedQuicEndpoint {
    fn poll_application<T, F>(
        &mut self,
        cx: &Cx,
        wake: &Arc<ManagedApplicationWake>,
        application: &mut F,
    ) -> Option<Result<EndpointEvent<T>, ManagedEndpointError>>
    where
        F: FnMut(&Cx, &mut Self, &mut Context<'_>) -> Poll<Result<T, ManagedEndpointError>>,
    {
        if !wake.ready.swap(false, Ordering::AcqRel) {
            return None;
        }
        let waker = Waker::from(Arc::clone(wake));
        let mut context = Context::from_waker(&waker);
        Some(match application(cx, self, &mut context) {
            Poll::Ready(result) => result.map(EndpointEvent::ApplicationComplete),
            Poll::Pending => Ok(EndpointEvent::ApplicationTurn),
        })
    }

    #[cfg(feature = "tls")]
    pub(crate) fn from_authenticated_connection(
        cx: &Cx,
        connection: super::NativeQuicUdpConnection,
        mut config: ManagedEndpointConfig,
    ) -> Result<Self, super::udp_connection::ManagedQuicHandoffError> {
        use super::udp_connection::ManagedQuicHandoffError;
        let mut timer_scheduler = QuicTimerScheduler::new();
        let preflight = (|| -> Result<Instant, ManagedEndpointError> {
            cx.checkpoint()
                .map_err(|_| ManagedEndpointError::Cancelled)?;
            if config.max_connections == 0 || config.packet_batch_size == 0 {
                return Err(ManagedEndpointError::InvalidConfig(
                    "max_connections and packet_batch_size must be > 0".to_string(),
                ));
            }
            if config.is_server != (connection.connection().role() == super::StreamRole::Server) {
                return Err(ManagedEndpointError::InvalidConfig(
                    "managed role must match the authenticated connection".to_string(),
                ));
            }
            if !connection.connection().can_send_app_data() {
                return Err(ConnectionRouterError::InvalidConnectionState {
                    connection_id: connection.local_connection_id(),
                    reason: "managed handoff requires an established application-data connection"
                        .to_string(),
                }
                .into());
            }
            timer_scheduler.now(cx).map_err(Into::into)
        })();
        let now = match preflight {
            Ok(now) => now,
            Err(error) => return Err(ManagedQuicHandoffError::new(error, connection)),
        };
        // The socket is already configured. Retain its requested bind settings;
        // this does not claim the kernel used those exact buffer capacities.
        config.udp_config = connection.udp_config().clone();
        let parts = connection.into_managed_parts();
        let deadline = (|| -> Result<Option<Instant>, ManagedEndpointError> {
            let elapsed = now
                .checked_duration_since(parts.clock_origin)
                .ok_or_else(|| {
                    ManagedEndpointError::InvalidConfig(
                        "managed clock predates the connection epoch".to_string(),
                    )
                })?;
            let now_micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
            let deadline = parts
                .connection
                .inner()
                .pto_deadline_micros(cx, now_micros)
                .map_err(|error| match error {
                    super::NativeQuicConnectionError::Cancelled => ManagedEndpointError::Cancelled,
                    other => ConnectionRouterError::PacketProcessingFailed {
                        connection_id: parts.local_cid,
                        reason: other.to_string(),
                    }
                    .into(),
                })?;
            deadline
                .map(|deadline| {
                    parts
                        .clock_origin
                        .checked_add(std::time::Duration::from_micros(deadline))
                        .ok_or_else(|| {
                            ManagedEndpointError::InvalidConfig(
                                "connection deadline exceeds the managed clock range".to_string(),
                            )
                        })
                })
                .transpose()
        })();
        let deadline = match deadline {
            Ok(deadline) => deadline,
            Err(error) => {
                return Err(ManagedQuicHandoffError::new(
                    error,
                    super::NativeQuicUdpConnection::from_managed_parts(parts),
                ));
            }
        };
        let (mut connection_router, udp_endpoint, pending_incoming) =
            ConnectionRouter::from_authenticated_parts(
                parts,
                config.connection_config,
                config.max_connections,
                deadline,
                now,
            );
        connection_router.set_idle_timeout_micros(config.connection_idle_timeout_micros);
        Ok(Self {
            udp_endpoint,
            connection_router,
            timer_scheduler,
            config,
            shutting_down: false,
            pending_outgoing: VecDeque::new(),
            pending_incoming: pending_incoming
                .into_iter()
                .map(|packet| ManagedIncomingPacket {
                    packet,
                    needs_clock_stamp: false,
                })
                .collect(),
            authenticated_only: true,
            #[cfg(feature = "tls")]
            pending_authenticated_accept: VecDeque::new(),
            #[cfg(feature = "tls")]
            authenticated_accept_result: VecDeque::new(),
            #[cfg(feature = "tls")]
            authenticated_accept_limit: 1,
            #[cfg(feature = "tls")]
            authenticated_accept_closed: false,
            #[cfg(feature = "tls")]
            authenticated_server: None,
            #[cfg(feature = "tls")]
            authenticated_initial_routes: Vec::new(),
            #[cfg(feature = "tls")]
            prefer_accept_output: true,
            #[cfg(feature = "tls")]
            retry_policy: RetryPolicy::default(),
            #[cfg(feature = "tls")]
            retry_secret: RetrySecret([0; 32]),
            #[cfg(feature = "tls")]
            retry_epoch: None,
            prefer_send: true,
            send_backoff_until: None,
            send_backoff_streak: 0,
        })
    }

    /// Access a negotiated application connection while its socket, keys and
    /// timers remain owned by this endpoint. Output queued before a callback
    /// panic remains eligible when the caller resumes the driver.
    ///
    /// A pending explicitly admitted TLS handshake is not visible here until
    /// its authenticated application owner has been installed.
    #[cfg(feature = "tls")]
    pub fn with_connection_mut<R>(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
        operation: impl FnOnce(&mut super::QuicConnection) -> R,
    ) -> Result<R, ManagedEndpointError> {
        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }
        self.connection_router
            .with_authenticated_connection(cx, connection_id, operation)
            .map_err(Into::into)
    }

    /// The ALPN accepted by the original authenticated handshake.
    #[cfg(feature = "tls")]
    pub fn negotiated_alpn(
        &self,
        connection_id: ConnectionId,
    ) -> Result<&[u8], ManagedEndpointError> {
        self.connection_router
            .negotiated_alpn(connection_id)
            .map_err(Into::into)
    }

    /// Opt into bounded concurrent authenticated handshakes on this socket.
    ///
    /// The default remains one. A nonzero limit may not exceed
    /// [`ManagedEndpointConfig::max_connections`]. Pending handshakes and their
    /// unread terminal receipts share the limit, so a caller which stops
    /// collecting results cannot grow an unbounded completion queue. Changing
    /// the limit requires both queues to be empty; established connections may
    /// remain active. Each admission retains the independent byte, packet,
    /// amplification and deadline bounds documented by
    /// [`Self::begin_authenticated_accept`], so their aggregate memory ceiling
    /// scales with this explicitly selected limit.
    #[cfg(feature = "tls")]
    pub fn set_authenticated_accept_limit(
        &mut self,
        limit: usize,
    ) -> Result<(), ManagedEndpointError> {
        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }
        if limit == 0 || limit > self.config.max_connections {
            return Err(accept_error(
                "admission limit must be nonzero and at most max_connections",
            ));
        }
        if !self.pending_authenticated_accept.is_empty()
            || !self.authenticated_accept_result.is_empty()
        {
            return Err(accept_error(
                "cannot change admission limit while handshakes or receipts are owned",
            ));
        }
        self.authenticated_accept_limit = limit;
        Ok(())
    }

    /// Enable automatic authenticated server admission on the bound UDP socket.
    ///
    /// Call after [`Self::bind`] with `is_server: true`. No imported connection,
    /// peer address or client-selected connection ID is required. Only bounded,
    /// version-1 Initial datagrams of at least 1200 bytes can create an admission,
    /// and their first packet must authenticate before retaining a slot. The
    /// managed loop drives each TLS exchange and publishes its generated server
    /// CID through [`Self::take_authenticated_accept_result_with_id`]. Configure
    /// concurrency separately with [`Self::set_authenticated_accept_limit`].
    ///
    /// The TLS configuration must advertise `required_alpn`. Client identity is
    /// required only if its certificate verifier requires it. The supplied
    /// transport-parameter template is validated before changing the endpoint;
    /// original-destination and initial-source CID fields are replaced for each
    /// admission. Template Retry-source, shared stateless-reset token and
    /// preferred-address parameters are refused; the endpoint sets the Retry
    /// source CID itself after a Retry (see [`Self::set_retry_policy`]). Server
    /// IDs and the Retry token key use the driving Cx's explicit entropy source,
    /// with bounded collision retries for IDs, never a peer ID.
    ///
    /// Configuration requires no pending admission or unread receipt. An active
    /// endpoint may be reconfigured only if it already has authenticated-only
    /// routing; existing connections retain their negotiated configuration.
    /// Automatic admission does not enable the legacy unauthenticated path,
    /// address migration, or acceptance of 0-RTT application data.
    #[cfg(feature = "tls")]
    pub fn configure_authenticated_server(
        &mut self,
        cx: &Cx,
        tls: Arc<rustls::ServerConfig>,
        transport_parameters: Vec<u8>,
        required_alpn: &[u8],
    ) -> Result<(), ManagedEndpointError> {
        cx.checkpoint()
            .map_err(|_| ManagedEndpointError::Cancelled)?;
        if self.shutting_down || self.authenticated_accept_closed {
            return Err(ManagedEndpointError::ShuttingDown);
        }
        if !self.config.is_server
            || (!self.authenticated_only && self.connection_stats().active_connections != 0)
            || !self.pending_authenticated_accept.is_empty()
            || !self.authenticated_accept_result.is_empty()
        {
            return Err(accept_error(
                "server policy requires an idle admission surface and no unauthenticated connections",
            ));
        }
        if self.config.udp_config.max_packet_size < ACCEPT_MIN_INITIAL_BYTES {
            return Err(accept_error(
                "server datagram bound must admit a 1200-byte Initial",
            ));
        }
        if required_alpn.is_empty()
            || required_alpn.len() > 255
            || !tls
                .alpn_protocols
                .iter()
                .any(|alpn| alpn.as_slice() == required_alpn)
        {
            return Err(accept_error(
                "required ALPN must contain 1..=255 bytes and be advertised by the server",
            ));
        }
        // Reserve room for two maximum-length per-connection CID parameters.
        if transport_parameters.len() > ACCEPT_MAX_BYTES - 64 {
            return Err(accept_error(
                "server transport parameter template exceeds admission byte bound",
            ));
        }
        let mut parameters =
            crate::net::quic_core::TransportParameters::decode(&transport_parameters)
                .map_err(accept_error)?;
        if parameters
            .unknown
            .iter()
            .any(|parameter| matches!(parameter.id, 0x02 | 0x0d | 0x10))
        {
            return Err(accept_error(
                "automatic admission does not support reset tokens, preferred addresses or Retry parameters",
            ));
        }
        parameters
            .unknown
            .retain(|parameter| !matches!(parameter.id, 0x00 | 0x0f));
        let mut encoded = Vec::new();
        parameters.encode(&mut encoded).map_err(accept_error)?;
        // Validate rustls QUIC/version/cipher configuration now. No peer input
        // or certificate resolver is invoked by creating this fresh driver.
        QuicHandshakeDriver::server(Arc::clone(&tls), encoded).map_err(accept_error)?;
        let mut secret = [0; 32];
        cx.random_bytes(&mut secret);
        cx.checkpoint()
            .map_err(|_| ManagedEndpointError::Cancelled)?;
        // A new key starts a new token clock at the next admission decision.
        self.retry_secret = RetrySecret(secret);
        self.retry_epoch = None;
        self.authenticated_server = Some(AuthenticatedServerPolicy {
            tls,
            transport_parameters: parameters,
            required_alpn: required_alpn.to_vec(),
        });
        self.authenticated_only = true;
        Ok(())
    }

    /// Choose when automatic admission answers an Initial with a stateless
    /// Retry. The default, [`RetryPolicy::UnderPressure`], leaves an idle
    /// server at one round trip and keeps spoofed Initials from holding the
    /// admission slots that validated clients need.
    #[cfg(feature = "tls")]
    pub fn set_retry_policy(&mut self, policy: RetryPolicy) {
        self.retry_policy = policy;
    }

    #[cfg(feature = "tls")]
    fn retry_token_mac(
        &self,
        peer: SocketAddr,
        original_dcid: ConnectionId,
        retry_scid: ConnectionId,
        issued: u64,
    ) -> hmac::Hmac<sha2::Sha256> {
        use hmac::{KeyInit, Mac};
        let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&self.retry_secret.0)
            .expect("HMAC accepts any key length");
        mac.update(&[RETRY_TOKEN_VERSION]);
        match peer.ip() {
            std::net::IpAddr::V4(ip) => {
                mac.update(&[4]);
                mac.update(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                mac.update(&[6]);
                mac.update(&ip.octets());
            }
        }
        mac.update(&peer.port().to_be_bytes());
        for cid in [original_dcid, retry_scid] {
            mac.update(&[cid.len() as u8]);
            mac.update(cid.as_bytes());
        }
        mac.update(&issued.to_be_bytes());
        mac
    }

    /// A token bound to the client address, the client's original DCID and the
    /// Retry source CID the client must use next: version, issue time (seconds
    /// on the endpoint's token clock), original DCID, truncated HMAC-SHA256.
    #[cfg(feature = "tls")]
    fn mint_retry_token(
        &self,
        peer: SocketAddr,
        original_dcid: ConnectionId,
        retry_scid: ConnectionId,
        now: Instant,
    ) -> Option<Vec<u8>> {
        use hmac::Mac;
        let issued = now.checked_duration_since(self.retry_epoch?)?.as_secs();
        let mac = self
            .retry_token_mac(peer, original_dcid, retry_scid, issued)
            .finalize()
            .into_bytes();
        let mut token = Vec::with_capacity(10 + original_dcid.len() + RETRY_TOKEN_MAC_LEN);
        token.push(RETRY_TOKEN_VERSION);
        token.extend_from_slice(&issued.to_be_bytes());
        token.push(original_dcid.len() as u8);
        token.extend_from_slice(original_dcid.as_bytes());
        token.extend_from_slice(&mac[..RETRY_TOKEN_MAC_LEN]);
        Some(token)
    }

    /// The client's original DCID when `token` is a live Retry token this
    /// endpoint issued to `peer` for an Initial now addressed to `retry_scid`.
    #[cfg(feature = "tls")]
    fn validate_retry_token(
        &self,
        token: &[u8],
        peer: SocketAddr,
        retry_scid: ConnectionId,
        now: Instant,
    ) -> Option<ConnectionId> {
        use hmac::Mac;
        let (&version, rest) = token.split_first()?;
        if version != RETRY_TOKEN_VERSION || rest.len() < 9 {
            return None;
        }
        let issued = u64::from_be_bytes(rest[..8].try_into().ok()?);
        let dcid_len = usize::from(rest[8]);
        let rest = &rest[9..];
        if rest.len() != dcid_len + RETRY_TOKEN_MAC_LEN {
            return None;
        }
        let original_dcid = ConnectionId::new(&rest[..dcid_len]).ok()?;
        let age = now
            .checked_duration_since(self.retry_epoch?)?
            .as_secs()
            .checked_sub(issued)?;
        if age > RETRY_TOKEN_LIFETIME.as_secs() {
            return None;
        }
        // Constant-time comparison of the truncated tag.
        self.retry_token_mac(peer, original_dcid, retry_scid, issued)
            .verify_truncated_left(&rest[dcid_len..])
            .ok()?;
        Some(original_dcid)
    }

    /// A stateless Retry (RFC 9000 section 17.2.5) with its RFC 9001 section 5.8
    /// integrity tag, addressed to the client's source CID.
    #[cfg(feature = "tls")]
    fn retry_packet(
        client_scid: ConnectionId,
        original_dcid: ConnectionId,
        retry_scid: ConnectionId,
        token: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        crate::net::quic_core::PacketHeader::Retry(crate::net::quic_core::RetryHeader {
            version: 1,
            dst_cid: client_scid,
            src_cid: retry_scid,
            token,
            integrity_tag: [0; 16],
        })
        .encode(&mut bytes)
        .ok()?;
        let tag_at = bytes.len().checked_sub(16)?;
        let tag = super::handshake_driver::retry_integrity_tag(original_dcid, &bytes[..tag_at])?;
        bytes[tag_at..].copy_from_slice(&tag);
        Some(bytes)
    }

    /// Answer a tokenless Initial with a Retry, keeping no state for it.
    ///
    /// Admission output waits in its pending handshake for queue space, but a
    /// Retry has nowhere to wait. It may therefore exceed a full send batch by
    /// [`RETRY_QUEUE_SLACK`]. Past that bound, as under an Initial flood, the
    /// Initial is dropped and a real client's PTO resends it.
    #[cfg(feature = "tls")]
    fn queue_retry(
        &mut self,
        cx: &Cx,
        client_scid: ConnectionId,
        original_dcid: ConnectionId,
        peer: SocketAddr,
        now: Instant,
    ) {
        if self.pending_outgoing.len()
            >= self
                .config
                .packet_batch_size
                .saturating_add(RETRY_QUEUE_SLACK)
        {
            return;
        }
        let mut bytes = [0; ConnectionId::MAX_LEN];
        cx.random_bytes(&mut bytes);
        let Ok(retry_scid) = ConnectionId::new(&bytes) else {
            return;
        };
        if retry_scid == original_dcid {
            return;
        }
        let Some(data) = self
            .mint_retry_token(peer, original_dcid, retry_scid, now)
            .and_then(|token| Self::retry_packet(client_scid, original_dcid, retry_scid, token))
        else {
            return;
        };
        self.pending_outgoing.push_back(RoutedOutgoingPacket {
            connection_id: retry_scid,
            packet: OutgoingPacket {
                dst_addr: peer,
                data,
                send_time: None,
            },
            final_handshake_flight: false,
            ack_eliciting: false,
        });
    }

    /// Permanently stop authenticated admission while established peers drain.
    ///
    /// Clears the automatic policy and resolves every pending handshake as
    /// [`ManagedEndpointError::ShuttingDown`]. Their attributed receipts remain
    /// available to the owner. Returns the number of pending admissions stopped.
    /// Established application traffic and protocol timers continue until the
    /// owner finishes its graceful work and calls [`Self::shutdown`].
    #[cfg(feature = "tls")]
    pub fn stop_authenticated_accepts(&mut self) -> usize {
        self.authenticated_accept_closed = true;
        self.authenticated_server = None;
        let stopped = self.pending_authenticated_accept.len();
        self.fail_authenticated_accept(ManagedEndpointError::ShuttingDown);
        stopped
    }

    /// Admit one fresh server TLS handshake on this endpoint's existing socket.
    ///
    /// The caller must drive the managed event loop and consume
    /// [`Self::take_authenticated_accept_result`] to release admission capacity.
    /// One admission is allowed by default; [`Self::set_authenticated_accept_limit`]
    /// enables concurrent peers. A silent peer cannot block another admitted
    /// handshake, and unread receipts continue charging the configured limit.
    /// Established peers continue using that same receive/send/timer loop.
    /// Only the configured source address and destination CID aliases reach
    /// this driver; unknown Initial packets are refused unless an automatic
    /// server policy has been configured separately.
    /// The required ALPN must be nonempty and at most 255 bytes. TLS completion,
    /// key installation and negotiated transport parameters are checked before
    /// publication. The supplied driver must be fresh and have the server role.
    ///
    /// Peer address pinning is routing, not certificate identity. Server-side
    /// client identity requires a driver configured with client authentication;
    /// the existing convenience TLS configuration does not enable it.
    /// One pending slot has a 96-second ceiling, 64 flights, 1024 input packets,
    /// 2 MiB of outstanding output and 2 MiB of early application packets. Its
    /// retained last-flight copy has a separate 2 MiB ceiling. Driver CRYPTO
    /// reassembly retains its existing per-space byte/range bounds.
    /// Before an authenticated Handshake packet proves return reachability,
    /// output is additionally limited to three times authenticated input bytes.
    /// A blocked flight stays owned while established peers continue progressing.
    #[cfg(feature = "tls")]
    pub fn begin_authenticated_accept(
        &mut self,
        cx: &Cx,
        driver: QuicHandshakeDriver,
        expected_peer: SocketAddr,
        initial_dcid: ConnectionId,
        local_cid: ConnectionId,
        required_alpn: &[u8],
    ) -> Result<(), ManagedEndpointError> {
        let pending = self.prepare_authenticated_accept(
            cx,
            driver,
            expected_peer,
            initial_dcid,
            local_cid,
            required_alpn,
        )?;
        self.pending_authenticated_accept.push_back(pending);
        Ok(())
    }

    #[cfg(feature = "tls")]
    fn prepare_authenticated_accept(
        &mut self,
        cx: &Cx,
        mut driver: QuicHandshakeDriver,
        expected_peer: SocketAddr,
        initial_dcid: ConnectionId,
        local_cid: ConnectionId,
        required_alpn: &[u8],
    ) -> Result<PendingAuthenticatedAccept, ManagedEndpointError> {
        cx.checkpoint()
            .map_err(|_| ManagedEndpointError::Cancelled)?;
        if self.shutting_down || self.authenticated_accept_closed {
            return Err(ManagedEndpointError::ShuttingDown);
        }
        if !self.authenticated_only || !self.config.is_server {
            return Err(accept_error("requires an authenticated server socket"));
        }
        if self.pending_authenticated_accept.len()
            >= self
                .authenticated_accept_limit
                .saturating_sub(self.authenticated_accept_result.len())
        {
            return Err(accept_error(
                "authenticated admission or terminal receipt capacity exhausted",
            ));
        }
        if required_alpn.is_empty() || required_alpn.len() > 255 {
            return Err(accept_error("required ALPN must contain 1..=255 bytes"));
        }
        if !driver.is_server()
            || driver.is_complete()
            || driver.peer_connection_id().is_some()
            || driver.handshake_keys_installed()
            || driver.one_rtt_keys_installed()
        {
            return Err(accept_error("requires a fresh server TLS driver"));
        }
        if self.connection_stats().active_connections
            >= self
                .config
                .max_connections
                .saturating_sub(self.pending_authenticated_accept.len())
        {
            return Err(ManagedEndpointError::MaxConnectionsReached {
                limit: self.config.max_connections,
            });
        }
        self.connection_router
            .validate_authenticated_cids(initial_dcid, local_cid)?;
        self.prune_authenticated_initial_routes();
        if self.authenticated_cids_reserved(initial_dcid, local_cid) {
            return Err(accept_error("occupied or ambiguous admitted connection ID"));
        }
        if driver.local_transport_parameters().len() > ACCEPT_MAX_BYTES {
            return Err(accept_error(
                "local transport parameters exceed admission byte bound",
            ));
        }
        let parameters =
            crate::net::quic_core::TransportParameters::decode(driver.local_transport_parameters())
                .map_err(accept_error)?;
        // After a Retry (RFC 9000 section 7.3) the admitted route is the Retry
        // source CID, and the original DCID came from a validated token.
        let retried = parameters
            .unknown
            .iter()
            .any(|parameter| parameter.id == 0x10);
        for parameter in &parameters.unknown {
            let expected = match parameter.id {
                0x00 if retried => None,
                0x00 | 0x10 => Some(initial_dcid),
                0x0f => Some(local_cid),
                _ => None,
            };
            if expected.is_some_and(|cid| parameter.value.as_slice() != cid.as_bytes()) {
                return Err(accept_error(
                    "local TLS transport CID does not match admitted route",
                ));
            }
        }
        let now = self.timer_scheduler.now(cx)?;
        let next_pto = now
            .checked_add(ACCEPT_PTO)
            .ok_or_else(|| accept_error("PTO overflow"))?;
        let expires = now
            .checked_add(ACCEPT_PTO * 64)
            .ok_or_else(|| accept_error("expiry overflow"))?;
        driver
            .install_initial_keys(initial_dcid.as_bytes())
            .map_err(accept_error)?;
        Ok(PendingAuthenticatedAccept {
            driver,
            peer: expected_peer,
            initial_cid: initial_dcid,
            local_cid,
            required_alpn: required_alpn.to_vec(),
            packet_number: 0,
            received_packets: 0,
            flights: 0,
            next_pto,
            expires,
            last_flight: Vec::new(),
            last_flight_plan: Vec::new(),
            last_flight_dst_cid: ConnectionId::default(),
            outbound: VecDeque::new(),
            outstanding_packets: 0,
            outstanding_bytes: 0,
            socket_pending_bytes: 0,
            authenticated_received_bytes: 0,
            sent_bytes: 0,
            address_validated: false,
            peer_max_udp_payload_size: None,
            early: Vec::new(),
            early_bytes: 0,
            final_ack_queued: false,
            automatic: false,
        })
    }

    #[cfg(feature = "tls")]
    fn prune_authenticated_initial_routes(&mut self) {
        let router = &self.connection_router;
        self.authenticated_initial_routes
            .retain(|(_, local)| router.negotiated_alpn(*local).is_ok());
    }

    #[cfg(feature = "tls")]
    fn authenticated_cids_reserved(
        &self,
        initial_dcid: ConnectionId,
        local_cid: ConnectionId,
    ) -> bool {
        // Short headers carry no CID length. Prefix-related local IDs cannot be
        // routed unambiguously; long-header aliases must not name another owner.
        let conflicts = |initial: ConnectionId, local: ConnectionId| {
            initial_dcid == initial
                || initial_dcid == local
                || local_cid == initial
                || local_cid.as_bytes().starts_with(local.as_bytes())
                || local.as_bytes().starts_with(local_cid.as_bytes())
        };
        self.pending_authenticated_accept
            .iter()
            .any(|pending| conflicts(pending.initial_cid, pending.local_cid))
            || self
                .authenticated_accept_result
                .iter()
                .any(|receipt| conflicts(receipt.initial_cid, receipt.local_cid))
            || self
                .authenticated_initial_routes
                .iter()
                .any(|&(initial, local)| conflicts(initial, local))
    }

    /// Returns true when automatic admission consumed or refused this Initial.
    /// Malformed unauthenticated input never acquires a slot or result receipt.
    #[cfg(feature = "tls")]
    fn try_automatic_authenticated_accept(
        &mut self,
        cx: &Cx,
        packet: &ReceivedPacket,
    ) -> Result<bool, ManagedEndpointError> {
        if self.authenticated_server.is_none() {
            return Ok(false);
        }
        let Ok(ProtectedHeaderPrefix::Long(header)) =
            ProtectedHeaderPrefix::decode(&packet.data, 0)
        else {
            return Ok(false);
        };
        if header.packet_type != LongPacketType::Initial {
            return Ok(false);
        }
        // Existing authenticated ownership always wins over admission. An old
        // original DCID is retained separately because the router keys by the
        // negotiated server CID after TLS completes.
        if self
            .connection_router
            .negotiated_alpn(header.dst_cid)
            .is_ok()
        {
            return Ok(false);
        }
        self.prune_authenticated_initial_routes();
        if header.version != 1
            || header.dst_cid.len() < 8
            || packet.data.len() < ACCEPT_MIN_INITIAL_BYTES
            || packet.data.len() > self.config.udp_config.max_packet_size
            || self
                .authenticated_initial_routes
                .iter()
                .any(|(initial, _)| *initial == header.dst_cid)
        {
            return Ok(true);
        }
        let now = self.timer_scheduler.now(cx)?;
        // Tokens use the same clock as every admission decision.
        self.retry_epoch.get_or_insert(now);
        // A Retry token proves the client receives at its source address. An
        // invalid one is discarded, as RFC 9000 section 8.1.2 permits.
        let original_dcid = if header.token.is_empty() {
            None
        } else {
            let Some(original_dcid) =
                self.validate_retry_token(&header.token, packet.src_addr, header.dst_cid, now)
            else {
                return Ok(true);
            };
            Some(original_dcid)
        };
        let capacity = self
            .authenticated_accept_limit
            .saturating_sub(self.authenticated_accept_result.len());
        if original_dcid.is_none() {
            let retry = match self.retry_policy {
                RetryPolicy::Always => true,
                RetryPolicy::Never => false,
                RetryPolicy::UnderPressure => {
                    self.pending_authenticated_accept.len().saturating_mul(2) >= capacity
                }
            };
            if retry {
                self.queue_retry(cx, header.src_cid, header.dst_cid, packet.src_addr, now);
                return Ok(true);
            }
        }
        if self.pending_authenticated_accept.len() >= capacity {
            // A validated client displaces the oldest automatic handshake whose
            // address is still unvalidated; nothing was ever published for it.
            let displaced = original_dcid.and_then(|_| {
                self.pending_authenticated_accept
                    .iter()
                    .position(|pending| pending.automatic && !pending.address_validated)
            });
            let Some(index) = displaced else {
                return Ok(true);
            };
            if let Some(pending) = self.pending_authenticated_accept.remove(index) {
                self.pending_outgoing
                    .retain(|queued| queued.connection_id != pending.local_cid);
                self.pending_incoming
                    .retain(|queued| !pending.owns_packet(&queued.packet));
                cx.trace(&format!(
                    "QUIC admission of {} displaced by an address-validated client",
                    pending.peer
                ));
            }
        }
        if self.connection_stats().active_connections
            >= self
                .config
                .max_connections
                .saturating_sub(self.pending_authenticated_accept.len())
        {
            return Ok(true);
        }
        let mut local_cid = None;
        for _ in 0..ACCEPT_CID_ATTEMPTS {
            let mut bytes = [0; ConnectionId::MAX_LEN];
            cx.random_bytes(&mut bytes);
            cx.checkpoint()
                .map_err(|_| ManagedEndpointError::Cancelled)?;
            let candidate = ConnectionId::new(&bytes).map_err(accept_error)?;
            if candidate != header.src_cid
                && candidate != header.dst_cid
                && self
                    .connection_router
                    .validate_authenticated_cids(header.dst_cid, candidate)
                    .is_ok()
                && !self.authenticated_cids_reserved(header.dst_cid, candidate)
            {
                local_cid = Some(candidate);
                break;
            }
        }
        let Some(local_cid) = local_cid else {
            return Ok(true);
        };
        let policy = self
            .authenticated_server
            .as_ref()
            .expect("configured automatic admission");
        let mut parameters = policy.transport_parameters.clone();
        // RFC 9000 section 7.3: after a Retry, original_destination_connection_id
        // is the client's first DCID and retry_source_connection_id is the CID
        // the Retry chose, which the client now addresses.
        let retry_source = original_dcid.map(|_| (0x10, header.dst_cid));
        for (id, cid) in [
            (0x00, original_dcid.unwrap_or(header.dst_cid)),
            (0x0f, local_cid),
        ]
        .into_iter()
        .chain(retry_source)
        {
            parameters
                .unknown
                .push(crate::net::quic_core::UnknownTransportParameter {
                    id,
                    value: cid.as_bytes().to_vec(),
                });
        }
        let mut encoded = Vec::new();
        parameters.encode(&mut encoded).map_err(accept_error)?;
        let driver =
            QuicHandshakeDriver::server(Arc::clone(&policy.tls), encoded).map_err(accept_error)?;
        let required_alpn = policy.required_alpn.clone();
        let mut pending = self.prepare_authenticated_accept(
            cx,
            driver,
            packet.src_addr,
            header.dst_cid,
            local_cid,
            &required_alpn,
        )?;
        pending.automatic = true;
        pending.address_validated = original_dcid.is_some();
        let result = pending.receive(packet.clone(), self.config.udp_config.max_packet_size, now);
        // Certificate resolution and other TLS hooks can cancel the owner. Do
        // not publish even a successfully authenticated first packet afterward.
        cx.checkpoint()
            .map_err(|_| ManagedEndpointError::Cancelled)?;
        if result.is_ok() && pending.received_packets != 0 {
            self.pending_authenticated_accept.push_back(pending);
        } else if result.is_err() {
            self.queue_crypto_error_close(&mut pending);
        }
        Ok(true)
    }

    /// Consume the oldest completed accept receipt after managed-loop progress.
    /// `None` does not drive or poll the socket. A managed application callback
    /// is offered another turn after actual transport/timer progress.
    #[cfg(feature = "tls")]
    pub fn take_authenticated_accept_result(
        &mut self,
    ) -> Option<Result<ConnectionId, ManagedEndpointError>> {
        self.take_authenticated_accept_result_with_id()
            .map(|(_, result)| result)
    }

    /// Consume a completed admission together with its caller-selected local CID.
    ///
    /// Results follow completion order, independent of admission order. The CID
    /// remains available on failure or cancellation so concurrent callers can
    /// identify the failed attempt. Consuming a receipt releases its admission
    /// slot; a successful connection remains owned by the endpoint.
    #[cfg(feature = "tls")]
    pub fn take_authenticated_accept_result_with_id(
        &mut self,
    ) -> Option<(ConnectionId, Result<ConnectionId, ManagedEndpointError>)> {
        self.authenticated_accept_result
            .pop_front()
            .map(|receipt| (receipt.local_cid, receipt.result))
    }

    #[cfg(feature = "tls")]
    fn fail_authenticated_accept(&mut self, error: ManagedEndpointError) {
        while !self.pending_authenticated_accept.is_empty() {
            self.fail_authenticated_accept_at(0, error.clone());
        }
    }

    #[cfg(feature = "tls")]
    fn fail_authenticated_accept_at(&mut self, index: usize, error: ManagedEndpointError) {
        if let Some(mut pending) = self.pending_authenticated_accept.remove(index) {
            self.pending_outgoing
                .retain(|packet| packet.connection_id != pending.local_cid);
            self.pending_incoming
                .retain(|packet| !pending.owns_packet(&packet.packet));
            self.queue_crypto_error_close(&mut pending);
            self.authenticated_accept_result
                .push_back(AuthenticatedAcceptResult {
                    initial_cid: pending.initial_cid,
                    local_cid: pending.local_cid,
                    result: Err(error),
                });
        }
    }

    /// Queue the close that tells the client a refused admission's TLS alert.
    ///
    /// Like a Retry, it has no admission left to wait in, so it shares the
    /// Retry's [`RETRY_QUEUE_SLACK`] past a full send batch. Past that bound,
    /// as under a flood of refused handshakes, the close is dropped and the
    /// client's handshake times out.
    #[cfg(feature = "tls")]
    fn queue_crypto_error_close(&mut self, pending: &mut PendingAuthenticatedAccept) {
        let bound = self
            .config
            .packet_batch_size
            .saturating_add(RETRY_QUEUE_SLACK);
        for packet in pending.crypto_error_close() {
            if self.pending_outgoing.len() >= bound {
                break;
            }
            self.pending_outgoing.push_back(RoutedOutgoingPacket {
                connection_id: pending.local_cid,
                packet,
                final_handshake_flight: false,
                ack_eliciting: false,
            });
        }
    }

    #[cfg(feature = "tls")]
    fn advance_authenticated_accept(&mut self, cx: &Cx, now: Instant) -> bool {
        self.prune_authenticated_initial_routes();
        let mut completed = false;
        let mut index = 0;
        while index < self.pending_authenticated_accept.len() {
            if self.advance_authenticated_accept_at(cx, now, index) {
                completed = true;
            } else {
                index += 1;
            }
            // TLS and connection installation can call user-provided hooks.
            // Never advance another admission after such a hook cancels Cx.
            if cx.is_cancel_requested() {
                break;
            }
        }
        completed
    }

    #[cfg(feature = "tls")]
    fn advance_authenticated_accept_at(&mut self, cx: &Cx, now: Instant, index: usize) -> bool {
        let Some(pending) = self.pending_authenticated_accept.get_mut(index) else {
            return false;
        };
        if now >= pending.expires {
            self.fail_authenticated_accept_at(index, accept_error("handshake deadline expired"));
            return true;
        }
        if pending.driver.is_complete() && pending.outstanding_packets == 0 {
            let peer_parameters = pending
                .driver
                .peer_transport_parameters()
                .ok_or_else(|| accept_error("missing authenticated peer transport parameters"))
                .and_then(|bytes| {
                    if bytes.len() > ACCEPT_MAX_BYTES {
                        return Err(accept_error(
                            "peer transport parameter byte bound exhausted",
                        ));
                    }
                    crate::net::quic_core::TransportParameters::decode(bytes).map_err(accept_error)
                });
            let checked = peer_parameters.and_then(|parameters| {
                let peer_cid = pending
                    .driver
                    .peer_connection_id()
                    .ok_or_else(|| accept_error("missing authenticated peer CID"))?;
                if parameters.unknown.iter().any(|parameter| {
                    parameter.id == 0x0f && parameter.value.as_slice() != peer_cid.as_bytes()
                }) {
                    return Err(accept_error(
                        "peer TLS transport CID does not match authenticated header",
                    ));
                }
                Ok(())
            });
            if let Err(error) = checked {
                self.fail_authenticated_accept_at(index, error);
                return true;
            }
            let pending = self
                .pending_authenticated_accept
                .remove(index)
                .expect("owned handshake");
            let result = super::NativeQuicUdpConnection::finish_authenticated_handshake(
                cx,
                pending.driver,
                self.config.connection_config,
                &pending.required_alpn,
                super::StreamRole::Server,
            )
            .map_err(accept_completion_error)
            .and_then(|parts| {
                self.connection_router
                    .insert_authenticated_connection(
                        cx,
                        pending.initial_cid,
                        pending.local_cid,
                        pending.peer,
                        parts,
                        now,
                    )
                    .map_err(accept_router_error)
            });
            if result.is_ok() {
                self.authenticated_initial_routes
                    .push((pending.initial_cid, pending.local_cid));
                // Early ciphertext still requires the real 1-RTT authentication
                // and replay checks. It is never treated as accepted plaintext.
                for packet in pending.early.into_iter().rev() {
                    self.pending_incoming.push_front(ManagedIncomingPacket {
                        packet,
                        needs_clock_stamp: false,
                    });
                }
            } else {
                self.pending_incoming.retain(|packet| {
                    !PendingAuthenticatedAccept::packet_matches(
                        &packet.packet,
                        pending.initial_cid,
                        pending.local_cid,
                    )
                });
            }
            self.authenticated_accept_result
                .push_back(AuthenticatedAcceptResult {
                    initial_cid: pending.initial_cid,
                    local_cid: pending.local_cid,
                    result: result.map(|()| pending.local_cid),
                });
            return true;
        }
        if now >= pending.next_pto {
            pending.next_pto = now.checked_add(ACCEPT_PTO).unwrap_or(pending.expires);
            // An unsent flight remains owned; don't duplicate it under socket
            // backpressure or let continuous ingress hide the hard deadline.
            if pending.outstanding_packets == 0 && !pending.last_flight.is_empty() {
                pending.flights += 1;
                let result = if pending.flights > ACCEPT_MAX_FLIGHTS {
                    Err(accept_error("handshake flight bound exhausted"))
                } else {
                    pending.retransmit()
                };
                if let Err(error) = result {
                    self.fail_authenticated_accept_at(index, error);
                    return true;
                }
            }
        }
        false
    }

    #[cfg(feature = "tls")]
    fn queue_accept_output(&mut self) {
        if self.pending_outgoing.len() >= self.config.packet_batch_size {
            return;
        }
        for _ in 0..self.pending_authenticated_accept.len() {
            let pending = self
                .pending_authenticated_accept
                .front_mut()
                .expect("owned admission");
            if pending
                .outbound
                .front()
                .is_none_or(|packet| !pending.can_queue(packet.data.len()))
            {
                self.pending_authenticated_accept.rotate_left(1);
                continue;
            }
            if let Some(packet) = pending.outbound.pop_front() {
                pending.socket_pending_bytes += packet.data.len();
                self.pending_outgoing.push_back(RoutedOutgoingPacket {
                    connection_id: pending.local_cid,
                    packet,
                    final_handshake_flight: false,
                    ack_eliciting: false,
                });
            }
            self.pending_authenticated_accept.rotate_left(1);
            break;
        }
    }

    /// Retire one connection and its retained local traffic without detaching
    /// another peer's socket, keys, queues or recovery epoch. The next managed
    /// drive turn refreshes the nearest remaining deadline on its bound clock.
    /// Already transmitted network packets cannot be recalled by this method.
    pub fn remove_connection(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
    ) -> Result<(), ManagedEndpointError> {
        cx.checkpoint()
            .map_err(|_| ManagedEndpointError::Cancelled)?;
        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }
        #[cfg(feature = "tls")]
        if let Some(index) = self
            .pending_authenticated_accept
            .iter()
            .position(|pending| pending.local_cid == connection_id)
        {
            self.fail_authenticated_accept_at(index, ManagedEndpointError::Cancelled);
            return Ok(());
        }
        // Decode retained short-header ownership while its CID is still known.
        // Mutating the route first would lose its CID length during dispatch.
        let mut retained_ids = Vec::with_capacity(self.pending_incoming.len());
        for packet in &self.pending_incoming {
            retained_ids.push(
                self.connection_router
                    .retained_packet_connection_id(&packet.packet),
            );
        }
        self.connection_router
            .remove_connection(cx, connection_id)?;
        #[cfg(feature = "tls")]
        self.prune_authenticated_initial_routes();
        let mut ids = retained_ids.into_iter();
        self.pending_incoming
            .retain(|_| ids.next().flatten() != Some(connection_id));
        self.pending_outgoing
            .retain(|packet| packet.connection_id != connection_id);
        #[cfg(feature = "tls")]
        for receipt in &mut self.authenticated_accept_result {
            if receipt.local_cid == connection_id {
                receipt.result =
                    Err(ConnectionRouterError::ConnectionNotFound(connection_id).into());
            }
        }
        Ok(())
    }

    /// Create a new managed QUIC endpoint bound to the specified address.
    pub async fn bind(
        cx: &Cx,
        addr: SocketAddr,
        config: ManagedEndpointConfig,
    ) -> Result<Self, ManagedEndpointError> {
        if cx.checkpoint().is_err() {
            return Err(ManagedEndpointError::Cancelled);
        }

        // Validate configuration
        if config.max_connections == 0 {
            return Err(ManagedEndpointError::InvalidConfig(
                "max_connections must be > 0".to_string(),
            ));
        }
        if config.packet_batch_size == 0 {
            return Err(ManagedEndpointError::InvalidConfig(
                "packet_batch_size must be > 0".to_string(),
            ));
        }

        // Create UDP endpoint
        let udp_endpoint = QuicUdpEndpoint::bind(cx, addr, config.udp_config.clone()).await?;

        // Create connection router
        let mut connection_router = ConnectionRouter::with_max_connections(
            config.connection_config,
            config.max_connections,
        );
        connection_router.set_idle_timeout_micros(config.connection_idle_timeout_micros);

        // Create timer scheduler
        let timer_scheduler = QuicTimerScheduler::new();

        let endpoint_id_str = udp_endpoint.endpoint_id().to_string();
        let local_addr_str = udp_endpoint.local_addr().to_string();
        let is_server = if config.is_server { "server" } else { "client" };
        let max_connections_str = config.max_connections.to_string();

        let fields = [
            ("endpoint_id", endpoint_id_str.as_str()),
            ("local_addr", local_addr_str.as_str()),
            ("role", is_server),
            ("max_connections", max_connections_str.as_str()),
        ];
        cx.trace_with_fields("managed_quic_endpoint.bind", &fields);

        Ok(Self {
            udp_endpoint,
            connection_router,
            timer_scheduler,
            config,
            shutting_down: false,
            pending_outgoing: VecDeque::new(),
            pending_incoming: VecDeque::new(),
            authenticated_only: false,
            #[cfg(feature = "tls")]
            pending_authenticated_accept: VecDeque::new(),
            #[cfg(feature = "tls")]
            authenticated_accept_result: VecDeque::new(),
            #[cfg(feature = "tls")]
            authenticated_accept_limit: 1,
            #[cfg(feature = "tls")]
            authenticated_accept_closed: false,
            #[cfg(feature = "tls")]
            authenticated_server: None,
            #[cfg(feature = "tls")]
            authenticated_initial_routes: Vec::new(),
            #[cfg(feature = "tls")]
            prefer_accept_output: true,
            #[cfg(feature = "tls")]
            retry_policy: RetryPolicy::default(),
            #[cfg(feature = "tls")]
            retry_secret: RetrySecret([0; 32]),
            #[cfg(feature = "tls")]
            retry_epoch: None,
            prefer_send: true,
            send_backoff_until: None,
            send_backoff_streak: 0,
        })
    }

    /// Get the local socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.udp_endpoint.local_addr()
    }

    /// Get the endpoint ID for logging and tracing.
    pub fn endpoint_id(&self) -> u64 {
        self.udp_endpoint.endpoint_id()
    }

    /// Get connection router statistics.
    pub fn connection_stats(&self) -> ConnectionRouterStats {
        self.connection_router.connection_stats()
    }

    /// Protected datagrams assembled and retained until UDP confirms a send.
    ///
    /// This does not count stream data or control frames still owned by a
    /// connection and not yet assembled. During graceful application shutdown,
    /// first finish those producers, keep driving the loop, then wait for this
    /// queue to empty before closing the endpoint.
    #[must_use]
    pub fn pending_datagram_count(&self) -> usize {
        self.pending_outgoing.len()
    }

    /// Assembled unsent datagrams for one connection, including output still
    /// owned by the router after cancellation or a partial managed handoff.
    #[cfg(all(feature = "tls", feature = "http3"))]
    pub(crate) fn pending_datagram_count_for(&self, connection_id: ConnectionId) -> usize {
        self.pending_outgoing
            .iter()
            .filter(|packet| packet.connection_id == connection_id)
            .count()
            + self
                .connection_router
                .pending_datagram_count_for(connection_id)
    }

    /// Retire one authenticated application's route without stopping its peers.
    /// Returns false while ordinary buffered or unacknowledged output still
    /// needs service, preserving response/GOAWAY recovery after packet loss.
    ///
    /// After an explicit application drain deadline, `force` discards only this
    /// connection's unsent ordinary output. A successful request is idempotent:
    /// the event loop owns its protected close until UDP send or the connection's
    /// existing drain deadline, then the normal lifecycle timer removes the route.
    #[cfg(all(feature = "tls", feature = "http3"))]
    pub(crate) fn request_authenticated_close(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
        app_error_code: u64,
        force: bool,
    ) -> Result<bool, ManagedEndpointError> {
        cx.checkpoint()
            .map_err(|_| ManagedEndpointError::Cancelled)?;
        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }
        let was_terminal = self.connection_router.connection_is_terminal(connection_id);
        if !was_terminal && !force && self.pending_datagram_count_for(connection_id) != 0 {
            return Ok(false);
        }
        let now = self.timer_scheduler.now(cx)?;
        let accepted = self.connection_router.request_authenticated_close(
            cx,
            connection_id,
            now,
            app_error_code,
            force,
        )?;
        if accepted && !was_terminal {
            self.pending_outgoing
                .retain(|packet| packet.connection_id != connection_id);
        }
        Ok(accepted)
    }

    /// Route a native connection into this endpoint for integration tests.
    #[cfg(any(test, feature = "test-internals"))]
    pub async fn create_connection_for_testing(
        &mut self,
        cx: &Cx,
        connection_id: crate::net::quic_core::ConnectionId,
        peer_addr: SocketAddr,
    ) -> Result<(), ManagedEndpointError> {
        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }

        self.connection_router
            .create_connection(cx, connection_id, peer_addr, self.config.is_server)
            .await
            .map_err(Into::into)
    }

    /// Remove a routed native connection and hand ownership to the caller.
    pub fn take_connection(
        &mut self,
        cx: &Cx,
        connection_id: crate::net::quic_core::ConnectionId,
    ) -> Result<AcceptedNativeQuicConnection, ManagedEndpointError> {
        if cx.checkpoint().is_err() {
            return Err(ManagedEndpointError::Cancelled);
        }

        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }

        let connection = self
            .connection_router
            .take_connection(cx, connection_id)
            .map_err(ManagedEndpointError::from)?;
        #[cfg(feature = "tls")]
        self.prune_authenticated_initial_routes();
        self.pending_outgoing
            .retain(|packet| packet.connection_id != connection_id);
        self.timer_scheduler.cancel_pending();
        Ok(connection)
    }

    /// Remove the next routed native connection using deterministic router order.
    pub fn take_next_connection(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<AcceptedNativeQuicConnection>, ManagedEndpointError> {
        if cx.checkpoint().is_err() {
            return Err(ManagedEndpointError::Cancelled);
        }

        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }

        let connection = self
            .connection_router
            .take_next_connection(cx)
            .map_err(ManagedEndpointError::from)?;
        #[cfg(feature = "tls")]
        self.prune_authenticated_initial_routes();
        if let Some(connection) = &connection {
            self.pending_outgoing
                .retain(|packet| packet.connection_id != connection.connection_id);
        }
        self.timer_scheduler.cancel_pending();
        Ok(connection)
    }

    /// Run the main endpoint event loop.
    ///
    /// This processes incoming packets, handles timer events, and manages
    /// connection lifecycle until cancellation or shutdown.
    pub async fn run_event_loop(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        let result = self
            .drive_event_loop(cx, false, |_, _, _| {
                Poll::<Result<(), ManagedEndpointError>>::Pending
            })
            .await
            .map(|_| ());
        self.timer_scheduler.cancel_pending();
        #[cfg(feature = "tls")]
        if matches!(
            &result,
            Err(ManagedEndpointError::Cancelled
                | ManagedEndpointError::ConnectionRouter(ConnectionRouterError::Cancelled))
        ) {
            self.fail_authenticated_accept(ManagedEndpointError::Cancelled);
        }
        match result {
            Err(ManagedEndpointError::ConnectionRouter(ConnectionRouterError::Cancelled)) => {
                Err(ManagedEndpointError::Cancelled)
            }
            other => other,
        }
    }

    /// Drive authenticated application work together with UDP and protocol
    /// timers. The callback can access connections through `with_connection_mut`
    /// and poll its own futures using the supplied task context.
    ///
    /// After returning `Pending`, the callback runs again when its registered
    /// waker fires or transport/timer progress is available. It is not polled by
    /// a periodic timer. Queued output gets a driver turn before parking.
    /// `Ready` returns the application result; the endpoint retains queued I/O
    /// and can be driven again or explicitly shut down by its owner.
    #[cfg(feature = "tls")]
    pub async fn run_event_loop_with_application<T, F>(
        &mut self,
        cx: &Cx,
        application: F,
    ) -> Result<T, ManagedEndpointError>
    where
        F: FnMut(&Cx, &mut Self, &mut Context<'_>) -> Poll<Result<T, ManagedEndpointError>>,
    {
        let result = self.drive_event_loop(cx, true, application).await;
        self.timer_scheduler.cancel_pending();
        if matches!(
            &result,
            Err(ManagedEndpointError::Cancelled
                | ManagedEndpointError::ConnectionRouter(ConnectionRouterError::Cancelled))
        ) {
            self.fail_authenticated_accept(ManagedEndpointError::Cancelled);
        }
        match result {
            Ok(Some(value)) => Ok(value),
            Ok(None) => Err(ManagedEndpointError::ShuttingDown),
            Err(ManagedEndpointError::ConnectionRouter(ConnectionRouterError::Cancelled)) => {
                Err(ManagedEndpointError::Cancelled)
            }
            Err(error) => Err(error),
        }
    }

    async fn drive_event_loop<T, F>(
        &mut self,
        cx: &Cx,
        application_enabled: bool,
        mut application: F,
    ) -> Result<Option<T>, ManagedEndpointError>
    where
        F: FnMut(&Cx, &mut Self, &mut Context<'_>) -> Poll<Result<T, ManagedEndpointError>>,
    {
        if cx.checkpoint().is_err() {
            return Err(ManagedEndpointError::Cancelled);
        }

        cx.trace(&format!(
            "Starting QUIC endpoint event loop for endpoint {}",
            self.endpoint_id()
        ));

        // Bind once, before network waits, so all subsequent deadlines and
        // packet timestamps use the same explicit runtime-clock mapping.
        self.timer_scheduler.now(cx)?;
        let mut cancel = QuicCancelWake::new(cx);
        let application_wake = application_enabled.then(|| {
            Arc::new(ManagedApplicationWake {
                ready: AtomicBool::new(true),
                parent: std::sync::Mutex::new(None),
            })
        });
        let _application_registration =
            ManagedApplicationRegistration(application_wake.as_ref().map(Arc::clone));
        let mut application_yielded = false;
        while !self.shutting_down {
            if cx.checkpoint().is_err() {
                return Err(ManagedEndpointError::Cancelled);
            }

            // Draining connections retain their route until the drain deadline.
            // Only an explicitly queued local close may survive that boundary.
            self.pending_outgoing.retain(|packet| {
                self.connection_router
                    .connection_can_send_queued(packet.connection_id)
            });

            #[cfg(feature = "tls")]
            {
                let now = self.timer_scheduler.now(cx)?;
                if self.advance_authenticated_accept(cx, now) {
                    if let Some(wake) = &application_wake {
                        wake.ready.store(true, Ordering::Release);
                    }
                }
            }

            let available = self
                .config
                .packet_batch_size
                .saturating_sub(self.pending_outgoing.len());
            self.pending_outgoing
                .extend(self.connection_router.take_pending_timer_output(available));
            #[cfg(feature = "tls")]
            {
                // Alternate admission and established output when the entire
                // configured send batch is one packet. Due timer output keeps
                // its existing priority; no new self-waking polling is added.
                if self.prefer_accept_output {
                    self.queue_accept_output();
                }
                self.prefer_accept_output = !self.prefer_accept_output;
            }
            let available = self
                .config
                .packet_batch_size
                .saturating_sub(self.pending_outgoing.len());
            if available > 0 {
                let now = self.timer_scheduler.now(cx)?;
                self.pending_outgoing.extend(
                    self.connection_router
                        .drain_deferred_output(cx, now, available)
                        .await?,
                );
            }
            #[cfg(feature = "tls")]
            self.queue_accept_output();
            self.drop_oversized_outgoing(cx)?;
            self.refresh_timer(cx).await?;
            let event = poll_fn(|task_cx| {
                let _current = Cx::set_current(Some(cx.clone()));
                if cancel.checkpoint(task_cx.waker()).is_err() {
                    return Poll::Ready(Err(ManagedEndpointError::Cancelled));
                }
                if let Poll::Ready(Some(deadline)) = self.timer_scheduler.poll_timer(task_cx) {
                    return Poll::Ready(Ok(EndpointEvent::Timer(deadline)));
                }
                if let Some(wake) = &application_wake {
                    // Updating the parent does not itself make application
                    // work ready; even executors replacing wakers can park.
                    wake.register_parent(task_cx.waker());
                    if !application_yielded {
                        if let Some(event) = self.poll_application(cx, wake, &mut application) {
                            return Poll::Ready(event);
                        }
                    }
                }
                for send in [self.prefer_send, !self.prefer_send] {
                    if send {
                        if !self.pending_outgoing.is_empty() && self.send_backoff_until.is_none() {
                            let pending = self
                                .pending_outgoing
                                .iter()
                                .take(self.config.packet_batch_size)
                                .map(|outgoing| &outgoing.packet);
                            match self.udp_endpoint.poll_send_batch(cx, task_cx, pending) {
                                Poll::Ready(result) => {
                                    self.prefer_send = false;
                                    return Poll::Ready(Ok(EndpointEvent::Sent(result)));
                                }
                                Poll::Pending => {}
                            }
                        }
                    } else {
                        // ACKs and other peers must progress even when writes are blocked.
                        // Packet processing defers output generation when the queue is full.
                        if !self.pending_incoming.is_empty() {
                            self.prefer_send = true;
                            return Poll::Ready(Ok(EndpointEvent::RetainedPackets));
                        }
                        match self.udp_endpoint.poll_receive_batch(
                            cx,
                            task_cx,
                            self.config.packet_batch_size,
                        ) {
                            Poll::Ready(result) => {
                                self.prefer_send = true;
                                return Poll::Ready(result.map(EndpointEvent::Packets).map_err(
                                    |error| match error {
                                        QuicUdpEndpointError::Cancelled => {
                                            ManagedEndpointError::Cancelled
                                        }
                                        other => other.into(),
                                    },
                                ));
                            }
                            Poll::Pending => {}
                        }
                    }
                }
                // A self-waking application gets another turn only after both
                // read and write readiness were offered service. Keep its wake
                // bit while doing so; no application event is discarded.
                if application_yielded {
                    if let Some(wake) = &application_wake {
                        if let Some(event) = self.poll_application(cx, wake, &mut application) {
                            return Poll::Ready(event);
                        }
                    }
                }
                Poll::Pending
            })
            .await?;
            let application_turn = matches!(&event, EndpointEvent::ApplicationTurn);
            application_yielded = application_turn;
            match event {
                EndpointEvent::ApplicationComplete(value) => return Ok(Some(value)),
                EndpointEvent::ApplicationTurn => {}
                EndpointEvent::Packets(packets) => self.process_packet_batch(cx, packets).await?,
                EndpointEvent::RetainedPackets => self.process_packet_batch(cx, Vec::new()).await?,
                EndpointEvent::Timer(deadline) => {
                    if self
                        .send_backoff_until
                        .is_some_and(|retry_at| retry_at <= deadline)
                    {
                        self.send_backoff_until = None;
                    }
                    self.process_timer_events(cx, deadline).await?;
                }
                EndpointEvent::Sent(Err(error)) => {
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        return Err(ManagedEndpointError::Cancelled);
                    }
                    if send_error_is_resource_shortage(&error) {
                        // The queue stays intact and receives keep running;
                        // the bound timer wakes the loop for the retry.
                        let shift = self.send_backoff_streak.min(SEND_BACKOFF_MAX_SHIFT);
                        let delay = SEND_BACKOFF_BASE * (1_u32 << shift);
                        self.send_backoff_streak = self.send_backoff_streak.saturating_add(1);
                        self.send_backoff_until = Some(self.timer_scheduler.now(cx)? + delay);
                        cx.trace(&format!(
                            "QUIC send resource shortage ({error}); retrying {} queued packets in {delay:?}",
                            self.pending_outgoing.len()
                        ));
                    } else if send_error_blames_destination(&error) {
                        if let Some(packet) = self.pending_outgoing.front() {
                            let peer = packet.packet.dst_addr;
                            #[cfg(feature = "tls")]
                            while let Some(index) = self
                                .pending_authenticated_accept
                                .iter()
                                .position(|pending| pending.peer == peer)
                            {
                                self.fail_authenticated_accept_at(
                                    index,
                                    ManagedEndpointError::UdpEndpoint(error.to_string()),
                                );
                            }
                            let queued = self.pending_outgoing.len();
                            self.pending_outgoing
                                .retain(|packet| packet.packet.dst_addr != peer);
                            self.pending_incoming
                                .retain(|packet| packet.packet.src_addr != peer);
                            let retired = self.connection_router.discard_peer_connections(peer);
                            #[cfg(feature = "tls")]
                            self.prune_authenticated_initial_routes();
                            cx.trace(&format!("QUIC peer {peer} send failed ({error}); retired {retired} connections and {} unsent packets", queued - self.pending_outgoing.len()));
                        }
                    } else {
                        return Err(ManagedEndpointError::UdpEndpoint(error.to_string()));
                    }
                }
                EndpointEvent::Sent(Ok(result)) => {
                    if result.packets_processed == 0
                        || result.packets_processed > self.pending_outgoing.len()
                    {
                        return Err(ManagedEndpointError::UdpEndpoint(
                            "UDP send made invalid progress".to_string(),
                        ));
                    }
                    self.send_backoff_streak = 0;
                    let sent_at = self.timer_scheduler.now(cx);
                    for packet in self.pending_outgoing.drain(..result.packets_processed) {
                        #[cfg(feature = "tls")]
                        if let Some(pending) = self
                            .pending_authenticated_accept
                            .iter_mut()
                            .find(|pending| packet.connection_id == pending.local_cid)
                        {
                            pending.sent(packet.packet.data.len());
                        }
                        // Commit the entire sent prefix even if clock validation
                        // fails; retrying it would duplicate transmitted packets.
                        self.connection_router
                            .packet_sent(&packet, sent_at.as_ref().ok().copied());
                    }
                    sent_at?;
                    if let Some(error) = result.error {
                        // Only a committed prefix reports a stringified error.
                        // Retrying the unchanged tail surfaces the concrete
                        // error kind, which the classification above handles.
                        cx.trace(&format!(
                            "QUIC send stopped after {} packets ({error}); retrying the unsent tail",
                            result.packets_processed
                        ));
                    }
                }
            }
            if !application_turn {
                if let Some(wake) = &application_wake {
                    wake.ready.store(true, Ordering::Release);
                }
            }
            // A perpetually readable socket must not monopolize a worker.
            // This is one cooperative turn, with no wall-clock polling delay.
            crate::runtime::yield_now().await;
        }

        cx.trace(&format!(
            "QUIC endpoint event loop stopped for endpoint {}",
            self.endpoint_id()
        ));

        Ok(None)
    }

    /// Process a batch of incoming packets.
    async fn process_packet_batch(
        &mut self,
        cx: &Cx,
        packets: Vec<ReceivedPacket>,
    ) -> Result<(), ManagedEndpointError> {
        // Own the entire received batch before checking cancellation. The
        // front packet is retained until routing completes, and later packets
        // never disappear when an earlier asynchronous operation is dropped.
        self.pending_incoming
            .extend(packets.into_iter().map(|packet| ManagedIncomingPacket {
                packet,
                needs_clock_stamp: true,
            }));
        // Stamp fresh socket input once, before cancellation can park this
        // batch. Handshake-buffered input already carries its original epoch.
        // A clock-binding failure still leaves every datagram owned for retry.
        if self
            .pending_incoming
            .iter()
            .any(|packet| packet.needs_clock_stamp)
        {
            let now = self.timer_scheduler.now(cx)?;
            for packet in &mut self.pending_incoming {
                if packet.needs_clock_stamp {
                    packet.packet.receive_time = now;
                    packet.needs_clock_stamp = false;
                }
            }
        }
        if cx.checkpoint().is_err() {
            return Err(ManagedEndpointError::Cancelled);
        }

        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }

        if self.pending_incoming.is_empty() {
            return Ok(()); // No packets to process
        }

        let count = self
            .config
            .packet_batch_size
            .min(self.pending_incoming.len());
        for _ in 0..count {
            let Some(packet) = self
                .pending_incoming
                .front()
                .map(|entry| entry.packet.clone())
            else {
                // A failed pending admission may have retired its entire
                // remaining suffix while preserving other peers' datagrams.
                break;
            };
            #[cfg(feature = "tls")]
            if let Some(index) = self
                .pending_authenticated_accept
                .iter()
                .position(|pending| pending.owns_packet(&packet))
            {
                self.pending_incoming.pop_front();
                let now = self.timer_scheduler.now(cx)?;
                let max_packet_size = self.config.udp_config.max_packet_size;
                let result = self
                    .pending_authenticated_accept
                    .get_mut(index)
                    .expect("owned admission")
                    .receive(packet, max_packet_size, now);
                if let Err(error) = result {
                    self.fail_authenticated_accept_at(index, error);
                }
                if cx.checkpoint().is_err() {
                    return Err(ManagedEndpointError::Cancelled);
                }
                continue;
            }
            #[cfg(feature = "tls")]
            if self.try_automatic_authenticated_accept(cx, &packet)? {
                self.pending_incoming.pop_front();
                cx.checkpoint()
                    .map_err(|_| ManagedEndpointError::Cancelled)?;
                continue;
            }
            // Route packet through connection router
            let emit_output = self.pending_outgoing.len() < self.config.packet_batch_size;
            let routed = match self
                .connection_router
                .route_packet_with_output(cx, packet, emit_output)
                .await
            {
                Ok(routed) => routed,
                Err(ConnectionRouterError::Cancelled) => {
                    return Err(ManagedEndpointError::Cancelled);
                }
                Err(error) => {
                    self.pending_incoming.pop_front();
                    cx.trace(&format!("Packet processing error: {error}"));
                    continue;
                }
            };
            self.pending_incoming.pop_front();
            match routed {
                RoutingResult::Routed {
                    connection_id,
                    outgoing_packets: packets,
                } => {
                    cx.trace(&format!("Routed packet to connection {connection_id:?}"));
                    self.queue_connection_packets(connection_id, packets);
                }
                RoutingResult::NewConnection {
                    connection_id,
                    peer_addr,
                    triggering_packet,
                    outgoing_packets: packets,
                } => {
                    if self.authenticated_only {
                        cx.trace(
                            "Dropped an unauthenticated Initial on an authenticated-only managed socket",
                        );
                        continue;
                    }
                    // Check connection limit
                    let stats = self.connection_router.connection_stats();
                    if stats.active_connections >= self.config.max_connections {
                        cx.trace(&format!(
                            "Rejecting new connection {connection_id:?}: max connections reached"
                        ));
                        continue;
                    }

                    // Create new connection
                    if let Err(e) = self
                        .connection_router
                        .create_connection(cx, connection_id, peer_addr, self.config.is_server)
                        .await
                    {
                        cx.trace(&format!(
                            "Failed to create connection {connection_id:?}: {e}"
                        ));
                        continue;
                    }

                    cx.trace(&format!("Created new connection {connection_id:?}"));
                    self.queue_connection_packets(connection_id, packets);
                    let mut outgoing_packets = Vec::new();
                    let rerouted = self
                        .reroute_triggering_new_connection_packet(
                            cx,
                            connection_id,
                            triggering_packet,
                            &mut outgoing_packets,
                        )
                        .await;
                    self.queue_connection_packets(connection_id, outgoing_packets);
                    match rerouted {
                        Ok(()) => {}
                        Err(ManagedEndpointError::Cancelled) => {
                            return Err(ManagedEndpointError::Cancelled);
                        }
                        Err(error) => cx.trace(&format!("Initial processing error: {error}")),
                    }
                }
                RoutingResult::Drop { reason } => {
                    cx.trace(&format!("Dropped packet: {reason}"));
                }
            }
            // An authenticated packet commits synchronously once its replay
            // number is accepted. Retire that packet before observing a cancel
            // raised by a stream waker during commitment; preserve the suffix.
            cx.checkpoint()
                .map_err(|_| ManagedEndpointError::Cancelled)?;
        }

        Ok(())
    }

    async fn reroute_triggering_new_connection_packet(
        &mut self,
        cx: &Cx,
        expected_connection_id: ConnectionId,
        triggering_packet: ReceivedPacket,
        outgoing_packets: &mut Vec<OutgoingPacket>,
    ) -> Result<(), ManagedEndpointError> {
        match self
            .connection_router
            .route_packet_with_output(
                cx,
                triggering_packet,
                self.pending_outgoing.len() < self.config.packet_batch_size,
            )
            .await?
        {
            RoutingResult::Routed {
                connection_id,
                outgoing_packets: mut packets,
            } => {
                if connection_id != expected_connection_id {
                    cx.trace(&format!(
                        "Triggering Initial rerouted to {connection_id:?}, expected {expected_connection_id:?}"
                    ));
                }
                outgoing_packets.append(&mut packets);
            }
            RoutingResult::NewConnection { connection_id, .. } => {
                cx.trace(&format!(
                    "Triggering Initial still appeared as new connection {connection_id:?} after creation"
                ));
            }
            RoutingResult::Drop { reason } => {
                cx.trace(&format!(
                    "Triggering Initial dropped after connection creation: {reason}"
                ));
            }
        }

        Ok(())
    }

    fn queue_connection_packets(
        &mut self,
        connection_id: ConnectionId,
        packets: impl IntoIterator<Item = OutgoingPacket>,
    ) {
        self.pending_outgoing
            .extend(packets.into_iter().map(|packet| RoutedOutgoingPacket {
                connection_id,
                packet,
                final_handshake_flight: false,
                ack_eliciting: false,
            }));
    }

    /// A datagram above the socket limit is a local packetization fault. It
    /// fails only the connection that built it; its peer address stays usable.
    fn drop_oversized_outgoing(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        let limit = self.udp_endpoint.config().max_packet_size;
        while let Some(index) = self
            .pending_outgoing
            .iter()
            .position(|packet| packet.packet.data.len() > limit)
        {
            let Some(packet) = self.pending_outgoing.remove(index) else {
                break;
            };
            let connection_id = packet.connection_id;
            let reason = format!(
                "connection {connection_id:?} built a {} byte datagram above the {limit} byte endpoint limit",
                packet.packet.data.len()
            );
            cx.trace(&format!(
                "QUIC {reason}; dropped it and failed only that connection"
            ));
            #[cfg(feature = "tls")]
            if let Some(index) = self
                .pending_authenticated_accept
                .iter()
                .position(|pending| pending.local_cid == connection_id)
            {
                self.fail_authenticated_accept_at(index, ManagedEndpointError::UdpEndpoint(reason));
                continue;
            }
            match self.remove_connection(cx, connection_id) {
                Ok(())
                | Err(ManagedEndpointError::ConnectionRouter(
                    ConnectionRouterError::ConnectionNotFound(_),
                )) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Process timer events for all connections.
    async fn refresh_timer(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        let next = self.connection_router.next_timer_deadline();
        // A send backoff wakes the loop through the same bound timer.
        let next = next.into_iter().chain(self.send_backoff_until).min();
        #[cfg(feature = "tls")]
        let next = self
            .pending_authenticated_accept
            .iter()
            .fold(next, |next, pending| {
                let admission = pending.next_pto.min(pending.expires);
                Some(next.map_or(admission, |established| established.min(admission)))
            });
        if self.timer_scheduler.current_deadline() != next {
            self.timer_scheduler.cancel_pending();
            if let Some(deadline) = next {
                self.timer_scheduler
                    .schedule_timer_bound(cx, deadline)
                    .await?;
            }
        }
        Ok(())
    }

    async fn process_timer_events(
        &mut self,
        cx: &Cx,
        deadline: Instant,
    ) -> Result<(), ManagedEndpointError> {
        if cx.checkpoint().is_err() {
            return Err(ManagedEndpointError::Cancelled);
        }

        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }

        let now = self.timer_scheduler.now(cx)?.max(deadline);
        // Each removal commits route and retained-queue ownership together,
        // before recovery processing can yield or observe cancellation.
        for cid in self.connection_router.expired_connections(now) {
            self.remove_connection(cx, cid)?;
        }
        self.pending_outgoing.retain(|packet| {
            self.connection_router
                .connection_can_send_queued(packet.connection_id)
        });
        let pending_connections = self
            .pending_outgoing
            .iter()
            .map(|packet| packet.connection_id)
            .collect();
        let outgoing_packets = self
            .connection_router
            .process_managed_timer_events(cx, now, &pending_connections)
            .await?;
        self.pending_outgoing.extend(outgoing_packets);

        Ok(())
    }

    /// Shut down the endpoint, sending a protected close for local 1-RTT connections.
    ///
    /// Sends are bounded by each connection's drain deadline. Cancellation or a
    /// send failure still releases local ownership. This terminal operation does
    /// not retain routes for close retransmission or send pre-1RTT close packets.
    pub async fn shutdown(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        cx.trace(&format!(
            "Shutting down managed QUIC endpoint {}",
            self.endpoint_id()
        ));

        self.shutting_down = true;

        #[cfg(feature = "tls")]
        self.fail_authenticated_accept(ManagedEndpointError::ShuttingDown);

        let closed_connections = self.connection_router.connection_stats().active_connections;
        let now = self
            .timer_scheduler
            .now(cx)
            .unwrap_or_else(|_| Instant::now());
        let retained_closes = self
            .pending_outgoing
            .drain(..)
            .filter_map(|packet| {
                self.connection_router
                    .queued_local_close_deadline(packet.connection_id)
                    .filter(|deadline| *deadline > now)
                    .map(|deadline| (packet.packet, deadline))
            })
            .collect();
        self.timer_scheduler.cancel_pending();
        // Hold cleanup across every suspension, including a blocked socket send.
        // Dropping this future must retire ownership on the retained endpoint.
        let cleanup = ManagedShutdownCleanup(self);
        let close_result = cleanup
            .0
            .send_shutdown_closes(cx, now, retained_closes)
            .await;
        let udp_result = cleanup.0.udp_endpoint.shutdown(cx).await;
        drop(cleanup);
        close_result?;
        udp_result.map_err(|error| match error {
            QuicUdpEndpointError::Cancelled => ManagedEndpointError::Cancelled,
            other => other.into(),
        })?;

        cx.trace(&format!(
            "Managed QUIC endpoint {} shutdown complete; closed {} connections",
            self.endpoint_id(),
            closed_connections
        ));

        Ok(())
    }

    async fn send_shutdown_closes(
        &mut self,
        cx: &Cx,
        now: Instant,
        mut packets: Vec<(OutgoingPacket, Instant)>,
    ) -> Result<(), ManagedEndpointError> {
        let additional_packets = self
            .connection_router
            .prepare_shutdown_close_packets(cx, now)
            .await
            .map_err(|error| match error {
                ConnectionRouterError::Cancelled => ManagedEndpointError::Cancelled,
                other => other.into(),
            })?;
        packets.extend(additional_packets);
        let mut cancel = QuicCancelWake::new(cx);
        for (packet, deadline) in packets {
            self.timer_scheduler.cancel_pending();
            self.timer_scheduler
                .schedule_timer_bound(cx, deadline)
                .await
                .map_err(|error| match error {
                    ConnectionRouterError::Cancelled => ManagedEndpointError::Cancelled,
                    other => other.into(),
                })?;
            poll_fn(|task_cx| {
                let _current = Cx::set_current(Some(cx.clone()));
                if cancel.checkpoint(task_cx.waker()).is_err() {
                    return Poll::Ready(Err(ManagedEndpointError::Cancelled));
                }
                // Check before every socket poll, including a resumed blocked send.
                if matches!(
                    self.timer_scheduler.poll_timer(task_cx),
                    Poll::Ready(Some(_))
                ) {
                    return Poll::Ready(Err(ManagedEndpointError::UdpEndpoint(
                        "QUIC close send exceeded drain deadline".to_string(),
                    )));
                }
                match self
                    .udp_endpoint
                    .poll_send_batch(cx, task_cx, std::iter::once(&packet))
                {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => {
                        Poll::Ready(Err(ManagedEndpointError::Cancelled))
                    }
                    Poll::Ready(Err(error)) => {
                        Poll::Ready(Err(ManagedEndpointError::UdpEndpoint(error.to_string())))
                    }
                    Poll::Ready(Ok(result)) => Poll::Ready(match result.error {
                        Some(error) => Err(ManagedEndpointError::UdpEndpoint(error)),
                        None if result.packets_processed == 1 => Ok(()),
                        None => Err(ManagedEndpointError::UdpEndpoint(
                            "QUIC close send made invalid progress".to_string(),
                        )),
                    }),
                }
            })
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "managed_endpoint_inline_tests.rs"]
mod tests;
