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

    fn queue_flight(&mut self, packets: &[OutgoingPacket]) -> Result<(), ManagedEndpointError> {
        let bytes = self.check_flight(packets)?;
        self.outstanding_packets += packets.len();
        self.outstanding_bytes += bytes;
        self.outbound.extend(packets.iter().cloned());
        Ok(())
    }

    fn retransmit(&mut self) -> Result<(), ManagedEndpointError> {
        let bytes = self.check_flight(&self.last_flight)?;
        self.outstanding_packets += self.last_flight.len();
        self.outstanding_bytes += bytes;
        self.outbound.extend(self.last_flight.iter().cloned());
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
            if self.early.len() == ACCEPT_MAX_PACKETS
                || packet.data.len() > ACCEPT_MAX_BYTES.saturating_sub(self.early_bytes)
            {
                return Err(accept_error("early application packet bound exhausted"));
            }
            self.received_packets += 1;
            self.early_bytes += packet.data.len();
            self.early.push(packet);
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
        let peer_cid = match self.driver.recv_handshake_packet(&packet.data) {
            Ok(cid) => cid,
            Err(error)
                if super::handshake_driver::is_stale_handshake_packet_error(&error)
                    || super::handshake_driver::is_unauthenticated_handshake_packet_error(
                        &error,
                    ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(accept_error(error)),
        };
        // Only an authenticated packet counts toward the accepted bound.
        self.received_packets += 1;
        // An Initial's publicly derivable keys do not prove return reachability.
        // Until a valid Handshake packet does, only successfully authenticated
        // received bytes fund output, including every actual PTO retransmission.
        self.authenticated_received_bytes = self
            .authenticated_received_bytes
            .saturating_add(packet.data.len() as u64);
        self.address_validated |= header.packet_type == LongPacketType::Handshake;
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
            }
        }
        if !packets.is_empty() {
            self.flights += 1;
            if self.flights > ACCEPT_MAX_FLIGHTS {
                return Err(accept_error("handshake flight bound exhausted"));
            }
            self.queue_flight(&packets)?;
            self.last_flight = packets;
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
    /// Alternate ready read/write batches; timers and cancellation always get a turn.
    prefer_send: bool,
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
            prefer_send: true,
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
    /// admission. Retry, shared stateless-reset tokens and preferred-address
    /// parameters are unsupported and refused. Server IDs use the driving Cx's
    /// explicit entropy source with bounded collision retries, never a peer ID.
    ///
    /// Configuration requires no pending admission or unread receipt. An active
    /// endpoint may be reconfigured only if it already has authenticated-only
    /// routing; existing connections retain their negotiated configuration.
    /// Automatic admission does not enable the legacy unauthenticated path,
    /// Retry, address migration, or acceptance of 0-RTT application data.
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
        cx.checkpoint()
            .map_err(|_| ManagedEndpointError::Cancelled)?;
        self.authenticated_server = Some(AuthenticatedServerPolicy {
            tls,
            transport_parameters: parameters,
            required_alpn: required_alpn.to_vec(),
        });
        self.authenticated_only = true;
        Ok(())
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
        for parameter in &parameters.unknown {
            let expected = match parameter.id {
                0x00 => Some(initial_dcid),
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
            || self.pending_authenticated_accept.len()
                >= self
                    .authenticated_accept_limit
                    .saturating_sub(self.authenticated_accept_result.len())
            || self.connection_stats().active_connections
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
        for (id, cid) in [(0x00, header.dst_cid), (0x0f, local_cid)] {
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
        let now = self.timer_scheduler.now(cx)?;
        let result = pending.receive(packet.clone(), self.config.udp_config.max_packet_size, now);
        // Certificate resolution and other TLS hooks can cancel the owner. Do
        // not publish even a successfully authenticated first packet afterward.
        cx.checkpoint()
            .map_err(|_| ManagedEndpointError::Cancelled)?;
        if result.is_ok() && pending.received_packets != 0 {
            self.pending_authenticated_accept.push_back(pending);
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
        if let Some(pending) = self.pending_authenticated_accept.remove(index) {
            self.pending_outgoing
                .retain(|packet| packet.connection_id != pending.local_cid);
            self.pending_incoming
                .retain(|packet| !pending.owns_packet(&packet.packet));
            self.authenticated_accept_result
                .push_back(AuthenticatedAcceptResult {
                    initial_cid: pending.initial_cid,
                    local_cid: pending.local_cid,
                    result: Err(error),
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
            prefer_send: true,
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
                        if !self.pending_outgoing.is_empty() {
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
                EndpointEvent::Timer(deadline) => self.process_timer_events(cx, deadline).await?,
                EndpointEvent::Sent(Err(error)) => {
                    use std::io::ErrorKind;
                    if error.kind() == ErrorKind::Interrupted {
                        return Err(ManagedEndpointError::Cancelled);
                    }
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionRefused
                            | ErrorKind::ConnectionReset
                            | ErrorKind::AddrNotAvailable
                            | ErrorKind::InvalidInput
                            | ErrorKind::HostUnreachable
                            | ErrorKind::NetworkUnreachable
                            | ErrorKind::PermissionDenied
                    ) {
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
                        // The unsent suffix remains available if the owner retries this loop.
                        return Err(ManagedEndpointError::UdpEndpoint(error));
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

    /// Process timer events for all connections.
    async fn refresh_timer(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        let next = self.connection_router.next_timer_deadline();
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
mod tests {
    use super::*;
    use crate::net::quic_core::ConnectionId;
    use crate::test_utils::run_test_with_cx;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[derive(Default)]
    struct SelectionWake(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for SelectionWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn selection_packet_protection(cx: &Cx) -> crate::net::atp::quic::AtpPacketProtection {
        use crate::net::atp::quic::AtpPacketProtection;
        use crate::net::quic_native::{PacketProtectionSpace, QuicHandshakeTranscript};
        let mut transcript = QuicHandshakeTranscript::new();
        transcript.record("client_initial", b"managed selection client fixture");
        transcript.record("server_handshake", b"managed selection server fixture");
        let mut protection = AtpPacketProtection::new_client(true).unwrap();
        protection
            .derive_keys(
                cx,
                PacketProtectionSpace::OneRtt,
                &transcript,
                b"managed selection unit fixture, not authenticated handshake proof",
            )
            .await
            .unwrap();
        protection
    }

    async fn selection_fixture(
        owner: &Cx,
    ) -> (
        Cx,
        Arc<crate::time::VirtualClock>,
        crate::time::TimerDriverHandle,
        ManagedQuicEndpoint,
        std::net::UdpSocket,
        ConnectionId,
    ) {
        use crate::net::quic_native::PacketNumberSpace;
        use crate::time::{TimerDriverHandle, VirtualClock};
        let clock = Arc::new(VirtualClock::starting_at(crate::Time::from_secs(37)));
        let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            crate::types::RegionId::new_for_test(0, 1),
            crate::types::TaskId::new_for_test(0, 0),
            crate::types::Budget::INFINITE,
            None,
            owner.io_driver_handle(),
            None,
            Some(driver.clone()),
            None,
        );
        let protection = selection_packet_protection(&cx).await;
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut endpoint = ManagedQuicEndpoint::bind(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            ManagedEndpointConfig {
                packet_batch_size: 1,
                ..ManagedEndpointConfig::default()
            },
        )
        .await
        .unwrap();
        endpoint.timer_scheduler.now(&cx).unwrap();
        let cid = ConnectionId::new(&[7; 8]).unwrap();
        endpoint
            .create_connection_for_testing(&cx, cid, peer.local_addr().unwrap())
            .await
            .unwrap();
        endpoint
            .connection_router
            .install_packet_protection(&cx, cid, protection)
            .unwrap();
        // Only recovery state is planted. Selection, timer registration, packet
        // protection and UDP use production code; this is not a TLS/.76 proof.
        let connection = endpoint
            .connection_router
            .connection_mut_for_testing(&cx, cid)
            .unwrap();
        connection.begin_handshake(&cx).unwrap();
        connection.on_handshake_keys_available(&cx).unwrap();
        connection.on_1rtt_keys_available(&cx).unwrap();
        connection.record_verified_server_identity();
        connection.on_handshake_confirmed(&cx).unwrap();
        connection
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1_200,
                true,
                true,
                1_000,
            )
            .unwrap();
        endpoint
            .connection_router
            .refresh_connection_timer_for_testing(&cx, cid, 1_000)
            .unwrap();
        (cx, clock, driver, endpoint, peer, cid)
    }

    #[test]
    fn lifecycle_reaping_idle_endpoint_without_in_flight_packets_accepts_a_new_peer() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().unwrap();
            let mut endpoint = ManagedQuicEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                ManagedEndpointConfig {
                    max_connections: 1,
                    connection_idle_timeout_micros: 10_000_000,
                    ..ManagedEndpointConfig::default()
                },
            )
            .await
            .unwrap();
            let cid = ConnectionId::new(b"idle").unwrap();
            let replacement = ConnectionId::new(b"next").unwrap();
            let peer = "127.0.0.1:4450".parse().unwrap();
            endpoint
                .create_connection_for_testing(&cx, cid, peer)
                .await
                .unwrap();
            let deadline = endpoint
                .connection_router
                .next_timer_deadline()
                .expect("an idle route must have a deadline without any recovery flight");
            assert!(
                endpoint
                    .create_connection_for_testing(&cx, replacement, peer)
                    .await
                    .is_err()
            );
            endpoint.process_timer_events(&cx, deadline).await.unwrap();
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert!(endpoint.pending_outgoing.is_empty());
            endpoint
                .create_connection_for_testing(&cx, replacement, peer)
                .await
                .unwrap();
            assert_eq!(endpoint.connection_stats().active_connections, 1);
            endpoint.shutdown(&cx).await.unwrap();
        }));
    }

    fn witness_selection_io_wake(owner: &Cx, wake: &SelectionWake, before: usize) {
        let driver = owner.io_driver_handle().unwrap();
        for _ in 0..16 {
            driver.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap();
            if wake.0.load(Ordering::SeqCst) > before {
                return;
            }
        }
        panic!("managed selection: registered native read interest lost its UDP wake");
    }

    #[test]
    fn application_self_wake_services_ready_udp_and_protected_output() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, clock, driver, mut endpoint, peer, cid) = selection_fixture(&owner).await;
            let deadline = endpoint.connection_router.next_timer_deadline().unwrap();
            let advance = deadline.duration_since(endpoint.timer_scheduler.now(&cx).unwrap());
            clock.advance(u64::try_from(advance.as_nanos()).unwrap());
            endpoint.process_timer_events(&cx, deadline).await.unwrap();
            assert_eq!(
                endpoint.pending_outgoing.len(),
                1,
                "one real protected PTO packet"
            );
            let expected = endpoint
                .pending_outgoing
                .front()
                .unwrap()
                .packet
                .data
                .clone();
            let address = endpoint.local_addr();
            assert_eq!(peer.send_to(b"invalid QUIC", address).unwrap(), 12);
            let metrics = endpoint.udp_endpoint.metrics();
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed_calls = Arc::clone(&calls);
            let observed_metrics = Arc::clone(&metrics);
            let wake = Arc::new(SelectionWake::default());
            let waker = Waker::from(Arc::clone(&wake));
            let mut completed = false;
            {
                let mut run =
                    std::pin::pin!(endpoint.drive_event_loop(&cx, true, move |_, _, task_cx| {
                        observed_calls.fetch_add(1, Ordering::SeqCst);
                        if observed_metrics.packets_sent.load(Ordering::Relaxed) == 1
                            && observed_metrics.packets_received.load(Ordering::Relaxed) == 1
                        {
                            return Poll::Ready(Ok(()));
                        }
                        task_cx.waker().wake_by_ref();
                        Poll::Pending
                    }));
                for _ in 0..16 {
                    match run.as_mut().poll(&mut Context::from_waker(&waker)) {
                        Poll::Ready(result) => {
                            assert_eq!(result, Ok(Some(())));
                            completed = true;
                            break;
                        }
                        Poll::Pending => {
                            owner
                                .io_driver_handle()
                                .unwrap()
                                .turn_with(Some(Duration::ZERO), |_, _| {})
                                .unwrap();
                        }
                    }
                }
            }
            assert!(
                completed,
                "self-waking application must permit both I/O directions"
            );
            assert!(calls.load(Ordering::SeqCst) >= 3);
            assert!(endpoint.pending_outgoing.is_empty());
            let mut bytes = [0_u8; 1_200];
            let (length, from) = peer.recv_from(&mut bytes).unwrap();
            assert_eq!(from, address);
            assert_eq!(&bytes[..length], expected.as_slice());
            let crate::net::quic_core::ProtectedHeaderPrefix::Short { dst_cid, .. } =
                crate::net::quic_core::ProtectedHeaderPrefix::decode(&bytes[..length], cid.len())
                    .unwrap()
            else {
                panic!("actual output must carry a protected 1-RTT header");
            };
            assert_eq!(dst_cid, cid);
            let mut verifier = selection_packet_protection(&cx).await;
            let plaintext = crate::net::quic_native::connection_manager::unprotect_1rtt_packet(
                &cx,
                cid,
                &mut verifier,
                &bytes[..length],
            )
            .await
            .unwrap()
            .plaintext;
            assert!(
                crate::net::quic_native::NativeQuicConnection::decode_frames(&plaintext)
                    .unwrap()
                    .iter()
                    .any(|frame| matches!(
                        frame,
                        crate::net::atp::protocol::quic_frames::QuicFrame::Ping
                    ))
            );
            endpoint.shutdown(&cx).await.unwrap();
            assert_eq!(driver.pending_count(), 0);
        }));
    }

    #[test]
    fn application_proxy_detaches_parent_and_does_not_poll_on_waker_replacement() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, _, driver, mut endpoint, _, _) = selection_fixture(&owner).await;
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let retained = Arc::new(std::sync::Mutex::new(None::<Waker>));
            let observed_calls = Arc::clone(&calls);
            let observed_retained = Arc::clone(&retained);
            let old = Arc::new(SelectionWake::default());
            let new = Arc::new(SelectionWake::default());
            let old_waker = Waker::from(Arc::clone(&old));
            let new_waker = Waker::from(Arc::clone(&new));
            {
                let mut run =
                    std::pin::pin!(endpoint.drive_event_loop(&cx, true, move |_, _, task_cx| {
                        observed_calls.fetch_add(1, Ordering::SeqCst);
                        *observed_retained.lock().unwrap() = Some(task_cx.waker().clone());
                        Poll::<Result<(), ManagedEndpointError>>::Pending
                    }));
                assert!(
                    run.as_mut()
                        .poll(&mut Context::from_waker(&old_waker))
                        .is_pending()
                );
                assert!(
                    run.as_mut()
                        .poll(&mut Context::from_waker(&old_waker))
                        .is_pending()
                );
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert!(
                    run.as_mut()
                        .poll(&mut Context::from_waker(&new_waker))
                        .is_pending()
                );
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    1,
                    "changing parent is not application readiness"
                );
                let before_old = old.0.load(Ordering::SeqCst);
                let before_new = new.0.load(Ordering::SeqCst);
                retained.lock().unwrap().as_ref().unwrap().wake_by_ref();
                assert_eq!(old.0.load(Ordering::SeqCst), before_old);
                assert_eq!(new.0.load(Ordering::SeqCst), before_new + 1);
                assert!(
                    run.as_mut()
                        .poll(&mut Context::from_waker(&new_waker))
                        .is_pending()
                );
                assert_eq!(calls.load(Ordering::SeqCst), 2);
            }
            let before_old = old.0.load(Ordering::SeqCst);
            let before_new = new.0.load(Ordering::SeqCst);
            retained.lock().unwrap().as_ref().unwrap().wake_by_ref();
            assert_eq!(old.0.load(Ordering::SeqCst), before_old);
            assert_eq!(
                new.0.load(Ordering::SeqCst),
                before_new,
                "dropped driver's proxy is detached"
            );
            // Isolate the registration's owned parent reference from independent
            // socket/timer registrations to prove that reference is released.
            let parent = Arc::new(SelectionWake::default());
            let parent_waker = Waker::from(Arc::clone(&parent));
            let proxy = Arc::new(ManagedApplicationWake {
                ready: AtomicBool::new(false),
                parent: std::sync::Mutex::new(None),
            });
            let baseline = Arc::strong_count(&parent);
            {
                let _registration = ManagedApplicationRegistration(Some(Arc::clone(&proxy)));
                proxy.register_parent(&parent_waker);
                assert_eq!(Arc::strong_count(&parent), baseline + 1);
            }
            assert_eq!(Arc::strong_count(&parent), baseline);
            proxy.wake_by_ref();
            assert_eq!(parent.0.load(Ordering::SeqCst), 0);
            endpoint.shutdown(&cx).await.unwrap();
            assert_eq!(driver.pending_count(), 0);
        }));
    }

    #[test]
    fn received_batch_keeps_early_epoch_and_stamps_fresh_input_once_before_cancel() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, clock, _, mut endpoint, peer, _) = selection_fixture(&owner).await;
            let original = endpoint.timer_scheduler.now(&cx).unwrap();
            let early_time = original.checked_sub(Duration::from_millis(1)).unwrap();
            endpoint.authenticated_only = true;
            endpoint.pending_incoming.push_back(ManagedIncomingPacket {
                packet: ReceivedPacket {
                    src_addr: peer.local_addr().unwrap(),
                    data: b"retained early input".to_vec(),
                    receive_time: early_time,
                    transmit_time: None,
                },
                needs_clock_stamp: false,
            });
            assert_eq!(
                peer.send_to(b"fresh kernel input", endpoint.local_addr())
                    .unwrap(),
                18
            );
            let packets = endpoint.udp_endpoint.receive_batch(&cx, 1).await.unwrap();
            assert_eq!(packets.len(), 1);
            let wall_received = packets[0].receive_time;
            clock.advance(10_000_000_000);
            let mapped = endpoint.timer_scheduler.now(&cx).unwrap();
            assert_eq!(mapped.duration_since(original), Duration::from_secs(10));
            assert!(mapped.duration_since(wall_received) >= Duration::from_secs(9));
            cx.cancel_with(crate::types::CancelKind::User, None);
            assert_eq!(
                endpoint.process_packet_batch(&cx, packets).await,
                Err(ManagedEndpointError::Cancelled)
            );
            assert_eq!(endpoint.pending_incoming.len(), 2);
            assert_eq!(endpoint.pending_incoming[0].packet.receive_time, early_time);
            assert_eq!(endpoint.pending_incoming[1].packet.receive_time, mapped);
            assert_eq!(
                endpoint.pending_incoming[1].packet.data,
                b"fresh kernel input"
            );
            clock.advance(20_000_000_000);
            assert_eq!(
                endpoint.process_packet_batch(&cx, Vec::new()).await,
                Err(ManagedEndpointError::Cancelled)
            );
            assert_eq!(endpoint.pending_incoming[0].packet.receive_time, early_time);
            assert_eq!(endpoint.pending_incoming[1].packet.receive_time, mapped);
            assert!(
                endpoint
                    .pending_incoming
                    .iter()
                    .all(|packet| !packet.needs_clock_stamp)
            );
            assert_eq!(
                endpoint.shutdown(&cx).await,
                Err(ManagedEndpointError::Cancelled)
            );
            assert!(endpoint.pending_incoming.is_empty());
        }));
    }

    #[test]
    fn simultaneous_ready_io_and_due_timer_cancel_before_consuming_owned_suffix() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let io_driver = owner.io_driver_handle().unwrap();
            let registrations = io_driver.waker_count();
            let (cx, clock, driver, mut endpoint, peer, _) = selection_fixture(&owner).await;
            let deadline = endpoint.connection_router.next_timer_deadline().unwrap();
            let advance = u64::try_from(
                deadline
                    .duration_since(endpoint.timer_scheduler.now(&cx).unwrap())
                    .as_nanos(),
            )
            .unwrap();
            assert!(advance > 0);
            let metrics = endpoint.udp_endpoint.metrics();
            let wake = Arc::new(SelectionWake::default());
            let waker = std::task::Waker::from(wake.clone());
            let endpoint_addr = endpoint.local_addr();
            {
                let mut run = std::pin::pin!(endpoint.run_event_loop(&cx));
                assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                assert_eq!(wake.0.load(Ordering::SeqCst), 0, "idle loop must genuinely park");
                assert_eq!(driver.pending_count(), 1);
                assert_eq!(io_driver.waker_count(), registrations + 1);
                let before = wake.0.load(Ordering::SeqCst);
                assert_eq!(peer.send_to(b"invalid QUIC", endpoint_addr).unwrap(), 12);
                witness_selection_io_wake(&owner, &wake, before);
                // Do not repoll before observing the real wake. Drop this parked
                // future solely to seed output through the retained endpoint.
            }
            assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 0);
            assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 0);
            assert_eq!(endpoint.timer_scheduler.current_deadline(), Some(deadline));
            let queue_cid = ConnectionId::new(&[9; 8]).unwrap();
            for index in 0..3u8 {
                endpoint.queue_connection_packets(
                    queue_cid,
                    [OutgoingPacket {
                        dst_addr: peer.local_addr().unwrap(),
                        data: vec![index],
                        send_time: None,
                    }],
                );
            }
            {
                let mut run = std::pin::pin!(endpoint.run_event_loop(&cx));
                // Restart the same owner; one writable packet commits before
                // yield, leaving an exact suffix and unread input ready.
                assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 1);
                assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 0);
                let before_timer = wake.0.load(Ordering::SeqCst);
                clock.advance(advance);
                assert_eq!(driver.process_timers(), 1);
                assert!(wake.0.load(Ordering::SeqCst) > before_timer, "due timer must wake the retained loop");
                let before_cancel = wake.0.load(Ordering::SeqCst);
                cx.cancel_with(crate::types::CancelKind::User, None);
                assert!(wake.0.load(Ordering::SeqCst) > before_cancel, "cancellation must wake its current registered waiter");
                assert_eq!(
                    run.as_mut().poll(&mut std::task::Context::from_waker(&waker)),
                    Poll::Ready(Err(ManagedEndpointError::Cancelled))
                );
            }
            assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 1);
            assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 0);
            assert_eq!(endpoint.pending_outgoing.len(), 2);
            for (packet, index) in endpoint.pending_outgoing.iter().zip(1..3u8) {
                assert_eq!(packet.connection_id, queue_cid);
                assert_eq!(packet.packet.data, vec![index]);
                assert_eq!(packet.packet.dst_addr, peer.local_addr().unwrap());
            }
            assert_eq!(driver.pending_count(), 0);
            assert!(!endpoint.timer_scheduler.has_pending_timer());
            let mut bytes = [0u8; 1_200];
            assert_eq!(peer.recv_from(&mut bytes).unwrap(), (1, endpoint_addr));
            assert_eq!(bytes[0], 0);
            assert_eq!(peer.recv_from(&mut bytes).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            assert_eq!(endpoint.shutdown(&cx).await, Err(ManagedEndpointError::Cancelled));
            assert!(endpoint.pending_outgoing.is_empty());
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert_eq!(driver.pending_count(), 0);
            assert_eq!(io_driver.waker_count(), registrations);
            println!("managed_selection_cancel bead=asupersync-bi2462.75 fixture=virtual37_native_udp parked_read_wake=true timer_firings=1 sent_prefix=1 retained_suffix=2 received_before_cancel=0 registrations_after_cleanup={registrations} outcome=cancelled");
        }));
    }

    #[test]
    fn continuous_ready_ingress_cannot_starve_due_protected_pto_output() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let io_driver = owner.io_driver_handle().unwrap();
            let registrations = io_driver.waker_count();
            let (cx, clock, driver, mut endpoint, peer, cid) = selection_fixture(&owner).await;
            let mut verifier = selection_packet_protection(&owner).await;
            let endpoint_addr = endpoint.local_addr();
            let deadline = endpoint.connection_router.next_timer_deadline().unwrap();
            let advance = u64::try_from(
                deadline
                    .duration_since(endpoint.timer_scheduler.now(&cx).unwrap())
                    .as_nanos(),
            )
            .unwrap();
            assert!(advance > 0);
            let metrics = endpoint.udp_endpoint.metrics();
            let wake = Arc::new(SelectionWake::default());
            let waker = std::task::Waker::from(wake.clone());
            {
                let mut run = std::pin::pin!(endpoint.run_event_loop(&cx));
                assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                assert_eq!(wake.0.load(Ordering::SeqCst), 0, "idle loop must genuinely park");
                assert_eq!(driver.pending_count(), 1);
                assert_eq!(io_driver.waker_count(), registrations + 1);
                let mut before = wake.0.load(Ordering::SeqCst);
                for _ in 0..32 {
                    assert_eq!(peer.send_to(b"invalid QUIC", endpoint_addr).unwrap(), 12);
                }
                witness_selection_io_wake(&owner, &wake, before);
                // Four real read batches precede the deadline. Every later
                // turn still has queued input: at most eight of 32 are read.
                for received in 1..=4 {
                    assert!(wake.0.load(Ordering::SeqCst) > before, "ready ingress/cooperative turn must wake before repoll");
                    before = wake.0.load(Ordering::SeqCst);
                    assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                    assert_eq!(metrics.packets_received.load(Ordering::Relaxed), received);
                    assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 0);
                }
                let before_timer = wake.0.load(Ordering::SeqCst);
                clock.advance(advance);
                assert_eq!(driver.process_timers(), 1);
                assert!(wake.0.load(Ordering::SeqCst) > before_timer, "actual timer registration must wake the loop");
                before = wake.0.load(Ordering::SeqCst);
                assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 4, "due PTO must beat already-readable input");
                assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 0);
                assert!(wake.0.load(Ordering::SeqCst) > before);
                before = wake.0.load(Ordering::SeqCst);
                assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 1, "PTO output must reach actual UDP while ingress remains ready");
                assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 4);
                for received in 5..=8 {
                    assert!(wake.0.load(Ordering::SeqCst) > before);
                    before = wake.0.load(Ordering::SeqCst);
                    assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                    assert_eq!(metrics.packets_received.load(Ordering::Relaxed), received);
                    assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 1);
                }
                let before_cancel = wake.0.load(Ordering::SeqCst);
                cx.cancel_with(crate::types::CancelKind::User, None);
                assert!(wake.0.load(Ordering::SeqCst) > before_cancel);
                assert_eq!(
                    run.as_mut().poll(&mut std::task::Context::from_waker(&waker)),
                    Poll::Ready(Err(ManagedEndpointError::Cancelled))
                );
            }
            assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 8);
            assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 1);
            assert!(endpoint.pending_outgoing.is_empty());
            assert!(endpoint.connection_router.next_timer_deadline().unwrap() > deadline);
            assert_eq!(driver.now(), crate::Time::from_nanos(37_000_000_000 + advance));
            assert_eq!(driver.pending_count(), 0);
            let mut bytes = [0u8; 1_200];
            let (length, source) = peer.recv_from(&mut bytes).unwrap();
            assert_eq!(source, endpoint_addr);
            let crate::net::quic_core::ProtectedHeaderPrefix::Short { dst_cid, .. } =
                crate::net::quic_core::ProtectedHeaderPrefix::decode(&bytes[..length], 8).unwrap()
            else {
                panic!("due managed PTO must emit an actual protected short packet")
            };
            assert_eq!(dst_cid, cid);
            let unprotected = crate::net::quic_native::connection_manager::unprotect_1rtt_packet(
                &owner,
                cid,
                &mut verifier,
                &bytes[..length],
            )
            .await
            .unwrap();
            assert_eq!(unprotected.header.dst_cid, cid);
            assert_eq!(unprotected.header.packet_number, 1);
            let plaintext = unprotected.plaintext;
            let mut expected = crate::bytes::BytesMut::new();
            crate::net::atp::protocol::quic_frames::QuicFrame::Ping.encode(&mut expected).unwrap();
            assert_eq!(plaintext, expected.as_ref());
            assert_eq!(peer.recv_from(&mut bytes).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            assert_eq!(endpoint.shutdown(&cx).await, Err(ManagedEndpointError::Cancelled));
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert_eq!(io_driver.waker_count(), registrations);
            assert_eq!(driver.pending_count(), 0);
            println!("managed_selection_pto bead=asupersync-bi2462.75 fixture=virtual37_native_udp input_sent=32 input_before_due=4 input_after_probe=8 protected_ping_packets=1 protected_bytes={length} timer_firings=1 virtual_advance_ns={advance} registrations_after_cleanup={registrations} outcome=pass no_authenticated_handshake_claim=true");
        }));
    }

    #[test]
    fn native_idle_loop_parks_and_acknowledges_cancellation_without_packets() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native worker context");
            let parked = Arc::new(AtomicBool::new(false));
            let parked_child = parked.clone();
            let mut child = cx
                .spawn(move |child_cx| async move {
                    let mut endpoint = ManagedQuicEndpoint::bind(
                        &child_cx,
                        "127.0.0.1:0".parse().unwrap(),
                        ManagedEndpointConfig::default(),
                    )
                    .await
                    .unwrap();
                    let result = {
                        let mut run = std::pin::pin!(endpoint.run_event_loop(&child_cx));
                        poll_fn(|task_cx| {
                            let poll = run.as_mut().poll(task_cx);
                            if poll.is_pending() {
                                parked_child.store(true, Ordering::SeqCst);
                            }
                            poll
                        })
                        .await
                    };
                    assert_eq!(
                        endpoint
                            .udp_endpoint
                            .metrics()
                            .packets_received
                            .load(Ordering::Relaxed),
                        0
                    );
                    assert!(!endpoint.timer_scheduler.has_pending_timer());
                    assert!(endpoint.pending_outgoing.is_empty());
                    result
                })
                .unwrap();
            for _ in 0..512 {
                if parked.load(Ordering::SeqCst) {
                    break;
                }
                crate::runtime::yield_now().await;
            }
            assert!(
                parked.load(Ordering::SeqCst),
                "native UDP receive must park before cancellation"
            );
            child.abort();
            let result = crate::time::timeout(cx.now(), Duration::from_secs(5), child.join(&cx))
                .await
                .unwrap();
            assert_eq!(result.unwrap(), Err(ManagedEndpointError::Cancelled));
        }));
    }

    #[test]
    fn native_loop_sends_healthy_peer_after_bad_destination_and_receives_during_load() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native worker context");
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_nonblocking(true).unwrap();
            let peer_addr = peer.local_addr().unwrap();
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
            let mut child = cx
                .spawn(move |child_cx| async move {
                    let config = ManagedEndpointConfig {
                        packet_batch_size: 4,
                        ..ManagedEndpointConfig::default()
                    };
                    let mut endpoint = ManagedQuicEndpoint::bind(
                        &child_cx,
                        "127.0.0.1:0".parse().unwrap(),
                        config,
                    )
                    .await
                    .unwrap();
                    endpoint.queue_connection_packets(
                        ConnectionId::default(),
                        [OutgoingPacket {
                            dst_addr: "127.0.0.1:0".parse().unwrap(),
                            data: vec![0xff],
                            send_time: None,
                        }],
                    );
                    for index in 0..65u8 {
                        endpoint.queue_connection_packets(
                            ConnectionId::default(),
                            [OutgoingPacket {
                                dst_addr: peer_addr,
                                data: vec![index],
                                send_time: None,
                            }],
                        );
                    }
                    let metrics = endpoint.udp_endpoint.metrics();
                    ready_tx.send((endpoint.local_addr(), metrics)).unwrap();
                    let result = endpoint.run_event_loop(&child_cx).await;
                    assert!(
                        endpoint.pending_outgoing.is_empty(),
                        "all permitted output must reach the socket before cancellation"
                    );
                    result
                })
                .unwrap();
            let mut ready = None;
            for _ in 0..512 {
                if let Ok(value) = ready_rx.try_recv() {
                    ready = Some(value);
                    break;
                }
                crate::runtime::yield_now().await;
            }
            let (endpoint_addr, metrics) = ready.expect("endpoint started on native worker");
            let mut observed = Vec::new();
            let mut ingress_with_multiple_output_batches_pending = false;
            let mut buffer = [0u8; 16];
            for _ in 0..2048 {
                // Keep ingress readable while checking both egress and scheduler progress.
                for _ in 0..8 {
                    peer.send_to(b"invalid QUIC", endpoint_addr).unwrap();
                }
                loop {
                    match peer.recv_from(&mut buffer) {
                        Ok((length, source)) => {
                            assert_eq!(source, endpoint_addr);
                            assert_eq!(length, 1);
                            observed.push(buffer[0]);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("native receive failed: {error}"),
                    }
                }
                ingress_with_multiple_output_batches_pending |=
                    metrics.packets_received.load(Ordering::Relaxed) > 0
                        && metrics.packets_sent.load(Ordering::Relaxed) <= 60;
                if observed.len() == 65 && metrics.packets_received.load(Ordering::Relaxed) > 0 {
                    break;
                }
                crate::runtime::yield_now().await;
            }
            assert_eq!(observed, (0..65u8).collect::<Vec<_>>());
            assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 65);
            assert!(
                metrics.send_errors.load(Ordering::Relaxed) > 0,
                "planted destination failure was reached"
            );
            assert!(metrics.packets_received.load(Ordering::Relaxed) > 0);
            assert!(
                ingress_with_multiple_output_batches_pending,
                "receives must progress before the output queue falls below one batch"
            );
            child.abort();
            let result = crate::time::timeout(cx.now(), Duration::from_secs(5), child.join(&cx))
                .await
                .unwrap();
            assert_eq!(result.unwrap(), Err(ManagedEndpointError::Cancelled));
        }));
    }

    #[test]
    fn handoff_after_dropped_loop_retires_only_that_connections_unsent_packets() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native worker context");
            for take_next in [false, true] {
                let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                peer.set_nonblocking(true).unwrap();
                let peer_addr = peer.local_addr().unwrap();
                let mut endpoint = ManagedQuicEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    ManagedEndpointConfig::default(),
                )
                .await
                .unwrap();
                let ids = [
                    ConnectionId::new(&[1]).unwrap(),
                    ConnectionId::new(&[2]).unwrap(),
                ];
                for (index, id) in ids.into_iter().enumerate() {
                    endpoint
                        .create_connection_for_testing(&cx, id, peer_addr)
                        .await
                        .unwrap();
                    endpoint.queue_connection_packets(
                        id,
                        [OutgoingPacket {
                            dst_addr: peer_addr,
                            data: vec![u8::try_from(index).unwrap()],
                            send_time: None,
                        }],
                    );
                }
                // Force a real receive turn followed by a cooperative yield while
                // both packets are still locally owned, then drop the loop future.
                endpoint.prefer_send = false;
                peer.send_to(b"invalid QUIC", endpoint.local_addr())
                    .unwrap();
                {
                    let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
                    let mut drive = std::pin::pin!(endpoint.run_event_loop(&cx));
                    assert!(drive.as_mut().poll(&mut task_cx).is_pending());
                }
                assert_eq!(endpoint.pending_outgoing.len(), 2);
                assert_eq!(
                    endpoint
                        .udp_endpoint
                        .metrics()
                        .packets_received
                        .load(Ordering::Relaxed),
                    1
                );
                assert_eq!(
                    endpoint
                        .udp_endpoint
                        .metrics()
                        .packets_sent
                        .load(Ordering::Relaxed),
                    0
                );
                let accepted = if take_next {
                    endpoint.take_next_connection(&cx).unwrap().unwrap()
                } else {
                    endpoint.take_connection(&cx, ids[0]).unwrap()
                };
                assert_eq!(accepted.connection_id, ids[0]);
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                assert_eq!(endpoint.pending_outgoing[0].connection_id, ids[1]);
                {
                    let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
                    let mut drive = std::pin::pin!(endpoint.run_event_loop(&cx));
                    assert!(drive.as_mut().poll(&mut task_cx).is_pending());
                }
                assert!(endpoint.pending_outgoing.is_empty());
                let mut buffer = [0u8; 16];
                let (length, source) = peer.recv_from(&mut buffer).unwrap();
                assert_eq!(source, endpoint.local_addr());
                assert_eq!(&buffer[..length], &[1]);
                assert_eq!(
                    peer.recv_from(&mut buffer).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                endpoint.shutdown(&cx).await.unwrap();
            }
        }));
    }

    #[test]
    fn restart_sends_retained_timer_prefix_before_another_deadline() {
        use crate::net::atp::quic::AtpPacketProtection;
        use crate::net::quic_native::{
            PacketNumberSpace, PacketProtectionSpace, QuicHandshakeTranscript,
        };
        use crate::time::{TimerDriverHandle, VirtualClock};
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let clock = Arc::new(VirtualClock::starting_at(crate::Time::from_secs(37)));
            let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
            let cx = Cx::new_with_drivers(
                crate::types::RegionId::new_for_test(0, 1),
                crate::types::TaskId::new_for_test(0, 0),
                crate::types::Budget::INFINITE,
                None,
                owner.io_driver_handle(),
                None,
                Some(driver.clone()),
                None,
            );
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_nonblocking(true).unwrap();
            let peer_addr = peer.local_addr().unwrap();
            let mut endpoint = ManagedQuicEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                ManagedEndpointConfig {
                    packet_batch_size: 4,
                    ..ManagedEndpointConfig::default()
                },
            )
            .await
            .unwrap();
            endpoint.timer_scheduler.now(&cx).unwrap();
            // Recovery fixture only: real frame protection and real UDP, with
            // explicit test keys/state rather than a claimed TLS handshake.
            for index in 0..33u64 {
                let cid = ConnectionId::new(&index.to_be_bytes()).unwrap();
                endpoint
                    .create_connection_for_testing(&cx, cid, peer_addr)
                    .await
                    .unwrap();
                if index == 32 {
                    continue;
                } // Idle tail: no overdue timer on restart.
                let mut transcript = QuicHandshakeTranscript::new();
                transcript.record("client_initial", b"retained timer client");
                transcript.record("server_handshake", b"retained timer server");
                let mut protection = AtpPacketProtection::new_client(true).unwrap();
                protection
                    .derive_keys(
                        &cx,
                        PacketProtectionSpace::OneRtt,
                        &transcript,
                        b"retained timer unit fixture",
                    )
                    .await
                    .unwrap();
                endpoint
                    .connection_router
                    .install_packet_protection(&cx, cid, protection)
                    .unwrap();
                let connection = endpoint
                    .connection_router
                    .connection_mut_for_testing(&cx, cid)
                    .unwrap();
                connection.begin_handshake(&cx).unwrap();
                connection.on_handshake_keys_available(&cx).unwrap();
                connection.on_1rtt_keys_available(&cx).unwrap();
                connection.record_verified_server_identity();
                connection.on_handshake_confirmed(&cx).unwrap();
                connection
                    .on_packet_sent(
                        &cx,
                        PacketNumberSpace::ApplicationData,
                        1_200,
                        true,
                        true,
                        1_000,
                    )
                    .unwrap();
                endpoint
                    .connection_router
                    .refresh_connection_timer_for_testing(&cx, cid, 1_000)
                    .unwrap();
            }
            let deadline = endpoint.connection_router.next_timer_deadline().unwrap();
            endpoint.refresh_timer(&cx).await.unwrap();
            assert!(
                endpoint
                    .timer_scheduler
                    .poll_timer(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                    .is_pending()
            );
            clock.advance(
                u64::try_from(
                    deadline
                        .duration_since(endpoint.timer_scheduler.now(&cx).unwrap())
                        .as_nanos(),
                )
                .unwrap(),
            );
            assert_eq!(driver.process_timers(), 1);
            assert_eq!(
                endpoint
                    .timer_scheduler
                    .poll_timer(&mut std::task::Context::from_waker(std::task::Waker::noop())),
                Poll::Ready(Some(deadline))
            );
            {
                // This is the same timer branch awaited by the main loop. Drop
                // it at the cooperative yield with its committed prefix retained.
                let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
                let mut timer_turn = std::pin::pin!(endpoint.process_timer_events(&cx, deadline));
                assert!(timer_turn.as_mut().poll(&mut task_cx).is_pending());
            }
            assert!(endpoint.pending_outgoing.is_empty());
            let next = endpoint.connection_router.next_timer_deadline().unwrap();
            assert!(next > endpoint.timer_scheduler.now(&cx).unwrap());
            let metrics = endpoint.udp_endpoint.metrics();
            {
                let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
                let mut restarted = std::pin::pin!(endpoint.run_event_loop(&cx));
                for _ in 0..64 {
                    assert!(restarted.as_mut().poll(&mut task_cx).is_pending());
                    if metrics.packets_sent.load(Ordering::Relaxed) == 32 {
                        break;
                    }
                }
            }
            assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 32);
            assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 0);
            assert!(
                next > endpoint.timer_scheduler.now(&cx).unwrap(),
                "no second PTO was needed"
            );
            let mut observed = std::collections::HashSet::new();
            let mut payload = [0u8; 1_200];
            for _ in 0..32 {
                let (length, source) = peer.recv_from(&mut payload).unwrap();
                assert_eq!(source, endpoint.local_addr());
                let crate::net::quic_core::ProtectedHeaderPrefix::Short { dst_cid, .. } =
                    crate::net::quic_core::ProtectedHeaderPrefix::decode(&payload[..length], 8)
                        .unwrap()
                else {
                    panic!("actual protected short packet expected")
                };
                assert!(observed.insert(dst_cid));
                // The packet number is header-protected; unmask it with the
                // same deterministic fixture keys every connection installed.
                let mut transcript = QuicHandshakeTranscript::new();
                transcript.record("client_initial", b"retained timer client");
                transcript.record("server_handshake", b"retained timer server");
                let mut verifier = AtpPacketProtection::new_client(true).unwrap();
                verifier
                    .derive_keys(
                        &cx,
                        PacketProtectionSpace::OneRtt,
                        &transcript,
                        b"retained timer unit fixture",
                    )
                    .await
                    .unwrap();
                let unprotected =
                    crate::net::quic_native::connection_manager::unprotect_1rtt_packet(
                        &cx,
                        dst_cid,
                        &mut verifier,
                        &payload[..length],
                    )
                    .await
                    .unwrap();
                assert_eq!(unprotected.header.packet_number, 1);
            }
            assert_eq!(observed.len(), 32);
            assert_eq!(
                peer.recv_from(&mut payload).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            endpoint.shutdown(&cx).await.unwrap();
            assert_eq!(driver.pending_count(), 0);
        }));
    }

    #[test]
    fn shutdown_uses_supplied_context_when_ambient_context_is_cancelled() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, _, driver, mut endpoint, peer, _) = selection_fixture(&owner).await;
            let ambient = Cx::new(
                crate::types::RegionId::new_for_test(0, 2),
                crate::types::TaskId::new_for_test(0, 1),
                crate::types::Budget::INFINITE,
            );
            ambient.cancel_with(crate::types::CancelKind::User, None);
            let mut shutdown = Box::pin(endpoint.shutdown(&cx));
            let result = {
                let _current = Cx::set_current(Some(ambient));
                shutdown
                    .as_mut()
                    .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
            };
            assert!(matches!(result, Poll::Ready(Ok(()))));
            drop(shutdown);
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert_eq!(driver.pending_count(), 0);
            assert!(peer.recv_from(&mut [0_u8; 1_200]).unwrap().0 > 0);
        }));
    }

    #[test]
    fn shutdown_cleanup_retires_ownership_when_parked_future_is_dropped() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, _, driver, mut endpoint, peer, cid) = selection_fixture(&owner).await;
            let deadline = endpoint.timer_scheduler.now(&cx).unwrap() + Duration::from_secs(60);
            endpoint
                .timer_scheduler
                .schedule_timer(&cx, deadline)
                .await
                .unwrap();
            let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
            {
                let _current = Cx::set_current(Some(cx.clone()));
                assert!(
                    endpoint
                        .timer_scheduler
                        .poll_timer(&mut task_cx)
                        .is_pending()
                );
            }
            assert!(driver.pending_count() > 0);
            endpoint.queue_connection_packets(
                cid,
                [OutgoingPacket {
                    dst_addr: peer.local_addr().unwrap(),
                    data: vec![1],
                    send_time: None,
                }],
            );
            // Exercise the ownership guard at a deterministic suspension point;
            // this does not claim to force kernel UDP backpressure.
            let mut parked = Box::pin(async {
                let cleanup = ManagedShutdownCleanup(&mut endpoint);
                std::future::pending::<()>().await;
                drop(cleanup);
            });
            assert!(parked.as_mut().poll(&mut task_cx).is_pending());
            drop(parked);
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert!(endpoint.pending_outgoing.is_empty());
            assert!(endpoint.pending_incoming.is_empty());
            assert!(!endpoint.timer_scheduler.has_pending_timer());
            assert_eq!(driver.pending_count(), 0);
        }));
    }

    #[test]
    fn shutdown_sends_only_protected_close_and_releases_ownership() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, _, driver, mut endpoint, peer, cid) = selection_fixture(&owner).await;
            let address = endpoint.local_addr();
            endpoint
                .create_connection_for_testing(
                    &cx,
                    ConnectionId::new(b"idle").unwrap(),
                    peer.local_addr().unwrap(),
                )
                .await
                .unwrap();
            endpoint.queue_connection_packets(
                cid,
                [OutgoingPacket {
                    dst_addr: peer.local_addr().unwrap(),
                    data: b"stale application output".to_vec(),
                    send_time: None,
                }],
            );
            endpoint.shutdown(&cx).await.unwrap();
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert!(endpoint.pending_outgoing.is_empty());
            assert_eq!(driver.pending_count(), 0);
            let mut bytes = [0_u8; 1_200];
            let (length, from) = peer.recv_from(&mut bytes).unwrap();
            assert_eq!(from, address);
            let mut verifier = selection_packet_protection(&cx).await;
            let plaintext = crate::net::quic_native::connection_manager::unprotect_1rtt_packet(
                &cx,
                cid,
                &mut verifier,
                &bytes[..length],
            )
            .await
            .unwrap()
            .plaintext;
            let frames =
                crate::net::quic_native::NativeQuicConnection::decode_frames(&plaintext).unwrap();
            assert!(matches!(frames.as_slice(), [
                crate::net::atp::protocol::quic_frames::QuicFrame::ConnectionClose {
                    error_code, frame_type: None, reason_phrase,
                }
            ] if error_code.value() == 0 && reason_phrase.is_empty()));
            endpoint.shutdown(&cx).await.unwrap();
            assert_eq!(
                peer.recv_from(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }));
    }

    #[test]
    fn shutdown_send_failure_still_retires_connections_and_timer() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, _, driver, mut endpoint, peer, _) = selection_fixture(&owner).await;
            endpoint.udp_endpoint = QuicUdpEndpoint::bind(
                &cx, "127.0.0.1:0".parse().unwrap(), QuicUdpEndpointConfig {
                    max_packet_size: 1,
                    ..QuicUdpEndpointConfig::default()
                },
            ).await.unwrap();
            assert!(matches!(endpoint.shutdown(&cx).await,
                Err(ManagedEndpointError::UdpEndpoint(message)) if message.contains("exceeds endpoint limit")));
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert!(!endpoint.timer_scheduler.has_pending_timer());
            assert_eq!(driver.pending_count(), 0);
            let mut bytes = [0_u8; 1_200];
            assert_eq!(peer.recv_from(&mut bytes).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        }));
    }

    #[test]
    fn shutdown_is_silent_after_peer_close_or_cancellation() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            for cancelled in [false, true] {
                let (cx, _, driver, mut endpoint, peer, cid) = selection_fixture(&owner).await;
                if cancelled {
                    cx.cancel_with(crate::types::CancelKind::User, None);
                } else {
                    endpoint
                        .connection_router
                        .connection_mut_for_testing(&cx, cid)
                        .unwrap()
                        .process_frame(
                            &cx,
                            &crate::net::atp::protocol::quic_frames::QuicFrame::ConnectionClose {
                                error_code: crate::net::atp::protocol::varint::VarInt::new(42)
                                    .unwrap(),
                                frame_type: None,
                                reason_phrase: crate::bytes::Bytes::new(),
                            },
                            crate::net::quic_native::PacketNumberSpace::ApplicationData,
                        )
                        .unwrap();
                }
                let result = endpoint.shutdown(&cx).await;
                if cancelled {
                    assert_eq!(result, Err(ManagedEndpointError::Cancelled));
                } else {
                    result.unwrap();
                }
                assert_eq!(endpoint.connection_stats().active_connections, 0);
                assert_eq!(driver.pending_count(), 0);
                let mut bytes = [0_u8; 1_200];
                assert_eq!(
                    peer.recv_from(&mut bytes).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
        }));
    }

    #[test]
    fn cancelled_shutdown_retires_queued_work_and_obsolete_timer_on_retained_endpoint() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native worker context");
            let mut endpoint = ManagedQuicEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                ManagedEndpointConfig::default(),
            )
            .await
            .unwrap();
            let deadline = endpoint.timer_scheduler.now(&cx).unwrap() + Duration::from_secs(60);
            endpoint
                .timer_scheduler
                .schedule_timer(&cx, deadline)
                .await
                .unwrap();
            assert!(
                endpoint
                    .timer_scheduler
                    .poll_timer(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                    .is_pending()
            );
            let driver = cx.timer_driver().unwrap();
            let armed = driver.pending_count();
            assert!(armed > 0);
            endpoint.refresh_timer(&cx).await.unwrap();
            assert_eq!(
                driver.pending_count(),
                armed - 1,
                "no connections means no timer"
            );
            endpoint.queue_connection_packets(
                ConnectionId::default(),
                [OutgoingPacket {
                    dst_addr: "127.0.0.1:9".parse().unwrap(),
                    data: vec![1],
                    send_time: None,
                }],
            );
            cx.cancel_with(crate::types::CancelKind::User, None);
            assert_eq!(
                endpoint.shutdown(&cx).await,
                Err(ManagedEndpointError::Cancelled)
            );
            assert!(endpoint.shutting_down);
            assert!(endpoint.pending_outgoing.is_empty());
            assert!(!endpoint.timer_scheduler.has_pending_timer());
            assert_eq!(endpoint.connection_stats().active_connections, 0);
        }));
    }

    #[test]
    fn test_managed_endpoint_bind() {
        run_test_with_cx(|cx| async move {
            let config = ManagedEndpointConfig::default();
            let endpoint = ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                .await
                .expect("bind should succeed");

            assert_ne!(endpoint.local_addr().port(), 0);
            assert_ne!(endpoint.endpoint_id(), 0);

            let stats = endpoint.connection_stats();
            assert_eq!(stats.active_connections, 0);
        });
    }

    #[test]
    fn test_managed_endpoint_config_validation() {
        run_test_with_cx(|cx| async move {
            // Test max_connections = 0
            let mut config = ManagedEndpointConfig::default();
            config.max_connections = 0;

            let result =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config).await;
            assert!(matches!(
                result,
                Err(ManagedEndpointError::InvalidConfig(_))
            ));

            // Test packet_batch_size = 0
            let mut config = ManagedEndpointConfig::default();
            config.packet_batch_size = 0;

            let result =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config).await;
            assert!(matches!(
                result,
                Err(ManagedEndpointError::InvalidConfig(_))
            ));
        });
    }

    #[test]
    fn test_endpoint_shutdown() {
        run_test_with_cx(|cx| async move {
            let config = ManagedEndpointConfig::default();
            let mut endpoint =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                    .await
                    .expect("bind should succeed");

            // Shutdown should complete without error
            endpoint
                .shutdown(&cx)
                .await
                .expect("shutdown should succeed");
            assert!(endpoint.shutting_down);
        });
    }

    #[test]
    fn test_managed_endpoint_take_connection_handoff() {
        run_test_with_cx(|cx| async move {
            let config = ManagedEndpointConfig::default();
            let mut endpoint =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                    .await
                    .expect("bind should succeed");
            let connection_id = ConnectionId::new(&[0x24, 0x00, 0x00, 0x01]).expect("cid");
            let peer_addr: SocketAddr = "127.0.0.1:5666".parse().unwrap();
            endpoint
                .connection_router
                .create_connection(&cx, connection_id, peer_addr, true)
                .await
                .expect("connection creation should succeed");

            let accepted = endpoint
                .take_connection(&cx, connection_id)
                .expect("endpoint should hand off connection");
            assert_eq!(accepted.connection_id, connection_id);
            assert_eq!(accepted.peer_addr, peer_addr);
            assert_eq!(endpoint.connection_stats().active_connections, 0);

            let err = endpoint
                .take_connection(&cx, connection_id)
                .expect_err("missing connection must fail closed");
            assert!(matches!(
                err,
                ManagedEndpointError::ConnectionRouter(
                    ConnectionRouterError::ConnectionNotFound(id)
                ) if id == connection_id
            ));
        });
    }

    #[test]
    fn test_managed_endpoint_take_next_connection_handoff_order() {
        run_test_with_cx(|cx| async move {
            let config = ManagedEndpointConfig::default();
            let mut endpoint =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                    .await
                    .expect("bind should succeed");
            let first = ConnectionId::new(&[0x01, 0x22, 0x00, 0x00]).expect("first cid");
            let second = ConnectionId::new(&[0x02, 0x22, 0x00, 0x00]).expect("second cid");
            let peer_addr: SocketAddr = "127.0.0.1:5667".parse().unwrap();

            for connection_id in [second, first] {
                endpoint
                    .connection_router
                    .create_connection(&cx, connection_id, peer_addr, true)
                    .await
                    .expect("connection creation should succeed");
            }

            let accepted = endpoint
                .take_next_connection(&cx)
                .expect("take should succeed")
                .expect("connection should exist");
            assert_eq!(accepted.connection_id, first);
            assert_eq!(endpoint.connection_stats().active_connections, 1);

            let accepted = endpoint
                .take_next_connection(&cx)
                .expect("take should succeed")
                .expect("connection should exist");
            assert_eq!(accepted.connection_id, second);
            assert_eq!(endpoint.connection_stats().active_connections, 0);

            assert!(
                endpoint
                    .take_next_connection(&cx)
                    .expect("empty take should succeed")
                    .is_none()
            );
        });
    }

    #[cfg(feature = "tls")]
    mod authenticated_accept_tests {
        use super::*;
        use crate::net::quic_core::PacketHeader;

        // The established route comes from selection_fixture's documented
        // recovery-state fixture. These tests prove pending-owner mechanics,
        // not a completed authenticated two-peer exchange or client identity.
        fn enable_admission_mechanics(endpoint: &mut ManagedQuicEndpoint) {
            endpoint.authenticated_only = true;
            endpoint.config.is_server = true;
            endpoint.config.udp_config.max_packet_size = 16_384;
        }

        fn server_policy(cancel_on_certificate: Option<Cx>) -> Arc<rustls::ServerConfig> {
            use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

            #[derive(Debug)]
            struct CancellingResolver {
                cx: Cx,
                inner: Arc<dyn rustls::server::ResolvesServerCert>,
            }

            impl rustls::server::ResolvesServerCert for CancellingResolver {
                fn resolve(
                    &self,
                    hello: rustls::server::ClientHello<'_>,
                ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                    self.cx.cancel_with(
                        crate::types::CancelKind::User,
                        Some("cancel inside actual TLS certificate resolution"),
                    );
                    self.inner.resolve(hello)
                }
            }

            let certs = CertificateDer::pem_reader_iter(&mut std::io::Cursor::new(include_bytes!(
                "../../../tests/fixtures/tls/server.crt"
            )))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let key = PrivateKeyDer::pem_reader_iter(&mut std::io::Cursor::new(include_bytes!(
                "../../../tests/fixtures/tls/server.key"
            )))
            .next()
            .transpose()
            .unwrap()
            .unwrap();
            let mut config = super::super::super::handshake_driver::server_config(
                certs,
                key,
                vec![b"atp/1".to_vec()],
            )
            .unwrap();
            if let Some(cx) = cancel_on_certificate {
                let config = Arc::get_mut(&mut config).unwrap();
                config.cert_resolver = Arc::new(CancellingResolver {
                    cx,
                    inner: Arc::clone(&config.cert_resolver),
                });
            }
            config
        }

        fn server_driver(cancel_on_certificate: Option<Cx>) -> QuicHandshakeDriver {
            QuicHandshakeDriver::server(server_policy(cancel_on_certificate), Vec::new()).unwrap()
        }

        fn initial_packet(peer: SocketAddr, initial: ConnectionId, now: Instant) -> ReceivedPacket {
            let config = super::super::super::handshake_driver::client_config(
                Vec::new(),
                vec![b"atp/1".to_vec()],
            )
            .unwrap();
            let mut client = QuicHandshakeDriver::client(
                config,
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                Vec::new(),
            )
            .unwrap();
            client.install_initial_keys(initial.as_bytes()).unwrap();
            let segments = client.pump_outbound().unwrap();
            assert_eq!(segments.len(), 1, "one actual ClientHello flight");
            let data = client
                .assemble_handshake_packet(
                    &segments[0],
                    initial,
                    ConnectionId::new(&[0x33; 8]).unwrap(),
                    0,
                )
                .unwrap();
            ReceivedPacket {
                src_addr: peer,
                data,
                receive_time: now,
                transmit_time: None,
            }
        }

        fn routed_packet(cid: ConnectionId, peer: SocketAddr, value: u8) -> RoutedOutgoingPacket {
            RoutedOutgoingPacket {
                connection_id: cid,
                packet: OutgoingPacket {
                    dst_addr: peer,
                    data: vec![value; 32],
                    send_time: None,
                },
                final_handshake_flight: false,
                ack_eliciting: false,
            }
        }

        fn short_packet(cid: ConnectionId, peer: SocketAddr, now: Instant) -> ReceivedPacket {
            let mut data = Vec::new();
            PacketHeader::Short(crate::net::quic_core::ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: cid,
                packet_number: 0,
                packet_number_len: 1,
            })
            .encode(&mut data)
            .unwrap();
            ReceivedPacket {
                src_addr: peer,
                data,
                receive_time: now,
                transmit_time: None,
            }
        }

        #[test]
        fn managed_accept_automatic_policy_preflight_and_malformed_initials_are_atomic() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, existing) =
                    selection_fixture(&Cx::current().unwrap()).await;
                endpoint.remove_connection(&cx, existing).unwrap();
                endpoint.config.is_server = true;
                let peer = peer.local_addr().unwrap();
                for (parameters, alpn) in [
                    (Vec::new(), b"absent".as_slice()),
                    (vec![0xff], b"atp/1".as_slice()),
                    (vec![0x02, 0], b"atp/1".as_slice()),
                    (vec![0x0d, 0], b"atp/1".as_slice()),
                    (vec![0x10, 0], b"atp/1".as_slice()),
                ] {
                    assert!(
                        endpoint
                            .configure_authenticated_server(
                                &cx,
                                server_policy(None),
                                parameters,
                                alpn,
                            )
                            .is_err()
                    );
                    assert!(!endpoint.authenticated_only);
                    assert!(endpoint.authenticated_server.is_none());
                }
                endpoint
                    .configure_authenticated_server(
                        &cx,
                        server_policy(None),
                        vec![0x00, 1, 9, 0x0f, 1, 8],
                        b"atp/1",
                    )
                    .unwrap();
                assert!(endpoint.authenticated_only);
                assert!(
                    endpoint
                        .configure_authenticated_server(
                            &cx,
                            server_policy(None),
                            Vec::new(),
                            b"absent",
                        )
                        .is_err()
                );
                assert_eq!(
                    endpoint
                        .authenticated_server
                        .as_ref()
                        .unwrap()
                        .required_alpn,
                    b"atp/1"
                );
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let initial = ConnectionId::new(&[0xe1; 8]).unwrap();
                let packet = initial_packet(peer, initial, now);
                let mut corrupt = packet.clone();
                *corrupt.data.last_mut().unwrap() ^= 1;
                let mut undersized = packet.clone();
                undersized.data.truncate(1199);
                let mut wrong_version = packet.clone();
                wrong_version.data[1..5].copy_from_slice(&2u32.to_be_bytes());
                for invalid in [
                    corrupt,
                    undersized,
                    wrong_version,
                    initial_packet(peer, ConnectionId::new(&[0xe2; 4]).unwrap(), now),
                ] {
                    assert!(
                        endpoint
                            .try_automatic_authenticated_accept(&cx, &invalid)
                            .unwrap()
                    );
                    assert!(endpoint.pending_authenticated_accept.is_empty());
                    assert!(endpoint.authenticated_accept_result.is_empty());
                    assert!(endpoint.pending_outgoing.is_empty());
                    assert_eq!(endpoint.connection_stats().active_connections, 0);
                }
                assert!(
                    endpoint
                        .try_automatic_authenticated_accept(&cx, &packet)
                        .unwrap()
                );
                assert_eq!(endpoint.pending_authenticated_accept.len(), 1);
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                let local = pending.local_cid;
                assert_eq!(local.len(), ConnectionId::MAX_LEN);
                assert_ne!(local, initial);
                assert_eq!(pending.peer, peer);
                assert_eq!(pending.received_packets, 1);
                assert!(
                    !pending.outbound.is_empty(),
                    "actual TLS flight was produced"
                );
                let parameters = crate::net::quic_core::TransportParameters::decode(
                    pending.driver.local_transport_parameters(),
                )
                .unwrap();
                for (id, expected) in [(0x00, initial), (0x0f, local)] {
                    assert_eq!(
                        parameters
                            .unknown
                            .iter()
                            .find(|p| p.id == id)
                            .unwrap()
                            .value,
                        expected.as_bytes(),
                        "each admitted CID replaces the static template value"
                    );
                }
                let mut wrong_peer = packet;
                wrong_peer.src_addr = "127.0.0.1:1".parse().unwrap();
                endpoint
                    .process_packet_batch(&cx, vec![wrong_peer])
                    .await
                    .unwrap();
                assert_eq!(
                    endpoint
                        .pending_authenticated_accept
                        .front()
                        .unwrap()
                        .received_packets,
                    1
                );
                assert_eq!(endpoint.stop_authenticated_accepts(), 1);
                assert_eq!(endpoint.stop_authenticated_accepts(), 0);
                assert_eq!(
                    endpoint.take_authenticated_accept_result_with_id(),
                    Some((local, Err(ManagedEndpointError::ShuttingDown)))
                );
                assert!(endpoint.pending_outgoing.is_empty());
                assert!(
                    endpoint.authenticated_only,
                    "closing admission never restores the plaintext path"
                );
                assert_eq!(
                    endpoint.configure_authenticated_server(
                        &cx,
                        server_policy(None),
                        Vec::new(),
                        b"atp/1",
                    ),
                    Err(ManagedEndpointError::ShuttingDown)
                );
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_automatic_cancellation_before_publication_retains_no_owner() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, existing) =
                    selection_fixture(&Cx::current().unwrap()).await;
                endpoint.remove_connection(&cx, existing).unwrap();
                endpoint.config.is_server = true;
                endpoint
                    .configure_authenticated_server(
                        &cx,
                        server_policy(Some(cx.clone())),
                        Vec::new(),
                        b"atp/1",
                    )
                    .unwrap();
                let packet = initial_packet(
                    peer.local_addr().unwrap(),
                    ConnectionId::new(&[0xe3; 8]).unwrap(),
                    endpoint.timer_scheduler.now(&cx).unwrap(),
                );
                assert_eq!(
                    endpoint.try_automatic_authenticated_accept(&cx, &packet),
                    Err(ManagedEndpointError::Cancelled)
                );
                assert!(endpoint.pending_authenticated_accept.is_empty());
                assert!(endpoint.authenticated_accept_result.is_empty());
                assert!(endpoint.pending_outgoing.is_empty());
                assert_eq!(endpoint.connection_stats().active_connections, 0);
                let _ = endpoint.shutdown(&cx).await;
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_segments_large_tls_flights_with_full_size_cids() {
            use super::super::super::handshake_driver::{
                client_config, server_config,
                tests::{CA_CERT_PEM, LEAF_CERT_PEM, leaf_key, parse_one_cert},
            };

            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, existing) =
                    selection_fixture(&Cx::current().unwrap()).await;
                endpoint.remove_connection(&cx, existing).unwrap();
                endpoint.config.is_server = true;
                endpoint.config.udp_config.max_packet_size = 1500;
                let mut parameters = crate::net::quic_core::TransportParameters::default();
                parameters
                    .unknown
                    .push(crate::net::quic_core::UnknownTransportParameter {
                        id: 0x173e,
                        value: vec![7; 4096],
                    });
                let mut encoded = Vec::new();
                parameters.encode(&mut encoded).unwrap();
                let tls = server_config(
                    vec![parse_one_cert(LEAF_CERT_PEM)],
                    leaf_key(),
                    vec![b"atp/1".to_vec()],
                )
                .unwrap();
                endpoint
                    .configure_authenticated_server(&cx, tls, encoded, b"atp/1")
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let peer_parameters = crate::net::quic_core::TransportParameters {
                    max_udp_payload_size: Some(1200),
                    ..crate::net::quic_core::TransportParameters::default()
                };
                let mut peer_encoded = Vec::new();
                peer_parameters.encode(&mut peer_encoded).unwrap();
                let mut client = QuicHandshakeDriver::client(
                    client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![b"atp/1".to_vec()])
                        .unwrap(),
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    peer_encoded,
                )
                .unwrap();
                let initial_cid = ConnectionId::new(&[0xe4; 20]).unwrap();
                let client_cid = ConnectionId::new(&[0xe5; 20]).unwrap();
                client.install_initial_keys(initial_cid.as_bytes()).unwrap();
                let segments = client.pump_outbound().unwrap();
                assert_eq!(segments.len(), 1);
                let packet = ReceivedPacket {
                    src_addr: peer.local_addr().unwrap(),
                    data: client
                        .assemble_handshake_packet(&segments[0], initial_cid, client_cid, 0)
                        .unwrap(),
                    receive_time: now,
                    transmit_time: None,
                };
                assert!(
                    endpoint
                        .try_automatic_authenticated_accept(&cx, &packet)
                        .unwrap()
                );
                let pending = endpoint
                    .pending_authenticated_accept
                    .front()
                    .expect("large valid TLS flight remains admitted");
                assert_eq!(pending.local_cid.len(), 20);
                assert!(
                    pending.last_flight.len() >= 5,
                    "TLS bytes split across bounded datagrams"
                );
                assert!(
                    pending
                        .last_flight
                        .iter()
                        .all(|packet| packet.data.len() <= 1200)
                );
                assert!(pending.outstanding_bytes > 4096);
                assert_eq!(
                    pending.outstanding_bytes,
                    pending
                        .last_flight
                        .iter()
                        .map(|packet| packet.data.len())
                        .sum::<usize>()
                );
                assert!(pending.outstanding_bytes <= ACCEPT_MAX_BYTES);
                // Real decryption and CRYPTO reassembly must reach the end of
                // the server's enlarged TLS flight without an offset gap.
                for packet in &pending.last_flight {
                    assert_eq!(
                        client.recv_handshake_packet(&packet.data).unwrap(),
                        pending.local_cid
                    );
                    let _ = client.pump_outbound().unwrap();
                }
                assert!(client.is_complete());
                assert!(client.one_rtt_keys_installed());
                let server_parameters = crate::net::quic_core::TransportParameters::decode(
                    client.peer_transport_parameters().unwrap(),
                )
                .unwrap();
                assert!(server_parameters.unknown.iter().any(|parameter| {
                    parameter.id == 0x173e && parameter.value == vec![7; 4096]
                }));
                endpoint.queue_accept_output();
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert!(
                    pending.socket_pending_bytes as u64 <= pending.authenticated_received_bytes * 3
                );
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_server_rejects_encoded_retry_without_claiming_other_cids() {
            let initial = ConnectionId::new(&[0x91; 8]).unwrap();
            let local = ConnectionId::new(&[0x92; 8]).unwrap();
            let other = ConnectionId::new(&[0x93; 8]).unwrap();
            let peer: SocketAddr = "127.0.0.1:9123".parse().unwrap();
            let now = Instant::now();
            let mut retained = Vec::new();
            for destination in [initial, local, other] {
                let header = PacketHeader::Retry(crate::net::quic_core::RetryHeader {
                    version: 1,
                    dst_cid: destination,
                    src_cid: ConnectionId::new(&[0x94; 8]).unwrap(),
                    token: b"actual encoded Retry token".to_vec(),
                    integrity_tag: [0x95; 16],
                });
                let mut data = Vec::new();
                header.encode(&mut data).unwrap();
                let (decoded, consumed) = PacketHeader::decode(&data, 0).unwrap();
                assert_eq!(decoded, header);
                assert_eq!(consumed, data.len());
                let packet = ReceivedPacket {
                    src_addr: peer,
                    data,
                    receive_time: now,
                    transmit_time: None,
                };
                assert!(!PendingAuthenticatedAccept::packet_matches(
                    &packet, initial, local
                ));
                retained.push(packet);
            }
            let a = short_packet(other, peer, now);
            let b = short_packet(local, peer, now);
            assert!(!PendingAuthenticatedAccept::packet_matches(
                &a, initial, local
            ));
            assert!(PendingAuthenticatedAccept::packet_matches(
                &b, initial, local
            ));
            retained.push(a.clone());
            retained.push(b);
            retained.retain(|packet| {
                !PendingAuthenticatedAccept::packet_matches(packet, initial, local)
            });
            assert_eq!(
                retained.len(),
                4,
                "only the pending server's short packet was claimed"
            );
            assert_eq!(retained.last().unwrap().data, a.data);
            // Header classification is not Retry integrity verification or an
            // authenticated peer exchange; all unclaimed packets stay with the
            // established router and its own role/authentication checks.
        }

        #[test]
        fn managed_accept_preflight_receipt_and_packet_bounds_preserve_existing_owner() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                let initial = ConnectionId::new(&[9; 8]).unwrap();
                let original_socket = endpoint.local_addr();
                let original_deadline = endpoint.connection_router.next_timer_deadline();
                enable_admission_mechanics(&mut endpoint);
                for (initial, local, alpn) in [
                    (initial, b, b"".as_slice()),
                    (a, b, b"atp/1".as_slice()),
                    (initial, a, b"atp/1".as_slice()),
                    (
                        initial,
                        ConnectionId::new(&[7; 4]).unwrap(),
                        b"atp/1".as_slice(),
                    ),
                ] {
                    assert!(
                        endpoint
                            .begin_authenticated_accept(
                                &cx,
                                server_driver(None),
                                peer,
                                initial,
                                local,
                                alpn
                            )
                            .is_err()
                    );
                    assert!(endpoint.pending_authenticated_accept.is_empty());
                    assert!(endpoint.take_authenticated_accept_result().is_none());
                    assert_eq!(endpoint.connection_stats().active_connections, 1);
                }
                endpoint.config.max_connections = 1;
                assert_eq!(
                    endpoint.begin_authenticated_accept(
                        &cx,
                        server_driver(None),
                        peer,
                        initial,
                        b,
                        b"atp/1"
                    ),
                    Err(ManagedEndpointError::MaxConnectionsReached { limit: 1 })
                );
                endpoint.config.max_connections = 2;
                endpoint
                    .begin_authenticated_accept(
                        &cx,
                        server_driver(None),
                        peer,
                        initial,
                        b,
                        b"atp/1",
                    )
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let pending = endpoint.pending_authenticated_accept.front_mut().unwrap();
                let wrong_peer = "127.0.0.1:1".parse().unwrap();
                pending
                    .receive(short_packet(b, wrong_peer, now), 16_384, now)
                    .unwrap();
                assert_eq!(pending.received_packets, 0);
                let packet = routed_packet(b, peer, 1).packet;
                let full = vec![packet.clone(); ACCEPT_MAX_PACKETS];
                pending.queue_flight(&full).unwrap();
                let owned_bytes = pending.outstanding_bytes;
                assert!(pending.queue_flight(&[packet]).is_err());
                assert_eq!(pending.outbound.len(), ACCEPT_MAX_PACKETS);
                assert_eq!(pending.outstanding_bytes, owned_bytes);
                endpoint
                    .pending_outgoing
                    .push_back(routed_packet(a, peer, 7));
                endpoint.remove_connection(&cx, b).unwrap();
                assert!(endpoint.pending_authenticated_accept.is_empty());
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                assert_eq!(endpoint.pending_outgoing[0].connection_id, a);
                assert!(
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            initial,
                            b,
                            b"atp/1"
                        )
                        .is_err(),
                    "unconsumed terminal receipt must stay owned"
                );
                assert_eq!(
                    endpoint.take_authenticated_accept_result(),
                    Some(Err(ManagedEndpointError::Cancelled))
                );
                assert!(endpoint.take_authenticated_accept_result().is_none());
                assert_eq!(endpoint.local_addr(), original_socket);
                assert_eq!(
                    endpoint.connection_router.next_timer_deadline(),
                    original_deadline
                );
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_concurrent_capacity_and_cid_ownership_include_unread_receipts() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, established) =
                    selection_fixture(&Cx::current().unwrap()).await;
                enable_admission_mechanics(&mut endpoint);
                endpoint.config.max_connections = 4;
                assert!(endpoint.set_authenticated_accept_limit(0).is_err());
                assert!(endpoint.set_authenticated_accept_limit(5).is_err());
                endpoint.set_authenticated_accept_limit(3).unwrap();
                let peer = peer.local_addr().unwrap();
                let first = ConnectionId::new(&[0x81; 8]).unwrap();
                let second = ConnectionId::new(&[0x82; 8]).unwrap();
                let third = ConnectionId::new(&[0x83; 8]).unwrap();
                let first_initial = ConnectionId::new(&[0x91; 8]).unwrap();
                let second_initial = ConnectionId::new(&[0x92; 8]).unwrap();
                let third_initial = ConnectionId::new(&[0x93; 8]).unwrap();
                for (initial, local) in [(first_initial, first), (second_initial, second)] {
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            initial,
                            local,
                            b"atp/1",
                        )
                        .unwrap();
                }
                assert_eq!(endpoint.pending_authenticated_accept.len(), 2);
                assert!(endpoint.set_authenticated_accept_limit(4).is_err());
                for (initial, local) in [
                    (first_initial, third),
                    (first, third),
                    (third_initial, first_initial),
                    (third_initial, ConnectionId::new(&[0x81; 4]).unwrap()),
                    (third_initial, ConnectionId::new(&[0x81; 12]).unwrap()),
                ] {
                    assert!(
                        endpoint
                            .begin_authenticated_accept(
                                &cx,
                                server_driver(None),
                                peer,
                                initial,
                                local,
                                b"atp/1",
                            )
                            .is_err(),
                        "pending aliases and ambiguous short IDs remain reserved"
                    );
                    assert_eq!(endpoint.pending_authenticated_accept.len(), 2);
                }
                endpoint.remove_connection(&cx, first).unwrap();
                assert!(
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            first_initial,
                            first,
                            b"atp/1",
                        )
                        .is_err(),
                    "failure receipt keeps its CID reservation"
                );
                endpoint
                    .begin_authenticated_accept(
                        &cx,
                        server_driver(None),
                        peer,
                        third_initial,
                        third,
                        b"atp/1",
                    )
                    .unwrap();
                assert!(
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            ConnectionId::new(&[0x94; 8]).unwrap(),
                            ConnectionId::new(&[0x84; 8]).unwrap(),
                            b"atp/1",
                        )
                        .is_err(),
                    "two pending plus one unread receipt fill three slots"
                );
                assert_eq!(
                    endpoint.take_authenticated_accept_result_with_id(),
                    Some((first, Err(ManagedEndpointError::Cancelled)))
                );
                endpoint.config.max_connections = 3;
                assert_eq!(
                    endpoint.begin_authenticated_accept(
                        &cx,
                        server_driver(None),
                        peer,
                        first_initial,
                        first,
                        b"atp/1",
                    ),
                    Err(ManagedEndpointError::MaxConnectionsReached { limit: 3 }),
                    "pending handshakes reserve eventual connection capacity"
                );
                endpoint.remove_connection(&cx, second).unwrap();
                endpoint.remove_connection(&cx, third).unwrap();
                assert_eq!(
                    endpoint.take_authenticated_accept_result_with_id(),
                    Some((second, Err(ManagedEndpointError::Cancelled)))
                );
                assert_eq!(
                    endpoint.take_authenticated_accept_result(),
                    Some(Err(ManagedEndpointError::Cancelled))
                );
                assert!(
                    endpoint
                        .take_authenticated_accept_result_with_id()
                        .is_none()
                );
                endpoint.set_authenticated_accept_limit(2).unwrap();
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                assert!(
                    endpoint
                        .connection_router
                        .connection_mut_for_testing(&cx, established)
                        .is_ok()
                );
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_round_robin_skips_silent_and_credit_blocked_peers() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, established) =
                    selection_fixture(&Cx::current().unwrap()).await;
                enable_admission_mechanics(&mut endpoint);
                endpoint.set_authenticated_accept_limit(3).unwrap();
                let peer = peer.local_addr().unwrap();
                let silent = ConnectionId::new(&[0xa1; 8]).unwrap();
                let first = ConnectionId::new(&[0xa2; 8]).unwrap();
                let second = ConnectionId::new(&[0xa3; 8]).unwrap();
                for (value, local) in [(0xb1, silent), (0xb2, first), (0xb3, second)] {
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            ConnectionId::new(&[value; 8]).unwrap(),
                            local,
                            b"atp/1",
                        )
                        .unwrap();
                }
                // Queue mechanics only: live TLS/UDP progress is exercised by
                // quic_h3_live_udp, not inferred from these planted flights.
                for local in [first, second] {
                    let pending = endpoint
                        .pending_authenticated_accept
                        .iter_mut()
                        .find(|pending| pending.local_cid == local)
                        .unwrap();
                    pending.address_validated = true;
                    let packet = routed_packet(local, peer, 1).packet;
                    pending.queue_flight(&[packet.clone(), packet]).unwrap();
                }
                for expected in [first, second, first, second] {
                    endpoint.queue_accept_output();
                    assert_eq!(endpoint.pending_outgoing.len(), 1);
                    let packet = endpoint.pending_outgoing.pop_front().unwrap();
                    assert_eq!(packet.connection_id, expected);
                    endpoint
                        .pending_authenticated_accept
                        .iter_mut()
                        .find(|pending| pending.local_cid == expected)
                        .unwrap()
                        .sent(packet.packet.data.len());
                }
                for local in [first, second] {
                    let pending = endpoint
                        .pending_authenticated_accept
                        .iter_mut()
                        .find(|pending| pending.local_cid == local)
                        .unwrap();
                    pending
                        .queue_flight(&[routed_packet(local, peer, 2).packet])
                        .unwrap();
                    pending.address_validated = local == second;
                }
                endpoint.queue_accept_output();
                let packet = endpoint.pending_outgoing.pop_front().unwrap();
                assert_eq!(
                    packet.connection_id, second,
                    "blocked peer must not hold the send turn"
                );
                endpoint
                    .pending_authenticated_accept
                    .iter_mut()
                    .find(|pending| pending.local_cid == second)
                    .unwrap()
                    .sent(packet.packet.data.len());
                endpoint
                    .pending_outgoing
                    .push_back(routed_packet(established, peer, 7));
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                endpoint
                    .pending_authenticated_accept
                    .iter_mut()
                    .find(|pending| pending.local_cid == silent)
                    .unwrap()
                    .expires = now;
                assert!(endpoint.advance_authenticated_accept(&cx, now));
                assert_eq!(endpoint.pending_authenticated_accept.len(), 2);
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                assert_eq!(endpoint.pending_outgoing[0].connection_id, established);
                assert!(
                    matches!(endpoint.take_authenticated_accept_result_with_id(),
                    Some((cid, Err(ManagedEndpointError::InvalidConfig(reason))))
                    if cid == silent && reason.contains("deadline expired"))
                );
                for pending in &mut endpoint.pending_authenticated_accept {
                    pending.next_pto = now
                        + Duration::from_millis(if pending.local_cid == first { 20 } else { 10 });
                }
                let earliest = now + Duration::from_millis(10);
                let expected = endpoint
                    .connection_router
                    .next_timer_deadline()
                    .map_or(earliest, |established| established.min(earliest));
                endpoint.refresh_timer(&cx).await.unwrap();
                assert_eq!(
                    endpoint.timer_scheduler.current_deadline(),
                    Some(expected),
                    "the nearest of every admission and established deadline drives wakeup"
                );
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(
                    endpoint.authenticated_accept_result.len(),
                    2,
                    "shutdown retains one terminal receipt for each remaining owner"
                );
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_failed_peer_does_not_discard_another_real_initial() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, established) =
                    selection_fixture(&Cx::current().unwrap()).await;
                enable_admission_mechanics(&mut endpoint);
                endpoint.config.packet_batch_size = 2;
                endpoint.set_authenticated_accept_limit(2).unwrap();
                let peer = peer.local_addr().unwrap();
                let first = ConnectionId::new(&[0xc1; 8]).unwrap();
                let second = ConnectionId::new(&[0xc2; 8]).unwrap();
                let first_initial = ConnectionId::new(&[0xd1; 8]).unwrap();
                let second_initial = ConnectionId::new(&[0xd2; 8]).unwrap();
                for (initial, local) in [(first_initial, first), (second_initial, second)] {
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            initial,
                            local,
                            b"atp/1",
                        )
                        .unwrap();
                }
                endpoint
                    .pending_authenticated_accept
                    .front_mut()
                    .unwrap()
                    .received_packets = ACCEPT_MAX_PACKETS;
                endpoint
                    .pending_outgoing
                    .push_back(routed_packet(established, peer, 7));
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                endpoint
                    .process_packet_batch(
                        &cx,
                        vec![
                            initial_packet(peer, first_initial, now),
                            initial_packet(peer, second_initial, now),
                        ],
                    )
                    .await
                    .unwrap();
                assert_eq!(endpoint.pending_authenticated_accept.len(), 1);
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert_eq!(pending.local_cid, second);
                assert_eq!(pending.received_packets, 1);
                assert!(
                    !pending.last_flight.is_empty(),
                    "second peer generated real TLS output"
                );
                assert_eq!(endpoint.pending_outgoing[0].connection_id, established);
                assert!(
                    matches!(endpoint.take_authenticated_accept_result_with_id(),
                    Some((cid, Err(ManagedEndpointError::InvalidConfig(reason))))
                    if cid == first && reason.contains("packet bound exhausted"))
                );
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        /// RFC 9000 §12.2: a datagram that fails authentication is discarded.
        /// Anyone who saw the cleartext Initial can spoof the client's
        /// address, so a corrupted copy of that Initial or a long header
        /// with a bogus Length must neither end the admission nor consume
        /// its accepted-packet bound; the real Initial still authenticates
        /// afterwards.
        #[test]
        fn managed_accept_discards_unauthenticated_datagrams_without_aborting() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, _timer, mut endpoint, peer, _a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                let initial = ConnectionId::new(&[9; 8]).unwrap();
                enable_admission_mechanics(&mut endpoint);
                endpoint.config.packet_batch_size = 1024;
                endpoint
                    .begin_authenticated_accept(
                        &cx,
                        server_driver(None),
                        peer,
                        initial,
                        b,
                        b"atp/1",
                    )
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let incoming = initial_packet(peer, initial, now);

                // A bit-flipped copy of the real Initial fails AEAD under the
                // live Initial keys.
                let mut corrupted = incoming.clone();
                let last = corrupted.data.len() - 1;
                corrupted.data[last] ^= 0x55;
                // A version-1 Initial whose Length runs past the datagram.
                let mut overrun = vec![0xC0, 0, 0, 0, 1, 8];
                overrun.extend_from_slice(&[9; 8]);
                overrun.push(0);
                overrun.push(0);
                overrun.extend_from_slice(&[0xBF, 0xFF, 0xFF, 0xFF]);
                overrun.extend_from_slice(&[0u8; 16]);
                let overrun = ReceivedPacket {
                    src_addr: peer,
                    data: overrun,
                    receive_time: now,
                    transmit_time: None,
                };
                {
                    let pending = endpoint.pending_authenticated_accept.front_mut().unwrap();
                    pending
                        .receive(corrupted, 16_384, now)
                        .expect("a corrupted datagram is discarded, not fatal");
                    pending
                        .receive(overrun, 16_384, now)
                        .expect("a length-overrun datagram is discarded, not fatal");
                    assert_eq!(pending.received_packets, 0);
                    assert_eq!(pending.authenticated_received_bytes, 0);
                }

                let initial_bytes = incoming.data.len() as u64;
                endpoint
                    .process_packet_batch(&cx, vec![incoming])
                    .await
                    .unwrap();
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert_eq!(pending.authenticated_received_bytes, initial_bytes);
                assert_eq!(pending.received_packets, 1);
                endpoint.shutdown(&cx).await.unwrap();
            }));
        }

        #[test]
        fn managed_accept_actual_initial_credit_bounds_queued_prefix_and_pto_replay() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                let initial = ConnectionId::new(&[9; 8]).unwrap();
                enable_admission_mechanics(&mut endpoint);
                endpoint.config.packet_batch_size = 1024;
                endpoint.begin_authenticated_accept(
                    &cx, server_driver(None), peer, initial, b, b"atp/1"
                ).unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let incoming = initial_packet(peer, initial, now);
                let initial_bytes = incoming.data.len() as u64;
                endpoint.process_packet_batch(&cx, vec![incoming.clone()]).await.unwrap();
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert_eq!(pending.authenticated_received_bytes, initial_bytes);
                assert!(!pending.address_validated);
                assert!(!pending.last_flight.is_empty(), "actual TLS server output");
                let flight_bytes: u64 = pending.last_flight.iter().map(|packet| packet.data.len() as u64).sum();
                let input_count = (flight_bytes * 2).div_ceil(initial_bytes * 3).max(1);
                assert!(input_count <= 16, "bounded real input funds two complete flights");
                for _ in 1..input_count {
                    endpoint.process_packet_batch(&cx, vec![incoming.clone()]).await.unwrap();
                }
                let received_bytes = initial_bytes * input_count;
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert_eq!(pending.authenticated_received_bytes, received_bytes);
                assert_eq!(pending.received_packets as u64, input_count);
                assert_eq!(pending.flights, 1, "duplicates grant byte credit without new TLS output");
                // Repeated real serialized flights spend the same finite input
                // credit. No extra receive, invented validation, or re-credit.
                let mut charged = 0usize;
                let mut pto_replays = 0usize;
                for _ in 0..ACCEPT_MAX_FLIGHTS {
                    while endpoint.pending_authenticated_accept.front().unwrap()
                        .outbound.front().is_some_and(|packet| endpoint
                            .pending_authenticated_accept.front().unwrap().can_queue(packet.data.len()))
                    {
                        endpoint.queue_accept_output();
                    }
                    let pending = endpoint.pending_authenticated_accept.front().unwrap();
                    assert!(pending.sent_bytes + pending.socket_pending_bytes as u64 <= received_bytes * 3);
                    let queued = endpoint.pending_outgoing.len();
                    endpoint.queue_accept_output();
                    assert_eq!(endpoint.pending_outgoing.len(), queued,
                        "a second queue pass cannot spend queued credit again");
                    for packet in endpoint.pending_outgoing.drain(..) {
                        assert_eq!(packet.connection_id, b);
                        charged += packet.packet.data.len();
                        endpoint.pending_authenticated_accept.front_mut().unwrap().sent(packet.packet.data.len());
                    }
                    let pending = endpoint.pending_authenticated_accept.front().unwrap();
                    if !pending.outbound.is_empty() {
                        let retained = pending.outbound.len();
                        let due = pending.next_pto;
                        assert!(!endpoint.advance_authenticated_accept(&cx, due));
                        assert_eq!(endpoint.pending_authenticated_accept.front().unwrap().outbound.len(), retained,
                            "credit-blocked flight must not duplicate on PTO");
                        break;
                    }
                    let due = pending.next_pto;
                    let before_flights = pending.flights;
                    assert!(!endpoint.advance_authenticated_accept(&cx, due));
                    let pending = endpoint.pending_authenticated_accept.front().unwrap();
                    assert_eq!(pending.flights, before_flights + 1);
                    assert!(!pending.outbound.is_empty(), "actual PTO enqueues retained TLS flight");
                    pto_replays += 1;
                }
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert!(!pending.outbound.is_empty(), "actual bounded credit becomes decisive");
                assert!(charged > 0, "the credit guard must admit a real positive prefix");
                assert!(pto_replays > 0, "at least one actual PTO replay must precede blocking");
                assert!(charged as u64 <= received_bytes * 3);
                assert_eq!(pending.sent_bytes, charged as u64);
                assert_eq!(pending.socket_pending_bytes, 0);
                endpoint.pending_outgoing.push_back(routed_packet(a, peer, 7));
                endpoint.queue_accept_output();
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                assert_eq!(endpoint.pending_outgoing[0].connection_id, a,
                    "blocked B never occupies the shared socket queue ahead of A");
                let expires = endpoint.pending_authenticated_accept.front().unwrap().expires;
                assert!(endpoint.advance_authenticated_accept(&cx, expires));
                assert!(matches!(endpoint.take_authenticated_accept_result(),
                    Some(Err(ManagedEndpointError::InvalidConfig(reason))) if reason.contains("deadline expired")));
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_tls_callback_cancellation_stops_at_one_packet_and_keeps_other_cid() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                let initial = ConnectionId::new(&[9; 8]).unwrap();
                enable_admission_mechanics(&mut endpoint);
                endpoint.config.packet_batch_size = 3;
                endpoint
                    .begin_authenticated_accept(
                        &cx,
                        server_driver(Some(cx.clone())),
                        peer,
                        initial,
                        b,
                        b"atp/1",
                    )
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let incoming = initial_packet(peer, initial, now);
                let retained_a = short_packet(a, peer, now);
                endpoint
                    .pending_outgoing
                    .push_back(routed_packet(a, peer, 7));
                assert_eq!(
                    endpoint
                        .process_packet_batch(
                            &cx,
                            vec![incoming.clone(), incoming, retained_a.clone()]
                        )
                        .await,
                    Err(ManagedEndpointError::Cancelled)
                );
                assert_eq!(
                    cx.cancel_reason().unwrap().message.as_deref(),
                    Some("cancel inside actual TLS certificate resolution")
                );
                assert_eq!(
                    endpoint
                        .pending_authenticated_accept
                        .front()
                        .unwrap()
                        .received_packets,
                    1
                );
                assert_eq!(
                    endpoint.pending_incoming.len(),
                    2,
                    "cancel must leave the second B datagram and A suffix unconsumed"
                );
                assert_eq!(
                    endpoint.run_event_loop(&cx).await,
                    Err(ManagedEndpointError::Cancelled)
                );
                assert_eq!(
                    endpoint.take_authenticated_accept_result(),
                    Some(Err(ManagedEndpointError::Cancelled))
                );
                assert_eq!(endpoint.pending_incoming.len(), 1);
                assert_eq!(endpoint.pending_incoming[0].packet.data, retained_a.data);
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                assert_eq!(endpoint.pending_outgoing[0].connection_id, a);
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                assert_eq!(
                    accept_completion_error(
                        super::super::super::NativeQuicUdpConnectionError::Cancelled
                    ),
                    ManagedEndpointError::Cancelled
                );
                assert_eq!(
                    accept_router_error(ConnectionRouterError::Cancelled),
                    ManagedEndpointError::Cancelled
                );
                assert_eq!(
                    endpoint.shutdown(&cx).await,
                    Err(ManagedEndpointError::Cancelled)
                );
                assert!(endpoint.pending_outgoing.is_empty());
                assert!(endpoint.pending_incoming.is_empty());
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn lifecycle_reaping_preserves_same_address_peer_queues_and_timer() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, _, mut endpoint, peer, a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                endpoint
                    .create_connection_for_testing(&cx, b, peer)
                    .await
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let survivor_deadline = endpoint.connection_router.next_timer_deadline();
                for cid in [a, b, a, b] {
                    endpoint.pending_outgoing.push_back(routed_packet(
                        cid,
                        peer,
                        cid.as_bytes()[0],
                    ));
                    endpoint.pending_incoming.push_back(ManagedIncomingPacket {
                        packet: short_packet(cid, peer, now),
                        needs_clock_stamp: false,
                    });
                }
                endpoint
                    .connection_router
                    .connection_mut_for_testing(&cx, b)
                    .unwrap()
                    .close_immediately(&cx, 0x19)
                    .unwrap();
                endpoint.process_timer_events(&cx, now).await.unwrap();
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                assert_eq!(
                    endpoint.connection_router.next_timer_deadline(),
                    survivor_deadline
                );
                assert_eq!(endpoint.pending_outgoing.len(), 2);
                assert!(
                    endpoint
                        .pending_outgoing
                        .iter()
                        .all(|packet| packet.connection_id == a)
                );
                assert_eq!(endpoint.pending_incoming.len(), 2);
                assert!(endpoint.pending_incoming.iter().all(|packet| {
                    endpoint
                        .connection_router
                        .retained_packet_connection_id(&packet.packet)
                        == Some(a)
                }));
                endpoint.shutdown(&cx).await.unwrap();
            }));
        }

        #[test]
        fn managed_remove_connection_preserves_same_address_peer_queues_and_timer() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                endpoint
                    .create_connection_for_testing(&cx, b, peer)
                    .await
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let deadline = endpoint.connection_router.next_timer_deadline();
                for cid in [a, b, a, b] {
                    endpoint.pending_outgoing.push_back(routed_packet(
                        cid,
                        peer,
                        cid.as_bytes()[0],
                    ));
                    endpoint.pending_incoming.push_back(ManagedIncomingPacket {
                        packet: short_packet(cid, peer, now),
                        needs_clock_stamp: false,
                    });
                }
                endpoint.remove_connection(&cx, b).unwrap();
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                assert_eq!(endpoint.connection_router.next_timer_deadline(), deadline);
                assert_eq!(endpoint.pending_outgoing.len(), 2);
                assert!(
                    endpoint.pending_outgoing.iter().all(
                        |packet| packet.connection_id == a && packet.packet.data == vec![7; 32]
                    )
                );
                assert_eq!(endpoint.pending_incoming.len(), 2);
                assert!(endpoint.pending_incoming.iter().all(|packet| {
                    endpoint
                        .connection_router
                        .retained_packet_connection_id(&packet.packet)
                        == Some(a)
                }));
                assert_eq!(
                    endpoint.remove_connection(&cx, b),
                    Err(ManagedEndpointError::ConnectionRouter(
                        ConnectionRouterError::ConnectionNotFound(b)
                    ))
                );
                endpoint.remove_connection(&cx, a).unwrap();
                assert_eq!(endpoint.connection_stats().active_connections, 0);
                assert!(endpoint.pending_outgoing.is_empty());
                assert!(endpoint.pending_incoming.is_empty());
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }
    }
}
