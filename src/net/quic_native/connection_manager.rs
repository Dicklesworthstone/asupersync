//! Connection routing and management for native QUIC endpoint.
//!
//! This module provides connection-ID routing, timer scheduling integration,
//! and connection lifecycle management for the ATP native QUIC endpoint.
//! It bridges the gap between the UDP endpoint packet I/O and individual
//! QUIC connection state machines.

#![allow(dead_code)]

use crate::cx::Cx;
use crate::net::atp::protocol::quic_frames::QuicFrame;
use crate::net::atp::quic::AtpPacketProtection;
use crate::net::quic_core::{
    ConnectionId, LongPacketType, PacketHeader, ProtectedHeaderPrefix, QuicCoreError, ShortHeader,
    apply_header_protection, decode_packet_number_reconstruct, header_protection_sample,
    remove_header_protection,
};
use crate::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, OutgoingPacket, QuicConnectionState,
    ReceivedPacket,
};
use crate::net::quic_native::{
    NativeQuicConnectionError, PacketNumberSpace, PacketProtectionRequest, PacketProtectionSpace,
    ProtectedPacket, ProtectionProof, TranscriptHash,
};
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::outcome::Outcome;
use std::collections::{HashMap, HashSet};
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

const DEFAULT_MAX_CONNECTIONS: usize = 4096;
const TIMER_CONNECTIONS_PER_TURN: usize = 32;

/// Connection routing table that maps connection IDs to active QUIC connections.
#[derive(Debug)]
pub struct ConnectionRouter {
    /// Map from destination connection ID to connection handle.
    connections: HashMap<ConnectionId, ConnectionHandle>,
    /// Maximum active connections accepted by this router.
    max_connections: usize,
    /// Next connection ID counter for generating new connections.
    next_connection_id: u64,
    /// Connection configuration template.
    config_template: NativeQuicConnectionConfig,
    /// Monotonic clock origin for connection timer APIs that use microseconds.
    clock_origin: Instant,
    /// Timer output remains owned across cancellation or another connection's error.
    pending_timer_packets: Vec<RoutedOutgoingPacket>,
    /// Committed deferred output survives cancellation before handoff.
    pending_deferred_packets: Vec<RoutedOutgoingPacket>,
    /// Last serviced CID, used to rotate deterministic deferred-output order.
    deferred_cursor: Option<ConnectionId>,
    /// Local idle policy, which peer negotiation may shorten but never extend.
    idle_timeout_micros: Option<u64>,
}

/// Private ownership envelope; the public UDP packet layout stays unchanged.
#[derive(Debug)]
pub(crate) struct RoutedOutgoingPacket {
    pub(crate) connection_id: ConnectionId,
    pub(crate) packet: OutgoingPacket,
    pub(crate) final_handshake_flight: bool,
    pub(crate) ack_eliciting: bool,
}

/// A requested close remains route-owned across asynchronous protection and
/// socket backpressure. Its sole queued packet is never ordinary stream work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalCloseOutput {
    Requested,
    Queued,
    Sent,
}

/// Handle to a managed QUIC connection with timing and lifecycle state.
#[derive(Debug)]
pub struct ConnectionHandle {
    /// The underlying QUIC connection state machine.
    connection: RoutedConnection,
    /// Packet-protection provider for 1-RTT UDP handoff.
    packet_protection: Option<ConnectionPacketProtection>,
    /// Remote peer address.
    peer_addr: SocketAddr,
    /// Last activity timestamp for connection timeout tracking.
    last_activity: Instant,
    /// Only the first ack-eliciting send after accepted input restarts idle.
    sent_since_receive: bool,
    /// Connection establishment timestamp.
    established_at: Option<Instant>,
    /// Pending timer deadline for this connection.
    next_timer_deadline: Option<Instant>,
    /// Input may make output ready while the endpoint's send queue is full.
    deferred_spaces: [bool; 3],
    next_deferred_space: usize,
    local_close_output: Option<LocalCloseOutput>,
    /// Imported connections keep their negotiated peer CID and recovery epoch.
    peer_connection_id: Option<ConnectionId>,
    clock_origin: Option<Instant>,
    #[cfg(feature = "tls")]
    authenticated: Option<AuthenticatedRouting>,
}

/// Keep the application-facing owner intact when an authenticated socket moves
/// into the router. Legacy routes retain their original native state machine.
#[derive(Debug)]
enum RoutedConnection {
    Native(NativeQuicConnection),
    #[cfg(feature = "tls")]
    Authenticated(super::QuicConnection),
}

impl std::ops::Deref for RoutedConnection {
    type Target = NativeQuicConnection;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Native(connection) => connection,
            #[cfg(feature = "tls")]
            Self::Authenticated(connection) => connection.inner(),
        }
    }
}

impl std::ops::DerefMut for RoutedConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Native(connection) => connection,
            #[cfg(feature = "tls")]
            Self::Authenticated(connection) => connection.inner_mut(),
        }
    }
}

#[cfg(feature = "tls")]
#[derive(Debug)]
struct AuthenticatedRouting {
    negotiated_alpn: Vec<u8>,
    final_handshake_flight: Vec<OutgoingPacket>,
    last_final_flight_retransmit: Option<Instant>,
    pending_final_flight_packets: usize,
}

#[cfg(feature = "tls")]
struct MarkApplicationOutput<'a>(&'a mut bool);

#[cfg(feature = "tls")]
impl Drop for MarkApplicationOutput<'_> {
    fn drop(&mut self) {
        *self.0 = true;
    }
}

/// Native QUIC connection removed from the router for application-level handoff.
#[derive(Debug)]
pub struct AcceptedNativeQuicConnection {
    /// Connection ID that owned the routed connection.
    pub connection_id: ConnectionId,
    /// The native QUIC connection state machine.
    pub connection: NativeQuicConnection,
    /// Remote peer address associated with the accepted connection.
    pub peer_addr: SocketAddr,
}

struct ConnectionPacketProtection {
    protection: AtpPacketProtection,
}

impl std::fmt::Debug for ConnectionPacketProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPacketProtection")
            .field("provider_kind", &self.protection.provider_kind())
            .finish_non_exhaustive()
    }
}

/// Timer event for a specific connection.
#[derive(Debug, Clone)]
pub struct ConnectionTimerEvent {
    /// Connection ID this timer event belongs to.
    pub connection_id: ConnectionId,
    /// Type of timer that fired.
    pub timer_type: TimerType,
    /// Deadline when this timer was scheduled to fire.
    pub deadline: Instant,
}

/// Types of timers used by QUIC connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerType {
    /// Probe timeout (PTO) for loss recovery.
    ProbeTimeout,
    /// ACK delay timer.
    AckDelay,
    /// Connection idle timeout.
    IdleTimeout,
    /// Connection draining timeout.
    DrainTimeout,
    /// Keep-alive probe.
    KeepAlive,
}

/// Result of routing a received packet to a connection.
#[derive(Debug)]
pub enum RoutingResult {
    /// Packet was successfully routed to an existing connection.
    Routed {
        /// Connection ID packet was routed to.
        connection_id: ConnectionId,
        /// Outgoing packets generated by processing this packet.
        outgoing_packets: Vec<OutgoingPacket>,
    },
    /// Packet is a new connection attempt (e.g., Initial packet).
    NewConnection {
        /// Suggested connection ID for the new connection.
        connection_id: ConnectionId,
        /// Remote address that originated the first datagram.
        peer_addr: SocketAddr,
        /// Original Initial packet that triggered connection creation.
        triggering_packet: ReceivedPacket,
        /// Initial outgoing packets for handshake response.
        outgoing_packets: Vec<OutgoingPacket>,
    },
    /// Packet should be dropped (invalid CID, stateless reset, etc.).
    Drop {
        /// Reason for dropping the packet.
        reason: String,
    },
}

/// Errors from connection routing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionRouterError {
    /// Operation was cancelled via Cx.
    Cancelled,
    /// Connection ID not found in routing table.
    ConnectionNotFound(ConnectionId),
    /// Connection is in invalid state for the operation.
    InvalidConnectionState {
        /// Connection ID.
        connection_id: ConnectionId,
        /// Description of invalid state.
        reason: String,
    },
    /// Unable to create new connection.
    ConnectionCreationFailed(String),
    /// Timer scheduling failed.
    TimerSchedulingFailed(String),
    /// Packet reached a connection but failed state-machine processing.
    PacketProcessingFailed {
        /// Connection ID.
        connection_id: ConnectionId,
        /// Processing error.
        reason: String,
    },
    /// Application-data frames were ready, but no 1-RTT packet protection was installed.
    PacketProtectionUnavailable {
        /// Connection ID.
        connection_id: ConnectionId,
    },
}

impl std::fmt::Display for ConnectionRouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::ConnectionNotFound(cid) => write!(f, "connection not found: {cid:?}"),
            Self::InvalidConnectionState {
                connection_id,
                reason,
            } => {
                write!(
                    f,
                    "invalid connection state for {connection_id:?}: {reason}"
                )
            }
            Self::ConnectionCreationFailed(msg) => write!(f, "connection creation failed: {msg}"),
            Self::TimerSchedulingFailed(msg) => write!(f, "timer scheduling failed: {msg}"),
            Self::PacketProcessingFailed {
                connection_id,
                reason,
            } => {
                write!(
                    f,
                    "packet processing failed for {connection_id:?}: {reason}"
                )
            }
            Self::PacketProtectionUnavailable { connection_id } => {
                write!(
                    f,
                    "packet protection unavailable for application-data packet on {connection_id:?}"
                )
            }
        }
    }
}

impl std::error::Error for ConnectionRouterError {}

impl ConnectionRouter {
    #[cfg(feature = "tls")]
    pub(crate) fn validate_authenticated_cids(
        &self,
        initial_cid: ConnectionId,
        local_cid: ConnectionId,
    ) -> Result<(), ConnectionRouterError> {
        if self.connections.len() >= self.max_connections {
            return Err(ConnectionRouterError::ConnectionCreationFailed(
                "authenticated connection capacity exhausted".to_string(),
            ));
        }
        if initial_cid.is_empty()
            || local_cid.is_empty()
            || self.connections.contains_key(&initial_cid)
            || self.connections.keys().any(|existing| {
                existing.as_bytes().starts_with(local_cid.as_bytes())
                    || local_cid.as_bytes().starts_with(existing.as_bytes())
            })
        {
            return Err(ConnectionRouterError::ConnectionCreationFailed(
                "empty, occupied, or ambiguous authenticated connection ID".to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "tls")]
    pub(crate) fn insert_authenticated_connection(
        &mut self,
        cx: &Cx,
        initial_cid: ConnectionId,
        local_cid: ConnectionId,
        peer_addr: SocketAddr,
        mut parts: super::udp_connection::AuthenticatedQuicParts,
        now: Instant,
    ) -> Result<(), ConnectionRouterError> {
        cx.checkpoint()
            .map_err(|_| ConnectionRouterError::Cancelled)?;
        self.validate_authenticated_cids(initial_cid, local_cid)?;
        let deadline = parts
            .connection
            .inner_mut()
            .pto_deadline_micros(cx, 0)
            .map_err(|error| match error {
                super::NativeQuicConnectionError::Cancelled => ConnectionRouterError::Cancelled,
                other => ConnectionRouterError::PacketProcessingFailed {
                    connection_id: local_cid,
                    reason: other.to_string(),
                },
            })?
            .map(|micros| {
                now.checked_add(Duration::from_micros(micros))
                    .ok_or_else(|| {
                        ConnectionRouterError::TimerSchedulingFailed(
                            "authenticated deadline exceeds the managed clock range".to_string(),
                        )
                    })
            })
            .transpose()?;
        self.connections.insert(
            local_cid,
            ConnectionHandle {
                connection: RoutedConnection::Authenticated(parts.connection),
                packet_protection: Some(ConnectionPacketProtection {
                    protection: parts.protection,
                }),
                peer_addr,
                last_activity: now,
                sent_since_receive: false,
                established_at: Some(now),
                next_timer_deadline: deadline,
                deferred_spaces: [false, false, true],
                next_deferred_space: 0,
                local_close_output: None,
                peer_connection_id: Some(parts.peer_cid),
                clock_origin: Some(now),
                authenticated: Some(AuthenticatedRouting {
                    negotiated_alpn: parts.negotiated_alpn,
                    final_handshake_flight: parts.final_handshake_flight,
                    last_final_flight_retransmit: None,
                    pending_final_flight_packets: 0,
                }),
            },
        );
        Ok(())
    }

    pub(crate) fn retained_packet_connection_id(
        &self,
        packet: &ReceivedPacket,
    ) -> Option<ConnectionId> {
        self.decode_routing_info(packet)
            .ok()
            .map(|info| info.destination_cid)
    }

    /// All fallible validation precedes this owned move. No negotiated state
    /// is recreated from the template or from handshake transition flags.
    #[cfg(feature = "tls")]
    pub(crate) fn from_authenticated_parts(
        parts: super::udp_connection::NativeQuicUdpHandoffParts,
        config_template: NativeQuicConnectionConfig,
        max_connections: usize,
        next_timer_deadline: Option<Instant>,
        now: Instant,
    ) -> (
        Self,
        super::QuicUdpEndpoint,
        std::collections::VecDeque<ReceivedPacket>,
    ) {
        let super::udp_connection::NativeQuicUdpHandoffParts {
            connection,
            endpoint,
            protection,
            local_cid,
            peer_cid,
            peer_addr,
            negotiated_alpn,
            final_handshake_flight,
            early_one_rtt_packets,
            last_final_flight_retransmit,
            clock_origin,
            last_activity,
            sent_since_receive,
            pending_outgoing,
        } = parts;
        let mut router = Self::with_max_connections(config_template, max_connections);
        router.pending_deferred_packets = pending_outgoing;
        router.connections.insert(
            local_cid,
            ConnectionHandle {
                connection: RoutedConnection::Authenticated(connection),
                packet_protection: Some(ConnectionPacketProtection { protection }),
                peer_addr,
                last_activity,
                sent_since_receive,
                established_at: Some(now),
                next_timer_deadline,
                deferred_spaces: [false, false, true],
                next_deferred_space: 0,
                local_close_output: None,
                peer_connection_id: Some(peer_cid),
                clock_origin: Some(clock_origin),
                authenticated: Some(AuthenticatedRouting {
                    negotiated_alpn,
                    final_handshake_flight,
                    last_final_flight_retransmit,
                    pending_final_flight_packets: 0,
                }),
            },
        );
        (router, endpoint, early_one_rtt_packets.into())
    }

    #[cfg(feature = "tls")]
    pub(crate) fn with_authenticated_connection<R>(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
        operation: impl FnOnce(&mut super::QuicConnection) -> R,
    ) -> Result<R, ConnectionRouterError> {
        cx.checkpoint()
            .map_err(|_| ConnectionRouterError::Cancelled)?;
        let handle = self
            .connections
            .get_mut(&connection_id)
            .ok_or(ConnectionRouterError::ConnectionNotFound(connection_id))?;
        let RoutedConnection::Authenticated(connection) = &mut handle.connection else {
            return Err(ConnectionRouterError::InvalidConnectionState {
                connection_id,
                reason: "connection has no authenticated application owner".to_string(),
            });
        };
        // An application callback may queue output and then unwind. Its caller
        // can resume the same owned endpoint without stranding that output.
        let _mark = MarkApplicationOutput(&mut handle.deferred_spaces[2]);
        Ok(operation(connection))
    }

    /// Start one authenticated route's local drain in its original clock
    /// domain. The event loop owns protection and delivery of the final close.
    /// A non-forced request preserves buffered and unacknowledged output.
    #[cfg(all(feature = "tls", any(test, feature = "http3")))]
    pub(crate) fn request_authenticated_close(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
        now: Instant,
        app_error_code: u64,
        force: bool,
    ) -> Result<bool, ConnectionRouterError> {
        cx.checkpoint()
            .map_err(|_| ConnectionRouterError::Cancelled)?;
        if !matches!(
            crate::net::atp::protocol::varint::VarInt::new(app_error_code),
            Outcome::Ok(_)
        ) {
            return Err(ConnectionRouterError::InvalidConnectionState {
                connection_id,
                reason: "close code exceeds QUIC varint range".to_string(),
            });
        }
        let queued_output = self.pending_datagram_count_for(connection_id) != 0;
        let handle = self
            .connections
            .get_mut(&connection_id)
            .ok_or(ConnectionRouterError::ConnectionNotFound(connection_id))?;
        if !matches!(handle.connection, RoutedConnection::Authenticated(_))
            || handle.authenticated.is_none()
            || handle.packet_protection.is_none()
        {
            return Err(ConnectionRouterError::InvalidConnectionState {
                connection_id,
                reason: "connection has no authenticated application owner".to_string(),
            });
        }
        if matches!(
            handle.connection.state(),
            QuicConnectionState::Draining | QuicConnectionState::Closed
        ) {
            return Ok(true);
        }
        if !force
            && (queued_output
                || handle.connection.has_pending_stream_frames()
                || handle.connection.has_pending_control_frames()
                || handle.connection.pending_outbound_datagram_count() != 0
                || handle.connection.transport().bytes_in_flight() != 0)
        {
            return Ok(false);
        }
        let origin = handle.clock_origin.unwrap_or(self.clock_origin);
        handle
            .connection
            .begin_close(cx, instant_micros_from(origin, now), app_error_code)
            .map_err(|error| ConnectionRouterError::PacketProcessingFailed {
                connection_id,
                reason: error.to_string(),
            })?;
        handle.local_close_output = Some(LocalCloseOutput::Requested);
        handle.deferred_spaces = [false; 3];
        handle.next_timer_deadline = None;
        // A forced deadline retires only this route's ordinary output. Once
        // locally draining, no further application or recovery packet is made.
        self.pending_timer_packets
            .retain(|packet| packet.connection_id != connection_id);
        self.pending_deferred_packets
            .retain(|packet| packet.connection_id != connection_id);
        Ok(true)
    }

    #[cfg(all(feature = "tls", any(test, feature = "http3")))]
    pub(crate) fn pending_datagram_count_for(&self, connection_id: ConnectionId) -> usize {
        self.pending_timer_packets
            .iter()
            .chain(self.pending_deferred_packets.iter())
            .filter(|packet| packet.connection_id == connection_id)
            .count()
    }

    #[cfg(feature = "tls")]
    pub(crate) fn negotiated_alpn(
        &self,
        connection_id: ConnectionId,
    ) -> Result<&[u8], ConnectionRouterError> {
        let handle = self
            .connections
            .get(&connection_id)
            .ok_or(ConnectionRouterError::ConnectionNotFound(connection_id))?;
        handle
            .authenticated
            .as_ref()
            .map(|state| state.negotiated_alpn.as_slice())
            .ok_or_else(|| ConnectionRouterError::InvalidConnectionState {
                connection_id,
                reason: "connection has no authenticated ALPN".to_string(),
            })
    }

    /// A final-flight copy remains outstanding until its actual UDP sent prefix
    /// is acknowledged. Other application/PTO packets cannot retire that copy.
    pub(crate) fn packet_sent(&mut self, packet: &RoutedOutgoingPacket, now: Option<Instant>) {
        if let Some(handle) = self.connections.get_mut(&packet.connection_id) {
            if handle.local_close_output == Some(LocalCloseOutput::Queued) {
                // The close request removed all ordinary packets for this CID
                // before its sole terminal packet was assembled.
                handle.local_close_output = Some(LocalCloseOutput::Sent);
            }
            if let Some(now) = now.filter(|_| packet.ack_eliciting && !handle.sent_since_receive) {
                handle.last_activity = handle.last_activity.max(now);
                handle.sent_since_receive = true;
            }
        }
        #[cfg(feature = "tls")]
        if packet.final_handshake_flight {
            if let Some(state) = self
                .connections
                .get_mut(&packet.connection_id)
                .and_then(|handle| handle.authenticated.as_mut())
            {
                state.pending_final_flight_packets = state
                    .pending_final_flight_packets
                    .checked_sub(1)
                    .expect("each final-flight packet is acknowledged once");
            }
        }
        #[cfg(not(feature = "tls"))]
        let _ = packet;
    }

    /// Create a new connection router with the given configuration template.
    pub fn new(config_template: NativeQuicConnectionConfig) -> Self {
        Self::with_max_connections(config_template, DEFAULT_MAX_CONNECTIONS)
    }

    /// Create a connection router with an explicit active-connection cap.
    ///
    /// A zero cap is normalized to one connection so the router never accepts an
    /// unbounded configuration by accident.
    pub fn with_max_connections(
        config_template: NativeQuicConnectionConfig,
        max_connections: usize,
    ) -> Self {
        Self {
            connections: HashMap::new(),
            max_connections: max_connections.max(1),
            next_connection_id: 1,
            config_template,
            clock_origin: Instant::now(),
            pending_timer_packets: Vec::new(),
            pending_deferred_packets: Vec::new(),
            deferred_cursor: None,
            idle_timeout_micros: None,
        }
    }

    pub(crate) fn set_idle_timeout_micros(&mut self, timeout: u64) {
        self.idle_timeout_micros = (timeout != 0).then_some(timeout);
    }

    /// Route a received packet to the appropriate connection.
    pub async fn route_packet(
        &mut self,
        cx: &Cx,
        packet: ReceivedPacket,
    ) -> Result<RoutingResult, ConnectionRouterError> {
        self.route_packet_with_output(cx, packet, true).await
    }

    /// Process input even under send backpressure, deferring destructive frame
    /// generation until the managed owner has room for the resulting packet.
    pub(crate) async fn route_packet_with_output(
        &mut self,
        cx: &Cx,
        #[allow(unused_mut)] mut packet: ReceivedPacket,
        emit_output: bool,
    ) -> Result<RoutingResult, ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        #[allow(unused_mut)]
        let mut routing_info = match self.decode_routing_info(&packet) {
            Ok(info) => info,
            Err(err) => {
                return Ok(RoutingResult::Drop {
                    reason: format!("invalid QUIC header: {err}"),
                });
            }
        };
        let connection_id = routing_info.destination_cid;
        let now_micros = self.instant_micros(packet.receive_time);

        if let Some(handle) = self.connections.get_mut(&connection_id) {
            if matches!(
                handle.connection.state(),
                QuicConnectionState::Closed | QuicConnectionState::Draining
            ) {
                return Ok(RoutingResult::Drop {
                    reason: "connection is draining or closed".to_string(),
                });
            }
            let now_micros = handle.clock_origin.map_or(now_micros, |origin| {
                instant_micros_from(origin, packet.receive_time)
            });
            #[cfg(feature = "tls")]
            if let Some(authenticated) = &mut handle.authenticated {
                if packet.src_addr != handle.peer_addr {
                    return Ok(RoutingResult::Drop {
                        reason: "packet source does not match the authenticated peer".to_string(),
                    });
                }
                if routing_info.kind != PacketRoutingKind::OneRtt {
                    // RFC 9000 section 12.2: a datagram may coalesce several
                    // long-header packets and then one 1-RTT short-header
                    // packet. Each long-header packet is bounded by its Length
                    // field and classified alone, so a peer that still holds
                    // Handshake keys and sends [Handshake(ACK)][1-RTT] neither
                    // requests the final flight nor loses its 1-RTT packet.
                    let mut offset = 0;
                    let mut only_handshake_acks = true;
                    let mut coalesced_1rtt = None;
                    while offset < packet.data.len() {
                        let rest = &packet.data[offset..];
                        match ProtectedHeaderPrefix::decode(rest, connection_id.len()) {
                            Ok(ProtectedHeaderPrefix::Long(long_header))
                                if long_header.dst_cid == connection_id =>
                            {
                                let Ok(long_len) = long_header.packet_len(rest.len()) else {
                                    only_handshake_acks = false;
                                    break;
                                };
                                only_handshake_acks = only_handshake_acks
                                    && handle.packet_protection.as_mut().is_some_and(
                                        |protection| {
                                            authenticated_handshake_ack_only(
                                                cx,
                                                connection_id,
                                                &mut protection.protection,
                                                &rest[..long_len],
                                            )
                                        },
                                    );
                                offset += long_len;
                            }
                            Ok(ProtectedHeaderPrefix::Short { dst_cid, .. })
                                if offset > 0 && dst_cid == connection_id =>
                            {
                                coalesced_1rtt = Some(rest.to_vec());
                                break;
                            }
                            // Padding, a malformed trailer or a packet for
                            // another connection ends the datagram; a leading
                            // packet of any other kind still requests recovery.
                            _ => {
                                only_handshake_acks &= offset > 0;
                                break;
                            }
                        }
                    }
                    // These encrypted handshake bytes belong to the retained
                    // TLS flight, never the legacy plaintext-frame path.
                    if !only_handshake_acks
                        && authenticated.pending_final_flight_packets == 0
                        && !authenticated.final_handshake_flight.is_empty()
                        && authenticated
                            .last_final_flight_retransmit
                            .is_none_or(|last| {
                                packet.receive_time.saturating_duration_since(last)
                                    >= super::udp_connection::FINAL_HANDSHAKE_FLIGHT_RESEND_INTERVAL
                            })
                    {
                        let retained = authenticated
                            .final_handshake_flight
                            .iter()
                            .cloned()
                            .map(|packet| RoutedOutgoingPacket {
                                connection_id,
                                packet,
                                final_handshake_flight: true,
                                ack_eliciting: false,
                            })
                            .collect::<Vec<_>>();
                        authenticated.pending_final_flight_packets = retained.len();
                        self.pending_deferred_packets.extend(retained);
                        authenticated.last_final_flight_retransmit = Some(packet.receive_time);
                    }

                    if let Some(short_data) = coalesced_1rtt {
                        packet.data = short_data;
                        // A 1-RTT tail is ApplicationData, not the long header's space.
                        routing_info = PacketRoutingInfo {
                            destination_cid: connection_id,
                            kind: PacketRoutingKind::OneRtt,
                            space: PacketNumberSpace::ApplicationData,
                        };
                    } else {
                        return Ok(RoutingResult::Routed {
                            connection_id,
                            outgoing_packets: Vec::new(),
                        });
                    }
                }
            }
            let authenticated = handle.clock_origin.is_some();
            if authenticated {
                // Replay admission and payload commitment are one bounded,
                // synchronous cancellation transaction. In particular a stream
                // waker may request cancellation while processing the first
                // frame: the remaining frames must still commit exactly once.
                // No socket, timer, or other asynchronous wait is masked.
                let admitted = cx.masked(|| -> Result<bool, ConnectionRouterError> {
                    let protection = handle.packet_protection.as_mut().ok_or(
                        ConnectionRouterError::PacketProtectionUnavailable { connection_id },
                    )?;
                    let unprotected = unprotect_1rtt_packet_now(
                        cx,
                        connection_id,
                        &mut protection.protection,
                        Some(&handle.connection),
                        &packet.data,
                    )?;
                    if unprotected.peer_key_update {
                        handle
                            .connection
                            .on_peer_key_phase_pn(
                                cx,
                                unprotected.header.key_phase,
                                unprotected.header.packet_number,
                            )
                            .map_err(|error| ConnectionRouterError::PacketProcessingFailed {
                                connection_id,
                                reason: error.to_string(),
                            })?;
                        protection
                            .protection
                            .note_peer_key_update(PacketProtectionSpace::OneRtt);
                        if handle.connection.tls().local_key_phase() != unprotected.header.key_phase
                        {
                            handle
                                .connection
                                .request_local_key_update(cx)
                                .map_err(|error| ConnectionRouterError::PacketProcessingFailed {
                                    connection_id,
                                    reason: error.to_string(),
                                })?;
                            handle
                                .connection
                                .commit_local_key_update(cx)
                                .map_err(|error| ConnectionRouterError::PacketProcessingFailed {
                                    connection_id,
                                    reason: error.to_string(),
                                })?;
                            protection
                                .protection
                                .note_local_key_update(PacketProtectionSpace::OneRtt);
                        }
                    }
                    handle
                        .connection
                        .on_datagram_received(cx, packet.data.len() as u64)
                        .map_err(|error| ConnectionRouterError::PacketProcessingFailed {
                            connection_id,
                            reason: error.to_string(),
                        })?;
                    let processing = handle.connection.process_packet_payload(
                        cx,
                        routing_info.space,
                        unprotected.header.packet_number,
                        &unprotected.plaintext,
                        now_micros,
                    );
                    if let Err(error) = processing {
                        if error.is_stream_reassembly_backpressure() {
                            return Ok(false);
                        }
                        Self::request_peer_violation_close(handle);
                        return Err(ConnectionRouterError::PacketProcessingFailed {
                            connection_id,
                            reason: error.to_string(),
                        });
                    }
                    handle.last_activity = handle.last_activity.max(packet.receive_time);
                    handle.sent_since_receive = false;
                    handle.deferred_spaces[packet_space_index(routing_info.space)] = true;
                    Self::refresh_connection_timer(
                        cx,
                        connection_id,
                        handle,
                        self.clock_origin,
                        now_micros,
                        packet.receive_time,
                    )?;
                    Ok(true)
                })?;
                if !admitted {
                    return Ok(RoutingResult::Drop {
                        reason: "stream reassembly backpressure".to_string(),
                    });
                }
                // Always acknowledge committed input before a later checkpoint
                // or await. The driver owns deferred output, so cancellation
                // cannot turn this accepted ciphertext into a replay retry.
                return Ok(RoutingResult::Routed {
                    connection_id,
                    outgoing_packets: Vec::new(),
                });
            }
            handle
                .connection
                .on_datagram_received(cx, packet.data.len() as u64)
                .map_err(|err| ConnectionRouterError::PacketProcessingFailed {
                    connection_id,
                    reason: err.to_string(),
                })?;
            let (packet_number, plaintext_payload) =
                if routing_info.kind == PacketRoutingKind::OneRtt {
                    let packet_protection = handle.packet_protection.as_mut().ok_or(
                        ConnectionRouterError::PacketProtectionUnavailable { connection_id },
                    )?;
                    let unprotected = unprotect_1rtt_packet_with_connection(
                        cx,
                        connection_id,
                        &mut packet_protection.protection,
                        Some(&handle.connection),
                        &packet.data,
                    )
                    .await?;
                    if unprotected.peer_key_update {
                        handle
                            .connection
                            .on_peer_key_phase_pn(
                                cx,
                                unprotected.header.key_phase,
                                unprotected.header.packet_number,
                            )
                            .map_err(|error| ConnectionRouterError::PacketProcessingFailed {
                                connection_id,
                                reason: error.to_string(),
                            })?;
                        packet_protection
                            .protection
                            .note_peer_key_update(PacketProtectionSpace::OneRtt);
                        if handle.connection.tls().local_key_phase() != unprotected.header.key_phase
                        {
                            handle
                                .connection
                                .request_local_key_update(cx)
                                .map_err(|error| ConnectionRouterError::PacketProcessingFailed {
                                    connection_id,
                                    reason: error.to_string(),
                                })?;
                            handle
                                .connection
                                .commit_local_key_update(cx)
                                .map_err(|error| ConnectionRouterError::PacketProcessingFailed {
                                    connection_id,
                                    reason: error.to_string(),
                                })?;
                            packet_protection
                                .protection
                                .note_local_key_update(PacketProtectionSpace::OneRtt);
                        }
                    }
                    (unprotected.header.packet_number, unprotected.plaintext)
                } else {
                    plaintext_packet_payload(connection_id, &packet.data)?
                };
            let processing = handle.connection.process_packet_payload(
                cx,
                routing_info.space,
                packet_number,
                &plaintext_payload,
                now_micros,
            );
            if let Err(error) = processing {
                if error.is_stream_reassembly_backpressure() {
                    return Ok(RoutingResult::Drop {
                        reason: "stream reassembly backpressure".to_string(),
                    });
                }
                Self::request_peer_violation_close(handle);
                return Err(ConnectionRouterError::PacketProcessingFailed {
                    connection_id,
                    reason: error.to_string(),
                });
            }
            handle.last_activity = handle.last_activity.max(packet.receive_time);
            handle.sent_since_receive = false;
            let space_index = packet_space_index(routing_info.space);
            handle.deferred_spaces[space_index] = true;
            let retained_start = self.pending_deferred_packets.len();
            if emit_output {
                let packets = drain_connection_frames(
                    cx,
                    connection_id,
                    handle,
                    routing_info.space,
                    packet.src_addr,
                    packet.receive_time,
                    now_micros,
                )
                .await?;
                handle.deferred_spaces[space_index] = !packets.is_empty();
                self.pending_deferred_packets.extend(packets);
            }
            Self::refresh_connection_timer(
                cx,
                connection_id,
                handle,
                self.clock_origin,
                now_micros,
                packet.receive_time,
            )?;
            cx.trace(&format!(
                "Routed packet from {} to connection {connection_id:?}",
                packet.src_addr
            ));

            Ok(RoutingResult::Routed {
                connection_id,
                outgoing_packets: self
                    .pending_deferred_packets
                    .split_off(retained_start)
                    .into_iter()
                    .map(|routed| routed.packet)
                    .collect(),
            })
        } else if routing_info.kind == PacketRoutingKind::Initial
            && self.connections.len() >= self.max_connections
        {
            Ok(RoutingResult::Drop {
                reason: format!(
                    "connection limit reached: active={}, max={}",
                    self.connections.len(),
                    self.max_connections
                ),
            })
        } else if routing_info.kind == PacketRoutingKind::Initial {
            let new_connection_id = connection_id;

            cx.trace(&format!(
                "New connection attempt from {} assigned ID {new_connection_id:?}",
                packet.src_addr
            ));

            Ok(RoutingResult::NewConnection {
                connection_id: new_connection_id,
                peer_addr: packet.src_addr,
                triggering_packet: packet,
                outgoing_packets: Vec::new(),
            })
        } else {
            Ok(RoutingResult::Drop {
                reason: format!(
                    "unknown connection ID {connection_id:?} for {:?} packet",
                    routing_info.kind
                ),
            })
        }
    }

    /// Create a new connection and add it to the routing table.
    pub async fn create_connection(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
        peer_addr: SocketAddr,
        is_server: bool,
    ) -> Result<(), ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        if self.connections.contains_key(&connection_id) {
            return Err(ConnectionRouterError::ConnectionCreationFailed(format!(
                "connection ID collision: {connection_id:?}"
            )));
        }
        if self.connections.len() >= self.max_connections {
            return Err(ConnectionRouterError::ConnectionCreationFailed(format!(
                "connection limit reached: active={}, max={}",
                self.connections.len(),
                self.max_connections
            )));
        }

        let mut config = self.config_template;
        config.role = if is_server {
            crate::net::quic_native::StreamRole::Server
        } else {
            crate::net::quic_native::StreamRole::Client
        };

        // Create the QUIC connection state machine
        let connection = NativeQuicConnection::new(config);

        let handle = ConnectionHandle {
            connection: RoutedConnection::Native(connection),
            packet_protection: None,
            peer_addr,
            last_activity: Instant::now(),
            sent_since_receive: false,
            established_at: None,
            next_timer_deadline: None,
            deferred_spaces: [false; 3],
            next_deferred_space: 0,
            local_close_output: None,
            peer_connection_id: None,
            clock_origin: None,
            #[cfg(feature = "tls")]
            authenticated: None,
        };

        self.connections.insert(connection_id, handle);

        cx.trace(&format!(
            "Created new connection {connection_id:?} for peer {peer_addr}"
        ));

        Ok(())
    }

    /// Install packet protection for a managed connection's 1-RTT
    /// UDP handoff path.
    ///
    /// Once installed, application-data frames drained by this router are
    /// assembled as short-header packets and protected before being passed to
    /// the UDP endpoint.
    pub fn install_packet_protection(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
        protection: AtpPacketProtection,
    ) -> Result<(), ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        let handle = self
            .connections
            .get_mut(&connection_id)
            .ok_or(ConnectionRouterError::ConnectionNotFound(connection_id))?;
        handle.packet_protection = Some(ConnectionPacketProtection { protection });
        handle.deferred_spaces[packet_space_index(PacketNumberSpace::ApplicationData)] = true;
        Ok(())
    }

    /// Borrow a managed connection for focused integration tests.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn connection_mut_for_testing(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
    ) -> Result<&mut NativeQuicConnection, ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        self.connections
            .get_mut(&connection_id)
            .map(|handle| &mut *handle.connection)
            .ok_or(ConnectionRouterError::ConnectionNotFound(connection_id))
    }

    /// Arm a unit fixture's real recovery deadline in this router's clock
    /// domain. No packet, timer deadline, or recovery state is manufactured.
    #[cfg(test)]
    pub(crate) fn refresh_connection_timer_for_testing(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
        now_micros: u64,
    ) -> Result<Instant, ConnectionRouterError> {
        cx.checkpoint()
            .map_err(|_| ConnectionRouterError::Cancelled)?;
        let now = self
            .clock_origin
            .checked_add(Duration::from_micros(now_micros))
            .ok_or_else(|| {
                ConnectionRouterError::TimerSchedulingFailed(
                    "test fixture time exceeds router Instant range".to_string(),
                )
            })?;
        let handle = self
            .connections
            .get_mut(&connection_id)
            .ok_or(ConnectionRouterError::ConnectionNotFound(connection_id))?;
        Self::refresh_connection_timer(
            cx,
            connection_id,
            handle,
            self.clock_origin,
            now_micros,
            now,
        )?;
        Ok(now)
    }

    /// Drain one batch of protected application-data packets for focused
    /// integration tests that need to cross the real UDP endpoint boundary.
    #[cfg(any(test, feature = "test-internals"))]
    pub async fn drain_application_data_for_testing(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
        dst_addr: SocketAddr,
        now: Instant,
    ) -> Result<Vec<OutgoingPacket>, ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        let now_micros = self.instant_micros(now);
        let handle = self
            .connections
            .get_mut(&connection_id)
            .ok_or(ConnectionRouterError::ConnectionNotFound(connection_id))?;
        let now_micros = handle
            .clock_origin
            .map_or(now_micros, |origin| instant_micros_from(origin, now));
        Ok(drain_connection_frames(
            cx,
            connection_id,
            handle,
            PacketNumberSpace::ApplicationData,
            dst_addr,
            now,
            now_micros,
        )
        .await?
        .into_iter()
        .map(|routed| routed.packet)
        .collect())
    }

    /// Remove a connection from the routing table.
    pub fn remove_connection(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
    ) -> Result<(), ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        if self.connections.remove(&connection_id).is_some() {
            self.purge_retained_output(connection_id);
            cx.trace(&format!("Removed connection {connection_id:?}"));
            Ok(())
        } else {
            Err(ConnectionRouterError::ConnectionNotFound(connection_id))
        }
    }

    /// Remove a connection from the router and hand ownership to the caller.
    pub fn take_connection(
        &mut self,
        cx: &Cx,
        connection_id: ConnectionId,
    ) -> Result<AcceptedNativeQuicConnection, ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        #[cfg(feature = "tls")]
        if self
            .connections
            .get(&connection_id)
            .is_some_and(|handle| handle.authenticated.is_some())
        {
            return Err(ConnectionRouterError::InvalidConnectionState {
                connection_id,
                reason: "authenticated connection ownership must remain with its managed socket and packet protection".to_string(),
            });
        }

        let handle = self
            .connections
            .remove(&connection_id)
            .ok_or(ConnectionRouterError::ConnectionNotFound(connection_id))?;

        self.purge_retained_output(connection_id);

        cx.trace(&format!(
            "Accepted native QUIC connection {connection_id:?}"
        ));
        Ok(AcceptedNativeQuicConnection {
            connection_id,
            connection: match handle.connection {
                RoutedConnection::Native(connection) => connection,
                #[cfg(feature = "tls")]
                RoutedConnection::Authenticated(_) => unreachable!("refused before removal"),
            },
            peer_addr: handle.peer_addr,
        })
    }

    /// Remove the next routed connection using deterministic connection-ID order.
    pub fn take_next_connection(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<AcceptedNativeQuicConnection>, ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        let Some(connection_id) = self
            .connections
            .keys()
            .min_by(|left, right| left.as_bytes().cmp(right.as_bytes()))
            .copied()
        else {
            return Ok(None);
        };

        self.take_connection(cx, connection_id).map(Some)
    }

    /// Close and remove every active connection.
    pub(crate) fn discard_peer_connections(&mut self, peer: SocketAddr) -> usize {
        let previous = self.connections.len();
        self.connections
            .retain(|_, handle| handle.peer_addr != peer);
        self.pending_timer_packets
            .retain(|routed| self.connections.contains_key(&routed.connection_id));
        self.pending_deferred_packets
            .retain(|routed| self.connections.contains_key(&routed.connection_id));
        previous - self.connections.len()
    }

    /// Terminal local ownership cleanup, including after the context is cancelled.
    pub(crate) fn discard_all(&mut self) {
        self.connections.clear();
        self.pending_timer_packets.clear();
        self.pending_deferred_packets.clear();
        self.deferred_cursor = None;
    }

    fn purge_retained_output(&mut self, connection_id: ConnectionId) {
        self.pending_timer_packets
            .retain(|routed| routed.connection_id != connection_id);
        self.pending_deferred_packets
            .retain(|routed| routed.connection_id != connection_id);
    }

    /// Close and remove every active connection.
    pub fn close_all(
        &mut self,
        cx: &Cx,
        now: Instant,
        app_error_code: u64,
    ) -> Result<usize, ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        let now_micros = self.instant_micros(now);
        for (connection_id, handle) in &mut self.connections {
            let now_micros = handle
                .clock_origin
                .map_or(now_micros, |origin| instant_micros_from(origin, now));
            handle
                .connection
                .begin_close(cx, now_micros, app_error_code)
                .or_else(|_| handle.connection.close_immediately(cx, app_error_code))
                .map_err(|err| ConnectionRouterError::PacketProcessingFailed {
                    connection_id: *connection_id,
                    reason: err.to_string(),
                })?;
        }
        let closed = self.connections.len();
        self.discard_all();
        Ok(closed)
    }

    /// Prepare terminal 1-RTT output without discarding its encryption keys.
    /// Shutdown owns these packets separately from ordinary application output.
    pub(crate) async fn prepare_shutdown_close_packets(
        &mut self,
        cx: &Cx,
        now: Instant,
    ) -> Result<Vec<(OutgoingPacket, Instant)>, ConnectionRouterError> {
        cx.checkpoint()
            .map_err(|_| ConnectionRouterError::Cancelled)?;
        let retained_deadlines: HashMap<_, _> = self
            .connections
            .keys()
            .filter_map(|cid| {
                self.queued_local_close_deadline(*cid)
                    .filter(|deadline| *deadline > now)
                    .map(|deadline| (*cid, deadline))
            })
            .collect();
        let mut packets: Vec<_> = self
            .pending_timer_packets
            .drain(..)
            .chain(self.pending_deferred_packets.drain(..))
            .filter_map(|packet| {
                retained_deadlines
                    .get(&packet.connection_id)
                    .map(|deadline| (packet.packet, *deadline))
            })
            .collect();
        for (connection_id, handle) in &mut self.connections {
            if matches!(
                handle.local_close_output,
                Some(LocalCloseOutput::Queued | LocalCloseOutput::Sent)
            ) {
                // Already committed ciphertext is owned either by this vector
                // or by the endpoint's retained shutdown packet vector.
                continue;
            }
            let origin = handle.clock_origin.unwrap_or(self.clock_origin);
            let now_micros = instant_micros_from(origin, now);
            if !matches!(
                handle.connection.state(),
                QuicConnectionState::Draining | QuicConnectionState::Closed
            ) {
                handle
                    .connection
                    .begin_close(cx, now_micros, 0)
                    .or_else(|_| handle.connection.close_immediately(cx, 0))
                    .map_err(|error| ConnectionRouterError::PacketProcessingFailed {
                        connection_id: *connection_id,
                        reason: error.to_string(),
                    })?;
            }
            if let Some(packet) =
                prepare_local_close_packet(cx, *connection_id, handle, origin, now).await?
            {
                packets.push(packet);
                handle.local_close_output = Some(LocalCloseOutput::Queued);
            }
        }
        Ok(packets)
    }

    /// A peer frame that broke a transport rule has closed this connection
    /// (`process_packet_frames`). Its transport CONNECTION_CLOSE leaves on the
    /// next deferred-output turn, as a requested close does, in every build
    /// (an ATP binary has `tls` without `http3`). A route without packet
    /// protection has no close to send.
    fn request_peer_violation_close(handle: &mut ConnectionHandle) {
        if handle.local_close_output.is_none()
            && handle.connection.local_close_frame_type().is_some()
        {
            handle.local_close_output = Some(LocalCloseOutput::Requested);
            handle.deferred_spaces = [false; 3];
            handle.next_timer_deadline = None;
        }
    }

    /// Refresh a connection's PTO deadline from its transport state.
    fn refresh_connection_timer(
        cx: &Cx,
        connection_id: ConnectionId,
        handle: &mut ConnectionHandle,
        origin: Instant,
        now_micros: u64,
        now_instant: Instant,
    ) -> Result<(), ConnectionRouterError> {
        let now_micros = handle.clock_origin.map_or(now_micros, |origin| {
            instant_micros_from(origin, now_instant)
        });
        let origin = handle.clock_origin.unwrap_or(origin);
        handle.next_timer_deadline = handle
            .connection
            .pto_deadline_micros(cx, now_micros)
            .map_err(|err| ConnectionRouterError::PacketProcessingFailed {
                connection_id,
                reason: err.to_string(),
            })?
            .and_then(|deadline| {
                let delta = deadline.saturating_sub(now_micros);
                origin
                    .checked_add(Duration::from_micros(deadline))
                    .or_else(|| now_instant.checked_add(Duration::from_micros(delta)))
            });
        Ok(())
    }

    /// Get the next timer deadline across all connections.
    pub fn next_timer_deadline(&self) -> Option<Instant> {
        self.connections
            .values()
            .flat_map(|handle| {
                let recovery = (!matches!(
                    handle.connection.state(),
                    QuicConnectionState::Closed | QuicConnectionState::Draining
                ))
                .then_some(handle.next_timer_deadline)
                .flatten();
                [recovery, self.lifecycle_deadline(handle)]
                    .into_iter()
                    .flatten()
            })
            .min()
    }

    fn lifecycle_deadline(&self, handle: &ConnectionHandle) -> Option<Instant> {
        let origin = handle.clock_origin.unwrap_or(self.clock_origin);
        match handle.connection.state() {
            QuicConnectionState::Closed => Some(origin),
            QuicConnectionState::Draining => handle
                .connection
                .transport()
                .drain_deadline_micros()
                .and_then(|micros| origin.checked_add(Duration::from_micros(micros))),
            _ => {
                let timeout = [
                    handle.connection.negotiated_idle_timeout_micros(),
                    self.idle_timeout_micros,
                ]
                .into_iter()
                .flatten()
                .min()?
                .max(handle.connection.transport().idle_timeout_floor_micros());
                handle
                    .last_activity
                    .checked_add(Duration::from_micros(timeout))
            }
        }
    }

    pub(crate) fn expired_connections(&self, now: Instant) -> Vec<ConnectionId> {
        let mut expired: Vec<_> = self
            .connections
            .iter()
            .filter_map(|(cid, handle)| {
                self.lifecycle_deadline(handle)
                    .filter(|deadline| *deadline <= now)
                    .map(|_| *cid)
            })
            .collect();
        expired.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        expired
    }

    pub(crate) fn connection_is_terminal(&self, cid: ConnectionId) -> bool {
        self.connections.get(&cid).is_some_and(|handle| {
            matches!(
                handle.connection.state(),
                QuicConnectionState::Closed | QuicConnectionState::Draining
            )
        })
    }

    /// Ordinary terminal output is discarded. A requested local close is the
    /// only terminal packet retained until UDP reports that packet was sent.
    pub(crate) fn connection_can_send_queued(&self, cid: ConnectionId) -> bool {
        !self.connection_is_terminal(cid)
            || self
                .connections
                .get(&cid)
                .is_some_and(|handle| handle.local_close_output == Some(LocalCloseOutput::Queued))
    }

    /// Deadline for the sole committed local-close packet, wherever its current
    /// owner retained it. Shutdown transfers that ciphertext without reassembly.
    pub(crate) fn queued_local_close_deadline(&self, cid: ConnectionId) -> Option<Instant> {
        let handle = self.connections.get(&cid)?;
        (handle.local_close_output == Some(LocalCloseOutput::Queued))
            .then(|| self.lifecycle_deadline(handle))
            .flatten()
    }

    fn discard_terminal_output(&mut self) {
        let terminal: HashSet<_> = self
            .connections
            .keys()
            .copied()
            .filter(|cid| !self.connection_can_send_queued(*cid))
            .collect();
        self.pending_timer_packets
            .retain(|packet| !terminal.contains(&packet.connection_id));
        self.pending_deferred_packets
            .retain(|packet| !terminal.contains(&packet.connection_id));
    }

    /// Hand off already committed timer output before a restarted managed loop
    /// parks on a future deadline. The caller checks cancellation and supplies
    /// its available queue capacity; no packet is generated or recommitted.
    pub(crate) fn take_pending_timer_output(
        &mut self,
        max_packets: usize,
    ) -> Vec<RoutedOutgoingPacket> {
        self.discard_terminal_output();
        let count = max_packets.min(self.pending_timer_packets.len());
        self.pending_timer_packets.drain(..count).collect()
    }

    /// Process timer events for connections.
    pub async fn process_timer_events(
        &mut self,
        cx: &Cx,
        current_time: Instant,
    ) -> Result<Vec<OutgoingPacket>, ConnectionRouterError> {
        Ok(self
            .process_managed_timer_events(cx, current_time, &HashSet::new())
            .await?
            .into_iter()
            .map(|routed| routed.packet)
            .collect())
    }

    /// Rearm due timers, retaining CID ownership until the managed endpoint
    /// takes each packet. An already committed packet waiting anywhere in the
    /// managed send path suppresses another probe for that same connection.
    pub(crate) async fn process_managed_timer_events(
        &mut self,
        cx: &Cx,
        current_time: Instant,
        pending_connections: &HashSet<ConnectionId>,
    ) -> Result<Vec<RoutedOutgoingPacket>, ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        for cid in self.expired_connections(current_time) {
            self.remove_connection(cx, cid)?;
        }
        self.discard_terminal_output();

        let origin = self.clock_origin;

        let mut connection_ids: Vec<_> = self.connections.keys().copied().collect();
        connection_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        for (index, connection_id) in connection_ids.into_iter().enumerate() {
            if index > 0 && index % TIMER_CONNECTIONS_PER_TURN == 0 {
                // Completed packets are already router-owned. Dropping this
                // future at the yield cannot lose them or recommit those probes.
                crate::runtime::yield_now().await;
                cx.checkpoint()
                    .map_err(|_| ConnectionRouterError::Cancelled)?;
            }
            let handle = self
                .connections
                .get_mut(&connection_id)
                .expect("snapshot CID");
            if matches!(
                handle.connection.state(),
                QuicConnectionState::Closed | QuicConnectionState::Draining
            ) {
                continue;
            }
            let origin = handle.clock_origin.unwrap_or(origin);
            if let Some(deadline) = handle.next_timer_deadline {
                if current_time >= deadline {
                    cx.trace(&format!(
                        "Timer fired for connection {connection_id:?} at {current_time:?}"
                    ));

                    handle.next_timer_deadline = None;
                    let now_micros = instant_micros_from(origin, current_time);
                    match handle.connection.on_managed_probe_timeout(cx, now_micros) {
                        Ok(Some(next)) => {
                            handle.next_timer_deadline =
                                origin.checked_add(Duration::from_micros(next));
                        }
                        Ok(None) => continue,
                        Err(error) => {
                            if cx.checkpoint().is_err() {
                                return Err(ConnectionRouterError::Cancelled);
                            }
                            cx.trace(&format!("QUIC timer failed for {connection_id:?}: {error}"));
                            continue;
                        }
                    }
                    if pending_connections.contains(&connection_id)
                        || self
                            .pending_timer_packets
                            .iter()
                            .any(|routed| routed.connection_id == connection_id)
                        || self
                            .pending_deferred_packets
                            .iter()
                            .any(|routed| routed.connection_id == connection_id)
                    {
                        cx.trace(&format!(
                            "QUIC PTO rearmed without another queued probe for {connection_id:?}"
                        ));
                        continue;
                    }
                    let peer_addr = handle.peer_addr;
                    match drain_connection_frames_inner(
                        cx,
                        connection_id,
                        handle,
                        PacketNumberSpace::ApplicationData,
                        peer_addr,
                        current_time,
                        instant_micros_from(origin, current_time),
                        true,
                    )
                    .await
                    {
                        Ok(packets) => self.pending_timer_packets.extend(packets),
                        Err(ConnectionRouterError::Cancelled) => {
                            return Err(ConnectionRouterError::Cancelled);
                        }
                        Err(error) => {
                            cx.trace(&format!(
                                "QUIC timer output failed for {connection_id:?}: {error}"
                            ));
                            continue;
                        }
                    }
                    if let Err(error) = Self::refresh_connection_timer(
                        cx,
                        connection_id,
                        handle,
                        origin,
                        instant_micros_from(origin, current_time),
                        current_time,
                    ) {
                        if cx.checkpoint().is_err() {
                            return Err(ConnectionRouterError::Cancelled);
                        }
                        cx.trace(&format!(
                            "QUIC timer rearm failed for {connection_id:?}: {error}"
                        ));
                    }
                }
            }
        }

        Ok(std::mem::take(&mut self.pending_timer_packets))
    }

    /// Drain deferred packet spaces up to the managed owner's available packet
    /// capacity. The retained prefix belongs to the router until a successful
    /// return, including cancellation after an earlier connection committed.
    /// A sorted, rotating CID order and rotating packet spaces avoid starving a
    /// peer when the caller repeatedly has room for only one packet.
    pub(crate) async fn drain_deferred_output(
        &mut self,
        cx: &Cx,
        now: Instant,
        max_packets: usize,
    ) -> Result<Vec<RoutedOutgoingPacket>, ConnectionRouterError> {
        cx.checkpoint()
            .map_err(|_| ConnectionRouterError::Cancelled)?;
        self.discard_terminal_output();
        if max_packets == 0 {
            return Ok(Vec::new());
        }
        let mut connection_ids: Vec<_> = self.connections.keys().copied().collect();
        connection_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if let Some(cursor) = self.deferred_cursor {
            let next = connection_ids.partition_point(|id| id.as_bytes() <= cursor.as_bytes());
            connection_ids.rotate_left(next);
        }
        let now_micros = self.instant_micros(now);
        for (index, connection_id) in connection_ids.into_iter().enumerate() {
            if self.pending_deferred_packets.len() >= max_packets {
                break;
            }
            if index > 0 && index % TIMER_CONNECTIONS_PER_TURN == 0 {
                crate::runtime::yield_now().await;
            }
            cx.checkpoint()
                .map_err(|_| ConnectionRouterError::Cancelled)?;
            let handle = self
                .connections
                .get_mut(&connection_id)
                .expect("snapshot CID");
            let now_micros = handle
                .clock_origin
                .map_or(now_micros, |origin| instant_micros_from(origin, now));
            if handle.local_close_output == Some(LocalCloseOutput::Requested) {
                let origin = handle.clock_origin.unwrap_or(self.clock_origin);
                match prepare_local_close_packet(cx, connection_id, handle, origin, now).await {
                    Ok(Some((packet, _))) => {
                        // Packet-number/amplification accounting commits inside
                        // protection. Store the packet before any yield.
                        self.pending_deferred_packets.push(RoutedOutgoingPacket {
                            connection_id,
                            packet,
                            final_handshake_flight: false,
                            ack_eliciting: false,
                        });
                        handle.local_close_output = Some(LocalCloseOutput::Queued);
                    }
                    Ok(None) => handle.local_close_output = None,
                    Err(error) => {
                        if cx.checkpoint().is_err() || error == ConnectionRouterError::Cancelled {
                            return Err(ConnectionRouterError::Cancelled);
                        }
                        // A failed close for one peer must not stop healthy
                        // routes. Its existing drain deadline still retires it.
                        handle.local_close_output = None;
                        cx.trace(&format!(
                            "QUIC local close failed for {connection_id:?}: {error}"
                        ));
                    }
                }
                self.deferred_cursor = Some(connection_id);
                continue;
            }
            let first_space = handle.next_deferred_space;
            for offset in 0..3 {
                if self.pending_deferred_packets.len() >= max_packets {
                    break;
                }
                let index = (first_space + offset) % 3;
                if !handle.deferred_spaces[index] {
                    continue;
                }
                self.deferred_cursor = Some(connection_id);
                handle.next_deferred_space = (index + 1) % 3;
                let space = [
                    PacketNumberSpace::Initial,
                    PacketNumberSpace::Handshake,
                    PacketNumberSpace::ApplicationData,
                ][index];
                let peer_addr = handle.peer_addr;
                match drain_connection_frames(
                    cx,
                    connection_id,
                    handle,
                    space,
                    peer_addr,
                    now,
                    now_micros,
                )
                .await
                {
                    Ok(packets) => {
                        // Empty (including cwnd blocked) is not readiness. New
                        // input/ACK marks the space again; nonempty output gets
                        // one later opportunity to drain the remaining frames.
                        handle.deferred_spaces[index] = !packets.is_empty();
                        self.pending_deferred_packets.extend(packets);
                    }
                    Err(error) => {
                        if cx.checkpoint().is_err() || error == ConnectionRouterError::Cancelled {
                            return Err(ConnectionRouterError::Cancelled);
                        }
                        cx.trace(&format!(
                            "QUIC deferred output failed for {connection_id:?}: {error}"
                        ));
                    }
                }
                if let Err(error) = Self::refresh_connection_timer(
                    cx,
                    connection_id,
                    handle,
                    self.clock_origin,
                    now_micros,
                    now,
                ) {
                    if cx.checkpoint().is_err() {
                        return Err(ConnectionRouterError::Cancelled);
                    }
                    cx.trace(&format!(
                        "QUIC deferred timer refresh failed for {connection_id:?}: {error}"
                    ));
                }
            }
        }
        let count = max_packets.min(self.pending_deferred_packets.len());
        Ok(self.pending_deferred_packets.drain(..count).collect())
    }

    /// Get connection statistics for observability.
    pub fn connection_stats(&self) -> ConnectionRouterStats {
        let active_connections = self.connections.len();
        let established_connections = self
            .connections
            .values()
            .filter(|h| h.established_at.is_some())
            .count();

        ConnectionRouterStats {
            active_connections,
            established_connections,
            pending_connections: active_connections - established_connections,
        }
    }

    /// Routing needs only the header-protection-invariant prefix.
    ///
    /// RFC 9001 §5.4: form/type bits and the destination CID are readable on
    /// the wire; the packet number and key phase are masked and only become
    /// readable inside the connection's own unprotect step.
    fn decode_routing_info(
        &self,
        packet: &ReceivedPacket,
    ) -> Result<PacketRoutingInfo, QuicCoreError> {
        if packet.data.first().is_some_and(|first| first & 0x80 != 0) {
            let prefix = ProtectedHeaderPrefix::decode(&packet.data, 0)?;
            return Ok(PacketRoutingInfo::from_prefix(&prefix));
        }

        for cid_len in self.known_connection_id_lengths() {
            if let Ok(prefix) = ProtectedHeaderPrefix::decode(&packet.data, cid_len) {
                let info = PacketRoutingInfo::from_prefix(&prefix);
                if self.connections.contains_key(&info.destination_cid) {
                    return Ok(info);
                }
            }
        }

        let prefix = ProtectedHeaderPrefix::decode(&packet.data, 0)?;
        Ok(PacketRoutingInfo::from_prefix(&prefix))
    }

    fn known_connection_id_lengths(&self) -> Vec<usize> {
        let mut lengths = self
            .connections
            .keys()
            .map(ConnectionId::len)
            .collect::<Vec<_>>();
        lengths.sort_unstable_by(|a, b| b.cmp(a));
        lengths.dedup();
        if !lengths.contains(&0) {
            lengths.push(0);
        }
        lengths
    }

    fn instant_micros(&self, instant: Instant) -> u64 {
        instant_micros_from(self.clock_origin, instant)
    }

    /// Allocate a new connection ID.
    pub(crate) fn allocate_connection_id(&mut self) -> ConnectionId {
        let id = self.next_connection_id;
        self.next_connection_id += 1;

        // Create connection ID from counter
        let id_bytes = id.to_be_bytes();
        ConnectionId::new(&id_bytes).expect("Connection ID from counter should always be valid")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketRoutingKind {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
    Retry,
}

#[derive(Debug, Clone)]
struct PacketRoutingInfo {
    destination_cid: ConnectionId,
    kind: PacketRoutingKind,
    space: PacketNumberSpace,
}

impl PacketRoutingInfo {
    fn from_prefix(prefix: &ProtectedHeaderPrefix) -> Self {
        match prefix {
            ProtectedHeaderPrefix::Long(header) => {
                let (kind, space) = match header.packet_type {
                    LongPacketType::Initial => {
                        (PacketRoutingKind::Initial, PacketNumberSpace::Initial)
                    }
                    LongPacketType::ZeroRtt => (
                        PacketRoutingKind::ZeroRtt,
                        PacketNumberSpace::ApplicationData,
                    ),
                    LongPacketType::Handshake => {
                        (PacketRoutingKind::Handshake, PacketNumberSpace::Handshake)
                    }
                    LongPacketType::Retry => (PacketRoutingKind::Retry, PacketNumberSpace::Initial),
                };
                Self {
                    destination_cid: header.dst_cid,
                    kind,
                    space,
                }
            }
            ProtectedHeaderPrefix::Retry(header) => Self {
                destination_cid: header.dst_cid,
                kind: PacketRoutingKind::Retry,
                space: PacketNumberSpace::Initial,
            },
            ProtectedHeaderPrefix::Short { dst_cid, .. } => Self {
                destination_cid: *dst_cid,
                kind: PacketRoutingKind::OneRtt,
                space: PacketNumberSpace::ApplicationData,
            },
        }
    }
}

/// Packet number and payload of a legacy plaintext long-header packet.
///
/// The lab/loopback transitions never derive keys, so their headers carry no
/// protection and are fully decodable on the wire.
fn plaintext_packet_payload(
    connection_id: ConnectionId,
    data: &[u8],
) -> Result<(u64, Vec<u8>), ConnectionRouterError> {
    let (header, header_len) = PacketHeader::decode(data, connection_id.len()).map_err(|err| {
        ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: format!("invalid QUIC header: {err}"),
        }
    })?;
    let packet_number = match header {
        PacketHeader::Long(header) => header.packet_number,
        PacketHeader::Retry(_) => 0,
        PacketHeader::Short(header) => header.packet_number,
    };
    let payload =
        data.get(header_len..)
            .ok_or_else(|| ConnectionRouterError::PacketProcessingFailed {
                connection_id,
                reason: "header length exceeded datagram length".to_string(),
            })?;
    Ok((packet_number, payload.to_vec()))
}

fn instant_micros_from(origin: Instant, instant: Instant) -> u64 {
    instant
        .checked_duration_since(origin)
        .unwrap_or(Duration::ZERO)
        .as_micros()
        .min(u128::from(u64::MAX)) as u64
}

fn packet_space_index(space: PacketNumberSpace) -> usize {
    match space {
        PacketNumberSpace::Initial => 0,
        PacketNumberSpace::Handshake => 1,
        PacketNumberSpace::ApplicationData => 2,
    }
}

/// Protect the already-recorded local close without admitting any application
/// output. Both endpoint shutdown and per-route retirement use this path.
async fn prepare_local_close_packet(
    cx: &Cx,
    connection_id: ConnectionId,
    handle: &mut ConnectionHandle,
    origin: Instant,
    now: Instant,
) -> Result<Option<(OutgoingPacket, Instant)>, ConnectionRouterError> {
    let Some(protection) = handle.packet_protection.as_mut() else {
        return Ok(None);
    };
    let Some(code) = handle.connection.transport().close_code() else {
        return Ok(None);
    };
    let Outcome::Ok(error_code) = crate::net::atp::protocol::varint::VarInt::new(code) else {
        return Err(ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: "close code exceeds QUIC varint range".to_string(),
        });
    };
    let frames = [QuicFrame::ConnectionClose {
        error_code,
        frame_type: handle.connection.local_close_frame_type(),
        reason_phrase: crate::bytes::Bytes::new(),
    }];
    if !handle.connection.is_local_close_frame(&frames) {
        return Ok(None);
    }
    let Some(deadline) = handle
        .connection
        .transport()
        .drain_deadline_micros()
        .and_then(|micros| origin.checked_add(Duration::from_micros(micros)))
        .filter(|deadline| *deadline > now)
    else {
        return Ok(None);
    };
    let mut payload = crate::bytes::BytesMut::new();
    NativeQuicConnection::encode_frames(&frames, &mut payload).map_err(|error| {
        ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: error.to_string(),
        }
    })?;
    let data = assemble_protected_1rtt_packet_inner(
        cx,
        handle.peer_connection_id.unwrap_or(connection_id),
        &mut handle.connection,
        &mut protection.protection,
        &frames,
        payload.as_ref(),
        instant_micros_from(origin, now),
        false,
        false,
    )
    .await?;
    Ok(Some((
        OutgoingPacket {
            dst_addr: handle.peer_addr,
            data,
            send_time: Some(now),
        },
        deadline,
    )))
}

async fn drain_connection_frames(
    cx: &Cx,
    connection_id: ConnectionId,
    handle: &mut ConnectionHandle,
    space: PacketNumberSpace,
    dst_addr: SocketAddr,
    now: Instant,
    now_micros: u64,
) -> Result<Vec<RoutedOutgoingPacket>, ConnectionRouterError> {
    drain_connection_frames_inner(
        cx,
        connection_id,
        handle,
        space,
        dst_addr,
        now,
        now_micros,
        false,
    )
    .await
}

async fn drain_connection_frames_inner(
    cx: &Cx,
    connection_id: ConnectionId,
    handle: &mut ConnectionHandle,
    space: PacketNumberSpace,
    dst_addr: SocketAddr,
    now: Instant,
    now_micros: u64,
    pto_probe: bool,
) -> Result<Vec<RoutedOutgoingPacket>, ConnectionRouterError> {
    if matches!(
        handle.connection.state(),
        QuicConnectionState::Closed | QuicConnectionState::Draining
    ) {
        return Ok(Vec::new());
    }
    let destination_cid = handle.peer_connection_id.unwrap_or(connection_id);
    let max_frame_bytes = if space == PacketNumberSpace::ApplicationData {
        if handle.packet_protection.is_none() {
            return Err(ConnectionRouterError::PacketProtectionUnavailable { connection_id });
        }
        PROTECTED_1RTT_MAX_PACKET_BYTES
            .saturating_sub(protected_1rtt_packet_len(destination_cid, 0))
    } else {
        PROTECTED_1RTT_MAX_PACKET_BYTES
    };
    if space == PacketNumberSpace::ApplicationData {
        // Keep DATAGRAM admission in step with the exact packet budget this
        // assembler enforces (GH#66).
        handle.connection.set_one_rtt_frame_budget(max_frame_bytes);
    }
    let frames = if pto_probe {
        handle
            .connection
            .generate_pto_probe_frames(cx, max_frame_bytes)
    } else if space == PacketNumberSpace::ApplicationData {
        generate_congestion_admitted_1rtt_frames(cx, &mut handle.connection, max_frame_bytes)
    } else {
        handle
            .connection
            .generate_frames(cx, space, max_frame_bytes)
    }
    .map_err(|err| ConnectionRouterError::PacketProcessingFailed {
        connection_id,
        reason: err.to_string(),
    })?;
    if frames.is_empty() {
        return Ok(Vec::new());
    }

    let mut payload = crate::bytes::BytesMut::new();
    NativeQuicConnection::encode_frames(&frames, &mut payload).map_err(
        |err: NativeQuicConnectionError| ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: err.to_string(),
        },
    )?;
    let data = if space == PacketNumberSpace::ApplicationData {
        match handle.packet_protection.as_mut() {
            Some(packet_protection) => {
                assemble_protected_1rtt_packet_inner(
                    cx,
                    destination_cid,
                    &mut handle.connection,
                    &mut packet_protection.protection,
                    &frames,
                    payload.as_ref(),
                    now_micros,
                    frames.iter().any(is_ack_eliciting),
                    pto_probe,
                )
                .await
            }
            None => Err(ConnectionRouterError::PacketProtectionUnavailable { connection_id }),
        }
    } else {
        Ok(payload.to_vec())
    };
    let data = match data {
        Ok(data) => data,
        Err(error) => {
            if !pto_probe {
                handle
                    .connection
                    .on_generated_frames_dropped(&frames)
                    .map_err(|recovery_error| ConnectionRouterError::PacketProcessingFailed {
                        connection_id,
                        reason: format!(
                            "packet assembly failed ({error}); reliable-frame requeue failed: {recovery_error}"
                        ),
                    })?;
            }
            return Err(error);
        }
    };

    Ok(vec![RoutedOutgoingPacket {
        connection_id,
        packet: OutgoingPacket {
            dst_addr,
            data,
            send_time: Some(now),
        },
        final_handshake_flight: false,
        ack_eliciting: frames.iter().any(is_ack_eliciting),
    }])
}

#[cfg(test)]
pub(crate) async fn assemble_protected_1rtt_packet(
    cx: &Cx,
    connection_id: ConnectionId,
    connection: &mut NativeQuicConnection,
    packet_protection: &mut AtpPacketProtection,
    frames: &[QuicFrame],
    payload: &[u8],
    now_micros: u64,
    ack_eliciting: bool,
) -> Result<Vec<u8>, ConnectionRouterError> {
    assemble_protected_1rtt_packet_inner(
        cx,
        connection_id,
        connection,
        packet_protection,
        frames,
        payload,
        now_micros,
        ack_eliciting,
        false,
    )
    .await
}

/// Every native 1-RTT assembler uses the same rotation and exhaustion policy.
/// Checking per packet also covers a batch that crosses the soft threshold,
/// PTO probes, and a final close packet. Already protected retained packets
/// never pass through this function again and keep their original key/nonce.
fn prepare_one_rtt_send_key(
    cx: &Cx,
    connection_id: ConnectionId,
    connection: &mut NativeQuicConnection,
    packet_protection: &mut AtpPacketProtection,
) -> Result<(), ConnectionRouterError> {
    cx.checkpoint()
        .map_err(|_| ConnectionRouterError::Cancelled)?;
    let space = PacketProtectionSpace::OneRtt;
    let mut rotation_failure = None;
    if packet_protection.confidentiality_key_update_due(space)
        && connection.can_initiate_local_key_update()
    {
        let next_phase = !connection.tls().local_key_phase();
        // Eligibility is checked before advancing the bidirectional rustls
        // ratchet. Receiving the peer's phase bit is not a substitute for an
        // ACK of our current generation (RFC 9001 section 6.1).
        match packet_protection.ensure_next_gen_keys(cx, space, next_phase) {
            Outcome::Ok(()) => {
                connection
                    .request_local_key_update(cx)
                    .and_then(|_| connection.commit_local_key_update(cx))
                    .map_err(|error| {
                        if matches!(error, NativeQuicConnectionError::Cancelled) {
                            ConnectionRouterError::Cancelled
                        } else {
                            ConnectionRouterError::PacketProcessingFailed {
                                connection_id,
                                reason: format!("1-RTT key update failed: {error}"),
                            }
                        }
                    })?;
                packet_protection.note_local_key_update(space);
            }
            Outcome::Err(error) => {
                rotation_failure = Some(format!("1-RTT key update failed: {error:?}"));
            }
            Outcome::Cancelled(_) => return Err(ConnectionRouterError::Cancelled),
            Outcome::Panicked(payload) => {
                rotation_failure = Some(format!("1-RTT key update panicked: {payload:?}"));
            }
        }
    }
    if packet_protection.confidentiality_limit_reached(space) {
        // No CONNECTION_CLOSE can be encrypted with an exhausted key. Stop
        // locally with AEAD_LIMIT_REACHED; the router reaps the closed owner.
        connection
            .close_immediately(cx, 0x0f)
            .map_err(|_| ConnectionRouterError::Cancelled)?;
        return Err(ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: "AEAD_LIMIT_REACHED: 1-RTT confidentiality limit exhausted".to_owned(),
        });
    }
    if let Some(reason) = rotation_failure {
        return Err(ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason,
        });
    }
    Ok(())
}

pub(crate) async fn assemble_protected_1rtt_packet_inner(
    cx: &Cx,
    connection_id: ConnectionId,
    connection: &mut NativeQuicConnection,
    packet_protection: &mut AtpPacketProtection,
    frames: &[QuicFrame],
    payload: &[u8],
    now_micros: u64,
    ack_eliciting: bool,
    pto_probe: bool,
) -> Result<Vec<u8>, ConnectionRouterError> {
    let packet_len = protected_1rtt_packet_len(connection_id, payload.len());
    if packet_len > PROTECTED_1RTT_MAX_PACKET_BYTES {
        return Err(ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: format!(
                "protected 1-RTT packet length {packet_len} exceeds max {PROTECTED_1RTT_MAX_PACKET_BYTES}"
            ),
        });
    }
    let local_close = !pto_probe && !ack_eliciting && connection.is_local_close_frame(frames);
    if local_close {
        connection
            .validate_local_close_packet(cx, packet_len as u64, frames)
            .map_err(|err| ConnectionRouterError::PacketProcessingFailed {
                connection_id,
                reason: err.to_string(),
            })?;
    }
    let packet_number = connection
        .next_packet_number_for_protection(PacketNumberSpace::ApplicationData)
        .map_err(|err| ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: err.to_string(),
        })?;
    prepare_one_rtt_send_key(cx, connection_id, connection, packet_protection)?;
    let key_phase = connection.tls().local_key_phase();
    let header = PacketHeader::Short(ShortHeader {
        spin: false,
        key_phase,
        dst_cid: connection_id,
        packet_number,
        packet_number_len: PROTECTED_1RTT_PACKET_NUMBER_LEN,
    });
    let mut header_bytes = Vec::new();
    header.encode(&mut header_bytes).map_err(|err| {
        ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: err.to_string(),
        }
    })?;
    let protected = match packet_protection
        .protect_packet(
            cx,
            PacketProtectionRequest {
                space: PacketProtectionSpace::OneRtt,
                key_phase,
                packet_number,
                associated_data: &header_bytes,
                payload,
            },
        )
        .await
    {
        Outcome::Ok(packet) => packet,
        Outcome::Err(err) => {
            return Err(ConnectionRouterError::PacketProcessingFailed {
                connection_id,
                reason: format!("1-RTT packet protection failed: {err:?}"),
            });
        }
        Outcome::Cancelled(_) => return Err(ConnectionRouterError::Cancelled),
        Outcome::Panicked(payload) => {
            return Err(ConnectionRouterError::PacketProcessingFailed {
                connection_id,
                reason: format!("1-RTT packet protection panicked: {payload:?}"),
            });
        }
    };

    // Finish the wire bytes, including header protection (RFC 9001 §5.4,
    // GH#69), before the packet is committed as sent: a failure here must
    // not leave the connection believing a packet left that never did.
    let mut packet =
        Vec::with_capacity(header_bytes.len() + protected.ciphertext.len() + protected.tag.len());
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(&protected.ciphertext);
    packet.extend_from_slice(&protected.tag);
    let packet_number_offset = 1 + connection_id.len();
    let sample = header_protection_sample(&packet, packet_number_offset).map_err(|err| {
        ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: format!("1-RTT header protection sample: {err}"),
        }
    })?;
    let mask = match packet_protection.header_protection_mask_now(
        cx,
        PacketProtectionSpace::OneRtt,
        &sample,
    ) {
        Outcome::Ok(mask) => mask,
        Outcome::Err(err) => {
            return Err(ConnectionRouterError::PacketProcessingFailed {
                connection_id,
                reason: format!("1-RTT header protection failed: {err:?}"),
            });
        }
        Outcome::Cancelled(_) => return Err(ConnectionRouterError::Cancelled),
        Outcome::Panicked(payload) => {
            return Err(ConnectionRouterError::PacketProcessingFailed {
                connection_id,
                reason: format!("1-RTT header protection panicked: {payload:?}"),
            });
        }
    };
    apply_header_protection(&mut packet, packet_number_offset, mask.bytes).map_err(|err| {
        ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: format!("1-RTT header protection apply: {err}"),
        }
    })?;

    let committed_packet_number = if local_close {
        connection.on_local_close_packet_sent(cx, packet_len as u64, frames)
    } else if pto_probe {
        connection.on_pto_probe_packet_sent(cx, packet_len as u64, now_micros, frames)
    } else {
        connection.on_packet_sent_with_frames(
            cx,
            PacketNumberSpace::ApplicationData,
            packet_len as u64,
            ack_eliciting,
            ack_eliciting,
            now_micros,
            frames,
        )
    }
    .map_err(|err| ConnectionRouterError::PacketProcessingFailed {
        connection_id,
        reason: err.to_string(),
    })?;
    debug_assert_eq!(committed_packet_number, packet_number);
    Ok(packet)
}

/// One authenticated 1-RTT packet: the unmasked short header (with the full,
/// reconstructed packet number), the plaintext payload, and whether this
/// packet was accepted as a genuine peer key update under next-generation keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unprotected1RttPacket {
    pub(crate) header: ShortHeader,
    pub(crate) plaintext: Vec<u8>,
    pub(crate) peer_key_update: bool,
}

/// Remove header protection from a received 1-RTT datagram addressed to
/// `connection_id` and authenticate it. See [`unprotect_1rtt_packet_now`].
pub(crate) async fn unprotect_1rtt_packet(
    cx: &Cx,
    connection_id: ConnectionId,
    packet_protection: &mut AtpPacketProtection,
    packet: &[u8],
) -> Result<Unprotected1RttPacket, ConnectionRouterError> {
    unprotect_1rtt_packet_now(cx, connection_id, packet_protection, None, packet)
}

/// Remove header protection and authenticate a 1-RTT datagram with connection
/// context to accurately disambiguate peer key updates (RFC 9001 §6.3).
pub(crate) async fn unprotect_1rtt_packet_with_connection(
    cx: &Cx,
    connection_id: ConnectionId,
    packet_protection: &mut AtpPacketProtection,
    connection: Option<&NativeQuicConnection>,
    packet: &[u8],
) -> Result<Unprotected1RttPacket, ConnectionRouterError> {
    unprotect_1rtt_packet_now(cx, connection_id, packet_protection, connection, packet)
}

/// Recognize an authenticated Handshake ACK without mistaking it for a
/// retransmitted TLS flight.
///
/// `packet` is one long-header packet bounded by its Length field: the router
/// classifies each packet of a coalesced datagram on its own. Unknown or
/// invalid packets keep the existing recovery behavior; only verified
/// ACK/PADDING is suppressed.
pub(crate) fn authenticated_handshake_ack_only(
    cx: &Cx,
    connection_id: ConnectionId,
    protection: &mut AtpPacketProtection,
    packet: &[u8],
) -> bool {
    let Ok(ProtectedHeaderPrefix::Long(prefix)) = ProtectedHeaderPrefix::decode(packet, 0) else {
        return false;
    };
    if prefix.packet_type != LongPacketType::Handshake || prefix.dst_cid != connection_id {
        return false;
    }
    let space = PacketProtectionSpace::Handshake;
    let offset = prefix.packet_number_offset;
    let Ok(sample) = header_protection_sample(packet, offset) else {
        return false;
    };
    let Outcome::Ok(mask) = protection.header_protection_mask_remote_now(cx, space, &sample) else {
        return false;
    };
    let mut bytes = packet.to_vec();
    let Ok(width) = remove_header_protection(&mut bytes, offset, mask.bytes) else {
        return false;
    };
    let header_len = offset + usize::from(width);
    if bytes.len() < header_len + PROTECTED_1RTT_TAG_LEN {
        return false;
    }
    let truncated = bytes[offset..header_len]
        .iter()
        .fold(0u32, |acc, byte| (acc << 8) | u32::from(*byte));
    let Ok(number) = decode_packet_number_reconstruct(
        truncated,
        width,
        protection
            .highest_accepted_packet_number(space)
            .unwrap_or(0),
    ) else {
        return false;
    };
    let tag_start = bytes.len() - PROTECTED_1RTT_TAG_LEN;
    let protected = ProtectedPacket {
        space,
        key_phase: false,
        packet_number: number,
        ciphertext: bytes[header_len..tag_start].to_vec(),
        tag: bytes[tag_start..].try_into().expect("tag length checked"),
        proof: ProtectionProof {
            provider_kind: protection.provider_kind(),
            space,
            key_phase: false,
            generation: 0,
            transcript_hash: TranscriptHash::from_bytes([0; 32]),
            failure_code: None,
        },
    };
    let Outcome::Ok(plaintext) =
        protection.inspect_handshake_packet_now(cx, &protected, &bytes[..header_len])
    else {
        return false;
    };
    let Ok((PacketHeader::Long(header), consumed)) = PacketHeader::decode(&bytes, 0) else {
        return false;
    };
    if consumed != header_len || header.payload_length != (bytes.len() - offset) as u64 {
        return false;
    }
    let Ok(frames) = NativeQuicConnection::decode_frames(&plaintext.plaintext) else {
        return false;
    };
    frames
        .iter()
        .any(|frame| matches!(frame, QuicFrame::Ack { .. }))
        && frames
            .iter()
            .all(|frame| matches!(frame, QuicFrame::Ack { .. } | QuicFrame::Padding { .. }))
}

/// Unmask and authenticate one short-header packet on the current task.
///
/// RFC 9001 §5.4.1 receiver order (GH#69): read the invariant prefix, sample
/// the ciphertext, unmask the first byte and the packet number with the
/// peer's header-protection key, reconstruct the full packet number against
/// the largest one accepted so far, AEAD-open with the unmasked header as
/// associated data, and only then validate the reserved bits (RFC 9000
/// §17.3.1 checks them after packet protection is removed).
fn unprotect_1rtt_packet_now(
    cx: &Cx,
    connection_id: ConnectionId,
    packet_protection: &mut AtpPacketProtection,
    connection: Option<&NativeQuicConnection>,
    packet: &[u8],
) -> Result<Unprotected1RttPacket, ConnectionRouterError> {
    let failed = |reason: String| ConnectionRouterError::PacketProcessingFailed {
        connection_id,
        reason,
    };
    let prefix = ProtectedHeaderPrefix::decode(packet, connection_id.len())
        .map_err(|err| failed(format!("invalid 1-RTT header: {err}")))?;
    let ProtectedHeaderPrefix::Short {
        dst_cid,
        packet_number_offset,
    } = prefix
    else {
        return Err(failed("expected a 1-RTT short header".to_string()));
    };
    if dst_cid != connection_id {
        return Err(failed(format!(
            "1-RTT packet addressed to {dst_cid:?}, not {connection_id:?}"
        )));
    }
    let sample = header_protection_sample(packet, packet_number_offset).map_err(|_| {
        failed(format!(
            "protected 1-RTT packet too short: len={}, header_len={packet_number_offset}, tag_len={PROTECTED_1RTT_TAG_LEN}",
            packet.len()
        ))
    })?;
    let mask = match packet_protection.header_protection_mask_remote_now(
        cx,
        PacketProtectionSpace::OneRtt,
        &sample,
    ) {
        Outcome::Ok(mask) => mask,
        Outcome::Err(err) => {
            return Err(failed(format!(
                "1-RTT header protection removal failed: {err:?}"
            )));
        }
        Outcome::Cancelled(_) => return Err(ConnectionRouterError::Cancelled),
        Outcome::Panicked(payload) => {
            return Err(failed(format!(
                "1-RTT header protection removal panicked: {payload:?}"
            )));
        }
    };
    let mut unmasked = packet.to_vec();
    let packet_number_len =
        remove_header_protection(&mut unmasked, packet_number_offset, mask.bytes)
            .map_err(|err| failed(format!("1-RTT header protection removal: {err}")))?;
    let header_len = packet_number_offset + usize::from(packet_number_len);
    if unmasked.len() < header_len + PROTECTED_1RTT_TAG_LEN {
        return Err(failed(format!(
            "protected 1-RTT packet too short: len={}, header_len={header_len}, tag_len={PROTECTED_1RTT_TAG_LEN}",
            unmasked.len()
        )));
    }
    let truncated = unmasked[packet_number_offset..header_len]
        .iter()
        .fold(0u32, |acc, byte| (acc << 8) | u32::from(*byte));
    let largest = packet_protection
        .highest_accepted_packet_number(PacketProtectionSpace::OneRtt)
        .unwrap_or(0);
    let packet_number = decode_packet_number_reconstruct(truncated, packet_number_len, largest)
        .map_err(|err| failed(format!("1-RTT packet number: {err}")))?;
    let key_phase = unmasked[0] & 0b0000_0100 != 0;

    let peer_key_update = match connection {
        Some(conn) => {
            key_phase != conn.tls().remote_key_phase()
                && conn.can_send_1rtt()
                && conn
                    .tls()
                    .peer_key_phase_is_new_update(key_phase, packet_number)
        }
        None => {
            !packet_protection.next_gen_keys_installed(PacketProtectionSpace::OneRtt, key_phase)
        }
    };

    if peer_key_update {
        if let Outcome::Err(err) =
            packet_protection.ensure_next_gen_keys(cx, PacketProtectionSpace::OneRtt, key_phase)
        {
            return Err(failed(format!(
                "1-RTT key update derivation failed: {err:?}"
            )));
        }
    }

    let tag_offset = unmasked.len() - PROTECTED_1RTT_TAG_LEN;
    let tag: [u8; PROTECTED_1RTT_TAG_LEN] = unmasked[tag_offset..]
        .try_into()
        .expect("tag length checked above");
    let protected = ProtectedPacket {
        space: PacketProtectionSpace::OneRtt,
        key_phase,
        packet_number,
        ciphertext: unmasked[header_len..tag_offset].to_vec(),
        tag,
        proof: ProtectionProof {
            provider_kind: packet_protection.provider_kind(),
            space: PacketProtectionSpace::OneRtt,
            key_phase,
            generation: 0,
            transcript_hash: TranscriptHash::from_bytes([0; 32]),
            failure_code: None,
        },
    };

    let plaintext =
        match packet_protection.unprotect_packet_now(cx, &protected, &unmasked[..header_len]) {
            Outcome::Ok(packet) => packet.plaintext,
            Outcome::Err(err) => {
                return Err(failed(format!("1-RTT packet unprotection failed: {err:?}")));
            }
            Outcome::Cancelled(_) => return Err(ConnectionRouterError::Cancelled),
            Outcome::Panicked(payload) => {
                return Err(failed(format!(
                    "1-RTT packet unprotection panicked: {payload:?}"
                )));
            }
        };

    // Authenticated: the reserved bits are now trustworthy and must be zero.
    let (PacketHeader::Short(mut header), consumed) =
        PacketHeader::decode(&unmasked[..header_len], connection_id.len())
            .map_err(|err| failed(format!("invalid 1-RTT header: {err}")))?
    else {
        return Err(failed("expected a 1-RTT short header".to_string()));
    };
    if consumed != header_len {
        return Err(failed("1-RTT header length mismatch".to_string()));
    }
    header.packet_number = packet_number;
    Ok(Unprotected1RttPacket {
        header,
        plaintext,
        peer_key_update,
    })
}

pub(crate) const PROTECTED_1RTT_MAX_PACKET_BYTES: usize = 1_200;
pub(crate) const PROTECTED_1RTT_PACKET_NUMBER_LEN: u8 = 4;
pub(crate) const PROTECTED_1RTT_TAG_LEN: usize = 16;

pub(crate) fn protected_1rtt_packet_len(connection_id: ConnectionId, payload_len: usize) -> usize {
    1 + connection_id.len()
        + usize::from(PROTECTED_1RTT_PACKET_NUMBER_LEN)
        + payload_len
        + PROTECTED_1RTT_TAG_LEN
}

/// Generate a protected 1-RTT packet only after conservatively reserving one
/// full packet against the congestion window.
///
/// The fixed ceiling makes admission stable across destructive generation and
/// asynchronous packet protection while the caller holds exclusive connection
/// ownership. When the window is full, only congestion-exempt ACK frames may
/// drain; all other control, STREAM, and DATAGRAM state remains queued exactly
/// as it was.
pub(crate) fn generate_congestion_admitted_1rtt_frames(
    cx: &Cx,
    connection: &mut NativeQuicConnection,
    max_frame_bytes: usize,
) -> Result<Vec<QuicFrame>, NativeQuicConnectionError> {
    if connection
        .transport()
        .can_send(PROTECTED_1RTT_MAX_PACKET_BYTES as u64)
    {
        connection.generate_frames(cx, PacketNumberSpace::ApplicationData, max_frame_bytes)
    } else {
        connection.generate_pending_ack_frames(cx, max_frame_bytes)
    }
}

pub(crate) fn is_ack_eliciting(frame: &crate::net::atp::protocol::quic_frames::QuicFrame) -> bool {
    !matches!(
        frame,
        crate::net::atp::protocol::quic_frames::QuicFrame::Padding { .. }
            | crate::net::atp::protocol::quic_frames::QuicFrame::Ack { .. }
            | crate::net::atp::protocol::quic_frames::QuicFrame::ConnectionClose { .. }
    )
}

/// Statistics about the connection router state.
#[derive(Debug, Clone)]
pub struct ConnectionRouterStats {
    /// Number of active connections in the routing table.
    pub active_connections: usize,
    /// Number of established connections.
    pub established_connections: usize,
    /// Number of connections still in handshake.
    pub pending_connections: usize,
}

/// Timer scheduler for QUIC connections that integrates with Asupersync runtime.
#[derive(Debug)]
pub struct QuicTimerScheduler {
    /// Currently scheduled timer sleep.
    current_sleep: Option<Sleep>,
    /// Next deadline we're sleeping until.
    current_deadline: Option<Instant>,
    /// Mapping for the currently owned driver; managed cancellation preserves it.
    clock: Option<QuicClock>,
}

#[derive(Debug, Clone)]
struct QuicClock {
    instant_origin: Instant,
    runtime_origin: crate::Time,
    driver: TimerDriverHandle,
}

/// Owns exactly one cancellation registration, including when a wait is dropped.
pub(crate) struct QuicCancelWake<'a> {
    cx: &'a Cx,
    token: Option<crate::cx::CancelWakerToken>,
}

impl<'a> QuicCancelWake<'a> {
    pub(crate) fn new(cx: &'a Cx) -> Self {
        Self { cx, token: None }
    }

    pub(crate) fn checkpoint(&mut self, waker: &Waker) -> Result<(), ConnectionRouterError> {
        self.token = Some(self.cx.refresh_cancel_waker(self.token, waker));
        self.cx
            .checkpoint()
            .map_err(|_| ConnectionRouterError::Cancelled)
    }
}

impl Drop for QuicCancelWake<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

impl QuicTimerScheduler {
    /// Create a new timer scheduler.
    pub fn new() -> Self {
        Self {
            current_sleep: None,
            current_deadline: None,
            clock: None,
        }
    }

    fn bind_clock(&mut self, cx: &Cx) -> Result<&QuicClock, ConnectionRouterError> {
        let driver = cx.timer_driver().ok_or_else(|| {
            ConnectionRouterError::TimerSchedulingFailed(
                "QUIC timers require the supplied Cx's timer driver".to_string(),
            )
        })?;
        if let Some(clock) = &self.clock {
            if !clock.driver.ptr_eq(&driver) {
                return Err(ConnectionRouterError::TimerSchedulingFailed(
                    "QUIC timer scheduler cannot change runtime clocks".to_string(),
                ));
            }
        }
        Ok(self.clock.get_or_insert_with(|| QuicClock {
            instant_origin: Instant::now(),
            runtime_origin: driver.now(),
            driver,
        }))
    }

    /// Current time in the same Instant domain as scheduled connection deadlines.
    pub(crate) fn now(&mut self, cx: &Cx) -> Result<Instant, ConnectionRouterError> {
        let clock = self.bind_clock(cx)?;
        clock
            .instant_origin
            .checked_add(Duration::from_nanos(
                clock
                    .driver
                    .now()
                    .as_nanos()
                    .saturating_sub(clock.runtime_origin.as_nanos()),
            ))
            .ok_or_else(|| {
                ConnectionRouterError::TimerSchedulingFailed(
                    "runtime time exceeds the Instant clock range".to_string(),
                )
            })
    }

    /// Schedule a timer to fire at the given deadline.
    ///
    /// If a timer is already scheduled for an earlier time, this is a no-op.
    /// If the new deadline is earlier, the current timer is cancelled and
    /// a new one is scheduled.
    ///
    /// A new timer uses the supplied context's driver when present, otherwise
    /// the established shared wall-clock `Sleep` fallback. A later-deadline
    /// no-op leaves the original driver and registration intact. Cancellation
    /// still observes the supplied context. [`Self::cancel`] permits reuse
    /// with another driver.
    pub async fn schedule_timer(
        &mut self,
        cx: &Cx,
        deadline: Instant,
    ) -> Result<(), ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        if self
            .current_deadline
            .is_some_and(|current| current <= deadline)
        {
            return Ok(());
        }
        let clock = cx.timer_driver().map(|driver| {
            self.clock
                .as_ref()
                .filter(|clock| clock.driver.ptr_eq(&driver))
                .cloned()
                .unwrap_or_else(|| QuicClock {
                    instant_origin: Instant::now(),
                    runtime_origin: driver.now(),
                    driver,
                })
        });
        self.arm_timer(cx, deadline, clock)
    }

    /// Managed endpoints keep one explicit clock across timer replacement and
    /// losing event-loop branches. Even a no-op must validate that owner.
    pub(crate) async fn schedule_timer_bound(
        &mut self,
        cx: &Cx,
        deadline: Instant,
    ) -> Result<(), ConnectionRouterError> {
        cx.checkpoint()
            .map_err(|_| ConnectionRouterError::Cancelled)?;
        let clock = self.bind_clock(cx)?.clone();
        if self
            .current_deadline
            .is_some_and(|current| current <= deadline)
        {
            return Ok(());
        }
        self.arm_timer(cx, deadline, Some(clock))
    }

    fn arm_timer(
        &mut self,
        cx: &Cx,
        deadline: Instant,
        clock: Option<QuicClock>,
    ) -> Result<(), ConnectionRouterError> {
        let sleep = if let Some(clock) = &clock {
            let time_deadline = if deadline >= clock.instant_origin {
                let delta = deadline.duration_since(clock.instant_origin).as_nanos();
                u64::try_from(delta)
                    .ok()
                    .and_then(|delta| clock.runtime_origin.as_nanos().checked_add(delta))
                    .ok_or_else(|| {
                        ConnectionRouterError::TimerSchedulingFailed(
                            "QUIC deadline exceeds the runtime clock range".to_string(),
                        )
                    })?
            } else {
                // Past deadlines remain armed and are observed exactly once.
                clock.runtime_origin.as_nanos().saturating_sub(
                    u64::try_from(clock.instant_origin.duration_since(deadline).as_nanos())
                        .unwrap_or(u64::MAX),
                )
            };
            Sleep::with_timer_driver(crate::Time::from_nanos(time_deadline), clock.driver.clone())
        } else {
            // Sleep's shared fallback and WallClock use this exact process
            // epoch. A duration from now is not an absolute Time deadline.
            let nanos = u64::try_from(
                deadline
                    .saturating_duration_since(crate::time::process_epoch())
                    .as_nanos(),
            )
            .map_err(|_| {
                ConnectionRouterError::TimerSchedulingFailed(
                    "QUIC deadline exceeds the wall-clock range".to_string(),
                )
            })?;
            Sleep::new(crate::Time::from_nanos(nanos))
        };
        // Construct and range-check before dropping the previous registration.
        self.current_sleep = Some(sleep);
        self.current_deadline = Some(deadline);
        self.clock = clock;
        cx.trace(&format!("Scheduled QUIC timer for {deadline:?}"));
        Ok(())
    }

    /// Wait for the next timer to fire.
    ///
    /// Returns the deadline that was reached, or None if no timer was scheduled.
    /// An already bound timer keeps its driver while cancellation observes the
    /// caller. A wall-clock fallback timer adopts a newly supplied driver by
    /// translating its Instant deadline into that driver's epoch before polling.
    pub async fn wait_for_timer(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<Instant>, ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }
        if self.clock.is_none() {
            if let (Some(deadline), Some(driver)) = (self.current_deadline, cx.timer_driver()) {
                self.arm_timer(
                    cx,
                    deadline,
                    Some(QuicClock {
                        instant_origin: Instant::now(),
                        runtime_origin: driver.now(),
                        driver,
                    }),
                )?;
            }
        }
        let mut cancel = QuicCancelWake::new(cx);
        poll_fn(|task_cx| {
            // Sleep's cancellation checks must observe the same explicit owner
            // as its bound timer driver. This guard never crosses an await.
            let _current = Cx::set_current(Some(cx.clone()));
            if let Err(err) = cancel.checkpoint(task_cx.waker()) {
                return Poll::Ready(Err(err));
            }
            let result = self.poll_timer(task_cx);
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(ConnectionRouterError::Cancelled));
            }
            result.map(Ok)
        })
        .await
    }

    /// Retain the sleep across losing branches; only a completed timer is removed.
    pub(crate) fn poll_timer(&mut self, task_cx: &mut Context<'_>) -> Poll<Option<Instant>> {
        let Some(sleep) = self.current_sleep.as_mut() else {
            return Poll::Ready(None);
        };
        if Pin::new(sleep).poll(task_cx).is_pending() {
            return Poll::Pending;
        }
        self.current_sleep = None;
        Poll::Ready(self.current_deadline.take())
    }

    /// Check if a timer is currently scheduled.
    pub fn has_pending_timer(&self) -> bool {
        self.current_sleep.is_some()
    }

    /// Get the current timer deadline if any.
    pub fn current_deadline(&self) -> Option<Instant> {
        self.current_deadline
    }

    /// Cancel the pending timer, if one is armed, and release its clock binding.
    pub fn cancel(&mut self) {
        self.cancel_pending();
        self.clock = None;
    }

    /// Drop pending work while retaining the managed owner's fixed epoch.
    pub(crate) fn cancel_pending(&mut self) {
        self.current_sleep = None;
        self.current_deadline = None;
    }
}

impl Default for QuicTimerScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "connection_manager_inline_tests.rs"]
mod tests;
