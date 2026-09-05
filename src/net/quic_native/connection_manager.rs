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
    ConnectionId, LongPacketType, PacketHeader, QuicCoreError, ShortHeader,
};
use crate::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, OutgoingPacket, ReceivedPacket,
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
}

/// Private ownership envelope; the public UDP packet layout stays unchanged.
#[derive(Debug)]
pub(crate) struct RoutedOutgoingPacket {
    pub(crate) connection_id: ConnectionId,
    pub(crate) packet: OutgoingPacket,
}

/// Handle to a managed QUIC connection with timing and lifecycle state.
#[derive(Debug)]
pub struct ConnectionHandle {
    /// The underlying QUIC connection state machine.
    connection: NativeQuicConnection,
    /// Packet-protection provider for 1-RTT UDP handoff.
    packet_protection: Option<ConnectionPacketProtection>,
    /// Remote peer address.
    peer_addr: SocketAddr,
    /// Last activity timestamp for connection timeout tracking.
    last_activity: Instant,
    /// Connection establishment timestamp.
    established_at: Option<Instant>,
    /// Pending timer deadline for this connection.
    next_timer_deadline: Option<Instant>,
    /// Input may make output ready while the endpoint's send queue is full.
    deferred_spaces: [bool; 3],
    next_deferred_space: usize,
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
        }
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
        packet: ReceivedPacket,
        emit_output: bool,
    ) -> Result<RoutingResult, ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        let routing_info = match self.decode_routing_info(&packet) {
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
            handle.last_activity = packet.receive_time;
            handle
                .connection
                .on_datagram_received(cx, packet.data.len() as u64)
                .map_err(|err| ConnectionRouterError::PacketProcessingFailed {
                    connection_id,
                    reason: err.to_string(),
                })?;
            let payload = packet.data.get(routing_info.header_len..).ok_or_else(|| {
                ConnectionRouterError::PacketProcessingFailed {
                    connection_id,
                    reason: "header length exceeded datagram length".to_string(),
                }
            })?;
            let plaintext_payload = if routing_info.space == PacketNumberSpace::ApplicationData {
                let packet_protection = handle
                    .packet_protection
                    .as_mut()
                    .ok_or(ConnectionRouterError::PacketProtectionUnavailable { connection_id })?;
                unprotect_1rtt_packet(
                    cx,
                    connection_id,
                    &mut packet_protection.protection,
                    &packet.data[..routing_info.header_len],
                    payload,
                    routing_info.packet_number,
                    routing_info.key_phase,
                )
                .await?
            } else {
                payload.to_vec()
            };
            handle
                .connection
                .process_packet_payload(
                    cx,
                    routing_info.space,
                    routing_info.packet_number,
                    &plaintext_payload,
                    now_micros,
                )
                .map_err(|err| ConnectionRouterError::PacketProcessingFailed {
                    connection_id,
                    reason: err.to_string(),
                })?;
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
                self.pending_deferred_packets
                    .extend(packets.into_iter().map(|packet| RoutedOutgoingPacket {
                        connection_id,
                        packet,
                    }));
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
            connection,
            packet_protection: None,
            peer_addr,
            last_activity: Instant::now(),
            established_at: None,
            next_timer_deadline: None,
            deferred_spaces: [false; 3],
            next_deferred_space: 0,
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
            .map(|handle| &mut handle.connection)
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
        drain_connection_frames(
            cx,
            connection_id,
            handle,
            PacketNumberSpace::ApplicationData,
            dst_addr,
            now,
            now_micros,
        )
        .await
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
            connection: handle.connection,
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

    /// Refresh a connection's PTO deadline from its transport state.
    fn refresh_connection_timer(
        cx: &Cx,
        connection_id: ConnectionId,
        handle: &mut ConnectionHandle,
        origin: Instant,
        now_micros: u64,
        now_instant: Instant,
    ) -> Result<(), ConnectionRouterError> {
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
            .filter_map(|handle| handle.next_timer_deadline)
            .min()
    }

    /// Hand off already committed timer output before a restarted managed loop
    /// parks on a future deadline. The caller checks cancellation and supplies
    /// its available queue capacity; no packet is generated or recommitted.
    pub(crate) fn take_pending_timer_output(
        &mut self,
        max_packets: usize,
    ) -> Vec<RoutedOutgoingPacket> {
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
                        Ok(packets) => {
                            self.pending_timer_packets
                                .extend(packets.into_iter().map(|packet| RoutedOutgoingPacket {
                                    connection_id,
                                    packet,
                                }))
                        }
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
                        self.pending_deferred_packets
                            .extend(packets.into_iter().map(|packet| RoutedOutgoingPacket {
                                connection_id,
                                packet,
                            }));
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

    fn decode_routing_info(
        &self,
        packet: &ReceivedPacket,
    ) -> Result<PacketRoutingInfo, QuicCoreError> {
        if packet.data.first().is_some_and(|first| first & 0x80 != 0) {
            let (header, header_len) = PacketHeader::decode(&packet.data, 0)?;
            return PacketRoutingInfo::from_header(header, header_len);
        }

        for cid_len in self.known_connection_id_lengths() {
            if let Ok((header, header_len)) = PacketHeader::decode(&packet.data, cid_len) {
                let info = PacketRoutingInfo::from_header(header, header_len)?;
                if self.connections.contains_key(&info.destination_cid) {
                    return Ok(info);
                }
            }
        }

        let (header, header_len) = PacketHeader::decode(&packet.data, 0)?;
        PacketRoutingInfo::from_header(header, header_len)
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
    packet_number: u64,
    key_phase: bool,
    header_len: usize,
}

impl PacketRoutingInfo {
    fn from_header(header: PacketHeader, header_len: usize) -> Result<Self, QuicCoreError> {
        match header {
            PacketHeader::Long(header) => {
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
                Ok(Self {
                    destination_cid: header.dst_cid,
                    kind,
                    space,
                    packet_number: header.packet_number,
                    key_phase: false,
                    header_len,
                })
            }
            PacketHeader::Retry(header) => Ok(Self {
                destination_cid: header.dst_cid,
                kind: PacketRoutingKind::Retry,
                space: PacketNumberSpace::Initial,
                packet_number: 0,
                key_phase: false,
                header_len,
            }),
            PacketHeader::Short(header) => Ok(Self {
                destination_cid: header.dst_cid,
                kind: PacketRoutingKind::OneRtt,
                space: PacketNumberSpace::ApplicationData,
                packet_number: header.packet_number,
                key_phase: header.key_phase,
                header_len,
            }),
        }
    }
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

async fn drain_connection_frames(
    cx: &Cx,
    connection_id: ConnectionId,
    handle: &mut ConnectionHandle,
    space: PacketNumberSpace,
    dst_addr: SocketAddr,
    now: Instant,
    now_micros: u64,
) -> Result<Vec<OutgoingPacket>, ConnectionRouterError> {
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
) -> Result<Vec<OutgoingPacket>, ConnectionRouterError> {
    let max_frame_bytes = if space == PacketNumberSpace::ApplicationData {
        if handle.packet_protection.is_none() {
            return Err(ConnectionRouterError::PacketProtectionUnavailable { connection_id });
        }
        PROTECTED_1RTT_MAX_PACKET_BYTES.saturating_sub(protected_1rtt_packet_len(connection_id, 0))
    } else {
        PROTECTED_1RTT_MAX_PACKET_BYTES
    };
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
                    connection_id,
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

    Ok(vec![OutgoingPacket {
        dst_addr,
        data,
        send_time: Some(now),
    }])
}

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

async fn assemble_protected_1rtt_packet_inner(
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
    let packet_number = connection
        .next_packet_number_for_protection(PacketNumberSpace::ApplicationData)
        .map_err(|err| ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: err.to_string(),
        })?;
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

    let committed_packet_number = if pto_probe {
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

    let mut packet =
        Vec::with_capacity(header_bytes.len() + protected.ciphertext.len() + protected.tag.len());
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(&protected.ciphertext);
    packet.extend_from_slice(&protected.tag);
    Ok(packet)
}

pub(crate) async fn unprotect_1rtt_packet(
    cx: &Cx,
    connection_id: ConnectionId,
    packet_protection: &mut AtpPacketProtection,
    associated_data: &[u8],
    protected_payload: &[u8],
    packet_number: u64,
    key_phase: bool,
) -> Result<Vec<u8>, ConnectionRouterError> {
    if protected_payload.len() < PROTECTED_1RTT_TAG_LEN {
        return Err(ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: format!(
                "protected 1-RTT packet too short: payload_len={}, tag_len={PROTECTED_1RTT_TAG_LEN}",
                protected_payload.len()
            ),
        });
    }

    let tag_offset = protected_payload.len() - PROTECTED_1RTT_TAG_LEN;
    let tag: [u8; PROTECTED_1RTT_TAG_LEN] = protected_payload[tag_offset..]
        .try_into()
        .expect("tag length checked above");
    let protected = ProtectedPacket {
        space: PacketProtectionSpace::OneRtt,
        key_phase,
        packet_number,
        ciphertext: protected_payload[..tag_offset].to_vec(),
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

    match packet_protection
        .unprotect_packet(cx, &protected, associated_data)
        .await
    {
        Outcome::Ok(packet) => Ok(packet.plaintext),
        Outcome::Err(err) => Err(ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: format!("1-RTT packet unprotection failed: {err:?}"),
        }),
        Outcome::Cancelled(_) => Err(ConnectionRouterError::Cancelled),
        Outcome::Panicked(payload) => Err(ConnectionRouterError::PacketProcessingFailed {
            connection_id,
            reason: format!("1-RTT packet unprotection panicked: {payload:?}"),
        }),
    }
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
    /// One fixed mapping from the public Instant domain to the explicit runtime clock.
    clock: Option<QuicClock>,
}

#[derive(Debug)]
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
    pub async fn schedule_timer(
        &mut self,
        cx: &Cx,
        deadline: Instant,
    ) -> Result<(), ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }

        // Check if we need to reschedule
        self.bind_clock(cx)?;
        let should_reschedule = match self.current_deadline {
            Some(current) => deadline < current,
            None => true,
        };

        if should_reschedule {
            let clock = self.bind_clock(cx)?;
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
            let sleep = Sleep::with_timer_driver(
                crate::Time::from_nanos(time_deadline),
                clock.driver.clone(),
            );
            self.current_sleep = Some(sleep);
            self.current_deadline = Some(deadline);

            cx.trace(&format!("Scheduled QUIC timer for {deadline:?}"));
        }

        Ok(())
    }

    /// Wait for the next timer to fire.
    ///
    /// Returns the deadline that was reached, or None if no timer was scheduled.
    pub async fn wait_for_timer(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<Instant>, ConnectionRouterError> {
        if cx.checkpoint().is_err() {
            return Err(ConnectionRouterError::Cancelled);
        }
        if self.has_pending_timer() {
            self.bind_clock(cx)?;
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

    /// Cancel the pending timer, if one is armed.
    pub fn cancel(&mut self) {
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
mod tests {
    use super::*;
    use crate::bytes::{Bytes, BytesMut};
    use crate::net::atp::protocol::quic_frames::QuicFrame;
    use crate::net::atp::quic::AtpPacketProtection;
    use crate::net::quic_core::{LongHeader, LongPacketType, PacketHeader};
    use crate::net::quic_native::QuicHandshakeTranscript;
    use crate::test_utils::run_test_with_cx;

    #[test]
    fn protected_packet_ack_elicitation_matches_rfc_9000() {
        let zero = crate::net::VarInt(0);
        assert!(!is_ack_eliciting(&QuicFrame::Padding { length: 1 }));
        assert!(!is_ack_eliciting(&QuicFrame::Ack {
            largest_acknowledged: zero,
            ack_delay: zero,
            ack_range_count: zero,
            first_ack_range: zero,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }));
        assert!(!is_ack_eliciting(&QuicFrame::ConnectionClose {
            error_code: zero,
            frame_type: None,
            reason_phrase: Bytes::new(),
        }));
        assert!(is_ack_eliciting(&QuicFrame::Ping));
        assert!(is_ack_eliciting(&QuicFrame::MaxData { maximum_data: zero }));
    }

    #[test]
    fn test_connection_router_creation() {
        let config = NativeQuicConnectionConfig::default();
        let router = ConnectionRouter::new(config);

        assert_eq!(router.connections.len(), 0);
        assert_eq!(router.next_connection_id, 1);
    }

    #[test]
    fn test_connection_id_allocation() {
        run_test_with_cx(|_cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);

            let id1 = router.allocate_connection_id();
            let id2 = router.allocate_connection_id();

            assert_ne!(id1, id2);
            assert!(router.next_connection_id > 2);
        });
    }

    #[test]
    fn test_connection_creation() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);

            let connection_id = router.allocate_connection_id();
            let peer_addr = "127.0.0.1:12345".parse().unwrap();

            router
                .create_connection(&cx, connection_id, peer_addr, false)
                .await
                .expect("connection creation should succeed");

            assert_eq!(router.connections.len(), 1);
            assert!(router.connections.contains_key(&connection_id));
        });
    }

    #[test]
    fn create_connection_rejects_duplicate_connection_id_without_overwrite() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let connection_id = ConnectionId::new(&[0x31, 0x71, 0x00, 0x01]).expect("cid");
            let original_peer: SocketAddr = "127.0.0.1:4401".parse().unwrap();
            let colliding_peer: SocketAddr = "127.0.0.1:4402".parse().unwrap();

            router
                .create_connection(&cx, connection_id, original_peer, true)
                .await
                .expect("first connection creation should succeed");

            let err = router
                .create_connection(&cx, connection_id, colliding_peer, false)
                .await
                .expect_err("duplicate destination CID must fail closed");
            assert!(matches!(
                err,
                ConnectionRouterError::ConnectionCreationFailed(ref msg)
                    if msg.contains("connection ID collision")
            ));
            assert_eq!(router.connections.len(), 1);
            assert_eq!(
                router
                    .connections
                    .get(&connection_id)
                    .expect("original connection remains")
                    .peer_addr,
                original_peer
            );
        });
    }

    #[test]
    fn connection_limit_rejects_create_and_drops_unknown_initials() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::with_max_connections(config, 0);
            assert_eq!(router.max_connections, 1);

            let peer_addr: SocketAddr = "127.0.0.1:4403".parse().unwrap();
            let first = ConnectionId::new(&[0x31, 0x71, 0x00, 0x02]).expect("first cid");
            router
                .create_connection(&cx, first, peer_addr, true)
                .await
                .expect("first connection within normalized limit should succeed");

            let second = ConnectionId::new(&[0x31, 0x71, 0x00, 0x03]).expect("second cid");
            let err = router
                .create_connection(&cx, second, peer_addr, true)
                .await
                .expect_err("second connection must hit the cap");
            assert!(matches!(
                err,
                ConnectionRouterError::ConnectionCreationFailed(ref msg)
                    if msg.contains("connection limit reached")
            ));

            let packet = ReceivedPacket {
                src_addr: peer_addr,
                data: encode_long_packet(second, LongPacketType::Initial, 0, QuicFrame::Ping),
                receive_time: Instant::now(),
                transmit_time: None,
            };
            match router.route_packet(&cx, packet).await.expect("route") {
                RoutingResult::Drop { reason } => {
                    assert!(reason.contains("connection limit reached"));
                }
                other => panic!("full router must not advertise a new connection: {other:?}"),
            }
        });
    }

    #[test]
    fn test_take_connection_removes_handle_and_preserves_peer() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let connection_id = ConnectionId::new(&[0x10, 0x00, 0x00, 0x01]).expect("cid");
            let peer_addr: SocketAddr = "127.0.0.1:5544".parse().unwrap();
            router
                .create_connection(&cx, connection_id, peer_addr, true)
                .await
                .expect("connection creation should succeed");

            let accepted = router
                .take_connection(&cx, connection_id)
                .expect("connection should be handed off");
            assert_eq!(accepted.connection_id, connection_id);
            assert_eq!(accepted.peer_addr, peer_addr);
            assert_eq!(accepted.connection.pending_outbound_datagram_count(), 0);
            assert!(!router.connections.contains_key(&connection_id));
            assert_eq!(router.connection_stats().active_connections, 0);

            let err = router
                .take_connection(&cx, connection_id)
                .expect_err("missing connection must fail closed");
            assert!(matches!(
                err,
                ConnectionRouterError::ConnectionNotFound(id) if id == connection_id
            ));
        });
    }

    #[test]
    fn test_take_next_connection_uses_deterministic_connection_id_order() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let low = ConnectionId::new(&[0x01, 0x00, 0x00, 0x00]).expect("low cid");
            let mid = ConnectionId::new(&[0x10, 0x00, 0x00, 0x00]).expect("mid cid");
            let high = ConnectionId::new(&[0xff, 0x00, 0x00, 0x00]).expect("high cid");
            let peer_addr: SocketAddr = "127.0.0.1:5545".parse().unwrap();

            for connection_id in [high, low, mid] {
                router
                    .create_connection(&cx, connection_id, peer_addr, true)
                    .await
                    .expect("connection creation should succeed");
            }

            let first = router
                .take_next_connection(&cx)
                .expect("take should succeed")
                .expect("connection should exist");
            assert_eq!(first.connection_id, low);

            let second = router
                .take_next_connection(&cx)
                .expect("take should succeed")
                .expect("connection should exist");
            assert_eq!(second.connection_id, mid);

            let third = router
                .take_next_connection(&cx)
                .expect("take should succeed")
                .expect("connection should exist");
            assert_eq!(third.connection_id, high);

            assert!(
                router
                    .take_next_connection(&cx)
                    .expect("empty take should succeed")
                    .is_none()
            );
        });
    }

    #[test]
    fn test_long_header_initial_routes_as_new_connection() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let dst_cid = ConnectionId::new(&[0xaa, 0xbb, 0xcc]).expect("cid");
            let src_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
            let packet = ReceivedPacket {
                src_addr,
                data: encode_long_packet(dst_cid, LongPacketType::Initial, 0, QuicFrame::Ping),
                receive_time: Instant::now(),
                transmit_time: None,
            };

            match router.route_packet(&cx, packet).await.expect("route") {
                RoutingResult::NewConnection { peer_addr, .. } => assert_eq!(peer_addr, src_addr),
                other => panic!("expected new connection, got {other:?}"),
            }
        });
    }

    #[test]
    fn test_new_initial_reroutes_after_connection_creation() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let dst_cid = ConnectionId::new(&[0xda, 0x7a, 0x00, 0x01]).expect("cid");
            let src_addr: SocketAddr = "127.0.0.1:4436".parse().unwrap();
            let packet = ReceivedPacket {
                src_addr,
                data: encode_long_packet(dst_cid, LongPacketType::Initial, 7, QuicFrame::Ping),
                receive_time: Instant::now(),
                transmit_time: None,
            };

            let triggering_packet = match router.route_packet(&cx, packet).await.expect("route") {
                RoutingResult::NewConnection {
                    connection_id,
                    peer_addr,
                    triggering_packet,
                    outgoing_packets,
                } => {
                    assert_eq!(connection_id, dst_cid);
                    assert_eq!(peer_addr, src_addr);
                    assert!(outgoing_packets.is_empty());
                    triggering_packet
                }
                other => panic!("expected new connection, got {other:?}"),
            };

            router
                .create_connection(&cx, dst_cid, src_addr, true)
                .await
                .expect("connection creation should succeed");

            match router
                .route_packet(&cx, triggering_packet)
                .await
                .expect("reroute")
            {
                RoutingResult::Routed {
                    connection_id,
                    outgoing_packets,
                } => {
                    assert_eq!(connection_id, dst_cid);
                    assert_eq!(outgoing_packets.len(), 1);
                    assert_eq!(outgoing_packets[0].dst_addr, src_addr);
                    assert!(!outgoing_packets[0].data.is_empty());
                }
                other => panic!("expected triggering Initial to reroute, got {other:?}"),
            }
        });
    }

    #[test]
    fn test_existing_connection_processes_ping_and_emits_ack_frame() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let connection_id = router.allocate_connection_id();
            let peer_addr: SocketAddr = "127.0.0.1:4434".parse().unwrap();
            router
                .create_connection(&cx, connection_id, peer_addr, false)
                .await
                .expect("connection creation should succeed");

            let packet = ReceivedPacket {
                src_addr: peer_addr,
                data: encode_long_packet(
                    connection_id,
                    LongPacketType::Initial,
                    42,
                    QuicFrame::Ping,
                ),
                receive_time: Instant::now(),
                transmit_time: None,
            };

            match router.route_packet(&cx, packet).await.expect("route") {
                RoutingResult::Routed {
                    outgoing_packets, ..
                } => {
                    assert_eq!(outgoing_packets.len(), 1);
                    assert_eq!(outgoing_packets[0].dst_addr, peer_addr);
                    assert!(!outgoing_packets[0].data.is_empty());
                }
                other => panic!("expected routed packet, got {other:?}"),
            }
        });
    }

    #[test]
    fn test_application_datagram_handoff_uses_protected_short_header_packet() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let connection_id = ConnectionId::new(&[0xa1, 0x01, 0x00, 0x01]).expect("cid");
            let peer_addr: SocketAddr = "127.0.0.1:4435".parse().unwrap();
            router
                .create_connection(&cx, connection_id, peer_addr, false)
                .await
                .expect("connection creation should succeed");
            router
                .install_packet_protection(
                    &cx,
                    connection_id,
                    deterministic_one_rtt_protection(&cx).await,
                )
                .expect("install packet protection");
            let mut receiver = ConnectionRouter::new(config);
            receiver
                .create_connection(&cx, connection_id, peer_addr, false)
                .await
                .expect("receiver connection creation should succeed");
            receiver
                .install_packet_protection(
                    &cx,
                    connection_id,
                    deterministic_one_rtt_protection(&cx).await,
                )
                .expect("install receiver packet protection");

            let datagram = Bytes::from_static(b"a1 protected udp symbol");
            {
                let handle = router
                    .connections
                    .get_mut(&connection_id)
                    .expect("connection handle");
                establish_for_application_data(&cx, &mut handle.connection);
                handle
                    .connection
                    .send_datagram(&cx, datagram.clone())
                    .expect("queue datagram");
            }

            let now = Instant::now();
            let packets = {
                let handle = router
                    .connections
                    .get_mut(&connection_id)
                    .expect("connection handle");
                drain_connection_frames(
                    &cx,
                    connection_id,
                    handle,
                    PacketNumberSpace::ApplicationData,
                    peer_addr,
                    now,
                    42_000,
                )
                .await
                .expect("drain protected packet")
            };
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].dst_addr, peer_addr);
            assert_eq!(packets[0].send_time, Some(now));
            assert!(packets[0].data.len() <= PROTECTED_1RTT_MAX_PACKET_BYTES);

            let mut raw_frame_payload = BytesMut::new();
            QuicFrame::Datagram { data: datagram }
                .encode(&mut raw_frame_payload)
                .expect("encode raw DATAGRAM frame");
            let packet = &packets[0].data;
            assert_ne!(packet.as_slice(), raw_frame_payload.as_ref());

            let (decoded, header_len) =
                PacketHeader::decode(packet, connection_id.len()).expect("decode short header");
            let PacketHeader::Short(header) = decoded else {
                panic!("expected a protected 1-RTT short header packet");
            };
            assert!(!header.spin);
            assert!(!header.key_phase);
            assert_eq!(header.dst_cid, connection_id);
            assert_eq!(header.packet_number, 0);
            assert_eq!(header.packet_number_len, PROTECTED_1RTT_PACKET_NUMBER_LEN);

            let protected_payload = &packet[header_len..];
            assert_eq!(
                protected_payload.len(),
                raw_frame_payload.len() + PROTECTED_1RTT_TAG_LEN
            );
            assert_ne!(
                &protected_payload[..raw_frame_payload.len()],
                raw_frame_payload.as_ref()
            );

            {
                let handle = receiver
                    .connections
                    .get_mut(&connection_id)
                    .expect("receiver connection handle");
                establish_for_application_data(&cx, &mut handle.connection);
            }
            let received = ReceivedPacket {
                src_addr: peer_addr,
                data: packet.clone(),
                receive_time: Instant::now(),
                transmit_time: None,
            };
            match receiver
                .route_packet(&cx, received)
                .await
                .expect("route protected packet")
            {
                RoutingResult::Routed {
                    connection_id: routed_id,
                    ..
                } => assert_eq!(routed_id, connection_id),
                other => panic!("expected routed protected packet, got {other:?}"),
            }
            let received_datagram = receiver
                .connections
                .get_mut(&connection_id)
                .expect("receiver connection handle")
                .connection
                .recv_datagram()
                .expect("datagram delivered after unprotect");
            assert_eq!(received_datagram.as_ref(), b"a1 protected udp symbol");
        });
    }

    #[test]
    fn test_application_datagram_handoff_without_protection_fails_closed() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let connection_id = ConnectionId::new(&[0xa1, 0x01, 0x00, 0x02]).expect("cid");
            let peer_addr: SocketAddr = "127.0.0.1:4436".parse().unwrap();
            router
                .create_connection(&cx, connection_id, peer_addr, false)
                .await
                .expect("connection creation should succeed");

            let handle = router
                .connections
                .get_mut(&connection_id)
                .expect("connection handle");
            establish_for_application_data(&cx, &mut handle.connection);
            handle
                .connection
                .send_datagram(&cx, Bytes::from_static(b"must not leak raw"))
                .expect("queue datagram");

            let err = drain_connection_frames(
                &cx,
                connection_id,
                handle,
                PacketNumberSpace::ApplicationData,
                peer_addr,
                Instant::now(),
                42_000,
            )
            .await
            .expect_err("missing 1-RTT packet protection must fail closed");
            assert!(matches!(
                err,
                ConnectionRouterError::PacketProtectionUnavailable { connection_id: id }
                    if id == connection_id
            ));
            assert_eq!(handle.connection.pending_outbound_datagram_count(), 1);
        });
    }

    #[test]
    fn overdue_managed_pto_emits_bounded_protected_probes_and_isolates_a_bad_connection() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let peer: SocketAddr = "127.0.0.1:4401".parse().unwrap();
            let ids = [1u8, 2, 3].map(|id| ConnectionId::new(&[id, 0, 0, 1]).unwrap());
            for (index, id) in ids.into_iter().enumerate() {
                router
                    .create_connection(&cx, id, peer, false)
                    .await
                    .unwrap();
                if index != 1 {
                    router
                        .install_packet_protection(
                            &cx,
                            id,
                            deterministic_one_rtt_protection(&cx).await,
                        )
                        .unwrap();
                }
                let handle = router.connections.get_mut(&id).unwrap();
                establish_for_application_data(&cx, &mut handle.connection);
                let cwnd = handle.connection.transport().congestion_window_bytes();
                for sent in 0..cwnd / 1_200 {
                    handle
                        .connection
                        .on_packet_sent(
                            &cx,
                            PacketNumberSpace::ApplicationData,
                            1_200,
                            true,
                            true,
                            1_000 + sent,
                        )
                        .unwrap();
                }
                handle
                    .connection
                    .send_datagram(&cx, Bytes::from_static(b"ordinary data must stay queued"))
                    .unwrap();
                let origin = router.clock_origin;
                ConnectionRouter::refresh_connection_timer(
                    &cx,
                    id,
                    handle,
                    origin,
                    1_000,
                    origin + Duration::from_micros(1_000),
                )
                .unwrap();
            }
            // One hour exceeds the old capped PTO horizon. Both healthy peers
            // must emit one authenticated probe despite a full congestion window.
            let now = router.clock_origin + Duration::from_secs(3_600);
            let packets = router.process_timer_events(&cx, now).await.unwrap();
            assert_eq!(
                packets.len(),
                2,
                "one broken protection provider must not erase healthy output"
            );
            for packet in packets {
                let (header, header_len) = PacketHeader::decode(&packet.data, 4).unwrap();
                let PacketHeader::Short(header) = header else {
                    panic!("protected short packet required")
                };
                assert!(header.dst_cid == ids[0] || header.dst_cid == ids[2]);
                let mut protection = deterministic_one_rtt_protection(&cx).await;
                let payload = unprotect_1rtt_packet(
                    &cx,
                    header.dst_cid,
                    &mut protection,
                    &packet.data[..header_len],
                    &packet.data[header_len..],
                    header.packet_number,
                    header.key_phase,
                )
                .await
                .unwrap();
                let mut expected = BytesMut::new();
                QuicFrame::Ping.encode(&mut expected).unwrap();
                assert_eq!(payload, expected.as_ref());
            }
            assert!(router.next_timer_deadline().unwrap() > now);
            assert!(
                router
                    .process_timer_events(&cx, now)
                    .await
                    .unwrap()
                    .is_empty(),
                "the same elapsed deadline must not fire twice"
            );
            for id in ids {
                let handle = &router.connections[&id];
                assert_eq!(handle.connection.pending_outbound_datagram_count(), 1);
                assert!(handle.next_timer_deadline.unwrap() > now);
            }
        });
    }

    #[test]
    fn test_timer_scheduler_basic() {
        let (cx, _, _) = timer_test_context(crate::Time::from_secs(123));
        futures_lite::future::block_on(async move {
            let mut scheduler = QuicTimerScheduler::new();

            assert!(!scheduler.has_pending_timer());
            assert_eq!(scheduler.current_deadline(), None);

            let deadline = Instant::now() + std::time::Duration::from_millis(10);
            scheduler
                .schedule_timer(&cx, deadline)
                .await
                .expect("timer scheduling should succeed");

            assert!(scheduler.has_pending_timer());
            assert_eq!(scheduler.current_deadline(), Some(deadline));
        });
    }

    // br-asupersync-bi2462.75: real router/frame/protection transitions with
    // explicit clock inputs; these unit cases do not claim native UDP delivery.
    #[test]
    fn managed_router_unsent_probe_keeps_queue_and_in_flight_bytes_bounded() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let cid = ConnectionId::new(&[7, 0, 0, 1]).unwrap();
            let peer = "127.0.0.1:4450".parse().unwrap();
            add_protected_test_connection(&cx, &mut router, cid, peer).await;
            let handle = router.connections.get_mut(&cid).unwrap();
            handle
                .connection
                .on_packet_sent(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    1_200,
                    true,
                    true,
                    1_000,
                )
                .unwrap();
            let origin = router.clock_origin;
            ConnectionRouter::refresh_connection_timer(
                &cx,
                cid,
                handle,
                origin,
                1_000,
                origin + Duration::from_micros(1_000),
            )
            .unwrap();
            let first = router.next_timer_deadline().unwrap();
            let mut queued = router
                .process_managed_timer_events(&cx, first, &HashSet::new())
                .await
                .unwrap();
            assert_eq!(queued.len(), 1);
            assert_eq!(queued[0].connection_id, cid);
            let committed_bytes = router.connections[&cid]
                .connection
                .transport()
                .bytes_in_flight();
            assert_eq!(committed_bytes, 1_200 + queued[0].packet.data.len() as u64);
            let first_packet = queued[0].packet.data.clone();
            let endpoint_pending = HashSet::from([cid]);
            for _ in 0..14 {
                let now = router.next_timer_deadline().unwrap() + Duration::from_secs(1);
                queued.extend(
                    router
                        .process_managed_timer_events(&cx, now, &endpoint_pending)
                        .await
                        .unwrap(),
                );
                assert_eq!(queued.len(), 1);
                assert_eq!(queued[0].packet.data, first_packet);
                assert_eq!(
                    router.connections[&cid]
                        .connection
                        .transport()
                        .bytes_in_flight(),
                    committed_bytes
                );
                assert!(router.next_timer_deadline().unwrap() > now);
            }
            // Exercise the same bound while the committed packet remains in
            // the router (for example after a cancelled multi-connection pass).
            router.pending_timer_packets.extend(queued);
            let now = router.next_timer_deadline().unwrap();
            let retained = router
                .process_managed_timer_events(&cx, now, &HashSet::new())
                .await
                .unwrap();
            assert_eq!(retained.len(), 1);
            assert_eq!(retained[0].packet.data, first_packet);
            assert_eq!(
                router.connections[&cid]
                    .connection
                    .transport()
                    .bytes_in_flight(),
                committed_bytes
            );
            assert!(router.next_timer_deadline().unwrap() > now);
            // Once the owner reports the packet drained, a later PTO really
            // commits another bounded protected probe rather than refusing all output.
            let now = router.next_timer_deadline().unwrap();
            let resumed = router
                .process_managed_timer_events(&cx, now, &HashSet::new())
                .await
                .unwrap();
            assert_eq!(resumed.len(), 1);
            assert_ne!(resumed[0].packet.data, first_packet);
            assert_eq!(
                router.connections[&cid]
                    .connection
                    .transport()
                    .bytes_in_flight(),
                committed_bytes + resumed[0].packet.data.len() as u64
            );
        });
    }

    #[test]
    fn managed_router_handoff_purges_only_its_cid_at_a_shared_peer() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let ids = [1u8, 2].map(|id| ConnectionId::new(&[8, 0, 0, id]).unwrap());
            let peer = "127.0.0.1:4451".parse().unwrap();
            for cid in ids {
                add_protected_test_connection(&cx, &mut router, cid, peer).await;
                let handle = router.connections.get_mut(&cid).unwrap();
                handle
                    .connection
                    .on_packet_sent(
                        &cx,
                        PacketNumberSpace::ApplicationData,
                        1_200,
                        true,
                        true,
                        1_000,
                    )
                    .unwrap();
                let origin = router.clock_origin;
                ConnectionRouter::refresh_connection_timer(
                    &cx,
                    cid,
                    handle,
                    origin,
                    1_000,
                    origin + Duration::from_micros(1_000),
                )
                .unwrap();
            }
            let now = router.next_timer_deadline().unwrap();
            let packets = router
                .process_managed_timer_events(&cx, now, &HashSet::new())
                .await
                .unwrap();
            assert_eq!(
                packets
                    .iter()
                    .map(|routed| routed.connection_id)
                    .collect::<Vec<_>>(),
                ids
            );
            let survivor = packets[1].packet.data.clone();
            router.pending_timer_packets.extend(packets);
            for cid in ids {
                router
                    .connections
                    .get_mut(&cid)
                    .unwrap()
                    .connection
                    .queue_ping(&cx)
                    .unwrap();
            }
            let deferred = router.drain_deferred_output(&cx, now, 2).await.unwrap();
            assert_eq!(deferred.len(), 2);
            let deferred_survivor = deferred
                .iter()
                .find(|routed| routed.connection_id == ids[1])
                .unwrap()
                .packet
                .data
                .clone();
            router.pending_deferred_packets.extend(deferred);
            let accepted = router.take_connection(&cx, ids[0]).unwrap();
            assert_eq!(accepted.peer_addr, peer);
            assert_eq!(router.pending_timer_packets.len(), 1);
            assert_eq!(router.pending_timer_packets[0].connection_id, ids[1]);
            assert_eq!(router.pending_timer_packets[0].packet.data, survivor);
            assert_eq!(router.pending_deferred_packets.len(), 1);
            assert_eq!(
                router.pending_deferred_packets[0].packet.data,
                deferred_survivor
            );
            router.remove_connection(&cx, ids[1]).unwrap();
            assert!(router.pending_timer_packets.is_empty());
            assert!(router.pending_deferred_packets.is_empty());
        });
    }

    #[test]
    fn managed_router_backpressure_processes_ack_then_drains_encrypted_data() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let cid = ConnectionId::new(&[9, 0, 0, 1]).unwrap();
            let peer = "127.0.0.1:4452".parse().unwrap();
            add_protected_test_connection(&cx, &mut router, cid, peer).await;
            let handle = router.connections.get_mut(&cid).unwrap();
            for _ in 0..10 {
                handle
                    .connection
                    .on_packet_sent(
                        &cx,
                        PacketNumberSpace::ApplicationData,
                        1_200,
                        true,
                        true,
                        1_000,
                    )
                    .unwrap();
            }
            handle
                .connection
                .send_datagram(&cx, Bytes::from_static(b"deferred actual data"))
                .unwrap();
            let now = router.clock_origin + Duration::from_micros(2_000);
            assert!(
                router
                    .drain_deferred_output(&cx, now, 1)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                !router.connections[&cid].deferred_spaces[2],
                "cwnd-blocked data is not immediate readiness"
            );
            assert_eq!(
                router.connections[&cid]
                    .connection
                    .pending_outbound_datagram_count(),
                1
            );

            let mut peer_connection =
                NativeQuicConnection::new(NativeQuicConnectionConfig::default());
            establish_for_application_data(&cx, &mut peer_connection);
            let mut protection = deterministic_one_rtt_protection(&cx).await;
            let zero = crate::net::VarInt(0);
            let ack = QuicFrame::Ack {
                largest_acknowledged: zero,
                ack_delay: zero,
                ack_range_count: zero,
                first_ack_range: zero,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            };
            let mut payload = BytesMut::new();
            ack.encode(&mut payload).unwrap();
            let packet = assemble_protected_1rtt_packet(
                &cx,
                cid,
                &mut peer_connection,
                &mut protection,
                &[ack],
                &payload,
                2_000,
                false,
            )
            .await
            .unwrap();
            let result = router
                .route_packet_with_output(
                    &cx,
                    ReceivedPacket {
                        src_addr: peer,
                        data: packet,
                        receive_time: now,
                        transmit_time: None,
                    },
                    false,
                )
                .await
                .unwrap();
            let RoutingResult::Routed {
                outgoing_packets, ..
            } = result
            else {
                panic!("ACK must reach connection")
            };
            assert!(outgoing_packets.is_empty());
            let connection = &router.connections[&cid].connection;
            assert_eq!(connection.transport().packets_acked_total(), 1);
            assert_eq!(connection.transport().bytes_in_flight(), 10_800);
            assert!(connection.transport().can_send(1_200));
            assert_eq!(connection.pending_outbound_datagram_count(), 1);
            assert_eq!(connection.datagrams_sent(), 0);
            assert!(router.connections[&cid].deferred_spaces[2]);
            assert!(
                router
                    .drain_deferred_output(&cx, now, 0)
                    .await
                    .unwrap()
                    .is_empty()
            );
            let output = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(output.len(), 1);
            assert_eq!(output[0].connection_id, cid);
            assert_eq!(
                router.connections[&cid]
                    .connection
                    .pending_outbound_datagram_count(),
                0
            );
            let packet = &output[0].packet.data;
            let (PacketHeader::Short(header), header_len) =
                PacketHeader::decode(packet, cid.len()).unwrap()
            else {
                panic!("protected short packet")
            };
            let plaintext = unprotect_1rtt_packet(
                &cx,
                cid,
                &mut protection,
                &packet[..header_len],
                &packet[header_len..],
                header.packet_number,
                header.key_phase,
            )
            .await
            .unwrap();
            let mut decoded = plaintext.as_slice();
            let frame = QuicFrame::decode(&mut decoded).unwrap().unwrap();
            assert!(
                matches!(frame, QuicFrame::Datagram { data } if data.as_ref() == b"deferred actual data")
            );
            assert!(decoded.is_empty());
            assert!(
                router
                    .drain_deferred_output(&cx, now, 1)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(!router.connections[&cid].deferred_spaces[2]);
        });
    }

    #[test]
    fn managed_router_timer_batch_yields_and_keeps_committed_prefix_after_drop() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let peer = "127.0.0.1:4454".parse().unwrap();
            let mut ids = Vec::new();
            for index in 0..=TIMER_CONNECTIONS_PER_TURN {
                let cid = ConnectionId::new(&(index as u64).to_be_bytes()).unwrap();
                ids.push(cid);
                add_protected_test_connection(&cx, &mut router, cid, peer).await;
                let handle = router.connections.get_mut(&cid).unwrap();
                handle
                    .connection
                    .on_packet_sent(
                        &cx,
                        PacketNumberSpace::ApplicationData,
                        1_200,
                        true,
                        true,
                        1_000,
                    )
                    .unwrap();
                let origin = router.clock_origin;
                ConnectionRouter::refresh_connection_timer(
                    &cx,
                    cid,
                    handle,
                    origin,
                    1_000,
                    origin + Duration::from_micros(1_000),
                )
                .unwrap();
            }
            let now = router.next_timer_deadline().unwrap();
            let pending = HashSet::new();
            {
                let mut timers =
                    std::pin::pin!(router.process_managed_timer_events(&cx, now, &pending));
                assert!(
                    timers
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            assert_eq!(
                router.pending_timer_packets.len(),
                TIMER_CONNECTIONS_PER_TURN
            );
            for cid in &ids[..TIMER_CONNECTIONS_PER_TURN] {
                assert!(router.connections[cid].next_timer_deadline.unwrap() > now);
            }
            let last = ids[TIMER_CONNECTIONS_PER_TURN];
            assert_eq!(router.connections[&last].next_timer_deadline, Some(now));
            let prefix: Vec<_> = router
                .pending_timer_packets
                .iter()
                .map(|routed| (routed.connection_id, routed.packet.data.clone()))
                .collect();
            let cancelled = Cx::for_testing();
            cancelled.set_cancel_requested(true);
            assert!(matches!(
                router
                    .process_managed_timer_events(&cancelled, now, &pending)
                    .await,
                Err(ConnectionRouterError::Cancelled)
            ));
            assert_eq!(
                router.pending_timer_packets.len(),
                TIMER_CONNECTIONS_PER_TURN
            );
            let resumed = router
                .process_managed_timer_events(&cx, now, &pending)
                .await
                .unwrap();
            assert_eq!(resumed.len(), TIMER_CONNECTIONS_PER_TURN + 1);
            assert_eq!(
                resumed
                    .iter()
                    .map(|routed| routed.connection_id)
                    .collect::<HashSet<_>>()
                    .len(),
                resumed.len()
            );
            for (routed, (cid, packet)) in resumed.iter().zip(prefix) {
                assert_eq!(routed.connection_id, cid);
                assert_eq!(routed.packet.data, packet);
            }
            for cid in ids {
                let handle = &router.connections[&cid];
                assert_eq!(handle.connection.transport().pto_count(), 1);
                assert!(handle.next_timer_deadline.unwrap() > now);
            }
            assert!(router.pending_timer_packets.is_empty());
        });
    }

    #[test]
    fn managed_router_restarted_timer_handoff_does_not_wait_for_future_deadline() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let peer = "127.0.0.1:4455".parse().unwrap();
            for index in 0..TIMER_CONNECTIONS_PER_TURN {
                let cid = ConnectionId::new(&(index as u64).to_be_bytes()).unwrap();
                add_protected_test_connection(&cx, &mut router, cid, peer).await;
                let handle = router.connections.get_mut(&cid).unwrap();
                handle
                    .connection
                    .on_packet_sent(
                        &cx,
                        PacketNumberSpace::ApplicationData,
                        1_200,
                        true,
                        true,
                        1_000,
                    )
                    .unwrap();
                let origin = router.clock_origin;
                ConnectionRouter::refresh_connection_timer(
                    &cx,
                    cid,
                    handle,
                    origin,
                    1_000,
                    origin + Duration::from_micros(1_000),
                )
                .unwrap();
            }
            // An idle final CID makes the traversal yield after all due
            // connections have already been rearmed into the future.
            let idle =
                ConnectionId::new(&(TIMER_CONNECTIONS_PER_TURN as u64).to_be_bytes()).unwrap();
            router
                .create_connection(&cx, idle, peer, false)
                .await
                .unwrap();
            let now = router.next_timer_deadline().unwrap();
            let pending = HashSet::new();
            {
                let mut timers =
                    std::pin::pin!(router.process_managed_timer_events(&cx, now, &pending));
                assert!(
                    timers
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            assert!(router.next_timer_deadline().unwrap() > now);
            assert!(router.connections[&idle].next_timer_deadline.is_none());
            let expected: Vec<_> = router
                .pending_timer_packets
                .iter()
                .map(|routed| (routed.connection_id, routed.packet.data.clone()))
                .collect();
            assert_eq!(expected.len(), TIMER_CONNECTIONS_PER_TURN);
            assert!(router.take_pending_timer_output(0).is_empty());
            assert_eq!(router.pending_timer_packets.len(), expected.len());
            let mut output = router.take_pending_timer_output(3);
            assert_eq!(output.len(), 3);
            assert_eq!(router.pending_timer_packets.len(), expected.len() - 3);
            output.extend(router.take_pending_timer_output(TIMER_CONNECTIONS_PER_TURN));
            assert_eq!(output.len(), expected.len());
            for (routed, (cid, bytes)) in output.iter().zip(expected) {
                assert_eq!(routed.connection_id, cid);
                assert_eq!(routed.packet.data, bytes);
                assert_eq!(routed.packet.dst_addr, peer);
                assert_eq!(
                    router.connections[&cid].connection.transport().pto_count(),
                    1
                );
            }
            assert!(router.take_pending_timer_output(1).is_empty());
            assert!(router.next_timer_deadline().unwrap() > now);
        });
    }

    #[test]
    fn managed_router_deferred_budget_rotates_peers_and_keeps_prefix_on_error() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let ids = [1u8, 2, 3].map(|id| ConnectionId::new(&[10, 0, 0, id]).unwrap());
            let peer = "127.0.0.1:4453".parse().unwrap();
            for cid in ids {
                add_protected_test_connection(&cx, &mut router, cid, peer).await;
                router
                    .connections
                    .get_mut(&cid)
                    .unwrap()
                    .connection
                    .queue_ping(&cx)
                    .unwrap();
            }
            let now = router.clock_origin + Duration::from_micros(1_000);
            let first = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(first.len(), 1);
            assert_eq!(first[0].connection_id, ids[0]);
            router
                .connections
                .get_mut(&ids[0])
                .unwrap()
                .connection
                .queue_ping(&cx)
                .unwrap();
            let second = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(second[0].connection_id, ids[1]);
            let third = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(third[0].connection_id, ids[2]);
            // The next pass commits CID 1 before CID 2 fails its real missing
            // protection gate. The good prefix must still be returned.
            router
                .connections
                .get_mut(&ids[1])
                .unwrap()
                .packet_protection = None;
            let prefix = router.drain_deferred_output(&cx, now, 3).await.unwrap();
            assert_eq!(prefix.len(), 1);
            assert_eq!(prefix[0].connection_id, ids[0]);
            let bytes = prefix[0].packet.data.clone();
            router.pending_deferred_packets.extend(prefix);
            let cancelled = Cx::for_testing();
            cancelled.set_cancel_requested(true);
            assert!(matches!(
                router.drain_deferred_output(&cancelled, now, 1).await,
                Err(ConnectionRouterError::Cancelled)
            ));
            assert_eq!(router.pending_deferred_packets.len(), 1);
            let recovered = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(recovered.len(), 1);
            assert_eq!(recovered[0].packet.data, bytes);
        });
    }

    fn timer_test_context(
        epoch: crate::Time,
    ) -> (
        Cx,
        std::sync::Arc<crate::time::VirtualClock>,
        TimerDriverHandle,
    ) {
        let clock = std::sync::Arc::new(crate::time::VirtualClock::starting_at(epoch));
        let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            crate::types::RegionId::new_for_test(0, 1),
            crate::types::TaskId::new_for_test(0, 0),
            crate::types::Budget::INFINITE,
            None,
            None,
            None,
            Some(driver.clone()),
            None,
        );
        (cx, clock, driver)
    }

    #[test]
    fn timer_uses_explicit_nonzero_epoch_and_survives_a_losing_wait() {
        let (cx, clock, driver) = timer_test_context(crate::Time::from_secs(123));
        let (ambient, _, ambient_driver) = timer_test_context(crate::Time::from_secs(900));
        let _ambient = Cx::set_current(Some(ambient));
        let mut scheduler = QuicTimerScheduler::new();
        let start = scheduler.now(&cx).unwrap();
        let deadline = start + Duration::from_secs(2);
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, deadline)).unwrap();
        let mut task_cx = Context::from_waker(Waker::noop());
        {
            let mut wait = std::pin::pin!(scheduler.wait_for_timer(&cx));
            assert!(wait.as_mut().poll(&mut task_cx).is_pending());
        }
        assert_eq!(scheduler.current_deadline(), Some(deadline));
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(ambient_driver.pending_count(), 0);
        clock.advance(1_999_999_999);
        assert_eq!(driver.process_timers(), 0);
        assert!(scheduler.poll_timer(&mut task_cx).is_pending());
        clock.advance(1);
        assert_eq!(driver.process_timers(), 1);
        assert_eq!(
            scheduler.poll_timer(&mut task_cx),
            Poll::Ready(Some(deadline))
        );
        assert_eq!(scheduler.poll_timer(&mut task_cx), Poll::Ready(None));
        assert_eq!(driver.pending_count(), 0);
    }

    #[test]
    fn timer_overdue_reschedule_and_removal_keep_one_registration() {
        let (cx, clock, driver) = timer_test_context(crate::Time::from_secs(100));
        let mut scheduler = QuicTimerScheduler::new();
        let start = scheduler.now(&cx).unwrap();
        let mut task_cx = Context::from_waker(Waker::noop());
        let overdue = start - Duration::from_secs(1);
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, overdue)).unwrap();
        assert!(scheduler.has_pending_timer());
        assert_eq!(
            scheduler.poll_timer(&mut task_cx),
            Poll::Ready(Some(overdue))
        );
        assert_eq!(scheduler.poll_timer(&mut task_cx), Poll::Ready(None));

        let early = start + Duration::from_secs(2);
        let late = start + Duration::from_secs(4);
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, late)).unwrap();
        assert!(scheduler.poll_timer(&mut task_cx).is_pending());
        assert_eq!(driver.pending_count(), 1);
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, early)).unwrap();
        assert_eq!(
            driver.pending_count(),
            0,
            "old registration removed on rearm"
        );
        assert!(scheduler.poll_timer(&mut task_cx).is_pending());
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, late)).unwrap();
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, early)).unwrap();
        assert_eq!(scheduler.current_deadline(), Some(early));
        assert_eq!(driver.pending_count(), 1);
        clock.advance(2_000_000_000);
        assert_eq!(driver.process_timers(), 1);
        assert_eq!(scheduler.poll_timer(&mut task_cx), Poll::Ready(Some(early)));
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, late)).unwrap();
        assert!(scheduler.poll_timer(&mut task_cx).is_pending());
        scheduler.cancel();
        assert_eq!(driver.pending_count(), 0);
        assert_eq!(scheduler.current_deadline(), None);
    }

    #[test]
    fn timer_refuses_missing_changed_or_overflowing_clock_without_losing_current_timer() {
        let mut scheduler = QuicTimerScheduler::new();
        let missing = Cx::for_testing();
        assert!(matches!(
            futures_lite::future::block_on(scheduler.schedule_timer(&missing, Instant::now())),
            Err(ConnectionRouterError::TimerSchedulingFailed(_))
        ));
        let (cx, _, _) = timer_test_context(crate::Time::from_nanos(u64::MAX - 100));
        let start = scheduler.now(&cx).unwrap();
        assert!(matches!(
            futures_lite::future::block_on(
                scheduler.schedule_timer(&cx, start + Duration::from_secs(1))
            ),
            Err(ConnectionRouterError::TimerSchedulingFailed(_))
        ));
        assert!(!scheduler.has_pending_timer());
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, start)).unwrap();
        let (other, _, _) = timer_test_context(crate::Time::ZERO);
        assert!(matches!(
            scheduler.now(&other),
            Err(ConnectionRouterError::TimerSchedulingFailed(_))
        ));
        for refused in [&other, &missing] {
            assert!(matches!(
                futures_lite::future::block_on(
                    scheduler.schedule_timer(refused, start + Duration::from_secs(1))
                ),
                Err(ConnectionRouterError::TimerSchedulingFailed(_))
            ));
            assert!(matches!(
                futures_lite::future::block_on(scheduler.wait_for_timer(refused)),
                Err(ConnectionRouterError::TimerSchedulingFailed(_))
            ));
        }
        assert_eq!(scheduler.current_deadline(), Some(start));
    }

    #[test]
    fn explicit_timer_cancellation_wakes_the_current_waiter_and_cleans_up_on_drop() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counter(AtomicUsize);
        impl std::task::Wake for Counter {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let (cx, _, driver) = timer_test_context(crate::Time::from_secs(5));
        let mut scheduler = QuicTimerScheduler::new();
        let deadline = scheduler.now(&cx).unwrap() + Duration::from_secs(10);
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, deadline)).unwrap();
        let first = std::sync::Arc::new(Counter(AtomicUsize::new(0)));
        let second = std::sync::Arc::new(Counter(AtomicUsize::new(0)));
        let first_waker = Waker::from(first.clone());
        let second_waker = Waker::from(second.clone());
        {
            let mut wait = std::pin::pin!(scheduler.wait_for_timer(&cx));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&first_waker))
                    .is_pending()
            );
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&second_waker))
                    .is_pending()
            );
            cx.cancel_with(crate::types::CancelKind::User, None);
            assert_eq!(first.0.load(Ordering::SeqCst), 0);
            assert!(second.0.load(Ordering::SeqCst) > 0);
            assert_eq!(
                wait.as_mut().poll(&mut Context::from_waker(&second_waker)),
                Poll::Ready(Err(ConnectionRouterError::Cancelled))
            );
        }
        scheduler.cancel();
        assert_eq!(driver.pending_count(), 0);
    }

    fn encode_long_packet(
        dst_cid: ConnectionId,
        packet_type: LongPacketType,
        packet_number: u64,
        frame: QuicFrame,
    ) -> Vec<u8> {
        let mut payload = BytesMut::new();
        frame.encode(&mut payload).expect("frame encode");
        let header = PacketHeader::Long(LongHeader {
            packet_type,
            version: 1,
            dst_cid,
            src_cid: ConnectionId::new(&[0x01, 0x02, 0x03, 0x04]).expect("src cid"),
            token: Vec::new(),
            payload_length: payload.len() as u64 + 1,
            packet_number,
            packet_number_len: 1,
        });
        let mut out = Vec::new();
        header.encode(&mut out).expect("header encode");
        out.extend_from_slice(&payload);
        out
    }

    async fn deterministic_one_rtt_protection(cx: &Cx) -> AtpPacketProtection {
        let mut transcript = QuicHandshakeTranscript::new();
        transcript.record("client_initial", b"a1 client hello");
        transcript.record("server_handshake", b"a1 server hello");
        let mut protection =
            AtpPacketProtection::new_client(true).expect("deterministic ATP packet protection");
        protection
            .derive_keys(
                cx,
                PacketProtectionSpace::OneRtt,
                &transcript,
                b"asupersync a1 protected udp handoff",
            )
            .await
            .expect("derive 1-RTT keys");
        protection
    }

    async fn add_protected_test_connection(
        cx: &Cx,
        router: &mut ConnectionRouter,
        cid: ConnectionId,
        peer: SocketAddr,
    ) {
        router
            .create_connection(cx, cid, peer, false)
            .await
            .unwrap();
        router
            .install_packet_protection(cx, cid, deterministic_one_rtt_protection(cx).await)
            .unwrap();
        establish_for_application_data(
            cx,
            &mut router.connections.get_mut(&cid).unwrap().connection,
        );
    }

    fn establish_for_application_data(cx: &Cx, connection: &mut NativeQuicConnection) {
        connection.begin_handshake(cx).expect("begin");
        connection
            .on_handshake_keys_available(cx)
            .expect("handshake keys");
        connection.on_1rtt_keys_available(cx).expect("1rtt keys");
        connection.record_verified_server_identity();
        connection
            .on_handshake_confirmed(cx)
            .expect("handshake confirmed");
    }
}
