//! Authenticated single-connection native QUIC over a real UDP endpoint.
//!
//! This module owns the production composition seam between the wire-driven
//! rustls handshake, handshake-derived 1-RTT packet protection, the real UDP
//! endpoint, and the application-facing [`QuicConnection`]. It deliberately
//! remains caller-driven: no executor, background task, or ambient listener is
//! created.
//!
//! # Caller-driven waits (GH#67)
//!
//! [`NativeQuicUdpConnection::drive_io_once`] bounds its receive wait with
//! [`timeout`] over [`QuicUdpEndpoint::receive_batch`]. Under the documented
//! composition — a plain executor such as `futures_lite::block_on` plus an
//! explicit [`Cx`] that carries no runtime drivers — both halves of that wait
//! park the calling thread: the timeout's `Sleep` registers with the
//! process-global fallback timer, and the socket's readiness interest
//! registers with the process-global fallback I/O driver owned by `net::udp`,
//! whose pump thread wakes the waiter when a datagram arrives. A quiet
//! connection therefore costs ~0 CPU between wakeups instead of re-polling in
//! a hot loop until the timeout fires. Under a runtime whose `Cx` carries I/O
//! and timer drivers, the same wait uses those drivers instead.

use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::bytes::{Bytes, BytesMut};
use crate::cx::Cx;
use crate::net::atp::protocol::quic_frames::QuicFrame;
use crate::net::atp::protocol::varint::VarInt;
use crate::net::atp::quic::{AtpPacketProtection, AtpPacketProtectionConfig};
use crate::net::quic_core::{ConnectionId, ProtectedHeaderPrefix, TransportParameters};
use crate::time::timeout;

use super::connection::{NativeQuicConnectionConfig, NativeQuicConnectionError};
use super::connection_manager::{
    ConnectionRouterError, PROTECTED_1RTT_MAX_PACKET_BYTES, RoutedOutgoingPacket,
    assemble_protected_1rtt_packet_inner, generate_congestion_admitted_1rtt_frames,
    is_ack_eliciting, protected_1rtt_packet_len, unprotect_1rtt_packet,
};
use super::endpoint::{
    OutgoingPacket, QuicUdpEndpoint, QuicUdpEndpointConfig, QuicUdpEndpointError, ReceivedPacket,
};
use super::endpoint_api::QuicConnection;
use super::handshake_driver::{
    QuicHandshakeDriver, client_handshake_over_udp, server_handshake_over_udp_with_early_data,
};
use super::managed_endpoint::{ManagedEndpointConfig, ManagedEndpointError, ManagedQuicEndpoint};
use super::streams::{StreamRole, StreamWindows};
use super::transport::{PacketNumberSpace, QuicConnectionState};

const RECEIVE_BATCH_SIZE: usize = 32;
const MAX_PACKETS_PER_FLUSH: usize = 64;
pub(crate) const FINAL_HANDSHAKE_FLIGHT_RESEND_INTERVAL: Duration = Duration::from_millis(750);

/// Progress made by one bounded live-UDP drive operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeQuicUdpIoProgress {
    /// Early 1-RTT packets retained during server handshake completion and
    /// replayed into the authenticated application-data path.
    pub early_packets_replayed: usize,
    /// Authenticated 1-RTT packets delivered to the connection state machine.
    pub packets_received: usize,
    /// Protected 1-RTT packets sent after receive processing.
    pub packets_sent: usize,
    /// Packets ignored before application delivery.
    pub packets_dropped: usize,
    /// Retained final handshake flights retransmitted after stale long-header traffic.
    pub handshake_flights_retransmitted: usize,
    /// Whether the bounded receive window elapsed without a UDP batch.
    pub receive_timed_out: bool,
}

/// Errors from the authenticated single-connection UDP owner.
#[derive(Debug)]
pub enum NativeQuicUdpConnectionError {
    /// The explicit capability context was cancelled.
    Cancelled,
    /// The real TLS/QUIC handshake failed.
    Handshake(super::tls::QuicTlsError),
    /// The native connection state machine rejected an operation.
    Transport(NativeQuicConnectionError),
    /// The real UDP endpoint failed.
    Endpoint(QuicUdpEndpointError),
    /// The completed handshake did not install all required state.
    HandshakeIncomplete(&'static str),
    /// TLS selected a protocol other than the required application protocol.
    AlpnMismatch {
        /// Required ALPN.
        expected: Vec<u8>,
        /// Negotiated ALPN, or `None` when the peer selected none.
        negotiated: Option<Vec<u8>>,
    },
    /// TLS-authenticated QUIC transport parameters were missing or invalid.
    TransportParameters(String),
    /// The packet-protection or packet-assembly boundary failed.
    Packet(String),
    /// A UDP batch reported partial failure.
    BatchSend(String),
}

impl fmt::Display for NativeQuicUdpConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "native QUIC UDP operation cancelled"),
            Self::Handshake(error) => write!(f, "native QUIC handshake failed: {error}"),
            Self::Transport(error) => write!(f, "native QUIC transport failed: {error}"),
            Self::Endpoint(error) => write!(f, "native QUIC UDP endpoint failed: {error}"),
            Self::HandshakeIncomplete(reason) => {
                write!(f, "native QUIC handshake handoff incomplete: {reason}")
            }
            Self::AlpnMismatch {
                expected,
                negotiated,
            } => write!(
                f,
                "native QUIC ALPN mismatch: expected {:?}, negotiated {:?}",
                String::from_utf8_lossy(expected),
                negotiated.as_deref().map(String::from_utf8_lossy)
            ),
            Self::TransportParameters(reason) => {
                write!(f, "native QUIC transport parameters invalid: {reason}")
            }
            Self::Packet(reason) => write!(f, "native QUIC packet failed: {reason}"),
            Self::BatchSend(reason) => write!(f, "native QUIC UDP batch failed: {reason}"),
        }
    }
}

impl std::error::Error for NativeQuicUdpConnectionError {}

impl From<NativeQuicConnectionError> for NativeQuicUdpConnectionError {
    fn from(value: NativeQuicConnectionError) -> Self {
        match value {
            NativeQuicConnectionError::Cancelled => Self::Cancelled,
            other => Self::Transport(other),
        }
    }
}

impl From<QuicUdpEndpointError> for NativeQuicUdpConnectionError {
    fn from(value: QuicUdpEndpointError) -> Self {
        match value {
            QuicUdpEndpointError::Cancelled => Self::Cancelled,
            other => Self::Endpoint(other),
        }
    }
}

impl From<ConnectionRouterError> for NativeQuicUdpConnectionError {
    fn from(value: ConnectionRouterError) -> Self {
        match value {
            ConnectionRouterError::Cancelled => Self::Cancelled,
            other => Self::Packet(other.to_string()),
        }
    }
}

/// One authenticated native QUIC connection bound to its real UDP socket.
///
/// The handle is intentionally not split: application stream state, packet
/// protection, connection IDs, timers, and UDP ownership cannot outlive or
/// silently detach from one another. Callers queue/read streams through
/// [`Self::connection_mut`], then call [`Self::flush`] and
/// [`Self::drive_io_once`] from their structured-concurrency scope.
/// [`Self::into_managed`] transfers this complete owner into a managed endpoint
/// without repeating the handshake or detaching its packet protection.
pub struct NativeQuicUdpConnection {
    connection: QuicConnection,
    endpoint: QuicUdpEndpoint,
    protection: AtpPacketProtection,
    local_cid: ConnectionId,
    peer_cid: ConnectionId,
    peer_addr: SocketAddr,
    negotiated_alpn: Vec<u8>,
    final_handshake_flight: Vec<OutgoingPacket>,
    early_one_rtt_packets: Vec<ReceivedPacket>,
    last_final_flight_retransmit: Option<Instant>,
    clock_origin: Instant,
    // Already protected/accounted packets remain owned across a dropped flush.
    pending_outgoing: Vec<RoutedOutgoingPacket>,
    local_close: Option<LocalClosePacket>,
}

/// One encrypted close is retained through send failure and reused verbatim
/// for bounded responses. Reusing ciphertext does not reuse an AEAD nonce for
/// a new encryption operation.
struct LocalClosePacket {
    packet: OutgoingPacket,
    pending: bool,
    last_sent: Option<Instant>,
}

/// Crate-private ownership transfer after the managed endpoint's preflight.
///
/// Keep the complete application handle and its original recovery clock. These
/// parts are moved, never reconstructed from handshake flags or cloned keys.
/// The retained packet vectors keep their existing order and timestamps.
pub(crate) struct NativeQuicUdpHandoffParts {
    pub(crate) connection: QuicConnection,
    pub(crate) endpoint: QuicUdpEndpoint,
    pub(crate) protection: AtpPacketProtection,
    pub(crate) local_cid: ConnectionId,
    pub(crate) peer_cid: ConnectionId,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) negotiated_alpn: Vec<u8>,
    pub(crate) final_handshake_flight: Vec<OutgoingPacket>,
    pub(crate) early_one_rtt_packets: Vec<ReceivedPacket>,
    pub(crate) last_final_flight_retransmit: Option<Instant>,
    pub(crate) clock_origin: Instant,
    pub(crate) pending_outgoing: Vec<RoutedOutgoingPacket>,
}

/// TLS-derived application ownership independent of the socket that drove it.
/// Only the completed-driver validator below creates these parts; managed
/// admission keeps its original UDP endpoint throughout the handshake.
pub(crate) struct AuthenticatedQuicParts {
    pub(crate) connection: QuicConnection,
    pub(crate) protection: AtpPacketProtection,
    pub(crate) peer_cid: ConnectionId,
    pub(crate) negotiated_alpn: Vec<u8>,
    pub(crate) final_handshake_flight: Vec<OutgoingPacket>,
}

/// A refused managed handoff, retaining the original authenticated UDP owner.
///
/// No connection, socket, queued stream data, packet-protection state, or
/// retained handshake/early packets are discarded by a preflight refusal.
/// Recover the owner with [`Self::into_connection`] to continue driving it or
/// retry the handoff with a suitable context and configuration.
#[derive(Debug)]
pub struct ManagedQuicHandoffError {
    error: ManagedEndpointError,
    connection: Box<NativeQuicUdpConnection>,
}

impl ManagedQuicHandoffError {
    pub(crate) fn new(error: ManagedEndpointError, connection: NativeQuicUdpConnection) -> Self {
        Self {
            error,
            connection: Box::new(connection),
        }
    }

    /// The typed reason the managed endpoint refused the handoff.
    #[must_use]
    pub fn error(&self) -> &ManagedEndpointError {
        &self.error
    }

    /// Inspect the original owner without consuming the refusal.
    #[must_use]
    pub fn connection(&self) -> &NativeQuicUdpConnection {
        &self.connection
    }

    /// Recover the original authenticated UDP owner.
    #[must_use]
    pub fn into_connection(self) -> NativeQuicUdpConnection {
        *self.connection
    }

    /// Recover both the refusal reason and the original owner.
    #[must_use]
    pub fn into_parts(self) -> (ManagedEndpointError, NativeQuicUdpConnection) {
        (self.error, *self.connection)
    }
}

impl fmt::Display for ManagedQuicHandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native QUIC managed handoff refused: {}", self.error)
    }
}

impl std::error::Error for ManagedQuicHandoffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl fmt::Debug for NativeQuicUdpConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeQuicUdpConnection")
            .field("role", &self.connection.role())
            .field("local_addr", &self.endpoint.local_addr())
            .field("peer_addr", &self.peer_addr)
            .field("local_cid", &self.local_cid)
            .field("peer_cid", &self.peer_cid)
            .field(
                "negotiated_alpn",
                &String::from_utf8_lossy(&self.negotiated_alpn),
            )
            .finish_non_exhaustive()
    }
}

impl NativeQuicUdpConnection {
    /// Transfer this authenticated connection and its socket to a managed driver.
    ///
    /// The handoff preserves the whole application handle, verified TLS state,
    /// packet-protection provider, negotiated transport parameters and ALPN,
    /// distinct local/peer connection IDs, original recovery clock, retained
    /// final handshake flight, and early application packets in their order.
    /// It performs no network I/O and starts no background task. Drive the
    /// returned endpoint from the caller's structured-concurrency scope.
    ///
    /// The supplied configuration controls managed scheduling and lifecycle.
    /// Its UDP and connection templates do not reconfigure the already bound
    /// socket or replace the authenticated connection's negotiated state.
    ///
    /// # Errors
    ///
    /// Returns the original owner with a typed reason when managed preflight
    /// refuses the context, configuration, role, clock, or connection state.
    pub fn into_managed(
        self,
        cx: &Cx,
        config: ManagedEndpointConfig,
    ) -> Result<ManagedQuicEndpoint, ManagedQuicHandoffError> {
        ManagedQuicEndpoint::from_authenticated_connection(cx, self, config)
    }

    /// The exact configuration retained by the already bound UDP endpoint.
    pub(crate) fn udp_config(&self) -> &QuicUdpEndpointConfig {
        self.endpoint.config()
    }

    pub(crate) fn into_managed_parts(self) -> NativeQuicUdpHandoffParts {
        // Managed preflight refuses a draining/closed owner and returns it
        // intact, including this cache. Only established owners reach here.
        debug_assert!(self.local_close.is_none());
        let Self {
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
            pending_outgoing,
            local_close: _,
        } = self;
        NativeQuicUdpHandoffParts {
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
            pending_outgoing,
        }
    }

    pub(crate) fn from_managed_parts(parts: NativeQuicUdpHandoffParts) -> Self {
        let NativeQuicUdpHandoffParts {
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
            pending_outgoing,
        } = parts;
        Self {
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
            pending_outgoing,
            local_close: None,
        }
    }

    /// Complete a client handshake over `endpoint` and bind its authenticated
    /// state directly to a live application-data connection.
    pub async fn connect(
        cx: &Cx,
        endpoint: QuicUdpEndpoint,
        peer_addr: SocketAddr,
        mut driver: QuicHandshakeDriver,
        initial_dcid: ConnectionId,
        local_cid: ConnectionId,
        connection_config: NativeQuicConnectionConfig,
        required_alpn: &[u8],
    ) -> Result<Self, NativeQuicUdpConnectionError> {
        if cx.checkpoint().is_err() {
            return Err(NativeQuicUdpConnectionError::Cancelled);
        }
        let mut endpoint = endpoint;
        if let Err(error) = client_handshake_over_udp(
            cx,
            &mut endpoint,
            peer_addr,
            &mut driver,
            initial_dcid,
            local_cid,
        )
        .await
        {
            return if cx.checkpoint().is_err() {
                Err(NativeQuicUdpConnectionError::Cancelled)
            } else {
                Err(NativeQuicUdpConnectionError::Handshake(error))
            };
        }
        Self::from_completed_handshake(
            cx,
            endpoint,
            peer_addr,
            driver,
            local_cid,
            connection_config,
            required_alpn,
            StreamRole::Client,
            Vec::new(),
        )
    }

    /// Complete a server handshake over `endpoint` and bind its authenticated
    /// state directly to a live application-data connection.
    ///
    /// `initial_dcid` is the destination CID from the client's Initial packet;
    /// a multi-connection listener is responsible for inspecting and routing
    /// that first datagram before calling this single-connection API.
    pub async fn accept(
        cx: &Cx,
        endpoint: QuicUdpEndpoint,
        mut driver: QuicHandshakeDriver,
        initial_dcid: ConnectionId,
        local_cid: ConnectionId,
        connection_config: NativeQuicConnectionConfig,
        required_alpn: &[u8],
    ) -> Result<Self, NativeQuicUdpConnectionError> {
        if cx.checkpoint().is_err() {
            return Err(NativeQuicUdpConnectionError::Cancelled);
        }
        let mut endpoint = endpoint;
        let (peer_addr, early_one_rtt_packets) = match server_handshake_over_udp_with_early_data(
            cx,
            &mut endpoint,
            &mut driver,
            initial_dcid,
            local_cid,
        )
        .await
        {
            Ok(peer_addr) => peer_addr,
            Err(error) => {
                return if cx.checkpoint().is_err() {
                    Err(NativeQuicUdpConnectionError::Cancelled)
                } else {
                    Err(NativeQuicUdpConnectionError::Handshake(error))
                };
            }
        };
        Self::from_completed_handshake(
            cx,
            endpoint,
            peer_addr,
            driver,
            local_cid,
            connection_config,
            required_alpn,
            StreamRole::Server,
            early_one_rtt_packets,
        )
    }

    fn from_completed_handshake(
        cx: &Cx,
        endpoint: QuicUdpEndpoint,
        peer_addr: SocketAddr,
        driver: QuicHandshakeDriver,
        local_cid: ConnectionId,
        connection_config: NativeQuicConnectionConfig,
        required_alpn: &[u8],
        role: StreamRole,
        early_one_rtt_packets: Vec<ReceivedPacket>,
    ) -> Result<Self, NativeQuicUdpConnectionError> {
        let parts = Self::finish_authenticated_handshake(
            cx,
            driver,
            connection_config,
            required_alpn,
            role,
        )?;
        Ok(Self {
            connection: parts.connection,
            endpoint,
            protection: parts.protection,
            local_cid,
            peer_cid: parts.peer_cid,
            peer_addr,
            negotiated_alpn: parts.negotiated_alpn,
            final_handshake_flight: parts.final_handshake_flight,
            early_one_rtt_packets,
            last_final_flight_retransmit: None,
            clock_origin: Instant::now(),
            pending_outgoing: Vec::new(),
            local_close: None,
        })
    }

    pub(crate) fn finish_authenticated_handshake(
        cx: &Cx,
        mut driver: QuicHandshakeDriver,
        connection_config: NativeQuicConnectionConfig,
        required_alpn: &[u8],
        role: StreamRole,
    ) -> Result<AuthenticatedQuicParts, NativeQuicUdpConnectionError> {
        if !driver.is_complete() || !driver.one_rtt_keys_installed() {
            return Err(NativeQuicUdpConnectionError::HandshakeIncomplete(
                "TLS did not complete with installed 1-RTT keys",
            ));
        }
        let negotiated_alpn = match driver.negotiated_alpn().map(<[u8]>::to_vec) {
            Some(negotiated) if negotiated == required_alpn => negotiated,
            negotiated => {
                return Err(NativeQuicUdpConnectionError::AlpnMismatch {
                    expected: required_alpn.to_vec(),
                    negotiated,
                });
            }
        };
        let peer_cid = driver.peer_connection_id().ok_or(
            NativeQuicUdpConnectionError::HandshakeIncomplete(
                "peer connection ID was not authenticated",
            ),
        )?;

        let local_parameters = TransportParameters::decode(driver.local_transport_parameters())
            .map_err(|error| {
                NativeQuicUdpConnectionError::TransportParameters(format!(
                    "local decode failed: {error}"
                ))
            })?;
        let peer_parameter_bytes = driver.peer_transport_parameters().ok_or(
            NativeQuicUdpConnectionError::HandshakeIncomplete(
                "peer transport parameters were not authenticated",
            ),
        )?;
        let peer_parameters =
            TransportParameters::decode(peer_parameter_bytes).map_err(|error| {
                NativeQuicUdpConnectionError::TransportParameters(format!(
                    "peer decode failed: {error}"
                ))
            })?;
        let bound =
            bind_transport_parameters(connection_config, &local_parameters, &peer_parameters);

        let mut connection = match role {
            StreamRole::Client => QuicConnection::client(bound.config),
            StreamRole::Server => QuicConnection::server(bound.config),
        };
        connection
            .inner_mut()
            .set_negotiated_idle_timeout(&local_parameters, &peer_parameters);
        connection.inner_mut().set_remote_stream_limits(
            local_parameters.initial_max_streams_bidi.unwrap_or(0),
            local_parameters.initial_max_streams_uni.unwrap_or(0),
        );
        connection
            .inner_mut()
            .set_initial_stream_windows(bound.send_windows, bound.recv_windows);
        connection.begin_handshake(cx)?;
        connection.mark_handshake_keys_available(cx)?;
        connection.mark_app_keys_available(cx)?;
        if role == StreamRole::Client {
            // Reaching here means rustls/WebPKI completed the client handshake
            // for its configured ServerName and roots.
            connection.record_verified_server_identity();
            connection
                .inner_mut()
                .on_authenticated_handshake_complete(cx)?;
        } else {
            connection.confirm_handshake(cx)?;
        }

        // DATAGRAM admission must know this connection's exact packet budget
        // before the first flush (GH#66).
        connection.inner_mut().set_one_rtt_frame_budget(
            PROTECTED_1RTT_MAX_PACKET_BYTES.saturating_sub(protected_1rtt_packet_len(peer_cid, 0)),
        );
        let final_handshake_flight = driver.take_final_flight();
        let protection = AtpPacketProtection::from_provider(
            Box::new(driver.into_provider()),
            AtpPacketProtectionConfig::default(),
        );
        Ok(AuthenticatedQuicParts {
            connection,
            protection,
            peer_cid,
            negotiated_alpn,
            final_handshake_flight,
        })
    }

    /// Application-facing QUIC stream/datagram handle.
    #[must_use]
    pub fn connection(&self) -> &QuicConnection {
        &self.connection
    }

    /// Application-facing mutable QUIC stream/datagram handle.
    pub fn connection_mut(&mut self) -> &mut QuicConnection {
        &mut self.connection
    }

    /// UDP socket address owned by this connection.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr()
    }

    /// Authenticated peer UDP address.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Connection ID the peer uses as its short-header destination.
    #[must_use]
    pub fn local_connection_id(&self) -> ConnectionId {
        self.local_cid
    }

    /// Authenticated peer source CID retained from the handshake.
    #[must_use]
    pub fn peer_connection_id(&self) -> ConnectionId {
        self.peer_cid
    }

    /// Exact ALPN admitted before application state was exposed.
    #[must_use]
    pub fn negotiated_alpn(&self) -> &[u8] {
        &self.negotiated_alpn
    }

    /// Begin a local application close using this owner's recovery clock and
    /// flush its protected CONNECTION_CLOSE. Continue driving I/O during the
    /// configured drain window to answer subsequent peer traffic with bounded
    /// retransmissions. A send error retains the close for a later `flush`.
    pub async fn close(
        &mut self,
        cx: &Cx,
        app_error_code: u64,
    ) -> Result<usize, NativeQuicUdpConnectionError> {
        cx.checkpoint()
            .map_err(|_| NativeQuicUdpConnectionError::Cancelled)?;
        if VarInt::new(app_error_code).is_err() {
            return Err(NativeQuicConnectionError::InvalidState(
                "application close code must fit a QUIC varint",
            )
            .into());
        }
        if self.connection.inner().state() != QuicConnectionState::Closed {
            let now_micros = self.instant_micros(Instant::now());
            self.connection
                .begin_close(cx, now_micros, app_error_code)?;
        }
        self.flush(cx).await
    }

    async fn flush_local_close(
        &mut self,
        cx: &Cx,
        now: Instant,
    ) -> Result<usize, NativeQuicUdpConnectionError> {
        if self.connection.close_was_peer_initiated() {
            self.local_close = None;
            return Ok(0);
        }
        if self.local_close.is_none() {
            let code = self.connection.inner().transport().close_code().ok_or(
                NativeQuicConnectionError::InvalidState("local close has no error code"),
            )?;
            let crate::types::Outcome::Ok(error_code) = VarInt::new(code) else {
                return Err(NativeQuicConnectionError::InvalidState(
                    "application close code must fit a QUIC varint",
                )
                .into());
            };
            let frames = [QuicFrame::ConnectionClose {
                error_code,
                frame_type: None,
                reason_phrase: Bytes::new(),
            }];
            let mut payload = BytesMut::new();
            super::NativeQuicConnection::encode_frames(&frames, &mut payload)?;
            let now_micros = self.instant_micros(now);
            let data = assemble_protected_1rtt_packet_inner(
                cx,
                self.peer_cid,
                self.connection.inner_mut(),
                &mut self.protection,
                &frames,
                &payload,
                now_micros,
                false,
                false,
            )
            .await?;
            self.local_close = Some(LocalClosePacket {
                packet: OutgoingPacket {
                    dst_addr: self.peer_addr,
                    data,
                    send_time: Some(now),
                },
                pending: true,
                last_sent: None,
            });
        }
        let clock_origin = self.clock_origin;
        let close = self.local_close.as_mut().expect("retained local close");
        if !close.pending {
            return Ok(0);
        }
        let limit = self.endpoint.config().max_packet_size;
        if close.packet.data.len() > limit {
            return Err(QuicUdpEndpointError::PacketTooLarge {
                size: close.packet.data.len(),
                limit,
            }
            .into());
        }
        std::future::poll_fn(|task_cx| {
            use std::task::Poll;
            // A previous poll may have parked on socket writability. Do not
            // send after the deadline merely because this flush began earlier.
            let now_micros = Instant::now()
                .saturating_duration_since(clock_origin)
                .as_micros()
                .min(u128::from(u64::MAX)) as u64;
            if let Err(error) = self.connection.inner_mut().poll(cx, now_micros) {
                return Poll::Ready(Err(error.into()));
            }
            if self.connection.inner().state() == QuicConnectionState::Closed {
                close.pending = false;
                return Poll::Ready(Ok(0));
            }
            let report =
                match self
                    .endpoint
                    .poll_send_batch(cx, task_cx, std::iter::once(&close.packet))
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Err(
                            if error.kind() == std::io::ErrorKind::Interrupted {
                                NativeQuicUdpConnectionError::Cancelled
                            } else {
                                NativeQuicUdpConnectionError::Endpoint(error.into())
                            },
                        ));
                    }
                    Poll::Ready(Ok(report)) => report,
                };
            if report.packets_processed > 0 {
                close.pending = false;
                close.last_sent = Some(Instant::now());
            }
            if let Some(error) = report.error {
                return Poll::Ready(Err(NativeQuicUdpConnectionError::BatchSend(error)));
            }
            if report.packets_processed == 0 {
                return Poll::Ready(Err(NativeQuicUdpConnectionError::BatchSend(
                    "UDP close send made no progress".to_owned(),
                )));
            }
            Poll::Ready(Ok(report.packets_processed))
        })
        .await
    }

    /// Protect and send a bounded batch of queued application frames, or the
    /// retained local close while draining.
    /// Unsent protected packets stay in this owner across errors or a dropped
    /// flush future and are retried before new application frames are admitted.
    pub async fn flush(&mut self, cx: &Cx) -> Result<usize, NativeQuicUdpConnectionError> {
        if cx.checkpoint().is_err() {
            return Err(NativeQuicUdpConnectionError::Cancelled);
        }
        let now = Instant::now();
        let now_micros = self.instant_micros(now);
        let state = self.connection.inner().state();
        if matches!(
            state,
            QuicConnectionState::Closed | QuicConnectionState::Draining
        ) {
            self.connection.inner_mut().poll(cx, now_micros)?;
            self.pending_outgoing.clear();
            if self.connection.inner().state() == QuicConnectionState::Closed {
                self.local_close = None;
                return Ok(0);
            }
            return self.flush_local_close(cx, now).await;
        }
        let max_frame_bytes = PROTECTED_1RTT_MAX_PACKET_BYTES
            .saturating_sub(protected_1rtt_packet_len(self.peer_cid, 0));
        self.connection
            .inner_mut()
            .set_one_rtt_frame_budget(max_frame_bytes);
        // Retry retained output before admitting more application work.
        let packet_budget = if self.pending_outgoing.is_empty() {
            MAX_PACKETS_PER_FLUSH
        } else {
            0
        };
        for _ in 0..packet_budget {
            // A due PTO permits one PING even when the original flight fills
            // cwnd. It must not drain application frames or declare them lost.
            let probe_frames = self
                .connection
                .inner_mut()
                .generate_pto_probe_frames(cx, max_frame_bytes)?;
            let pto_probe = !probe_frames.is_empty();
            let frames = if pto_probe {
                probe_frames
            } else {
                generate_congestion_admitted_1rtt_frames(
                    cx,
                    self.connection.inner_mut(),
                    max_frame_bytes,
                )?
            };
            if frames.is_empty() {
                break;
            }
            let mut payload = BytesMut::new();
            super::connection::NativeQuicConnection::encode_frames(&frames, &mut payload)?;
            let assembled = assemble_protected_1rtt_packet_inner(
                cx,
                self.peer_cid,
                self.connection.inner_mut(),
                &mut self.protection,
                &frames,
                payload.as_ref(),
                now_micros,
                frames.iter().any(is_ack_eliciting),
                pto_probe,
            )
            .await;
            let data = match assembled {
                Ok(data) => data,
                Err(error) => {
                    if !pto_probe {
                        self.connection
                            .inner_mut()
                            .on_generated_frames_dropped(&frames)?;
                    }
                    return Err(error.into());
                }
            };
            self.pending_outgoing.push(RoutedOutgoingPacket {
                connection_id: self.local_cid,
                packet: OutgoingPacket {
                    dst_addr: self.peer_addr,
                    data,
                    send_time: Some(now),
                },
                final_handshake_flight: false,
                ack_eliciting: frames.iter().any(is_ack_eliciting),
            });
        }

        // Preserve the public endpoint error classification used by send_batch.
        let packet_limit = self.endpoint.config().max_packet_size;
        if let Some(packet) = self
            .pending_outgoing
            .iter()
            .find(|packet| packet.packet.data.len() > packet_limit)
        {
            return Err(QuicUdpEndpointError::PacketTooLarge {
                size: packet.packet.data.len(),
                limit: packet_limit,
            }
            .into());
        }
        let mut sent = 0;
        std::future::poll_fn(|task_cx| {
            while !self.pending_outgoing.is_empty() {
                let report = match self.endpoint.poll_send_batch(
                    cx,
                    task_cx,
                    self.pending_outgoing.iter().map(|packet| &packet.packet),
                ) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Ok(report)) => report,
                    std::task::Poll::Ready(Err(error)) => {
                        return std::task::Poll::Ready(Err(
                            if error.kind() == std::io::ErrorKind::Interrupted {
                                NativeQuicUdpConnectionError::Cancelled
                            } else {
                                NativeQuicUdpConnectionError::Endpoint(error.into())
                            },
                        ));
                    }
                };
                // Publish every acknowledged prefix before returning Pending
                // or an error. The future owns no unsent wire bytes.
                drop(self.pending_outgoing.drain(..report.packets_processed));
                sent += report.packets_processed;
                if let Some(error) = report.error {
                    return std::task::Poll::Ready(Err(NativeQuicUdpConnectionError::BatchSend(
                        error,
                    )));
                }
                if report.packets_processed == 0 {
                    return std::task::Poll::Ready(Err(NativeQuicUdpConnectionError::BatchSend(
                        "UDP send made no progress".to_owned(),
                    )));
                }
            }
            std::task::Poll::Ready(Ok(sent))
        })
        .await
    }

    /// Receive at most one bounded UDP batch, deliver authenticated 1-RTT
    /// payloads, service a due loss timer, and flush resulting ACK/application
    /// frames. A quiet timeout is reported as progress rather than an error so
    /// callers can compose their own explicit drive loop and cancellation scope.
    pub async fn drive_io_once(
        &mut self,
        cx: &Cx,
        receive_timeout: Duration,
    ) -> Result<NativeQuicUdpIoProgress, NativeQuicUdpConnectionError> {
        if cx.checkpoint().is_err() {
            return Err(NativeQuicUdpConnectionError::Cancelled);
        }
        let mut progress = NativeQuicUdpIoProgress::default();
        let received = if self.early_one_rtt_packets.is_empty() {
            let bounded_wait = self.receive_wait_duration(cx, receive_timeout)?;
            if bounded_wait.is_zero() {
                progress.receive_timed_out = true;
                self.service_due_loss_timer(cx)?;
                progress.packets_sent = self.flush(cx).await?;
                return Ok(progress);
            }
            match timeout(
                cx.now(),
                bounded_wait,
                self.endpoint.receive_batch(cx, RECEIVE_BATCH_SIZE),
            )
            .await
            {
                Ok(Ok(packets)) => packets,
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {
                    progress.receive_timed_out = true;
                    self.service_due_loss_timer(cx)?;
                    progress.packets_sent = self.flush(cx).await?;
                    return Ok(progress);
                }
            }
        } else {
            let early = std::mem::take(&mut self.early_one_rtt_packets);
            progress.early_packets_replayed = early.len();
            early
        };

        for packet in received {
            if packet.src_addr != self.peer_addr {
                progress.packets_dropped = progress.packets_dropped.saturating_add(1);
                continue;
            }
            if matches!(
                self.connection.inner().state(),
                QuicConnectionState::Draining | QuicConnectionState::Closed
            ) {
                // Never retransmit retained handshake/application data after
                // closing. Only matching peer traffic can arm a cached close,
                // at most once per base PTO, until the drain deadline expires.
                if self.connection.inner().state() == QuicConnectionState::Draining
                    && matches!(ProtectedHeaderPrefix::decode(&packet.data, self.local_cid.len()),
                        Ok(ProtectedHeaderPrefix::Short { dst_cid, .. }) if dst_cid == self.local_cid)
                {
                    let interval = Duration::from_micros(
                        self.connection
                            .inner()
                            .transport()
                            .idle_timeout_floor_micros()
                            / 3,
                    )
                    .max(Duration::from_millis(1));
                    if let Some(close) = &mut self.local_close {
                        if close.last_sent.is_none_or(|last| {
                            packet.receive_time.saturating_duration_since(last) >= interval
                        }) {
                            close.pending = true;
                        }
                    }
                }
                progress.packets_dropped = progress.packets_dropped.saturating_add(1);
                continue;
            }
            if packet.data.first().is_some_and(|byte| byte & 0x80 != 0) {
                progress.packets_dropped = progress.packets_dropped.saturating_add(1);
                if super::connection_manager::authenticated_handshake_ack_only(
                    cx,
                    self.local_cid,
                    &mut self.protection,
                    &packet.data,
                ) {
                    continue;
                }
                if !self.final_handshake_flight.is_empty()
                    && self.last_final_flight_retransmit.is_none_or(|last| {
                        packet.receive_time.saturating_duration_since(last)
                            >= FINAL_HANDSHAKE_FLIGHT_RESEND_INTERVAL
                    })
                {
                    let report = self
                        .endpoint
                        .send_batch(cx, &self.final_handshake_flight)
                        .await?;
                    if report.packets_processed != self.final_handshake_flight.len()
                        || report.error.is_some()
                    {
                        return Err(NativeQuicUdpConnectionError::BatchSend(
                            report.error.unwrap_or_else(|| {
                                "final handshake flight was only partially retransmitted"
                                    .to_string()
                            }),
                        ));
                    }
                    progress.handshake_flights_retransmitted =
                        progress.handshake_flights_retransmitted.saturating_add(1);
                    self.last_final_flight_retransmit = Some(packet.receive_time);
                }
                continue;
            }

            // Only the header-protection-invariant prefix is readable before
            // the peer's HP key unmasks the packet number (RFC 9001 §5.4);
            // `unprotect_1rtt_packet` does the unmask + AEAD in RFC order.
            let Ok(ProtectedHeaderPrefix::Short { dst_cid, .. }) =
                ProtectedHeaderPrefix::decode(&packet.data, self.local_cid.len())
            else {
                progress.packets_dropped = progress.packets_dropped.saturating_add(1);
                continue;
            };
            if dst_cid != self.local_cid {
                progress.packets_dropped = progress.packets_dropped.saturating_add(1);
                continue;
            }
            let unprotected =
                match unprotect_1rtt_packet(cx, self.local_cid, &mut self.protection, &packet.data)
                    .await
                {
                    Ok(unprotected) => unprotected,
                    Err(ConnectionRouterError::Cancelled) => {
                        return Err(NativeQuicUdpConnectionError::Cancelled);
                    }
                    Err(_) => {
                        progress.packets_dropped = progress.packets_dropped.saturating_add(1);
                        continue;
                    }
                };
            let header = unprotected.header;
            let plaintext = unprotected.plaintext;
            self.connection
                .inner_mut()
                .on_datagram_received(cx, packet.data.len() as u64)?;
            let now_micros = self.instant_micros(packet.receive_time);
            if let Err(error) = self.connection.inner_mut().process_packet_payload(
                cx,
                PacketNumberSpace::ApplicationData,
                header.packet_number,
                &plaintext,
                now_micros,
            ) {
                if error.is_stream_reassembly_backpressure() {
                    // Do not ACK or park ahead of the packet that fills the
                    // hole. Reliable frames can return under a fresh number.
                    progress.packets_dropped = progress.packets_dropped.saturating_add(1);
                    continue;
                }
                return Err(error.into());
            }
            progress.packets_received = progress.packets_received.saturating_add(1);
        }

        self.service_due_loss_timer(cx)?;
        progress.packets_sent = self.flush(cx).await?;
        Ok(progress)
    }

    fn instant_micros(&self, instant: Instant) -> u64 {
        instant
            .checked_duration_since(self.clock_origin)
            .unwrap_or(Duration::ZERO)
            .as_micros()
            .min(u128::from(u64::MAX)) as u64
    }

    fn receive_wait_duration(
        &mut self,
        cx: &Cx,
        requested: Duration,
    ) -> Result<Duration, NativeQuicUdpConnectionError> {
        let now = Instant::now();
        let now_micros = self.instant_micros(now);
        let deadline = match self.connection.inner().state() {
            QuicConnectionState::Draining => {
                self.connection.inner().transport().drain_deadline_micros()
            }
            // Preserve caller-driven idle pacing after expiry. Returning zero
            // forever would turn an existing drive loop into a busy loop.
            QuicConnectionState::Closed => return Ok(requested),
            _ => self
                .connection
                .inner_mut()
                .pto_deadline_micros(cx, now_micros)?,
        };
        let Some(deadline_micros) = deadline else {
            return Ok(requested);
        };
        Ok(requested.min(Duration::from_micros(
            deadline_micros.saturating_sub(now_micros),
        )))
    }

    fn service_due_loss_timer(&mut self, cx: &Cx) -> Result<(), NativeQuicUdpConnectionError> {
        let now_micros = self.instant_micros(Instant::now());
        if matches!(
            self.connection.inner().state(),
            QuicConnectionState::Draining | QuicConnectionState::Closed
        ) {
            self.connection.inner_mut().poll(cx, now_micros)?;
            return Ok(());
        }
        let Some(deadline) = self
            .connection
            .inner_mut()
            .pto_deadline_micros(cx, now_micros)?
        else {
            return Ok(());
        };
        if deadline <= now_micros {
            self.connection
                .inner_mut()
                .on_managed_probe_timeout(cx, now_micros)?;
        }
        Ok(())
    }
}

/// Connection configuration after the authenticated transport parameters of
/// both endpoints have been applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BoundTransportParameters {
    /// Stream counts, connection-level limits and the DATAGRAM cap, each the
    /// smaller of the configured value and the negotiated one. `send_window`
    /// and `recv_window` stay the configured per-stream caps.
    config: NativeQuicConnectionConfig,
    /// Per-type initial send windows: the peer's `initial_max_stream_data_*`
    /// values capped by `config.send_window` (RFC 9000 §18.2).
    send_windows: StreamWindows,
    /// Per-type initial receive windows: this endpoint's
    /// `initial_max_stream_data_*` values capped by `config.recv_window`.
    recv_windows: StreamWindows,
}

/// Bind both endpoints' transport parameters onto the connection configuration.
///
/// Stream windows are kept per stream type. A locally opened bidirectional
/// stream sends against the peer's `initial_max_stream_data_bidi_remote` and
/// receives against the local `initial_max_stream_data_bidi_local`; a
/// peer-opened bidirectional stream uses the mirrored pair; unidirectional
/// streams use `initial_max_stream_data_uni` on their data-carrying side. A
/// parameter an endpoint omits is zero for that type only, so a peer that does
/// not advertise a unidirectional window still gets its full bidirectional
/// windows.
fn bind_transport_parameters(
    mut config: NativeQuicConnectionConfig,
    local: &TransportParameters,
    peer: &TransportParameters,
) -> BoundTransportParameters {
    config.max_local_bidi = config
        .max_local_bidi
        .min(peer.initial_max_streams_bidi.unwrap_or(0));
    config.max_local_uni = config
        .max_local_uni
        .min(peer.initial_max_streams_uni.unwrap_or(0));
    config.connection_send_limit = config
        .connection_send_limit
        .min(peer.initial_max_data.unwrap_or(0));
    config.connection_recv_limit = config
        .connection_recv_limit
        .min(local.initial_max_data.unwrap_or(0));

    let send_cap = config.send_window;
    let send_windows = StreamWindows {
        local_bidi: send_cap.min(peer.initial_max_stream_data_bidi_remote.unwrap_or(0)),
        remote_bidi: send_cap.min(peer.initial_max_stream_data_bidi_local.unwrap_or(0)),
        uni: send_cap.min(peer.initial_max_stream_data_uni.unwrap_or(0)),
    };
    let recv_cap = config.recv_window;
    let recv_windows = StreamWindows {
        local_bidi: recv_cap.min(local.initial_max_stream_data_bidi_local.unwrap_or(0)),
        remote_bidi: recv_cap.min(local.initial_max_stream_data_bidi_remote.unwrap_or(0)),
        uni: recv_cap.min(local.initial_max_stream_data_uni.unwrap_or(0)),
    };
    config.max_datagram_frame_size = config.max_datagram_frame_size.min(
        peer.max_datagram_frame_size
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
    );
    BoundTransportParameters {
        config,
        send_windows,
        recv_windows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Bytes;
    use crate::net::atp::protocol::quic_frames::QuicFrame;
    use crate::net::atp::protocol::varint::VarInt;
    use crate::net::quic_native::connection::NativeQuicConnection;
    use crate::net::quic_native::connection_manager::{
        ConnectionRouter, RoutingResult, assemble_protected_1rtt_packet,
    };
    use crate::net::quic_native::handshake_driver::tests::{
        CA_CERT_PEM, LEAF_CERT_PEM, leaf_key, parse_one_cert,
    };
    use crate::net::quic_native::handshake_driver::{client_config, server_config};
    use crate::net::quic_native::{QuicConnectionState, StreamId};
    use futures_lite::future::{block_on, zip};
    use rustls::pki_types::ServerName;

    /// A peer that omits `initial_max_stream_data_uni` (as the managed-quiet
    /// loopback pair does) must keep full bidirectional windows. The previous
    /// binding took the minimum over all three per-type parameters with an
    /// omitted one counted as zero, which left every stream with zero send
    /// credit and failed the first `write_stream` with `Flow(Exhausted)`.
    #[test]
    fn bind_transport_parameters_keeps_bidi_windows_when_uni_is_omitted() {
        let config = NativeQuicConnectionConfig {
            max_local_bidi: 4,
            max_local_uni: 4,
            send_window: 1 << 18,
            recv_window: 1 << 18,
            connection_send_limit: 1 << 20,
            connection_recv_limit: 1 << 20,
            ..NativeQuicConnectionConfig::default()
        };
        let peer = TransportParameters {
            initial_max_data: Some(1 << 19),
            initial_max_stream_data_bidi_local: Some(1_000),
            initial_max_stream_data_bidi_remote: Some(2_000),
            initial_max_stream_data_uni: None,
            initial_max_streams_bidi: Some(2),
            ..TransportParameters::default()
        };
        let local = TransportParameters {
            initial_max_data: Some(1 << 21),
            initial_max_stream_data_bidi_local: Some(3_000),
            initial_max_stream_data_bidi_remote: Some(1 << 20),
            initial_max_stream_data_uni: None,
            initial_max_streams_bidi: Some(4),
            ..TransportParameters::default()
        };

        let bound = bind_transport_parameters(config, &local, &peer);

        // Send side: a locally opened bidi stream sends against the peer's
        // `bidi_remote`, a peer-opened one against the peer's `bidi_local`.
        assert_eq!(
            bound.send_windows,
            StreamWindows {
                local_bidi: 2_000,
                remote_bidi: 1_000,
                uni: 0,
            }
        );
        // Receive side mirrors the mapping and is capped by the configured
        // window: the local `bidi_remote` of 1 MiB clamps to 256 KiB.
        assert_eq!(
            bound.recv_windows,
            StreamWindows {
                local_bidi: 3_000,
                remote_bidi: 1 << 18,
                uni: 0,
            }
        );
        assert_eq!(bound.config.send_window, 1 << 18);
        assert_eq!(bound.config.recv_window, 1 << 18);
        assert_eq!(bound.config.max_local_bidi, 2);
        assert_eq!(bound.config.connection_send_limit, 1 << 19);
        assert_eq!(bound.config.connection_recv_limit, 1 << 20);
        assert_eq!(bound.config.max_datagram_frame_size, 0);

        // The windows reach the stream table: a client opening stream 0 gets
        // the peer's `bidi_remote` credit, not zero.
        let mut connection = QuicConnection::client(bound.config);
        connection
            .inner_mut()
            .set_initial_stream_windows(bound.send_windows, bound.recv_windows);
        let cx = Cx::for_testing();
        connection.begin_handshake(&cx).unwrap();
        connection.mark_handshake_keys_available(&cx).unwrap();
        connection.mark_app_keys_available(&cx).unwrap();
        // The production handoff records the rustls-verified server identity
        // before confirming; a client cannot confirm without it.
        connection.record_verified_server_identity();
        connection.confirm_handshake(&cx).unwrap();
        let stream = connection.open_bidi_stream(&cx).unwrap();
        assert_eq!(stream, StreamId(0));
        assert_eq!(
            connection
                .inner()
                .streams()
                .stream_send_credit_remaining(stream),
            2_000
        );
        assert_eq!(
            connection
                .inner()
                .streams()
                .stream(stream)
                .unwrap()
                .recv_credit
                .limit(),
            3_000
        );
    }

    fn assert_reassembly_recovered(cx: &Cx, connection: &mut NativeQuicConnection) {
        assert_eq!(connection.state(), QuicConnectionState::Established);
        assert_eq!(connection.datagrams_received(), 1);
        assert_eq!(connection.recv_datagram().as_deref(), Some(&b"once"[..]));
        assert!(connection.recv_datagram().is_none());
        let mut received = Vec::new();
        while received.len() < 2 {
            let bytes = connection.read_stream_bytes(cx, StreamId(0), 2).unwrap();
            assert!(!bytes.is_empty());
            received.extend_from_slice(&bytes);
        }
        assert_eq!(received, b"hx");
        assert!(!connection.is_stream_read_eof(StreamId(0)).unwrap());
        assert_eq!(
            connection
                .streams()
                .stream(StreamId(0))
                .unwrap()
                .recv_offset,
            2
        );
    }

    async fn authenticated_udp_pair() -> (NativeQuicUdpConnection, NativeQuicUdpConnection) {
        let cx = Cx::for_testing();
        let config = NativeQuicConnectionConfig::default();
        let parameters = TransportParameters {
            initial_max_data: Some(config.connection_recv_limit),
            initial_max_stream_data_bidi_local: Some(config.recv_window),
            initial_max_stream_data_bidi_remote: Some(config.recv_window),
            initial_max_streams_bidi: Some(config.max_local_bidi),
            ..TransportParameters::default()
        };
        let mut encoded = Vec::new();
        parameters.encode(&mut encoded).unwrap();
        let client_socket = QuicUdpEndpoint::bind(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            QuicUdpEndpointConfig::default(),
        )
        .await
        .unwrap();
        let server_socket = QuicUdpEndpoint::bind(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            QuicUdpEndpointConfig::default(),
        )
        .await
        .unwrap();
        let address = server_socket.local_addr();
        let alpn = b"pto-test";
        let client_tls =
            client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![alpn.to_vec()]).unwrap();
        let server_tls = server_config(
            vec![parse_one_cert(LEAF_CERT_PEM)],
            leaf_key(),
            vec![alpn.to_vec()],
        )
        .unwrap();
        let initial_cid = ConnectionId::new(b"initial").unwrap();
        let (client, server) = zip(
            NativeQuicUdpConnection::connect(
                &cx,
                client_socket,
                address,
                QuicHandshakeDriver::client(
                    client_tls,
                    ServerName::try_from("localhost").unwrap(),
                    encoded.clone(),
                )
                .unwrap(),
                initial_cid,
                ConnectionId::new(b"client").unwrap(),
                config,
                alpn,
            ),
            NativeQuicUdpConnection::accept(
                &cx,
                server_socket,
                QuicHandshakeDriver::server(server_tls, encoded).unwrap(),
                initial_cid,
                ConnectionId::new(b"server").unwrap(),
                config,
                alpn,
            ),
        )
        .await;
        (client.unwrap(), server.unwrap())
    }

    #[test]
    fn udp_local_close_retains_ciphertext_and_stops_at_drain_deadline() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut client, mut server) = authenticated_udp_pair().await;
            assert!(client.close(&cx, u64::MAX).await.is_err());
            assert_eq!(
                client.connection.inner().state(),
                QuicConnectionState::Established
            );

            // Force a real socket send failure after protection and packet-number
            // commitment. Retrying must reuse that ciphertext, not encrypt again.
            let peer = client.peer_addr;
            client.pending_outgoing.push(RoutedOutgoingPacket {
                connection_id: client.local_cid,
                packet: OutgoingPacket {
                    dst_addr: peer,
                    data: b"must never escape after closing".to_vec(),
                    send_time: None,
                },
                final_handshake_flight: false,
                ack_eliciting: true,
            });
            client.peer_addr.set_port(0);
            assert!(client.close(&cx, 42).await.is_err());
            assert!(client.pending_outgoing.is_empty());
            let retained = client.local_close.as_ref().unwrap().packet.data.clone();
            assert!(client.local_close.as_ref().unwrap().pending);
            assert!(client.local_close.as_ref().unwrap().last_sent.is_none());
            let cancelled = Cx::for_testing();
            cancelled.set_cancel_requested(true);
            assert!(matches!(
                client.flush(&cancelled).await,
                Err(NativeQuicUdpConnectionError::Cancelled)
            ));
            assert_eq!(client.local_close.as_ref().unwrap().packet.data, retained);
            client = client
                .into_managed(&cx, ManagedEndpointConfig::default())
                .expect_err("closing owner must retain standalone output")
                .into_connection();
            assert_eq!(client.local_close.as_ref().unwrap().packet.data, retained);
            client.peer_addr = peer;
            client.local_close.as_mut().unwrap().packet.dst_addr = peer;
            assert_eq!(client.flush(&cx).await.unwrap(), 1);
            assert_eq!(client.flush(&cx).await.unwrap(), 0);
            assert_eq!(client.local_close.as_ref().unwrap().packet.data, retained);
            let progress = server
                .drive_io_once(&cx, Duration::from_secs(1))
                .await
                .unwrap();
            assert_eq!(progress.packets_received, 1);
            assert_eq!(progress.packets_sent, 0);
            assert!(server.connection.close_was_peer_initiated());
            assert_eq!(server.connection.inner().transport().close_code(), Some(42));

            // The closing owner responds only to the matching short-header
            // destination, coalescing traffic into at most one send per PTO.
            let mut matching = vec![0x40];
            matching.extend_from_slice(client.local_cid.as_bytes());
            matching.extend_from_slice(&[0; 24]);
            let packet = ReceivedPacket {
                src_addr: peer,
                data: matching,
                receive_time: Instant::now(),
                transmit_time: None,
            };
            client.early_one_rtt_packets.push(packet.clone());
            let progress = client.drive_io_once(&cx, Duration::ZERO).await.unwrap();
            assert_eq!(progress.packets_dropped, 1);
            assert_eq!(progress.packets_sent, 0);
            let interval = Duration::from_micros(
                client
                    .connection
                    .inner()
                    .transport()
                    .idle_timeout_floor_micros()
                    / 3,
            )
            .max(Duration::from_millis(1));
            client.local_close.as_mut().unwrap().last_sent = Some(
                Instant::now()
                    .checked_sub(interval)
                    .unwrap()
                    .checked_sub(Duration::from_millis(1))
                    .unwrap(),
            );
            let mut wrong_cid = packet.clone();
            wrong_cid.data[1] ^= 1;
            let mut wrong_peer = packet.clone();
            wrong_peer.src_addr.set_port(0);
            let mut stale_handshake = packet.clone();
            stale_handshake.data[0] = 0x80;
            client
                .early_one_rtt_packets
                .extend([wrong_cid, wrong_peer, stale_handshake]);
            let progress = client.drive_io_once(&cx, Duration::ZERO).await.unwrap();
            assert_eq!(progress.packets_sent, 0);
            assert_eq!(progress.handshake_flights_retransmitted, 0);
            let mut packet = packet;
            packet.receive_time = Instant::now();
            client
                .early_one_rtt_packets
                .extend([packet.clone(), packet]);
            let progress = client.drive_io_once(&cx, Duration::ZERO).await.unwrap();
            assert_eq!(progress.packets_sent, 1);
            assert_eq!(client.local_close.as_ref().unwrap().packet.data, retained);
            let retransmission = server.endpoint.receive_batch(&cx, 1).await.unwrap();
            assert_eq!(retransmission.len(), 1);
            assert_eq!(retransmission[0].data, retained);

            // An expired recovery timer must not produce an application probe.
            client.service_due_loss_timer(&cx).unwrap();
            assert_eq!(client.flush(&cx).await.unwrap(), 0);
            let deadline = client
                .connection
                .inner()
                .transport()
                .drain_deadline_micros()
                .unwrap();
            client.clock_origin = Instant::now()
                .checked_sub(Duration::from_micros(deadline))
                .unwrap()
                .checked_sub(Duration::from_millis(1))
                .unwrap();
            client.local_close.as_mut().unwrap().pending = true;
            assert_eq!(
                client.flush_local_close(&cx, Instant::now()).await.unwrap(),
                0
            );
            assert_eq!(
                client.connection.inner().state(),
                QuicConnectionState::Closed
            );
            assert_eq!(client.flush(&cx).await.unwrap(), 0);
            assert!(client.local_close.is_none());
            assert_eq!(
                client
                    .receive_wait_duration(&cx, Duration::from_secs(1))
                    .unwrap(),
                Duration::from_secs(1)
            );
        });
    }

    #[test]
    fn udp_pto_preserves_full_flight_and_sends_one_probe() {
        block_on(async {
            let cx = Cx::for_testing();
            let config = NativeQuicConnectionConfig::default();
            let (mut client, mut server) = authenticated_udp_pair().await;
            // Seed a full flight without sleeping for a real network timeout.
            // Handshake, packet protection, and probe transmission use real UDP.
            let connection = client.connection.inner_mut();
            let window = connection.transport().congestion_window_bytes();
            let mut original = Vec::new();
            let mut remaining = window;
            while remaining > 0 {
                let bytes = remaining.min(1200);
                original.push(
                    connection
                        .on_packet_sent(
                            &cx,
                            PacketNumberSpace::ApplicationData,
                            bytes,
                            true,
                            true,
                            0,
                        )
                        .unwrap(),
                );
                remaining -= bytes;
            }
            let stream = connection.open_local_bidi(&cx).unwrap();
            connection
                .write_stream_bytes(&cx, stream, Bytes::from_static(b"still queued"), false)
                .unwrap();
            let queued = connection.pending_stream_data_bytes();
            let deadline = connection.pto_deadline_micros(&cx, 0).unwrap().unwrap();
            client.clock_origin = Instant::now()
                .checked_sub(Duration::from_micros(deadline + 1))
                .unwrap();
            client.service_due_loss_timer(&cx).unwrap();
            let transport = client.connection.inner_mut().transport();
            assert_eq!(transport.bytes_in_flight(), window);
            assert_eq!(transport.congestion_window_bytes(), window);
            assert_eq!(transport.packets_lost_total(), 0);
            assert_eq!(transport.pto_count(), 1);
            let cancelled = Cx::for_testing();
            cancelled.set_cancel_requested(true);
            assert!(matches!(
                client.flush(&cancelled).await,
                Err(NativeQuicUdpConnectionError::Cancelled)
            ));
            assert_eq!(
                client.connection.inner_mut().transport().bytes_in_flight(),
                window,
                "cancelled admission must not consume the probe permit"
            );
            // Refuse an already-protected packet at the real endpoint boundary.
            // Keep the original socket alive so retry uses the same peer tuple.
            let small_endpoint = QuicUdpEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                QuicUdpEndpointConfig {
                    max_packet_size: 1,
                    ..QuicUdpEndpointConfig::default()
                },
            )
            .await
            .unwrap();
            let original_endpoint = std::mem::replace(&mut client.endpoint, small_endpoint);
            assert!(matches!(
                client.flush(&cx).await,
                Err(NativeQuicUdpConnectionError::Endpoint(_))
            ));
            assert_eq!(client.pending_outgoing.len(), 1);
            let protected_probe = client.pending_outgoing[0].packet.data.clone();
            let accounted = client.connection.inner_mut().transport().bytes_in_flight();
            assert!(matches!(
                client.flush(&cancelled).await,
                Err(NativeQuicUdpConnectionError::Cancelled)
            ));
            client = NativeQuicUdpConnection::from_managed_parts(client.into_managed_parts());
            assert_eq!(client.pending_outgoing.len(), 1);
            assert_eq!(client.pending_outgoing[0].packet.data, protected_probe);
            let small_endpoint = std::mem::replace(&mut client.endpoint, original_endpoint);
            assert_eq!(client.flush(&cx).await.unwrap(), 1);
            assert!(client.pending_outgoing.is_empty());
            assert_eq!(
                client.connection.inner_mut().transport().bytes_in_flight(),
                accounted,
                "retry must not allocate another packet number or account twice"
            );
            assert_eq!(client.flush(&cx).await.unwrap(), 0, "permit consumed once");
            let mut received_probe = false;
            for _ in 0..4 {
                let packets = timeout(
                    cx.now(),
                    Duration::from_secs(1),
                    server.endpoint.receive_batch(&cx, RECEIVE_BATCH_SIZE),
                )
                .await
                .expect("probe must reach the peer")
                .unwrap();
                for packet in packets {
                    if !matches!(
                        ProtectedHeaderPrefix::decode(&packet.data, server.local_cid.len()),
                        Ok(ProtectedHeaderPrefix::Short { .. })
                    ) {
                        // Handshake retransmissions may precede the probe.
                        continue;
                    }
                    let decoded = unprotect_1rtt_packet(
                        &cx,
                        server.local_cid,
                        &mut server.protection,
                        &packet.data,
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        NativeQuicConnection::decode_frames(&decoded.plaintext).unwrap(),
                        vec![QuicFrame::Ping]
                    );
                    assert!(!received_probe, "only one probe was authorized");
                    received_probe = true;
                }
                if received_probe {
                    break;
                }
            }
            assert!(received_probe, "peer authenticated the PING probe");
            let connection = client.connection.inner_mut();
            assert_eq!(connection.transport().congestion_window_bytes(), window);
            assert_eq!(connection.pending_stream_data_bytes(), queued);
            let after_probe = connection.transport().bytes_in_flight();
            assert!(after_probe > window && after_probe <= window + 1200);
            connection
                .on_ack_received(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    &original,
                    0,
                    deadline + 2,
                )
                .unwrap();
            assert_eq!(
                connection.transport().bytes_in_flight(),
                after_probe - window
            );
            assert_eq!(connection.transport().packets_lost_total(), 0);
            // Send one protected packet before a real destination error, then
            // import only the unsent suffix into the router.
            connection
                .write_stream_bytes(&cx, stream, Bytes::from(vec![7; 3600]), true)
                .unwrap();
            let original_endpoint = std::mem::replace(&mut client.endpoint, small_endpoint);
            assert!(matches!(
                client.flush(&cx).await,
                Err(NativeQuicUdpConnectionError::Endpoint(
                    QuicUdpEndpointError::PacketTooLarge { limit: 1, .. }
                ))
            ));
            assert!(client.pending_outgoing.len() >= 3);
            let protected_flight: Vec<_> = client
                .pending_outgoing
                .iter()
                .map(|packet| packet.packet.data.clone())
                .collect();
            let accounted = client.connection.inner_mut().transport().bytes_in_flight();
            client.pending_outgoing[1].packet.dst_addr.set_port(0);
            client.endpoint = original_endpoint;
            assert!(matches!(
                client.flush(&cx).await,
                Err(NativeQuicUdpConnectionError::Endpoint(_))
            ));
            assert_eq!(client.pending_outgoing.len(), protected_flight.len() - 1);
            assert!(
                client
                    .pending_outgoing
                    .iter()
                    .map(|packet| &packet.packet.data)
                    .eq(protected_flight[1..].iter()),
                "the acknowledged prefix must be removed without changing the suffix"
            );
            assert_eq!(
                client.connection.inner_mut().transport().bytes_in_flight(),
                accounted,
                "a partial send must not account for protected packets twice"
            );
            let received = timeout(
                cx.now(),
                Duration::from_secs(1),
                server.endpoint.receive_batch(&cx, RECEIVE_BATCH_SIZE),
            )
            .await
            .expect("the successful prefix must reach the peer")
            .unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].data, protected_flight[0]);
            unprotect_1rtt_packet(
                &cx,
                server.local_cid,
                &mut server.protection,
                &received[0].data,
            )
            .await
            .expect("the peer must authenticate the successful prefix");
            client.pending_outgoing[0].packet.dst_addr = client.peer_addr;
            let expected_first = protected_flight[1].clone();
            let local_cid = client.local_cid;
            let now = Instant::now();
            let (mut router, _endpoint, incoming) = ConnectionRouter::from_authenticated_parts(
                client.into_managed_parts(),
                config,
                1,
                None,
                now,
            );
            assert!(incoming.is_empty());
            assert!(
                router
                    .drain_deferred_output(&cx, now, 0)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(matches!(
                router.drain_deferred_output(&cancelled, now, 1).await,
                Err(ConnectionRouterError::Cancelled)
            ));
            let prefix = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(prefix.len(), 1);
            assert_eq!(prefix[0].connection_id, local_cid);
            assert_eq!(prefix[0].packet.data, expected_first);
            assert!(prefix[0].ack_eliciting);
            assert!(!prefix[0].final_handshake_flight);
            assert_eq!(router.close_all(&cx, now, 0).unwrap(), 1);
            assert!(
                router
                    .drain_deferred_output(&cx, now, MAX_PACKETS_PER_FLUSH)
                    .await
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    fn reassembly_backpressure_recovers_in_udp_owner_and_authenticated_router() {
        block_on(async {
            for routed in [false, true] {
                let cx = Cx::for_testing();
                let config = NativeQuicConnectionConfig::default();
                let parameters = TransportParameters {
                    initial_max_data: Some(config.connection_recv_limit),
                    initial_max_stream_data_bidi_local: Some(config.recv_window),
                    initial_max_stream_data_bidi_remote: Some(config.recv_window),
                    initial_max_stream_data_uni: Some(config.recv_window),
                    initial_max_streams_bidi: Some(config.max_local_bidi),
                    max_datagram_frame_size: Some(1200),
                    ..TransportParameters::default()
                };
                let mut parameters_bytes = Vec::new();
                parameters.encode(&mut parameters_bytes).unwrap();
                let client_socket = QuicUdpEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    QuicUdpEndpointConfig::default(),
                )
                .await
                .unwrap();
                let server_socket = QuicUdpEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    QuicUdpEndpointConfig::default(),
                )
                .await
                .unwrap();
                let address = server_socket.local_addr();
                let alpn = b"reassembly-test";
                let client_tls =
                    client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![alpn.to_vec()]).unwrap();
                let server_tls = server_config(
                    vec![parse_one_cert(LEAF_CERT_PEM)],
                    leaf_key(),
                    vec![alpn.to_vec()],
                )
                .unwrap();
                let initial_cid = ConnectionId::new(b"initial").unwrap();
                let server_cid = ConnectionId::new(b"server").unwrap();
                let (client, server) = zip(
                    NativeQuicUdpConnection::connect(
                        &cx,
                        client_socket,
                        address,
                        QuicHandshakeDriver::client(
                            client_tls,
                            ServerName::try_from("localhost").unwrap(),
                            parameters_bytes.clone(),
                        )
                        .unwrap(),
                        initial_cid,
                        ConnectionId::new(b"client").unwrap(),
                        config,
                        alpn,
                    ),
                    NativeQuicUdpConnection::accept(
                        &cx,
                        server_socket,
                        QuicHandshakeDriver::server(server_tls, parameters_bytes).unwrap(),
                        initial_cid,
                        server_cid,
                        config,
                        alpn,
                    ),
                )
                .await;
                let mut client = client.unwrap();
                let mut server = server.unwrap();
                assert!(server.early_one_rtt_packets.is_empty());
                let id = StreamId(0);
                let connection = server.connection.inner_mut();
                connection.accept_remote_stream(&cx, id).unwrap();
                // Seed only the bounded capacity precondition. All three
                // admission/recovery packets use real TLS keys and UDP below.
                for fragment in 0..4095u64 {
                    connection
                        .receive_stream_bytes(
                            &cx,
                            id,
                            1 + fragment * 2,
                            Bytes::from_static(b"x"),
                            false,
                        )
                        .unwrap();
                }
                connection
                    .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65535)
                    .unwrap();
                let overflow = vec![
                    QuicFrame::Datagram {
                        data: Bytes::from_static(b"once"),
                    },
                    QuicFrame::Stream {
                        stream_id: VarInt(id.0),
                        offset: Some(VarInt(8191)),
                        data: Bytes::from_static(b"z"),
                        fin: true,
                    },
                ];
                let repair = vec![QuicFrame::Stream {
                    stream_id: VarInt(id.0),
                    offset: Some(VarInt(0)),
                    data: Bytes::from_static(b"h"),
                    fin: false,
                }];
                let mut packets = Vec::new();
                for frames in [&overflow, &repair, &overflow] {
                    let mut payload = BytesMut::new();
                    NativeQuicConnection::encode_frames(frames, &mut payload).unwrap();
                    let data = assemble_protected_1rtt_packet(
                        &cx,
                        server_cid,
                        client.connection.inner_mut(),
                        &mut client.protection,
                        frames,
                        &payload,
                        1,
                        true,
                    )
                    .await
                    .unwrap();
                    packets.push(OutgoingPacket {
                        dst_addr: address,
                        data,
                        send_time: None,
                    });
                }
                let sent = client.endpoint.send_batch(&cx, &packets).await.unwrap();
                assert_eq!(sent.packets_processed, 3);
                assert!(sent.error.is_none());
                if routed {
                    let (mut router, mut endpoint, early) =
                        ConnectionRouter::from_authenticated_parts(
                            server.into_managed_parts(),
                            config,
                            1,
                            None,
                            Instant::now(),
                        );
                    assert!(early.is_empty());
                    let mut outcomes = Vec::new();
                    while outcomes.len() < 3 {
                        let packets = timeout(
                            crate::time::wall_now(),
                            Duration::from_secs(10),
                            endpoint.receive_batch(&cx, 3 - outcomes.len()),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                        for packet in packets {
                            outcomes.push(router.route_packet(&cx, packet).await.unwrap());
                        }
                    }
                    assert!(matches!(&outcomes[0], RoutingResult::Drop { reason }
                        if reason == "stream reassembly backpressure"));
                    assert!(matches!(&outcomes[1], RoutingResult::Routed { .. }));
                    assert!(matches!(&outcomes[2], RoutingResult::Routed { .. }));
                    let connection = router.connection_mut_for_testing(&cx, server_cid).unwrap();
                    assert_reassembly_recovered(&cx, connection);
                    let frames = connection
                        .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65535)
                        .unwrap();
                    assert!(frames.iter().any(|frame| matches!(frame,
                        QuicFrame::Ack { largest_acknowledged, first_ack_range, ack_ranges, .. }
                            if largest_acknowledged.value() == 2 && first_ack_range.value() == 1 && ack_ranges.is_empty()
                    )), "only packets 1 and 2 were admitted");
                } else {
                    let mut received = 0;
                    let mut dropped = 0;
                    for _ in 0..3 {
                        let progress = server
                            .drive_io_once(&cx, Duration::from_secs(10))
                            .await
                            .unwrap();
                        received += progress.packets_received;
                        dropped += progress.packets_dropped;
                        if received + dropped == 3 {
                            break;
                        }
                    }
                    assert_eq!((received, dropped), (2, 1));
                    assert_reassembly_recovered(&cx, server.connection.inner_mut());
                }
            }
        });
    }
}
