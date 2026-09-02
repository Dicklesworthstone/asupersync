//! Authenticated single-connection native QUIC over a real UDP endpoint.
//!
//! This module owns the production composition seam between the wire-driven
//! rustls handshake, handshake-derived 1-RTT packet protection, the real UDP
//! endpoint, and the application-facing [`QuicConnection`]. It deliberately
//! remains caller-driven: no executor, background task, or ambient listener is
//! created.

use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::bytes::BytesMut;
use crate::cx::Cx;
use crate::net::atp::quic::{AtpPacketProtection, AtpPacketProtectionConfig};
use crate::net::quic_core::{ConnectionId, PacketHeader, TransportParameters};
use crate::time::timeout;

use super::connection::{NativeQuicConnectionConfig, NativeQuicConnectionError};
use super::connection_manager::{
    ConnectionRouterError, PROTECTED_1RTT_MAX_PACKET_BYTES, assemble_protected_1rtt_packet,
    generate_congestion_admitted_1rtt_frames, is_ack_eliciting, protected_1rtt_packet_len,
    unprotect_1rtt_packet,
};
use super::endpoint::{OutgoingPacket, QuicUdpEndpoint, QuicUdpEndpointError, ReceivedPacket};
use super::endpoint_api::QuicConnection;
use super::handshake_driver::{
    QuicHandshakeDriver, client_handshake_over_udp, server_handshake_over_udp_with_early_data,
};
use super::streams::StreamRole;
use super::transport::PacketNumberSpace;

const RECEIVE_BATCH_SIZE: usize = 32;
const MAX_PACKETS_PER_FLUSH: usize = 64;
const FINAL_HANDSHAKE_FLIGHT_RESEND_INTERVAL: Duration = Duration::from_millis(750);

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
        mut driver: QuicHandshakeDriver,
        local_cid: ConnectionId,
        connection_config: NativeQuicConnectionConfig,
        required_alpn: &[u8],
        role: StreamRole,
        early_one_rtt_packets: Vec<ReceivedPacket>,
    ) -> Result<Self, NativeQuicUdpConnectionError> {
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
        let connection_config =
            bind_transport_parameters(connection_config, &local_parameters, &peer_parameters);

        let mut connection = match role {
            StreamRole::Client => QuicConnection::client(connection_config),
            StreamRole::Server => QuicConnection::server(connection_config),
        };
        connection.inner_mut().set_remote_stream_limits(
            local_parameters.initial_max_streams_bidi.unwrap_or(0),
            local_parameters.initial_max_streams_uni.unwrap_or(0),
        );
        connection.begin_handshake(cx)?;
        connection.mark_handshake_keys_available(cx)?;
        connection.mark_app_keys_available(cx)?;
        if role == StreamRole::Client {
            // Reaching here means rustls/WebPKI completed the client handshake
            // for its configured ServerName and roots.
            connection.record_verified_server_identity();
        }
        connection.confirm_handshake(cx)?;

        let final_handshake_flight = driver.take_final_flight();
        let protection = AtpPacketProtection::from_provider(
            Box::new(driver.into_provider()),
            AtpPacketProtectionConfig::default(),
        );
        Ok(Self {
            connection,
            endpoint,
            protection,
            local_cid,
            peer_cid,
            peer_addr,
            negotiated_alpn,
            final_handshake_flight,
            early_one_rtt_packets,
            last_final_flight_retransmit: None,
            clock_origin: Instant::now(),
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

    /// Protect and send a bounded batch of queued application frames.
    pub async fn flush(&mut self, cx: &Cx) -> Result<usize, NativeQuicUdpConnectionError> {
        if cx.checkpoint().is_err() {
            return Err(NativeQuicUdpConnectionError::Cancelled);
        }
        let now = Instant::now();
        let now_micros = self.instant_micros(now);
        let max_frame_bytes = PROTECTED_1RTT_MAX_PACKET_BYTES
            .saturating_sub(protected_1rtt_packet_len(self.peer_cid, 0));
        let mut packets = Vec::new();

        for _ in 0..MAX_PACKETS_PER_FLUSH {
            let frames = generate_congestion_admitted_1rtt_frames(
                cx,
                self.connection.inner_mut(),
                max_frame_bytes,
            )?;
            if frames.is_empty() {
                break;
            }
            let mut payload = BytesMut::new();
            super::connection::NativeQuicConnection::encode_frames(&frames, &mut payload)?;
            let assembled = assemble_protected_1rtt_packet(
                cx,
                self.peer_cid,
                self.connection.inner_mut(),
                &mut self.protection,
                &frames,
                payload.as_ref(),
                now_micros,
                frames.iter().any(is_ack_eliciting),
            )
            .await;
            let data = match assembled {
                Ok(data) => data,
                Err(error) => {
                    self.connection
                        .inner_mut()
                        .on_generated_frames_dropped(&frames)?;
                    return Err(error.into());
                }
            };
            packets.push(OutgoingPacket {
                dst_addr: self.peer_addr,
                data,
                send_time: Some(now),
            });
        }

        if packets.is_empty() {
            return Ok(0);
        }
        let expected = packets.len();
        let report = self.endpoint.send_batch(cx, &packets).await?;
        if report.packets_processed != expected || report.error.is_some() {
            return Err(NativeQuicUdpConnectionError::BatchSend(
                report.error.unwrap_or_else(|| {
                    format!(
                        "sent {} of {expected} protected packets",
                        report.packets_processed
                    )
                }),
            ));
        }
        Ok(expected)
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
            if packet.data.first().is_some_and(|byte| byte & 0x80 != 0) {
                progress.packets_dropped = progress.packets_dropped.saturating_add(1);
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

            let Ok((PacketHeader::Short(header), header_len)) =
                PacketHeader::decode(&packet.data, self.local_cid.len())
            else {
                progress.packets_dropped = progress.packets_dropped.saturating_add(1);
                continue;
            };
            if header.dst_cid != self.local_cid || header_len > packet.data.len() {
                progress.packets_dropped = progress.packets_dropped.saturating_add(1);
                continue;
            }
            let plaintext = match unprotect_1rtt_packet(
                cx,
                self.local_cid,
                &mut self.protection,
                &packet.data[..header_len],
                &packet.data[header_len..],
                header.packet_number,
                header.key_phase,
            )
            .await
            {
                Ok(plaintext) => plaintext,
                Err(ConnectionRouterError::Cancelled) => {
                    return Err(NativeQuicUdpConnectionError::Cancelled);
                }
                Err(_) => {
                    progress.packets_dropped = progress.packets_dropped.saturating_add(1);
                    continue;
                }
            };
            self.connection
                .inner_mut()
                .on_datagram_received(cx, packet.data.len() as u64)?;
            let now_micros = self.instant_micros(packet.receive_time);
            self.connection.inner_mut().process_packet_payload(
                cx,
                PacketNumberSpace::ApplicationData,
                header.packet_number,
                &plaintext,
                now_micros,
            )?;
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
        let Some(deadline_micros) = self
            .connection
            .inner_mut()
            .pto_deadline_micros(cx, now_micros)?
        else {
            return Ok(requested);
        };
        Ok(requested.min(Duration::from_micros(
            deadline_micros.saturating_sub(now_micros),
        )))
    }

    fn service_due_loss_timer(&mut self, cx: &Cx) -> Result<(), NativeQuicUdpConnectionError> {
        let now_micros = self.instant_micros(Instant::now());
        let Some(deadline) = self
            .connection
            .inner_mut()
            .pto_deadline_micros(cx, now_micros)?
        else {
            return Ok(());
        };
        if deadline <= now_micros {
            self.connection.inner_mut().on_loss_timeout_expired(
                cx,
                PacketNumberSpace::ApplicationData,
                now_micros,
            )?;
        }
        Ok(())
    }
}

fn bind_transport_parameters(
    mut config: NativeQuicConnectionConfig,
    local: &TransportParameters,
    peer: &TransportParameters,
) -> NativeQuicConnectionConfig {
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

    let peer_stream_send_limit = [
        peer.initial_max_stream_data_bidi_local.unwrap_or(0),
        peer.initial_max_stream_data_bidi_remote.unwrap_or(0),
        peer.initial_max_stream_data_uni.unwrap_or(0),
    ]
    .into_iter()
    .min()
    .unwrap_or(0);
    config.send_window = config.send_window.min(peer_stream_send_limit);
    let local_stream_recv_limit = [
        local.initial_max_stream_data_bidi_local.unwrap_or(0),
        local.initial_max_stream_data_bidi_remote.unwrap_or(0),
        local.initial_max_stream_data_uni.unwrap_or(0),
    ]
    .into_iter()
    .min()
    .unwrap_or(0);
    config.recv_window = config.recv_window.min(local_stream_recv_limit);
    config.max_datagram_frame_size = config.max_datagram_frame_size.min(
        peer.max_datagram_frame_size
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
    );
    config
}
