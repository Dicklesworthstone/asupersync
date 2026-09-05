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
use std::task::Poll;
use std::time::Instant;

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
    /// Alternate ready read/write batches; timers and cancellation always get a turn.
    prefer_send: bool,
}

enum EndpointEvent {
    Packets(Vec<ReceivedPacket>),
    Sent(std::io::Result<crate::net::quic_native::BatchResult>),
    Timer(Instant),
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
    /// Connection idle timeout in microseconds.
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
        match e {
            QuicUdpEndpointError::Cancelled => Self::Cancelled,
            other => Self::UdpEndpoint(other.to_string()),
        }
    }
}

impl From<ConnectionRouterError> for ManagedEndpointError {
    fn from(e: ConnectionRouterError) -> Self {
        match e {
            ConnectionRouterError::Cancelled => Self::Cancelled,
            other => Self::ConnectionRouter(other),
        }
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
        let connection_router = ConnectionRouter::new(config.connection_config);

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
        self.pending_outgoing
            .retain(|packet| packet.connection_id != connection_id);
        self.timer_scheduler.cancel();
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
        if let Some(connection) = &connection {
            self.pending_outgoing
                .retain(|packet| packet.connection_id != connection.connection_id);
        }
        self.timer_scheduler.cancel();
        Ok(connection)
    }

    /// Run the main endpoint event loop.
    ///
    /// This processes incoming packets, handles timer events, and manages
    /// connection lifecycle until cancellation or shutdown.
    pub async fn run_event_loop(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        let result = self.drive_event_loop(cx).await;
        self.timer_scheduler.cancel();
        result
    }

    async fn drive_event_loop(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
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
        while !self.shutting_down {
            if cx.checkpoint().is_err() {
                return Err(ManagedEndpointError::Cancelled);
            }

            let available = self
                .config
                .packet_batch_size
                .saturating_sub(self.pending_outgoing.len());
            self.pending_outgoing
                .extend(self.connection_router.take_pending_timer_output(available));
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
            self.refresh_timer(cx).await?;
            let event = poll_fn(|task_cx| {
                let _current = Cx::set_current(Some(cx.clone()));
                if cancel.checkpoint(task_cx.waker()).is_err() {
                    return Poll::Ready(Err(ManagedEndpointError::Cancelled));
                }
                if let Poll::Ready(Some(deadline)) = self.timer_scheduler.poll_timer(task_cx) {
                    return Poll::Ready(Ok(EndpointEvent::Timer(deadline)));
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
                        match self.udp_endpoint.poll_receive_batch(
                            cx,
                            task_cx,
                            self.config.packet_batch_size,
                        ) {
                            Poll::Ready(result) => {
                                self.prefer_send = true;
                                return Poll::Ready(
                                    result.map(EndpointEvent::Packets).map_err(Into::into),
                                );
                            }
                            Poll::Pending => {}
                        }
                    }
                }
                Poll::Pending
            })
            .await?;
            match event {
                EndpointEvent::Packets(packets) => self.process_packet_batch(cx, packets).await?,
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
                            let queued = self.pending_outgoing.len();
                            self.pending_outgoing
                                .retain(|packet| packet.packet.dst_addr != peer);
                            let retired = self.connection_router.discard_peer_connections(peer);
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
                    self.pending_outgoing.drain(..result.packets_processed);
                    if let Some(error) = result.error {
                        // The unsent suffix remains available if the owner retries this loop.
                        return Err(ManagedEndpointError::UdpEndpoint(error));
                    }
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

        Ok(())
    }

    /// Process a batch of incoming packets.
    async fn process_packet_batch(
        &mut self,
        cx: &Cx,
        packets: Vec<ReceivedPacket>,
    ) -> Result<(), ManagedEndpointError> {
        if cx.checkpoint().is_err() {
            return Err(ManagedEndpointError::Cancelled);
        }

        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }

        if packets.is_empty() {
            return Ok(()); // No packets to process
        }

        for mut packet in packets {
            packet.receive_time = self.timer_scheduler.now(cx)?;
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
                    cx.trace(&format!("Packet processing error: {error}"));
                    continue;
                }
            };
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
            }));
    }

    /// Process timer events for all connections.
    async fn refresh_timer(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        let next = self.connection_router.next_timer_deadline();
        if self.timer_scheduler.current_deadline() != next {
            self.timer_scheduler.cancel();
            if let Some(deadline) = next {
                self.timer_scheduler.schedule_timer(cx, deadline).await?;
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

    /// Gracefully shut down the endpoint.
    ///
    /// This stops accepting new connections, drains existing connections,
    /// and ensures all resources are cleaned up properly.
    pub async fn shutdown(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        cx.trace(&format!(
            "Shutting down managed QUIC endpoint {}",
            self.endpoint_id()
        ));

        self.shutting_down = true;

        let closed_connections = self.connection_router.connection_stats().active_connections;
        let now = self
            .timer_scheduler
            .now(cx)
            .unwrap_or_else(|_| Instant::now());
        let close_result = self.connection_router.close_all(cx, now, 0);
        // Terminal cleanup is local ownership release, not new runtime work.
        // Keep it unconditional so cancellation cannot strand a retained endpoint.
        self.connection_router.discard_all();
        self.pending_outgoing.clear();
        self.timer_scheduler.cancel();
        let udp_result = self.udp_endpoint.shutdown(cx).await;
        close_result?;
        udp_result?;

        cx.trace(&format!(
            "Managed QUIC endpoint {} shutdown complete; closed {} connections",
            self.endpoint_id(),
            closed_connections
        ));

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
            let (crate::net::quic_core::PacketHeader::Short(header), header_len) =
                crate::net::quic_core::PacketHeader::decode(&bytes[..length], 8).unwrap()
            else {
                panic!("due managed PTO must emit an actual protected short packet")
            };
            assert_eq!(header.dst_cid, cid);
            assert_eq!(header.packet_number, 1);
            let plaintext = crate::net::quic_native::connection_manager::unprotect_1rtt_packet(
                &owner,
                cid,
                &mut verifier,
                &bytes[..header_len],
                &bytes[header_len..length],
                header.packet_number,
                header.key_phase,
            )
            .await
            .unwrap();
            let mut expected = bytes::BytesMut::new();
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
                let (crate::net::quic_core::PacketHeader::Short(header), _) =
                    crate::net::quic_core::PacketHeader::decode(&payload[..length], 8).unwrap()
                else {
                    panic!("actual protected short packet expected")
                };
                assert!(observed.insert(header.dst_cid));
                assert_eq!(header.packet_number, 1);
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
}
