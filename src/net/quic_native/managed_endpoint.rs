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
use crate::net::quic_native::{
    ConnectionRouter, ConnectionRouterError, ConnectionRouterStats, NativeQuicConnectionConfig,
    OutgoingPacket, QuicTimerScheduler, QuicUdpEndpoint, QuicUdpEndpointConfig,
    QuicUdpEndpointError, RoutingResult,
};
use crate::time::sleep;
use std::net::SocketAddr;
use std::time::Duration;
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

    /// Run the main endpoint event loop.
    ///
    /// This processes incoming packets, handles timer events, and manages
    /// connection lifecycle until cancellation or shutdown.
    pub async fn run_event_loop(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        if cx.checkpoint().is_err() {
            return Err(ManagedEndpointError::Cancelled);
        }

        cx.trace(&format!(
            "Starting QUIC endpoint event loop for endpoint {}",
            self.endpoint_id()
        ));

        while !self.shutting_down {
            if cx.checkpoint().is_err() {
                return Err(ManagedEndpointError::Cancelled);
            }

            // Process packets first
            if let Err(e) = self.process_packet_batch(cx).await {
                match e {
                    ManagedEndpointError::Cancelled => return Err(e),
                    ManagedEndpointError::ShuttingDown => break,
                    _ => {
                        cx.trace(&format!("Packet processing error: {e}"));
                        // Continue running on non-fatal errors
                    }
                }
            }

            // Then process timer events
            if let Err(e) = self.process_timer_events(cx).await {
                match e {
                    ManagedEndpointError::Cancelled => return Err(e),
                    ManagedEndpointError::ShuttingDown => break,
                    _ => {
                        cx.trace(&format!("Timer processing error: {e}"));
                        // Continue running on non-fatal errors
                    }
                }
            }

            // Brief yield to prevent busy loop
            let now = crate::Time::from_nanos(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::ZERO)
                    .as_nanos() as u64,
            );
            sleep(now, Duration::from_millis(1)).await;
        }

        cx.trace(&format!(
            "QUIC endpoint event loop stopped for endpoint {}",
            self.endpoint_id()
        ));

        Ok(())
    }

    /// Process a batch of incoming packets.
    async fn process_packet_batch(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        if cx.checkpoint().is_err() {
            return Err(ManagedEndpointError::Cancelled);
        }

        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }

        // Receive packet batch
        let packets = self
            .udp_endpoint
            .receive_batch(cx, self.config.packet_batch_size)
            .await?;

        if packets.is_empty() {
            return Ok(()); // No packets to process
        }

        let mut outgoing_packets: Vec<OutgoingPacket> = Vec::new();

        for packet in packets {
            // Route packet through connection router
            match self.connection_router.route_packet(cx, packet).await? {
                RoutingResult::Routed {
                    connection_id,
                    outgoing_packets: mut packets,
                } => {
                    cx.trace(&format!("Routed packet to connection {connection_id:?}"));
                    outgoing_packets.append(&mut packets);
                }
                RoutingResult::NewConnection {
                    connection_id,
                    peer_addr,
                    outgoing_packets: mut packets,
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
                    outgoing_packets.append(&mut packets);
                }
                RoutingResult::Drop { reason } => {
                    cx.trace(&format!("Dropped packet: {reason}"));
                }
            }
        }

        // Send outgoing packets
        if !outgoing_packets.is_empty() {
            let result = self.udp_endpoint.send_batch(cx, &outgoing_packets).await?;
            cx.trace(&format!(
                "Sent {} outgoing packets ({} bytes)",
                result.packets_processed, result.bytes_processed
            ));
        }

        Ok(())
    }

    /// Process timer events for all connections.
    async fn process_timer_events(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        if cx.checkpoint().is_err() {
            return Err(ManagedEndpointError::Cancelled);
        }

        if self.shutting_down {
            return Err(ManagedEndpointError::ShuttingDown);
        }

        // Check for next timer deadline
        if let Some(deadline) = self.connection_router.next_timer_deadline() {
            // Schedule timer if needed
            self.timer_scheduler.schedule_timer(cx, deadline).await?;
        }

        // Check if timer fired
        if let Some(_deadline) = self.timer_scheduler.wait_for_timer(cx).await? {
            let now = Instant::now();
            let outgoing_packets = self.connection_router.process_timer_events(cx, now).await?;

            if !outgoing_packets.is_empty() {
                let result = self.udp_endpoint.send_batch(cx, &outgoing_packets).await?;
                cx.trace(&format!(
                    "Sent {} timer-triggered packets ({} bytes)",
                    result.packets_processed, result.bytes_processed
                ));
            }
        }

        Ok(())
    }

    /// Gracefully shut down the endpoint.
    ///
    /// This stops accepting new connections, drains existing connections,
    /// and ensures all resources are cleaned up properly.
    pub async fn shutdown(&mut self, cx: &Cx) -> Result<(), ManagedEndpointError> {
        if cx.checkpoint().is_err() {
            return Err(ManagedEndpointError::Cancelled);
        }

        cx.trace(&format!(
            "Shutting down managed QUIC endpoint {}",
            self.endpoint_id()
        ));

        self.shutting_down = true;

        // Shut down UDP endpoint
        self.udp_endpoint.shutdown(cx).await?;

        let closed_connections = self.connection_router.close_all(cx, Instant::now(), 0)?;
        self.timer_scheduler.cancel();

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
    use crate::test_utils::run_test_with_cx;

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
}
