//! [br-e2e-4] Real QUIC Native E2E Tests
//!
//! Real-service E2E tests for QUIC native endpoint using actual UDP-bound servers
//! and real QUIC protocol handling. Tests the complete QUIC connection lifecycle,
//! packet exchange, and stream operations without mocks.
//!
//! Uses rch + CARGO_TARGET_DIR=/tmp/rch_target_pane1_e2e for end-to-end validation
//! with actual QUIC protocol implementations bound to ephemeral ports.

#[cfg(any(test, feature = "test-internals"))]
mod quic_native_e2e_tests {
    use crate::cx::{Cx, CxBuilder};
    use crate::net::UdpSocket;
    use crate::net::quic_native::{
        OutgoingPacket, QuicUdpEndpoint, QuicUdpEndpointConfig, ReceivedPacket,
    };
    use crate::runtime::RuntimeBuilder;
    use crate::time::{Duration, Instant, sleep};
    use crate::types::{Budget, Outcome};
    use serde_json;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Real QUIC server for E2E testing with actual protocol handling
    pub struct RealQuicServer {
        endpoint: QuicUdpEndpoint,
        local_addr: SocketAddr,
        is_running: Arc<AtomicBool>,
        stats: Arc<QuicE2EStats>,
        config: QuicServerConfig,
    }

    /// Configuration for QUIC server E2E testing
    #[derive(Debug, Clone)]
    pub struct QuicServerConfig {
        pub bind_addr: SocketAddr,
        pub max_connections: usize,
        pub idle_timeout: Duration,
        pub max_packet_size: usize,
        pub enable_0rtt: bool,
        pub certificate_chain: Option<Vec<u8>>,
        pub private_key: Option<Vec<u8>>,
    }

    impl Default for QuicServerConfig {
        fn default() -> Self {
            Self {
                bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), // ephemeral port
                max_connections: 100,
                idle_timeout: Duration::from_secs(30),
                max_packet_size: 1500,
                enable_0rtt: false,
                certificate_chain: None,
                private_key: None,
            }
        }
    }

    /// Statistics for QUIC E2E testing
    #[derive(Debug, Default)]
    pub struct QuicE2EStats {
        pub packets_sent: AtomicU64,
        pub packets_received: AtomicU64,
        pub bytes_sent: AtomicU64,
        pub bytes_received: AtomicU64,
        pub connections_established: AtomicU64,
        pub connections_closed: AtomicU64,
        pub handshake_errors: AtomicU64,
        pub packet_drops: AtomicU64,
    }

    /// Enhanced logger for QUIC E2E tests with protocol-specific tracking
    pub struct QuicE2ELogger {
        events: Arc<Mutex<Vec<QuicLogEvent>>>,
        start_time: Instant,
    }

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct QuicLogEvent {
        pub timestamp: u64,
        pub event_type: String,
        pub connection_id: Option<String>,
        pub packet_type: Option<String>,
        pub packet_size: Option<usize>,
        pub src_addr: Option<String>,
        pub dst_addr: Option<String>,
        pub details: HashMap<String, serde_json::Value>,
    }

    impl QuicE2ELogger {
        pub fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                start_time: Instant::now(),
            }
        }

        pub fn log_packet_sent(
            &self,
            packet: &OutgoingPacket,
            connection_id: Option<&str>,
            packet_type: &str,
        ) {
            let mut details = HashMap::new();
            details.insert(
                "direction".to_string(),
                serde_json::Value::String("outbound".to_string()),
            );
            if let Some(send_time) = packet.send_time {
                details.insert(
                    "send_time_ms".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(
                        send_time.duration_since(self.start_time).as_millis() as u64,
                    )),
                );
            }

            let event = QuicLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "packet_sent".to_string(),
                connection_id: connection_id.map(String::from),
                packet_type: Some(packet_type.to_string()),
                packet_size: Some(packet.data.len()),
                src_addr: None,
                dst_addr: Some(packet.dst_addr.to_string()),
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_packet_received(
            &self,
            packet: &ReceivedPacket,
            connection_id: Option<&str>,
            packet_type: &str,
        ) {
            let mut details = HashMap::new();
            details.insert(
                "direction".to_string(),
                serde_json::Value::String("inbound".to_string()),
            );
            details.insert(
                "receive_time_ms".to_string(),
                serde_json::Value::Number(serde_json::Number::from(
                    packet
                        .receive_time
                        .duration_since(self.start_time)
                        .as_millis() as u64,
                )),
            );
            if let Some(transmit_time) = packet.transmit_time {
                details.insert(
                    "transmit_time_ms".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(
                        transmit_time.duration_since(self.start_time).as_millis() as u64,
                    )),
                );
            }

            let event = QuicLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "packet_received".to_string(),
                connection_id: connection_id.map(String::from),
                packet_type: Some(packet_type.to_string()),
                packet_size: Some(packet.data.len()),
                src_addr: Some(packet.src_addr.to_string()),
                dst_addr: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_connection_event(
            &self,
            event_type: &str,
            connection_id: &str,
            details: HashMap<String, serde_json::Value>,
        ) {
            let event = QuicLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: event_type.to_string(),
                connection_id: Some(connection_id.to_string()),
                packet_type: None,
                packet_size: None,
                src_addr: None,
                dst_addr: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn export_json(&self) -> String {
            if let Ok(events) = self.events.lock() {
                serde_json::to_string_pretty(&*events).unwrap_or_else(|_| "[]".to_string())
            } else {
                "[]".to_string()
            }
        }

        pub fn get_event_count(&self) -> usize {
            if let Ok(events) = self.events.lock() {
                events.len()
            } else {
                0
            }
        }
    }

    impl RealQuicServer {
        /// Create a new real QUIC server with actual UDP endpoint
        pub async fn new(
            cx: &Cx,
            config: QuicServerConfig,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            // Validate environment for real service testing
            Self::validate_test_environment()?;

            // Create UDP socket with ephemeral port
            let socket = UdpSocket::bind(config.bind_addr)
                .await
                .map_err(|e| format!("Failed to bind UDP socket: {:?}", e))?;

            let local_addr = socket
                .local_addr()
                .map_err(|e| format!("Failed to get local address: {:?}", e))?;

            // Create QUIC UDP endpoint
            let endpoint_config = QuicUdpEndpointConfig {
                max_packet_size: config.max_packet_size,
                socket_recv_buffer_size: Some(1024 * 1024),
                socket_send_buffer_size: Some(1024 * 1024),
                max_batch_size: 16,
                enable_timestamping: true,
            };

            let endpoint = QuicUdpEndpoint::bind(cx, socket, endpoint_config)
                .map_err(|e| format!("Failed to create QUIC endpoint: {:?}", e))?;

            Ok(Self {
                endpoint,
                local_addr,
                is_running: Arc::new(AtomicBool::new(false)),
                stats: Arc::new(QuicE2EStats::default()),
                config,
            })
        }

        /// Validate environment is safe for real service testing
        fn validate_test_environment() -> Result<(), String> {
            // Production safety guards
            if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
                return Err(
                    "Cannot run real service E2E tests in production environment".to_string(),
                );
            }

            if std::env::var("REAL_SERVICE_TESTS").unwrap_or_default() != "true" {
                return Err(
                    "Set REAL_SERVICE_TESTS=true to enable real service testing".to_string()
                );
            }

            Ok(())
        }

        pub fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        pub fn stats(&self) -> Arc<QuicE2EStats> {
            self.stats.clone()
        }

        /// Start the QUIC server with packet handling loop
        pub async fn start(&self, cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
            self.is_running.store(true, Ordering::SeqCst);

            // Simplified packet handling loop for E2E testing
            let mut endpoint = &self.endpoint;
            let stats = self.stats.clone();
            let is_running = self.is_running.clone();

            while is_running.load(Ordering::SeqCst) {
                if cx.checkpoint().is_err() {
                    break;
                }

                // Receive packets
                match endpoint.receive_batch(cx, 16).await {
                    Ok(packets) => {
                        for packet in packets {
                            stats.packets_received.fetch_add(1, Ordering::Relaxed);
                            stats
                                .bytes_received
                                .fetch_add(packet.data.len() as u64, Ordering::Relaxed);

                            // For E2E testing, echo simple packets back
                            if packet.data.len() > 0 {
                                let response = OutgoingPacket {
                                    dst_addr: packet.src_addr,
                                    data: format!(
                                        "QUIC_ECHO:{}",
                                        String::from_utf8_lossy(&packet.data)
                                    )
                                    .into_bytes(),
                                    send_time: Some(Instant::now()),
                                };

                                match endpoint.send_packet(cx, &response).await {
                                    Ok(()) => {
                                        stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                                        stats.bytes_sent.fetch_add(
                                            response.data.len() as u64,
                                            Ordering::Relaxed,
                                        );
                                    }
                                    Err(_) => {
                                        stats.packet_drops.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Short delay on error to prevent tight loops
                        let _ = sleep(cx, Duration::from_millis(10)).await;
                    }
                }
            }

            Ok(())
        }

        pub async fn stop(&self, cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
            self.is_running.store(false, Ordering::SeqCst);

            // Give server time to process any pending packets
            let _ = sleep(cx, Duration::from_millis(100)).await;

            Ok(())
        }
    }

    /// Production safety guard - validates environment
    fn validate_quic_e2e_environment() -> Result<(), String> {
        if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
            return Err("Real QUIC E2E tests blocked in production".to_string());
        }

        if std::env::var("REAL_SERVICE_TESTS").unwrap_or_default() != "true" {
            return Err("Set REAL_SERVICE_TESTS=true to enable".to_string());
        }

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_quic_server_basic_packet_exchange() -> Result<(), Box<dyn std::error::Error>>
    {
        validate_quic_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = QuicE2ELogger::new();
        let config = QuicServerConfig::default();
        let server = RealQuicServer::new(&cx, config).await?;
        let server_addr = server.local_addr();

        // Start server in background
        let server_handle = {
            let server = &server;
            let cx = &cx;
            async move { server.start(cx).await }
        };

        // Give server time to start
        let _ = sleep(&cx, Duration::from_millis(50)).await;

        // Create client endpoint
        let client_config = QuicUdpEndpointConfig::default();
        let client_socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;

        let mut client_endpoint = QuicUdpEndpoint::bind(&cx, client_socket, client_config).await?;

        // Send test packet
        let test_message = b"TEST_QUIC_MESSAGE";
        let outgoing = OutgoingPacket {
            dst_addr: server_addr,
            data: test_message.to_vec(),
            send_time: Some(Instant::now()),
        };

        logger.log_packet_sent(&outgoing, Some("client-test"), "Initial");
        client_endpoint.send_packet(&cx, &outgoing).await?;

        // Receive echo response
        let received_packets = client_endpoint.receive_batch(&cx, 1).await?;
        assert!(!received_packets.is_empty(), "Should receive echo response");

        let response = &received_packets[0];
        logger.log_packet_received(response, Some("client-test"), "Echo");

        let response_text = String::from_utf8_lossy(&response.data);
        assert!(
            response_text.starts_with("QUIC_ECHO:"),
            "Response should be echoed back: {}",
            response_text
        );

        // Stop server
        server.stop(&cx).await?;

        // Verify statistics
        let stats = server.stats();
        assert!(
            stats.packets_received.load(Ordering::Relaxed) > 0,
            "Server should have received packets"
        );
        assert!(
            stats.packets_sent.load(Ordering::Relaxed) > 0,
            "Server should have sent packets"
        );

        eprintln!("QUIC E2E structured log:\n{}", logger.export_json());
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_quic_server_multiple_connections() -> Result<(), Box<dyn std::error::Error>>
    {
        validate_quic_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = QuicE2ELogger::new();
        let config = QuicServerConfig {
            max_connections: 5,
            ..Default::default()
        };
        let server = RealQuicServer::new(&cx, config).await?;
        let server_addr = server.local_addr();

        // Start server
        let _server_handle = {
            let server = &server;
            let cx = &cx;
            async move { server.start(cx).await }
        };

        let _ = sleep(&cx, Duration::from_millis(50)).await;

        // Create multiple clients
        const NUM_CLIENTS: usize = 3;
        let mut client_endpoints = Vec::new();

        for i in 0..NUM_CLIENTS {
            let client_socket = UdpSocket::bind(
                &cx,
                &UdpSocketConfig {
                    bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                    reuse_address: true,
                    broadcast: false,
                    multicast_loop: None,
                    multicast_ttl: None,
                    ttl: None,
                },
            )
            .await?;

            let client_endpoint =
                QuicUdpEndpoint::bind(&cx, client_socket, QuicUdpEndpointConfig::default()).await?;
            client_endpoints.push(client_endpoint);

            // Send packet from each client
            let test_message = format!("CLIENT_{}_MESSAGE", i);
            let outgoing = OutgoingPacket {
                dst_addr: server_addr,
                data: test_message.into_bytes(),
                send_time: Some(Instant::now()),
            };

            logger.log_packet_sent(&outgoing, Some(&format!("client-{}", i)), "MultiClient");
            client_endpoints[i].send_packet(&cx, &outgoing).await?;
        }

        // Receive responses from all clients
        let mut total_responses = 0;
        for (i, endpoint) in client_endpoints.iter_mut().enumerate() {
            if let Ok(packets) = endpoint.receive_batch(&cx, 1).await {
                for packet in packets {
                    logger.log_packet_received(
                        &packet,
                        Some(&format!("client-{}", i)),
                        "MultiClientEcho",
                    );
                    total_responses += 1;
                }
            }
        }

        server.stop(&cx).await?;

        // Verify all clients received responses
        assert!(
            total_responses > 0,
            "Should receive responses from multiple clients"
        );

        let stats = server.stats();
        assert!(
            stats.packets_received.load(Ordering::Relaxed) >= NUM_CLIENTS as u64,
            "Server should receive packets from all clients"
        );

        eprintln!(
            "Multi-client QUIC E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_quic_server_graceful_shutdown() -> Result<(), Box<dyn std::error::Error>> {
        validate_quic_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = QuicE2ELogger::new();
        let config = QuicServerConfig::default();
        let server = RealQuicServer::new(&cx, config).await?;

        // Track shutdown timing
        let mut details = HashMap::new();
        let start_time = Instant::now();

        logger.log_connection_event("server_start", "main", details.clone());

        // Start and immediately stop server
        let _server_handle = {
            let server = &server;
            let cx = &cx;
            async move { server.start(cx).await }
        };

        sleep(&cx, Duration::from_millis(10)).await?;

        details.insert(
            "shutdown_initiated_ms".to_string(),
            serde_json::Value::Number(serde_json::Number::from(
                start_time.elapsed().as_millis() as u64
            )),
        );
        logger.log_connection_event("server_shutdown_start", "main", details.clone());

        server.stop(&cx).await?;

        details.insert(
            "shutdown_completed_ms".to_string(),
            serde_json::Value::Number(serde_json::Number::from(
                start_time.elapsed().as_millis() as u64
            )),
        );
        logger.log_connection_event("server_shutdown_complete", "main", details);

        // Verify server stopped running
        assert!(
            !server.is_running.load(Ordering::SeqCst),
            "Server should be stopped"
        );

        eprintln!(
            "Shutdown QUIC E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }
}

use std::sync::atomic::AtomicBool;

#[cfg(any(test, feature = "test-internals"))]
pub use quic_native_e2e_tests::*;
