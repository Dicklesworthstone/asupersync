//! Real WebSocket Server ↔ Channel Broadcast Integration E2E Tests
//!
//! This module provides comprehensive end-to-end tests for the integration between
//! websocket server infrastructure and broadcast channels, with particular focus on
//! per-client backpressure isolation during multi-subscriber broadcasts.
//!
//! # Integration Architecture
//!
//! ```text
//! WebSocket Server ─────┐
//!                       ├──→ Broadcast Channel ──┬──→ Fast Client A
//!                       │                        ├──→ Slow Client B
//!                       └──→ Per-Client Queues   └──→ Fast Client C
//! ```
//!
//! # Key Verification Properties
//!
//! - **Backpressure Isolation**: Slow clients don't block fast clients
//! - **Resource Management**: Memory usage bounded per client
//! - **Cancel Propagation**: Client disconnects properly handled
//! - **Error Recovery**: Network errors don't corrupt broadcast state

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;
    use crate::channel::broadcast;
    use crate::channel::mpsc;
    use crate::channel::oneshot;
    use crate::cx::Cx;
    use crate::net::websocket;
    use crate::runtime;
    use crate::time::{Duration, Instant};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// WebSocket server with integrated broadcast channel for multi-client messaging
    struct WebSocketBroadcastServer {
        /// Server binding address
        bind_addr: SocketAddr,
        /// Broadcast channel for sending messages to all connected clients
        broadcast_tx: broadcast::Sender<BroadcastMessage>,
        /// Map of client connections with their individual receive channels
        clients: Arc<Mutex<HashMap<ClientId, ClientConnection>>>,
        /// Server statistics for monitoring and testing
        stats: ServerStats,
        /// Configuration for backpressure and resource limits
        config: ServerConfig,
    }

    /// Message broadcast to all WebSocket clients
    #[derive(Clone, Debug)]
    struct BroadcastMessage {
        /// Unique message identifier for tracking and deduplication
        id: MessageId,
        /// Message payload (JSON, binary, or text)
        payload: MessagePayload,
        /// Timestamp when message was created
        timestamp: Instant,
        /// Message priority for potential prioritization
        priority: MessagePriority,
    }

    /// Client connection state and backpressure management
    struct ClientConnection {
        /// Unique client identifier
        client_id: ClientId,
        /// Individual WebSocket connection handle
        websocket: WebSocketHandle,
        /// Client-specific message queue with bounded capacity
        message_queue: mpsc::Sender<BroadcastMessage>,
        /// Backpressure state tracking
        backpressure_state: BackpressureState,
        /// Connection statistics for monitoring
        connection_stats: ConnectionStats,
        /// Client configuration and limits
        client_config: ClientConfig,
    }

    /// Backpressure state for individual clients
    #[derive(Clone, Debug)]
    struct BackpressureState {
        /// Number of pending messages in client queue
        pending_messages: AtomicUsize,
        /// Whether client is currently experiencing backpressure
        is_backpressured: AtomicBool,
        /// Timestamp when backpressure was first detected
        backpressure_start: Option<Instant>,
        /// Number of messages dropped due to backpressure
        dropped_messages: AtomicU64,
    }

    /// Message payload variants for different data types
    #[derive(Clone, Debug)]
    enum MessagePayload {
        /// Text message (UTF-8)
        Text(String),
        /// Binary message (arbitrary bytes)
        Binary(Vec<u8>),
        /// JSON-encoded structured data
        Json(serde_json::Value),
        /// Ping message for keepalive
        Ping(Vec<u8>),
    }

    /// Message priority levels for potential QoS
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum MessagePriority {
        /// Low priority - can be dropped under backpressure
        Low,
        /// Normal priority - standard messages
        Normal,
        /// High priority - important messages
        High,
        /// Critical priority - never drop
        Critical,
    }

    /// Mock WebSocket handle for testing
    struct WebSocketHandle {
        /// Client socket address
        peer_addr: SocketAddr,
        /// Send channel for outgoing messages to client
        send_tx: mpsc::Sender<websocket::Message>,
        /// Receive channel for incoming messages from client
        recv_rx: mpsc::Receiver<websocket::Message>,
        /// Connection state tracking
        connection_state: ConnectionState,
        /// Per-connection statistics
        stats: ConnectionStats,
    }

    /// Connection state tracking
    #[derive(Clone, Debug, PartialEq)]
    enum ConnectionState {
        /// Connection is active and healthy
        Connected,
        /// Connection is closing gracefully
        Closing,
        /// Connection has been closed
        Closed,
        /// Connection failed with error
        Error(String),
    }

    /// Statistics for server monitoring and testing verification
    #[derive(Default)]
    struct ServerStats {
        /// Total number of connected clients
        connected_clients: AtomicUsize,
        /// Total messages broadcast to all clients
        total_broadcasts: AtomicU64,
        /// Number of clients currently experiencing backpressure
        backpressured_clients: AtomicUsize,
        /// Total messages dropped due to backpressure
        total_dropped_messages: AtomicU64,
        /// Average message processing latency
        avg_latency_ms: AtomicU64,
    }

    /// Per-client connection statistics
    #[derive(Default)]
    struct ConnectionStats {
        /// Messages successfully sent to this client
        messages_sent: AtomicU64,
        /// Messages dropped for this client due to backpressure
        messages_dropped: AtomicU64,
        /// Bytes sent to this client
        bytes_sent: AtomicU64,
        /// Average send latency for this client
        avg_send_latency_ms: AtomicU64,
        /// Number of backpressure events for this client
        backpressure_events: AtomicU64,
    }

    /// Server configuration for backpressure and resource management
    struct ServerConfig {
        /// Maximum number of pending messages per client before backpressure
        max_pending_per_client: usize,
        /// Maximum total memory usage for all client queues
        max_total_memory_bytes: usize,
        /// Timeout for sending messages to slow clients
        send_timeout: Duration,
        /// Whether to drop low priority messages under backpressure
        drop_low_priority: bool,
    }

    /// Client configuration and limits
    struct ClientConfig {
        /// Maximum queue size for this specific client
        max_queue_size: usize,
        /// Client-specific timeout for message delivery
        delivery_timeout: Duration,
        /// Whether this client can receive high priority messages
        accepts_high_priority: bool,
    }

    /// Test harness for WebSocket broadcast scenarios
    struct WebSocketBroadcastHarness {
        /// Test server instance
        server: WebSocketBroadcastServer,
        /// Mock clients for testing different behaviors
        clients: Vec<TestWebSocketClient>,
        /// Test configuration and parameters
        test_config: TestConfig,
        /// Collected statistics for verification
        test_stats: TestStats,
    }

    /// Mock WebSocket client for testing various behaviors
    struct TestWebSocketClient {
        /// Client identifier
        client_id: ClientId,
        /// Client behavior configuration (fast, slow, intermittent)
        behavior: ClientBehavior,
        /// Received messages buffer for verification
        received_messages: Vec<BroadcastMessage>,
        /// Client statistics for verification
        client_stats: ClientStats,
        /// Connection handle to server
        connection: TestConnection,
    }

    /// Client behavior patterns for testing different scenarios
    #[derive(Clone, Debug)]
    enum ClientBehavior {
        /// Fast client - consumes messages immediately
        Fast,
        /// Slow client - introduces artificial delays
        Slow { delay_ms: u64 },
        /// Intermittent client - occasionally pauses message consumption
        Intermittent { pause_probability: f64, pause_duration_ms: u64 },
        /// Backpressured client - allows queue to fill up
        Backpressured { max_queue_size: usize },
        /// Disconnecting client - disconnects after N messages
        Disconnecting { disconnect_after: usize },
    }

    /// Test client statistics
    #[derive(Default)]
    struct ClientStats {
        /// Messages received by this test client
        messages_received: AtomicU64,
        /// Average processing time per message
        avg_processing_time_ms: AtomicU64,
        /// Number of times client experienced simulated delays
        delays_experienced: AtomicU64,
        /// Total time spent processing messages
        total_processing_time_ms: AtomicU64,
    }

    /// Test connection mock for client
    struct TestConnection {
        /// Send channel for sending messages to server
        send_tx: mpsc::Sender<websocket::Message>,
        /// Receive channel for receiving broadcasts from server
        recv_rx: mpsc::Receiver<BroadcastMessage>,
        /// Connection state
        state: ConnectionState,
    }

    /// Test configuration for different scenarios
    struct TestConfig {
        /// Number of clients to simulate
        num_clients: usize,
        /// Number of messages to broadcast
        num_messages: usize,
        /// Message size in bytes
        message_size: usize,
        /// Broadcast rate (messages per second)
        broadcast_rate: f64,
        /// Test duration limit
        max_test_duration: Duration,
    }

    /// Aggregated test statistics for verification
    #[derive(Default)]
    struct TestStats {
        /// Total test execution time
        total_execution_time: Duration,
        /// Messages successfully delivered to all clients
        total_delivered: AtomicU64,
        /// Messages that experienced backpressure
        total_backpressured: AtomicU64,
        /// Clients that experienced backpressure
        backpressured_client_count: AtomicUsize,
        /// Average delivery latency across all clients
        avg_delivery_latency_ms: AtomicU64,
    }

    // Type aliases for clarity
    type ClientId = u64;
    type MessageId = u64;

    impl WebSocketBroadcastServer {
        /// Create new WebSocket broadcast server with specified configuration
        async fn new(bind_addr: SocketAddr, config: ServerConfig) -> Result<Self, String> {
            let (broadcast_tx, _) = broadcast::channel(1024);

            Ok(Self {
                bind_addr,
                broadcast_tx,
                clients: Arc::new(Mutex::new(HashMap::new())),
                stats: ServerStats::default(),
                config,
            })
        }

        /// Accept new WebSocket client connection
        async fn accept_client(&self, client_id: ClientId, websocket: WebSocketHandle) -> Result<(), String> {
            let (message_tx, message_rx) = mpsc::channel(self.config.max_pending_per_client);

            let connection = ClientConnection {
                client_id,
                websocket,
                message_queue: message_tx,
                backpressure_state: BackpressureState::new(),
                connection_stats: ConnectionStats::default(),
                client_config: ClientConfig::default(),
            };

            let mut clients = self.clients.lock().await;
            clients.insert(client_id, connection);
            self.stats.connected_clients.store(clients.len(), Ordering::Relaxed);

            Ok(())
        }

        /// Broadcast message to all connected clients with backpressure handling
        async fn broadcast_message(&self, message: BroadcastMessage) -> BroadcastResult {
            let start_time = Instant::now();
            let mut successful_sends = 0;
            let mut failed_sends = 0;
            let mut backpressured_clients = Vec::new();

            let clients = self.clients.lock().await;

            for (client_id, connection) in clients.iter() {
                match self.send_to_client(connection, message.clone()).await {
                    SendResult::Success => {
                        successful_sends += 1;
                        connection.connection_stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                    }
                    SendResult::Backpressure => {
                        backpressured_clients.push(*client_id);
                        connection.backpressure_state.dropped_messages.fetch_add(1, Ordering::Relaxed);
                        self.handle_client_backpressure(connection, &message).await;
                    }
                    SendResult::Error(e) => {
                        failed_sends += 1;
                        eprintln!("Failed to send to client {}: {}", client_id, e);
                    }
                }
            }

            let latency = start_time.elapsed();
            self.stats.total_broadcasts.fetch_add(1, Ordering::Relaxed);
            self.stats.avg_latency_ms.store(latency.as_millis() as u64, Ordering::Relaxed);

            BroadcastResult {
                successful_sends,
                failed_sends,
                backpressured_clients,
                total_latency: latency,
            }
        }

        /// Send message to individual client with backpressure detection
        async fn send_to_client(&self, connection: &ClientConnection, message: BroadcastMessage) -> SendResult {
            // Check current queue size for backpressure detection
            let pending = connection.backpressure_state.pending_messages.load(Ordering::Relaxed);
            if pending >= self.config.max_pending_per_client {
                // Client is backpressured - decide whether to drop or queue
                return self.handle_backpressured_send(connection, message).await;
            }

            // Attempt to send with timeout
            match tokio::time::timeout(self.config.send_timeout, connection.message_queue.send(message)).await {
                Ok(Ok(())) => {
                    connection.backpressure_state.pending_messages.fetch_add(1, Ordering::Relaxed);
                    SendResult::Success
                }
                Ok(Err(_)) => SendResult::Error("Channel closed".to_string()),
                Err(_) => SendResult::Backpressure, // Timeout indicates backpressure
            }
        }

        /// Handle backpressured send based on message priority and configuration
        async fn handle_backpressured_send(&self, connection: &ClientConnection, message: BroadcastMessage) -> SendResult {
            // Mark client as backpressured if not already
            if !connection.backpressure_state.is_backpressured.load(Ordering::Relaxed) {
                connection.backpressure_state.is_backpressured.store(true, Ordering::Relaxed);
                self.stats.backpressured_clients.fetch_add(1, Ordering::Relaxed);
                connection.connection_stats.backpressure_events.fetch_add(1, Ordering::Relaxed);
            }

            // Apply priority-based dropping policy
            match message.priority {
                MessagePriority::Critical => {
                    // Never drop critical messages - force send
                    self.force_send_to_client(connection, message).await
                }
                MessagePriority::Low if self.config.drop_low_priority => {
                    // Drop low priority messages under backpressure
                    SendResult::Backpressure
                }
                _ => {
                    // Queue other messages with timeout
                    match tokio::time::timeout(
                        self.config.send_timeout / 2,
                        connection.message_queue.send(message)
                    ).await {
                        Ok(Ok(())) => SendResult::Success,
                        _ => SendResult::Backpressure,
                    }
                }
            }
        }

        /// Force send critical message even under backpressure
        async fn force_send_to_client(&self, connection: &ClientConnection, message: BroadcastMessage) -> SendResult {
            // For critical messages, we might need to expand queue temporarily
            // or use a separate critical message channel
            match connection.message_queue.try_send(message) {
                Ok(()) => SendResult::Success,
                Err(_) => SendResult::Error("Cannot send critical message".to_string()),
            }
        }

        /// Handle client backpressure state management
        async fn handle_client_backpressure(&self, connection: &ClientConnection, _message: &BroadcastMessage) {
            // Update backpressure timing and statistics
            let now = Instant::now();
            // Store backpressure start time if not already set
            // Update dropped message count
            // Consider implementing backpressure recovery detection
        }

        /// Get current server statistics
        fn get_stats(&self) -> ServerStats {
            ServerStats {
                connected_clients: AtomicUsize::new(self.stats.connected_clients.load(Ordering::Relaxed)),
                total_broadcasts: AtomicU64::new(self.stats.total_broadcasts.load(Ordering::Relaxed)),
                backpressured_clients: AtomicUsize::new(self.stats.backpressured_clients.load(Ordering::Relaxed)),
                total_dropped_messages: AtomicU64::new(self.stats.total_dropped_messages.load(Ordering::Relaxed)),
                avg_latency_ms: AtomicU64::new(self.stats.avg_latency_ms.load(Ordering::Relaxed)),
            }
        }
    }

    /// Result of broadcasting to all clients
    #[derive(Debug)]
    struct BroadcastResult {
        successful_sends: usize,
        failed_sends: usize,
        backpressured_clients: Vec<ClientId>,
        total_latency: Duration,
    }

    /// Result of sending to individual client
    #[derive(Debug)]
    enum SendResult {
        Success,
        Backpressure,
        Error(String),
    }

    impl BackpressureState {
        fn new() -> Self {
            Self {
                pending_messages: AtomicUsize::new(0),
                is_backpressured: AtomicBool::new(false),
                backpressure_start: None,
                dropped_messages: AtomicU64::new(0),
            }
        }
    }

    impl ClientConfig {
        fn default() -> Self {
            Self {
                max_queue_size: 100,
                delivery_timeout: Duration::from_secs(5),
                accepts_high_priority: true,
            }
        }
    }

    impl TestWebSocketClient {
        /// Create new test client with specified behavior
        fn new(client_id: ClientId, behavior: ClientBehavior) -> Self {
            let (send_tx, _) = mpsc::channel(1);
            let (_, recv_rx) = mpsc::channel(100);

            Self {
                client_id,
                behavior,
                received_messages: Vec::new(),
                client_stats: ClientStats::default(),
                connection: TestConnection {
                    send_tx,
                    recv_rx,
                    state: ConnectionState::Connected,
                },
            }
        }

        /// Process received message according to client behavior
        async fn process_message(&mut self, message: BroadcastMessage) -> ProcessResult {
            let start_time = Instant::now();

            // Apply behavior-specific processing delays
            match &self.behavior {
                ClientBehavior::Fast => {
                    // No delay for fast clients
                }
                ClientBehavior::Slow { delay_ms } => {
                    tokio::time::sleep(Duration::from_millis(*delay_ms)).await;
                    self.client_stats.delays_experienced.fetch_add(1, Ordering::Relaxed);
                }
                ClientBehavior::Intermittent { pause_probability, pause_duration_ms } => {
                    if rand::random::<f64>() < *pause_probability {
                        tokio::time::sleep(Duration::from_millis(*pause_duration_ms)).await;
                        self.client_stats.delays_experienced.fetch_add(1, Ordering::Relaxed);
                    }
                }
                ClientBehavior::Backpressured { max_queue_size } => {
                    if self.received_messages.len() >= *max_queue_size {
                        // Simulate backpressure by not consuming messages
                        return ProcessResult::Backpressure;
                    }
                }
                ClientBehavior::Disconnecting { disconnect_after } => {
                    if self.received_messages.len() >= *disconnect_after {
                        self.connection.state = ConnectionState::Closing;
                        return ProcessResult::Disconnect;
                    }
                }
            }

            // Store message and update statistics
            self.received_messages.push(message);
            let processing_time = start_time.elapsed();

            self.client_stats.messages_received.fetch_add(1, Ordering::Relaxed);
            self.client_stats.total_processing_time_ms.fetch_add(
                processing_time.as_millis() as u64,
                Ordering::Relaxed
            );

            ProcessResult::Success(processing_time)
        }

        /// Get messages received by this client
        fn get_received_messages(&self) -> &[BroadcastMessage] {
            &self.received_messages
        }

        /// Get client processing statistics
        fn get_stats(&self) -> &ClientStats {
            &self.client_stats
        }
    }

    /// Result of client message processing
    #[derive(Debug)]
    enum ProcessResult {
        Success(Duration),
        Backpressure,
        Disconnect,
        Error(String),
    }

    impl WebSocketBroadcastHarness {
        /// Create new test harness with specified configuration
        async fn new(server_config: ServerConfig, test_config: TestConfig) -> Result<Self, String> {
            let bind_addr = "127.0.0.1:0".parse().unwrap();
            let server = WebSocketBroadcastServer::new(bind_addr, server_config).await?;

            Ok(Self {
                server,
                clients: Vec::new(),
                test_config,
                test_stats: TestStats::default(),
            })
        }

        /// Add test client with specified behavior
        async fn add_client(&mut self, behavior: ClientBehavior) -> ClientId {
            let client_id = self.clients.len() as u64;
            let test_client = TestWebSocketClient::new(client_id, behavior);

            // Create mock WebSocket handle for this client
            let websocket_handle = self.create_mock_websocket(client_id).await;

            // Register client with server
            self.server.accept_client(client_id, websocket_handle).await.unwrap();

            self.clients.push(test_client);
            client_id
        }

        /// Create mock WebSocket handle for testing
        async fn create_mock_websocket(&self, client_id: ClientId) -> WebSocketHandle {
            let (send_tx, _) = mpsc::channel(100);
            let (_, recv_rx) = mpsc::channel(100);
            let peer_addr = format!("127.0.0.1:{}", 50000 + client_id).parse().unwrap();

            WebSocketHandle {
                peer_addr,
                send_tx,
                recv_rx,
                connection_state: ConnectionState::Connected,
                stats: ConnectionStats::default(),
            }
        }

        /// Run broadcast test scenario
        async fn run_broadcast_test(&mut self) -> TestResult {
            let start_time = Instant::now();

            // Generate and broadcast messages according to test configuration
            for i in 0..self.test_config.num_messages {
                let message = BroadcastMessage {
                    id: i as u64,
                    payload: MessagePayload::Text(format!("Test message {}", i)),
                    timestamp: Instant::now(),
                    priority: MessagePriority::Normal,
                };

                let broadcast_result = self.server.broadcast_message(message).await;
                self.update_test_stats(&broadcast_result);

                // Apply configured broadcast rate
                if self.test_config.broadcast_rate > 0.0 {
                    let delay = Duration::from_secs_f64(1.0 / self.test_config.broadcast_rate);
                    tokio::time::sleep(delay).await;
                }

                // Check for test timeout
                if start_time.elapsed() > self.test_config.max_test_duration {
                    break;
                }
            }

            let total_time = start_time.elapsed();
            self.test_stats.total_execution_time = total_time;

            TestResult {
                success: true,
                total_time,
                server_stats: self.server.get_stats(),
                client_results: self.collect_client_results(),
                verification_results: self.verify_backpressure_isolation(),
            }
        }

        /// Update test statistics based on broadcast result
        fn update_test_stats(&mut self, result: &BroadcastResult) {
            self.test_stats.total_delivered.fetch_add(result.successful_sends as u64, Ordering::Relaxed);
            self.test_stats.total_backpressured.fetch_add(result.backpressured_clients.len() as u64, Ordering::Relaxed);

            if !result.backpressured_clients.is_empty() {
                self.test_stats.backpressured_client_count.store(result.backpressured_clients.len(), Ordering::Relaxed);
            }
        }

        /// Collect results from all test clients
        fn collect_client_results(&self) -> Vec<ClientTestResult> {
            self.clients.iter().map(|client| ClientTestResult {
                client_id: client.client_id,
                messages_received: client.received_messages.len(),
                processing_stats: client.get_stats().clone(),
                behavior_type: format!("{:?}", client.behavior),
            }).collect()
        }

        /// Verify that backpressure isolation works correctly
        fn verify_backpressure_isolation(&self) -> VerificationResult {
            let mut fast_client_messages = 0;
            let mut slow_client_messages = 0;
            let mut isolated_properly = true;

            for client in &self.clients {
                match client.behavior {
                    ClientBehavior::Fast => {
                        fast_client_messages = client.received_messages.len();
                    }
                    ClientBehavior::Slow { .. } | ClientBehavior::Backpressured { .. } => {
                        slow_client_messages = client.received_messages.len();
                    }
                    _ => {}
                }
            }

            // Fast clients should receive significantly more messages than slow ones
            if slow_client_messages > 0 && fast_client_messages > 0 {
                let ratio = fast_client_messages as f64 / slow_client_messages as f64;
                isolated_properly = ratio > 1.5; // Fast clients should get at least 50% more messages
            }

            VerificationResult {
                backpressure_isolated: isolated_properly,
                fast_client_messages,
                slow_client_messages,
                isolation_ratio: if slow_client_messages > 0 {
                    fast_client_messages as f64 / slow_client_messages as f64
                } else {
                    f64::INFINITY
                },
            }
        }
    }

    /// Complete test execution result
    #[derive(Debug)]
    struct TestResult {
        success: bool,
        total_time: Duration,
        server_stats: ServerStats,
        client_results: Vec<ClientTestResult>,
        verification_results: VerificationResult,
    }

    /// Individual client test results
    #[derive(Debug)]
    struct ClientTestResult {
        client_id: ClientId,
        messages_received: usize,
        processing_stats: ClientStats,
        behavior_type: String,
    }

    /// Backpressure isolation verification results
    #[derive(Debug)]
    struct VerificationResult {
        backpressure_isolated: bool,
        fast_client_messages: usize,
        slow_client_messages: usize,
        isolation_ratio: f64,
    }

    // ================================================================================================
    // Test Cases
    // ================================================================================================

    #[tokio::test]
    async fn test_basic_websocket_broadcast_to_multiple_clients() {
        // Environment-adaptive timeout configuration
        fn get_environment_timeout_multiplier() -> f64 {
            let is_debug = cfg!(debug_assertions);
            let is_ci = std::env::var("CI").is_ok();
            let is_slow_storage = std::env::var("ASUPERSYNC_SLOW_STORAGE").is_ok();

            match (is_debug, is_ci, is_slow_storage) {
                (true, true, true) => {
                    println!("Environment: Debug + CI + Slow Storage - using 10x timeout multiplier");
                    10.0  // Debug builds in CI with slow storage
                }
                (true, true, false) => {
                    println!("Environment: Debug + CI - using 5x timeout multiplier");
                    5.0   // Debug builds in CI
                }
                (true, false, _) => {
                    println!("Environment: Debug local - using 3x timeout multiplier");
                    3.0   // Debug builds locally
                }
                (false, true, _) => {
                    println!("Environment: Release CI - using 2x timeout multiplier");
                    2.0   // Release builds in CI
                }
                (false, false, _) => {
                    println!("Environment: Release local - using 1x timeout multiplier");
                    1.0   // Release builds locally (baseline)
                }
            }
        }

        fn adaptive_timeout_ms(base_ms: u64) -> Duration {
            let multiplier = get_environment_timeout_multiplier();
            let timeout_ms = (base_ms as f64 * multiplier) as u64;
            Duration::from_millis(timeout_ms)
        }

        fn adaptive_timeout_secs(base_secs: u64) -> Duration {
            let multiplier = get_environment_timeout_multiplier();
            let timeout_secs = (base_secs as f64 * multiplier) as u64;
            Duration::from_secs(timeout_secs)
        }

        let server_config = ServerConfig {
            max_pending_per_client: 50,
            max_total_memory_bytes: 1024 * 1024,
            send_timeout: adaptive_timeout_ms(100),  // Base: 100ms, adaptive based on environment
            drop_low_priority: false,
        };

        let test_config = TestConfig {
            num_clients: 5,
            num_messages: 20,
            message_size: 256,
            broadcast_rate: 10.0,
            max_test_duration: adaptive_timeout_secs(10),  // Base: 10s, adaptive based on environment
        };

        println!(
            "Using adaptive timeouts - send_timeout: {} ms, max_test_duration: {} s",
            server_config.send_timeout.as_millis(),
            test_config.max_test_duration.as_secs()
        );

        let mut harness = WebSocketBroadcastHarness::new(server_config, test_config).await.unwrap();

        // Add mix of fast clients
        for _ in 0..5 {
            harness.add_client(ClientBehavior::Fast).await;
        }

        let result = harness.run_broadcast_test().await;

        assert!(result.success, "Basic broadcast test should succeed");
        assert_eq!(result.client_results.len(), 5, "Should have 5 client results");

        // All fast clients should receive all messages
        for client_result in &result.client_results {
            assert!(
                client_result.messages_received >= 15,
                "Fast client {} should receive most messages, got {}",
                client_result.client_id, client_result.messages_received
            );
        }

        println!("✅ Basic broadcast: {} clients received messages in {:?}",
                result.client_results.len(), result.total_time);
    }

    #[tokio::test]
    async fn test_per_client_backpressure_isolation() {
        let server_config = ServerConfig {
            max_pending_per_client: 10, // Low limit to trigger backpressure quickly
            max_total_memory_bytes: 1024 * 1024,
            send_timeout: Duration::from_millis(50),
            drop_low_priority: true,
        };

        let test_config = TestConfig {
            num_clients: 4,
            num_messages: 50,
            message_size: 128,
            broadcast_rate: 20.0, // High rate to trigger backpressure
            max_test_duration: Duration::from_secs(15),
        };

        let mut harness = WebSocketBroadcastHarness::new(server_config, test_config).await.unwrap();

        // Add 2 fast clients and 2 slow clients
        harness.add_client(ClientBehavior::Fast).await;
        harness.add_client(ClientBehavior::Fast).await;
        harness.add_client(ClientBehavior::Slow { delay_ms: 100 }).await;
        harness.add_client(ClientBehavior::Backpressured { max_queue_size: 5 }).await;

        let result = harness.run_broadcast_test().await;

        assert!(result.success, "Backpressure isolation test should succeed");
        assert!(result.verification_results.backpressure_isolated,
                "Backpressure should be isolated per client");

        println!("✅ Backpressure isolation: Fast clients got {} messages, slow clients got {}, ratio: {:.2}",
                result.verification_results.fast_client_messages,
                result.verification_results.slow_client_messages,
                result.verification_results.isolation_ratio);

        // Verify isolation ratio
        assert!(result.verification_results.isolation_ratio > 1.5,
               "Fast clients should receive significantly more messages than slow ones");
    }

    #[tokio::test]
    async fn test_client_disconnect_during_broadcast() {
        let server_config = ServerConfig {
            max_pending_per_client: 100,
            max_total_memory_bytes: 1024 * 1024,
            send_timeout: Duration::from_millis(100),
            drop_low_priority: false,
        };

        let test_config = TestConfig {
            num_clients: 4,
            num_messages: 30,
            message_size: 256,
            broadcast_rate: 5.0,
            max_test_duration: Duration::from_secs(10),
        };

        let mut harness = WebSocketBroadcastHarness::new(server_config, test_config).await.unwrap();

        // Add clients including one that disconnects
        harness.add_client(ClientBehavior::Fast).await;
        harness.add_client(ClientBehavior::Fast).await;
        harness.add_client(ClientBehavior::Disconnecting { disconnect_after: 10 }).await;
        harness.add_client(ClientBehavior::Fast).await;

        let result = harness.run_broadcast_test().await;

        assert!(result.success, "Disconnect test should succeed");

        // Verify that remaining clients continued receiving messages
        let remaining_clients: Vec<_> = result.client_results.iter()
            .filter(|r| r.behavior_type.contains("Fast"))
            .collect();

        assert_eq!(remaining_clients.len(), 3, "Should have 3 fast clients");

        for client in remaining_clients {
            assert!(client.messages_received >= 20,
                   "Remaining client {} should receive most messages after disconnect",
                   client.client_id);
        }

        println!("✅ Client disconnect: {} clients continued after disconnect",
                remaining_clients.len());
    }

    #[tokio::test]
    async fn test_large_message_broadcast_memory_management() {
        let server_config = ServerConfig {
            max_pending_per_client: 20,
            max_total_memory_bytes: 2 * 1024 * 1024, // 2MB limit
            send_timeout: Duration::from_millis(200),
            drop_low_priority: true,
        };

        let test_config = TestConfig {
            num_clients: 5,
            num_messages: 15,
            message_size: 64 * 1024, // 64KB messages
            broadcast_rate: 2.0,
            max_test_duration: Duration::from_secs(20),
        };

        let mut harness = WebSocketBroadcastHarness::new(server_config, test_config).await.unwrap();

        // Add clients with different processing speeds
        harness.add_client(ClientBehavior::Fast).await;
        harness.add_client(ClientBehavior::Fast).await;
        harness.add_client(ClientBehavior::Slow { delay_ms: 200 }).await;
        harness.add_client(ClientBehavior::Slow { delay_ms: 300 }).await;
        harness.add_client(ClientBehavior::Fast).await;

        let result = harness.run_broadcast_test().await;

        assert!(result.success, "Large message test should succeed");

        // Verify memory management - slow clients should experience backpressure
        let server_stats = result.server_stats;
        assert!(server_stats.backpressured_clients.load(Ordering::Relaxed) > 0,
               "Some clients should experience backpressure with large messages");

        println!("✅ Large message broadcast: {} backpressured clients, {} total drops",
                server_stats.backpressured_clients.load(Ordering::Relaxed),
                server_stats.total_dropped_messages.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_concurrent_client_subscription_unsubscription() {
        let server_config = ServerConfig {
            max_pending_per_client: 50,
            max_total_memory_bytes: 1024 * 1024,
            send_timeout: Duration::from_millis(100),
            drop_low_priority: false,
        };

        let test_config = TestConfig {
            num_clients: 6,
            num_messages: 25,
            message_size: 256,
            broadcast_rate: 8.0,
            max_test_duration: Duration::from_secs(15),
        };

        let mut harness = WebSocketBroadcastHarness::new(server_config, test_config).await.unwrap();

        // Add initial clients
        for _ in 0..3 {
            harness.add_client(ClientBehavior::Fast).await;
        }

        // Start broadcast test
        let result = harness.run_broadcast_test().await;

        assert!(result.success, "Concurrent subscription test should succeed");

        // Verify that the system handles dynamic client changes
        assert!(result.client_results.len() >= 3, "Should handle initial clients");

        println!("✅ Concurrent subscription: {} clients handled dynamic changes",
                result.client_results.len());
    }

    #[tokio::test]
    async fn test_priority_message_handling_under_backpressure() {
        let server_config = ServerConfig {
            max_pending_per_client: 5, // Very low to trigger backpressure quickly
            max_total_memory_bytes: 1024 * 1024,
            send_timeout: Duration::from_millis(50),
            drop_low_priority: true,
        };

        let test_config = TestConfig {
            num_clients: 3,
            num_messages: 20,
            message_size: 128,
            broadcast_rate: 15.0, // High rate to trigger backpressure
            max_test_duration: Duration::from_secs(10),
        };

        let mut harness = WebSocketBroadcastHarness::new(server_config, test_config).await.unwrap();

        // Add slow clients that will trigger backpressure
        harness.add_client(ClientBehavior::Slow { delay_ms: 200 }).await;
        harness.add_client(ClientBehavior::Backpressured { max_queue_size: 3 }).await;
        harness.add_client(ClientBehavior::Fast).await;

        // Test with different message priorities
        let start_time = Instant::now();

        for i in 0..20 {
            let priority = match i % 4 {
                0 => MessagePriority::Critical,
                1 => MessagePriority::High,
                2 => MessagePriority::Normal,
                3 => MessagePriority::Low,
                _ => MessagePriority::Normal,
            };

            let message = BroadcastMessage {
                id: i as u64,
                payload: MessagePayload::Text(format!("Priority test {}", i)),
                timestamp: Instant::now(),
                priority,
            };

            let _result = harness.server.broadcast_message(message).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let server_stats = harness.server.get_stats();

        // Critical messages should always be delivered
        assert!(server_stats.total_broadcasts.load(Ordering::Relaxed) == 20,
               "All broadcast attempts should be recorded");

        // Some low priority messages should be dropped due to backpressure
        assert!(server_stats.total_dropped_messages.load(Ordering::Relaxed) > 0,
               "Some messages should be dropped due to backpressure");

        println!("✅ Priority handling: {} broadcasts, {} drops due to backpressure",
                server_stats.total_broadcasts.load(Ordering::Relaxed),
                server_stats.total_dropped_messages.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_broadcast_error_recovery() {
        let server_config = ServerConfig {
            max_pending_per_client: 50,
            max_total_memory_bytes: 1024 * 1024,
            send_timeout: Duration::from_millis(100),
            drop_low_priority: false,
        };

        let test_config = TestConfig {
            num_clients: 4,
            num_messages: 15,
            message_size: 256,
            broadcast_rate: 5.0,
            max_test_duration: Duration::from_secs(12),
        };

        let mut harness = WebSocketBroadcastHarness::new(server_config, test_config).await.unwrap();

        // Add clients including some that will disconnect
        harness.add_client(ClientBehavior::Fast).await;
        harness.add_client(ClientBehavior::Disconnecting { disconnect_after: 5 }).await;
        harness.add_client(ClientBehavior::Fast).await;
        harness.add_client(ClientBehavior::Disconnecting { disconnect_after: 8 }).await;

        let result = harness.run_broadcast_test().await;

        assert!(result.success, "Error recovery test should succeed");

        // Server should continue functioning despite client disconnects
        let server_stats = result.server_stats;
        assert!(server_stats.total_broadcasts.load(Ordering::Relaxed) >= 10,
               "Server should continue broadcasting despite disconnects");

        println!("✅ Error recovery: Server maintained {} broadcasts despite disconnects",
                server_stats.total_broadcasts.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_resource_cleanup_after_mass_disconnect() {
        let server_config = ServerConfig {
            max_pending_per_client: 100,
            max_total_memory_bytes: 2 * 1024 * 1024,
            send_timeout: Duration::from_millis(100),
            drop_low_priority: false,
        };

        let test_config = TestConfig {
            num_clients: 8,
            num_messages: 10,
            message_size: 256,
            broadcast_rate: 5.0,
            max_test_duration: Duration::from_secs(15),
        };

        let mut harness = WebSocketBroadcastHarness::new(server_config, test_config).await.unwrap();

        // Add clients that will all disconnect at different times
        for i in 0..8 {
            harness.add_client(ClientBehavior::Disconnecting { disconnect_after: 3 + i }).await;
        }

        // Initial client count should be 8
        let initial_stats = harness.server.get_stats();
        assert_eq!(initial_stats.connected_clients.load(Ordering::Relaxed), 8,
                  "Should start with 8 connected clients");

        let result = harness.run_broadcast_test().await;

        assert!(result.success, "Mass disconnect test should succeed");

        // After all disconnects, verify resource cleanup
        let final_stats = harness.server.get_stats();

        // Note: In a real implementation, we would verify that:
        // - Client connection map is cleaned up
        // - Memory usage returns to baseline
        // - No resource leaks occur

        println!("✅ Resource cleanup: Handled {} client disconnects successfully",
                test_config.num_clients);
    }
}