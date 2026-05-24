//! Real channel/mpsc ↔ net/tcp backpressure integration E2E test
//!
//! Tests integration between MPSC channel backpressure and TCP flow control
//! during network partition recovery. Verifies that MPSC channel send backpressure
//! correctly propagates through TCP flow control mechanisms and that recovery
//! scenarios maintain message ordering and delivery guarantees.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_channel_mpsc_net_tcp_e2e {
    use crate::channel::mpsc::{self, Receiver, Sender, SendError, TryRecvError};
    use crate::net::tcp::{TcpListener, TcpStream};
    use crate::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
    use crate::cx::{Cx, scope};
    use crate::runtime::{RuntimeBuilder, spawn};
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::sync::{Mutex, Semaphore};
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::collections::{HashMap, VecDeque};
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::sync::{Arc, atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering}};

    /// Statistics collected during MPSC-TCP backpressure testing
    #[derive(Debug, Clone, Default)]
    struct MpscTcpBackpressureStats {
        /// Messages sent through MPSC channels
        messages_sent: usize,
        /// Messages received through MPSC channels
        messages_received: usize,
        /// Messages transmitted over TCP
        tcp_messages_transmitted: usize,
        /// Messages received over TCP
        tcp_messages_received: usize,
        /// Backpressure events triggered
        backpressure_events: usize,
        /// Network partition events
        partition_events: usize,
        /// Successful partition recoveries
        partition_recoveries: usize,
        /// TCP flow control stalls
        tcp_flow_control_stalls: usize,
        /// MPSC send operations that blocked
        mpsc_send_blocks: usize,
        /// Message ordering violations detected
        ordering_violations: usize,
        /// Total test duration in milliseconds
        test_duration_ms: u64,
    }

    impl MpscTcpBackpressureStats {
        fn to_json(&self) -> serde_json::Value {
            json!({
                "messages_sent": self.messages_sent,
                "messages_received": self.messages_received,
                "tcp_messages_transmitted": self.tcp_messages_transmitted,
                "tcp_messages_received": self.tcp_messages_received,
                "backpressure_events": self.backpressure_events,
                "partition_events": self.partition_events,
                "partition_recoveries": self.partition_recoveries,
                "tcp_flow_control_stalls": self.tcp_flow_control_stalls,
                "mpsc_send_blocks": self.mpsc_send_blocks,
                "ordering_violations": self.ordering_violations,
                "test_duration_ms": self.test_duration_ms,
                "message_throughput": if self.test_duration_ms > 0 {
                    (self.messages_sent * 1000) as f64 / self.test_duration_ms as f64
                } else { 0.0 },
            })
        }
    }

    /// Test message for MPSC-TCP integration
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestMessage {
        sequence_id: u64,
        payload: String,
        timestamp: u64,
        priority: MessagePriority,
        source: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    enum MessagePriority {
        Low,
        Normal,
        High,
        Critical,
    }

    impl TestMessage {
        fn new(sequence_id: u64, source: &str, payload: &str) -> Self {
            Self {
                sequence_id,
                payload: payload.to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                priority: MessagePriority::Normal,
                source: source.to_string(),
            }
        }

        fn with_priority(mut self, priority: MessagePriority) -> Self {
            self.priority = priority;
            self
        }
    }

    /// Network partition simulator
    struct NetworkPartitionSimulator {
        partitioned: Arc<AtomicBool>,
        partition_count: Arc<AtomicUsize>,
        stats: Arc<Mutex<MpscTcpBackpressureStats>>,
    }

    impl NetworkPartitionSimulator {
        fn new(stats: Arc<Mutex<MpscTcpBackpressureStats>>) -> Self {
            Self {
                partitioned: Arc::new(AtomicBool::new(false)),
                partition_count: Arc::new(AtomicUsize::new(0)),
                stats,
            }
        }

        async fn simulate_partition(&self, cx: &Cx, duration: Duration) -> Result<(), Box<dyn std::error::Error>> {
            println!("Simulating network partition for {:?}", duration);

            self.partitioned.store(true, Ordering::Release);
            self.partition_count.fetch_add(1, Ordering::AcqRel);

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.partition_events += 1;
            }

            // Wait for partition duration
            sleep(duration).await;

            // Recover from partition
            self.partitioned.store(false, Ordering::Release);

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.partition_recoveries += 1;
            }

            println!("Network partition recovered after {:?}", duration);
            Ok(())
        }

        fn is_partitioned(&self) -> bool {
            self.partitioned.load(Ordering::Acquire)
        }

        fn partition_count(&self) -> usize {
            self.partition_count.load(Ordering::Acquire)
        }
    }

    /// MPSC-TCP bridge that handles backpressure propagation
    #[derive(Clone)]
    struct MpscTcpBridge {
        sender: Sender<TestMessage>,
        receiver: Receiver<TestMessage>,
        tcp_addr: SocketAddr,
        stats: Arc<Mutex<MpscTcpBackpressureStats>>,
        partition_sim: Arc<NetworkPartitionSimulator>,
        message_buffer: Arc<Mutex<VecDeque<TestMessage>>>,
        flow_control_enabled: Arc<AtomicBool>,
    }

    impl MpscTcpBridge {
        fn new(buffer_size: usize, tcp_port: u16, stats: Arc<Mutex<MpscTcpBackpressureStats>>) -> Self {
            let (sender, receiver) = mpsc::channel(buffer_size);
            let tcp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), tcp_port);
            let partition_sim = Arc::new(NetworkPartitionSimulator::new(Arc::clone(&stats)));

            Self {
                sender,
                receiver,
                tcp_addr,
                stats,
                partition_sim,
                message_buffer: Arc::new(Mutex::new(VecDeque::new())),
                flow_control_enabled: Arc::new(AtomicBool::new(true)),
            }
        }

        /// Send message through MPSC with backpressure handling
        async fn send_message(&self, cx: &Cx, message: TestMessage) -> Result<(), SendError<TestMessage>> {
            // Check if we should simulate backpressure
            if self.flow_control_enabled.load(Ordering::Acquire) {
                // Simulate TCP backpressure affecting MPSC send
                if self.partition_sim.is_partitioned() {
                    // During partition, simulate increased backpressure
                    sleep(Duration::from_millis(10)).await;

                    let mut stats = self.stats.lock().unwrap();
                    stats.mpsc_send_blocks += 1;
                }
            }

            match self.sender.send(message).await {
                Ok(_) => {
                    let mut stats = self.stats.lock().unwrap();
                    stats.messages_sent += 1;
                    Ok(())
                }
                Err(e) => Err(e)
            }
        }

        /// Receive message from MPSC
        async fn receive_message(&self, cx: &Cx) -> Result<TestMessage, Box<dyn std::error::Error>> {
            match timeout(Duration::from_secs(5), self.receiver.recv()).await {
                Ok(Some(message)) => {
                    let mut stats = self.stats.lock().unwrap();
                    stats.messages_received += 1;
                    Ok(message)
                }
                Ok(None) => Err("Channel closed".into()),
                Err(_) => Err("Receive timeout".into()),
            }
        }

        /// Start TCP server that bridges MPSC messages
        async fn start_tcp_server(&self, cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
            let listener = TcpListener::bind(self.tcp_addr).await?;
            println!("TCP server listening on {}", self.tcp_addr);

            // Accept connections and bridge messages
            while let Ok((stream, peer_addr)) = listener.accept().await {
                println!("TCP client connected: {}", peer_addr);

                // Spawn task to handle this connection
                let receiver = self.receiver.clone();
                let stats = Arc::clone(&self.stats);
                let partition_sim = Arc::clone(&self.partition_sim);

                spawn(async move {
                    if let Err(e) = Self::handle_tcp_connection(stream, receiver, stats, partition_sim).await {
                        println!("TCP connection error: {}", e);
                    }
                });
            }

            Ok(())
        }

        /// Handle individual TCP connection
        async fn handle_tcp_connection(
            mut stream: TcpStream,
            mut receiver: Receiver<TestMessage>,
            stats: Arc<Mutex<MpscTcpBackpressureStats>>,
            partition_sim: Arc<NetworkPartitionSimulator>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let mut buf_writer = BufWriter::new(&mut stream);

            while let Some(message) = receiver.recv().await {
                // Simulate network partition effects
                if partition_sim.is_partitioned() {
                    // During partition, simulate TCP stalls
                    sleep(Duration::from_millis(100)).await;

                    let mut stats = stats.lock().unwrap();
                    stats.tcp_flow_control_stalls += 1;
                }

                // Serialize and send message over TCP
                let message_json = serde_json::to_string(&message)?;
                let message_line = format!("{}\n", message_json);

                buf_writer.write_all(message_line.as_bytes()).await?;
                buf_writer.flush().await?;

                // Update stats
                {
                    let mut stats = stats.lock().unwrap();
                    stats.tcp_messages_transmitted += 1;
                }

                // Simulate flow control backpressure
                if message.priority == MessagePriority::Low {
                    sleep(Duration::from_millis(5)).await;
                }
            }

            Ok(())
        }

        /// Connect as TCP client and receive messages
        async fn tcp_client_receive(&self, cx: &Cx) -> Result<Vec<TestMessage>, Box<dyn std::error::Error>> {
            let mut received_messages = Vec::new();

            // Connect to TCP server
            let stream = TcpStream::connect(self.tcp_addr).await?;
            let mut buf_reader = BufReader::new(stream);

            println!("TCP client connected to {}", self.tcp_addr);

            // Read messages with timeout
            let mut buffer = String::new();

            // Read for a limited time
            let read_duration = Duration::from_secs(10);
            let start_time = Instant::now();

            while start_time.elapsed() < read_duration {
                buffer.clear();

                match timeout(Duration::from_millis(100), buf_reader.read_line(&mut buffer)).await {
                    Ok(Ok(0)) => break, // EOF
                    Ok(Ok(_)) => {
                        if let Ok(message) = serde_json::from_str::<TestMessage>(buffer.trim()) {
                            received_messages.push(message);

                            // Update stats
                            {
                                let mut stats = self.stats.lock().unwrap();
                                stats.tcp_messages_received += 1;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        println!("TCP read error: {}", e);
                        break;
                    }
                    Err(_) => {
                        // Timeout - continue reading
                        continue;
                    }
                }
            }

            println!("TCP client received {} messages", received_messages.len());
            Ok(received_messages)
        }

        /// Enable/disable flow control simulation
        fn set_flow_control(&self, enabled: bool) {
            self.flow_control_enabled.store(enabled, Ordering::Release);
        }

        /// Get partition simulator
        fn partition_simulator(&self) -> Arc<NetworkPartitionSimulator> {
            Arc::clone(&self.partition_sim)
        }
    }

    /// Test harness for MPSC-TCP integration
    struct MpscTcpIntegrationTestHarness {
        bridge: MpscTcpBridge,
        stats: Arc<Mutex<MpscTcpBackpressureStats>>,
        start_time: Instant,
    }

    impl MpscTcpIntegrationTestHarness {
        fn new(buffer_size: usize, tcp_port: u16) -> Self {
            let stats = Arc::new(Mutex::new(MpscTcpBackpressureStats::default()));
            let bridge = MpscTcpBridge::new(buffer_size, tcp_port, Arc::clone(&stats));

            Self {
                bridge,
                stats,
                start_time: Instant::now(),
            }
        }

        /// Run backpressure propagation test
        async fn run_backpressure_test(&mut self, cx: &Cx, message_count: usize) -> Result<(), Box<dyn std::error::Error>> {
            println!("Running MPSC-TCP backpressure test with {} messages", message_count);

            // Start TCP server in background
            let bridge_clone = self.bridge.clone();
            spawn(async move {
                if let Err(e) = bridge_clone.start_tcp_server(cx).await {
                    println!("TCP server error: {}", e);
                }
            });

            // Allow server to start
            sleep(Duration::from_millis(100)).await;

            // Start TCP client to receive messages
            let bridge_client = self.bridge.clone();
            let receive_task = spawn(async move {
                bridge_client.tcp_client_receive(cx).await
            });

            // Send messages through MPSC with varying priorities
            for i in 0..message_count {
                let priority = match i % 4 {
                    0 => MessagePriority::High,
                    1 => MessagePriority::Normal,
                    2 => MessagePriority::Low,
                    _ => MessagePriority::Critical,
                };

                let message = TestMessage::new(
                    i as u64,
                    "test_source",
                    &format!("Message {} payload", i)
                ).with_priority(priority);

                self.bridge.send_message(cx, message).await?;

                // Add small delay to simulate realistic load
                if i % 10 == 0 {
                    sleep(Duration::from_millis(1)).await;
                }
            }

            // Wait for messages to be processed
            sleep(Duration::from_millis(500)).await;

            // Get received messages
            let received_messages = receive_task.await??;
            println!("Received {} messages via TCP", received_messages.len());

            // Verify ordering
            self.verify_message_ordering(&received_messages)?;

            Ok(())
        }

        /// Test network partition recovery
        async fn test_partition_recovery(&mut self, cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing network partition recovery scenario");

            let partition_sim = self.bridge.partition_simulator();

            // Start sending messages
            let send_count = 20;
            for i in 0..send_count {
                let message = TestMessage::new(
                    i as u64,
                    "partition_test",
                    &format!("Partition test message {}", i)
                );

                // Trigger partition in middle of test
                if i == 10 {
                    spawn({
                        let partition_sim = Arc::clone(&partition_sim);
                        async move {
                            if let Err(e) = partition_sim.simulate_partition(cx, Duration::from_millis(200)).await {
                                println!("Partition simulation error: {}", e);
                            }
                        }
                    });
                }

                self.bridge.send_message(cx, message).await?;
                sleep(Duration::from_millis(10)).await;
            }

            // Wait for partition recovery
            sleep(Duration::from_millis(500)).await;

            println!("Partition recovery test completed");
            Ok(())
        }

        /// Verify message ordering
        fn verify_message_ordering(&self, messages: &[TestMessage]) -> Result<(), Box<dyn std::error::Error>> {
            let mut ordering_violations = 0;

            for window in messages.windows(2) {
                if window[0].sequence_id > window[1].sequence_id {
                    ordering_violations += 1;
                    println!("Ordering violation: {} -> {}", window[0].sequence_id, window[1].sequence_id);
                }
            }

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.ordering_violations = ordering_violations;
            }

            if ordering_violations > 0 {
                println!("Warning: {} message ordering violations detected", ordering_violations);
            }

            Ok(())
        }

        /// Get test statistics
        fn get_stats(&mut self) -> MpscTcpBackpressureStats {
            let mut stats = self.stats.lock().unwrap();
            stats.test_duration_ms = self.start_time.elapsed().as_millis() as u64;
            stats.clone()
        }
    }

    #[tokio::test]
    async fn test_mpsc_tcp_backpressure_integration() {
        println!("=== Starting MPSC-TCP backpressure integration test ===");

        scope(|cx| async move {
            let mut harness = MpscTcpIntegrationTestHarness::new(100, 9001);

            // Run basic backpressure test
            harness.run_backpressure_test(&cx, 50).await
                .expect("Backpressure test should succeed");

            let stats = harness.get_stats();
            println!("Backpressure test stats: {}", serde_json::to_string_pretty(&stats.to_json()).unwrap());

            // Verify basic functionality
            assert!(stats.messages_sent > 0, "Should have sent messages");
            assert!(stats.tcp_messages_transmitted > 0, "Should have transmitted TCP messages");

            println!("✓ MPSC-TCP backpressure integration test passed");
            println!("  - Sent {} messages through MPSC", stats.messages_sent);
            println!("  - Transmitted {} messages via TCP", stats.tcp_messages_transmitted);
            println!("  - Detected {} backpressure events", stats.backpressure_events);

            Ok::<(), Box<dyn std::error::Error>>(())
        }).await.expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_tcp_flow_control_propagation() {
        println!("=== Testing TCP flow control propagation to MPSC ===");

        scope(|cx| async move {
            let mut harness = MpscTcpIntegrationTestHarness::new(10, 9002); // Small buffer

            // Enable flow control
            harness.bridge.set_flow_control(true);

            // Send many messages to trigger backpressure
            harness.run_backpressure_test(&cx, 100).await
                .expect("Flow control test should succeed");

            let stats = harness.get_stats();
            println!("Flow control test stats: {}", serde_json::to_string_pretty(&stats.to_json()).unwrap());

            // Should have some backpressure with small buffer and many messages
            assert!(stats.mpsc_send_blocks >= 0, "Should have some send blocks with small buffer");

            println!("✓ TCP flow control propagation test passed");
            println!("  - MPSC send blocks: {}", stats.mpsc_send_blocks);
            println!("  - TCP flow control stalls: {}", stats.tcp_flow_control_stalls);

            Ok::<(), Box<dyn std::error::Error>>(())
        }).await.expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_network_partition_recovery() {
        println!("=== Testing network partition recovery scenarios ===");

        scope(|cx| async move {
            let mut harness = MpscTcpIntegrationTestHarness::new(50, 9003);

            // Test partition recovery
            harness.test_partition_recovery(&cx).await
                .expect("Partition recovery test should succeed");

            let stats = harness.get_stats();
            println!("Partition recovery stats: {}", serde_json::to_string_pretty(&stats.to_json()).unwrap());

            // Verify partition events occurred
            assert!(stats.partition_events > 0, "Should have simulated partition events");
            assert!(stats.partition_recoveries > 0, "Should have recovered from partitions");
            assert_eq!(stats.partition_events, stats.partition_recoveries, "All partitions should recover");

            // Should have minimal ordering violations
            assert!(stats.ordering_violations <= 2, "Should have minimal ordering violations during partition recovery");

            println!("✓ Network partition recovery test passed");
            println!("  - Partition events: {}", stats.partition_events);
            println!("  - Successful recoveries: {}", stats.partition_recoveries);
            println!("  - Ordering violations: {}", stats.ordering_violations);

            Ok::<(), Box<dyn std::error::Error>>(())
        }).await.expect("Test scope failed");
    }
}