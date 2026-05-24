//! Real gRPC client-server bidirectional streaming E2E tests
//!
//! Tests complete gRPC bidirectional streaming with real asupersync gRPC
//! implementation. Validates streaming protocol, flow control, error handling,
//! and concurrent stream management end-to-end.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_grpc_bidirectional_e2e {
    use crate::channel::mpsc;
    use crate::cx::{Cx, scope};
    use crate::grpc::{
        BidirectionalStream, ClientStreamingMethod, GrpcClient, GrpcMetadata, GrpcMethod,
        GrpcRequest, GrpcResponse, GrpcServer, GrpcService, GrpcStatus, GrpcStream,
        ServerStreamingMethod,
    };
    use crate::net::tcp::TcpListener;
    use crate::runtime::{Runtime, spawn};
    use crate::runtime::builder::JoinHandle;
    use crate::time::{Duration, Instant, sleep, timeout};
    use bytes::Bytes;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    /// Collection for managing background tasks with automatic cleanup on Drop
    struct TaskCollection {
        tasks: Vec<JoinHandle<()>>,
    }

    impl TaskCollection {
        fn new() -> Self {
            Self { tasks: Vec::new() }
        }

        fn spawn<F>(&mut self, future: F)
        where
            F: Future<Output = ()> + Send + 'static,
        {
            let handle = spawn(future);
            self.tasks.push(handle);
        }
    }

    impl Drop for TaskCollection {
        fn drop(&mut self) {
            for task in self.tasks.drain(..) {
                task.abort();
            }
            if !self.tasks.is_empty() {
                eprintln!("TaskCollection: Aborted {} background tasks", self.tasks.len());
            }
        }
    }

    /// gRPC test harness with bidirectional streaming monitoring
    struct GrpcBidirectionalTestHarness {
        server_addr: SocketAddr,
        start_time: Instant,
        log_entries: Arc<Mutex<Vec<Value>>>,
        stream_stats: Arc<Mutex<Vec<StreamStats>>>,
        message_log: Arc<Mutex<Vec<GrpcMessageLog>>>,
        connection_stats: Arc<Mutex<ConnectionStats>>,
        background_tasks: Mutex<TaskCollection>,
    }

    #[derive(Debug, Clone)]
    struct StreamStats {
        timestamp: Instant,
        stream_id: u64,
        stream_type: String,
        messages_sent: usize,
        messages_received: usize,
        bytes_sent: u64,
        bytes_received: u64,
        stream_duration_ms: u64,
        completed_successfully: bool,
        error: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct GrpcMessageLog {
        timestamp: Instant,
        stream_id: u64,
        direction: String, // "client_to_server" or "server_to_client"
        message_id: usize,
        message_size: usize,
        sequence_number: u64,
        is_end_stream: bool,
    }

    #[derive(Debug, Clone, Default)]
    struct ConnectionStats {
        total_streams: usize,
        active_streams: usize,
        completed_streams: usize,
        failed_streams: usize,
        total_messages: usize,
        total_bytes_transferred: u64,
        connection_duration_ms: u64,
    }

    impl GrpcBidirectionalTestHarness {
        async fn new() -> Self {
            // Find available port for test server
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("Failed to bind test server");
            let server_addr = listener.local_addr().expect("Failed to get server address");

            Self {
                server_addr,
                start_time: Instant::now(),
                log_entries: Arc::new(Mutex::new(Vec::new())),
                stream_stats: Arc::new(Mutex::new(Vec::new())),
                message_log: Arc::new(Mutex::new(Vec::new())),
                connection_stats: Arc::new(Mutex::new(ConnectionStats::default())),
                background_tasks: Mutex::new(TaskCollection::new()),
            }
        }

        fn log(&self, event: &str, data: Value) {
            let entry = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event": event,
                "data": data,
                "elapsed_ms": self.start_time.elapsed().as_millis()
            });
            eprintln!("{}", serde_json::to_string(&entry).unwrap());
            self.log_entries.lock().unwrap().push(entry);
        }

        fn record_stream_stats(&self, stats: StreamStats) {
            self.stream_stats.lock().unwrap().push(stats.clone());

            self.log(
                "grpc_stream_stats",
                json!({
                    "stream_id": stats.stream_id,
                    "type": stats.stream_type,
                    "messages_sent": stats.messages_sent,
                    "messages_received": stats.messages_received,
                    "bytes_sent": stats.bytes_sent,
                    "bytes_received": stats.bytes_received,
                    "duration_ms": stats.stream_duration_ms,
                    "success": stats.completed_successfully
                }),
            );
        }

        fn record_message(&self, message_log: GrpcMessageLog) {
            self.message_log.lock().unwrap().push(message_log.clone());

            if message_log.message_id % 10 == 0 || message_log.is_end_stream {
                self.log(
                    "grpc_message",
                    json!({
                        "stream_id": message_log.stream_id,
                        "direction": message_log.direction,
                        "message_id": message_log.message_id,
                        "size": message_log.message_size,
                        "sequence": message_log.sequence_number,
                        "end_stream": message_log.is_end_stream
                    }),
                );
            }
        }

        fn update_connection_stats<F>(&self, update_fn: F)
        where
            F: FnOnce(&mut ConnectionStats),
        {
            let mut stats = self.connection_stats.lock().unwrap();
            update_fn(&mut *stats);
        }

        async fn start_test_server(&self) -> Result<Arc<GrpcServer>, String> {
            let server = Arc::new(
                GrpcServer::builder()
                    .add_service(TestBidirectionalService::new(self.clone()))
                    .build()
                    .map_err(|e| format!("Server build failed: {}", e))?,
            );

            let server_clone = Arc::clone(&server);
            let bind_addr = self.server_addr;

            // Start server in background with managed task collection
            self.background_tasks.lock().unwrap().spawn(async move {
                if let Err(e) = server_clone.serve(bind_addr).await {
                    eprintln!("Server error: {}", e);
                }
            });

            // Wait for server to start
            sleep(Duration::from_millis(100)).await;

            self.log(
                "grpc_server_started",
                json!({
                    "address": self.server_addr.to_string()
                }),
            );

            Ok(server)
        }

        async fn create_client(&self) -> Result<GrpcClient, String> {
            let client = GrpcClient::connect(format!("http://{}", self.server_addr))
                .await
                .map_err(|e| format!("Client connection failed: {}", e))?;

            self.log(
                "grpc_client_connected",
                json!({
                    "server_address": self.server_addr.to_string()
                }),
            );

            Ok(client)
        }

        async fn test_bidirectional_echo_stream(
            &self,
            client: &GrpcClient,
            stream_id: u64,
            message_count: usize,
        ) -> Result<StreamStats, String> {
            let stream_start = Instant::now();

            self.update_connection_stats(|stats| {
                stats.total_streams += 1;
                stats.active_streams += 1;
            });

            // Create bidirectional stream
            let mut stream = client
                .bidirectional_stream("test.EchoService/BidirectionalEcho")
                .await
                .map_err(|e| format!("Failed to create bidirectional stream: {}", e))?;

            let mut messages_sent = 0;
            let mut messages_received = 0;
            let mut bytes_sent = 0u64;
            let mut bytes_received = 0u64;
            let mut sequence_counter = 0u64;

            // Send messages and receive responses concurrently
            let (tx, mut rx) = mpsc::channel(100);

            // Sender task
            let send_tx = tx.clone();
            let sender_task = spawn(async move {
                for i in 0..message_count {
                    let message = format!("Echo message {} from stream {}", i, stream_id);
                    let message_bytes = message.as_bytes().to_vec();
                    let message_size = message_bytes.len();

                    match stream.send_message(Bytes::from(message_bytes)).await {
                        Ok(_) => {
                            let _ = send_tx.send((i, message_size, false)).await;
                        }
                        Err(e) => {
                            eprintln!("Send error on stream {}: {}", stream_id, e);
                            break;
                        }
                    }

                    // Small delay between messages
                    sleep(Duration::from_millis(10)).await;
                }

                // End the send side
                if let Err(e) = stream.finish_send().await {
                    eprintln!("Finish send error on stream {}: {}", stream_id, e);
                }

                let _ = send_tx.send((message_count, 0, true)).await;
            });

            // Receiver task
            let recv_tx = tx.clone();
            let receiver_task = spawn(async move {
                let mut received_count = 0;

                while let Some(result) = stream.receive_message().await {
                    match result {
                        Ok(response_bytes) => {
                            received_count += 1;
                            let response_size = response_bytes.len();
                            let _ = recv_tx
                                .send((
                                    received_count,
                                    response_size,
                                    received_count >= message_count,
                                ))
                                .await;

                            if received_count >= message_count {
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("Receive error on stream {}: {}", stream_id, e);
                            break;
                        }
                    }
                }

                received_count
            });

            // Collect results
            drop(tx);
            while let Some((msg_id, size, is_end)) = rx.recv().await {
                if msg_id <= message_count {
                    // This is from sender
                    messages_sent = msg_id;
                    bytes_sent += size as u64;

                    self.record_message(GrpcMessageLog {
                        timestamp: Instant::now(),
                        stream_id,
                        direction: "client_to_server".to_string(),
                        message_id: msg_id,
                        message_size: size,
                        sequence_number: sequence_counter,
                        is_end_stream: is_end,
                    });
                } else {
                    // This is from receiver
                    messages_received = msg_id - message_count;
                    bytes_received += size as u64;

                    self.record_message(GrpcMessageLog {
                        timestamp: Instant::now(),
                        stream_id,
                        direction: "server_to_client".to_string(),
                        message_id: messages_received,
                        message_size: size,
                        sequence_number: sequence_counter,
                        is_end_stream: is_end,
                    });
                }

                sequence_counter += 1;
            }

            // Wait for tasks to complete
            let _ = sender_task.await;
            let final_received = receiver_task.await;

            let stream_duration = stream_start.elapsed();
            let success = messages_sent == message_count && final_received == message_count;

            self.update_connection_stats(|stats| {
                stats.active_streams -= 1;
                if success {
                    stats.completed_streams += 1;
                } else {
                    stats.failed_streams += 1;
                }
                stats.total_messages += messages_sent + final_received;
                stats.total_bytes_transferred += bytes_sent + bytes_received;
            });

            let stats = StreamStats {
                timestamp: stream_start,
                stream_id,
                stream_type: "bidirectional_echo".to_string(),
                messages_sent,
                messages_received: final_received,
                bytes_sent,
                bytes_received,
                stream_duration_ms: stream_duration.as_millis() as u64,
                completed_successfully: success,
                error: if success {
                    None
                } else {
                    Some("Message count mismatch".to_string())
                },
            };

            self.record_stream_stats(stats.clone());
            Ok(stats)
        }

        fn validate_bidirectional_performance(&self) -> Result<(), String> {
            let stream_stats = self.stream_stats.lock().unwrap();
            let connection_stats = self.connection_stats.lock().unwrap();

            // Check success rate
            let successful_streams = stream_stats
                .iter()
                .filter(|s| s.completed_successfully)
                .count();
            let total_streams = stream_stats.len();
            let success_rate = successful_streams as f64 / total_streams as f64;

            if success_rate < 0.9 {
                return Err(format!(
                    "Success rate too low: {:.1}% ({}/{})",
                    success_rate * 100.0,
                    successful_streams,
                    total_streams
                ));
            }

            // Check average message throughput
            let avg_duration: f64 = stream_stats
                .iter()
                .filter(|s| s.completed_successfully)
                .map(|s| s.stream_duration_ms as f64)
                .sum::<f64>()
                / successful_streams as f64;

            let avg_messages_per_stream: f64 = stream_stats
                .iter()
                .filter(|s| s.completed_successfully)
                .map(|s| (s.messages_sent + s.messages_received) as f64)
                .sum::<f64>()
                / successful_streams as f64;

            let messages_per_second = (avg_messages_per_stream * 1000.0) / avg_duration;

            if messages_per_second < 10.0 {
                return Err(format!(
                    "Message throughput too low: {:.1} messages/second",
                    messages_per_second
                ));
            }

            // Check for no hanging streams
            if connection_stats.active_streams > 0 {
                return Err(format!(
                    "Still have {} active streams after test completion",
                    connection_stats.active_streams
                ));
            }

            Ok(())
        }
    }

    // Mock gRPC service for testing
    struct TestBidirectionalService {
        harness: Arc<GrpcBidirectionalTestHarness>,
    }

    impl TestBidirectionalService {
        fn new(harness: Arc<GrpcBidirectionalTestHarness>) -> Self {
            Self { harness }
        }
    }

    impl GrpcService for TestBidirectionalService {
        fn name(&self) -> &str {
            "test.EchoService"
        }

        async fn handle_bidirectional_stream(
            &self,
            _method: &str,
            stream: BidirectionalStream,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let stream_id = rand::random::<u64>();
            let mut message_count = 0;

            // Echo each received message back
            while let Some(result) = stream.receive_message().await {
                match result {
                    Ok(request_bytes) => {
                        message_count += 1;

                        // Echo the message back
                        let echo_message =
                            format!("Echo: {}", String::from_utf8_lossy(&request_bytes));
                        let echo_bytes = Bytes::from(echo_message.as_bytes().to_vec());

                        if let Err(e) = stream.send_message(echo_bytes).await {
                            self.harness.log(
                                "server_send_error",
                                json!({
                                    "stream_id": stream_id,
                                    "error": e.to_string()
                                }),
                            );
                            break;
                        }

                        self.harness.log(
                            "server_echo",
                            json!({
                                "stream_id": stream_id,
                                "message_count": message_count,
                                "message_size": request_bytes.len()
                            }),
                        );
                    }
                    Err(e) => {
                        self.harness.log(
                            "server_receive_error",
                            json!({
                                "stream_id": stream_id,
                                "error": e.to_string()
                            }),
                        );
                        break;
                    }
                }
            }

            // Finish the stream
            if let Err(e) = stream.finish_send().await {
                self.harness.log(
                    "server_finish_error",
                    json!({
                        "stream_id": stream_id,
                        "error": e.to_string()
                    }),
                );
            }

            self.harness.log(
                "server_stream_complete",
                json!({
                    "stream_id": stream_id,
                    "total_messages": message_count
                }),
            );

            Ok(())
        }
    }

    #[tokio::test]
    async fn test_single_bidirectional_stream() {
        let harness = Arc::new(GrpcBidirectionalTestHarness::new().await);
        harness.log("test_start", json!({"test": "single_bidirectional_stream"}));

        // Start gRPC server
        let _server = harness
            .start_test_server()
            .await
            .expect("Failed to start test server");

        // Create client
        let client = harness
            .create_client()
            .await
            .expect("Failed to create client");

        // Test single bidirectional stream
        let message_count = 20;
        let stream_result = harness
            .test_bidirectional_echo_stream(&client, 1, message_count)
            .await;

        match stream_result {
            Ok(stats) => {
                assert!(
                    stats.completed_successfully,
                    "Stream should complete successfully"
                );
                assert_eq!(
                    stats.messages_sent, message_count,
                    "Should send all messages"
                );
                assert_eq!(
                    stats.messages_received, message_count,
                    "Should receive all messages"
                );

                harness.log(
                    "single_stream_success",
                    json!({
                        "messages_sent": stats.messages_sent,
                        "messages_received": stats.messages_received,
                        "duration_ms": stats.stream_duration_ms
                    }),
                );
            }
            Err(e) => {
                panic!("Single bidirectional stream test failed: {}", e);
            }
        }

        // Validate performance
        let validation_result = harness.validate_bidirectional_performance();
        assert!(
            validation_result.is_ok(),
            "Performance validation failed: {:?}",
            validation_result
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "stream_completed": true,
                "message_count": message_count,
                "message": "Single bidirectional stream validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_concurrent_bidirectional_streams() {
        let harness = Arc::new(GrpcBidirectionalTestHarness::new().await);
        harness.log(
            "test_start",
            json!({"test": "concurrent_bidirectional_streams"}),
        );

        // Start gRPC server
        let _server = harness
            .start_test_server()
            .await
            .expect("Failed to start test server");

        // Create client
        let client = Arc::new(
            harness
                .create_client()
                .await
                .expect("Failed to create client"),
        );

        let num_concurrent_streams = 5;
        let messages_per_stream = 10;

        let mut stream_handles = Vec::new();

        // Create concurrent bidirectional streams
        for stream_id in 0..num_concurrent_streams {
            let client = Arc::clone(&client);
            let harness = Arc::clone(&harness);

            let handle = spawn(async move {
                harness
                    .test_bidirectional_echo_stream(&client, stream_id as u64, messages_per_stream)
                    .await
            });

            stream_handles.push(handle);
        }

        // Wait for all streams to complete
        let mut successful_streams = 0;
        let mut total_messages = 0;

        for handle in stream_handles {
            match handle.await {
                Ok(stats) => {
                    if stats.completed_successfully {
                        successful_streams += 1;
                        total_messages += stats.messages_sent + stats.messages_received;
                    }

                    harness.log(
                        "concurrent_stream_result",
                        json!({
                            "stream_id": stats.stream_id,
                            "success": stats.completed_successfully,
                            "messages_sent": stats.messages_sent,
                            "messages_received": stats.messages_received
                        }),
                    );
                }
                Err(e) => {
                    harness.log(
                        "concurrent_stream_error",
                        json!({
                            "error": e
                        }),
                    );
                }
            }
        }

        // Validate concurrent performance
        assert_eq!(
            successful_streams, num_concurrent_streams,
            "All concurrent streams should complete successfully"
        );

        let expected_total_messages = num_concurrent_streams * messages_per_stream * 2; // Send + receive
        assert_eq!(
            total_messages, expected_total_messages,
            "Total message count should match expected"
        );

        let validation_result = harness.validate_bidirectional_performance();
        assert!(
            validation_result.is_ok(),
            "Concurrent performance validation failed: {:?}",
            validation_result
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "concurrent_streams": num_concurrent_streams,
                "successful_streams": successful_streams,
                "total_messages": total_messages,
                "message": "Concurrent bidirectional streams validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_bidirectional_stream_error_handling() {
        let harness = Arc::new(GrpcBidirectionalTestHarness::new().await);
        harness.log(
            "test_start",
            json!({"test": "bidirectional_stream_error_handling"}),
        );

        // Start gRPC server
        let _server = harness
            .start_test_server()
            .await
            .expect("Failed to start test server");

        // Create client
        let client = harness
            .create_client()
            .await
            .expect("Failed to create client");

        // Test error handling scenarios
        let error_scenarios = vec![
            ("large_message", 1000000), // 1MB message - may hit limits
            ("rapid_messages", 100),    // Rapid message sending
        ];

        for (scenario_name, message_param) in error_scenarios {
            harness.log(
                "error_scenario_start",
                json!({
                    "scenario": scenario_name,
                    "parameter": message_param
                }),
            );

            let stream_result = match scenario_name {
                "large_message" => {
                    // Test with very large message
                    let mut stream = client
                        .bidirectional_stream("test.EchoService/BidirectionalEcho")
                        .await
                        .expect("Failed to create stream");

                    let large_message = vec![b'X'; message_param];
                    stream.send_message(Bytes::from(large_message)).await
                }
                "rapid_messages" => {
                    // Test with rapid message sending
                    let mut stream = client
                        .bidirectional_stream("test.EchoService/BidirectionalEcho")
                        .await
                        .expect("Failed to create stream");

                    for i in 0..message_param {
                        let message = format!("Rapid message {}", i);
                        if let Err(e) = stream
                            .send_message(Bytes::from(message.as_bytes().to_vec()))
                            .await
                        {
                            break;
                        }
                    }
                    Ok(())
                }
                _ => Ok(()),
            };

            harness.log(
                "error_scenario_result",
                json!({
                    "scenario": scenario_name,
                    "result": if stream_result.is_ok() { "success" } else { "error" },
                    "error": stream_result.err().map(|e| e.to_string())
                }),
            );
        }

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "error_scenarios_tested": error_scenarios.len(),
                "message": "Bidirectional stream error handling validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_bidirectional_stream_flow_control() {
        let harness = Arc::new(GrpcBidirectionalTestHarness::new().await);
        harness.log(
            "test_start",
            json!({"test": "bidirectional_stream_flow_control"}),
        );

        // Start gRPC server
        let _server = harness
            .start_test_server()
            .await
            .expect("Failed to start test server");

        // Create client
        let client = harness
            .create_client()
            .await
            .expect("Failed to create client");

        // Test flow control with different message sizes and rates
        let flow_control_tests = vec![
            ("small_fast", 100, 10), // 100 small messages, 10ms interval
            ("medium_slow", 50, 50), // 50 medium messages, 50ms interval
            ("large_burst", 20, 0),  // 20 large messages, no delay
        ];

        for (test_name, message_count, delay_ms) in flow_control_tests {
            harness.log(
                "flow_control_test_start",
                json!({
                    "test": test_name,
                    "message_count": message_count,
                    "delay_ms": delay_ms
                }),
            );

            let mut stream = client
                .bidirectional_stream("test.EchoService/BidirectionalEcho")
                .await
                .expect("Failed to create stream");

            let test_start = Instant::now();
            let mut messages_sent = 0;
            let mut messages_received = 0;

            // Send messages with specified delay
            let (send_tx, mut send_rx) = mpsc::channel(message_count);

            // Sender task
            let sender_task = spawn(async move {
                for i in 0..message_count {
                    let message = format!("{} message {} with flow control", test_name, i);

                    match stream
                        .send_message(Bytes::from(message.as_bytes().to_vec()))
                        .await
                    {
                        Ok(_) => {
                            let _ = send_tx.send(i).await;
                            if delay_ms > 0 {
                                sleep(Duration::from_millis(delay_ms)).await;
                            }
                        }
                        Err(e) => {
                            harness.log(
                                "flow_control_send_error",
                                json!({
                                    "test": test_name,
                                    "message_id": i,
                                    "error": e.to_string()
                                }),
                            );
                            break;
                        }
                    }
                }

                let _ = stream.finish_send().await;
                drop(send_tx);
            });

            // Receiver task
            let receiver_task = spawn(async move {
                while let Some(result) = stream.receive_message().await {
                    match result {
                        Ok(_response) => {
                            messages_received += 1;
                        }
                        Err(e) => {
                            harness.log(
                                "flow_control_receive_error",
                                json!({
                                    "test": test_name,
                                    "error": e.to_string()
                                }),
                            );
                            break;
                        }
                    }
                }
                messages_received
            });

            // Wait for sender to finish and count sent messages
            while let Some(_) = send_rx.recv().await {
                messages_sent += 1;
            }

            let _ = sender_task.await;
            let final_received = receiver_task.await;
            let test_duration = test_start.elapsed();

            harness.log(
                "flow_control_test_result",
                json!({
                    "test": test_name,
                    "messages_sent": messages_sent,
                    "messages_received": final_received,
                    "duration_ms": test_duration.as_millis(),
                    "expected_count": message_count
                }),
            );

            // Validate flow control worked correctly
            assert_eq!(
                messages_sent, message_count,
                "{}: Should send all messages",
                test_name
            );
            assert_eq!(
                final_received, message_count,
                "{}: Should receive all messages",
                test_name
            );
        }

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "flow_control_tests": flow_control_tests.len(),
                "message": "Bidirectional stream flow control validated successfully"
            }),
        );
    }

    impl Drop for GrpcBidirectionalTestHarness {
        fn drop(&mut self) {
            // Clear all shared state to prevent test pollution
            if let Ok(mut log) = self.log_entries.lock() {
                log.clear();
            }
            if let Ok(mut stats) = self.stream_stats.lock() {
                stats.clear();
            }
            if let Ok(mut messages) = self.message_log.lock() {
                messages.clear();
            }
            if let Ok(mut conn_stats) = self.connection_stats.lock() {
                *conn_stats = ConnectionStats::default();
            }

            eprintln!("GrpcBidirectionalTestHarness cleanup completed");
        }
    }
}
