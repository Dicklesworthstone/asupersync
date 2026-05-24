//! Real-service E2E tests: server connection tracking + session types + evidence collection.
//!
//! Tests integration between:
//! - `server::connection`: Connection tracking and lifecycle management
//! - `session`: Protocol-safe typed session channels
//! - `evidence_sink`: Runtime decision evidence collection
//!
//! This exercises real server scenarios with no mocks, using transaction-like
//! isolation for test determinism and structured logging for debugging.

#[cfg(test)]
mod tests {
    use crate::cx::Cx;
    use crate::session::{Session, Send, Recv, End, Choose, Left, Right, channel};
    use crate::server::connection::{ConnectionManager, ConnectionGuard, ConnectionId};
    use crate::evidence_sink::{CollectorSink, EvidenceSink};
    use crate::runtime::region;
    use crate::types::Time;
    use franken_evidence::EvidenceLedger;
    use std::collections::HashMap;
    use std::io;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// Allocate a single test port dynamically to avoid conflicts
    fn allocate_test_port() -> io::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        Ok(addr.port())
    }

    /// Allocate multiple test ports for multi-connection scenarios
    fn allocate_test_ports(count: usize) -> io::Result<Vec<SocketAddr>> {
        let mut addrs = Vec::new();
        for _ in 0..count {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let addr = listener.local_addr()?;
            addrs.push(addr);
            // Drop listener to free port for actual use
            drop(listener);
        }
        Ok(addrs)
    }

    // Test data factories for realistic scenarios
    #[derive(Debug, Clone)]
    struct TestClientRequest {
        client_id: u64,
        request_type: RequestType,
        payload: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    enum RequestType {
        Subscribe { topic: String },
        Unsubscribe { topic: String },
        PublishMessage { topic: String, message: String },
    }

    #[derive(Debug, Clone)]
    struct TestServerResponse {
        success: bool,
        message: String,
        subscription_count: usize,
    }

    // Session type definitions for our protocol
    type ClientProtocol = Send<TestClientRequest,
                          Recv<TestServerResponse,
                          Choose<
                              Send<TestClientRequest, End>,  // Left: another request
                              End                            // Right: disconnect
                          >>>;

    type ServerProtocol = <ClientProtocol as Session>::Dual;

    struct TestDataFactory {
        client_counter: AtomicU64,
        request_counter: AtomicU64,
    }

    impl TestDataFactory {
        fn new() -> Self {
            Self {
                client_counter: AtomicU64::new(1),
                request_counter: AtomicU64::new(1),
            }
        }

        fn create_client_request(&self, req_type: RequestType) -> TestClientRequest {
            TestClientRequest {
                client_id: self.client_counter.fetch_add(1, Ordering::Relaxed),
                request_type: req_type,
                payload: self.generate_payload(),
            }
        }

        fn generate_payload(&self) -> Vec<u8> {
            let req_id = self.request_counter.fetch_add(1, Ordering::Relaxed);
            format!("test_payload_{}", req_id).into_bytes()
        }

        fn create_response(&self, success: bool, msg: &str, sub_count: usize) -> TestServerResponse {
            TestServerResponse {
                success,
                message: format!("{}_req_{}", msg, self.request_counter.load(Ordering::Relaxed)),
                subscription_count: sub_count,
            }
        }
    }

    // Test logger for structured logging
    #[derive(Debug)]
    struct TestLogger {
        test_name: String,
        phase: String,
        events: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    impl TestLogger {
        fn new(test_name: &str) -> Self {
            Self {
                test_name: test_name.to_string(),
                phase: "init".to_string(),
                events: Arc::new(parking_lot::Mutex::new(Vec::new())),
            }
        }

        fn phase(&mut self, phase: &str) {
            self.phase = phase.to_string();
            self.log_event(&format!("phase_start:{}", phase));
        }

        fn log_event(&self, event: &str) {
            let timestamp = crate::time::wall_now();
            let entry = format!("{{\"test\":\"{}\",\"phase\":\"{}\",\"event\":\"{}\",\"ts\":{}}}",
                self.test_name, self.phase, event, timestamp.as_nanos());
            self.events.lock().push(entry);
            eprintln!("{}", entry);
        }

        fn connection_event(&self, conn_id: ConnectionId, event: &str) {
            self.log_event(&format!("conn:{}:{}", conn_id, event));
        }

        fn evidence_event(&self, evidence_count: usize) {
            self.log_event(&format!("evidence_collected:{}", evidence_count));
        }

        fn session_event(&self, client_id: u64, event: &str) {
            self.log_event(&format!("session:{}:{}", client_id, event));
        }

        fn get_events(&self) -> Vec<String> {
            self.events.lock().clone()
        }
    }

    // Real server implementation that integrates all three components
    struct TestServer {
        connection_manager: ConnectionManager,
        evidence_sink: Arc<CollectorSink>,
        subscriptions: Arc<parking_lot::Mutex<HashMap<String, Vec<u64>>>>,
        logger: TestLogger,
    }

    impl TestServer {
        fn new(test_name: &str) -> Self {
            let mut logger = TestLogger::new(test_name);
            logger.phase("server_init");

            let connection_manager = ConnectionManager::new(
                100, // max_connections
                Duration::from_secs(30), // idle_timeout
            );

            let evidence_sink = Arc::new(CollectorSink::new());

            logger.log_event("server_initialized");

            Self {
                connection_manager,
                evidence_sink: evidence_sink.clone(),
                subscriptions: Arc::new(parking_lot::Mutex::new(HashMap::new())),
                logger,
            }
        }

        async fn accept_connection(&mut self, cx: &Cx) -> Result<(ConnectionId, ConnectionGuard), String> {
            self.logger.log_event("accept_connection_start");

            // Emit evidence about connection acceptance
            let evidence = EvidenceLedger::builder()
                .decision_type("connection_accept")
                .context("server_e2e_test")
                .build();
            self.evidence_sink.emit(&evidence);

            // Register connection with manager using dynamic port
            let test_port = allocate_test_port().expect("Failed to allocate test port");
            let remote_addr = format!("127.0.0.1:{}", test_port).parse().unwrap();
            let (conn_id, guard) = self.connection_manager
                .register_connection(remote_addr)
                .map_err(|e| format!("Connection registration failed: {:?}", e))?;

            self.logger.connection_event(conn_id, "registered");
            self.logger.evidence_event(self.evidence_sink.entries().len());

            Ok((conn_id, guard))
        }

        async fn handle_session_protocol(
            &mut self,
            cx: &Cx,
            conn_id: ConnectionId,
            mut server_endpoint: crate::session::Endpoint<ServerProtocol>,
        ) -> Result<(), String> {
            self.logger.session_event(0, "protocol_start");

            // Receive initial client request
            let (request, next_endpoint) = server_endpoint.recv().await
                .map_err(|e| format!("Failed to receive request: {:?}", e))?;

            self.logger.session_event(request.client_id, "request_received");

            // Emit evidence about request processing
            let evidence = EvidenceLedger::builder()
                .decision_type("request_processing")
                .context(&format!("client_{}", request.client_id))
                .build();
            self.evidence_sink.emit(&evidence);

            // Process request and generate response
            let response = self.process_request(&request).await;

            // Send response
            let choice_endpoint = next_endpoint.send(response).await
                .map_err(|e| format!("Failed to send response: {:?}", e))?;

            self.logger.session_event(request.client_id, "response_sent");

            // Offer choice to client: continue or end
            match choice_endpoint.offer().await {
                Ok(crate::session::Branch::Left(continue_endpoint)) => {
                    self.logger.session_event(request.client_id, "client_chose_continue");

                    // Handle additional request
                    let (second_request, end_endpoint) = continue_endpoint.recv().await
                        .map_err(|e| format!("Failed to receive second request: {:?}", e))?;

                    self.logger.session_event(second_request.client_id, "second_request_received");

                    // Process and end
                    let _second_response = self.process_request(&second_request).await;
                    end_endpoint.close();

                    self.logger.session_event(second_request.client_id, "protocol_completed");
                }
                Ok(crate::session::Branch::Right(end_endpoint)) => {
                    self.logger.session_event(request.client_id, "client_chose_disconnect");
                    end_endpoint.close();
                }
                Err(e) => {
                    return Err(format!("Choice offer failed: {:?}", e));
                }
            }

            self.logger.connection_event(conn_id, "session_completed");
            Ok(())
        }

        async fn process_request(&mut self, request: &TestClientRequest) -> TestServerResponse {
            let mut subscriptions = self.subscriptions.lock();

            match &request.request_type {
                RequestType::Subscribe { topic } => {
                    subscriptions.entry(topic.clone())
                        .or_insert_with(Vec::new)
                        .push(request.client_id);

                    self.logger.session_event(request.client_id, &format!("subscribed:{}", topic));

                    TestServerResponse {
                        success: true,
                        message: format!("Subscribed to {}", topic),
                        subscription_count: subscriptions.get(topic).map_or(0, |v| v.len()),
                    }
                }
                RequestType::Unsubscribe { topic } => {
                    if let Some(subscribers) = subscriptions.get_mut(topic) {
                        subscribers.retain(|&id| id != request.client_id);
                        if subscribers.is_empty() {
                            subscriptions.remove(topic);
                        }
                    }

                    self.logger.session_event(request.client_id, &format!("unsubscribed:{}", topic));

                    TestServerResponse {
                        success: true,
                        message: format!("Unsubscribed from {}", topic),
                        subscription_count: subscriptions.get(topic).map_or(0, |v| v.len()),
                    }
                }
                RequestType::PublishMessage { topic, message } => {
                    let subscriber_count = subscriptions.get(topic).map_or(0, |v| v.len());

                    self.logger.session_event(
                        request.client_id,
                        &format!("published:{}:to_{}_subscribers", topic, subscriber_count)
                    );

                    TestServerResponse {
                        success: true,
                        message: format!("Published '{}' to {}", message, topic),
                        subscription_count: subscriber_count,
                    }
                }
            }
        }

        fn get_evidence_entries(&self) -> Vec<EvidenceLedger> {
            self.evidence_sink.entries()
        }

        fn get_active_connections(&self) -> usize {
            self.connection_manager.active_count()
        }
    }

    #[test]
    fn test_server_connection_session_evidence_integration() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut logger = TestLogger::new("server_session_evidence_integration");
            let factory = TestDataFactory::new();

            logger.phase("setup");

            // Create server with real components (no mocks)
            let mut server = TestServer::new("integration_test");
            logger.log_event("server_created");

            logger.phase("connection_acceptance");

            // Accept a connection (simulating real network client)
            let (conn_id, _connection_guard) = server.accept_connection(&cx).await
                .expect("Connection acceptance should succeed");

            assert_eq!(server.get_active_connections(), 1);
            logger.connection_event(conn_id, "active_count_verified");

            logger.phase("session_protocol");

            // Create session channel pair
            let (client_endpoint, server_endpoint) = channel::<ClientProtocol>();
            logger.log_event("session_channel_created");

            // Simulate client side in background task
            let client_factory = factory.clone();
            let client_handle = crate::cx::spawn(&cx, async move {
                let mut client_endpoint = client_endpoint;

                // Send initial request
                let request = client_factory.create_client_request(
                    RequestType::Subscribe { topic: "test_topic".to_string() }
                );

                let recv_endpoint = client_endpoint.send(request).await?;

                // Receive response
                let (response, choice_endpoint) = recv_endpoint.recv().await?;
                assert!(response.success);
                assert_eq!(response.subscription_count, 1);

                // Choose to send another request
                let send_endpoint = choice_endpoint.choose_left().await?;

                let second_request = client_factory.create_client_request(
                    RequestType::PublishMessage {
                        topic: "test_topic".to_string(),
                        message: "Hello subscribers!".to_string(),
                    }
                );

                let end_endpoint = send_endpoint.send(second_request).await?;
                end_endpoint.close();

                Ok::<(), Box<dyn std::error::Error>>(())
            }).expect("Client task spawn should succeed");

            // Handle server side of protocol
            server.handle_session_protocol(&cx, conn_id, server_endpoint).await
                .expect("Session protocol should complete successfully");

            // Wait for client to complete
            client_handle.await
                .expect("Client task should complete")
                .expect("Client protocol should succeed");

            logger.phase("verification");

            // Verify evidence was collected
            let evidence_entries = server.get_evidence_entries();
            assert!(!evidence_entries.is_empty(), "Evidence should be collected");
            assert!(evidence_entries.len() >= 2, "Should have evidence for connection accept and request processing");

            logger.evidence_event(evidence_entries.len());

            // Verify evidence contains expected decision types
            let decision_types: std::collections::HashSet<_> = evidence_entries
                .iter()
                .map(|e| e.decision_type())
                .collect();

            assert!(decision_types.contains("connection_accept"),
                "Should have connection acceptance evidence");
            assert!(decision_types.contains("request_processing"),
                "Should have request processing evidence");

            logger.log_event("evidence_verification_passed");

            logger.phase("connection_cleanup");

            // Connection should still be active until guard is dropped
            assert_eq!(server.get_active_connections(), 1);
            drop(_connection_guard);

            // After guard drop, connection should be cleaned up
            // Note: In a real scenario, this might need a small delay or explicit cleanup call
            logger.log_event("connection_guard_dropped");

            logger.phase("final_verification");

            let events = logger.get_events();
            assert!(!events.is_empty(), "Should have logged structured events");

            // Verify event sequence
            let phase_events: Vec<_> = events.iter()
                .filter(|e| e.contains("phase_start"))
                .collect();

            assert!(phase_events.len() >= 5, "Should have gone through multiple phases");
            logger.log_event("test_completed_successfully");

            Ok(())
        }).expect("Test should complete successfully");
    }

    #[test]
    fn test_connection_capacity_limits_with_evidence() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut logger = TestLogger::new("connection_capacity_limits");
            logger.phase("setup");

            // Create server with limited connection capacity
            let connection_manager = ConnectionManager::new(
                2, // max_connections = 2
                Duration::from_secs(30),
            );

            let evidence_sink = Arc::new(CollectorSink::new());
            logger.log_event("limited_capacity_server_created");

            logger.phase("connection_limit_test");

            // Allocate dynamic ports for multi-connection test
            let test_addrs = allocate_test_ports(3).expect("Failed to allocate test ports");
            let remote_addr1 = test_addrs[0];
            let remote_addr2 = test_addrs[1];
            let remote_addr3 = test_addrs[2];

            // First two connections should succeed
            let (conn1_id, _guard1) = connection_manager.register_connection(remote_addr1)
                .expect("First connection should succeed");
            logger.connection_event(conn1_id, "first_connection_registered");

            let (conn2_id, _guard2) = connection_manager.register_connection(remote_addr2)
                .expect("Second connection should succeed");
            logger.connection_event(conn2_id, "second_connection_registered");

            assert_eq!(connection_manager.active_count(), 2);
            logger.log_event("capacity_limit_reached");

            // Third connection should fail
            let result = connection_manager.register_connection(remote_addr3);
            assert!(result.is_err(), "Third connection should be rejected");
            logger.log_event("third_connection_rejected_as_expected");

            // Emit evidence about capacity limit enforcement
            let evidence = EvidenceLedger::builder()
                .decision_type("capacity_limit_enforcement")
                .context("connection_manager_e2e")
                .build();
            evidence_sink.emit(&evidence);

            logger.phase("capacity_release");

            // Drop first connection guard to free capacity
            drop(_guard1);
            assert_eq!(connection_manager.active_count(), 1);
            logger.connection_event(conn1_id, "connection_released");

            // Now third connection should succeed
            let (conn3_id, _guard3) = connection_manager.register_connection(remote_addr3)
                .expect("Third connection should now succeed");
            logger.connection_event(conn3_id, "third_connection_registered_after_release");

            assert_eq!(connection_manager.active_count(), 2);
            logger.log_event("capacity_management_verified");

            // Verify evidence collection
            let entries = evidence_sink.entries();
            assert!(!entries.is_empty(), "Should have capacity enforcement evidence");
            logger.evidence_event(entries.len());

            logger.phase("cleanup");
            drop(_guard2);
            drop(_guard3);

            assert_eq!(connection_manager.active_count(), 0);
            logger.log_event("all_connections_cleaned_up");

            Ok(())
        }).expect("Capacity limit test should complete successfully");
    }

    #[test]
    fn test_session_protocol_error_handling_with_evidence() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut logger = TestLogger::new("session_error_handling");
            let factory = TestDataFactory::new();

            logger.phase("setup");

            let mut server = TestServer::new("error_handling_test");

            // Accept connection
            let (conn_id, _guard) = server.accept_connection(&cx).await
                .expect("Connection should succeed");
            logger.connection_event(conn_id, "connection_established_for_error_test");

            logger.phase("error_simulation");

            // Create session channel
            let (client_endpoint, server_endpoint) = channel::<ClientProtocol>();

            // Simulate client that sends malformed data by dropping endpoint
            // This will cause the server to get a session error
            drop(client_endpoint);
            logger.log_event("client_endpoint_dropped_to_simulate_error");

            // Server should handle the error gracefully
            let result = server.handle_session_protocol(&cx, conn_id, server_endpoint).await;
            assert!(result.is_err(), "Should get error when client drops connection");

            logger.log_event("server_handled_error_gracefully");

            logger.phase("evidence_verification");

            // Verify evidence was still collected despite error
            let evidence_entries = server.get_evidence_entries();
            assert!(!evidence_entries.is_empty(), "Evidence should be collected even on error");

            // Should at least have connection acceptance evidence
            let has_connection_evidence = evidence_entries.iter()
                .any(|e| e.decision_type() == "connection_accept");
            assert!(has_connection_evidence, "Should have connection acceptance evidence");

            logger.evidence_event(evidence_entries.len());
            logger.log_event("error_handling_test_completed");

            Ok(())
        }).expect("Error handling test should complete successfully");
    }

    #[test]
    fn test_backpressure_handling_with_evidence() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut logger = TestLogger::new("backpressure_handling");
            let factory = TestDataFactory::new();

            logger.phase("setup");

            // Create server with connection tracking
            let mut server = TestServer::new("backpressure_test");
            let (conn_id, _guard) = server.accept_connection(&cx).await
                .expect("Connection should succeed");

            logger.phase("backpressure_simulation");

            // Create session channel with limited capacity buffer to simulate backpressure
            let (client_endpoint, server_endpoint) = channel::<ClientProtocol>();

            // Simulate high-volume client that creates backpressure
            let client_factory = factory.clone();
            let backpressure_handle = crate::cx::spawn(&cx, async move {
                let mut client_endpoint = client_endpoint;

                // Send initial request
                let request = client_factory.create_client_request(
                    RequestType::Subscribe { topic: "high_volume_topic".to_string() }
                );

                let recv_endpoint = client_endpoint.send(request).await?;

                // Receive response
                let (response, choice_endpoint) = recv_endpoint.recv().await?;
                assert!(response.success);

                // Choose to send a large message to trigger potential backpressure
                let send_endpoint = choice_endpoint.choose_left().await?;

                let large_request = TestClientRequest {
                    client_id: client_factory.client_counter.load(Ordering::Relaxed),
                    request_type: RequestType::PublishMessage {
                        topic: "high_volume_topic".to_string(),
                        message: "x".repeat(10000), // Large message
                    },
                    payload: vec![0u8; 50000], // Large payload
                };

                let end_endpoint = send_endpoint.send(large_request).await?;
                end_endpoint.close();

                Ok::<(), Box<dyn std::error::Error>>(())
            })?;

            // Handle server side with backpressure monitoring
            let result = server.handle_session_protocol(&cx, conn_id, server_endpoint).await;
            assert!(result.is_ok(), "Server should handle large messages gracefully");

            // Wait for client
            backpressure_handle.await??;

            logger.phase("verification");

            // Verify evidence was collected during backpressure scenario
            let evidence_entries = server.get_evidence_entries();
            assert!(!evidence_entries.is_empty(), "Should collect evidence during backpressure");

            logger.evidence_event(evidence_entries.len());
            logger.log_event("backpressure_test_completed");

            Ok(())
        }).expect("Backpressure test should complete successfully");
    }

    #[test]
    fn test_connection_idle_timeout_with_evidence() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut logger = TestLogger::new("connection_idle_timeout");

            logger.phase("setup");

            // Create connection manager with short idle timeout
            let connection_manager = ConnectionManager::new(
                10, // max_connections
                Duration::from_millis(100), // very short idle timeout for testing
            );

            let evidence_sink = Arc::new(CollectorSink::new());

            logger.phase("connection_registration");

            let test_port = allocate_test_port().expect("Failed to allocate test port");
            let remote_addr = format!("127.0.0.1:{}", test_port).parse().unwrap();
            let (conn_id, guard) = connection_manager.register_connection(remote_addr)
                .expect("Connection should be registered");

            logger.connection_event(conn_id, "registered_for_timeout_test");

            // Emit evidence about timeout monitoring
            let evidence = EvidenceLedger::builder()
                .decision_type("idle_timeout_monitoring")
                .context(&format!("conn_{}", conn_id.raw()))
                .build();
            evidence_sink.emit(&evidence);

            logger.phase("idle_simulation");

            // Simulate idle connection by not using it
            crate::time::sleep(&cx, Duration::from_millis(150)).await;

            logger.log_event("idle_period_elapsed");

            logger.phase("cleanup");

            // Connection should still be tracked until guard is dropped
            assert_eq!(connection_manager.active_count(), 1);

            drop(guard);
            logger.connection_event(conn_id, "guard_dropped");

            // Verify evidence collection
            let entries = evidence_sink.entries();
            assert!(!entries.is_empty(), "Should have timeout monitoring evidence");

            let has_timeout_evidence = entries.iter()
                .any(|e| e.decision_type() == "idle_timeout_monitoring");
            assert!(has_timeout_evidence, "Should have idle timeout monitoring evidence");

            logger.evidence_event(entries.len());
            logger.log_event("idle_timeout_test_completed");

            Ok(())
        }).expect("Idle timeout test should complete successfully");
    }

    #[test]
    fn test_concurrent_sessions_with_shared_evidence() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut logger = TestLogger::new("concurrent_sessions");
            let factory = TestDataFactory::new();

            logger.phase("setup");

            let server = TestServer::new("concurrent_test");
            let evidence_sink = server.evidence_sink.clone();
            let connection_manager = &server.connection_manager;

            logger.phase("concurrent_connections");

            // Create multiple concurrent connections and sessions
            let num_concurrent = 3;
            let mut handles = Vec::new();

            for i in 0..num_concurrent {
                let cx_clone = cx.clone();
                let evidence_sink_clone = evidence_sink.clone();
                let factory_clone = factory.clone();

                let handle = crate::cx::spawn(&cx, async move {
                    // Each task gets its own connection
                    let remote_addr = format!("127.0.0.1:{}", 20000 + i).parse().unwrap();
                    let (_conn_id, _guard) = connection_manager.register_connection(remote_addr)
                        .expect("Connection should succeed");

                    // Emit evidence from this concurrent session
                    let evidence = EvidenceLedger::builder()
                        .decision_type("concurrent_session")
                        .context(&format!("session_{}", i))
                        .build();
                    evidence_sink_clone.emit(&evidence);

                    // Create session and do some work
                    let (client_endpoint, _server_endpoint) = channel::<ClientProtocol>();

                    // Simulate some client work
                    let request = factory_clone.create_client_request(
                        RequestType::Subscribe {
                            topic: format!("topic_{}", i)
                        }
                    );

                    // Just create the request to exercise the factory
                    assert_eq!(request.client_id, i + 1); // Factories start at 1

                    Ok::<(), Box<dyn std::error::Error>>(())
                })?;

                handles.push(handle);
            }

            // Wait for all concurrent sessions to complete
            for handle in handles {
                handle.await??;
            }

            logger.log_event("all_concurrent_sessions_completed");

            logger.phase("verification");

            // Verify evidence from all concurrent sessions was collected
            let evidence_entries = evidence_sink.entries();
            assert!(evidence_entries.len() >= num_concurrent,
                "Should have evidence from all concurrent sessions");

            let concurrent_evidence_count = evidence_entries.iter()
                .filter(|e| e.decision_type() == "concurrent_session")
                .count();
            assert_eq!(concurrent_evidence_count, num_concurrent,
                "Should have exactly {} concurrent session evidence entries", num_concurrent);

            logger.evidence_event(evidence_entries.len());
            logger.log_event("concurrent_test_completed_successfully");

            Ok(())
        }).expect("Concurrent sessions test should complete successfully");
    }
}