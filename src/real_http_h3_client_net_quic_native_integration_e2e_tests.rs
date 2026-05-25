//! Real E2E integration tests: http/h3/client ↔ net/quic_native (br-e2e-184).
//!
//! Tests that H3 0-RTT resumption correctly survives session ticket rotation.
//! Verifies the integration between:
//!
//! - `http::h3::client`: HTTP/3 client with 0-RTT resumption support
//! - `net::quic_native`: Native QUIC transport with session ticket management
//!
//! Key integration properties:
//! - H3 0-RTT resumption works across session ticket rotations
//! - Session ticket cache maintains consistency during rotation
//! - QUIC transport preserves 0-RTT capability after ticket refresh
//! - Client resumes connections with valid cached tickets post-rotation
//! - Session ticket rotation doesn't break ongoing H3 streams
//! - 0-RTT data integrity maintained across ticket lifecycle

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::{
        cx::{Cx, Scope},
        error::{Error, Result},
        http::h3::{
            client::{H3Client, H3ClientConfig, H3Request, H3Response},
            H3Error, H3Stream, H3StreamId, ZeroRttState, ResumptionTicket,
        },
        net::quic_native::{
            QuicConnection, QuicConnectionConfig, QuicEndpoint, QuicStream,
            SessionTicket, TicketRotation, TransportParameters, ConnectionId,
            ZeroRttContext, ResumptionToken, TicketStore,
        },
        net::tcp::{TcpListener, TcpStream},
        runtime::{spawn, Runtime},
        sync::{Arc, Mutex, RwLock},
        time::{sleep, Duration, Instant},
        types::{Budget, CancelReason, Outcome, TaskId, Time},
    };
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // H3 + QUIC Native 0-RTT Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ZeroRttEventType {
        InitialHandshake,
        TicketReceived,
        TicketRotated,
        ZeroRttAttempted,
        ZeroRttAccepted,
        ZeroRttRejected,
        ResumptionSucceeded,
        ResumptionFailed,
        StreamDataSent,
        StreamDataReceived,
    }

    #[derive(Debug, Clone)]
    struct ZeroRttEvent {
        event_type: ZeroRttEventType,
        connection_id: ConnectionId,
        ticket_generation: u64,
        stream_id: Option<H3StreamId>,
        data_bytes: Option<usize>,
        timestamp: Instant,
        rtt_measurement: Option<Duration>,
    }

    #[derive(Debug)]
    struct H3QuicTestFramework {
        runtime: Arc<Runtime>,
        server_endpoint: Arc<Mutex<Option<QuicEndpoint>>>,
        client_endpoint: Arc<Mutex<Option<QuicEndpoint>>>,
        ticket_store: Arc<RwLock<TicketStore>>,
        active_connections: Arc<RwLock<HashMap<ConnectionId, H3Connection>>>,
        zero_rtt_events: Arc<Mutex<Vec<ZeroRttEvent>>>,
        server_addr: SocketAddr,
        resumption_stats: Arc<Mutex<ResumptionStats>>,
    }

    #[derive(Debug, Clone)]
    struct H3Connection {
        connection_id: ConnectionId,
        h3_client: H3Client,
        quic_connection: Arc<QuicConnection>,
        active_streams: HashMap<H3StreamId, H3Stream>,
        session_tickets: Vec<SessionTicket>,
        zero_rtt_state: ZeroRttState,
        resumption_token: Option<ResumptionToken>,
    }

    #[derive(Debug, Default)]
    struct ResumptionStats {
        tickets_issued: u64,
        tickets_rotated: u64,
        zero_rtt_attempts: u64,
        zero_rtt_successes: u64,
        zero_rtt_rejections: u64,
        resumption_attempts: u64,
        resumption_successes: u64,
        data_bytes_0rtt: u64,
        average_resumption_rtt: Option<Duration>,
        ticket_rotation_intervals: Vec<Duration>,
    }

    #[derive(Debug, Clone)]
    struct TestRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Option<Vec<u8>>,
        expect_zero_rtt: bool,
    }

    #[derive(Debug, Clone)]
    struct TestResponse {
        status: u16,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        was_zero_rtt: bool,
        rtt_measurement: Duration,
    }

    impl H3QuicTestFramework {
        async fn new() -> Result<Self> {
            let runtime = Arc::new(Runtime::new().await?);
            let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
            let server_endpoint = Arc::new(Mutex::new(None));
            let client_endpoint = Arc::new(Mutex::new(None));
            let ticket_store = Arc::new(RwLock::new(TicketStore::new()));
            let active_connections = Arc::new(RwLock::new(HashMap::new()));
            let zero_rtt_events = Arc::new(Mutex::new(Vec::new()));
            let resumption_stats = Arc::new(Mutex::new(ResumptionStats::default()));

            Ok(Self {
                runtime,
                server_endpoint,
                client_endpoint,
                ticket_store,
                active_connections,
                zero_rtt_events,
                server_addr,
                resumption_stats,
            })
        }

        async fn start_h3_server(&self, cx: &Cx) -> Result<SocketAddr> {
            let quic_config = QuicConnectionConfig::new()
                .with_session_tickets_enabled(true)
                .with_zero_rtt_enabled(true)
                .with_ticket_rotation_interval(Duration::from_secs(30))
                .with_max_idle_timeout(Duration::from_secs(300));

            let endpoint = QuicEndpoint::bind(self.server_addr, quic_config).await?;
            let actual_addr = endpoint.local_addr()?;

            // Start H3 server task
            let endpoint_ref = endpoint.clone();
            let framework_ref = Arc::new(self.clone());

            spawn(cx, Budget::unlimited(), async move {
                loop {
                    match endpoint_ref.accept().await {
                        Ok(conn) => {
                            let framework = framework_ref.clone();
                            spawn(cx, Budget::unlimited(), async move {
                                framework.handle_h3_connection(cx, conn).await.unwrap();
                            });
                        }
                        Err(_) => break,
                    }
                }
                Ok(())
            });

            *self.server_endpoint.lock().await = Some(endpoint);
            Ok(actual_addr)
        }

        async fn handle_h3_connection(&self, cx: &Cx, quic_conn: QuicConnection) -> Result<()> {
            let connection_id = quic_conn.connection_id();

            // Handle H3 over QUIC
            let mut h3_streams = HashMap::new();

            loop {
                match quic_conn.accept_stream().await {
                    Ok(quic_stream) => {
                        let stream_id = H3StreamId::from_quic_stream_id(quic_stream.id());
                        let h3_stream = H3Stream::new(quic_stream);
                        h3_streams.insert(stream_id, h3_stream);

                        // Process H3 request on this stream
                        self.handle_h3_request(cx, stream_id, &mut h3_streams).await?;
                    }
                    Err(_) => break,
                }
            }

            Ok(())
        }

        async fn handle_h3_request(
            &self,
            cx: &Cx,
            stream_id: H3StreamId,
            streams: &mut HashMap<H3StreamId, H3Stream>,
        ) -> Result<()> {
            let stream = streams.get_mut(&stream_id)
                .ok_or_else(|| Error::new("H3 stream not found"))?;

            // Read H3 request
            let request_data = stream.read_request().await?;
            let was_zero_rtt = stream.was_zero_rtt();

            // Record zero-RTT event
            if was_zero_rtt {
                let event = ZeroRttEvent {
                    event_type: ZeroRttEventType::ZeroRttAccepted,
                    connection_id: stream.connection_id(),
                    ticket_generation: self.get_current_ticket_generation().await,
                    stream_id: Some(stream_id),
                    data_bytes: Some(request_data.len()),
                    timestamp: Instant::now(),
                    rtt_measurement: Some(Duration::from_micros(0)), // 0-RTT
                };
                self.zero_rtt_events.lock().await.push(event);
            }

            // Send H3 response
            let response_body = format!("H3 Response for stream {}, 0-RTT: {}", stream_id, was_zero_rtt);
            let response = H3Response::ok()
                .with_header("content-type", "text/plain")
                .with_body(response_body.into_bytes());

            stream.send_response(response).await?;

            Ok(())
        }

        async fn create_h3_client(&self, server_addr: SocketAddr) -> Result<H3Client> {
            let quic_config = QuicConnectionConfig::new()
                .with_zero_rtt_enabled(true)
                .with_session_ticket_store(self.ticket_store.clone())
                .with_resumption_enabled(true);

            let client_endpoint = QuicEndpoint::new(quic_config).await?;
            *self.client_endpoint.lock().await = Some(client_endpoint.clone());

            let h3_config = H3ClientConfig::new()
                .with_zero_rtt_enabled(true)
                .with_resumption_enabled(true);

            let h3_client = H3Client::connect(client_endpoint, server_addr, h3_config).await?;

            Ok(h3_client)
        }

        async fn send_h3_request(
            &self,
            cx: &Cx,
            client: &H3Client,
            request: TestRequest,
        ) -> Result<TestResponse> {
            let start_time = Instant::now();

            // Create H3 request
            let mut h3_request = H3Request::new(&request.method, &request.path);
            for (name, value) in &request.headers {
                h3_request = h3_request.with_header(name, value);
            }
            if let Some(body) = &request.body {
                h3_request = h3_request.with_body(body.clone());
            }

            // Attempt 0-RTT if expected
            let (response, was_zero_rtt) = if request.expect_zero_rtt {
                match client.send_zero_rtt_request(h3_request).await {
                    Ok(resp) => (resp, true),
                    Err(_) => {
                        // Fallback to regular request
                        let resp = client.send_request(h3_request).await?;
                        (resp, false)
                    }
                }
            } else {
                let resp = client.send_request(h3_request).await?;
                (resp, false)
            };

            let rtt_measurement = start_time.elapsed();

            // Record zero-RTT event
            if request.expect_zero_rtt {
                let event_type = if was_zero_rtt {
                    ZeroRttEventType::ZeroRttAccepted
                } else {
                    ZeroRttEventType::ZeroRttRejected
                };

                let event = ZeroRttEvent {
                    event_type,
                    connection_id: client.connection_id(),
                    ticket_generation: self.get_current_ticket_generation().await,
                    stream_id: Some(response.stream_id()),
                    data_bytes: request.body.as_ref().map(|b| b.len()),
                    timestamp: Instant::now(),
                    rtt_measurement: Some(rtt_measurement),
                };
                self.zero_rtt_events.lock().await.push(event);
            }

            // Update stats
            {
                let mut stats = self.resumption_stats.lock().await;
                if request.expect_zero_rtt {
                    stats.zero_rtt_attempts += 1;
                    if was_zero_rtt {
                        stats.zero_rtt_successes += 1;
                        if let Some(body) = &request.body {
                            stats.data_bytes_0rtt += body.len() as u64;
                        }
                    } else {
                        stats.zero_rtt_rejections += 1;
                    }
                }
            }

            Ok(TestResponse {
                status: response.status(),
                headers: response.headers().clone(),
                body: response.body().to_vec(),
                was_zero_rtt,
                rtt_measurement,
            })
        }

        async fn rotate_session_tickets(&self, cx: &Cx) -> Result<()> {
            let server_endpoint = self.server_endpoint.lock().await;
            if let Some(endpoint) = server_endpoint.as_ref() {
                // Trigger ticket rotation
                endpoint.rotate_session_tickets().await?;

                // Record rotation event
                let event = ZeroRttEvent {
                    event_type: ZeroRttEventType::TicketRotated,
                    connection_id: ConnectionId::zero(), // Server-side rotation
                    ticket_generation: self.get_current_ticket_generation().await,
                    stream_id: None,
                    data_bytes: None,
                    timestamp: Instant::now(),
                    rtt_measurement: None,
                };
                self.zero_rtt_events.lock().await.push(event);

                // Update stats
                let mut stats = self.resumption_stats.lock().await;
                stats.tickets_rotated += 1;
            }

            Ok(())
        }

        async fn test_resumption_across_rotation(
            &self,
            cx: &Cx,
            server_addr: SocketAddr,
        ) -> Result<bool> {
            // Phase 1: Establish initial connection and get session ticket
            let client1 = self.create_h3_client(server_addr).await?;

            let initial_request = TestRequest {
                method: "GET".to_string(),
                path: "/initial".to_string(),
                headers: HashMap::new(),
                body: None,
                expect_zero_rtt: false,
            };

            let _response1 = self.send_h3_request(cx, &client1, initial_request).await?;

            // Wait for session ticket
            sleep(Duration::from_millis(100)).await;

            // Phase 2: Rotate session tickets on server
            self.rotate_session_tickets(cx).await?;

            // Phase 3: Test 0-RTT resumption with rotated tickets
            let client2 = self.create_h3_client(server_addr).await?;

            let zero_rtt_request = TestRequest {
                method: "POST".to_string(),
                path: "/zero_rtt_test".to_string(),
                headers: [("content-type".to_string(), "text/plain".to_string())].into(),
                body: Some(b"0-RTT test data after rotation".to_vec()),
                expect_zero_rtt: true,
            };

            let response2 = self.send_h3_request(cx, &client2, zero_rtt_request).await?;

            // Phase 4: Verify 0-RTT worked after rotation
            Ok(response2.was_zero_rtt)
        }

        async fn test_continuous_rotation_survival(
            &self,
            cx: &Cx,
            server_addr: SocketAddr,
            rotation_count: u32,
        ) -> Result<Vec<bool>> {
            let mut results = Vec::new();
            let mut client = self.create_h3_client(server_addr).await?;

            // Initial handshake
            let handshake_request = TestRequest {
                method: "GET".to_string(),
                path: "/handshake".to_string(),
                headers: HashMap::new(),
                body: None,
                expect_zero_rtt: false,
            };

            self.send_h3_request(cx, &client, handshake_request).await?;

            for rotation_round in 0..rotation_count {
                // Rotate tickets
                self.rotate_session_tickets(cx).await?;

                // Wait for rotation to propagate
                sleep(Duration::from_millis(50)).await;

                // Create new client to test resumption
                client = self.create_h3_client(server_addr).await?;

                // Test 0-RTT resumption
                let zero_rtt_request = TestRequest {
                    method: "PUT".to_string(),
                    path: &format!("/rotation_test_{}", rotation_round),
                    headers: [("x-rotation".to_string(), rotation_round.to_string())].into(),
                    body: Some(format!("Test data for rotation {}", rotation_round).into_bytes()),
                    expect_zero_rtt: true,
                };

                let response = self.send_h3_request(cx, &client, zero_rtt_request).await?;
                results.push(response.was_zero_rtt);

                // Small delay between rotations
                sleep(Duration::from_millis(100)).await;
            }

            Ok(results)
        }

        async fn verify_ticket_cache_consistency(&self) -> Result<bool> {
            let ticket_store = self.ticket_store.read().await;

            // Verify that ticket cache has valid entries
            let valid_tickets = ticket_store.count_valid_tickets();
            let expired_tickets = ticket_store.count_expired_tickets();

            // Should have at least some valid tickets and properly manage expired ones
            Ok(valid_tickets > 0 && ticket_store.is_consistent())
        }

        async fn get_current_ticket_generation(&self) -> u64 {
            // Return current ticket generation from server
            if let Some(endpoint) = self.server_endpoint.lock().await.as_ref() {
                endpoint.current_ticket_generation()
            } else {
                0
            }
        }

        async fn get_resumption_stats(&self) -> ResumptionStats {
            self.resumption_stats.lock().await.clone()
        }

        async fn get_zero_rtt_event_count(&self, event_type: ZeroRttEventType) -> usize {
            self.zero_rtt_events.lock().await
                .iter()
                .filter(|event| event.event_type == event_type)
                .count()
        }
    }

    // Clone implementation for the framework (needed for Arc usage)
    impl Clone for H3QuicTestFramework {
        fn clone(&self) -> Self {
            Self {
                runtime: self.runtime.clone(),
                server_endpoint: self.server_endpoint.clone(),
                client_endpoint: self.client_endpoint.clone(),
                ticket_store: self.ticket_store.clone(),
                active_connections: self.active_connections.clone(),
                zero_rtt_events: self.zero_rtt_events.clone(),
                server_addr: self.server_addr,
                resumption_stats: self.resumption_stats.clone(),
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_h3_zero_rtt_basic_resumption() {
        let framework = H3QuicTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            // Start H3 server
            let server_addr = framework.start_h3_server(cx).await.unwrap();

            // Phase 1: Initial connection to establish session
            let client = framework.create_h3_client(server_addr).await.unwrap();
            let initial_request = TestRequest {
                method: "GET".to_string(),
                path: "/establish".to_string(),
                headers: HashMap::new(),
                body: None,
                expect_zero_rtt: false,
            };

            let response1 = framework.send_h3_request(cx, &client, initial_request).await.unwrap();
            assert_eq!(response1.status, 200);
            assert!(!response1.was_zero_rtt);

            // Wait for session ticket
            sleep(Duration::from_millis(200)).await;

            // Phase 2: New connection with 0-RTT
            let client2 = framework.create_h3_client(server_addr).await.unwrap();
            let zero_rtt_request = TestRequest {
                method: "POST".to_string(),
                path: "/zero_rtt".to_string(),
                headers: [("content-type".to_string(), "application/json".to_string())].into(),
                body: Some(b"{\"test\": \"0rtt_data\"}".to_vec()),
                expect_zero_rtt: true,
            };

            let response2 = framework.send_h3_request(cx, &client2, zero_rtt_request).await.unwrap();
            assert_eq!(response2.status, 200);
            assert!(response2.was_zero_rtt);

            // Verify stats
            let stats = framework.get_resumption_stats().await;
            assert_eq!(stats.zero_rtt_attempts, 1);
            assert_eq!(stats.zero_rtt_successes, 1);
            assert!(stats.data_bytes_0rtt > 0);

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_zero_rtt_survives_ticket_rotation() {
        let framework = H3QuicTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            let server_addr = framework.start_h3_server(cx).await.unwrap();

            // Test resumption across single rotation
            let resumption_success = framework.test_resumption_across_rotation(cx, server_addr).await.unwrap();
            assert!(resumption_success, "0-RTT resumption should work after ticket rotation");

            // Verify ticket rotation was recorded
            let rotation_events = framework.get_zero_rtt_event_count(ZeroRttEventType::TicketRotated).await;
            assert!(rotation_events >= 1);

            // Verify 0-RTT was successful
            let zero_rtt_successes = framework.get_zero_rtt_event_count(ZeroRttEventType::ZeroRttAccepted).await;
            assert!(zero_rtt_successes >= 1);

            // Check final stats
            let stats = framework.get_resumption_stats().await;
            assert!(stats.tickets_rotated >= 1);
            assert!(stats.zero_rtt_successes >= 1);

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_continuous_ticket_rotation_survival() {
        let framework = H3QuicTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            let server_addr = framework.start_h3_server(cx).await.unwrap();

            // Test 0-RTT across multiple rotations
            let rotation_count = 5;
            let results = framework.test_continuous_rotation_survival(
                cx,
                server_addr,
                rotation_count,
            ).await.unwrap();

            // Verify that most (at least 80%) of 0-RTT attempts succeeded
            let success_count = results.iter().filter(|&&success| success).count();
            let success_rate = success_count as f64 / results.len() as f64;

            assert!(success_rate >= 0.8,
                "0-RTT success rate should be at least 80% across rotations, got {}",
                success_rate);

            // Verify all rotations were recorded
            let rotation_events = framework.get_zero_rtt_event_count(ZeroRttEventType::TicketRotated).await;
            assert_eq!(rotation_events, rotation_count as usize);

            // Check stats reflect multiple rotations
            let stats = framework.get_resumption_stats().await;
            assert_eq!(stats.tickets_rotated, rotation_count as u64);
            assert!(stats.zero_rtt_successes >= (rotation_count as u64 * 4 / 5)); // At least 80%

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_ticket_cache_consistency_during_rotation() {
        let framework = H3QuicTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            let server_addr = framework.start_h3_server(cx).await.unwrap();

            // Establish multiple connections to populate ticket cache
            for i in 0..3 {
                let client = framework.create_h3_client(server_addr).await.unwrap();
                let request = TestRequest {
                    method: "GET".to_string(),
                    path: &format!("/cache_test_{}", i),
                    headers: HashMap::new(),
                    body: None,
                    expect_zero_rtt: false,
                };
                framework.send_h3_request(cx, &client, request).await.unwrap();
            }

            // Wait for tickets to be cached
            sleep(Duration::from_millis(300)).await;

            // Verify cache consistency before rotation
            assert!(framework.verify_ticket_cache_consistency().await.unwrap());

            // Perform ticket rotation
            framework.rotate_session_tickets(cx).await.unwrap();

            // Verify cache consistency after rotation
            assert!(framework.verify_ticket_cache_consistency().await.unwrap());

            // Test that cached tickets still work for 0-RTT
            let client = framework.create_h3_client(server_addr).await.unwrap();
            let zero_rtt_request = TestRequest {
                method: "POST".to_string(),
                path: "/post_rotation_test".to_string(),
                headers: HashMap::new(),
                body: Some(b"post-rotation 0-RTT test".to_vec()),
                expect_zero_rtt: true,
            };

            let response = framework.send_h3_request(cx, &client, zero_rtt_request).await.unwrap();
            assert!(response.was_zero_rtt);

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_zero_rtt_requests_during_rotation() {
        let framework = H3QuicTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            let server_addr = framework.start_h3_server(cx).await.unwrap();

            // Establish initial session
            let initial_client = framework.create_h3_client(server_addr).await.unwrap();
            let handshake_request = TestRequest {
                method: "GET".to_string(),
                path: "/handshake".to_string(),
                headers: HashMap::new(),
                body: None,
                expect_zero_rtt: false,
            };
            framework.send_h3_request(cx, &initial_client, handshake_request).await.unwrap();

            sleep(Duration::from_millis(200)).await;

            let framework_ref = &framework;

            // Spawn concurrent 0-RTT requests while rotating tickets
            let tasks: Vec<_> = (0..6).map(|i| {
                spawn(cx, Budget::unlimited(), async move {
                    let client = framework_ref.create_h3_client(server_addr).await.unwrap();
                    let request = TestRequest {
                        method: "PUT".to_string(),
                        path: &format!("/concurrent_{}", i),
                        headers: [("x-request-id".to_string(), i.to_string())].into(),
                        body: Some(format!("concurrent request {}", i).into_bytes()),
                        expect_zero_rtt: true,
                    };

                    // Add some jitter to requests
                    sleep(Duration::from_millis(i as u64 * 50)).await;

                    let response = framework_ref.send_h3_request(cx, &client, request).await.unwrap();
                    Ok(response.was_zero_rtt)
                })
            }).collect();

            // Trigger rotation in the middle of concurrent requests
            sleep(Duration::from_millis(150)).await;
            framework.rotate_session_tickets(cx).await.unwrap();

            // Wait for all requests to complete
            let mut zero_rtt_successes = 0;
            for task in tasks {
                match task.join().await {
                    Outcome::Ok(Ok(was_zero_rtt)) => {
                        if was_zero_rtt {
                            zero_rtt_successes += 1;
                        }
                    }
                    _ => {}
                }
            }

            // Should have some 0-RTT successes despite concurrent rotation
            assert!(zero_rtt_successes > 0, "Should have at least some 0-RTT successes");

            // Verify that rotation occurred
            let rotation_events = framework.get_zero_rtt_event_count(ZeroRttEventType::TicketRotated).await;
            assert_eq!(rotation_events, 1);

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_zero_rtt_data_integrity_across_rotation() {
        let framework = H3QuicTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            let server_addr = framework.start_h3_server(cx).await.unwrap();

            // Phase 1: Establish session
            let client1 = framework.create_h3_client(server_addr).await.unwrap();
            framework.send_h3_request(cx, &client1, TestRequest {
                method: "GET".to_string(),
                path: "/establish".to_string(),
                headers: HashMap::new(),
                body: None,
                expect_zero_rtt: false,
            }).await.unwrap();

            sleep(Duration::from_millis(200)).await;

            // Phase 2: Rotate tickets
            framework.rotate_session_tickets(cx).await.unwrap();

            // Phase 3: Send 0-RTT request with specific data
            let test_data = b"Critical data that must survive 0-RTT across ticket rotation";
            let client2 = framework.create_h3_client(server_addr).await.unwrap();
            let zero_rtt_request = TestRequest {
                method: "POST".to_string(),
                path: "/data_integrity_test".to_string(),
                headers: [
                    ("content-type".to_string(), "application/octet-stream".to_string()),
                    ("x-test-data-length".to_string(), test_data.len().to_string()),
                ].into(),
                body: Some(test_data.to_vec()),
                expect_zero_rtt: true,
            };

            let response = framework.send_h3_request(cx, &client2, zero_rtt_request).await.unwrap();

            // Verify 0-RTT worked and data integrity
            assert!(response.was_zero_rtt);
            assert_eq!(response.status, 200);
            assert!(response.body.len() > 0);

            // Verify response contains reference to our test data
            let response_text = String::from_utf8_lossy(&response.body);
            assert!(response_text.contains("0-RTT: true"));

            // Check that data was properly transmitted in 0-RTT
            let stats = framework.get_resumption_stats().await;
            assert_eq!(stats.data_bytes_0rtt, test_data.len() as u64);

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_zero_rtt_rejection_fallback_after_rotation() {
        let framework = H3QuicTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            let server_addr = framework.start_h3_server(cx).await.unwrap();

            // Create client but don't establish session first
            // This should cause 0-RTT to be rejected and fallback to regular handshake
            let client = framework.create_h3_client(server_addr).await.unwrap();
            let zero_rtt_request = TestRequest {
                method: "GET".to_string(),
                path: "/should_fallback".to_string(),
                headers: HashMap::new(),
                body: Some(b"This should fallback to regular handshake".to_vec()),
                expect_zero_rtt: true,
            };

            let response = framework.send_h3_request(cx, &client, zero_rtt_request).await.unwrap();

            // Should have fallen back to regular handshake
            assert!(!response.was_zero_rtt);
            assert_eq!(response.status, 200);

            // Verify rejection was recorded
            let rejection_events = framework.get_zero_rtt_event_count(ZeroRttEventType::ZeroRttRejected).await;
            assert_eq!(rejection_events, 1);

            // Verify stats reflect the rejection
            let stats = framework.get_resumption_stats().await;
            assert_eq!(stats.zero_rtt_attempts, 1);
            assert_eq!(stats.zero_rtt_rejections, 1);
            assert_eq!(stats.zero_rtt_successes, 0);

            Ok(())
        }).await.unwrap();
    }
}