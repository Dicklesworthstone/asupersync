//! Real HTTP/H2 server with concurrent client load E2E tests
//!
//! Tests HTTP/2 server under concurrent client load with response timing
//! validation under contention. Uses real asupersync HTTP/2 implementation
//! with comprehensive load testing and performance monitoring.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_http_h2_concurrent_load_e2e {
    use crate::channel::mpsc;
    use crate::cx::{Cx, scope};
    use crate::http::{
        H2Connection, H2Stream, HttpClient, HttpHeaders, HttpMethod, HttpRequest, HttpResponse,
        HttpServer, HttpStatus,
    };
    use crate::net::tcp::TcpListener;
    use crate::runtime::{Runtime, spawn};
    use crate::time::{Duration, Instant, sleep, timeout};
    use bytes::Bytes;
    use serde_json::{Value, json};
    use std::collections::{HashMap, VecDeque};
    use std::net::SocketAddr;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    /// HTTP/2 load test harness with concurrent client monitoring
    struct Http2LoadTestHarness {
        server_addr: SocketAddr,
        start_time: Instant,
        log_entries: Arc<Mutex<Vec<Value>>>,
        request_stats: Arc<Mutex<Vec<RequestStats>>>,
        connection_stats: Arc<Mutex<Vec<ConnectionStats>>>,
        load_metrics: Arc<Mutex<LoadMetrics>>,
        response_times: Arc<Mutex<Vec<Duration>>>,
    }

    #[derive(Debug, Clone)]
    struct RequestStats {
        timestamp: Instant,
        client_id: usize,
        request_id: usize,
        method: String,
        path: String,
        request_size: usize,
        response_size: usize,
        response_time_ms: u64,
        status_code: u16,
        success: bool,
        error: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct ConnectionStats {
        timestamp: Instant,
        connection_id: u64,
        client_id: usize,
        streams_created: usize,
        streams_completed: usize,
        bytes_sent: u64,
        bytes_received: u64,
        connection_duration_ms: u64,
        connection_successful: bool,
    }

    #[derive(Debug, Clone, Default)]
    struct LoadMetrics {
        concurrent_connections: usize,
        peak_concurrent_connections: usize,
        total_requests: usize,
        successful_requests: usize,
        failed_requests: usize,
        total_bytes_transferred: u64,
        avg_response_time_ms: f64,
        p95_response_time_ms: f64,
        p99_response_time_ms: f64,
        requests_per_second: f64,
    }

    impl Http2LoadTestHarness {
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
                request_stats: Arc::new(Mutex::new(Vec::new())),
                connection_stats: Arc::new(Mutex::new(Vec::new())),
                load_metrics: Arc::new(Mutex::new(LoadMetrics::default())),
                response_times: Arc::new(Mutex::new(Vec::new())),
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

        fn record_request_stats(&self, stats: RequestStats) {
            self.response_times
                .lock()
                .unwrap()
                .push(Duration::from_millis(stats.response_time_ms));
            self.request_stats.lock().unwrap().push(stats.clone());

            if stats.request_id % 50 == 0 || !stats.success {
                self.log(
                    "http2_request_stats",
                    json!({
                        "client_id": stats.client_id,
                        "request_id": stats.request_id,
                        "method": stats.method,
                        "path": stats.path,
                        "response_time_ms": stats.response_time_ms,
                        "status": stats.status_code,
                        "success": stats.success,
                        "request_size": stats.request_size,
                        "response_size": stats.response_size
                    }),
                );
            }
        }

        fn record_connection_stats(&self, stats: ConnectionStats) {
            self.connection_stats.lock().unwrap().push(stats.clone());

            self.log(
                "http2_connection_stats",
                json!({
                    "connection_id": stats.connection_id,
                    "client_id": stats.client_id,
                    "streams_created": stats.streams_created,
                    "streams_completed": stats.streams_completed,
                    "bytes_sent": stats.bytes_sent,
                    "bytes_received": stats.bytes_received,
                    "duration_ms": stats.connection_duration_ms,
                    "success": stats.connection_successful
                }),
            );
        }

        fn update_load_metrics(&self) {
            let request_stats = self.request_stats.lock().unwrap();
            let response_times = self.response_times.lock().unwrap();
            let mut load_metrics = self.load_metrics.lock().unwrap();

            load_metrics.total_requests = request_stats.len();
            load_metrics.successful_requests = request_stats.iter().filter(|r| r.success).count();
            load_metrics.failed_requests =
                load_metrics.total_requests - load_metrics.successful_requests;

            load_metrics.total_bytes_transferred = request_stats
                .iter()
                .map(|r| r.request_size as u64 + r.response_size as u64)
                .sum();

            if !response_times.is_empty() {
                let total_time: Duration = response_times.iter().sum();
                load_metrics.avg_response_time_ms =
                    total_time.as_millis() as f64 / response_times.len() as f64;

                let mut sorted_times = response_times.clone();
                sorted_times.sort();

                let p95_index = (sorted_times.len() as f64 * 0.95) as usize;
                let p99_index = (sorted_times.len() as f64 * 0.99) as usize;

                load_metrics.p95_response_time_ms = sorted_times
                    .get(p95_index)
                    .unwrap_or(&Duration::from_millis(0))
                    .as_millis() as f64;

                load_metrics.p99_response_time_ms = sorted_times
                    .get(p99_index)
                    .unwrap_or(&Duration::from_millis(0))
                    .as_millis() as f64;
            }

            let test_duration = self.start_time.elapsed().as_secs_f64();
            if test_duration > 0.0 {
                load_metrics.requests_per_second =
                    load_metrics.successful_requests as f64 / test_duration;
            }

            // Update connection metrics
            let connection_stats = self.connection_stats.lock().unwrap();
            load_metrics.concurrent_connections = connection_stats.len();
            load_metrics.peak_concurrent_connections = load_metrics
                .peak_concurrent_connections
                .max(load_metrics.concurrent_connections);
        }

        async fn start_test_server(&self) -> Result<Arc<HttpServer>, String> {
            let server = Arc::new(
                HttpServer::builder()
                    .bind(self.server_addr)
                    .http2_only(true)
                    .route("GET", "/health", |_req| async {
                        HttpResponse::builder()
                            .status(HttpStatus::OK)
                            .body(Bytes::from("healthy"))
                            .build()
                    })
                    .route("GET", "/echo/:id", |req| async move {
                        let id = req.path_param("id").unwrap_or("unknown");
                        let response_body = format!("Echo response for ID: {}", id);
                        HttpResponse::builder()
                            .status(HttpStatus::OK)
                            .body(Bytes::from(response_body))
                            .build()
                    })
                    .route("POST", "/data", |mut req| async move {
                        let body = req.body().await.unwrap_or_default();
                        let response_body = format!("Received {} bytes", body.len());
                        HttpResponse::builder()
                            .status(HttpStatus::OK)
                            .body(Bytes::from(response_body))
                            .build()
                    })
                    .route("GET", "/slow", |_req| async {
                        // Simulate slow response
                        sleep(Duration::from_millis(100)).await;
                        HttpResponse::builder()
                            .status(HttpStatus::OK)
                            .body(Bytes::from("slow response"))
                            .build()
                    })
                    .route("GET", "/large", |_req| async {
                        // Large response
                        let large_body = vec![b'X'; 10240]; // 10KB
                        HttpResponse::builder()
                            .status(HttpStatus::OK)
                            .body(Bytes::from(large_body))
                            .build()
                    })
                    .build()
                    .map_err(|e| format!("Server build failed: {}", e))?,
            );

            let server_clone = Arc::clone(&server);

            // Start server in background
            spawn(async move {
                if let Err(e) = server_clone.serve().await {
                    eprintln!("Server error: {}", e);
                }
            });

            // Wait for server to start
            sleep(Duration::from_millis(200)).await;

            self.log(
                "http2_server_started",
                json!({
                    "address": self.server_addr.to_string()
                }),
            );

            Ok(server)
        }

        async fn create_h2_client(&self, client_id: usize) -> Result<Arc<HttpClient>, String> {
            let client = Arc::new(
                HttpClient::builder()
                    .http2_prior_knowledge(true) // Force HTTP/2
                    .connect(format!("http://{}", self.server_addr))
                    .await
                    .map_err(|e| format!("Client {} connection failed: {}", client_id, e))?,
            );

            self.log(
                "http2_client_connected",
                json!({
                    "client_id": client_id,
                    "server_address": self.server_addr.to_string()
                }),
            );

            Ok(client)
        }

        async fn run_concurrent_load_test(
            &self,
            client: Arc<HttpClient>,
            client_id: usize,
            requests_per_client: usize,
        ) -> Result<ConnectionStats, String> {
            let connection_start = Instant::now();
            let connection_id = rand::random::<u64>();

            let mut successful_requests = 0;
            let mut total_bytes_sent = 0u64;
            let mut total_bytes_received = 0u64;
            let mut request_futures = Vec::new();

            // Create multiple concurrent requests on the same connection
            for request_id in 0..requests_per_client {
                let client = Arc::clone(&client);
                let harness = Arc::clone(&self);

                let request_future = spawn(async move {
                    let request_start = Instant::now();

                    // Vary request types for realistic load
                    let (method, path, body) = match request_id % 5 {
                        0 => (HttpMethod::GET, "/health".to_string(), None),
                        1 => (HttpMethod::GET, format!("/echo/{}", request_id), None),
                        2 => (
                            HttpMethod::POST,
                            "/data".to_string(),
                            Some(format!("test data {}", request_id).into_bytes()),
                        ),
                        3 => (HttpMethod::GET, "/slow".to_string(), None),
                        4 => (HttpMethod::GET, "/large".to_string(), None),
                        _ => unreachable!(),
                    };

                    let mut request_builder = HttpRequest::builder()
                        .method(method.clone())
                        .uri(path.clone());

                    let request_size = if let Some(ref body_data) = body {
                        request_builder = request_builder.body(Bytes::from(body_data.clone()));
                        body_data.len()
                    } else {
                        0
                    };

                    let request = request_builder
                        .build()
                        .map_err(|e| format!("Request build failed: {}", e))?;

                    // Send request
                    match client.send(request).await {
                        Ok(response) => {
                            let response_time = request_start.elapsed();
                            let status_code = response.status().as_u16();
                            let response_body = response.body().await.unwrap_or_default();
                            let response_size = response_body.len();

                            let stats = RequestStats {
                                timestamp: request_start,
                                client_id,
                                request_id,
                                method: format!("{:?}", method),
                                path,
                                request_size,
                                response_size,
                                response_time_ms: response_time.as_millis() as u64,
                                status_code,
                                success: status_code >= 200 && status_code < 300,
                                error: None,
                            };

                            harness.record_request_stats(stats);
                            Ok((request_size, response_size, true))
                        }
                        Err(e) => {
                            let response_time = request_start.elapsed();

                            let stats = RequestStats {
                                timestamp: request_start,
                                client_id,
                                request_id,
                                method: format!("{:?}", method),
                                path,
                                request_size,
                                response_size: 0,
                                response_time_ms: response_time.as_millis() as u64,
                                status_code: 0,
                                success: false,
                                error: Some(e.to_string()),
                            };

                            harness.record_request_stats(stats);
                            Ok((request_size, 0, false))
                        }
                    }
                });

                request_futures.push(request_future);
            }

            // Wait for all requests to complete
            for request_future in request_futures {
                match request_future.await {
                    Ok((req_size, resp_size, success)) => {
                        total_bytes_sent += req_size as u64;
                        total_bytes_received += resp_size as u64;
                        if success {
                            successful_requests += 1;
                        }
                    }
                    Err(_) => {
                        // Request failed
                    }
                }
            }

            let connection_duration = connection_start.elapsed();

            let connection_stats = ConnectionStats {
                timestamp: connection_start,
                connection_id,
                client_id,
                streams_created: requests_per_client,
                streams_completed: successful_requests,
                bytes_sent: total_bytes_sent,
                bytes_received: total_bytes_received,
                connection_duration_ms: connection_duration.as_millis() as u64,
                connection_successful: successful_requests > 0,
            };

            self.record_connection_stats(connection_stats.clone());
            Ok(connection_stats)
        }

        fn validate_load_performance(&self) -> Result<(), String> {
            self.update_load_metrics();
            let load_metrics = self.load_metrics.lock().unwrap();

            // Check success rate
            let success_rate =
                load_metrics.successful_requests as f64 / load_metrics.total_requests as f64;
            if success_rate < 0.95 {
                return Err(format!(
                    "Success rate too low: {:.1}% ({}/{})",
                    success_rate * 100.0,
                    load_metrics.successful_requests,
                    load_metrics.total_requests
                ));
            }

            // Check throughput
            if load_metrics.requests_per_second < 10.0 {
                return Err(format!(
                    "Request throughput too low: {:.1} req/sec",
                    load_metrics.requests_per_second
                ));
            }

            // Check response times under load
            if load_metrics.p95_response_time_ms > 1000.0 {
                return Err(format!(
                    "P95 response time too high: {:.1}ms",
                    load_metrics.p95_response_time_ms
                ));
            }

            if load_metrics.p99_response_time_ms > 2000.0 {
                return Err(format!(
                    "P99 response time too high: {:.1}ms",
                    load_metrics.p99_response_time_ms
                ));
            }

            // Check average response time
            if load_metrics.avg_response_time_ms > 500.0 {
                return Err(format!(
                    "Average response time too high: {:.1}ms",
                    load_metrics.avg_response_time_ms
                ));
            }

            Ok(())
        }

        fn generate_load_report(&self) -> Value {
            self.update_load_metrics();
            let load_metrics = self.load_metrics.lock().unwrap();

            json!({
                "summary": {
                    "total_requests": load_metrics.total_requests,
                    "successful_requests": load_metrics.successful_requests,
                    "failed_requests": load_metrics.failed_requests,
                    "success_rate_pct": (load_metrics.successful_requests as f64 / load_metrics.total_requests as f64) * 100.0,
                    "requests_per_second": load_metrics.requests_per_second
                },
                "response_times": {
                    "avg_ms": load_metrics.avg_response_time_ms,
                    "p95_ms": load_metrics.p95_response_time_ms,
                    "p99_ms": load_metrics.p99_response_time_ms
                },
                "connections": {
                    "concurrent_connections": load_metrics.concurrent_connections,
                    "peak_concurrent_connections": load_metrics.peak_concurrent_connections
                },
                "bandwidth": {
                    "total_bytes_transferred": load_metrics.total_bytes_transferred,
                    "avg_bytes_per_request": if load_metrics.total_requests > 0 {
                        load_metrics.total_bytes_transferred / load_metrics.total_requests as u64
                    } else { 0 }
                }
            })
        }
    }

    #[tokio::test]
    async fn test_http2_concurrent_client_load() {
        let harness = Arc::new(Http2LoadTestHarness::new().await);
        harness.log(
            "test_start",
            json!({"test": "http2_concurrent_client_load"}),
        );

        // Start HTTP/2 server
        let _server = harness
            .start_test_server()
            .await
            .expect("Failed to start test server");

        // Parameterized concurrency scenarios for comprehensive load testing
        #[derive(Debug, Clone)]
        struct ConcurrencyScenario {
            name: &'static str,
            num_clients: usize,
            requests_per_client: usize,
            expected_success_rate: f64,  // Expected minimum success rate
        }

        let concurrency_scenarios = vec![
            ConcurrencyScenario {
                name: "light_load",
                num_clients: 1,
                requests_per_client: 5,
                expected_success_rate: 1.0,  // 100% success expected
            },
            ConcurrencyScenario {
                name: "moderate_load",
                num_clients: 10,
                requests_per_client: 20,
                expected_success_rate: 0.95, // 95% success expected
            },
            ConcurrencyScenario {
                name: "heavy_load",
                num_clients: 25,
                requests_per_client: 50,
                expected_success_rate: 0.90, // 90% success expected
            },
        ];

        for scenario in concurrency_scenarios {
            println!("Testing HTTP/2 concurrency scenario: {} ({} clients × {} requests)",
                     scenario.name, scenario.num_clients, scenario.requests_per_client);
            let scenario_start = std::time::Instant::now();

            let total_expected_requests = scenario.num_clients * scenario.requests_per_client;
            let mut client_handles = Vec::new();

            // Create concurrent clients for this scenario
            for client_id in 0..scenario.num_clients {
                let harness = Arc::clone(&harness);
                let requests_for_client = scenario.requests_per_client;

                let handle = spawn(async move {
                    // Each client creates its own HTTP/2 connection
                    let client = harness.create_h2_client(client_id).await?;

                    // Run load test for this client
                    harness
                        .run_concurrent_load_test(client, client_id, requests_for_client)
                        .await
                });

                client_handles.push(handle);
            }

            // Wait for all clients to complete and collect scenario-specific results
            let mut scenario_successful_connections = 0;
            let mut scenario_completed_requests = 0;

            for handle in client_handles {
                match handle.await {
                    Ok(connection_stats) => {
                        if connection_stats.connection_successful {
                            scenario_successful_connections += 1;
                            scenario_completed_requests += connection_stats.streams_completed;
                        }

                        harness.log(
                            "client_load_result",
                            json!({
                                "scenario": scenario.name,
                                "client_id": connection_stats.client_id,
                                "connection_successful": connection_stats.connection_successful,
                                "streams_completed": connection_stats.streams_completed,
                                "bytes_sent": connection_stats.bytes_sent,
                                "bytes_received": connection_stats.bytes_received,
                                "duration_ms": connection_stats.connection_duration_ms
                            }),
                        );
                    }
                    Err(e) => {
                        harness.log(
                            "client_load_error",
                            json!({
                                "scenario": scenario.name,
                                "error": e
                            }),
                        );
                    }
                }
            }

            // Calculate scenario-specific success rate
            let actual_success_rate = if total_expected_requests > 0 {
                scenario_completed_requests as f64 / total_expected_requests as f64
            } else {
                0.0
            };

            let scenario_duration = scenario_start.elapsed().as_millis();

            // Validate scenario-specific performance expectations
            assert!(
                actual_success_rate >= scenario.expected_success_rate,
                "Scenario {}: Expected success rate >= {:.1}%, got {:.1}% ({}/{} requests)",
                scenario.name,
                scenario.expected_success_rate * 100.0,
                actual_success_rate * 100.0,
                scenario_completed_requests,
                total_expected_requests
            );

            println!(
                "✓ Scenario {} completed: {:.1}% success rate, {} ms total duration",
                scenario.name,
                actual_success_rate * 100.0,
                scenario_duration
            );

            harness.log(
                "scenario_summary",
                json!({
                    "scenario": scenario.name,
                    "clients": scenario.num_clients,
                    "requests_per_client": scenario.requests_per_client,
                    "successful_connections": scenario_successful_connections,
                    "completed_requests": scenario_completed_requests,
                    "total_expected_requests": total_expected_requests,
                    "success_rate": actual_success_rate,
                    "duration_ms": scenario_duration
                }),
            );
        }

        let performance_validation = harness.validate_load_performance();
        assert!(
            performance_validation.is_ok(),
            "Load performance validation failed: {:?}",
            performance_validation
        );

        // Generate load report
        let load_report = harness.generate_load_report();
        harness.log("load_test_report", load_report);

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "concurrent_clients": num_clients,
                "total_requests": total_expected_requests,
                "successful_connections": total_successful_connections,
                "completed_requests": total_completed_requests,
                "message": "HTTP/2 concurrent client load validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_http2_response_timing_under_contention() {
        let harness = Arc::new(Http2LoadTestHarness::new().await);
        harness.log(
            "test_start",
            json!({"test": "http2_response_timing_contention"}),
        );

        // Start HTTP/2 server
        let _server = harness
            .start_test_server()
            .await
            .expect("Failed to start test server");

        // Test different contention levels
        let contention_levels = vec![
            ("low_contention", 2, 10),    // 2 clients, 10 requests each
            ("medium_contention", 5, 15), // 5 clients, 15 requests each
            ("high_contention", 10, 25),  // 10 clients, 25 requests each
        ];

        for (test_name, num_clients, requests_per_client) in contention_levels {
            harness.log(
                "contention_test_start",
                json!({
                    "test": test_name,
                    "clients": num_clients,
                    "requests_per_client": requests_per_client
                }),
            );

            let test_start = Instant::now();
            let mut client_handles = Vec::new();

            // Create concurrent clients for this contention level
            for client_id in 0..num_clients {
                let harness = Arc::clone(&harness);

                let handle = spawn(async move {
                    let client = harness.create_h2_client(client_id).await?;
                    harness
                        .run_concurrent_load_test(client, client_id, requests_per_client)
                        .await
                });

                client_handles.push(handle);
            }

            // Wait for all clients to complete
            let mut successful_connections = 0;
            let mut total_requests = 0;

            for handle in client_handles {
                if let Ok(stats) = handle.await {
                    if stats.connection_successful {
                        successful_connections += 1;
                    }
                    total_requests += stats.streams_completed;
                }
            }

            let test_duration = test_start.elapsed();

            // Update and check metrics for this contention level
            harness.update_load_metrics();
            let load_metrics = harness.load_metrics.lock().unwrap();

            harness.log(
                "contention_test_result",
                json!({
                    "test": test_name,
                    "clients": num_clients,
                    "successful_connections": successful_connections,
                    "total_requests": total_requests,
                    "test_duration_ms": test_duration.as_millis(),
                    "avg_response_time_ms": load_metrics.avg_response_time_ms,
                    "p95_response_time_ms": load_metrics.p95_response_time_ms,
                    "requests_per_second": load_metrics.requests_per_second
                }),
            );

            // Validate response timing under this contention level
            assert!(
                load_metrics.avg_response_time_ms < 800.0,
                "{}: Average response time too high: {:.1}ms",
                test_name,
                load_metrics.avg_response_time_ms
            );

            assert!(
                load_metrics.p95_response_time_ms < 1500.0,
                "{}: P95 response time too high: {:.1}ms",
                test_name,
                load_metrics.p95_response_time_ms
            );

            assert!(
                load_metrics.requests_per_second > 5.0,
                "{}: Request rate too low: {:.1} req/sec",
                test_name,
                load_metrics.requests_per_second
            );
        }

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "contention_levels_tested": contention_levels.len(),
                "response_timing_validated": true,
                "message": "HTTP/2 response timing under contention validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_http2_connection_multiplexing() {
        let harness = Arc::new(Http2LoadTestHarness::new().await);
        harness.log(
            "test_start",
            json!({"test": "http2_connection_multiplexing"}),
        );

        // Start HTTP/2 server
        let _server = harness
            .start_test_server()
            .await
            .expect("Failed to start test server");

        // Test connection multiplexing with many streams per connection
        let num_connections = 3;
        let streams_per_connection = 50;

        let mut connection_handles = Vec::new();

        for connection_id in 0..num_connections {
            let harness = Arc::clone(&harness);

            let handle = spawn(async move {
                let client = harness.create_h2_client(connection_id).await?;

                // Create many concurrent streams on this connection
                let mut stream_handles = Vec::new();

                for stream_id in 0..streams_per_connection {
                    let client = Arc::clone(&client);
                    let harness = Arc::clone(&harness);

                    let stream_handle = spawn(async move {
                        let request_start = Instant::now();

                        let request = HttpRequest::builder()
                            .method(HttpMethod::GET)
                            .uri(format!("/echo/{}", stream_id))
                            .build()
                            .map_err(|e| format!("Request build failed: {}", e))?;

                        match client.send(request).await {
                            Ok(response) => {
                                let response_time = request_start.elapsed();
                                let status_code = response.status().as_u16();
                                let body = response.body().await.unwrap_or_default();

                                let stats = RequestStats {
                                    timestamp: request_start,
                                    client_id: connection_id,
                                    request_id: stream_id,
                                    method: "GET".to_string(),
                                    path: format!("/echo/{}", stream_id),
                                    request_size: 0,
                                    response_size: body.len(),
                                    response_time_ms: response_time.as_millis() as u64,
                                    status_code,
                                    success: status_code == 200,
                                    error: None,
                                };

                                harness.record_request_stats(stats);
                                Ok(true)
                            }
                            Err(e) => {
                                let stats = RequestStats {
                                    timestamp: request_start,
                                    client_id: connection_id,
                                    request_id: stream_id,
                                    method: "GET".to_string(),
                                    path: format!("/echo/{}", stream_id),
                                    request_size: 0,
                                    response_size: 0,
                                    response_time_ms: request_start.elapsed().as_millis() as u64,
                                    status_code: 0,
                                    success: false,
                                    error: Some(e.to_string()),
                                };

                                harness.record_request_stats(stats);
                                Ok(false)
                            }
                        }
                    });

                    stream_handles.push(stream_handle);
                }

                // Wait for all streams on this connection
                let mut successful_streams = 0;
                for stream_handle in stream_handles {
                    if let Ok(Ok(success)) = stream_handle.await {
                        if success {
                            successful_streams += 1;
                        }
                    }
                }

                Ok(successful_streams)
            });

            connection_handles.push(handle);
        }

        // Wait for all connections to complete
        let mut total_successful_streams = 0;

        for handle in connection_handles {
            match handle.await {
                Ok(successful_streams) => {
                    total_successful_streams += successful_streams;
                    harness.log(
                        "multiplexing_connection_result",
                        json!({
                            "successful_streams": successful_streams,
                            "expected_streams": streams_per_connection
                        }),
                    );
                }
                Err(e) => {
                    harness.log(
                        "multiplexing_connection_error",
                        json!({
                            "error": e
                        }),
                    );
                }
            }
        }

        let expected_total_streams = num_connections * streams_per_connection;

        // Validate multiplexing performance
        assert!(
            total_successful_streams >= expected_total_streams * 95 / 100,
            "Should complete at least 95% of streams: {}/{}",
            total_successful_streams,
            expected_total_streams
        );

        let performance_validation = harness.validate_load_performance();
        assert!(
            performance_validation.is_ok(),
            "Multiplexing performance validation failed: {:?}",
            performance_validation
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "connections": num_connections,
                "streams_per_connection": streams_per_connection,
                "successful_streams": total_successful_streams,
                "expected_streams": expected_total_streams,
                "message": "HTTP/2 connection multiplexing validated successfully"
            }),
        );
    }
}
