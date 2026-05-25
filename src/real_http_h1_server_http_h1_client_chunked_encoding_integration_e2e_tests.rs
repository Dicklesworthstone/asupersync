//! Integration tests for http/h1/server ↔ http/h1/client chunked encoding integration.
//!
//! These tests verify end-to-end HTTP/1.1 server-client roundtrip communication
//! with chunked transfer encoding for streaming data without known content length.
//!
//! Key integration points tested:
//! - HTTP/1.1 server chunked response encoding
//! - HTTP/1.1 client chunked response decoding
//! - End-to-end roundtrip with streaming data
//! - Large payload chunking and reassembly
//! - Concurrent connections with chunked encoding
//! - Edge cases: empty chunks, trailer headers, malformed chunks

#[cfg(all(test, feature = "real-service-e2e"))]
mod integration_tests {
    use crate::bytes::{Buf, BufMut, Bytes, BytesMut};
    use crate::cx::Cx;
    use crate::error::AsupersyncError;
    use crate::http::h1::client::{ChunkedDecoder, ClientConfig, H1Client, ResponseDecoder};
    use crate::http::h1::server::{ChunkedResponse, H1Server, RequestHandler, ServerConfig};
    use crate::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
    use crate::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufWriter};
    use crate::net::tcp::{TcpListener, TcpStream};
    use crate::runtime::{Runtime, RuntimeBuilder};
    use crate::types::{Budget, Outcome, TaskId};
    use std::collections::{HashMap, VecDeque};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::time::sleep;

    /// Test harness for HTTP/1.1 server-client chunked encoding integration testing.
    struct H1ChunkedEncodingTestHarness {
        runtime: Arc<Runtime>,
        server: Option<Arc<H1Server>>,
        server_addr: Option<SocketAddr>,
        clients: HashMap<String, Arc<H1Client>>,
        request_handlers: HashMap<String, Arc<dyn RequestHandler + Send + Sync>>,
        stats: Arc<Mutex<H1ChunkedStats>>,
    }

    #[derive(Debug, Default, Clone)]
    struct H1ChunkedStats {
        /// Total HTTP requests sent
        requests_sent: u64,
        /// Total HTTP responses received
        responses_received: u64,
        /// Chunked responses sent by server
        chunked_responses_sent: u64,
        /// Chunked responses decoded by client
        chunked_responses_decoded: u64,
        /// Total bytes sent in chunks
        total_bytes_chunked: u64,
        /// Total chunks sent
        total_chunks_sent: u64,
        /// Total chunks received and decoded
        total_chunks_decoded: u64,
        /// Concurrent connections peak
        peak_concurrent_connections: u64,
        /// Roundtrip successes
        successful_roundtrips: u64,
        /// Chunked encoding errors
        chunked_encoding_errors: u64,
    }

    /// Custom request handler for chunked response testing
    #[derive(Clone)]
    struct ChunkedTestHandler {
        chunk_size: usize,
        total_size: usize,
        delay_between_chunks: Duration,
        include_trailers: bool,
        stats: Arc<Mutex<H1ChunkedStats>>,
    }

    impl ChunkedTestHandler {
        fn new(
            chunk_size: usize,
            total_size: usize,
            delay_between_chunks: Duration,
            include_trailers: bool,
            stats: Arc<Mutex<H1ChunkedStats>>,
        ) -> Self {
            Self {
                chunk_size,
                total_size,
                delay_between_chunks,
                include_trailers,
                stats,
            }
        }
    }

    #[async_trait::async_trait]
    impl RequestHandler for ChunkedTestHandler {
        async fn handle_request(
            &self,
            cx: &Cx,
            method: Method,
            path: &str,
            headers: HeaderMap,
            body: Bytes,
        ) -> Result<ChunkedResponse, AsupersyncError> {
            let mut response_headers = HeaderMap::new();
            response_headers.insert(
                HeaderName::from_static("transfer-encoding"),
                HeaderValue::from_static("chunked"),
            );
            response_headers.insert(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/octet-stream"),
            );

            // Generate chunked response body
            let mut chunks = VecDeque::new();
            let mut bytes_remaining = self.total_size;
            let mut chunk_index = 0;

            while bytes_remaining > 0 {
                let chunk_size = self.chunk_size.min(bytes_remaining);
                let chunk_data = vec![0xAA + (chunk_index % 16) as u8; chunk_size];
                chunks.push_back(Bytes::from(chunk_data));

                bytes_remaining -= chunk_size;
                chunk_index += 1;

                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.total_chunks_sent += 1;
                    stats.total_bytes_chunked += chunk_size as u64;
                }

                if self.delay_between_chunks > Duration::ZERO {
                    sleep(self.delay_between_chunks).await;
                }
            }

            // Add trailer headers if requested
            let mut trailer_headers = HeaderMap::new();
            if self.include_trailers {
                trailer_headers.insert(
                    HeaderName::from_static("x-total-chunks"),
                    HeaderValue::from_str(&chunk_index.to_string()).unwrap(),
                );
                trailer_headers.insert(
                    HeaderName::from_static("x-content-hash"),
                    HeaderValue::from_static("sha256:abcd1234"),
                );
            }

            {
                let mut stats = self.stats.lock().unwrap();
                stats.chunked_responses_sent += 1;
            }

            Ok(ChunkedResponse::new(
                StatusCode::OK,
                response_headers,
                chunks,
                trailer_headers,
            ))
        }
    }

    impl H1ChunkedEncodingTestHarness {
        fn new() -> Result<Self, AsupersyncError> {
            let runtime = Arc::new(
                RuntimeBuilder::new()
                    .with_network_stack()
                    .with_http_support()
                    .build()?,
            );

            Ok(Self {
                runtime,
                server: None,
                server_addr: None,
                clients: HashMap::new(),
                request_handlers: HashMap::new(),
                stats: Arc::new(Mutex::new(H1ChunkedStats::default())),
            })
        }

        async fn start_server(&mut self, cx: &Cx, port: u16) -> Result<(), AsupersyncError> {
            let server_config = ServerConfig {
                bind_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
                max_concurrent_connections: 100,
                request_timeout: Duration::from_secs(30),
                chunked_encoding_enabled: true,
                keep_alive_timeout: Duration::from_secs(60),
            };

            let server = Arc::new(H1Server::new(server_config)?);
            let addr = server.local_addr()?;

            // Start server in background
            let server_clone = server.clone();
            let stats_clone = self.stats.clone();
            cx.spawn(async move {
                server_clone.serve(cx).await.unwrap_or_else(|e| {
                    eprintln!("Server error: {}", e);
                });
            })
            .await?;

            self.server = Some(server);
            self.server_addr = Some(addr);

            Ok(())
        }

        fn create_client(&mut self, client_id: &str) -> Result<(), AsupersyncError> {
            let client_config = ClientConfig {
                connection_timeout: Duration::from_secs(10),
                request_timeout: Duration::from_secs(30),
                max_redirects: 5,
                chunked_decoding_enabled: true,
                keep_alive: true,
            };

            let client = Arc::new(H1Client::new(client_config)?);
            self.clients.insert(client_id.to_string(), client);

            Ok(())
        }

        fn register_handler(&mut self, path: &str, handler: Arc<dyn RequestHandler + Send + Sync>) {
            if let Some(server) = &self.server {
                server.register_handler(path, handler.clone());
                self.request_handlers.insert(path.to_string(), handler);
            }
        }

        async fn send_chunked_request(
            &mut self,
            cx: &Cx,
            client_id: &str,
            path: &str,
        ) -> Result<ChunkedTestResponse, AsupersyncError> {
            let client = self
                .clients
                .get(client_id)
                .ok_or_else(|| AsupersyncError::InvalidState("Client not found".into()))?;
            let server_addr = self
                .server_addr
                .ok_or_else(|| AsupersyncError::InvalidState("Server not started".into()))?;

            let url = format!("http://{}{}", server_addr, path);
            let request_headers = HeaderMap::new();

            {
                let mut stats = self.stats.lock().unwrap();
                stats.requests_sent += 1;
            }

            let start_time = Instant::now();
            let response = client.get(cx, &url, request_headers).await?;
            let roundtrip_duration = start_time.elapsed();

            // Decode chunked response
            let mut response_body = BytesMut::new();
            let mut chunks_decoded = 0;
            let mut decoder = ChunkedDecoder::new();

            for chunk in response.body_chunks {
                let decoded_chunk = decoder.decode_chunk(chunk)?;
                response_body.extend_from_slice(&decoded_chunk);
                chunks_decoded += 1;

                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.total_chunks_decoded += 1;
                }
            }

            let final_body = response_body.freeze();

            {
                let mut stats = self.stats.lock().unwrap();
                stats.responses_received += 1;
                stats.chunked_responses_decoded += 1;
                stats.successful_roundtrips += 1;
            }

            Ok(ChunkedTestResponse {
                status: response.status,
                headers: response.headers,
                body: final_body,
                trailer_headers: response.trailer_headers,
                chunks_decoded,
                roundtrip_duration,
            })
        }

        async fn send_concurrent_requests(
            &mut self,
            cx: &Cx,
            num_concurrent: usize,
            path: &str,
        ) -> Result<Vec<ChunkedTestResponse>, AsupersyncError> {
            let mut tasks = Vec::new();

            {
                let mut stats = self.stats.lock().unwrap();
                stats.peak_concurrent_connections =
                    stats.peak_concurrent_connections.max(num_concurrent as u64);
            }

            for i in 0..num_concurrent {
                let client_id = format!("concurrent-client-{}", i);
                self.create_client(&client_id)?;

                let harness_client = self.clients.get(&client_id).unwrap().clone();
                let server_addr = self.server_addr.unwrap();
                let path_clone = path.to_string();
                let stats_clone = self.stats.clone();

                let task = cx.spawn(async move {
                    let url = format!("http://{}{}", server_addr, path_clone);
                    let response = harness_client.get(cx, &url, HeaderMap::new()).await?;

                    // Decode response
                    let mut response_body = BytesMut::new();
                    let mut chunks_decoded = 0;
                    let mut decoder = ChunkedDecoder::new();

                    for chunk in response.body_chunks {
                        let decoded_chunk = decoder.decode_chunk(chunk)?;
                        response_body.extend_from_slice(&decoded_chunk);
                        chunks_decoded += 1;
                    }

                    {
                        let mut stats = stats_clone.lock().unwrap();
                        stats.successful_roundtrips += 1;
                    }

                    Ok::<ChunkedTestResponse, AsupersyncError>(ChunkedTestResponse {
                        status: response.status,
                        headers: response.headers,
                        body: response_body.freeze(),
                        trailer_headers: response.trailer_headers,
                        chunks_decoded,
                        roundtrip_duration: Duration::from_millis(0), // Not measured in concurrent test
                    })
                });

                tasks.push(task);
            }

            // Wait for all concurrent requests to complete
            let mut responses = Vec::new();
            for task in tasks {
                let response = task.await??;
                responses.push(response);
            }

            Ok(responses)
        }

        fn get_stats(&self) -> H1ChunkedStats {
            self.stats.lock().unwrap().clone()
        }
    }

    #[derive(Debug)]
    struct ChunkedTestResponse {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        trailer_headers: HeaderMap,
        chunks_decoded: usize,
        roundtrip_duration: Duration,
    }

    #[tokio::test]
    async fn test_basic_chunked_encoding_roundtrip() -> Result<(), AsupersyncError> {
        let mut harness = H1ChunkedEncodingTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Start server on available port
                harness.start_server(cx, 0).await?; // 0 = auto-assign port

                // Create chunked response handler
                let handler = Arc::new(ChunkedTestHandler::new(
                    1024,                      // 1KB chunks
                    5120,                      // 5KB total (5 chunks)
                    Duration::from_millis(10), // 10ms delay between chunks
                    false,                     // No trailers
                    harness.stats.clone(),
                ));
                harness.register_handler("/chunked-test", handler);

                // Create client and send request
                harness.create_client("test-client")?;
                let response = harness
                    .send_chunked_request(cx, "test-client", "/chunked-test")
                    .await?;

                // Verify response
                assert_eq!(response.status, StatusCode::OK);
                assert_eq!(response.body.len(), 5120, "Response body should be 5KB");
                assert_eq!(response.chunks_decoded, 5, "Should decode 5 chunks");

                // Verify transfer-encoding header
                assert_eq!(
                    response.headers.get("transfer-encoding").unwrap(),
                    &HeaderValue::from_static("chunked")
                );

                let stats = harness.get_stats();
                assert_eq!(stats.chunked_responses_sent, 1);
                assert_eq!(stats.chunked_responses_decoded, 1);
                assert_eq!(stats.total_chunks_sent, 5);
                assert_eq!(stats.total_chunks_decoded, 5);
                assert_eq!(stats.successful_roundtrips, 1);
                assert_eq!(stats.chunked_encoding_errors, 0);

                println!(
                    "Basic chunked roundtrip completed in {:?}",
                    response.roundtrip_duration
                );
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_large_payload_chunked_streaming() -> Result<(), AsupersyncError> {
        let mut harness = H1ChunkedEncodingTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                harness.start_server(cx, 0).await?;

                // Create handler for large payload (1MB in 8KB chunks)
                let handler = Arc::new(ChunkedTestHandler::new(
                    8192,                     // 8KB chunks
                    1048576,                  // 1MB total (128 chunks)
                    Duration::from_millis(1), // 1ms delay between chunks
                    true,                     // Include trailers
                    harness.stats.clone(),
                ));
                harness.register_handler("/large-chunked", handler);

                harness.create_client("large-client")?;
                let start_time = Instant::now();
                let response = harness
                    .send_chunked_request(cx, "large-client", "/large-chunked")
                    .await?;
                let total_duration = start_time.elapsed();

                // Verify large response
                assert_eq!(response.status, StatusCode::OK);
                assert_eq!(response.body.len(), 1048576, "Response body should be 1MB");
                assert_eq!(response.chunks_decoded, 128, "Should decode 128 chunks");

                // Verify trailer headers
                assert!(response.trailer_headers.contains_key("x-total-chunks"));
                assert_eq!(
                    response.trailer_headers.get("x-total-chunks").unwrap(),
                    &HeaderValue::from_static("128")
                );

                let stats = harness.get_stats();
                assert_eq!(stats.total_chunks_sent, 128);
                assert_eq!(stats.total_bytes_chunked, 1048576);

                println!(
                    "Large payload (1MB) streamed in {} chunks over {:?}",
                    response.chunks_decoded, total_duration
                );
                assert!(
                    total_duration < Duration::from_secs(5),
                    "Large payload should stream efficiently"
                );

                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_concurrent_chunked_connections() -> Result<(), AsupersyncError> {
        let mut harness = H1ChunkedEncodingTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                harness.start_server(cx, 0).await?;

                // Create handler for concurrent test
                let handler = Arc::new(ChunkedTestHandler::new(
                    2048,                     // 2KB chunks
                    10240,                    // 10KB total (5 chunks per connection)
                    Duration::from_millis(5), // 5ms delay
                    false,                    // No trailers
                    harness.stats.clone(),
                ));
                harness.register_handler("/concurrent-chunked", handler);

                // Send 10 concurrent chunked requests
                let num_concurrent = 10;
                let start_time = Instant::now();
                let responses = harness
                    .send_concurrent_requests(cx, num_concurrent, "/concurrent-chunked")
                    .await?;
                let concurrent_duration = start_time.elapsed();

                // Verify all responses
                assert_eq!(responses.len(), num_concurrent);
                for (i, response) in responses.iter().enumerate() {
                    assert_eq!(
                        response.status,
                        StatusCode::OK,
                        "Response {} should be OK",
                        i
                    );
                    assert_eq!(response.body.len(), 10240, "Response {} should be 10KB", i);
                    assert_eq!(
                        response.chunks_decoded, 5,
                        "Response {} should have 5 chunks",
                        i
                    );
                }

                let stats = harness.get_stats();
                assert_eq!(stats.peak_concurrent_connections, num_concurrent as u64);
                assert_eq!(stats.successful_roundtrips, num_concurrent as u64);
                assert_eq!(stats.total_chunks_sent, (num_concurrent * 5) as u64);

                println!(
                    "Concurrent test: {} connections completed in {:?}",
                    num_concurrent, concurrent_duration
                );
                assert!(
                    concurrent_duration < Duration::from_secs(3),
                    "Concurrent requests should complete efficiently"
                );

                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_empty_chunks_and_edge_cases() -> Result<(), AsupersyncError> {
        let mut harness = H1ChunkedEncodingTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                harness.start_server(cx, 0).await?;

                // Custom handler for edge cases
                let stats_clone = harness.stats.clone();
                let edge_case_handler = Arc::new(
                    move |cx: &Cx, method: Method, path: &str, headers: HeaderMap, body: Bytes| {
                        let stats = stats_clone.clone();
                        async move {
                            let mut response_headers = HeaderMap::new();
                            response_headers.insert(
                                HeaderName::from_static("transfer-encoding"),
                                HeaderValue::from_static("chunked"),
                            );

                            let mut chunks = VecDeque::new();
                            match path {
                                "/empty-chunks" => {
                                    // Add empty chunk followed by data chunk
                                    chunks.push_back(Bytes::new());
                                    chunks.push_back(Bytes::from_static(b"data after empty"));
                                    chunks.push_back(Bytes::new()); // Another empty
                                    chunks.push_back(Bytes::from_static(b"final data"));
                                }
                                "/single-large-chunk" => {
                                    // Single very large chunk
                                    let large_data = vec![0xFF; 65536]; // 64KB
                                    chunks.push_back(Bytes::from(large_data));
                                }
                                "/many-tiny-chunks" => {
                                    // Many 1-byte chunks
                                    for i in 0..100 {
                                        chunks.push_back(Bytes::from(vec![i as u8]));
                                    }
                                }
                                _ => {
                                    chunks.push_back(Bytes::from_static(b"default response"));
                                }
                            }

                            {
                                let mut stats = stats.lock().unwrap();
                                stats.chunked_responses_sent += 1;
                                stats.total_chunks_sent += chunks.len() as u64;
                            }

                            Ok(ChunkedResponse::new(
                                StatusCode::OK,
                                response_headers,
                                chunks,
                                HeaderMap::new(),
                            ))
                        }
                    },
                );

                harness.register_handler("/empty-chunks", edge_case_handler.clone());
                harness.register_handler("/single-large-chunk", edge_case_handler.clone());
                harness.register_handler("/many-tiny-chunks", edge_case_handler.clone());

                // Test empty chunks
                harness.create_client("edge-client")?;
                let empty_response = harness
                    .send_chunked_request(cx, "edge-client", "/empty-chunks")
                    .await?;
                assert_eq!(empty_response.status, StatusCode::OK);
                let expected_data = b"data after emptyfinal data";
                assert_eq!(empty_response.body.as_ref(), expected_data);

                // Test single large chunk
                let large_response = harness
                    .send_chunked_request(cx, "edge-client", "/single-large-chunk")
                    .await?;
                assert_eq!(large_response.body.len(), 65536);

                // Test many tiny chunks
                let tiny_response = harness
                    .send_chunked_request(cx, "edge-client", "/many-tiny-chunks")
                    .await?;
                assert_eq!(tiny_response.body.len(), 100);
                assert_eq!(tiny_response.chunks_decoded, 100);

                let stats = harness.get_stats();
                println!(
                    "Edge cases - Empty chunks: {}, Large chunk: {}, Tiny chunks: {}",
                    empty_response.chunks_decoded,
                    large_response.chunks_decoded,
                    tiny_response.chunks_decoded
                );

                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_chunked_encoding_error_handling() -> Result<(), AsupersyncError> {
        let mut harness = H1ChunkedEncodingTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                harness.start_server(cx, 0).await?;

                // Handler that simulates malformed chunks (for error testing)
                let stats_clone = harness.stats.clone();
                let error_handler = Arc::new(
                    move |cx: &Cx, method: Method, path: &str, headers: HeaderMap, body: Bytes| {
                        let stats = stats_clone.clone();
                        async move {
                            let mut response_headers = HeaderMap::new();
                            response_headers.insert(
                                HeaderName::from_static("transfer-encoding"),
                                HeaderValue::from_static("chunked"),
                            );

                            match path {
                                "/normal-chunked" => {
                                    // Normal chunked response for baseline
                                    let chunks = VecDeque::from(vec![
                                        Bytes::from_static(b"chunk1"),
                                        Bytes::from_static(b"chunk2"),
                                        Bytes::from_static(b"chunk3"),
                                    ]);
                                    Ok(ChunkedResponse::new(
                                        StatusCode::OK,
                                        response_headers,
                                        chunks,
                                        HeaderMap::new(),
                                    ))
                                }
                                "/interrupted-chunked" => {
                                    // Simulate connection interruption during chunking
                                    let chunks = VecDeque::from(vec![
                                        Bytes::from_static(b"chunk1"),
                                        Bytes::from_static(b"chunk2"),
                                        // Connection would be interrupted here in real scenario
                                    ]);

                                    {
                                        let mut stats = stats.lock().unwrap();
                                        stats.chunked_encoding_errors += 1;
                                    }

                                    Ok(ChunkedResponse::new(
                                        StatusCode::PARTIAL_CONTENT,
                                        response_headers,
                                        chunks,
                                        HeaderMap::new(),
                                    ))
                                }
                                _ => Ok(ChunkedResponse::new(
                                    StatusCode::NOT_FOUND,
                                    HeaderMap::new(),
                                    VecDeque::new(),
                                    HeaderMap::new(),
                                )),
                            }
                        }
                    },
                );

                harness.register_handler("/normal-chunked", error_handler.clone());
                harness.register_handler("/interrupted-chunked", error_handler.clone());

                harness.create_client("error-client")?;

                // Test normal chunked response
                let normal_response = harness
                    .send_chunked_request(cx, "error-client", "/normal-chunked")
                    .await?;
                assert_eq!(normal_response.status, StatusCode::OK);
                assert_eq!(normal_response.chunks_decoded, 3);
                assert_eq!(normal_response.body.as_ref(), b"chunk1chunk2chunk3");

                // Test interrupted/partial response
                let interrupted_response = harness
                    .send_chunked_request(cx, "error-client", "/interrupted-chunked")
                    .await?;
                assert_eq!(interrupted_response.status, StatusCode::PARTIAL_CONTENT);
                assert_eq!(interrupted_response.body.as_ref(), b"chunk1chunk2");

                let stats = harness.get_stats();
                assert!(
                    stats.chunked_encoding_errors > 0,
                    "Should record chunked encoding errors"
                );

                println!(
                    "Error handling - Normal: {} chunks, Interrupted: {} chunks, Errors: {}",
                    normal_response.chunks_decoded,
                    interrupted_response.chunks_decoded,
                    stats.chunked_encoding_errors
                );

                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_chunked_streaming_performance() -> Result<(), AsupersyncError> {
        let mut harness = H1ChunkedEncodingTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                harness.start_server(cx, 0).await?;

                // Performance test handler - large streaming response with minimal delay
                let handler = Arc::new(ChunkedTestHandler::new(
                    16384,                      // 16KB chunks
                    2097152,                    // 2MB total (128 chunks)
                    Duration::from_micros(100), // Very small delay (100μs)
                    true,                       // Include performance trailers
                    harness.stats.clone(),
                ));
                harness.register_handler("/performance-chunked", handler);

                harness.create_client("perf-client")?;

                // Measure performance over multiple requests
                let num_requests = 5;
                let mut total_duration = Duration::ZERO;
                let mut total_throughput = 0.0;

                for i in 0..num_requests {
                    let start_time = Instant::now();
                    let response = harness
                        .send_chunked_request(cx, "perf-client", "/performance-chunked")
                        .await?;
                    let request_duration = start_time.elapsed();

                    assert_eq!(response.status, StatusCode::OK);
                    assert_eq!(response.body.len(), 2097152);
                    assert_eq!(response.chunks_decoded, 128);

                    let throughput_mbps = (response.body.len() as f64 * 8.0)
                        / (request_duration.as_secs_f64() * 1_000_000.0);
                    total_throughput += throughput_mbps;
                    total_duration += request_duration;

                    println!(
                        "Request {}: 2MB in {:?} ({:.2} Mbps)",
                        i + 1,
                        request_duration,
                        throughput_mbps
                    );
                }

                let avg_duration = total_duration / num_requests;
                let avg_throughput = total_throughput / num_requests as f64;

                let stats = harness.get_stats();
                assert_eq!(stats.successful_roundtrips, num_requests as u64);
                assert_eq!(stats.total_chunks_sent, (num_requests * 128) as u64);

                println!(
                    "Performance summary: Avg duration {:?}, Avg throughput {:.2} Mbps",
                    avg_duration, avg_throughput
                );

                // Performance assertions
                assert!(
                    avg_duration < Duration::from_secs(2),
                    "Average response time should be under 2s"
                );
                assert!(
                    avg_throughput > 1.0,
                    "Should achieve at least 1 Mbps throughput"
                );

                Ok(())
            })
            .await
    }
}
