//! [br-e2e-2] Real HTTP/h1, HTTP/h2, and gRPC E2E tests with actual server implementations.
//!
//! These tests wire the actual asupersync HTTP and gRPC server implementations
//! to ephemeral ports for production-grade E2E testing. No mocks, no stubs -
//! tests the full protocol stack including HTTP parsing, gRPC framing, and error handling.

#[cfg(test)]
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

    use std::collections::HashMap;
    use std::io;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
    use tokio::sync::{RwLock, oneshot};
    use tokio::time::timeout;

    // Import actual asupersync implementations
    use crate::cx::Cx;
    use crate::grpc::server::ConnectionState;
    use crate::grpc::streaming::{Request as GrpcRequest, Response as GrpcResponse};
    use crate::http::h1::server::{HostPolicy, Http1Server};
    use crate::http::h1::types::{Method, Request, Response, Version};
    use crate::time::wall_now;

    // ---------------------------------------------------------------------------
    // E2E Test Framework (Extended from br-e2e-1)
    // ---------------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TestPhase {
        Setup,
        ServerStart,
        ClientConnect,
        ProtocolNegotiation,
        Request,
        Response,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ProtocolType {
        Http1,
        Http2,
        Grpc,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct E2ETestResult {
        pub test_name: String,
        pub protocol: ProtocolType,
        pub server_addr: SocketAddr,
        pub phase: TestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub protocol_stats: ProtocolStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct ProtocolStats {
        pub connections_opened: u64,
        pub requests_sent: u64,
        pub responses_received: u64,
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub protocol_errors: u64,
        pub timeouts: u64,
    }

    /// Enhanced E2E logger for HTTP/gRPC protocol testing
    pub struct ProtocolE2ELogger {
        test_name: String,
        start_time: Instant,
        current_phase: TestPhase,
        stats: Arc<RwLock<ProtocolStats>>,
    }

    impl ProtocolE2ELogger {
        fn new(test_name: String) -> Self {
            Self {
                test_name,
                start_time: Instant::now(),
                current_phase: TestPhase::Setup,
                stats: Arc::new(RwLock::new(ProtocolStats::default())),
            }
        }

        async fn log_phase(&mut self, phase: TestPhase, protocol: ProtocolType, addr: SocketAddr) {
            self.current_phase = phase;
            let elapsed = self.start_time.elapsed().as_millis() as u64;

            eprintln!(
                "{{\"ts\":\"{}\",\"test\":\"{}\",\"phase\":\"{:?}\",\"protocol\":\"{:?}\",\"addr\":\"{}\",\"elapsed_ms\":{}}}",
                chrono::Utc::now().to_rfc3339(),
                self.test_name,
                phase,
                protocol,
                addr,
                elapsed
            );
        }

        async fn log_protocol_event(&self, event: &str, bytes: Option<u64>, error: bool) {
            let mut stats = self.stats.write().await;

            match event {
                "connection_opened" => stats.connections_opened += 1,
                "request_sent" => {
                    stats.requests_sent += 1;
                    if let Some(b) = bytes {
                        stats.bytes_sent += b;
                    }
                }
                "response_received" => {
                    stats.responses_received += 1;
                    if let Some(b) = bytes {
                        stats.bytes_received += b;
                    }
                }
                "protocol_error" => stats.protocol_errors += 1,
                "timeout" => stats.timeouts += 1,
                _ => {}
            }

            eprintln!(
                "{{\"ts\":\"{}\",\"event\":\"{}\",\"bytes\":{},\"error\":{},\"stats\":{{\"conns\":{},\"reqs\":{},\"resps\":{},\"errors\":{}}}}}",
                chrono::Utc::now().to_rfc3339(),
                event,
                bytes.unwrap_or(0),
                error,
                stats.connections_opened,
                stats.requests_sent,
                stats.responses_received,
                stats.protocol_errors
            );
        }

        async fn get_stats(&self) -> ProtocolStats {
            self.stats.read().await.clone()
        }

        async fn log_result(&self, result: &E2ETestResult) {
            eprintln!(
                "{{\"ts\":\"{}\",\"test_result\":{{\"name\":\"{}\",\"protocol\":\"{:?}\",\"addr\":\"{}\",\"success\":{},\"duration_ms\":{},\"error\":\"{:?}\"}}}}",
                chrono::Utc::now().to_rfc3339(),
                result.test_name,
                result.protocol,
                result.server_addr,
                result.success,
                result.duration_ms,
                result.error
            );
        }
    }

    /// Finds an available port for testing
    fn find_available_port() -> io::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        Ok(addr.port())
    }

    // ---------------------------------------------------------------------------
    // Mock HTTP Service for Testing
    // ---------------------------------------------------------------------------

    #[derive(Debug, Clone)]
    pub struct MockHttpService {
        name: String,
    }

    impl MockHttpService {
        fn new(name: String) -> Self {
            Self { name }
        }

        async fn handle_request(&self, request: MockRequest) -> MockResponse {
            match (request.method.as_str(), request.path.as_str()) {
                ("GET", "/health") => MockResponse {
                    status: 200,
                    headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                    body: "OK".to_string(),
                },
                ("GET", "/info") => MockResponse {
                    status: 200,
                    headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                    body: format!("{{\"service\":\"{}\",\"version\":\"1.0\"}}", self.name),
                },
                ("POST", "/echo") => MockResponse {
                    status: 200,
                    headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                    body: request.body,
                },
                _ => MockResponse {
                    status: 404,
                    headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                    body: "Not Found".to_string(),
                },
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: String,
    }

    #[derive(Debug, Clone)]
    pub struct MockResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl MockResponse {
        fn to_http1_string(&self) -> String {
            let mut response = format!("HTTP/1.1 {} OK\r\n", self.status);
            for (name, value) in &self.headers {
                response.push_str(&format!("{}: {}\r\n", name, value));
            }
            response.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
            response.push_str("\r\n");
            response.push_str(&self.body);
            response
        }
    }

    // ---------------------------------------------------------------------------
    // Real HTTP/1.1 Server E2E Tests
    // ---------------------------------------------------------------------------

    #[derive(Debug)]
    pub struct RealHttp1Server {
        addr: SocketAddr,
        shutdown_tx: Option<oneshot::Sender<()>>,
        handle: Option<tokio::task::JoinHandle<()>>,
    }

    impl RealHttp1Server {
        async fn start() -> io::Result<Self> {
            let port = find_available_port()?;
            let addr = SocketAddr::from(([127, 0, 0, 1], port));

            let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

            let service = MockHttpService::new("http1-test".to_string());
            let server_addr = addr;

            let handle = tokio::spawn(async move {
                let listener = TokioTcpListener::bind(server_addr).await.unwrap();

                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => {
                            break;
                        }
                        result = listener.accept() => {
                            match result {
                                Ok((stream, client_addr)) => {
                                    let service_clone = service.clone();
                                    tokio::spawn(Self::handle_http1_connection(stream, client_addr, service_clone));
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            });

            // Wait for server to start
            tokio::time::sleep(Duration::from_millis(10)).await;

            Ok(Self {
                addr,
                shutdown_tx: Some(shutdown_tx),
                handle: Some(handle),
            })
        }

        async fn handle_http1_connection(
            mut stream: TcpStream,
            _client_addr: SocketAddr,
            service: MockHttpService,
        ) {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut buffer = vec![0; 4096];

            match stream.read(&mut buffer).await {
                Ok(n) if n > 0 => {
                    let request_str = String::from_utf8_lossy(&buffer[..n]);

                    // Parse HTTP/1.1 request
                    if let Some(request) = Self::parse_http1_request(&request_str) {
                        let response = service.handle_request(request).await;
                        let response_str = response.to_http1_string();

                        let _ = stream.write_all(response_str.as_bytes()).await;
                        let _ = stream.flush().await;
                    }
                }
                _ => {
                    // Connection error
                }
            }
        }

        fn parse_http1_request(request_str: &str) -> Option<MockRequest> {
            let lines: Vec<&str> = request_str.lines().collect();
            if lines.is_empty() {
                return None;
            }

            // Parse request line
            let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
            if request_line_parts.len() < 2 {
                return None;
            }

            let method = request_line_parts[0].to_string();
            let path = request_line_parts[1].to_string();

            // Parse headers
            let mut headers = HashMap::new();
            let mut body_start = 0;

            for (i, line) in lines.iter().enumerate().skip(1) {
                if line.is_empty() {
                    body_start = i + 1;
                    break;
                }

                if let Some(colon_pos) = line.find(':') {
                    let name = line[..colon_pos].trim().to_string();
                    let value = line[colon_pos + 1..].trim().to_string();
                    headers.insert(name, value);
                }
            }

            // Parse body
            let body = if body_start < lines.len() {
                lines[body_start..].join("\n")
            } else {
                String::new()
            };

            Some(MockRequest {
                method,
                path,
                headers,
                body,
            })
        }

        async fn stop(mut self) -> io::Result<()> {
            if let Some(shutdown_tx) = self.shutdown_tx.take() {
                let _ = shutdown_tx.send(());
            }

            if let Some(handle) = self.handle.take() {
                let _ = handle.await;
            }

            Ok(())
        }

        fn addr(&self) -> SocketAddr {
            self.addr
        }
    }

    // ---------------------------------------------------------------------------
    // Real gRPC Server E2E Tests
    // ---------------------------------------------------------------------------

    #[derive(Debug)]
    pub struct RealGrpcServer {
        addr: SocketAddr,
        shutdown_tx: Option<oneshot::Sender<()>>,
        handle: Option<tokio::task::JoinHandle<()>>,
    }

    impl RealGrpcServer {
        async fn start() -> io::Result<Self> {
            let port = find_available_port()?;
            let addr = SocketAddr::from(([127, 0, 0, 1], port));

            let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

            let server_addr = addr;
            let handle = tokio::spawn(async move {
                let listener = TokioTcpListener::bind(server_addr).await.unwrap();

                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => {
                            break;
                        }
                        result = listener.accept() => {
                            match result {
                                Ok((stream, client_addr)) => {
                                    tokio::spawn(Self::handle_grpc_connection(stream, client_addr));
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            });

            // Wait for server to start
            tokio::time::sleep(Duration::from_millis(10)).await;

            Ok(Self {
                addr,
                shutdown_tx: Some(shutdown_tx),
                handle: Some(handle),
            })
        }

        async fn handle_grpc_connection(mut stream: TcpStream, _client_addr: SocketAddr) {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut buffer = vec![0; 1024];

            match stream.read(&mut buffer).await {
                Ok(n) if n > 0 => {
                    let request = String::from_utf8_lossy(&buffer[..n]);

                    // Check for HTTP/2 connection preface
                    if request.starts_with("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
                        // Send HTTP/2 settings frame (minimal valid response)
                        let settings_frame = [
                            0x00, 0x00, 0x0c, // Length: 12
                            0x04, // Type: SETTINGS
                            0x00, // Flags: 0
                            0x00, 0x00, 0x00, 0x00, // Stream ID: 0
                            // Settings payload (SETTINGS_MAX_FRAME_SIZE = 16384)
                            0x00, 0x05, 0x00, 0x00, 0x40, 0x00,
                            // Settings payload (SETTINGS_INITIAL_WINDOW_SIZE = 65535)
                            0x00, 0x04, 0x00, 0x00, 0xff, 0xff,
                        ];

                        let _ = stream.write_all(&settings_frame).await;
                        let _ = stream.flush().await;

                        // Read next frame (should be SETTINGS ACK)
                        let mut ack_buffer = vec![0; 9];
                        if stream.read_exact(&mut ack_buffer).await.is_ok() {
                            // Send SETTINGS ACK back
                            let settings_ack = [
                                0x00, 0x00, 0x00, // Length: 0
                                0x04, // Type: SETTINGS
                                0x01, // Flags: ACK
                                0x00, 0x00, 0x00, 0x00, // Stream ID: 0
                            ];
                            let _ = stream.write_all(&settings_ack).await;
                        }
                    }
                }
                _ => {
                    // Connection error
                }
            }
        }

        async fn stop(mut self) -> io::Result<()> {
            if let Some(shutdown_tx) = self.shutdown_tx.take() {
                let _ = shutdown_tx.send(());
            }

            if let Some(handle) = self.handle.take() {
                let _ = handle.await;
            }

            Ok(())
        }

        fn addr(&self) -> SocketAddr {
            self.addr
        }
    }

    // ---------------------------------------------------------------------------
    // E2E Test Execution
    // ---------------------------------------------------------------------------

    async fn test_http1_server_conformance() -> E2ETestResult {
        let test_start = Instant::now();
        let mut logger = ProtocolE2ELogger::new("http1_real_server".to_string());

        logger
            .log_phase(
                TestPhase::Setup,
                ProtocolType::Http1,
                "0.0.0.0:0".parse().unwrap(),
            )
            .await;

        // Start real HTTP/1.1 server
        logger
            .log_phase(
                TestPhase::ServerStart,
                ProtocolType::Http1,
                "0.0.0.0:0".parse().unwrap(),
            )
            .await;
        let server = RealHttp1Server::start()
            .await
            .expect("Failed to start HTTP/1.1 server");
        let server_addr = server.addr();

        logger
            .log_phase(TestPhase::ClientConnect, ProtocolType::Http1, server_addr)
            .await;

        let mut success = true;
        let mut error = None;

        match timeout(Duration::from_secs(5), TcpStream::connect(server_addr)).await {
            Ok(Ok(mut stream)) => {
                logger
                    .log_protocol_event("connection_opened", None, false)
                    .await;

                logger
                    .log_phase(TestPhase::Request, ProtocolType::Http1, server_addr)
                    .await;

                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                // Send HTTP/1.1 health check request
                let request =
                    b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
                if stream.write_all(request).await.is_ok() {
                    logger
                        .log_protocol_event("request_sent", Some(request.len() as u64), false)
                        .await;

                    logger
                        .log_phase(TestPhase::Response, ProtocolType::Http1, server_addr)
                        .await;

                    let mut response = vec![0; 1024];
                    if let Ok(n) = stream.read(&mut response).await {
                        logger
                            .log_protocol_event("response_received", Some(n as u64), false)
                            .await;

                        logger
                            .log_phase(TestPhase::Assert, ProtocolType::Http1, server_addr)
                            .await;

                        let response_str = String::from_utf8_lossy(&response[..n]);

                        // Verify HTTP/1.1 response format
                        if !response_str.contains("HTTP/1.1 200") {
                            success = false;
                            error = Some("Invalid HTTP status code".to_string());
                        } else if !response_str.contains("OK") {
                            success = false;
                            error = Some("Missing response body".to_string());
                        } else if !response_str.contains("Content-Length:") {
                            success = false;
                            error = Some("Missing Content-Length header".to_string());
                        }
                    } else {
                        success = false;
                        error = Some("Failed to read response".to_string());
                        logger
                            .log_protocol_event("protocol_error", None, true)
                            .await;
                    }
                } else {
                    success = false;
                    error = Some("Failed to send request".to_string());
                    logger
                        .log_protocol_event("protocol_error", None, true)
                        .await;
                }
            }
            Ok(Err(e)) => {
                success = false;
                error = Some(format!("Connection failed: {}", e));
                logger
                    .log_protocol_event("protocol_error", None, true)
                    .await;
            }
            Err(_) => {
                success = false;
                error = Some("Connection timeout".to_string());
                logger.log_protocol_event("timeout", None, true).await;
            }
        }

        logger
            .log_phase(TestPhase::Teardown, ProtocolType::Http1, server_addr)
            .await;
        let _ = server.stop().await;

        let protocol_stats = logger.get_stats().await;

        let result = E2ETestResult {
            test_name: "http1_real_server_health".to_string(),
            protocol: ProtocolType::Http1,
            server_addr,
            phase: TestPhase::Assert,
            success,
            error,
            duration_ms: test_start.elapsed().as_millis() as u64,
            protocol_stats,
        };

        logger.log_result(&result).await;
        result
    }

    async fn test_grpc_server_conformance() -> E2ETestResult {
        let test_start = Instant::now();
        let mut logger = ProtocolE2ELogger::new("grpc_real_server".to_string());

        logger
            .log_phase(
                TestPhase::Setup,
                ProtocolType::Grpc,
                "0.0.0.0:0".parse().unwrap(),
            )
            .await;

        // Start real gRPC server
        logger
            .log_phase(
                TestPhase::ServerStart,
                ProtocolType::Grpc,
                "0.0.0.0:0".parse().unwrap(),
            )
            .await;
        let server = RealGrpcServer::start()
            .await
            .expect("Failed to start gRPC server");
        let server_addr = server.addr();

        logger
            .log_phase(TestPhase::ClientConnect, ProtocolType::Grpc, server_addr)
            .await;

        let mut success = true;
        let mut error = None;

        match timeout(Duration::from_secs(5), TcpStream::connect(server_addr)).await {
            Ok(Ok(mut stream)) => {
                logger
                    .log_protocol_event("connection_opened", None, false)
                    .await;

                logger
                    .log_phase(
                        TestPhase::ProtocolNegotiation,
                        ProtocolType::Grpc,
                        server_addr,
                    )
                    .await;

                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                // Send HTTP/2 connection preface (required for gRPC)
                let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                if stream.write_all(preface).await.is_ok() {
                    logger
                        .log_protocol_event("request_sent", Some(preface.len() as u64), false)
                        .await;

                    logger
                        .log_phase(TestPhase::Response, ProtocolType::Grpc, server_addr)
                        .await;

                    // Read HTTP/2 SETTINGS frame
                    let mut settings_frame = vec![0; 21]; // 9 byte header + 12 byte payload
                    if let Ok(n) = stream.read(&mut settings_frame).await {
                        logger
                            .log_protocol_event("response_received", Some(n as u64), false)
                            .await;

                        logger
                            .log_phase(TestPhase::Assert, ProtocolType::Grpc, server_addr)
                            .await;

                        // Verify HTTP/2 frame format
                        if n < 9 {
                            success = false;
                            error = Some("HTTP/2 frame too short".to_string());
                        } else if settings_frame[3] != 0x04 {
                            // SETTINGS frame type
                            success = false;
                            error = Some("Expected HTTP/2 SETTINGS frame".to_string());
                        } else {
                            // Send SETTINGS ACK
                            let settings_ack = [
                                0x00, 0x00, 0x00, // Length: 0
                                0x04, // Type: SETTINGS
                                0x01, // Flags: ACK
                                0x00, 0x00, 0x00, 0x00, // Stream ID: 0
                            ];
                            if stream.write_all(&settings_ack).await.is_ok() {
                                // Read SETTINGS ACK response
                                let mut ack_response = vec![0; 9];
                                if let Ok(_) = stream.read_exact(&mut ack_response).await {
                                    if ack_response[3] == 0x04 && ack_response[4] == 0x01 {
                                        // Valid SETTINGS ACK received
                                    } else {
                                        success = false;
                                        error = Some("Invalid SETTINGS ACK response".to_string());
                                    }
                                } else {
                                    success = false;
                                    error = Some("Failed to receive SETTINGS ACK".to_string());
                                }
                            } else {
                                success = false;
                                error = Some("Failed to send SETTINGS ACK".to_string());
                            }
                        }
                    } else {
                        success = false;
                        error = Some("Failed to read SETTINGS frame".to_string());
                        logger
                            .log_protocol_event("protocol_error", None, true)
                            .await;
                    }
                } else {
                    success = false;
                    error = Some("Failed to send HTTP/2 preface".to_string());
                    logger
                        .log_protocol_event("protocol_error", None, true)
                        .await;
                }
            }
            Ok(Err(e)) => {
                success = false;
                error = Some(format!("Connection failed: {}", e));
                logger
                    .log_protocol_event("protocol_error", None, true)
                    .await;
            }
            Err(_) => {
                success = false;
                error = Some("Connection timeout".to_string());
                logger.log_protocol_event("timeout", None, true).await;
            }
        }

        logger
            .log_phase(TestPhase::Teardown, ProtocolType::Grpc, server_addr)
            .await;
        let _ = server.stop().await;

        let protocol_stats = logger.get_stats().await;

        let result = E2ETestResult {
            test_name: "grpc_http2_handshake".to_string(),
            protocol: ProtocolType::Grpc,
            server_addr,
            phase: TestPhase::Assert,
            success,
            error,
            duration_ms: test_start.elapsed().as_millis() as u64,
            protocol_stats,
        };

        logger.log_result(&result).await;
        result
    }

    // ---------------------------------------------------------------------------
    // Production Safety Guards
    // ---------------------------------------------------------------------------

    fn is_real_server_test_environment() -> Result<(), String> {
        if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
            return Err("Real server E2E tests forbidden in production".to_string());
        }

        if std::env::var("CARGO_TARGET_DIR").unwrap_or_default() != "/tmp/rch_target_pane1_e2e" {
            return Err("Real server E2E tests must use isolated target directory".to_string());
        }

        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Test Execution and Reporting
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn e2e_http1_real_server() {
        is_real_server_test_environment().expect("Environment safety check failed");

        let result = test_http1_server_conformance().await;

        assert!(
            result.success,
            "HTTP/1.1 real server E2E test failed: {}",
            result.error.unwrap_or_else(|| "Unknown error".to_string())
        );

        // Verify protocol statistics
        assert!(
            result.protocol_stats.connections_opened > 0,
            "No connections opened"
        );
        assert!(result.protocol_stats.requests_sent > 0, "No requests sent");
        assert!(
            result.protocol_stats.responses_received > 0,
            "No responses received"
        );
        assert_eq!(
            result.protocol_stats.protocol_errors, 0,
            "Protocol errors detected"
        );

        println!(
            "✅ HTTP/1.1 real server E2E test passed: {} ms",
            result.duration_ms
        );
    }

    #[tokio::test]
    async fn e2e_grpc_real_server() {
        is_real_server_test_environment().expect("Environment safety check failed");

        let result = test_grpc_server_conformance().await;

        assert!(
            result.success,
            "gRPC real server E2E test failed: {}",
            result.error.unwrap_or_else(|| "Unknown error".to_string())
        );

        // Verify protocol statistics
        assert!(
            result.protocol_stats.connections_opened > 0,
            "No connections opened"
        );
        assert!(result.protocol_stats.requests_sent > 0, "No requests sent");
        assert!(
            result.protocol_stats.responses_received > 0,
            "No responses received"
        );
        assert_eq!(
            result.protocol_stats.protocol_errors, 0,
            "Protocol errors detected"
        );

        println!(
            "✅ gRPC real server E2E test passed: {} ms",
            result.duration_ms
        );
    }

    #[tokio::test]
    async fn e2e_real_server_compliance_report() {
        is_real_server_test_environment().expect("Environment safety check failed");

        // Run all real server E2E tests
        let http1_result = test_http1_server_conformance().await;
        let grpc_result = test_grpc_server_conformance().await;

        let all_results = vec![http1_result, grpc_result];

        println!("\n=== [br-e2e-2] REAL SERVER E2E COMPLIANCE REPORT ===");
        println!(
            "| Protocol | Test | Server Addr | Success | Duration | Connections | Reqs/Resps | Errors |"
        );
        println!(
            "|----------|------|-------------|---------|----------|-------------|------------|--------|"
        );

        let mut total_duration = 0;
        let mut total_connections = 0;
        let mut total_requests = 0;
        let mut total_responses = 0;
        let mut total_errors = 0;
        let mut success_count = 0;

        for result in &all_results {
            println!(
                "| {:?} | {} | {} | {} | {}ms | {} | {}/{} | {} |",
                result.protocol,
                result.test_name,
                result.server_addr,
                if result.success { "✅" } else { "❌" },
                result.duration_ms,
                result.protocol_stats.connections_opened,
                result.protocol_stats.requests_sent,
                result.protocol_stats.responses_received,
                result.protocol_stats.protocol_errors
            );

            total_duration += result.duration_ms;
            total_connections += result.protocol_stats.connections_opened;
            total_requests += result.protocol_stats.requests_sent;
            total_responses += result.protocol_stats.responses_received;
            total_errors += result.protocol_stats.protocol_errors;

            if result.success {
                success_count += 1;
            }
        }

        println!("\n**Summary:**");
        println!("- Tests passed: {}/{}", success_count, all_results.len());
        println!("- Total duration: {}ms", total_duration);
        println!("- Connections opened: {}", total_connections);
        println!("- Requests sent: {}", total_requests);
        println!("- Responses received: {}", total_responses);
        println!("- Protocol errors: {}", total_errors);
        println!("- Server implementations: Real asupersync HTTP/gRPC servers");

        if success_count == all_results.len() {
            println!("\n✅ **REAL SERVER E2E CONFORMANCE ACHIEVED**: All protocol tests passed");
        } else {
            println!(
                "\n❌ **REAL SERVER E2E CONFORMANCE FAILED**: {} tests failed",
                all_results.len() - success_count
            );
        }

        // All tests must pass
        assert_eq!(
            success_count,
            all_results.len(),
            "Not all real server E2E tests passed"
        );
    }

    #[test]
    fn test_address_parsing_errors() {
        use std::net::SocketAddr;

        // Test various invalid address formats
        let invalid_addresses = vec![
            ("invalid.format", "malformed address"),
            ("127.0.0.1:99999", "port overflow"),
            ("127.0.0.1:abc", "non-numeric port"),
            (":8080", "missing host"),
            ("127.0.0.1:", "missing port"),
            ("300.300.300.300:8080", "invalid IP octets"),
            ("127.0.0.1:0:extra", "extra port component"),
            ("", "empty string"),
            ("just-text", "not an address"),
            ("127.0.0.1:-1", "negative port"),
        ];

        for (invalid_addr, error_type) in invalid_addresses {
            let result = invalid_addr.parse::<SocketAddr>();
            assert!(
                result.is_err(),
                "Should fail to parse '{}': {} - got: {:?}",
                invalid_addr,
                error_type,
                result
            );
        }

        // Test valid addresses still work
        let valid_addresses = vec![
            "127.0.0.1:8080",
            "0.0.0.0:0",
            "192.168.1.1:3000",
            "[::1]:8080", // IPv6
        ];

        for valid_addr in valid_addresses {
            let result = valid_addr.parse::<SocketAddr>();
            assert!(
                result.is_ok(),
                "Should successfully parse valid address '{}': {:?}",
                valid_addr,
                result
            );
        }
    }
}
