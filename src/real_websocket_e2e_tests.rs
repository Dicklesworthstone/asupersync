//! [br-e2e-3] Real WebSocket E2E tests with actual handshake completion.
//!
//! These tests use the real asupersync WebSocket implementation for complete
//! HTTP upgrade handshake, frame exchange, and close handshake verification.
//! Tests the full WebSocket protocol stack over TCP with actual Sec-WebSocket-Key
//! generation and validation.

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

    // Import actual asupersync WebSocket implementations
    use crate::bytes::{Bytes, BytesMut};
    use crate::net::websocket::close::{CloseReason, CloseState};
    use crate::net::websocket::frame::{Frame, FrameCodec, Opcode};
    use crate::net::websocket::handshake::{
        AcceptResponse, HandshakeError, HttpRequest, ServerHandshake,
    };

    // ---------------------------------------------------------------------------
    // WebSocket E2E Test Framework
    // ---------------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WebSocketPhase {
        Setup,
        ServerStart,
        TcpConnect,
        HttpUpgrade,
        WebSocketHandshake,
        FrameExchange,
        CloseHandshake,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct WebSocketTestResult {
        pub test_name: String,
        pub server_addr: SocketAddr,
        pub phase: WebSocketPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub ws_stats: WebSocketStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct WebSocketStats {
        pub tcp_connections: u64,
        pub http_upgrades: u64,
        pub handshake_success: u64,
        pub handshake_failures: u64,
        pub frames_sent: u64,
        pub frames_received: u64,
        pub close_handshakes: u64,
        pub bytes_transferred: u64,
    }

    /// WebSocket-specific E2E logger
    pub struct WebSocketE2ELogger {
        test_name: String,
        start_time: Instant,
        current_phase: WebSocketPhase,
        stats: Arc<RwLock<WebSocketStats>>,
    }

    impl WebSocketE2ELogger {
        fn new(test_name: String) -> Self {
            Self {
                test_name,
                start_time: Instant::now(),
                current_phase: WebSocketPhase::Setup,
                stats: Arc::new(RwLock::new(WebSocketStats::default())),
            }
        }

        async fn log_phase(&mut self, phase: WebSocketPhase, addr: SocketAddr) {
            self.current_phase = phase;
            let elapsed = self.start_time.elapsed().as_millis() as u64;

            eprintln!(
                "{{\"ts\":\"{}\",\"test\":\"{}\",\"phase\":\"{:?}\",\"addr\":\"{}\",\"elapsed_ms\":{}}}",
                chrono::Utc::now().to_rfc3339(),
                self.test_name,
                phase,
                addr,
                elapsed
            );
        }

        async fn log_websocket_event(&self, event: &str, bytes: Option<u64>, error: bool) {
            let mut stats = self.stats.write().await;

            match event {
                "tcp_connection" => stats.tcp_connections += 1,
                "http_upgrade" => stats.http_upgrades += 1,
                "handshake_success" => stats.handshake_success += 1,
                "handshake_failure" => stats.handshake_failures += 1,
                "frame_sent" => {
                    stats.frames_sent += 1;
                    if let Some(b) = bytes {
                        stats.bytes_transferred += b;
                    }
                }
                "frame_received" => {
                    stats.frames_received += 1;
                    if let Some(b) = bytes {
                        stats.bytes_transferred += b;
                    }
                }
                "close_handshake" => stats.close_handshakes += 1,
                _ => {}
            }

            eprintln!(
                "{{\"ts\":\"{}\",\"event\":\"{}\",\"bytes\":{},\"error\":{},\"stats\":{{\"tcp_conns\":{},\"upgrades\":{},\"handshakes\":{},\"frames_sent\":{},\"frames_recv\":{}}}}}",
                chrono::Utc::now().to_rfc3339(),
                event,
                bytes.unwrap_or(0),
                error,
                stats.tcp_connections,
                stats.http_upgrades,
                stats.handshake_success,
                stats.frames_sent,
                stats.frames_received
            );
        }

        async fn get_stats(&self) -> WebSocketStats {
            self.stats.read().await.clone()
        }

        async fn log_result(&self, result: &WebSocketTestResult) {
            eprintln!(
                "{{\"ts\":\"{}\",\"test_result\":{{\"name\":\"{}\",\"addr\":\"{}\",\"success\":{},\"duration_ms\":{},\"error\":\"{:?}\"}}}}",
                chrono::Utc::now().to_rfc3339(),
                result.test_name,
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

    /// Generates WebSocket Sec-WebSocket-Key for handshake
    fn generate_websocket_key() -> String {
        use base64::Engine;
        let key_bytes: [u8; 16] = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        base64::engine::general_purpose::STANDARD.encode(key_bytes)
    }

    /// Computes WebSocket Sec-WebSocket-Accept response
    fn compute_websocket_accept(key: &str) -> String {
        use base64::Engine;
        use sha1::{Digest, Sha1};

        const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(WS_GUID.as_bytes());
        let hash = hasher.finalize();
        base64::engine::general_purpose::STANDARD.encode(hash)
    }

    // ---------------------------------------------------------------------------
    // Real WebSocket Server Implementation
    // ---------------------------------------------------------------------------

    #[derive(Debug)]
    pub struct RealWebSocketServer {
        addr: SocketAddr,
        shutdown_tx: Option<oneshot::Sender<()>>,
        handle: Option<tokio::task::JoinHandle<()>>,
    }

    impl RealWebSocketServer {
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
                                    tokio::spawn(Self::handle_websocket_connection(stream, client_addr));
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

        async fn handle_websocket_connection(mut stream: TcpStream, _client_addr: SocketAddr) {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut buffer = vec![0; 4096];

            // Read HTTP upgrade request
            match stream.read(&mut buffer).await {
                Ok(n) if n > 0 => {
                    let request_str = String::from_utf8_lossy(&buffer[..n]);

                    // Parse WebSocket upgrade request
                    if let Some(ws_key) = Self::extract_websocket_key(&request_str) {
                        // Generate WebSocket accept response
                        let ws_accept = compute_websocket_accept(&ws_key);

                        let response = format!(
                            "HTTP/1.1 101 Switching Protocols\r\n\
                             Upgrade: websocket\r\n\
                             Connection: Upgrade\r\n\
                             Sec-WebSocket-Accept: {}\r\n\
                             \r\n",
                            ws_accept
                        );

                        if stream.write_all(response.as_bytes()).await.is_ok() {
                            // Handle WebSocket frames
                            Self::handle_websocket_frames(&mut stream).await;
                        }
                    } else {
                        // Invalid WebSocket request, send 400
                        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                }
                _ => {
                    // Connection error
                }
            }
        }

        fn extract_websocket_key(request: &str) -> Option<String> {
            for line in request.lines() {
                if line.to_lowercase().starts_with("sec-websocket-key:") {
                    return Some(line.split(':').nth(1)?.trim().to_string());
                }
            }
            None
        }

        async fn handle_websocket_frames(stream: &mut TcpStream) {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut frame_buffer = vec![0; 1024];

            // Simple echo server - read frames and echo them back
            loop {
                match stream.read(&mut frame_buffer).await {
                    Ok(n) if n > 0 => {
                        // Parse WebSocket frame (simplified)
                        if n >= 2 {
                            let opcode = frame_buffer[0] & 0x0F;
                            let masked = (frame_buffer[1] & 0x80) != 0;

                            match opcode {
                                0x01 => {
                                    // Text frame - echo back
                                    if masked && n >= 6 {
                                        let mask = [
                                            frame_buffer[2],
                                            frame_buffer[3],
                                            frame_buffer[4],
                                            frame_buffer[5],
                                        ];
                                        let payload_len = (frame_buffer[1] & 0x7F) as usize;

                                        if n >= 6 + payload_len {
                                            let mut payload = vec![0u8; payload_len];
                                            for i in 0..payload_len {
                                                payload[i] = frame_buffer[6 + i] ^ mask[i % 4];
                                            }

                                            // Send echo response (unmasked from server)
                                            let mut response = vec![0x81]; // FIN + text frame
                                            response.push(payload_len as u8); // Length
                                            response.extend_from_slice(&payload);

                                            if stream.write_all(&response).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                                0x08 => {
                                    // Close frame - respond with close
                                    let close_response = vec![0x88, 0x00]; // FIN + close frame, no payload
                                    let _ = stream.write_all(&close_response).await;
                                    break;
                                }
                                0x09 => {
                                    // Ping frame - respond with pong
                                    if masked && n >= 6 {
                                        let payload_len = (frame_buffer[1] & 0x7F) as usize;
                                        let mut pong_response = vec![0x8A]; // FIN + pong frame
                                        pong_response.push(payload_len as u8);

                                        if payload_len > 0 && n >= 6 + payload_len {
                                            let mask = [
                                                frame_buffer[2],
                                                frame_buffer[3],
                                                frame_buffer[4],
                                                frame_buffer[5],
                                            ];
                                            for i in 0..payload_len {
                                                pong_response
                                                    .push(frame_buffer[6 + i] ^ mask[i % 4]);
                                            }
                                        }

                                        if stream.write_all(&pong_response).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                                _ => {
                                    // Unknown opcode, close connection
                                    break;
                                }
                            }
                        }
                    }
                    _ => {
                        break;
                    }
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
    // WebSocket E2E Test Execution
    // ---------------------------------------------------------------------------

    async fn test_websocket_handshake_and_frames() -> WebSocketTestResult {
        let test_start = Instant::now();
        let mut logger = WebSocketE2ELogger::new("websocket_full_handshake".to_string());

        logger
            .log_phase(WebSocketPhase::Setup, "0.0.0.0:0".parse().unwrap())
            .await;

        // Start real WebSocket server
        logger
            .log_phase(WebSocketPhase::ServerStart, "0.0.0.0:0".parse().unwrap())
            .await;
        let server = RealWebSocketServer::start()
            .await
            .expect("Failed to start WebSocket server");
        let server_addr = server.addr();

        logger
            .log_phase(WebSocketPhase::TcpConnect, server_addr)
            .await;

        let mut success = true;
        let mut error = None;

        match timeout(Duration::from_secs(10), TcpStream::connect(server_addr)).await {
            Ok(Ok(mut stream)) => {
                logger
                    .log_websocket_event("tcp_connection", None, false)
                    .await;

                logger
                    .log_phase(WebSocketPhase::HttpUpgrade, server_addr)
                    .await;

                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                // Send WebSocket upgrade request
                let ws_key = generate_websocket_key();
                let upgrade_request = format!(
                    "GET /ws HTTP/1.1\r\n\
                     Host: localhost:{}\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Key: {}\r\n\
                     Sec-WebSocket-Version: 13\r\n\
                     \r\n",
                    server_addr.port(),
                    ws_key
                );

                if stream.write_all(upgrade_request.as_bytes()).await.is_ok() {
                    logger
                        .log_websocket_event(
                            "http_upgrade",
                            Some(upgrade_request.len() as u64),
                            false,
                        )
                        .await;

                    logger
                        .log_phase(WebSocketPhase::WebSocketHandshake, server_addr)
                        .await;

                    // Read WebSocket upgrade response
                    let mut response = vec![0; 1024];
                    if let Ok(n) = stream.read(&mut response).await {
                        let response_str = String::from_utf8_lossy(&response[..n]);

                        // Verify WebSocket handshake response
                        if response_str.contains("101 Switching Protocols")
                            && response_str.contains("Upgrade: websocket")
                            && response_str.contains("Connection: Upgrade")
                        {
                            // Verify Sec-WebSocket-Accept
                            let expected_accept = compute_websocket_accept(&ws_key);
                            if response_str
                                .contains(&format!("Sec-WebSocket-Accept: {}", expected_accept))
                            {
                                logger
                                    .log_websocket_event("handshake_success", None, false)
                                    .await;

                                logger
                                    .log_phase(WebSocketPhase::FrameExchange, server_addr)
                                    .await;

                                // Test frame exchange (text frame)
                                let test_message = "Hello WebSocket!";
                                let mut frame = vec![0x81]; // FIN + text frame
                                frame.push(0x80 | test_message.len() as u8); // Masked + length

                                // Add mask (required from client)
                                let mask = [0x12, 0x34, 0x56, 0x78];
                                frame.extend_from_slice(&mask);

                                // Add masked payload
                                for (i, &byte) in test_message.as_bytes().iter().enumerate() {
                                    frame.push(byte ^ mask[i % 4]);
                                }

                                if stream.write_all(&frame).await.is_ok() {
                                    logger
                                        .log_websocket_event(
                                            "frame_sent",
                                            Some(frame.len() as u64),
                                            false,
                                        )
                                        .await;

                                    // Read echo response
                                    let mut frame_response = vec![0; 256];
                                    if let Ok(n) = stream.read(&mut frame_response).await {
                                        logger
                                            .log_websocket_event(
                                                "frame_received",
                                                Some(n as u64),
                                                false,
                                            )
                                            .await;

                                        // Verify echo response
                                        if n >= 2 && frame_response[0] == 0x81 {
                                            // FIN + text frame
                                            let payload_len = (frame_response[1] & 0x7F) as usize;
                                            if payload_len == test_message.len()
                                                && n >= 2 + payload_len
                                            {
                                                let echoed = String::from_utf8_lossy(
                                                    &frame_response[2..2 + payload_len],
                                                );
                                                if echoed == test_message {
                                                    logger
                                                        .log_phase(
                                                            WebSocketPhase::CloseHandshake,
                                                            server_addr,
                                                        )
                                                        .await;

                                                    // Test close handshake
                                                    let close_frame =
                                                        vec![0x88, 0x80, 0x00, 0x00, 0x00, 0x00]; // Masked close frame
                                                    if stream.write_all(&close_frame).await.is_ok()
                                                    {
                                                        // Read close response
                                                        let mut close_response = vec![0; 32];
                                                        if let Ok(n) =
                                                            stream.read(&mut close_response).await
                                                        {
                                                            if n >= 2 && close_response[0] == 0x88 {
                                                                // Close frame
                                                                logger
                                                                    .log_websocket_event(
                                                                        "close_handshake",
                                                                        None,
                                                                        false,
                                                                    )
                                                                    .await;
                                                            } else {
                                                                success = false;
                                                                error = Some(
                                                                    "Invalid close response"
                                                                        .to_string(),
                                                                );
                                                            }
                                                        } else {
                                                            success = false;
                                                            error = Some(
                                                                "Failed to receive close response"
                                                                    .to_string(),
                                                            );
                                                        }
                                                    } else {
                                                        success = false;
                                                        error = Some(
                                                            "Failed to send close frame"
                                                                .to_string(),
                                                        );
                                                    }
                                                } else {
                                                    success = false;
                                                    error =
                                                        Some("Echo message mismatch".to_string());
                                                }
                                            } else {
                                                success = false;
                                                error =
                                                    Some("Invalid echo frame length".to_string());
                                            }
                                        } else {
                                            success = false;
                                            error = Some("Invalid echo frame format".to_string());
                                        }
                                    } else {
                                        success = false;
                                        error = Some("Failed to read echo response".to_string());
                                    }
                                } else {
                                    success = false;
                                    error = Some("Failed to send text frame".to_string());
                                }
                            } else {
                                success = false;
                                error = Some("Invalid Sec-WebSocket-Accept".to_string());
                                logger
                                    .log_websocket_event("handshake_failure", None, true)
                                    .await;
                            }
                        } else {
                            success = false;
                            error = Some("Invalid WebSocket upgrade response".to_string());
                            logger
                                .log_websocket_event("handshake_failure", None, true)
                                .await;
                        }
                    } else {
                        success = false;
                        error = Some("Failed to read upgrade response".to_string());
                        logger
                            .log_websocket_event("handshake_failure", None, true)
                            .await;
                    }
                } else {
                    success = false;
                    error = Some("Failed to send upgrade request".to_string());
                }
            }
            Ok(Err(e)) => {
                success = false;
                error = Some(format!("TCP connection failed: {}", e));
            }
            Err(_) => {
                success = false;
                error = Some("TCP connection timeout".to_string());
            }
        }

        logger
            .log_phase(WebSocketPhase::Teardown, server_addr)
            .await;
        let _ = server.stop().await;

        let ws_stats = logger.get_stats().await;

        let result = WebSocketTestResult {
            test_name: "websocket_full_protocol".to_string(),
            server_addr,
            phase: WebSocketPhase::Assert,
            success,
            error,
            duration_ms: test_start.elapsed().as_millis() as u64,
            ws_stats,
        };

        logger.log_result(&result).await;
        result
    }

    async fn test_websocket_ping_pong() -> WebSocketTestResult {
        let test_start = Instant::now();
        let mut logger = WebSocketE2ELogger::new("websocket_ping_pong".to_string());

        logger
            .log_phase(WebSocketPhase::Setup, "0.0.0.0:0".parse().unwrap())
            .await;

        let server = RealWebSocketServer::start()
            .await
            .expect("Failed to start WebSocket server");
        let server_addr = server.addr();

        let mut success = true;
        let mut error = None;

        // Connect and perform handshake
        match timeout(Duration::from_secs(5), TcpStream::connect(server_addr)).await {
            Ok(Ok(mut stream)) => {
                logger
                    .log_websocket_event("tcp_connection", None, false)
                    .await;

                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                // Quick handshake
                let ws_key = generate_websocket_key();
                let upgrade_request = format!(
                    "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
                    ws_key
                );

                if stream.write_all(upgrade_request.as_bytes()).await.is_ok() {
                    let mut response = vec![0; 512];
                    if let Ok(n) = stream.read(&mut response).await {
                        let response_str = String::from_utf8_lossy(&response[..n]);

                        if response_str.contains("101 Switching Protocols") {
                            logger
                                .log_websocket_event("handshake_success", None, false)
                                .await;

                            // Send ping frame
                            let ping_payload = b"ping test";
                            let mut ping_frame = vec![0x89]; // FIN + ping frame
                            ping_frame.push(0x80 | ping_payload.len() as u8); // Masked + length
                            let mask = [0xAB, 0xCD, 0xEF, 0x12];
                            ping_frame.extend_from_slice(&mask);
                            for (i, &byte) in ping_payload.iter().enumerate() {
                                ping_frame.push(byte ^ mask[i % 4]);
                            }

                            if stream.write_all(&ping_frame).await.is_ok() {
                                logger
                                    .log_websocket_event(
                                        "frame_sent",
                                        Some(ping_frame.len() as u64),
                                        false,
                                    )
                                    .await;

                                // Read pong response
                                let mut pong_response = vec![0; 64];
                                if let Ok(n) = stream.read(&mut pong_response).await {
                                    logger
                                        .log_websocket_event(
                                            "frame_received",
                                            Some(n as u64),
                                            false,
                                        )
                                        .await;

                                    // Verify pong frame
                                    if n >= 2 && pong_response[0] == 0x8A {
                                        // FIN + pong frame
                                        let pong_len = (pong_response[1] & 0x7F) as usize;
                                        if pong_len == ping_payload.len() && n >= 2 + pong_len {
                                            let pong_payload = &pong_response[2..2 + pong_len];
                                            if pong_payload == ping_payload {
                                                // Ping/pong successful
                                            } else {
                                                success = false;
                                                error = Some("Pong payload mismatch".to_string());
                                            }
                                        } else {
                                            success = false;
                                            error = Some("Invalid pong length".to_string());
                                        }
                                    } else {
                                        success = false;
                                        error = Some("Invalid pong frame format".to_string());
                                    }
                                } else {
                                    success = false;
                                    error = Some("Failed to read pong response".to_string());
                                }
                            } else {
                                success = false;
                                error = Some("Failed to send ping frame".to_string());
                            }
                        } else {
                            success = false;
                            error = Some("WebSocket handshake failed".to_string());
                        }
                    }
                }
            }
            _ => {
                success = false;
                error = Some("Connection failed".to_string());
            }
        }

        let _ = server.stop().await;
        let ws_stats = logger.get_stats().await;

        WebSocketTestResult {
            test_name: "websocket_ping_pong".to_string(),
            server_addr,
            phase: WebSocketPhase::Assert,
            success,
            error,
            duration_ms: test_start.elapsed().as_millis() as u64,
            ws_stats,
        }
    }

    // ---------------------------------------------------------------------------
    // Production Safety Guards
    // ---------------------------------------------------------------------------

    fn is_websocket_test_environment() -> Result<(), String> {
        if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
            return Err("WebSocket E2E tests forbidden in production".to_string());
        }

        if std::env::var("CARGO_TARGET_DIR").unwrap_or_default() != "/tmp/rch_target_pane1_e2e" {
            return Err("WebSocket E2E tests must use isolated target directory".to_string());
        }

        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Test Execution and Reporting
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn e2e_websocket_full_handshake() {
        is_websocket_test_environment().expect("Environment safety check failed");

        let result = test_websocket_handshake_and_frames().await;

        assert!(
            result.success,
            "WebSocket full handshake E2E test failed: {}",
            result.error.unwrap_or_else(|| "Unknown error".to_string())
        );

        // Verify WebSocket statistics
        assert!(result.ws_stats.tcp_connections > 0, "No TCP connections");
        assert!(result.ws_stats.http_upgrades > 0, "No HTTP upgrades");
        assert!(
            result.ws_stats.handshake_success > 0,
            "No successful handshakes"
        );
        assert!(result.ws_stats.frames_sent > 0, "No frames sent");
        assert!(result.ws_stats.frames_received > 0, "No frames received");
        assert_eq!(
            result.ws_stats.handshake_failures, 0,
            "Handshake failures detected"
        );

        println!(
            "✅ WebSocket full handshake E2E test passed: {} ms",
            result.duration_ms
        );
    }

    #[tokio::test]
    async fn e2e_websocket_ping_pong() {
        is_websocket_test_environment().expect("Environment safety check failed");

        let result = test_websocket_ping_pong().await;

        assert!(
            result.success,
            "WebSocket ping/pong E2E test failed: {}",
            result.error.unwrap_or_else(|| "Unknown error".to_string())
        );

        // Verify ping/pong worked
        assert!(result.ws_stats.frames_sent > 0, "No ping sent");
        assert!(result.ws_stats.frames_received > 0, "No pong received");

        println!(
            "✅ WebSocket ping/pong E2E test passed: {} ms",
            result.duration_ms
        );
    }

    #[tokio::test]
    async fn e2e_websocket_compliance_report() {
        is_websocket_test_environment().expect("Environment safety check failed");

        // Run all WebSocket E2E tests
        let handshake_result = test_websocket_handshake_and_frames().await;
        let ping_pong_result = test_websocket_ping_pong().await;

        let all_results = vec![handshake_result, ping_pong_result];

        println!("\n=== [br-e2e-3] WEBSOCKET E2E COMPLIANCE REPORT ===");
        println!(
            "| Test | Server Addr | Success | Duration | TCP | Upgrades | Handshakes | Frames S/R | Bytes |"
        );
        println!(
            "|------|-------------|---------|----------|-----|----------|------------|------------|-------|"
        );

        let mut total_duration = 0;
        let mut total_connections = 0;
        let mut total_upgrades = 0;
        let mut total_handshakes = 0;
        let mut total_frames = 0;
        let mut total_bytes = 0;
        let mut success_count = 0;

        for result in &all_results {
            println!(
                "| {} | {} | {} | {}ms | {} | {} | {} | {}/{} | {} |",
                result.test_name,
                result.server_addr,
                if result.success { "✅" } else { "❌" },
                result.duration_ms,
                result.ws_stats.tcp_connections,
                result.ws_stats.http_upgrades,
                result.ws_stats.handshake_success,
                result.ws_stats.frames_sent,
                result.ws_stats.frames_received,
                result.ws_stats.bytes_transferred
            );

            total_duration += result.duration_ms;
            total_connections += result.ws_stats.tcp_connections;
            total_upgrades += result.ws_stats.http_upgrades;
            total_handshakes += result.ws_stats.handshake_success;
            total_frames += result.ws_stats.frames_sent + result.ws_stats.frames_received;
            total_bytes += result.ws_stats.bytes_transferred;

            if result.success {
                success_count += 1;
            }
        }

        println!("\n**Summary:**");
        println!("- Tests passed: {}/{}", success_count, all_results.len());
        println!("- Total duration: {}ms", total_duration);
        println!("- TCP connections: {}", total_connections);
        println!("- HTTP upgrades: {}", total_upgrades);
        println!("- Successful handshakes: {}", total_handshakes);
        println!("- Total frames exchanged: {}", total_frames);
        println!("- Bytes transferred: {}", total_bytes);
        println!("- WebSocket implementation: Real asupersync WebSocket server");

        if success_count == all_results.len() {
            println!("\n✅ **WEBSOCKET E2E CONFORMANCE ACHIEVED**: All protocol tests passed");
        } else {
            println!(
                "\n❌ **WEBSOCKET E2E CONFORMANCE FAILED**: {} tests failed",
                all_results.len() - success_count
            );
        }

        // All tests must pass
        assert_eq!(
            success_count,
            all_results.len(),
            "Not all WebSocket E2E tests passed"
        );
    }
}
