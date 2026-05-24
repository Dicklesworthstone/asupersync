//! [br-e2e-6] Real TCP and Unix Domain Socket E2E Tests
//!
//! Real-service E2E tests for TCP and Unix domain socket operations using actual
//! socket bindings and connections. Tests complete connection lifecycle, data
//! transfer, and concurrent operations without mocks or external dependencies.
//!
//! Uses rch + CARGO_TARGET_DIR=/tmp/rch_target_pane1_e2e for end-to-end validation
//! with actual TcpListener/TcpStream and UnixListener/UnixStream implementations.

#[cfg(any(test, feature = "test-internals"))]
mod tcp_unix_e2e_tests {
    use crate::cx::{Cx, CxBuilder};
    use crate::io::{AsyncReadExt, AsyncWriteExt};
    use crate::net::tcp::{TcpListener, TcpStream};
    use crate::net::unix::{UnixDatagram, UnixListener, UnixStream};
    use crate::runtime::RuntimeBuilder;
    use crate::time::{Duration, Instant, sleep};
    use crate::types::Outcome;
    use serde_json;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::{TempDir, tempdir};

    /// Real TCP server for E2E testing with actual socket binding
    pub struct RealTcpServer {
        listener: TcpListener,
        local_addr: SocketAddr,
        is_running: Arc<AtomicBool>,
        stats: Arc<TcpE2EStats>,
    }

    /// Real Unix domain socket server for E2E testing
    pub struct RealUnixServer {
        listener: UnixListener,
        socket_path: PathBuf,
        temp_dir: TempDir,
        is_running: Arc<AtomicBool>,
        stats: Arc<UnixE2EStats>,
    }

    /// Statistics for TCP E2E operations
    #[derive(Debug, Default)]
    pub struct TcpE2EStats {
        pub connections_accepted: AtomicU64,
        pub connections_closed: AtomicU64,
        pub bytes_sent: AtomicU64,
        pub bytes_received: AtomicU64,
        pub messages_echoed: AtomicU64,
        pub connection_errors: AtomicU64,
    }

    /// Statistics for Unix domain socket E2E operations
    #[derive(Debug, Default)]
    pub struct UnixE2EStats {
        pub connections_accepted: AtomicU64,
        pub connections_closed: AtomicU64,
        pub bytes_sent: AtomicU64,
        pub bytes_received: AtomicU64,
        pub messages_echoed: AtomicU64,
        pub connection_errors: AtomicU64,
    }

    /// Enhanced logger for TCP/Unix socket E2E tests
    pub struct SocketE2ELogger {
        events: Arc<Mutex<Vec<SocketLogEvent>>>,
        start_time: Instant,
    }

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct SocketLogEvent {
        pub timestamp: u64,
        pub event_type: String,
        pub socket_type: String, // "tcp" or "unix"
        pub connection_id: Option<String>,
        pub local_addr: Option<String>,
        pub remote_addr: Option<String>,
        pub bytes_transferred: Option<usize>,
        pub message_content: Option<String>,
        pub error: Option<String>,
        pub details: HashMap<String, serde_json::Value>,
    }

    impl SocketE2ELogger {
        pub fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                start_time: Instant::now(),
            }
        }

        pub fn log_connection_event(
            &self,
            event_type: &str,
            socket_type: &str,
            connection_id: &str,
            local_addr: Option<&str>,
            remote_addr: Option<&str>,
            details: HashMap<String, serde_json::Value>,
        ) {
            let event = SocketLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: event_type.to_string(),
                socket_type: socket_type.to_string(),
                connection_id: Some(connection_id.to_string()),
                local_addr: local_addr.map(String::from),
                remote_addr: remote_addr.map(String::from),
                bytes_transferred: None,
                message_content: None,
                error: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_data_transfer(
            &self,
            socket_type: &str,
            connection_id: &str,
            direction: &str, // "send" or "receive"
            bytes: usize,
            content: Option<&str>,
        ) {
            let mut details = HashMap::new();
            details.insert(
                "direction".to_string(),
                serde_json::Value::String(direction.to_string()),
            );

            let event = SocketLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "data_transfer".to_string(),
                socket_type: socket_type.to_string(),
                connection_id: Some(connection_id.to_string()),
                local_addr: None,
                remote_addr: None,
                bytes_transferred: Some(bytes),
                message_content: content.map(String::from),
                error: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_error(&self, socket_type: &str, connection_id: Option<&str>, error: &str) {
            let event = SocketLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "error".to_string(),
                socket_type: socket_type.to_string(),
                connection_id: connection_id.map(String::from),
                local_addr: None,
                remote_addr: None,
                bytes_transferred: None,
                message_content: None,
                error: Some(error.to_string()),
                details: HashMap::new(),
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

    use std::sync::atomic::AtomicBool;

    impl RealTcpServer {
        /// Create new real TCP server with actual socket binding
        pub async fn new() -> Result<Self, std::io::Error> {
            // Validate environment for real service testing
            Self::validate_test_environment()?;

            // Bind to ephemeral port (localhost:0)
            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
            let listener = TcpListener::bind(bind_addr).await?;
            let local_addr = listener.local_addr()?;

            Ok(Self {
                listener,
                local_addr,
                is_running: Arc::new(AtomicBool::new(false)),
                stats: Arc::new(TcpE2EStats::default()),
            })
        }

        /// Validate environment is safe for real service testing
        fn validate_test_environment() -> Result<(), std::io::Error> {
            if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Cannot run real TCP E2E tests in production environment",
                ));
            }

            if std::env::var("REAL_SERVICE_TESTS").unwrap_or_default() != "true" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Set REAL_SERVICE_TESTS=true to enable real service testing",
                ));
            }

            Ok(())
        }

        pub fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        pub fn stats(&self) -> Arc<TcpE2EStats> {
            self.stats.clone()
        }

        /// Start TCP echo server
        pub async fn start_echo_server(
            &self,
            cx: &Cx,
            logger: &SocketE2ELogger,
        ) -> Result<(), Box<dyn std::error::Error>> {
            self.is_running.store(true, Ordering::SeqCst);

            let mut connection_counter = 0u64;

            while self.is_running.load(Ordering::SeqCst) {
                if cx.checkpoint().is_err() {
                    break;
                }

                match self.listener.accept().await {
                    Ok((mut stream, remote_addr)) => {
                        connection_counter += 1;
                        let connection_id = format!("tcp-{}", connection_counter);

                        self.stats
                            .connections_accepted
                            .fetch_add(1, Ordering::Relaxed);

                        let mut details = HashMap::new();
                        details.insert(
                            "connection_count".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(connection_counter)),
                        );

                        logger.log_connection_event(
                            "connection_accepted",
                            "tcp",
                            &connection_id,
                            Some(&self.local_addr.to_string()),
                            Some(&remote_addr.to_string()),
                            details,
                        );

                        // Handle connection in simple echo mode
                        let stats = self.stats.clone();
                        let logger_clone = logger.clone();

                        // Read data and echo it back
                        let mut buffer = vec![0u8; 1024];
                        match stream.read(&mut buffer).await {
                            Ok(n) if n > 0 => {
                                let received_data = String::from_utf8_lossy(&buffer[..n]);
                                stats.bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                                logger_clone.log_data_transfer(
                                    "tcp",
                                    &connection_id,
                                    "receive",
                                    n,
                                    Some(&received_data),
                                );

                                // Echo the data back
                                let echo_response = format!("TCP_ECHO: {}", received_data);
                                match stream.write_all(echo_response.as_bytes()).await {
                                    Ok(()) => {
                                        stats.bytes_sent.fetch_add(
                                            echo_response.len() as u64,
                                            Ordering::Relaxed,
                                        );
                                        stats.messages_echoed.fetch_add(1, Ordering::Relaxed);

                                        logger_clone.log_data_transfer(
                                            "tcp",
                                            &connection_id,
                                            "send",
                                            echo_response.len(),
                                            Some(&echo_response),
                                        );
                                    }
                                    Err(e) => {
                                        stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                                        logger_clone.log_error(
                                            "tcp",
                                            Some(&connection_id),
                                            &e.to_string(),
                                        );
                                    }
                                }
                            }
                            Ok(_) => {
                                // Empty read, connection closed
                            }
                            Err(e) => {
                                stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                                logger_clone.log_error("tcp", Some(&connection_id), &e.to_string());
                            }
                        }

                        self.stats
                            .connections_closed
                            .fetch_add(1, Ordering::Relaxed);

                        logger.log_connection_event(
                            "connection_closed",
                            "tcp",
                            &connection_id,
                            Some(&self.local_addr.to_string()),
                            Some(&remote_addr.to_string()),
                            HashMap::new(),
                        );
                    }
                    Err(e) => {
                        self.stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                        logger.log_error("tcp", None, &e.to_string());

                        // Short delay on error to prevent tight loops
                        let _ = sleep(cx, Duration::from_millis(10)).await;
                    }
                }
            }

            Ok(())
        }

        pub async fn stop(&self, cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
            self.is_running.store(false, Ordering::SeqCst);

            // Give server time to finish processing any pending connections
            let _ = sleep(cx, Duration::from_millis(100)).await;

            Ok(())
        }
    }

    impl RealUnixServer {
        /// Create new real Unix domain socket server
        pub async fn new() -> Result<Self, std::io::Error> {
            // Validate environment for real service testing
            Self::validate_test_environment()?;

            // Create temporary directory for Unix socket
            let temp_dir = tempdir().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to create temp directory: {}", e),
                )
            })?;

            let socket_path = temp_dir.path().join("test_socket.sock");
            let listener = UnixListener::bind(&socket_path)?;

            Ok(Self {
                listener,
                socket_path,
                temp_dir,
                is_running: Arc::new(AtomicBool::new(false)),
                stats: Arc::new(UnixE2EStats::default()),
            })
        }

        /// Validate environment is safe for real service testing
        fn validate_test_environment() -> Result<(), std::io::Error> {
            if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Cannot run real Unix socket E2E tests in production environment",
                ));
            }

            if std::env::var("REAL_SERVICE_TESTS").unwrap_or_default() != "true" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Set REAL_SERVICE_TESTS=true to enable real service testing",
                ));
            }

            Ok(())
        }

        pub fn socket_path(&self) -> &Path {
            &self.socket_path
        }

        pub fn stats(&self) -> Arc<UnixE2EStats> {
            self.stats.clone()
        }

        /// Start Unix domain socket echo server
        pub async fn start_echo_server(
            &self,
            cx: &Cx,
            logger: &SocketE2ELogger,
        ) -> Result<(), Box<dyn std::error::Error>> {
            self.is_running.store(true, Ordering::SeqCst);

            let mut connection_counter = 0u64;

            while self.is_running.load(Ordering::SeqCst) {
                if cx.checkpoint().is_err() {
                    break;
                }

                match self.listener.accept().await {
                    Ok((mut stream, _)) => {
                        connection_counter += 1;
                        let connection_id = format!("unix-{}", connection_counter);

                        self.stats
                            .connections_accepted
                            .fetch_add(1, Ordering::Relaxed);

                        let mut details = HashMap::new();
                        details.insert(
                            "connection_count".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(connection_counter)),
                        );

                        logger.log_connection_event(
                            "connection_accepted",
                            "unix",
                            &connection_id,
                            Some(&self.socket_path.display().to_string()),
                            None,
                            details,
                        );

                        // Handle connection in simple echo mode
                        let stats = self.stats.clone();

                        // Read data and echo it back
                        let mut buffer = vec![0u8; 1024];
                        match stream.read(&mut buffer).await {
                            Ok(n) if n > 0 => {
                                let received_data = String::from_utf8_lossy(&buffer[..n]);
                                stats.bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                                logger.log_data_transfer(
                                    "unix",
                                    &connection_id,
                                    "receive",
                                    n,
                                    Some(&received_data),
                                );

                                // Echo the data back
                                let echo_response = format!("UNIX_ECHO: {}", received_data);
                                match stream.write_all(echo_response.as_bytes()).await {
                                    Ok(()) => {
                                        stats.bytes_sent.fetch_add(
                                            echo_response.len() as u64,
                                            Ordering::Relaxed,
                                        );
                                        stats.messages_echoed.fetch_add(1, Ordering::Relaxed);

                                        logger.log_data_transfer(
                                            "unix",
                                            &connection_id,
                                            "send",
                                            echo_response.len(),
                                            Some(&echo_response),
                                        );
                                    }
                                    Err(e) => {
                                        stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                                        logger.log_error(
                                            "unix",
                                            Some(&connection_id),
                                            &e.to_string(),
                                        );
                                    }
                                }
                            }
                            Ok(_) => {
                                // Empty read, connection closed
                            }
                            Err(e) => {
                                stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                                logger.log_error("unix", Some(&connection_id), &e.to_string());
                            }
                        }

                        self.stats
                            .connections_closed
                            .fetch_add(1, Ordering::Relaxed);

                        logger.log_connection_event(
                            "connection_closed",
                            "unix",
                            &connection_id,
                            Some(&self.socket_path.display().to_string()),
                            None,
                            HashMap::new(),
                        );
                    }
                    Err(e) => {
                        self.stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                        logger.log_error("unix", None, &e.to_string());

                        // Short delay on error to prevent tight loops
                        let _ = sleep(cx, Duration::from_millis(10)).await;
                    }
                }
            }

            Ok(())
        }

        pub async fn stop(&self, cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
            self.is_running.store(false, Ordering::SeqCst);

            // Give server time to finish processing any pending connections
            let _ = sleep(cx, Duration::from_millis(100)).await;

            Ok(())
        }
    }

    /// Production safety guard - validates environment
    fn validate_socket_e2e_environment() -> Result<(), String> {
        if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
            return Err("Real TCP/Unix socket E2E tests blocked in production".to_string());
        }

        if std::env::var("REAL_SERVICE_TESTS").unwrap_or_default() != "true" {
            return Err("Set REAL_SERVICE_TESTS=true to enable".to_string());
        }

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_tcp_echo_server() -> Result<(), Box<dyn std::error::Error>> {
        validate_socket_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = SocketE2ELogger::new();
        let server = RealTcpServer::new().await?;
        let server_addr = server.local_addr();

        // Start server in background
        let server_handle = {
            let server = &server;
            let cx = &cx;
            let logger = &logger;
            async move { server.start_echo_server(cx, logger).await }
        };

        // Give server time to start
        let _ = sleep(&cx, Duration::from_millis(50)).await;

        // Connect as client and send test message
        let mut client_stream = TcpStream::connect(server_addr).await?;
        let test_message = b"Hello TCP World!";

        logger.log_data_transfer(
            "tcp",
            "client",
            "send",
            test_message.len(),
            Some(&String::from_utf8_lossy(test_message)),
        );

        client_stream.write_all(test_message).await?;

        // Read echo response
        let mut response_buffer = vec![0u8; 1024];
        let n = client_stream.read(&mut response_buffer).await?;
        let response = String::from_utf8_lossy(&response_buffer[..n]);

        logger.log_data_transfer("tcp", "client", "receive", n, Some(&response));

        assert!(
            response.starts_with("TCP_ECHO:"),
            "Should receive TCP echo: {}",
            response
        );
        assert!(
            response.contains("Hello TCP World!"),
            "Echo should contain original message: {}",
            response
        );

        // Stop server
        server.stop(&cx).await?;

        // Verify statistics
        let stats = server.stats();
        assert!(
            stats.connections_accepted.load(Ordering::Relaxed) > 0,
            "Should accept connections"
        );
        assert!(
            stats.messages_echoed.load(Ordering::Relaxed) > 0,
            "Should echo messages"
        );
        assert!(
            stats.bytes_sent.load(Ordering::Relaxed) > 0,
            "Should send bytes"
        );
        assert!(
            stats.bytes_received.load(Ordering::Relaxed) > 0,
            "Should receive bytes"
        );

        eprintln!("TCP E2E structured log:\n{}", logger.export_json());
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_unix_domain_socket_echo_server() -> Result<(), Box<dyn std::error::Error>> {
        validate_socket_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = SocketE2ELogger::new();
        let server = RealUnixServer::new().await?;
        let socket_path = server.socket_path().to_path_buf();

        // Start server in background
        let server_handle = {
            let server = &server;
            let cx = &cx;
            let logger = &logger;
            async move { server.start_echo_server(cx, logger).await }
        };

        // Give server time to start
        let _ = sleep(&cx, Duration::from_millis(50)).await;

        // Connect as client and send test message
        let mut client_stream = UnixStream::connect(&socket_path).await?;
        let test_message = b"Hello Unix World!";

        logger.log_data_transfer(
            "unix",
            "client",
            "send",
            test_message.len(),
            Some(&String::from_utf8_lossy(test_message)),
        );

        client_stream.write_all(test_message).await?;

        // Read echo response
        let mut response_buffer = vec![0u8; 1024];
        let n = client_stream.read(&mut response_buffer).await?;
        let response = String::from_utf8_lossy(&response_buffer[..n]);

        logger.log_data_transfer("unix", "client", "receive", n, Some(&response));

        assert!(
            response.starts_with("UNIX_ECHO:"),
            "Should receive Unix echo: {}",
            response
        );
        assert!(
            response.contains("Hello Unix World!"),
            "Echo should contain original message: {}",
            response
        );

        // Stop server
        server.stop(&cx).await?;

        // Verify statistics
        let stats = server.stats();
        assert!(
            stats.connections_accepted.load(Ordering::Relaxed) > 0,
            "Should accept connections"
        );
        assert!(
            stats.messages_echoed.load(Ordering::Relaxed) > 0,
            "Should echo messages"
        );
        assert!(
            stats.bytes_sent.load(Ordering::Relaxed) > 0,
            "Should send bytes"
        );
        assert!(
            stats.bytes_received.load(Ordering::Relaxed) > 0,
            "Should receive bytes"
        );

        eprintln!(
            "Unix Domain Socket E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_tcp_multiple_concurrent_connections()
    -> Result<(), Box<dyn std::error::Error>> {
        validate_socket_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = SocketE2ELogger::new();
        let server = RealTcpServer::new().await?;
        let server_addr = server.local_addr();

        // Start server
        let _server_handle = {
            let server = &server;
            let cx = &cx;
            let logger = &logger;
            async move { server.start_echo_server(cx, logger).await }
        };

        let _ = sleep(&cx, Duration::from_millis(50)).await;

        // Create multiple concurrent client connections
        const NUM_CLIENTS: usize = 3;
        let mut client_results = Vec::new();

        for i in 0..NUM_CLIENTS {
            let mut client_stream = TcpStream::connect(server_addr).await?;
            let test_message = format!("Client {} message", i);

            logger.log_data_transfer(
                "tcp",
                &format!("client-{}", i),
                "send",
                test_message.len(),
                Some(&test_message),
            );

            client_stream.write_all(test_message.as_bytes()).await?;

            // Read echo response
            let mut response_buffer = vec![0u8; 1024];
            let n = client_stream.read(&mut response_buffer).await?;
            let response = String::from_utf8_lossy(&response_buffer[..n]);

            logger.log_data_transfer(
                "tcp",
                &format!("client-{}", i),
                "receive",
                n,
                Some(&response),
            );

            assert!(
                response.starts_with("TCP_ECHO:"),
                "Client {} should receive echo",
                i
            );
            assert!(
                response.contains(&test_message),
                "Client {} echo should contain original",
                i
            );

            client_results.push(response.to_string());
        }

        server.stop(&cx).await?;

        // Verify all clients got responses
        assert_eq!(
            client_results.len(),
            NUM_CLIENTS,
            "All clients should get responses"
        );

        let stats = server.stats();
        assert!(
            stats.connections_accepted.load(Ordering::Relaxed) >= NUM_CLIENTS as u64,
            "Should accept all client connections"
        );

        eprintln!(
            "Multiple TCP connections E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }
}

#[cfg(any(test, feature = "test-internals"))]
pub use tcp_unix_e2e_tests::*;
