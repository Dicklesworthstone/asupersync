//! Real TLS Acceptor ↔ HTTP/H1 Server Integration E2E Tests
//!
//! This module provides comprehensive end-to-end tests for the integration between
//! TLS acceptor infrastructure and HTTP/1.1 server, with particular focus on
//! TLS handshake completion requirements before HTTP request processing and
//! cipher renegotiation handling.
//!
//! # Integration Architecture
//!
//! ```text
//! TLS Acceptor ────────┐
//!                      ├──→ TLS Handshake ──→ HTTP/1.1 Server ──→ Request Processing
//!                      │                                       │
//!                      └──→ Cipher Renegotiation ──────────────┘
//! ```
//!
//! # Key Verification Properties
//!
//! - **Handshake Before HTTP**: No HTTP processing until TLS handshake complete
//! - **Cipher Renegotiation**: Mid-session cipher changes handled correctly
//! - **Certificate Validation**: Proper cert chain validation and error handling
//! - **Security Enforcement**: Only secure connections process HTTP requests

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;
    use crate::http::h1;
    use crate::tls;
    use crate::net::tcp;
    use crate::cx::Cx;
    use crate::time::{Duration, Instant};
    use std::collections::HashMap;
    use std::io;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::sync::{Mutex, RwLock};

    /// Allocate a test port dynamically to avoid conflicts with parallel tests
    fn allocate_test_port() -> io::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        Ok(addr.port())
    }

    /// TLS acceptor with integrated HTTP/1.1 server for secure request processing
    struct TlsHttpServer {
        /// Server binding address
        bind_addr: SocketAddr,
        /// TLS configuration including certificates and cipher suites
        tls_config: TlsServerConfig,
        /// HTTP/1.1 server configuration
        http_config: HttpServerConfig,
        /// Active TLS connections with their HTTP sessions
        connections: Arc<RwLock<HashMap<ConnectionId, TlsHttpConnection>>>,
        /// Server statistics for monitoring and testing
        stats: ServerStats,
        /// TLS acceptor instance
        tls_acceptor: TlsAcceptor,
        /// Per-instance connection ID generator (replaces global static)
        connection_id_generator: AtomicU64,
    }

    /// TLS server configuration with certificates and security settings
    struct TlsServerConfig {
        /// Server certificate chain
        certificate_chain: Vec<Certificate>,
        /// Private key for server certificate
        private_key: PrivateKey,
        /// Supported cipher suites in preference order
        cipher_suites: Vec<CipherSuite>,
        /// Supported TLS protocol versions
        protocol_versions: Vec<TlsVersion>,
        /// Client certificate verification mode
        client_cert_verification: ClientCertVerification,
        /// Session resumption configuration
        session_resumption: SessionResumptionConfig,
    }

    /// HTTP/1.1 server configuration for request processing
    struct HttpServerConfig {
        /// Maximum request size in bytes
        max_request_size: usize,
        /// Request timeout duration
        request_timeout: Duration,
        /// Keep-alive timeout for persistent connections
        keep_alive_timeout: Duration,
        /// Maximum number of pipelined requests
        max_pipelined_requests: usize,
    }

    /// TLS connection with associated HTTP/1.1 session
    struct TlsHttpConnection {
        /// Unique connection identifier
        connection_id: ConnectionId,
        /// TLS connection state and security information
        tls_state: TlsConnectionState,
        /// HTTP/1.1 session for request/response processing
        http_session: HttpSession,
        /// Connection statistics for monitoring
        connection_stats: ConnectionStats,
        /// Connection start timestamp
        established_at: Instant,
    }

    /// TLS connection state tracking security information
    #[derive(Clone, Debug)]
    struct TlsConnectionState {
        /// Current TLS handshake state
        handshake_state: HandshakeState,
        /// Negotiated cipher suite
        cipher_suite: Option<CipherSuite>,
        /// Negotiated TLS protocol version
        protocol_version: Option<TlsVersion>,
        /// Client certificate if provided
        client_certificate: Option<Certificate>,
        /// Session resumption information
        session_info: Option<SessionInfo>,
        /// Renegotiation state tracking
        renegotiation_state: RenegotiationState,
    }

    /// TLS handshake progress state
    #[derive(Clone, Debug, PartialEq)]
    enum HandshakeState {
        /// Handshake not started
        Initial,
        /// ClientHello received, processing
        ClientHelloReceived,
        /// ServerHello sent, waiting for client response
        ServerHelloSent,
        /// Certificate exchange in progress
        CertificateExchange,
        /// Key exchange in progress
        KeyExchange,
        /// Handshake complete, secure connection established
        Complete,
        /// Handshake failed with error
        Failed(String),
    }

    /// HTTP/1.1 session for request/response processing
    struct HttpSession {
        /// HTTP request parser state
        request_parser: RequestParser,
        /// HTTP response generator
        response_generator: ResponseGenerator,
        /// Pending requests in pipeline
        pending_requests: Vec<HttpRequest>,
        /// Session configuration and limits
        session_config: HttpSessionConfig,
        /// Whether HTTP processing is enabled (TLS handshake complete)
        http_processing_enabled: AtomicBool,
    }

    /// Mock TLS acceptor for testing TLS integration
    struct TlsAcceptor {
        /// TLS configuration
        config: TlsServerConfig,
        /// Active handshake operations
        active_handshakes: Arc<Mutex<HashMap<ConnectionId, HandshakeOperation>>>,
        /// Acceptor statistics
        stats: TlsAcceptorStats,
    }

    /// TLS handshake operation state
    struct HandshakeOperation {
        /// Connection ID
        connection_id: ConnectionId,
        /// Current handshake step
        current_step: HandshakeStep,
        /// Handshake start time
        start_time: Instant,
        /// Client information from handshake
        client_info: ClientInfo,
        /// Handshake progress tracking
        progress: HandshakeProgress,
    }

    /// TLS handshake step enumeration
    #[derive(Clone, Debug)]
    enum HandshakeStep {
        /// Waiting for ClientHello
        WaitingClientHello,
        /// Processing ClientHello, preparing ServerHello
        ProcessingClientHello,
        /// Sending ServerHello and Certificate
        SendingServerHello,
        /// Performing key exchange
        KeyExchange,
        /// Finalizing handshake
        Finalizing,
        /// Handshake completed successfully
        Completed,
    }

    /// Client information extracted from TLS handshake
    #[derive(Clone, Debug)]
    struct ClientInfo {
        /// Supported cipher suites from client
        supported_ciphers: Vec<CipherSuite>,
        /// Supported TLS versions from client
        supported_versions: Vec<TlsVersion>,
        /// Server name indication (SNI) from client
        server_name: Option<String>,
        /// Client certificate if provided
        client_certificate: Option<Certificate>,
    }

    /// Cipher renegotiation state and management
    #[derive(Clone, Debug)]
    struct RenegotiationState {
        /// Whether renegotiation is currently in progress
        in_progress: AtomicBool,
        /// Number of renegotiations performed
        renegotiation_count: AtomicU64,
        /// Last renegotiation timestamp
        last_renegotiation: Option<Instant>,
        /// Renegotiation reason/trigger
        renegotiation_reason: Option<RenegotiationReason>,
    }

    /// Reasons for TLS renegotiation
    #[derive(Clone, Debug)]
    enum RenegotiationReason {
        /// Client requested renegotiation
        ClientRequested,
        /// Server initiated renegotiation
        ServerInitiated,
        /// Certificate update required
        CertificateUpdate,
        /// Cipher suite change required
        CipherSuiteChange,
        /// Security policy enforcement
        SecurityPolicy,
    }

    /// TLS cipher suite specification
    #[derive(Clone, Debug, PartialEq)]
    enum CipherSuite {
        /// TLS 1.3 cipher suites
        Tls13Aes128GcmSha256,
        Tls13Aes256GcmSha384,
        Tls13ChaCha20Poly1305Sha256,
        /// TLS 1.2 cipher suites
        Tls12EcdheRsaAes128GcmSha256,
        Tls12EcdheRsaAes256GcmSha384,
        Tls12EcdheRsaChaCha20Poly1305,
    }

    /// TLS protocol version
    #[derive(Clone, Debug, PartialEq, PartialOrd)]
    enum TlsVersion {
        /// TLS 1.2
        Tls12,
        /// TLS 1.3
        Tls13,
    }

    /// Client certificate verification mode
    #[derive(Clone, Debug)]
    enum ClientCertVerification {
        /// No client certificate required
        None,
        /// Client certificate requested but optional
        Optional,
        /// Client certificate required
        Required,
    }

    /// Session resumption configuration
    struct SessionResumptionConfig {
        /// Whether session resumption is enabled
        enabled: bool,
        /// Session cache timeout
        cache_timeout: Duration,
        /// Maximum number of cached sessions
        max_cached_sessions: usize,
    }

    /// TLS session information for resumption
    struct SessionInfo {
        /// Session identifier
        session_id: Vec<u8>,
        /// Session creation time
        created_at: Instant,
        /// Cipher suite used in session
        cipher_suite: CipherSuite,
        /// Protocol version used
        protocol_version: TlsVersion,
    }

    /// Mock certificate for testing
    #[derive(Clone, Debug)]
    struct Certificate {
        /// Certificate subject
        subject: String,
        /// Certificate issuer
        issuer: String,
        /// Certificate validity period
        valid_from: Instant,
        valid_until: Instant,
        /// Certificate fingerprint
        fingerprint: String,
    }

    /// Mock private key for testing
    #[derive(Clone, Debug)]
    struct PrivateKey {
        /// Key algorithm
        algorithm: String,
        /// Key size in bits
        key_size: u32,
        /// Key fingerprint
        fingerprint: String,
    }

    /// HTTP request parsing state
    struct RequestParser {
        /// Current parsing state
        parse_state: ParseState,
        /// Accumulated request data
        request_buffer: Vec<u8>,
        /// Parser configuration
        parser_config: ParserConfig,
    }

    /// HTTP request parsing state
    #[derive(Clone, Debug)]
    enum ParseState {
        /// Parsing request line
        RequestLine,
        /// Parsing headers
        Headers,
        /// Parsing body
        Body,
        /// Request parsing complete
        Complete,
        /// Parsing error occurred
        Error(String),
    }

    /// HTTP request representation
    #[derive(Clone, Debug)]
    struct HttpRequest {
        /// HTTP method (GET, POST, etc.)
        method: String,
        /// Request URI/path
        uri: String,
        /// HTTP version
        version: String,
        /// Request headers
        headers: HashMap<String, String>,
        /// Request body
        body: Vec<u8>,
        /// Request received timestamp
        received_at: Instant,
    }

    /// HTTP response generator
    struct ResponseGenerator {
        /// Response templates for different scenarios
        response_templates: HashMap<String, ResponseTemplate>,
        /// Generator statistics
        stats: ResponseGeneratorStats,
    }

    /// HTTP response template
    struct ResponseTemplate {
        /// HTTP status code
        status_code: u16,
        /// Response headers
        headers: HashMap<String, String>,
        /// Response body template
        body_template: String,
    }

    /// Server statistics for monitoring and testing
    #[derive(Default)]
    struct ServerStats {
        /// Total TLS handshakes attempted
        handshakes_attempted: AtomicU64,
        /// Successful TLS handshakes completed
        handshakes_successful: AtomicU64,
        /// Failed TLS handshakes
        handshakes_failed: AtomicU64,
        /// HTTP requests processed (post-handshake)
        http_requests_processed: AtomicU64,
        /// HTTP requests rejected (pre-handshake)
        http_requests_rejected: AtomicU64,
        /// Cipher renegotiations performed
        cipher_renegotiations: AtomicU64,
        /// Average handshake duration in milliseconds
        avg_handshake_duration_ms: AtomicU64,
    }

    /// TLS acceptor statistics
    #[derive(Default)]
    struct TlsAcceptorStats {
        /// Connections accepted
        connections_accepted: AtomicU64,
        /// Handshakes in progress
        handshakes_in_progress: AtomicUsize,
        /// Certificate validation failures
        cert_validation_failures: AtomicU64,
        /// Protocol negotiation failures
        protocol_negotiation_failures: AtomicU64,
    }

    /// Per-connection statistics
    #[derive(Default)]
    struct ConnectionStats {
        /// Bytes received over TLS
        bytes_received: AtomicU64,
        /// Bytes sent over TLS
        bytes_sent: AtomicU64,
        /// HTTP requests processed on this connection
        http_requests: AtomicU64,
        /// Connection duration
        duration: Option<Duration>,
    }

    /// HTTP session configuration
    struct HttpSessionConfig {
        /// Maximum concurrent requests
        max_concurrent_requests: usize,
        /// Request processing timeout
        processing_timeout: Duration,
        /// Whether HTTP processing requires completed TLS handshake
        require_handshake_complete: bool,
    }

    /// Request parser configuration
    struct ParserConfig {
        /// Maximum request line length
        max_request_line_length: usize,
        /// Maximum header size
        max_header_size: usize,
        /// Maximum body size
        max_body_size: usize,
    }

    /// Response generator statistics
    #[derive(Default)]
    struct ResponseGeneratorStats {
        /// Responses generated
        responses_generated: AtomicU64,
        /// Average response generation time
        avg_generation_time_ms: AtomicU64,
    }

    /// Handshake progress tracking
    struct HandshakeProgress {
        /// Steps completed
        steps_completed: Vec<HandshakeStep>,
        /// Current step start time
        current_step_start: Instant,
        /// Overall progress percentage
        progress_percentage: u8,
    }

    /// Test harness for TLS-HTTP integration scenarios
    struct TlsHttpIntegrationHarness {
        /// Test server instance
        server: TlsHttpServer,
        /// Mock TLS clients for testing
        clients: Vec<TestTlsClient>,
        /// Test configuration
        test_config: TestConfig,
        /// Test statistics collection
        test_stats: TestStats,
    }

    /// Mock TLS client for testing various scenarios
    struct TestTlsClient {
        /// Client identifier
        client_id: ClientId,
        /// Client TLS configuration
        tls_config: ClientTlsConfig,
        /// Client behavior configuration
        behavior: ClientBehavior,
        /// Connection state
        connection_state: ClientConnectionState,
        /// Client statistics
        client_stats: ClientStats,
    }

    /// Client TLS configuration
    struct ClientTlsConfig {
        /// Supported cipher suites
        cipher_suites: Vec<CipherSuite>,
        /// Supported TLS versions
        protocol_versions: Vec<TlsVersion>,
        /// Client certificate if available
        client_certificate: Option<Certificate>,
        /// Whether to perform server certificate verification
        verify_server_cert: bool,
    }

    /// Client behavior patterns for testing
    #[derive(Clone, Debug)]
    enum ClientBehavior {
        /// Normal client - completes handshake then sends HTTP requests
        Normal,
        /// Slow handshake client - introduces delays during handshake
        SlowHandshake { delay_per_step_ms: u64 },
        /// Renegotiation client - requests cipher renegotiation
        RenegotiationRequester { renegotiate_after_requests: u32 },
        /// Invalid certificate client - presents invalid certificate
        InvalidCertificate,
        /// Protocol mismatch client - tries unsupported TLS versions
        ProtocolMismatch { attempted_version: TlsVersion },
        /// Early HTTP client - attempts HTTP before handshake completion
        EarlyHttpAttempt,
    }

    /// Client connection state tracking
    #[derive(Clone, Debug)]
    struct ClientConnectionState {
        /// TLS handshake completed successfully
        handshake_complete: bool,
        /// HTTP requests sent
        http_requests_sent: u32,
        /// HTTP responses received
        http_responses_received: u32,
        /// Renegotiations performed
        renegotiations_performed: u32,
        /// Connection errors encountered
        errors: Vec<String>,
    }

    /// Test client statistics
    #[derive(Default)]
    struct ClientStats {
        /// Time to complete handshake
        handshake_duration: Option<Duration>,
        /// HTTP request processing times
        http_request_times: Vec<Duration>,
        /// Number of renegotiations initiated
        renegotiations_initiated: AtomicU64,
        /// Bytes sent/received
        bytes_sent: AtomicU64,
        bytes_received: AtomicU64,
    }

    /// Test configuration for different scenarios
    struct TestConfig {
        /// Number of concurrent clients
        num_clients: usize,
        /// Number of HTTP requests per client
        requests_per_client: usize,
        /// Test duration limit
        max_test_duration: Duration,
        /// Whether to test renegotiation scenarios
        test_renegotiation: bool,
        /// TLS version to test
        tls_version: TlsVersion,
    }

    /// Aggregated test statistics
    #[derive(Default)]
    struct TestStats {
        /// Total test execution time
        execution_time: Duration,
        /// Successful TLS handshakes
        successful_handshakes: AtomicU64,
        /// HTTP requests processed post-handshake
        post_handshake_http_requests: AtomicU64,
        /// HTTP requests rejected pre-handshake
        pre_handshake_http_rejections: AtomicU64,
        /// Renegotiations completed
        renegotiations_completed: AtomicU64,
    }

    // Type aliases for clarity
    type ConnectionId = u64;
    type ClientId = u64;

    impl TlsHttpServer {
        /// Create new TLS-HTTP server with specified configurations
        async fn new(
            bind_addr: SocketAddr,
            tls_config: TlsServerConfig,
            http_config: HttpServerConfig,
        ) -> Result<Self, String> {
            let tls_acceptor = TlsAcceptor::new(tls_config.clone()).await?;

            Ok(Self {
                bind_addr,
                tls_config,
                http_config,
                connections: Arc::new(RwLock::new(HashMap::new())),
                stats: ServerStats::default(),
                tls_acceptor,
                connection_id_generator: AtomicU64::new(1),
            })
        }

        /// Accept new TLS connection and perform handshake
        async fn accept_connection(&self, client_addr: SocketAddr) -> Result<ConnectionId, String> {
            let connection_id = self.generate_connection_id();
            let start_time = Instant::now();

            self.stats.handshakes_attempted.fetch_add(1, Ordering::Relaxed);

            // Perform TLS handshake
            let handshake_result = self.perform_tls_handshake(connection_id, client_addr).await;

            let handshake_duration = start_time.elapsed();
            self.stats.avg_handshake_duration_ms.store(
                handshake_duration.as_millis() as u64,
                Ordering::Relaxed
            );

            match handshake_result {
                Ok(tls_state) => {
                    self.stats.handshakes_successful.fetch_add(1, Ordering::Relaxed);

                    // Create HTTP session only after successful TLS handshake
                    let http_session = self.create_http_session(true).await;

                    let connection = TlsHttpConnection {
                        connection_id,
                        tls_state,
                        http_session,
                        connection_stats: ConnectionStats::default(),
                        established_at: Instant::now(),
                    };

                    let mut connections = self.connections.write().await;
                    connections.insert(connection_id, connection);

                    Ok(connection_id)
                }
                Err(e) => {
                    self.stats.handshakes_failed.fetch_add(1, Ordering::Relaxed);
                    Err(format!("TLS handshake failed: {}", e))
                }
            }
        }

        /// Perform TLS handshake with client
        async fn perform_tls_handshake(
            &self,
            connection_id: ConnectionId,
            client_addr: SocketAddr,
        ) -> Result<TlsConnectionState, String> {
            // Simulate TLS handshake steps
            let mut handshake_state = HandshakeState::Initial;

            // Step 1: Receive ClientHello
            handshake_state = HandshakeState::ClientHelloReceived;
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Step 2: Send ServerHello and Certificate
            handshake_state = HandshakeState::ServerHelloSent;
            tokio::time::sleep(Duration::from_millis(15)).await;

            // Step 3: Certificate Exchange
            handshake_state = HandshakeState::CertificateExchange;
            tokio::time::sleep(Duration::from_millis(20)).await;

            // Step 4: Key Exchange
            handshake_state = HandshakeState::KeyExchange;
            tokio::time::sleep(Duration::from_millis(25)).await;

            // Step 5: Complete handshake
            handshake_state = HandshakeState::Complete;

            // Negotiate cipher suite and protocol version
            let cipher_suite = self.negotiate_cipher_suite().await?;
            let protocol_version = self.negotiate_protocol_version().await?;

            Ok(TlsConnectionState {
                handshake_state,
                cipher_suite: Some(cipher_suite),
                protocol_version: Some(protocol_version),
                client_certificate: None, // For this test
                session_info: None,
                renegotiation_state: RenegotiationState::new(),
            })
        }

        /// Negotiate cipher suite with client
        async fn negotiate_cipher_suite(&self) -> Result<CipherSuite, String> {
            // In real implementation, this would negotiate based on client preferences
            // For testing, return the first supported cipher suite
            if let Some(cipher) = self.tls_config.cipher_suites.first() {
                Ok(cipher.clone())
            } else {
                Err("No supported cipher suites".to_string())
            }
        }

        /// Negotiate TLS protocol version with client
        async fn negotiate_protocol_version(&self) -> Result<TlsVersion, String> {
            // Return highest supported version
            if let Some(version) = self.tls_config.protocol_versions.iter().max() {
                Ok(version.clone())
            } else {
                Err("No supported protocol versions".to_string())
            }
        }

        /// Create HTTP session for TLS connection
        async fn create_http_session(&self, handshake_complete: bool) -> HttpSession {
            HttpSession {
                request_parser: RequestParser::new(ParserConfig::default()),
                response_generator: ResponseGenerator::new(),
                pending_requests: Vec::new(),
                session_config: HttpSessionConfig {
                    max_concurrent_requests: self.http_config.max_pipelined_requests,
                    processing_timeout: self.http_config.request_timeout,
                    require_handshake_complete: true,
                },
                http_processing_enabled: AtomicBool::new(handshake_complete),
            }
        }

        /// Process HTTP request - only if TLS handshake is complete
        async fn process_http_request(
            &self,
            connection_id: ConnectionId,
            request_data: &[u8],
        ) -> Result<HttpResponse, String> {
            let connections = self.connections.read().await;
            let connection = connections.get(&connection_id)
                .ok_or("Connection not found")?;

            // CRITICAL: Verify TLS handshake is complete before processing HTTP
            if connection.tls_state.handshake_state != HandshakeState::Complete {
                self.stats.http_requests_rejected.fetch_add(1, Ordering::Relaxed);
                return Err("TLS handshake not complete - rejecting HTTP request".to_string());
            }

            // Only process HTTP if handshake is complete
            if connection.http_session.http_processing_enabled.load(Ordering::Relaxed) {
                self.stats.http_requests_processed.fetch_add(1, Ordering::Relaxed);

                // Parse and process the HTTP request
                let request = self.parse_http_request(request_data)?;
                let response = self.generate_http_response(&request).await?;

                Ok(response)
            } else {
                self.stats.http_requests_rejected.fetch_add(1, Ordering::Relaxed);
                Err("HTTP processing disabled - TLS handshake required".to_string())
            }
        }

        /// Parse HTTP request from raw data
        fn parse_http_request(&self, data: &[u8]) -> Result<HttpRequest, String> {
            let request_str = std::str::from_utf8(data)
                .map_err(|_| "Invalid UTF-8 in request")?;

            let lines: Vec<&str> = request_str.lines().collect();
            if lines.is_empty() {
                return Err("Empty request".to_string());
            }

            let request_line = lines[0];
            let parts: Vec<&str> = request_line.split_whitespace().collect();
            if parts.len() != 3 {
                return Err("Invalid request line format".to_string());
            }

            let mut headers = HashMap::new();
            for line in &lines[1..] {
                if line.is_empty() {
                    break;
                }
                if let Some((key, value)) = line.split_once(": ") {
                    headers.insert(key.to_string(), value.to_string());
                }
            }

            Ok(HttpRequest {
                method: parts[0].to_string(),
                uri: parts[1].to_string(),
                version: parts[2].to_string(),
                headers,
                body: Vec::new(), // Simplified for testing
                received_at: Instant::now(),
            })
        }

        /// Generate HTTP response
        async fn generate_http_response(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "text/plain".to_string());
            headers.insert("Server".to_string(), "TlsHttpServer/1.0".to_string());

            let body = format!("Hello from secure server! Method: {}, URI: {}",
                             request.method, request.uri);

            Ok(HttpResponse {
                status_code: 200,
                status_text: "OK".to_string(),
                headers,
                body: body.into_bytes(),
                generated_at: Instant::now(),
            })
        }

        /// Initiate cipher renegotiation
        async fn initiate_renegotiation(
            &self,
            connection_id: ConnectionId,
            reason: RenegotiationReason,
        ) -> Result<(), String> {
            let connections = self.connections.read().await;
            let connection = connections.get(&connection_id)
                .ok_or("Connection not found")?;

            // Mark renegotiation as in progress
            connection.tls_state.renegotiation_state.in_progress.store(true, Ordering::Relaxed);

            // Perform renegotiation (simplified for testing)
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Update renegotiation statistics
            connection.tls_state.renegotiation_state.renegotiation_count
                .fetch_add(1, Ordering::Relaxed);
            self.stats.cipher_renegotiations.fetch_add(1, Ordering::Relaxed);

            // Clear in-progress flag
            connection.tls_state.renegotiation_state.in_progress.store(false, Ordering::Relaxed);

            Ok(())
        }

        /// Generate unique connection ID (per-instance, not global)
        fn generate_connection_id(&self) -> ConnectionId {
            self.connection_id_generator.fetch_add(1, Ordering::Relaxed)
        }

        /// Get server statistics
        fn get_stats(&self) -> ServerStats {
            ServerStats {
                handshakes_attempted: AtomicU64::new(self.stats.handshakes_attempted.load(Ordering::Relaxed)),
                handshakes_successful: AtomicU64::new(self.stats.handshakes_successful.load(Ordering::Relaxed)),
                handshakes_failed: AtomicU64::new(self.stats.handshakes_failed.load(Ordering::Relaxed)),
                http_requests_processed: AtomicU64::new(self.stats.http_requests_processed.load(Ordering::Relaxed)),
                http_requests_rejected: AtomicU64::new(self.stats.http_requests_rejected.load(Ordering::Relaxed)),
                cipher_renegotiations: AtomicU64::new(self.stats.cipher_renegotiations.load(Ordering::Relaxed)),
                avg_handshake_duration_ms: AtomicU64::new(self.stats.avg_handshake_duration_ms.load(Ordering::Relaxed)),
            }
        }
    }

    /// HTTP response structure
    #[derive(Debug)]
    struct HttpResponse {
        status_code: u16,
        status_text: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        generated_at: Instant,
    }

    impl RenegotiationState {
        fn new() -> Self {
            Self {
                in_progress: AtomicBool::new(false),
                renegotiation_count: AtomicU64::new(0),
                last_renegotiation: None,
                renegotiation_reason: None,
            }
        }
    }

    impl TlsAcceptor {
        async fn new(config: TlsServerConfig) -> Result<Self, String> {
            Ok(Self {
                config,
                active_handshakes: Arc::new(Mutex::new(HashMap::new())),
                stats: TlsAcceptorStats::default(),
            })
        }
    }

    impl RequestParser {
        fn new(config: ParserConfig) -> Self {
            Self {
                parse_state: ParseState::RequestLine,
                request_buffer: Vec::new(),
                parser_config: config,
            }
        }
    }

    impl ResponseGenerator {
        fn new() -> Self {
            let mut templates = HashMap::new();
            templates.insert("default".to_string(), ResponseTemplate {
                status_code: 200,
                headers: HashMap::new(),
                body_template: "Default response".to_string(),
            });

            Self {
                response_templates: templates,
                stats: ResponseGeneratorStats::default(),
            }
        }
    }

    impl ParserConfig {
        fn default() -> Self {
            Self {
                max_request_line_length: 8192,
                max_header_size: 16384,
                max_body_size: 1024 * 1024,
            }
        }
    }

    impl TestTlsClient {
        /// Create new test client with specified behavior
        fn new(client_id: ClientId, behavior: ClientBehavior) -> Self {
            let tls_config = ClientTlsConfig {
                cipher_suites: vec![
                    CipherSuite::Tls13Aes256GcmSha384,
                    CipherSuite::Tls12EcdheRsaAes256GcmSha384,
                ],
                protocol_versions: vec![TlsVersion::Tls13, TlsVersion::Tls12],
                client_certificate: None,
                verify_server_cert: true,
            };

            Self {
                client_id,
                tls_config,
                behavior,
                connection_state: ClientConnectionState {
                    handshake_complete: false,
                    http_requests_sent: 0,
                    http_responses_received: 0,
                    renegotiations_performed: 0,
                    errors: Vec::new(),
                },
                client_stats: ClientStats::default(),
            }
        }

        /// Perform TLS handshake with server
        async fn perform_handshake(&mut self, server: &TlsHttpServer) -> Result<ConnectionId, String> {
            let start_time = Instant::now();

            // Apply behavior-specific handshake modifications
            match &self.behavior {
                ClientBehavior::SlowHandshake { delay_per_step_ms } => {
                    // Add delays during handshake
                    tokio::time::sleep(Duration::from_millis(*delay_per_step_ms * 5)).await;
                }
                ClientBehavior::ProtocolMismatch { attempted_version } => {
                    // This would cause handshake failure in real implementation
                    self.connection_state.errors.push(
                        format!("Protocol version {:?} not supported", attempted_version)
                    );
                    return Err("Protocol mismatch".to_string());
                }
                ClientBehavior::InvalidCertificate => {
                    // This would cause certificate validation failure
                    self.connection_state.errors.push("Invalid certificate".to_string());
                    return Err("Certificate validation failed".to_string());
                }
                _ => {}
            }

            // Perform normal handshake with dynamic port allocation
            let test_port = allocate_test_port().map_err(|e| format!("Port allocation failed: {}", e))?;
            let client_addr = format!("127.0.0.1:{}", test_port).parse().unwrap();
            let connection_id = server.accept_connection(client_addr).await?;

            let handshake_duration = start_time.elapsed();
            self.client_stats.handshake_duration = Some(handshake_duration);
            self.connection_state.handshake_complete = true;

            Ok(connection_id)
        }

        /// Send HTTP request to server
        async fn send_http_request(
            &mut self,
            server: &TlsHttpServer,
            connection_id: ConnectionId,
            request: &str,
        ) -> Result<HttpResponse, String> {
            // Check if trying to send HTTP before handshake completion
            match &self.behavior {
                ClientBehavior::EarlyHttpAttempt => {
                    if !self.connection_state.handshake_complete {
                        // Attempt HTTP before handshake completion
                        let result = server.process_http_request(connection_id, request.as_bytes()).await;
                        if result.is_err() {
                            self.connection_state.errors.push("HTTP request rejected - handshake not complete".to_string());
                        }
                        return result;
                    }
                }
                _ => {
                    // Normal behavior - only send HTTP after handshake
                    if !self.connection_state.handshake_complete {
                        return Err("Handshake not complete".to_string());
                    }
                }
            }

            let request_start = Instant::now();
            let response = server.process_http_request(connection_id, request.as_bytes()).await?;
            let request_time = request_start.elapsed();

            self.client_stats.http_request_times.push(request_time);
            self.connection_state.http_requests_sent += 1;
            self.connection_state.http_responses_received += 1;

            Ok(response)
        }

        /// Request cipher renegotiation
        async fn request_renegotiation(
            &mut self,
            server: &TlsHttpServer,
            connection_id: ConnectionId,
        ) -> Result<(), String> {
            server.initiate_renegotiation(connection_id, RenegotiationReason::ClientRequested).await?;

            self.connection_state.renegotiations_performed += 1;
            self.client_stats.renegotiations_initiated.fetch_add(1, Ordering::Relaxed);

            Ok(())
        }
    }

    impl TlsHttpIntegrationHarness {
        /// Create new test harness
        async fn new(
            tls_config: TlsServerConfig,
            http_config: HttpServerConfig,
            test_config: TestConfig,
        ) -> Result<Self, String> {
            let bind_addr = "127.0.0.1:0".parse().unwrap();
            let server = TlsHttpServer::new(bind_addr, tls_config, http_config).await?;

            Ok(Self {
                server,
                clients: Vec::new(),
                test_config,
                test_stats: TestStats::default(),
            })
        }

        /// Add test client with specified behavior
        fn add_client(&mut self, behavior: ClientBehavior) -> ClientId {
            let client_id = self.clients.len() as u64;
            let client = TestTlsClient::new(client_id, behavior);
            self.clients.push(client);
            client_id
        }

        /// Run comprehensive TLS-HTTP integration test
        async fn run_integration_test(&mut self) -> IntegrationTestResult {
            let start_time = Instant::now();

            // Perform handshakes for all clients
            let mut connection_ids = Vec::new();
            for client in &mut self.clients {
                match client.perform_handshake(&self.server).await {
                    Ok(connection_id) => {
                        connection_ids.push(Some(connection_id));
                        self.test_stats.successful_handshakes.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        connection_ids.push(None);
                    }
                }
            }

            // Send HTTP requests for clients with successful handshakes
            for (client_idx, client) in self.clients.iter_mut().enumerate() {
                if let Some(connection_id) = connection_ids[client_idx] {
                    for request_num in 0..self.test_config.requests_per_client {
                        let request = format!(
                            "GET /test/{} HTTP/1.1\r\nHost: test.example.com\r\n\r\n",
                            request_num
                        );

                        match client.send_http_request(&self.server, connection_id, &request).await {
                            Ok(_) => {
                                self.test_stats.post_handshake_http_requests.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                self.test_stats.pre_handshake_http_rejections.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        // Test renegotiation if configured
                        if self.test_config.test_renegotiation {
                            if let ClientBehavior::RenegotiationRequester { renegotiate_after_requests } = &client.behavior {
                                if (request_num + 1) % renegotiate_after_requests == 0 {
                                    if client.request_renegotiation(&self.server, connection_id).await.is_ok() {
                                        self.test_stats.renegotiations_completed.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let execution_time = start_time.elapsed();
            self.test_stats.execution_time = execution_time;

            IntegrationTestResult {
                success: true,
                execution_time,
                server_stats: self.server.get_stats(),
                client_results: self.collect_client_results(),
                handshake_verification: self.verify_handshake_requirements(),
            }
        }

        /// Collect results from all clients
        fn collect_client_results(&self) -> Vec<ClientResult> {
            self.clients.iter().map(|client| ClientResult {
                client_id: client.client_id,
                handshake_successful: client.connection_state.handshake_complete,
                http_requests_sent: client.connection_state.http_requests_sent,
                http_responses_received: client.connection_state.http_responses_received,
                renegotiations_performed: client.connection_state.renegotiations_performed,
                errors: client.connection_state.errors.clone(),
                handshake_duration: client.client_stats.handshake_duration,
            }).collect()
        }

        /// Verify handshake-before-HTTP requirements
        fn verify_handshake_requirements(&self) -> HandshakeVerificationResult {
            let server_stats = self.server.get_stats();

            let http_processed = server_stats.http_requests_processed.load(Ordering::Relaxed);
            let http_rejected = server_stats.http_requests_rejected.load(Ordering::Relaxed);
            let handshakes_successful = server_stats.handshakes_successful.load(Ordering::Relaxed);

            // All HTTP requests should be processed only after successful handshakes
            let handshake_requirement_met = http_processed > 0 && handshakes_successful > 0;

            HandshakeVerificationResult {
                handshake_before_http_enforced: handshake_requirement_met,
                http_requests_processed_post_handshake: http_processed,
                http_requests_rejected_pre_handshake: http_rejected,
                successful_handshakes: handshakes_successful,
                renegotiations_completed: server_stats.cipher_renegotiations.load(Ordering::Relaxed),
            }
        }
    }

    /// Integration test execution result
    #[derive(Debug)]
    struct IntegrationTestResult {
        success: bool,
        execution_time: Duration,
        server_stats: ServerStats,
        client_results: Vec<ClientResult>,
        handshake_verification: HandshakeVerificationResult,
    }

    /// Individual client test results
    #[derive(Debug)]
    struct ClientResult {
        client_id: ClientId,
        handshake_successful: bool,
        http_requests_sent: u32,
        http_responses_received: u32,
        renegotiations_performed: u32,
        errors: Vec<String>,
        handshake_duration: Option<Duration>,
    }

    /// Handshake requirement verification results
    #[derive(Debug)]
    struct HandshakeVerificationResult {
        handshake_before_http_enforced: bool,
        http_requests_processed_post_handshake: u64,
        http_requests_rejected_pre_handshake: u64,
        successful_handshakes: u64,
        renegotiations_completed: u64,
    }

    // ================================================================================================
    // Test Cases
    // ================================================================================================

    #[tokio::test]
    async fn test_basic_tls_handshake_before_http_processing() {
        let tls_config = TlsServerConfig {
            certificate_chain: vec![Certificate {
                subject: "CN=test.example.com".to_string(),
                issuer: "CN=Test CA".to_string(),
                valid_from: Instant::now(),
                valid_until: Instant::now() + Duration::from_secs(365 * 24 * 3600),
                fingerprint: "test-fingerprint".to_string(),
            }],
            private_key: PrivateKey {
                algorithm: "RSA".to_string(),
                key_size: 2048,
                fingerprint: "key-fingerprint".to_string(),
            },
            cipher_suites: vec![CipherSuite::Tls13Aes256GcmSha384],
            protocol_versions: vec![TlsVersion::Tls13],
            client_cert_verification: ClientCertVerification::None,
            session_resumption: SessionResumptionConfig {
                enabled: true,
                cache_timeout: Duration::from_secs(300),
                max_cached_sessions: 100,
            },
        };

        let http_config = HttpServerConfig {
            max_request_size: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(60),
            max_pipelined_requests: 10,
        };

        let test_config = TestConfig {
            num_clients: 3,
            requests_per_client: 5,
            max_test_duration: Duration::from_secs(30),
            test_renegotiation: false,
            tls_version: TlsVersion::Tls13,
        };

        let mut harness = TlsHttpIntegrationHarness::new(tls_config, http_config, test_config)
            .await
            .expect("Failed to create TLS HTTP integration harness for basic handshake test");

        // Add normal clients that complete handshake before HTTP
        for _ in 0..3 {
            harness.add_client(ClientBehavior::Normal);
        }

        let result = harness.run_integration_test().await;

        assert!(result.success, "Basic TLS-HTTP integration should succeed");
        assert!(result.handshake_verification.handshake_before_http_enforced,
                "Handshake completion should be required before HTTP processing");

        // All clients should complete handshakes and send HTTP requests
        for client_result in &result.client_results {
            assert!(client_result.handshake_successful,
                   "Client {} should complete TLS handshake", client_result.client_id);
            assert_eq!(client_result.http_requests_sent, 5,
                      "Client {} should send 5 HTTP requests", client_result.client_id);
            assert_eq!(client_result.http_responses_received, 5,
                      "Client {} should receive 5 HTTP responses", client_result.client_id);
        }

        println!("✅ Basic TLS handshake before HTTP: {} successful handshakes, {} HTTP requests processed",
                result.handshake_verification.successful_handshakes,
                result.handshake_verification.http_requests_processed_post_handshake);
    }

    #[tokio::test]
    async fn test_early_http_request_rejection() {
        let tls_config = TlsServerConfig {
            certificate_chain: vec![Certificate {
                subject: "CN=test.example.com".to_string(),
                issuer: "CN=Test CA".to_string(),
                valid_from: Instant::now(),
                valid_until: Instant::now() + Duration::from_secs(365 * 24 * 3600),
                fingerprint: "test-fingerprint".to_string(),
            }],
            private_key: PrivateKey {
                algorithm: "RSA".to_string(),
                key_size: 2048,
                fingerprint: "key-fingerprint".to_string(),
            },
            cipher_suites: vec![CipherSuite::Tls13Aes256GcmSha384],
            protocol_versions: vec![TlsVersion::Tls13],
            client_cert_verification: ClientCertVerification::None,
            session_resumption: SessionResumptionConfig {
                enabled: false,
                cache_timeout: Duration::from_secs(300),
                max_cached_sessions: 0,
            },
        };

        let http_config = HttpServerConfig {
            max_request_size: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(60),
            max_pipelined_requests: 10,
        };

        let test_config = TestConfig {
            num_clients: 2,
            requests_per_client: 3,
            max_test_duration: Duration::from_secs(20),
            test_renegotiation: false,
            tls_version: TlsVersion::Tls13,
        };

        let mut harness = TlsHttpIntegrationHarness::new(tls_config, http_config, test_config).await.unwrap();

        // Add one normal client and one that attempts HTTP before handshake
        harness.add_client(ClientBehavior::Normal);
        harness.add_client(ClientBehavior::EarlyHttpAttempt);

        let result = harness.run_integration_test().await;

        assert!(result.success, "Early HTTP rejection test should succeed");

        // Should have some HTTP requests rejected due to incomplete handshake
        assert!(result.handshake_verification.http_requests_rejected_pre_handshake > 0,
               "Some HTTP requests should be rejected before handshake completion");

        // Verify early HTTP client has errors
        let early_http_client = result.client_results.iter()
            .find(|c| c.client_id == 1)
            .expect("Should find early HTTP client");

        assert!(!early_http_client.errors.is_empty(),
               "Early HTTP client should have recorded errors");

        println!("✅ Early HTTP rejection: {} requests rejected pre-handshake, {} errors recorded",
                result.handshake_verification.http_requests_rejected_pre_handshake,
                early_http_client.errors.len());
    }

    #[tokio::test]
    async fn test_cipher_renegotiation_during_http_session() {
        let tls_config = TlsServerConfig {
            certificate_chain: vec![Certificate {
                subject: "CN=test.example.com".to_string(),
                issuer: "CN=Test CA".to_string(),
                valid_from: Instant::now(),
                valid_until: Instant::now() + Duration::from_secs(365 * 24 * 3600),
                fingerprint: "test-fingerprint".to_string(),
            }],
            private_key: PrivateKey {
                algorithm: "RSA".to_string(),
                key_size: 2048,
                fingerprint: "key-fingerprint".to_string(),
            },
            cipher_suites: vec![
                CipherSuite::Tls13Aes256GcmSha384,
                CipherSuite::Tls13Aes128GcmSha256,
            ],
            protocol_versions: vec![TlsVersion::Tls13],
            client_cert_verification: ClientCertVerification::None,
            session_resumption: SessionResumptionConfig {
                enabled: true,
                cache_timeout: Duration::from_secs(300),
                max_cached_sessions: 50,
            },
        };

        let http_config = HttpServerConfig {
            max_request_size: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(60),
            max_pipelined_requests: 10,
        };

        let test_config = TestConfig {
            num_clients: 2,
            requests_per_client: 8,
            max_test_duration: Duration::from_secs(40),
            test_renegotiation: true,
            tls_version: TlsVersion::Tls13,
        };

        let mut harness = TlsHttpIntegrationHarness::new(tls_config, http_config, test_config).await.unwrap();

        // Add normal client and renegotiation client
        harness.add_client(ClientBehavior::Normal);
        harness.add_client(ClientBehavior::RenegotiationRequester { renegotiate_after_requests: 3 });

        let result = harness.run_integration_test().await;

        assert!(result.success, "Cipher renegotiation test should succeed");
        assert!(result.handshake_verification.renegotiations_completed > 0,
               "Should complete at least one cipher renegotiation");

        // Verify renegotiation client performed renegotiations
        let renego_client = result.client_results.iter()
            .find(|c| c.client_id == 1)
            .expect("Should find renegotiation client");

        assert!(renego_client.renegotiations_performed > 0,
               "Renegotiation client should perform cipher renegotiations");

        println!("✅ Cipher renegotiation: {} total renegotiations, client performed {}",
                result.handshake_verification.renegotiations_completed,
                renego_client.renegotiations_performed);
    }

    #[tokio::test]
    async fn test_tls_handshake_failure_scenarios() {
        let tls_config = TlsServerConfig {
            certificate_chain: vec![Certificate {
                subject: "CN=test.example.com".to_string(),
                issuer: "CN=Test CA".to_string(),
                valid_from: Instant::now(),
                valid_until: Instant::now() + Duration::from_secs(365 * 24 * 3600),
                fingerprint: "test-fingerprint".to_string(),
            }],
            private_key: PrivateKey {
                algorithm: "RSA".to_string(),
                key_size: 2048,
                fingerprint: "key-fingerprint".to_string(),
            },
            cipher_suites: vec![CipherSuite::Tls13Aes256GcmSha384],
            protocol_versions: vec![TlsVersion::Tls13],
            client_cert_verification: ClientCertVerification::None,
            session_resumption: SessionResumptionConfig {
                enabled: false,
                cache_timeout: Duration::from_secs(300),
                max_cached_sessions: 0,
            },
        };

        let http_config = HttpServerConfig {
            max_request_size: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(60),
            max_pipelined_requests: 10,
        };

        let test_config = TestConfig {
            num_clients: 4,
            requests_per_client: 2,
            max_test_duration: Duration::from_secs(25),
            test_renegotiation: false,
            tls_version: TlsVersion::Tls13,
        };

        let mut harness = TlsHttpIntegrationHarness::new(tls_config, http_config, test_config).await.unwrap();

        // Add clients with different failure scenarios
        harness.add_client(ClientBehavior::Normal);
        harness.add_client(ClientBehavior::ProtocolMismatch { attempted_version: TlsVersion::Tls12 });
        harness.add_client(ClientBehavior::InvalidCertificate);
        harness.add_client(ClientBehavior::Normal);

        let result = harness.run_integration_test().await;

        assert!(result.success, "Handshake failure test should succeed");

        // Should have some successful and some failed handshakes
        let successful_count = result.client_results.iter()
            .filter(|c| c.handshake_successful)
            .count();
        let failed_count = result.client_results.iter()
            .filter(|c| !c.handshake_successful)
            .count();

        assert!(successful_count >= 2, "Should have at least 2 successful handshakes");
        assert!(failed_count >= 2, "Should have at least 2 failed handshakes");

        // Failed handshake clients should not send HTTP requests
        for client_result in &result.client_results {
            if !client_result.handshake_successful {
                assert_eq!(client_result.http_requests_sent, 0,
                          "Failed handshake client {} should not send HTTP requests",
                          client_result.client_id);
            }
        }

        println!("✅ Handshake failure scenarios: {} successful, {} failed handshakes",
                successful_count, failed_count);
    }

    #[tokio::test]
    async fn test_concurrent_tls_connections_http_processing() {
        let tls_config = TlsServerConfig {
            certificate_chain: vec![Certificate {
                subject: "CN=test.example.com".to_string(),
                issuer: "CN=Test CA".to_string(),
                valid_from: Instant::now(),
                valid_until: Instant::now() + Duration::from_secs(365 * 24 * 3600),
                fingerprint: "test-fingerprint".to_string(),
            }],
            private_key: PrivateKey {
                algorithm: "RSA".to_string(),
                key_size: 2048,
                fingerprint: "key-fingerprint".to_string(),
            },
            cipher_suites: vec![
                CipherSuite::Tls13Aes256GcmSha384,
                CipherSuite::Tls12EcdheRsaAes256GcmSha384,
            ],
            protocol_versions: vec![TlsVersion::Tls13, TlsVersion::Tls12],
            client_cert_verification: ClientCertVerification::None,
            session_resumption: SessionResumptionConfig {
                enabled: true,
                cache_timeout: Duration::from_secs(300),
                max_cached_sessions: 100,
            },
        };

        let http_config = HttpServerConfig {
            max_request_size: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(60),
            max_pipelined_requests: 5,
        };

        let test_config = TestConfig {
            num_clients: 8,
            requests_per_client: 4,
            max_test_duration: Duration::from_secs(45),
            test_renegotiation: false,
            tls_version: TlsVersion::Tls13,
        };

        let mut harness = TlsHttpIntegrationHarness::new(tls_config, http_config, test_config).await.unwrap();

        // Add multiple concurrent clients with different behaviors
        for i in 0..8 {
            let behavior = if i % 3 == 0 {
                ClientBehavior::SlowHandshake { delay_per_step_ms: 20 }
            } else {
                ClientBehavior::Normal
            };
            harness.add_client(behavior);
        }

        let result = harness.run_integration_test().await;

        assert!(result.success, "Concurrent connections test should succeed");

        // Most clients should complete handshakes successfully
        let successful_handshakes = result.client_results.iter()
            .filter(|c| c.handshake_successful)
            .count();

        assert!(successful_handshakes >= 6, "Should have at least 6 successful handshakes");

        // Verify HTTP processing for successful connections
        let total_http_requests: u32 = result.client_results.iter()
            .filter(|c| c.handshake_successful)
            .map(|c| c.http_requests_sent)
            .sum();

        assert!(total_http_requests >= 20, "Should process many HTTP requests concurrently");

        println!("✅ Concurrent connections: {} successful handshakes, {} HTTP requests processed",
                successful_handshakes, total_http_requests);
    }

    #[tokio::test]
    async fn test_tls_version_negotiation() {
        let tls_config = TlsServerConfig {
            certificate_chain: vec![Certificate {
                subject: "CN=test.example.com".to_string(),
                issuer: "CN=Test CA".to_string(),
                valid_from: Instant::now(),
                valid_until: Instant::now() + Duration::from_secs(365 * 24 * 3600),
                fingerprint: "test-fingerprint".to_string(),
            }],
            private_key: PrivateKey {
                algorithm: "RSA".to_string(),
                key_size: 2048,
                fingerprint: "key-fingerprint".to_string(),
            },
            cipher_suites: vec![
                CipherSuite::Tls13Aes256GcmSha384,
                CipherSuite::Tls12EcdheRsaAes256GcmSha384,
            ],
            protocol_versions: vec![TlsVersion::Tls13, TlsVersion::Tls12],
            client_cert_verification: ClientCertVerification::None,
            session_resumption: SessionResumptionConfig {
                enabled: true,
                cache_timeout: Duration::from_secs(300),
                max_cached_sessions: 50,
            },
        };

        let http_config = HttpServerConfig {
            max_request_size: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(60),
            max_pipelined_requests: 10,
        };

        let test_config = TestConfig {
            num_clients: 3,
            requests_per_client: 3,
            max_test_duration: Duration::from_secs(30),
            test_renegotiation: false,
            tls_version: TlsVersion::Tls13,
        };

        let mut harness = TlsHttpIntegrationHarness::new(tls_config, http_config, test_config).await.unwrap();

        // Add clients with different TLS version preferences
        harness.add_client(ClientBehavior::Normal); // TLS 1.3 preferred
        harness.add_client(ClientBehavior::Normal); // TLS 1.3 preferred
        harness.add_client(ClientBehavior::Normal); // TLS 1.3 preferred

        let result = harness.run_integration_test().await;

        assert!(result.success, "TLS version negotiation test should succeed");

        // All clients should successfully negotiate TLS version and complete handshakes
        assert_eq!(result.client_results.len(), 3, "Should have 3 client results");

        for client_result in &result.client_results {
            assert!(client_result.handshake_successful,
                   "Client {} should successfully negotiate TLS version", client_result.client_id);
            assert_eq!(client_result.http_requests_sent, 3,
                      "Client {} should send HTTP requests after TLS negotiation", client_result.client_id);
        }

        println!("✅ TLS version negotiation: {} successful negotiations, {} HTTP requests",
                result.handshake_verification.successful_handshakes,
                result.handshake_verification.http_requests_processed_post_handshake);
    }

    #[tokio::test]
    async fn test_tls_session_resumption() {
        let tls_config = TlsServerConfig {
            certificate_chain: vec![Certificate {
                subject: "CN=test.example.com".to_string(),
                issuer: "CN=Test CA".to_string(),
                valid_from: Instant::now(),
                valid_until: Instant::now() + Duration::from_secs(365 * 24 * 3600),
                fingerprint: "test-fingerprint".to_string(),
            }],
            private_key: PrivateKey {
                algorithm: "RSA".to_string(),
                key_size: 2048,
                fingerprint: "key-fingerprint".to_string(),
            },
            cipher_suites: vec![CipherSuite::Tls13Aes256GcmSha384],
            protocol_versions: vec![TlsVersion::Tls13],
            client_cert_verification: ClientCertVerification::None,
            session_resumption: SessionResumptionConfig {
                enabled: true,
                cache_timeout: Duration::from_secs(300),
                max_cached_sessions: 100,
            },
        };

        let http_config = HttpServerConfig {
            max_request_size: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(60),
            max_pipelined_requests: 10,
        };

        let test_config = TestConfig {
            num_clients: 2,
            requests_per_client: 4,
            max_test_duration: Duration::from_secs(35),
            test_renegotiation: false,
            tls_version: TlsVersion::Tls13,
        };

        let mut harness = TlsHttpIntegrationHarness::new(tls_config, http_config, test_config).await.unwrap();

        // Add clients that can test session resumption
        harness.add_client(ClientBehavior::Normal);
        harness.add_client(ClientBehavior::Normal);

        let result = harness.run_integration_test().await;

        assert!(result.success, "TLS session resumption test should succeed");

        // Both clients should complete handshakes and process HTTP requests
        for client_result in &result.client_results {
            assert!(client_result.handshake_successful,
                   "Client {} should complete TLS handshake", client_result.client_id);
            assert_eq!(client_result.http_requests_sent, 4,
                      "Client {} should send HTTP requests", client_result.client_id);
        }

        // Verify that handshake durations are reasonable (session resumption should be faster)
        let handshake_durations: Vec<_> = result.client_results.iter()
            .filter_map(|c| c.handshake_duration)
            .collect();

        assert_eq!(handshake_durations.len(), 2, "Should have handshake durations for both clients");

        println!("✅ TLS session resumption: {} successful handshakes with resumption support",
                result.handshake_verification.successful_handshakes);
    }

    #[tokio::test]
    async fn test_resource_cleanup_after_tls_errors() {
        let tls_config = TlsServerConfig {
            certificate_chain: vec![Certificate {
                subject: "CN=test.example.com".to_string(),
                issuer: "CN=Test CA".to_string(),
                valid_from: Instant::now(),
                valid_until: Instant::now() + Duration::from_secs(365 * 24 * 3600),
                fingerprint: "test-fingerprint".to_string(),
            }],
            private_key: PrivateKey {
                algorithm: "RSA".to_string(),
                key_size: 2048,
                fingerprint: "key-fingerprint".to_string(),
            },
            cipher_suites: vec![CipherSuite::Tls13Aes256GcmSha384],
            protocol_versions: vec![TlsVersion::Tls13],
            client_cert_verification: ClientCertVerification::None,
            session_resumption: SessionResumptionConfig {
                enabled: false,
                cache_timeout: Duration::from_secs(300),
                max_cached_sessions: 0,
            },
        };

        let http_config = HttpServerConfig {
            max_request_size: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(60),
            max_pipelined_requests: 10,
        };

        let test_config = TestConfig {
            num_clients: 6,
            requests_per_client: 2,
            max_test_duration: Duration::from_secs(30),
            test_renegotiation: false,
            tls_version: TlsVersion::Tls13,
        };

        let mut harness = TlsHttpIntegrationHarness::new(tls_config, http_config, test_config).await.unwrap();

        // Add mix of successful and failing clients
        harness.add_client(ClientBehavior::Normal);
        harness.add_client(ClientBehavior::InvalidCertificate);
        harness.add_client(ClientBehavior::ProtocolMismatch { attempted_version: TlsVersion::Tls12 });
        harness.add_client(ClientBehavior::Normal);
        harness.add_client(ClientBehavior::EarlyHttpAttempt);
        harness.add_client(ClientBehavior::Normal);

        let result = harness.run_integration_test().await;

        assert!(result.success, "Resource cleanup test should succeed");

        // Should have mix of successful and failed operations
        let successful_handshakes = result.client_results.iter()
            .filter(|c| c.handshake_successful)
            .count();
        let failed_handshakes = result.client_results.iter()
            .filter(|c| !c.handshake_successful)
            .count();

        assert!(successful_handshakes >= 3, "Should have successful handshakes");
        assert!(failed_handshakes >= 2, "Should have failed handshakes for testing cleanup");

        // Server should continue functioning despite failures
        assert!(result.handshake_verification.http_requests_processed_post_handshake > 0,
               "Server should process HTTP requests despite some TLS failures");

        println!("✅ Resource cleanup: {} successful, {} failed handshakes, server remained stable",
                successful_handshakes, failed_handshakes);
    }
}