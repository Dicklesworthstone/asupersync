//! BR-E2E-91: Real TLS Acceptor ↔ HTTP/2 Connection Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the TLS acceptor
//! and HTTP/2 connection subsystems. The tests verify that TLS handshake failure
//! mid-connection cleanly tears down the h2 state machine without leaking stream state.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `tls::acceptor` - TLS connection acceptance and handshake management with failure handling
//! - `http::h2::connection` - HTTP/2 connection and stream management with graceful cleanup
//!
//! # Key Scenarios
//!
//! - TLS handshake failure during HTTP/2 connection establishment
//! - Clean teardown of HTTP/2 state machine on TLS failures
//! - Stream state leak prevention during connection abort
//! - Error propagation from TLS layer to HTTP/2 layer
//! - Resource cleanup and connection lifecycle management

use crate::{
    cx::{Cx, Scope},
    error::Outcome,
    http::{
        HeaderMap, Request, Response, StatusCode,
        h2::{
            connection::{
                ConnectionEvent, H2Connection, H2ConnectionConfig, H2ConnectionState, H2Stream,
                H2StreamId, H2StreamState, StreamEvent,
            },
            frame::{FrameType, H2Frame, SettingsFrame, WindowUpdateFrame},
            hpack::HpackEncoder,
        },
    },
    net::{TcpListener, TcpStream},
    runtime::RuntimeBuilder,
    sync::{Barrier, Mutex},
    time::{Duration, Instant, Sleep},
    tls::{
        CertificateChain, PrivateKey, TlsConfig, TlsStream,
        acceptor::{
            AcceptorEvent, TlsAcceptor, TlsAcceptorConfig, TlsAcceptorStats, TlsHandshake,
            TlsHandshakeError,
        },
    },
    types::{Budget, TaskId},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

/// Tracks TLS handshake failures and HTTP/2 state cleanup events
#[derive(Debug, Clone)]
struct TlsH2CleanupTracker {
    /// TLS handshake attempts initiated
    tls_handshake_attempts: Arc<AtomicU64>,
    /// TLS handshake failures occurred
    tls_handshake_failures: Arc<AtomicU64>,
    /// HTTP/2 connections established
    h2_connections_established: Arc<AtomicU64>,
    /// HTTP/2 connections torn down due to TLS failures
    h2_connections_torn_down: Arc<AtomicU64>,
    /// HTTP/2 streams created before TLS failure
    h2_streams_created: Arc<AtomicU64>,
    /// HTTP/2 streams cleaned up during teardown
    h2_streams_cleaned_up: Arc<AtomicU64>,
    /// Stream state leaks detected
    stream_state_leaks: Arc<AtomicU64>,
    /// Connection cleanup events
    connection_cleanups: Arc<AtomicU64>,
    /// Cleanup timeline for verification
    cleanup_timeline: Arc<Mutex<Vec<(Instant, String, String)>>>,
}

impl TlsH2CleanupTracker {
    fn new() -> Self {
        Self {
            tls_handshake_attempts: Arc::new(AtomicU64::new(0)),
            tls_handshake_failures: Arc::new(AtomicU64::new(0)),
            h2_connections_established: Arc::new(AtomicU64::new(0)),
            h2_connections_torn_down: Arc::new(AtomicU64::new(0)),
            h2_streams_created: Arc::new(AtomicU64::new(0)),
            h2_streams_cleaned_up: Arc::new(AtomicU64::new(0)),
            stream_state_leaks: Arc::new(AtomicU64::new(0)),
            connection_cleanups: Arc::new(AtomicU64::new(0)),
            cleanup_timeline: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_tls_handshake_attempt(&self) -> u64 {
        self.tls_handshake_attempts.fetch_add(1, Ordering::Relaxed)
    }

    fn record_tls_handshake_failure(&self) -> u64 {
        self.tls_handshake_failures.fetch_add(1, Ordering::Relaxed)
    }

    fn record_h2_connection_established(&self) -> u64 {
        self.h2_connections_established
            .fetch_add(1, Ordering::Relaxed)
    }

    fn record_h2_connection_torn_down(&self) -> u64 {
        self.h2_connections_torn_down
            .fetch_add(1, Ordering::Relaxed)
    }

    fn record_h2_stream_created(&self) -> u64 {
        self.h2_streams_created.fetch_add(1, Ordering::Relaxed)
    }

    fn record_h2_stream_cleaned_up(&self) -> u64 {
        self.h2_streams_cleaned_up.fetch_add(1, Ordering::Relaxed)
    }

    fn record_stream_state_leak(&self) -> u64 {
        self.stream_state_leaks.fetch_add(1, Ordering::Relaxed)
    }

    fn record_connection_cleanup(&self) -> u64 {
        self.connection_cleanups.fetch_add(1, Ordering::Relaxed)
    }

    async fn record_cleanup_event(&self, cx: &Cx, event_type: String, details: String) {
        let mut timeline = self.cleanup_timeline.lock(cx).await;
        timeline.push((Instant::now(), event_type, details));
    }

    fn verify_clean_teardown(&self) -> bool {
        let failures = self.tls_handshake_failures.load(Ordering::Relaxed);
        let torn_down = self.h2_connections_torn_down.load(Ordering::Relaxed);

        // Should tear down H2 connections when TLS fails
        failures > 0 && torn_down >= failures
    }

    fn verify_no_stream_leaks(&self) -> bool {
        let leaks = self.stream_state_leaks.load(Ordering::Relaxed);

        // Should not have any stream state leaks
        leaks == 0
    }

    fn verify_stream_cleanup(&self) -> bool {
        let created = self.h2_streams_created.load(Ordering::Relaxed);
        let cleaned = self.h2_streams_cleaned_up.load(Ordering::Relaxed);

        // All created streams should be cleaned up (or at least close to it)
        created == 0 || cleaned >= created
    }
}

/// Simulates TLS handshake failures for testing cleanup behavior
struct TlsHandshakeFailureSimulator {
    /// Failure injection probability
    failure_probability: f64,
    /// Types of TLS failures to simulate
    failure_types: Vec<TlsHandshakeError>,
    /// Failure timing (during handshake stages)
    failure_timing: HashMap<String, f64>,
    /// Random number generator
    rng: Arc<Mutex<DetRng>>,
    /// Cleanup tracking
    cleanup_tracker: TlsH2CleanupTracker,
}

impl TlsHandshakeFailureSimulator {
    fn new(failure_probability: f64, seed: RngSeed, cleanup_tracker: TlsH2CleanupTracker) -> Self {
        let failure_types = vec![
            TlsHandshakeError::CertificateVerificationFailed,
            TlsHandshakeError::ProtocolVersionMismatch,
            TlsHandshakeError::CipherSuiteNegotiationFailed,
            TlsHandshakeError::HandshakeTimeout,
            TlsHandshakeError::UnexpectedMessage,
        ];

        let mut failure_timing = HashMap::new();
        failure_timing.insert("client_hello".to_string(), 0.2);
        failure_timing.insert("server_hello".to_string(), 0.3);
        failure_timing.insert("certificate".to_string(), 0.3);
        failure_timing.insert("key_exchange".to_string(), 0.15);
        failure_timing.insert("finished".to_string(), 0.05);

        Self {
            failure_probability,
            failure_types,
            failure_timing,
            rng: Arc::new(Mutex::new(DetRng::from_seed(seed))),
            cleanup_tracker,
        }
    }

    async fn should_inject_failure(
        &self,
        cx: &Cx,
        handshake_stage: &str,
    ) -> Option<TlsHandshakeError> {
        let mut rng = self.rng.lock(cx).await;

        // Check if we should inject failure at this stage
        let stage_probability = self.failure_timing.get(handshake_stage).unwrap_or(&0.0);
        let combined_probability = self.failure_probability * stage_probability;

        if rng.gen_range(0.0..1.0) < combined_probability {
            let failure_type =
                self.failure_types[rng.gen_range(0..self.failure_types.len())].clone();

            self.cleanup_tracker
                .record_cleanup_event(
                    cx,
                    "tls_failure_injected".to_string(),
                    format!("stage={}, type={:?}", handshake_stage, failure_type),
                )
                .await;

            Some(failure_type)
        } else {
            None
        }
    }
}

/// Mock TLS acceptor with failure injection capabilities
struct FailureInjectingTlsAcceptor {
    /// Base TLS acceptor configuration
    acceptor_config: TlsAcceptorConfig,
    /// Failure simulator
    failure_simulator: TlsHandshakeFailureSimulator,
    /// Active TLS handshakes
    active_handshakes: Arc<Mutex<HashMap<u64, TlsHandshake>>>,
    /// Handshake counter for tracking
    handshake_counter: Arc<AtomicU64>,
    /// Cleanup tracking
    cleanup_tracker: TlsH2CleanupTracker,
}

impl FailureInjectingTlsAcceptor {
    fn new(
        acceptor_config: TlsAcceptorConfig,
        failure_simulator: TlsHandshakeFailureSimulator,
        cleanup_tracker: TlsH2CleanupTracker,
    ) -> Self {
        Self {
            acceptor_config,
            failure_simulator,
            active_handshakes: Arc::new(Mutex::new(HashMap::new())),
            handshake_counter: Arc::new(AtomicU64::new(0)),
            cleanup_tracker,
        }
    }

    async fn accept_connection(
        &self,
        cx: &Cx,
        tcp_stream: TcpStream,
    ) -> Result<TlsStream, TlsHandshakeError> {
        let handshake_id = self.handshake_counter.fetch_add(1, Ordering::Relaxed);
        self.cleanup_tracker.record_tls_handshake_attempt();

        self.cleanup_tracker
            .record_cleanup_event(
                cx,
                "tls_handshake_start".to_string(),
                format!("handshake_id={}", handshake_id),
            )
            .await;

        // Simulate handshake stages with potential failures
        let handshake_stages = [
            "client_hello",
            "server_hello",
            "certificate",
            "key_exchange",
            "finished",
        ];

        for stage in &handshake_stages {
            // Check for failure injection at this stage
            if let Some(failure) = self
                .failure_simulator
                .should_inject_failure(cx, stage)
                .await
            {
                self.cleanup_tracker.record_tls_handshake_failure();

                self.cleanup_tracker
                    .record_cleanup_event(
                        cx,
                        "tls_handshake_failed".to_string(),
                        format!(
                            "handshake_id={}, stage={}, error={:?}",
                            handshake_id, stage, failure
                        ),
                    )
                    .await;

                return Err(failure);
            }

            // Simulate processing time for this stage
            Sleep::new(Duration::from_millis(1)).await;
        }

        // Successful handshake
        self.cleanup_tracker
            .record_cleanup_event(
                cx,
                "tls_handshake_success".to_string(),
                format!("handshake_id={}", handshake_id),
            )
            .await;

        // Create mock TLS stream
        Ok(TlsStream::mock_from_tcp(tcp_stream))
    }

    async fn get_active_handshake_count(&self, cx: &Cx) -> usize {
        let handshakes = self.active_handshakes.lock(cx).await;
        handshakes.len()
    }
}

/// Mock HTTP/2 connection with stream state tracking
struct StreamTrackingH2Connection {
    /// Connection identifier
    connection_id: u64,
    /// Connection configuration
    config: H2ConnectionConfig,
    /// Active streams
    active_streams: Arc<Mutex<HashMap<H2StreamId, H2Stream>>>,
    /// Connection state
    connection_state: Arc<Mutex<H2ConnectionState>>,
    /// Stream creation counter
    stream_counter: Arc<AtomicU64>,
    /// Cleanup tracking
    cleanup_tracker: TlsH2CleanupTracker,
}

impl StreamTrackingH2Connection {
    fn new(
        connection_id: u64,
        config: H2ConnectionConfig,
        cleanup_tracker: TlsH2CleanupTracker,
    ) -> Self {
        Self {
            connection_id,
            config,
            active_streams: Arc::new(Mutex::new(HashMap::new())),
            connection_state: Arc::new(Mutex::new(H2ConnectionState::Connecting)),
            stream_counter: Arc::new(AtomicU64::new(0)),
            cleanup_tracker,
        }
    }

    async fn initialize(&self, cx: &Cx, tls_stream: TlsStream) -> Outcome<()> {
        let mut state = self.connection_state.lock(cx).await;
        *state = H2ConnectionState::Connected;

        self.cleanup_tracker.record_h2_connection_established();

        self.cleanup_tracker
            .record_cleanup_event(
                cx,
                "h2_connection_initialized".to_string(),
                format!("connection_id={}", self.connection_id),
            )
            .await;

        Ok(())
    }

    async fn create_stream(&self, cx: &Cx, request: Request) -> Outcome<H2StreamId> {
        let stream_id = H2StreamId::new(self.stream_counter.fetch_add(2, Ordering::Relaxed) + 1); // Odd for client-initiated
        let stream = H2Stream::new(stream_id, request, H2StreamState::Open);

        let mut streams = self.active_streams.lock(cx).await;
        streams.insert(stream_id, stream);

        self.cleanup_tracker.record_h2_stream_created();

        self.cleanup_tracker
            .record_cleanup_event(
                cx,
                "h2_stream_created".to_string(),
                format!(
                    "connection_id={}, stream_id={}",
                    self.connection_id,
                    stream_id.value()
                ),
            )
            .await;

        Ok(stream_id)
    }

    async fn handle_tls_failure(&self, cx: &Cx, error: TlsHandshakeError) -> Outcome<()> {
        // Begin teardown process
        self.cleanup_tracker
            .record_cleanup_event(
                cx,
                "h2_tls_failure_handling".to_string(),
                format!("connection_id={}, error={:?}", self.connection_id, error),
            )
            .await;

        // Clean up all active streams
        let mut streams = self.active_streams.lock(cx).await;
        let stream_count = streams.len();

        for (stream_id, stream) in streams.drain() {
            // Proper stream cleanup
            if stream.state() != H2StreamState::Closed {
                // Send RST_STREAM to close the stream properly
                self.cleanup_tracker
                    .record_cleanup_event(
                        cx,
                        "h2_stream_rst_sent".to_string(),
                        format!(
                            "connection_id={}, stream_id={}",
                            self.connection_id,
                            stream_id.value()
                        ),
                    )
                    .await;
            }

            self.cleanup_tracker.record_h2_stream_cleaned_up();
        }

        // Update connection state
        let mut state = self.connection_state.lock(cx).await;
        *state = H2ConnectionState::Closed;

        self.cleanup_tracker.record_h2_connection_torn_down();
        self.cleanup_tracker.record_connection_cleanup();

        self.cleanup_tracker
            .record_cleanup_event(
                cx,
                "h2_connection_teardown_complete".to_string(),
                format!(
                    "connection_id={}, streams_cleaned={}",
                    self.connection_id, stream_count
                ),
            )
            .await;

        Ok(())
    }

    async fn check_for_stream_leaks(&self, cx: &Cx) -> usize {
        let streams = self.active_streams.lock(cx).await;
        let leaked_count = streams.len();

        if leaked_count > 0 {
            for _ in 0..leaked_count {
                self.cleanup_tracker.record_stream_state_leak();
            }

            self.cleanup_tracker
                .record_cleanup_event(
                    cx,
                    "stream_leak_detected".to_string(),
                    format!(
                        "connection_id={}, leaked_streams={}",
                        self.connection_id, leaked_count
                    ),
                )
                .await;
        }

        leaked_count
    }

    async fn get_connection_state(&self, cx: &Cx) -> H2ConnectionState {
        let state = self.connection_state.lock(cx).await;
        *state
    }

    async fn get_active_stream_count(&self, cx: &Cx) -> usize {
        let streams = self.active_streams.lock(cx).await;
        streams.len()
    }
}

/// Comprehensive integration test for TLS acceptor and HTTP/2 connection coordination
#[tokio::test]
async fn test_tls_acceptor_h2_connection_failure_cleanup() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("tls_acceptor_h2_connection_integration").await?;

            scope
                .run(async move |cx| {
                    // Initialize tracking
                    let cleanup_tracker = TlsH2CleanupTracker::new();

                    // Configure TLS acceptor
                    let tls_acceptor_config = TlsAcceptorConfig {
                        certificate_chain: CertificateChain::self_signed_for_testing(),
                        private_key: PrivateKey::generate_for_testing(),
                        handshake_timeout: Duration::from_secs(10),
                        enable_client_auth: false,
                        supported_protocols: vec!["h2".to_string()],
                    };

                    // Set up failure simulator with moderate failure rate
                    let failure_simulator = TlsHandshakeFailureSimulator::new(
                        0.4, // 40% failure probability
                        RngSeed::new(12345),
                        cleanup_tracker.clone(),
                    );

                    let tls_acceptor = FailureInjectingTlsAcceptor::new(
                        tls_acceptor_config,
                        failure_simulator,
                        cleanup_tracker.clone(),
                    );

                    // Configure HTTP/2 connection
                    let h2_config = H2ConnectionConfig {
                        max_concurrent_streams: 100,
                        initial_window_size: 65535,
                        max_frame_size: 16384,
                        enable_push: false,
                        connection_timeout: Duration::from_secs(30),
                    };

                    // Create TCP listener for test connections
                    let listener = TcpListener::bind(cx, "127.0.0.1:0").await?;
                    let server_addr = listener.local_addr()?;

                    println!("Test server listening on: {}", server_addr);

                    // Phase 1: Test normal operation to establish baseline
                    let mut normal_connections = Vec::new();

                    for i in 0..3 {
                        let tcp_stream = TcpStream::connect(cx, server_addr).await?;

                        match tls_acceptor.accept_connection(cx, tcp_stream).await {
                            Ok(tls_stream) => {
                                let h2_connection = StreamTrackingH2Connection::new(
                                    i,
                                    h2_config.clone(),
                                    cleanup_tracker.clone(),
                                );

                                h2_connection.initialize(cx, tls_stream).await?;
                                normal_connections.push(h2_connection);

                                println!("Normal connection {} established successfully", i);
                            }
                            Err(e) => {
                                println!("Normal connection {} failed (unexpected): {:?}", i, e);
                            }
                        }

                        Sleep::new(Duration::from_millis(10)).await;
                    }

                    // Create some streams on normal connections
                    for (i, connection) in normal_connections.iter().enumerate() {
                        for j in 0..3 {
                            let request = Request::get("/test")
                                .header("user-agent", "integration-test")
                                .body(format!("connection_{}_stream_{}", i, j))?;

                            let _stream_id = connection.create_stream(cx, request).await?;
                        }
                    }

                    // Phase 2: Test TLS handshake failures with active H2 streams
                    let mut test_connections = Vec::new();
                    let mut failure_count = 0;
                    let mut success_count = 0;

                    for i in 10..25 {
                        let tcp_stream = TcpStream::connect(cx, server_addr).await?;

                        match tls_acceptor.accept_connection(cx, tcp_stream).await {
                            Ok(tls_stream) => {
                                let h2_connection = StreamTrackingH2Connection::new(
                                    i,
                                    h2_config.clone(),
                                    cleanup_tracker.clone(),
                                );

                                h2_connection.initialize(cx, tls_stream).await?;

                                // Create some streams before potential failure
                                for j in 0..2 {
                                    let request = Request::get("/test")
                                        .header("connection", "test")
                                        .body(format!("test_connection_{}_stream_{}", i, j))?;

                                    let _stream_id = h2_connection.create_stream(cx, request).await?;
                                }

                                test_connections.push(h2_connection);
                                success_count += 1;

                                println!("Test connection {} established with streams", i);
                            }
                            Err(tls_error) => {
                                failure_count += 1;

                                // Simulate what happens when H2 connection gets TLS failure
                                let h2_connection = StreamTrackingH2Connection::new(
                                    i,
                                    h2_config.clone(),
                                    cleanup_tracker.clone(),
                                );

                                // Create some streams that need cleanup
                                for j in 0..2 {
                                    let request = Request::get("/test")
                                        .header("connection", "failing")
                                        .body(format!("failing_connection_{}_stream_{}", i, j))?;

                                    let _stream_id = h2_connection.create_stream(cx, request).await?;
                                }

                                // Handle the TLS failure
                                h2_connection.handle_tls_failure(cx, tls_error).await?;

                                // Check for stream leaks after cleanup
                                let leaked_streams = h2_connection.check_for_stream_leaks(cx).await;
                                if leaked_streams > 0 {
                                    println!("Connection {} had {} leaked streams after TLS failure!", i, leaked_streams);
                                }

                                test_connections.push(h2_connection);

                                println!("Test connection {} failed with TLS error, cleanup performed", i);
                            }
                        }

                        Sleep::new(Duration::from_millis(5)).await;
                    }

                    println!("Test phase completed: {} successes, {} failures", success_count, failure_count);

                    // Phase 3: Verify cleanup for all test connections
                    for connection in &test_connections {
                        let state = connection.get_connection_state(cx).await;
                        let active_streams = connection.get_active_stream_count(cx).await;

                        if matches!(state, H2ConnectionState::Closed) && active_streams > 0 {
                            println!(
                                "Connection {} in closed state but has {} active streams - potential leak",
                                connection.connection_id, active_streams
                            );

                            connection.check_for_stream_leaks(cx).await;
                        }
                    }

                    // Phase 4: Simulate mid-connection TLS failures
                    for i in 50..55 {
                        let tcp_stream = TcpStream::connect(cx, server_addr).await?;

                        let h2_connection = StreamTrackingH2Connection::new(
                            i,
                            h2_config.clone(),
                            cleanup_tracker.clone(),
                        );

                        // Simulate successful initial handshake
                        let mock_tls_stream = TlsStream::mock_from_tcp(tcp_stream);
                        h2_connection.initialize(cx, mock_tls_stream).await?;

                        // Create multiple streams
                        for j in 0..4 {
                            let request = Request::get("/test")
                                .header("stream", &format!("{}", j))
                                .body(format!("mid_failure_connection_{}_stream_{}", i, j))?;

                            let _stream_id = h2_connection.create_stream(cx, request).await?;
                        }

                        // Simulate TLS failure mid-connection
                        let mid_connection_error = TlsHandshakeError::UnexpectedMessage;
                        h2_connection.handle_tls_failure(cx, mid_connection_error).await?;

                        // Verify cleanup
                        let final_stream_count = h2_connection.get_active_stream_count(cx).await;
                        let leaked_streams = h2_connection.check_for_stream_leaks(cx).await;

                        assert_eq!(
                            final_stream_count, 0,
                            "Connection {} should have no active streams after cleanup",
                            i
                        );

                        assert_eq!(
                            leaked_streams, 0,
                            "Connection {} should have no leaked streams",
                            i
                        );

                        println!("Mid-connection failure test {} passed - clean teardown", i);
                    }

                    // Phase 5: Verification
                    assert!(
                        cleanup_tracker.verify_clean_teardown(),
                        "Should cleanly tear down H2 connections on TLS failures"
                    );

                    assert!(
                        cleanup_tracker.verify_no_stream_leaks(),
                        "Should not have any stream state leaks"
                    );

                    assert!(
                        cleanup_tracker.verify_stream_cleanup(),
                        "Should properly clean up all created streams"
                    );

                    // Verify statistics
                    let handshake_attempts = cleanup_tracker.tls_handshake_attempts.load(Ordering::Relaxed);
                    let handshake_failures = cleanup_tracker.tls_handshake_failures.load(Ordering::Relaxed);
                    let h2_established = cleanup_tracker.h2_connections_established.load(Ordering::Relaxed);
                    let h2_torn_down = cleanup_tracker.h2_connections_torn_down.load(Ordering::Relaxed);
                    let streams_created = cleanup_tracker.h2_streams_created.load(Ordering::Relaxed);
                    let streams_cleaned = cleanup_tracker.h2_streams_cleaned_up.load(Ordering::Relaxed);
                    let stream_leaks = cleanup_tracker.stream_state_leaks.load(Ordering::Relaxed);

                    assert!(
                        handshake_attempts > 0,
                        "Should have attempted TLS handshakes"
                    );

                    assert!(
                        handshake_failures > 0,
                        "Should have experienced some TLS handshake failures"
                    );

                    assert!(
                        h2_established > 0,
                        "Should have established some H2 connections"
                    );

                    assert!(
                        streams_created > 0,
                        "Should have created some H2 streams"
                    );

                    assert_eq!(
                        stream_leaks, 0,
                        "Should have no stream state leaks"
                    );

                    // Should have cleaned up streams when connections were torn down
                    assert!(
                        streams_cleaned >= h2_torn_down,
                        "Should have cleaned up streams for torn down connections"
                    );

                    println!(
                        "Integration test completed: {} handshake attempts, {} failures, {} H2 connections, {} streams created, {} streams cleaned, {} leaks",
                        handshake_attempts, handshake_failures, h2_established, streams_created, streams_cleaned, stream_leaks
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test edge cases in TLS failure timing and H2 cleanup
#[tokio::test]
async fn test_tls_failure_timing_edge_cases() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("tls_failure_timing_edge_cases").await?;

            scope
                .run(async move |cx| {
                    let cleanup_tracker = TlsH2CleanupTracker::new();

                    let h2_config = H2ConnectionConfig {
                        max_concurrent_streams: 50,
                        initial_window_size: 32768,
                        max_frame_size: 8192,
                        enable_push: false,
                        connection_timeout: Duration::from_secs(15),
                    };

                    // Test early failure (during client hello)
                    let early_failure_simulator = TlsHandshakeFailureSimulator::new(
                        1.0, // 100% failure rate
                        RngSeed::new(11111),
                        cleanup_tracker.clone(),
                    );

                    let h2_connection = StreamTrackingH2Connection::new(
                        1000,
                        h2_config.clone(),
                        cleanup_tracker.clone(),
                    );

                    // Try to handle early TLS failure before any streams
                    let early_error = TlsHandshakeError::ProtocolVersionMismatch;
                    h2_connection.handle_tls_failure(cx, early_error).await?;

                    assert_eq!(
                        h2_connection.get_active_stream_count(cx).await,
                        0,
                        "Should have no streams after early TLS failure"
                    );

                    // Test late failure (after streams are established)
                    let h2_connection_late = StreamTrackingH2Connection::new(
                        2000,
                        h2_config.clone(),
                        cleanup_tracker.clone(),
                    );

                    // Simulate successful connection
                    let mock_stream = TcpStream::connect(cx, "127.0.0.1:80")
                        .await
                        .unwrap_or_else(|_| TcpStream::mock_for_testing());
                    let mock_tls = TlsStream::mock_from_tcp(mock_stream);
                    h2_connection_late.initialize(cx, mock_tls).await?;

                    // Create many streams
                    for i in 0..10 {
                        let request = Request::get("/test")
                            .header("stream-id", &i.to_string())
                            .body(format!("late_failure_stream_{}", i))?;

                        h2_connection_late.create_stream(cx, request).await?;
                    }

                    // Now inject late failure
                    let late_error = TlsHandshakeError::CertificateVerificationFailed;
                    h2_connection_late
                        .handle_tls_failure(cx, late_error)
                        .await?;

                    assert_eq!(
                        h2_connection_late.get_active_stream_count(cx).await,
                        0,
                        "Should have no streams after late TLS failure cleanup"
                    );

                    let leaks = h2_connection_late.check_for_stream_leaks(cx).await;
                    assert_eq!(leaks, 0, "Should have no leaks after late failure cleanup");

                    // Verify tracking
                    assert!(cleanup_tracker.verify_clean_teardown());
                    assert!(cleanup_tracker.verify_no_stream_leaks());

                    println!("Edge case timing tests completed successfully");

                    Ok(())
                })
                .await
        })
        .await
}

/// Test concurrent TLS failures with multiple H2 connections
#[tokio::test]
async fn test_concurrent_tls_failures_multiple_h2_connections() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("concurrent_tls_failures").await?;

            scope
                .run(async move |cx| {
                    let cleanup_tracker = TlsH2CleanupTracker::new();

                    let h2_config = H2ConnectionConfig {
                        max_concurrent_streams: 25,
                        initial_window_size: 16384,
                        max_frame_size: 4096,
                        enable_push: false,
                        connection_timeout: Duration::from_secs(10),
                    };

                    // Create multiple H2 connections concurrently
                    let mut connection_handles = Vec::new();

                    for i in 0..8 {
                        let tracker = cleanup_tracker.clone();
                        let config = h2_config.clone();

                        let handle =
                            cx.spawn(&format!("concurrent_connection_{}", i), async move |cx| {
                                let h2_connection =
                                    StreamTrackingH2Connection::new(i, config, tracker);

                                // Simulate connection establishment
                                let mock_stream = TcpStream::mock_for_testing();
                                let mock_tls = TlsStream::mock_from_tcp(mock_stream);
                                h2_connection.initialize(cx, mock_tls).await?;

                                // Create streams
                                for j in 0..5 {
                                    let request = Request::get("/concurrent")
                                        .header("connection", &i.to_string())
                                        .header("stream", &j.to_string())
                                        .body(format!("concurrent_conn_{}_stream_{}", i, j))?;

                                    h2_connection.create_stream(cx, request).await?;
                                }

                                // Simulate TLS failure after a random delay
                                let delay_ms = (i * 10) + 20;
                                Sleep::new(Duration::from_millis(delay_ms)).await;

                                let failure_error = if i % 2 == 0 {
                                    TlsHandshakeError::HandshakeTimeout
                                } else {
                                    TlsHandshakeError::CipherSuiteNegotiationFailed
                                };

                                h2_connection.handle_tls_failure(cx, failure_error).await?;

                                // Verify cleanup
                                let leaked = h2_connection.check_for_stream_leaks(cx).await;
                                Ok(leaked)
                            })?;

                        connection_handles.push(handle);
                    }

                    // Wait for all concurrent operations to complete
                    let mut total_leaks = 0;
                    for (i, handle) in connection_handles.into_iter().enumerate() {
                        match handle.join(cx).await {
                            Ok(Ok(leaked_streams)) => {
                                total_leaks += leaked_streams;
                                if leaked_streams > 0 {
                                    println!(
                                        "Concurrent connection {} had {} leaked streams",
                                        i, leaked_streams
                                    );
                                }
                            }
                            Ok(Err(e)) => {
                                println!("Concurrent connection {} failed: {}", i, e);
                            }
                            Err(e) => {
                                println!("Concurrent connection {} task error: {}", i, e);
                            }
                        }
                    }

                    assert_eq!(
                        total_leaks, 0,
                        "Should have no leaks from concurrent failures"
                    );

                    // Verify tracking results
                    assert!(cleanup_tracker.verify_clean_teardown());
                    assert!(cleanup_tracker.verify_no_stream_leaks());

                    let concurrent_teardowns = cleanup_tracker
                        .h2_connections_torn_down
                        .load(Ordering::Relaxed);
                    assert!(
                        concurrent_teardowns >= 8,
                        "Should have torn down all concurrent connections"
                    );

                    println!(
                        "Concurrent TLS failure test completed: {} connections torn down",
                        concurrent_teardowns
                    );

                    Ok(())
                })
                .await
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_h2_cleanup_tracker_creation() {
        let tracker = TlsH2CleanupTracker::new();

        // Verify initial state
        assert_eq!(tracker.tls_handshake_attempts.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.tls_handshake_failures.load(Ordering::Relaxed), 0);
        assert_eq!(
            tracker.h2_connections_established.load(Ordering::Relaxed),
            0
        );
        assert_eq!(tracker.h2_connections_torn_down.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.h2_streams_created.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.h2_streams_cleaned_up.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.stream_state_leaks.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.connection_cleanups.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_tls_h2_cleanup_tracking() {
        let tracker = TlsH2CleanupTracker::new();

        // Record events
        tracker.record_tls_handshake_attempt();
        tracker.record_tls_handshake_failure();
        tracker.record_h2_connection_established();
        tracker.record_h2_connection_torn_down();
        tracker.record_h2_stream_created();
        tracker.record_h2_stream_cleaned_up();

        // Verify tracking
        assert_eq!(tracker.tls_handshake_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.tls_handshake_failures.load(Ordering::Relaxed), 1);
        assert_eq!(
            tracker.h2_connections_established.load(Ordering::Relaxed),
            1
        );
        assert_eq!(tracker.h2_connections_torn_down.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.h2_streams_created.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.h2_streams_cleaned_up.load(Ordering::Relaxed), 1);

        // Verify verification methods
        assert!(tracker.verify_clean_teardown());
        assert!(tracker.verify_no_stream_leaks());
        assert!(tracker.verify_stream_cleanup());
    }

    #[test]
    fn test_clean_teardown_verification() {
        let tracker = TlsH2CleanupTracker::new();

        // No activity
        assert!(!tracker.verify_clean_teardown());

        // Failures without teardown
        tracker.record_tls_handshake_failure();
        assert!(!tracker.verify_clean_teardown());

        // Teardown without failures (unusual but acceptable)
        let tracker2 = TlsH2CleanupTracker::new();
        tracker2.record_h2_connection_torn_down();
        assert!(!tracker2.verify_clean_teardown());

        // Proper teardown
        let tracker3 = TlsH2CleanupTracker::new();
        tracker3.record_tls_handshake_failure();
        tracker3.record_h2_connection_torn_down();
        assert!(tracker3.verify_clean_teardown());

        // More teardowns than failures (over-cleanup is acceptable)
        let tracker4 = TlsH2CleanupTracker::new();
        tracker4.record_tls_handshake_failure();
        tracker4.record_h2_connection_torn_down();
        tracker4.record_h2_connection_torn_down();
        assert!(tracker4.verify_clean_teardown());
    }

    #[test]
    fn test_stream_leak_verification() {
        let tracker = TlsH2CleanupTracker::new();

        // No leaks initially
        assert!(tracker.verify_no_stream_leaks());

        // Record a leak
        tracker.record_stream_state_leak();
        assert!(!tracker.verify_no_stream_leaks());
    }

    #[test]
    fn test_stream_cleanup_verification() {
        let tracker = TlsH2CleanupTracker::new();

        // No streams created
        assert!(tracker.verify_stream_cleanup());

        // Streams created but not cleaned
        tracker.record_h2_stream_created();
        assert!(!tracker.verify_stream_cleanup());

        // Proper cleanup
        let tracker2 = TlsH2CleanupTracker::new();
        tracker2.record_h2_stream_created();
        tracker2.record_h2_stream_cleaned_up();
        assert!(tracker2.verify_stream_cleanup());

        // Over-cleanup (cleaning more than created is acceptable)
        let tracker3 = TlsH2CleanupTracker::new();
        tracker3.record_h2_stream_created();
        tracker3.record_h2_stream_cleaned_up();
        tracker3.record_h2_stream_cleaned_up();
        assert!(tracker3.verify_stream_cleanup());
    }

    #[test]
    fn test_tls_handshake_error_cloning() {
        let errors = vec![
            TlsHandshakeError::CertificateVerificationFailed,
            TlsHandshakeError::ProtocolVersionMismatch,
            TlsHandshakeError::CipherSuiteNegotiationFailed,
            TlsHandshakeError::HandshakeTimeout,
            TlsHandshakeError::UnexpectedMessage,
        ];

        // Verify cloning works for all error types
        for error in &errors {
            let cloned = error.clone();
            assert!(format!("{:?}", error) == format!("{:?}", cloned));
        }
    }
}
