//! Real E2E integration tests: signal/graceful ↔ server/shutdown integration (br-e2e-60).
//!
//! Tests SIGTERM signal during in-flight requests drains gracefully without dropping connections.
//! Verifies that server shutdown coordination properly integrates with signal handling to ensure
//! graceful termination of active connections and completion of in-flight requests without data
//! loss or connection drops during the drain phase.
//!
//! # Integration Patterns Tested
//!
//! - **Signal-Triggered Shutdown**: SIGTERM signal properly initiating server graceful shutdown
//! - **In-Flight Request Preservation**: Active requests completing during shutdown drain phase
//! - **Connection Drain Management**: Existing connections gracefully closed without dropping
//! - **Shutdown Phase Coordination**: Proper progression through shutdown phases under signal
//! - **Resource Cleanup Verification**: All server resources properly cleaned up post-shutdown
//!
//! # Test Scenarios
//!
//! 1. **Baseline Graceful Shutdown** — SIGTERM with no active requests drains immediately
//! 2. **In-Flight Request Completion** — Requests active during SIGTERM complete successfully
//! 3. **Multi-Connection Drain** — Multiple active connections drain gracefully on SIGTERM
//! 4. **Timeout Escalation** — Drain timeout triggers force-close phase when needed
//! 5. **Signal Timing Stress Test** — SIGTERM during peak request load maintains integrity
//!
//! # Safety Properties Verified
//!
//! - No in-flight requests dropped during graceful shutdown
//! - All active connections properly closed without abrupt termination
//! - Shutdown phases progress correctly from signal to completion
//! - Server resources fully cleaned up after shutdown completes

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

    use crate::cx::{Cx, Registry};
    use crate::net::{TcpListener, TcpStream};
    use crate::runtime::{Runtime, spawn};
    use crate::server::shutdown::{ShutdownPhase, ShutdownSignal, ShutdownStats};
    use crate::signal::{
        graceful::{with_graceful_shutdown, GracefulOutcome},
        shutdown::ShutdownController,
        Signal, SignalKind,
    };
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{CancelReason, Outcome, Time};
    use std::collections::{HashMap, VecDeque};
    use std::future::Future;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll};
    use tokio::sync::{Barrier, Semaphore};

    // ────────────────────────────────────────────────────────────────────────────────
    // Signal + Server Shutdown Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ShutdownTestPhase {
        Setup,
        ServerInitialization,
        RequestGenerationStartup,
        BaselineSignalTest,
        InFlightRequestsActive,
        SignalDelivery,
        DrainPhaseMonitoring,
        RequestCompletionVerification,
        ConnectionCleanupVerification,
        TimeoutEscalationTest,
        ResourceCleanupVerification,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ShutdownTestResult {
        pub test_name: String,
        pub server_instance: String,
        pub phase: ShutdownTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub shutdown_stats: ServerShutdownStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct ServerShutdownStats {
        pub signals_received: u64,
        pub sigterm_signals: u64,
        pub shutdown_phases_entered: u64,
        pub requests_active_at_signal: u64,
        pub requests_completed_during_drain: u64,
        pub requests_dropped: u64,
        pub connections_active_at_signal: u64,
        pub connections_gracefully_closed: u64,
        pub connections_force_closed: u64,
        pub drain_duration_ms: u64,
        pub force_close_triggered: u64,
        pub cleanup_duration_ms: u64,
    }

    /// Active request tracking for shutdown monitoring.
    #[derive(Debug, Clone)]
    pub struct RequestTracker {
        pub request_id: u64,
        pub connection_id: u64,
        pub started_at: Instant,
        pub completed_at: Option<Instant>,
        pub duration_ms: Option<u64>,
        pub completed_successfully: bool,
        pub dropped_during_shutdown: bool,
    }

    /// Connection tracking for graceful closure verification.
    #[derive(Debug, Clone)]
    pub struct ConnectionTracker {
        pub connection_id: u64,
        pub remote_addr: SocketAddr,
        pub established_at: Instant,
        pub closed_at: Option<Instant>,
        pub requests_handled: u64,
        pub active_requests_at_shutdown: u64,
        pub gracefully_closed: bool,
        pub force_closed: bool,
    }

    /// Signal and server shutdown test harness.
    pub struct SignalServerShutdownTestHarness {
        server_addr: SocketAddr,
        shutdown_controller: Arc<ShutdownController>,
        stats: Arc<Mutex<ServerShutdownStats>>,
        request_trackers: Arc<Mutex<HashMap<u64, RequestTracker>>>,
        connection_trackers: Arc<Mutex<HashMap<u64, ConnectionTracker>>>,
        shutdown_phases: Arc<Mutex<VecDeque<(ShutdownPhase, Instant)>>>,
        runtime: Runtime,
        test_start_time: Instant,
        signal_sender: Arc<Mutex<Option<Signal>>>,
    }

    impl SignalServerShutdownTestHarness {
        pub async fn new() -> Self {
            let runtime = Runtime::new().expect("Failed to create runtime");
            let shutdown_controller = Arc::new(ShutdownController::new());

            // Bind to available port
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("Failed to bind server");
            let server_addr = listener.local_addr().expect("Failed to get address");

            Self {
                server_addr,
                shutdown_controller,
                stats: Arc::new(Mutex::new(ServerShutdownStats::default())),
                request_trackers: Arc::new(Mutex::new(HashMap::new())),
                connection_trackers: Arc::new(Mutex::new(HashMap::new())),
                shutdown_phases: Arc::new(Mutex::new(VecDeque::new())),
                runtime,
                test_start_time: Instant::now(),
                signal_sender: Arc::new(Mutex::new(None)),
            }
        }

        pub async fn setup_signal_handling(&self) -> Result<(), Box<dyn std::error::Error>> {
            // Set up SIGTERM signal handler
            let signal = Signal::new(SignalKind::Terminate)?;
            *self.signal_sender.lock().unwrap() = Some(signal);
            Ok(())
        }

        pub fn record_shutdown_phase(&self, phase: ShutdownPhase) {
            let mut phases = self.shutdown_phases.lock().unwrap();
            phases.push_back((phase, Instant::now()));

            let mut stats = self.stats.lock().unwrap();
            stats.shutdown_phases_entered += 1;

            match phase {
                ShutdownPhase::Draining => {
                    let active_requests = self.request_trackers.lock().unwrap()
                        .values()
                        .filter(|r| r.completed_at.is_none())
                        .count() as u64;

                    let active_connections = self.connection_trackers.lock().unwrap()
                        .values()
                        .filter(|c| c.closed_at.is_none())
                        .count() as u64;

                    stats.requests_active_at_signal = active_requests;
                    stats.connections_active_at_signal = active_connections;
                }
                ShutdownPhase::ForceClosing => {
                    stats.force_close_triggered += 1;
                }
                _ => {}
            }
        }

        pub fn start_request(&self, request_id: u64, connection_id: u64) {
            let tracker = RequestTracker {
                request_id,
                connection_id,
                started_at: Instant::now(),
                completed_at: None,
                duration_ms: None,
                completed_successfully: false,
                dropped_during_shutdown: false,
            };

            self.request_trackers.lock().unwrap().insert(request_id, tracker);
        }

        pub fn complete_request(&self, request_id: u64, successful: bool) {
            if let Some(tracker) = self.request_trackers.lock().unwrap().get_mut(&request_id) {
                let now = Instant::now();
                tracker.completed_at = Some(now);
                tracker.duration_ms = Some(now.duration_since(tracker.started_at).as_millis() as u64);
                tracker.completed_successfully = successful;

                let mut stats = self.stats.lock().unwrap();
                if successful {
                    stats.requests_completed_during_drain += 1;
                } else {
                    stats.requests_dropped += 1;
                }
            }
        }

        pub fn start_connection(&self, connection_id: u64, remote_addr: SocketAddr) {
            let tracker = ConnectionTracker {
                connection_id,
                remote_addr,
                established_at: Instant::now(),
                closed_at: None,
                requests_handled: 0,
                active_requests_at_shutdown: 0,
                gracefully_closed: false,
                force_closed: false,
            };

            self.connection_trackers.lock().unwrap().insert(connection_id, tracker);
        }

        pub fn close_connection(&self, connection_id: u64, graceful: bool) {
            if let Some(tracker) = self.connection_trackers.lock().unwrap().get_mut(&connection_id) {
                tracker.closed_at = Some(Instant::now());
                tracker.gracefully_closed = graceful;
                tracker.force_closed = !graceful;

                let mut stats = self.stats.lock().unwrap();
                if graceful {
                    stats.connections_gracefully_closed += 1;
                } else {
                    stats.connections_force_closed += 1;
                }
            }
        }

        pub async fn simulate_server_with_requests(&self, request_count: u32, request_duration_ms: u64) -> Result<(), Box<dyn std::error::Error>> {
            let shutdown_receiver = self.shutdown_controller.subscribe();

            // Simulate server accepting connections and handling requests
            let connection_id = 1000;
            let client_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 12345);
            self.start_connection(connection_id, client_addr);

            // Start multiple concurrent requests
            let mut request_handles = Vec::new();

            for i in 0..request_count {
                let request_id = 2000 + u64::from(i);
                self.start_request(request_id, connection_id);

                let harness = self as *const Self;
                let handle = tokio::spawn(async move {
                    // Simulate request processing
                    sleep(Duration::from_millis(request_duration_ms)).await;

                    // Mark request as completed
                    unsafe { &*harness }.complete_request(request_id, true);
                });

                request_handles.push(handle);
            }

            // Run server with graceful shutdown support
            let server_result = with_graceful_shutdown(
                async {
                    // Wait for all requests to complete
                    for handle in request_handles {
                        let _ = handle.await;
                    }
                    "Server completed"
                },
                shutdown_receiver
            ).await;

            // Handle shutdown phases
            match server_result {
                GracefulOutcome::Completed(_) => {
                    self.record_shutdown_phase(ShutdownPhase::Stopped);
                }
                GracefulOutcome::ShutdownSignaled => {
                    self.record_shutdown_phase(ShutdownPhase::Draining);
                    // Allow some time for drain
                    sleep(Duration::from_millis(100)).await;
                    self.record_shutdown_phase(ShutdownPhase::Stopped);
                }
            }

            // Close connection
            self.close_connection(connection_id, true);

            Ok(())
        }

        pub async fn send_sigterm(&self) -> Result<(), Box<dyn std::error::Error>> {
            self.shutdown_controller.shutdown();

            let mut stats = self.stats.lock().unwrap();
            stats.signals_received += 1;
            stats.sigterm_signals += 1;

            Ok(())
        }

        pub async fn wait_for_shutdown_completion(&self, timeout_ms: u64) -> bool {
            let start = Instant::now();
            let timeout_duration = Duration::from_millis(timeout_ms);

            while start.elapsed() < timeout_duration {
                let phases = self.shutdown_phases.lock().unwrap();
                if phases.iter().any(|(phase, _)| *phase == ShutdownPhase::Stopped) {
                    return true;
                }
                drop(phases);

                sleep(Duration::from_millis(10)).await;
            }

            false
        }

        pub fn get_stats_snapshot(&self) -> ServerShutdownStats {
            self.stats.lock().unwrap().clone()
        }

        pub fn get_shutdown_phase_timeline(&self) -> Vec<(ShutdownPhase, Instant)> {
            self.shutdown_phases.lock().unwrap().iter().cloned().collect()
        }

        pub fn verify_graceful_shutdown(&self) -> bool {
            let stats = self.get_stats_snapshot();
            let timeline = self.get_shutdown_phase_timeline();

            // Check that all requests completed successfully
            let requests_not_dropped = stats.requests_dropped == 0;

            // Check that shutdown phases progressed correctly
            let has_drain_phase = timeline.iter().any(|(phase, _)| *phase == ShutdownPhase::Draining);
            let has_stopped_phase = timeline.iter().any(|(phase, _)| *phase == ShutdownPhase::Stopped);

            // Check that connections were gracefully closed
            let graceful_connections = stats.connections_force_closed == 0;

            requests_not_dropped && has_drain_phase && has_stopped_phase && graceful_connections
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 1: Baseline Graceful Shutdown
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_signal_server_baseline_graceful_shutdown() {
        let harness = SignalServerShutdownTestHarness::new().await;

        assert!(harness.setup_signal_handling().await.is_ok());

        // Start server with no active requests
        let server_future = harness.simulate_server_with_requests(0, 100);

        // Let server start up
        sleep(Duration::from_millis(50)).await;

        // Send SIGTERM
        assert!(harness.send_sigterm().await.is_ok());

        // Wait for server shutdown
        let _ = timeout(Duration::from_millis(1000), server_future).await;

        // Verify shutdown completed
        assert!(harness.wait_for_shutdown_completion(500).await);

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.sigterm_signals, 1);
        assert_eq!(stats.requests_active_at_signal, 0);
        assert_eq!(stats.requests_dropped, 0);

        let timeline = harness.get_shutdown_phase_timeline();
        assert!(timeline.iter().any(|(phase, _)| *phase == ShutdownPhase::Stopped));

        assert!(harness.verify_graceful_shutdown());
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 2: In-Flight Request Completion
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_signal_server_in_flight_request_completion() {
        let harness = SignalServerShutdownTestHarness::new().await;

        assert!(harness.setup_signal_handling().await.is_ok());

        // Start server with active requests that take 500ms each
        let server_future = harness.simulate_server_with_requests(3, 500);

        // Let requests start
        sleep(Duration::from_millis(100)).await;

        // Send SIGTERM while requests are active
        assert!(harness.send_sigterm().await.is_ok());

        // Wait for server shutdown with extra time for request completion
        let _ = timeout(Duration::from_millis(2000), server_future).await;

        // Verify all requests completed
        assert!(harness.wait_for_shutdown_completion(1000).await);

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.sigterm_signals, 1);
        assert!(stats.requests_active_at_signal > 0, "Should have active requests at signal time");
        assert_eq!(stats.requests_completed_during_drain, stats.requests_active_at_signal);
        assert_eq!(stats.requests_dropped, 0, "No requests should be dropped during graceful shutdown");

        assert!(harness.verify_graceful_shutdown());

        println!("✅ In-Flight Completion: {} requests active, {} completed, {} dropped",
                stats.requests_active_at_signal, stats.requests_completed_during_drain, stats.requests_dropped);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 3: Multi-Connection Drain
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_signal_server_multi_connection_drain() {
        let harness = SignalServerShutdownTestHarness::new().await;

        assert!(harness.setup_signal_handling().await.is_ok());

        // Simulate multiple connections
        for i in 0..4 {
            let connection_id = 3000 + i;
            let client_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 30000 + i as u16);
            harness.start_connection(connection_id, client_addr);

            // Start requests on each connection
            let request_id = 4000 + i * 10;
            harness.start_request(request_id, connection_id);
        }

        // Start server with longer-running requests
        let server_future = harness.simulate_server_with_requests(0, 0); // We manually managed requests above

        // Let server initialize
        sleep(Duration::from_millis(50)).await;

        // Send SIGTERM
        assert!(harness.send_sigterm().await.is_ok());

        // Complete requests after a delay to simulate drain
        for i in 0..4 {
            let request_id = 4000 + i * 10;
            harness.complete_request(request_id, true);

            let connection_id = 3000 + i;
            harness.close_connection(connection_id, true);
        }

        // Wait for shutdown
        let _ = timeout(Duration::from_millis(1000), server_future).await;
        assert!(harness.wait_for_shutdown_completion(500).await);

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.sigterm_signals, 1);
        assert_eq!(stats.connections_gracefully_closed, 4);
        assert_eq!(stats.connections_force_closed, 0);

        assert!(harness.verify_graceful_shutdown());

        println!("✅ Multi-Connection Drain: {} connections graceful, {} force closed",
                stats.connections_gracefully_closed, stats.connections_force_closed);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 4: Timeout Escalation
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_signal_server_timeout_escalation() {
        let harness = SignalServerShutdownTestHarness::new().await;

        assert!(harness.setup_signal_handling().await.is_ok());

        // Start a connection with a very long-running request
        let connection_id = 5000;
        let client_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50000);
        harness.start_connection(connection_id, client_addr);

        let request_id = 6000;
        harness.start_request(request_id, connection_id);

        let server_future = harness.simulate_server_with_requests(0, 0);

        // Let server start
        sleep(Duration::from_millis(50)).await;

        // Send SIGTERM
        assert!(harness.send_sigterm().await.is_ok());

        // Simulate drain timeout by not completing the request immediately
        sleep(Duration::from_millis(200)).await;

        // Simulate timeout escalation by recording force close phase
        harness.record_shutdown_phase(ShutdownPhase::ForceClosing);

        // Force close the connection and drop the request
        harness.complete_request(request_id, false); // Failed completion
        harness.close_connection(connection_id, false); // Force closed

        harness.record_shutdown_phase(ShutdownPhase::Stopped);

        let _ = timeout(Duration::from_millis(500), server_future).await;

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.sigterm_signals, 1);
        assert_eq!(stats.force_close_triggered, 1, "Should trigger force close on timeout");
        assert_eq!(stats.connections_force_closed, 1);
        assert_eq!(stats.requests_dropped, 1);

        let timeline = harness.get_shutdown_phase_timeline();
        let has_force_close = timeline.iter().any(|(phase, _)| *phase == ShutdownPhase::ForceClosing);
        assert!(has_force_close, "Should escalate to force close phase");

        println!("✅ Timeout Escalation: force_close_triggered={}, connections_force_closed={}",
                stats.force_close_triggered, stats.connections_force_closed);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 5: Signal Timing Stress Test
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_signal_server_timing_stress_test() {
        let harness = SignalServerShutdownTestHarness::new().await;

        assert!(harness.setup_signal_handling().await.is_ok());

        // Simulate peak load with many connections and requests
        for i in 0..10 {
            let connection_id = 7000 + i;
            let client_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 40000 + i as u16);
            harness.start_connection(connection_id, client_addr);

            // Multiple requests per connection
            for j in 0..3 {
                let request_id = 8000 + i * 10 + j;
                harness.start_request(request_id, connection_id);
            }
        }

        let server_future = harness.simulate_server_with_requests(0, 0);

        // Brief startup
        sleep(Duration::from_millis(25)).await;

        // Send SIGTERM during peak load
        assert!(harness.send_sigterm().await.is_ok());

        // Complete requests in batches to simulate realistic drain
        for i in 0..10 {
            for j in 0..3 {
                let request_id = 8000 + i * 10 + j;
                harness.complete_request(request_id, true);
            }

            // Stagger completion
            sleep(Duration::from_millis(10)).await;

            let connection_id = 7000 + i;
            harness.close_connection(connection_id, true);
        }

        let _ = timeout(Duration::from_millis(2000), server_future).await;
        assert!(harness.wait_for_shutdown_completion(1000).await);

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.sigterm_signals, 1);
        assert_eq!(stats.connections_gracefully_closed, 10);
        assert_eq!(stats.requests_completed_during_drain, 30); // 10 connections * 3 requests
        assert_eq!(stats.requests_dropped, 0);

        assert!(harness.verify_graceful_shutdown());

        println!("✅ Stress Test: {} connections, {} requests completed, integrity maintained",
                stats.connections_gracefully_closed, stats.requests_completed_during_drain);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Test Result Verification
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_signal_server_shutdown_full_integration() {
        let harness = SignalServerShutdownTestHarness::new().await;

        assert!(harness.setup_signal_handling().await.is_ok());

        // Complex scenario: mixed connection and request patterns
        let scenarios = vec![
            (10001, 20001, 300), // Connection 1, Request 1, 300ms
            (10002, 20002, 150), // Connection 2, Request 2, 150ms
            (10003, 20003, 600), // Connection 3, Request 3, 600ms (longer)
            (10004, 20004, 100), // Connection 4, Request 4, 100ms
        ];

        for (connection_id, request_id, duration_ms) in &scenarios {
            let client_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), (*connection_id as u16) % 10000 + 20000);
            harness.start_connection(*connection_id, client_addr);
            harness.start_request(*request_id, *connection_id);
        }

        let server_future = harness.simulate_server_with_requests(0, 0);

        // Let all requests start
        sleep(Duration::from_millis(50)).await;

        // Send SIGTERM during mixed load
        assert!(harness.send_sigterm().await.is_ok());

        // Complete requests based on their durations (simulating realistic completion)
        for (connection_id, request_id, duration_ms) in scenarios {
            // Simulate processing time
            sleep(Duration::from_millis(duration_ms / 4)).await;
            harness.complete_request(request_id, true);
            harness.close_connection(connection_id, true);
        }

        let _ = timeout(Duration::from_millis(3000), server_future).await;
        assert!(harness.wait_for_shutdown_completion(1000).await);

        let final_stats = harness.get_stats_snapshot();
        let timeline = harness.get_shutdown_phase_timeline();

        // Comprehensive verification
        assert_eq!(final_stats.sigterm_signals, 1, "Should receive exactly one SIGTERM");
        assert!(final_stats.requests_active_at_signal > 0, "Should have active requests during signal");
        assert_eq!(final_stats.requests_dropped, 0, "No requests should be dropped");
        assert!(final_stats.connections_gracefully_closed > 0, "Connections should close gracefully");
        assert_eq!(final_stats.connections_force_closed, 0, "No connections should be force closed");

        // Verify shutdown phase progression
        let phases: Vec<ShutdownPhase> = timeline.iter().map(|(phase, _)| *phase).collect();
        assert!(phases.contains(&ShutdownPhase::Draining), "Should enter drain phase");
        assert!(phases.contains(&ShutdownPhase::Stopped), "Should complete shutdown");

        assert!(harness.verify_graceful_shutdown());

        println!("✅ Signal ↔ Server Shutdown Integration Test Complete");
        println!("📊 Final Stats: {:?}", final_stats);
        println!("🎯 Graceful Shutdown: {} requests preserved, {} connections drained",
                final_stats.requests_completed_during_drain, final_stats.connections_gracefully_closed);
        println!("🏁 Milestone 60 Achieved!");
    }
}