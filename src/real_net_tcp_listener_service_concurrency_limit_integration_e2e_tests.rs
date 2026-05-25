//! br-e2e-146: Real net/tcp/listener ↔ service/concurrency_limit integration tests
//!
//! Verifies that concurrency limiter correctly back-pressures listener accept loop
//! when at saturation. Tests the integration between:
//!
//! - `net::tcp::listener`: TCP connection acceptance and listener management
//! - `service::concurrency_limit`: Request concurrency limiting and back-pressure
//!
//! Key integration properties:
//! - Concurrency limiter correctly back-pressures listener accept loop at saturation
//! - Back-pressure prevents connection acceptance when limit is reached
//! - Graceful recovery when connections complete and limit becomes available
//! - Proper coordination between TCP accept and concurrency enforcement
//! - Resource exhaustion prevention through coordinated limiting

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::{
        channel::{broadcast, mpsc, oneshot},
        cx::Cx,
        error::{Error, ErrorKind},
        net::tcp::{TcpListener, TcpSocketAddr, TcpStream},
        runtime::Runtime,
        service::concurrency_limit::{ConcurrencyLimitConfig, ConcurrencyLimiter, LimitExceeded},
        service::{Service, ServiceExt},
        sync::{AtomicBool, AtomicU64, Mutex, Semaphore},
        test_utils::{TestTracer, find_available_port, init_test_runtime},
        time::{Duration, Instant, Sleep},
        types::{Budget, Outcome, TaskId},
    };
    use std::collections::{HashMap, VecDeque};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    /// Test framework for TCP listener-concurrency limit integration scenarios
    struct TcpConcurrencyTestFramework {
        runtime: Runtime,
        tracer: TestTracer,
        listener: TcpListener,
        concurrency_limiter: ConcurrencyLimiter,
        stats: Arc<IntegrationStats>,
        config: IntegrationConfig,
    }

    /// Statistics for TCP-concurrency integration
    #[derive(Debug)]
    struct IntegrationStats {
        connections_attempted: AtomicU64,
        connections_accepted: AtomicU64,
        connections_rejected: AtomicU64,
        connections_completed: AtomicU64,
        back_pressure_events: AtomicU64,
        saturation_events: AtomicU64,
        accept_loop_blocks: AtomicU64,
        recovery_events: AtomicU64,
    }

    /// Configuration for TCP-concurrency integration testing
    struct IntegrationConfig {
        concurrency_limit: usize,
        listener_port: u16,
        connection_duration: Duration,
        concurrent_clients: usize,
        back_pressure_threshold: f64,
        enable_monitoring: bool,
    }

    /// Represents a TCP connection with concurrency tracking
    struct TrackedConnection {
        id: u64,
        stream: TcpStream,
        accepted_at: Instant,
        client_addr: SocketAddr,
        concurrency_token: Option<ConcurrencyToken>,
    }

    /// Token representing concurrency slot allocation
    struct ConcurrencyToken {
        id: u64,
        allocated_at: Instant,
        release_callback: Option<oneshot::Sender<()>>,
    }

    /// Monitors back-pressure effects on accept loop
    struct AcceptLoopMonitor {
        accept_times: Arc<Mutex<VecDeque<(Instant, bool)>>>, // (timestamp, accepted)
        back_pressure_detector: Arc<BackPressureDetector>,
        saturation_tracker: Arc<SaturationTracker>,
    }

    /// Detects back-pressure patterns in accept loop
    struct BackPressureDetector {
        rejection_window: Arc<Mutex<VecDeque<Instant>>>,
        threshold_calculator: Arc<ThresholdCalculator>,
        detection_sensitivity: f64,
    }

    /// Tracks saturation and recovery cycles
    struct SaturationTracker {
        saturation_periods: Arc<Mutex<Vec<SaturationPeriod>>>,
        current_saturation: Arc<AtomicBool>,
        recovery_monitor: Arc<RecoveryMonitor>,
    }

    /// Represents a period of concurrency saturation
    #[derive(Debug, Clone)]
    struct SaturationPeriod {
        start_time: Instant,
        end_time: Option<Instant>,
        peak_connections: u32,
        rejection_count: u32,
        recovery_duration: Option<Duration>,
    }

    /// Monitors recovery from saturation
    struct RecoveryMonitor {
        recovery_events: Arc<Mutex<Vec<RecoveryEvent>>>,
        recovery_threshold: f64,
    }

    /// Represents a recovery event from saturation
    #[derive(Debug, Clone)]
    struct RecoveryEvent {
        timestamp: Instant,
        connections_before: u32,
        connections_after: u32,
        recovery_rate: f64,
    }

    /// Calculates dynamic thresholds for back-pressure detection
    struct ThresholdCalculator {
        baseline_threshold: f64,
        adaptive_factor: AtomicU64, // Fixed point: value * 1000
        utilization_history: Arc<Mutex<VecDeque<(Instant, f64)>>>,
    }

    /// Client simulator for concurrent connection testing
    struct ConnectionSimulator {
        client_id: u32,
        connection_duration: Duration,
        retry_attempts: u32,
        success_callback: Option<oneshot::Sender<ConnectionResult>>,
    }

    /// Result from connection simulation
    #[derive(Debug)]
    struct ConnectionResult {
        client_id: u32,
        success: bool,
        connection_time: Duration,
        rejection_reason: Option<String>,
        back_pressure_detected: bool,
    }

    impl TcpConcurrencyTestFramework {
        async fn new(cx: &Cx, config: IntegrationConfig) -> Result<Self, Error> {
            let runtime = init_test_runtime(cx).await?;
            let tracer = TestTracer::new();

            // Create TCP listener on configured port
            let listener_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), config.listener_port);
            let listener = TcpListener::bind(cx, listener_addr).await?;

            // Configure concurrency limiter
            let limiter_config = ConcurrencyLimitConfig {
                max_concurrent: config.concurrency_limit,
                queue_size: config.concurrency_limit / 2,
                timeout: Duration::from_secs(5),
                enable_back_pressure: true,
            };
            let concurrency_limiter = ConcurrencyLimiter::new(limiter_config)?;

            let stats = Arc::new(IntegrationStats {
                connections_attempted: AtomicU64::new(0),
                connections_accepted: AtomicU64::new(0),
                connections_rejected: AtomicU64::new(0),
                connections_completed: AtomicU64::new(0),
                back_pressure_events: AtomicU64::new(0),
                saturation_events: AtomicU64::new(0),
                accept_loop_blocks: AtomicU64::new(0),
                recovery_events: AtomicU64::new(0),
            });

            Ok(Self {
                runtime,
                tracer,
                listener,
                concurrency_limiter,
                stats,
                config,
            })
        }

        /// Execute TCP accept loop with concurrency limiting
        async fn execute_accept_loop_with_concurrency_limit(
            &self,
            cx: &Cx,
            test_duration: Duration,
        ) -> Result<AcceptLoopResults, Error> {
            let monitor = Arc::new(AcceptLoopMonitor {
                accept_times: Arc::new(Mutex::new(VecDeque::new())),
                back_pressure_detector: Arc::new(BackPressureDetector::new(0.8)),
                saturation_tracker: Arc::new(SaturationTracker::new()),
            });

            // Start accept loop with concurrency limiting
            let accept_handle = self.start_monitored_accept_loop(cx, &monitor).await?;

            // Start client simulator
            let client_handle = self.start_client_simulator(cx).await?;

            // Run test for specified duration
            Sleep::new(test_duration).await;

            // Stop accept loop and clients
            accept_handle.cancel().await;
            client_handle.cancel().await;

            // Collect results
            Ok(AcceptLoopResults {
                total_attempted: self.stats.connections_attempted.load(Ordering::Relaxed),
                total_accepted: self.stats.connections_accepted.load(Ordering::Relaxed),
                total_rejected: self.stats.connections_rejected.load(Ordering::Relaxed),
                total_completed: self.stats.connections_completed.load(Ordering::Relaxed),
                back_pressure_events: self.stats.back_pressure_events.load(Ordering::Relaxed),
                saturation_events: self.stats.saturation_events.load(Ordering::Relaxed),
                accept_loop_blocks: self.stats.accept_loop_blocks.load(Ordering::Relaxed),
                recovery_events: self.stats.recovery_events.load(Ordering::Relaxed),
            })
        }

        /// Start monitored accept loop
        async fn start_monitored_accept_loop(
            &self,
            cx: &Cx,
            monitor: &AcceptLoopMonitor,
        ) -> Result<AcceptHandle, Error> {
            let (cancel_tx, cancel_rx) = oneshot::channel();
            let listener_ref = self.listener.clone();
            let limiter_ref = self.concurrency_limiter.clone();
            let stats_ref = Arc::clone(&self.stats);
            let monitor_ref = Arc::clone(monitor);
            let config = self.config.clone();

            let accept_task = cx
                .spawn(async move {
                    let mut connection_counter = 0u64;

                    loop {
                        // Check for cancellation
                        if cancel_rx.try_recv().is_ok() {
                            break;
                        }

                        let accept_start = Instant::now();

                        // Try to acquire concurrency limit before accepting
                        match limiter_ref.try_acquire().await {
                            Ok(permit) => {
                                // Accept connection with permit
                                match listener_ref.accept().await {
                                    Ok((stream, addr)) => {
                                        connection_counter += 1;
                                        stats_ref
                                            .connections_attempted
                                            .fetch_add(1, Ordering::Relaxed);
                                        stats_ref
                                            .connections_accepted
                                            .fetch_add(1, Ordering::Relaxed);

                                        let connection = TrackedConnection {
                                            id: connection_counter,
                                            stream,
                                            accepted_at: Instant::now(),
                                            client_addr: addr,
                                            concurrency_token: Some(ConcurrencyToken {
                                                id: connection_counter,
                                                allocated_at: accept_start,
                                                release_callback: None,
                                            }),
                                        };

                                        // Record accept time
                                        {
                                            let mut accept_times =
                                                monitor_ref.accept_times.lock().await;
                                            accept_times.push_back((accept_start, true));
                                            // Keep only recent records
                                            while accept_times.len() > 1000 {
                                                accept_times.pop_front();
                                            }
                                        }

                                        // Handle connection in background
                                        let stats_ref_inner = Arc::clone(&stats_ref);
                                        let config_inner = config.clone();
                                        cx.spawn(async move {
                                            // Simulate connection processing
                                            Sleep::new(config_inner.connection_duration).await;

                                            drop(permit); // Release concurrency limit
                                            stats_ref_inner
                                                .connections_completed
                                                .fetch_add(1, Ordering::Relaxed);
                                        })
                                        .await
                                        .ok();
                                    }
                                    Err(_) => {
                                        // Accept failed - might be due to back-pressure
                                        stats_ref
                                            .accept_loop_blocks
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            Err(LimitExceeded) => {
                                // Concurrency limit reached - back-pressure the accept loop
                                stats_ref
                                    .back_pressure_events
                                    .fetch_add(1, Ordering::Relaxed);
                                stats_ref.saturation_events.fetch_add(1, Ordering::Relaxed);

                                // Record back-pressure event
                                monitor_ref.back_pressure_detector.record_rejection().await;
                                monitor_ref.saturation_tracker.record_saturation().await;

                                // Record failed accept
                                {
                                    let mut accept_times = monitor_ref.accept_times.lock().await;
                                    accept_times.push_back((accept_start, false));
                                    while accept_times.len() > 1000 {
                                        accept_times.pop_front();
                                    }
                                }

                                // Back off to prevent CPU spinning
                                Sleep::new(Duration::from_millis(10)).await;
                            }
                        }
                    }
                })
                .await?;

            Ok(AcceptHandle {
                cancel_sender: cancel_tx,
                task_handle: accept_task,
            })
        }

        /// Start client connection simulator
        async fn start_client_simulator(&self, cx: &Cx) -> Result<ClientHandle, Error> {
            let (cancel_tx, cancel_rx) = oneshot::channel();
            let stats_ref = Arc::clone(&self.stats);
            let config = self.config.clone();
            let listener_addr = self.listener.local_addr()?;

            let client_task = cx
                .spawn(async move {
                    let mut client_counter = 0u32;

                    loop {
                        // Check for cancellation
                        if cancel_rx.try_recv().is_ok() {
                            break;
                        }

                        // Launch concurrent clients
                        let mut client_handles = Vec::new();
                        for _ in 0..config.concurrent_clients {
                            client_counter += 1;
                            let simulator = ConnectionSimulator::new(
                                client_counter,
                                config.connection_duration,
                            );
                            let handle = simulator.connect_and_process(cx, listener_addr).await;
                            client_handles.push(handle);
                        }

                        // Wait for clients to complete
                        for handle in client_handles {
                            if let Ok(result) = handle.await {
                                stats_ref
                                    .connections_attempted
                                    .fetch_add(1, Ordering::Relaxed);
                                if result.success {
                                    // Connection was successful - stats already updated by accept loop
                                } else {
                                    stats_ref
                                        .connections_rejected
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }

                        // Brief pause between rounds
                        Sleep::new(Duration::from_millis(100)).await;
                    }
                })
                .await?;

            Ok(ClientHandle {
                cancel_sender: cancel_tx,
                task_handle: client_task,
            })
        }
    }

    impl BackPressureDetector {
        fn new(sensitivity: f64) -> Self {
            Self {
                rejection_window: Arc::new(Mutex::new(VecDeque::new())),
                threshold_calculator: Arc::new(ThresholdCalculator::new(0.8)),
                detection_sensitivity: sensitivity,
            }
        }

        async fn record_rejection(&self) {
            let mut window = self.rejection_window.lock().await;
            let now = Instant::now();
            window.push_back(now);

            // Keep only rejections from last second
            while let Some(&front_time) = window.front() {
                if now.duration_since(front_time) > Duration::from_secs(1) {
                    window.pop_front();
                } else {
                    break;
                }
            }
        }

        async fn detect_back_pressure_pattern(&self) -> bool {
            let window = self.rejection_window.lock().await;
            // Consider back-pressure if more than 5 rejections in the last second
            window.len() > 5
        }
    }

    impl SaturationTracker {
        fn new() -> Self {
            Self {
                saturation_periods: Arc::new(Mutex::new(Vec::new())),
                current_saturation: Arc::new(AtomicBool::new(false)),
                recovery_monitor: Arc::new(RecoveryMonitor::new()),
            }
        }

        async fn record_saturation(&self) {
            let was_saturated = self.current_saturation.swap(true, Ordering::Relaxed);
            if !was_saturated {
                // Start new saturation period
                let mut periods = self.saturation_periods.lock().await;
                periods.push(SaturationPeriod {
                    start_time: Instant::now(),
                    end_time: None,
                    peak_connections: 0,
                    rejection_count: 1,
                    recovery_duration: None,
                });
            } else {
                // Update existing saturation period
                let mut periods = self.saturation_periods.lock().await;
                if let Some(current_period) = periods.last_mut() {
                    current_period.rejection_count += 1;
                }
            }
        }

        async fn record_recovery(&self) {
            let was_saturated = self.current_saturation.swap(false, Ordering::Relaxed);
            if was_saturated {
                // End current saturation period
                let mut periods = self.saturation_periods.lock().await;
                if let Some(current_period) = periods.last_mut() {
                    let now = Instant::now();
                    current_period.end_time = Some(now);
                    current_period.recovery_duration =
                        Some(now.duration_since(current_period.start_time));
                }

                self.recovery_monitor.record_recovery_event().await;
            }
        }
    }

    impl RecoveryMonitor {
        fn new() -> Self {
            Self {
                recovery_events: Arc::new(Mutex::new(Vec::new())),
                recovery_threshold: 0.5,
            }
        }

        async fn record_recovery_event(&self) {
            let mut events = self.recovery_events.lock().await;
            events.push(RecoveryEvent {
                timestamp: Instant::now(),
                connections_before: 0, // Would be calculated from actual state
                connections_after: 0,  // Would be calculated from actual state
                recovery_rate: 1.0,
            });
        }
    }

    impl ThresholdCalculator {
        fn new(baseline: f64) -> Self {
            Self {
                baseline_threshold: baseline,
                adaptive_factor: AtomicU64::new(1000), // 1.0 in fixed point
                utilization_history: Arc::new(Mutex::new(VecDeque::new())),
            }
        }
    }

    impl ConnectionSimulator {
        fn new(client_id: u32, duration: Duration) -> Self {
            Self {
                client_id,
                connection_duration: duration,
                retry_attempts: 3,
                success_callback: None,
            }
        }

        async fn connect_and_process(
            &self,
            cx: &Cx,
            target_addr: SocketAddr,
        ) -> oneshot::Receiver<ConnectionResult> {
            let (result_tx, result_rx) = oneshot::channel();
            let client_id = self.client_id;
            let duration = self.connection_duration;

            cx.spawn(async move {
                let start_time = Instant::now();
                let mut success = false;
                let mut rejection_reason = None;
                let mut back_pressure_detected = false;

                // Attempt connection
                match TcpStream::connect(cx, target_addr).await {
                    Ok(stream) => {
                        success = true;
                        // Simulate data exchange
                        Sleep::new(duration).await;
                        drop(stream);
                    }
                    Err(e) => {
                        rejection_reason = Some(format!("Connection failed: {}", e));
                        // Check if error indicates back-pressure
                        back_pressure_detected = e.to_string().contains("Connection refused")
                            || e.to_string().contains("timeout");
                    }
                }

                let result = ConnectionResult {
                    client_id,
                    success,
                    connection_time: start_time.elapsed(),
                    rejection_reason,
                    back_pressure_detected,
                };

                let _ = result_tx.send(result);
            })
            .await
            .ok();

            result_rx
        }
    }

    impl Clone for IntegrationConfig {
        fn clone(&self) -> Self {
            Self {
                concurrency_limit: self.concurrency_limit,
                listener_port: self.listener_port,
                connection_duration: self.connection_duration,
                concurrent_clients: self.concurrent_clients,
                back_pressure_threshold: self.back_pressure_threshold,
                enable_monitoring: self.enable_monitoring,
            }
        }
    }

    /// Results from accept loop execution
    #[derive(Debug)]
    struct AcceptLoopResults {
        total_attempted: u64,
        total_accepted: u64,
        total_rejected: u64,
        total_completed: u64,
        back_pressure_events: u64,
        saturation_events: u64,
        accept_loop_blocks: u64,
        recovery_events: u64,
    }

    /// Handle for controlling accept loop
    struct AcceptHandle {
        cancel_sender: oneshot::Sender<()>,
        task_handle: TaskId,
    }

    impl AcceptHandle {
        async fn cancel(self) {
            let _ = self.cancel_sender.send(());
            Sleep::new(Duration::from_millis(50)).await;
        }
    }

    /// Handle for controlling client simulator
    struct ClientHandle {
        cancel_sender: oneshot::Sender<()>,
        task_handle: TaskId,
    }

    impl ClientHandle {
        async fn cancel(self) {
            let _ = self.cancel_sender.send(());
            Sleep::new(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn test_concurrency_limit_back_pressures_accept_loop() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            concurrency_limit: 5,
            listener_port: find_available_port(),
            connection_duration: Duration::from_millis(500),
            concurrent_clients: 20, // More clients than limit
            back_pressure_threshold: 0.8,
            enable_monitoring: true,
        };

        let framework = TcpConcurrencyTestFramework::new(&cx, config).await.unwrap();
        let test_duration = Duration::from_secs(3);

        let results = framework
            .execute_accept_loop_with_concurrency_limit(&cx, test_duration)
            .await
            .unwrap();

        // Verify back-pressure behavior
        assert!(
            results.back_pressure_events > 0,
            "Should detect back-pressure events"
        );
        assert!(
            results.saturation_events > 0,
            "Should detect saturation events"
        );
        assert!(
            results.total_rejected > 0,
            "Some connections should be rejected due to concurrency limit"
        );

        // Verify concurrency limit enforcement
        assert!(
            results.total_accepted <= (config.concurrency_limit as u64) * 10,
            "Accepted connections should respect concurrency limit over time"
        );

        // Verify accept loop blocks when saturated
        assert!(
            results.accept_loop_blocks > 0,
            "Accept loop should block when concurrency limit reached"
        );

        cx.trace("Concurrency limit correctly back-pressures accept loop")
            .await;
    }

    #[tokio::test]
    async fn test_accept_loop_recovery_after_saturation() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            concurrency_limit: 3,
            listener_port: find_available_port(),
            connection_duration: Duration::from_millis(200), // Shorter duration for faster recovery
            concurrent_clients: 10,
            back_pressure_threshold: 0.7,
            enable_monitoring: true,
        };

        let framework = TcpConcurrencyTestFramework::new(&cx, config).await.unwrap();
        let test_duration = Duration::from_secs(4);

        let results = framework
            .execute_accept_loop_with_concurrency_limit(&cx, test_duration)
            .await
            .unwrap();

        // Verify saturation and recovery cycle
        assert!(
            results.saturation_events > 0,
            "Should experience saturation"
        );
        assert!(
            results.recovery_events > 0,
            "Should recover from saturation"
        );
        assert!(
            results.total_completed > 0,
            "Some connections should complete"
        );

        // Verify accept loop continues functioning after recovery
        let acceptance_rate = results.total_accepted as f64 / results.total_attempted as f64;
        assert!(
            acceptance_rate > 0.1,
            "Should maintain some acceptance rate after recovery"
        );

        cx.trace("Accept loop recovers correctly after saturation")
            .await;
    }

    #[tokio::test]
    async fn test_gradual_load_increase_back_pressure() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            concurrency_limit: 8,
            listener_port: find_available_port(),
            connection_duration: Duration::from_millis(300),
            concurrent_clients: 5, // Start with low load
            back_pressure_threshold: 0.75,
            enable_monitoring: true,
        };

        let framework = TcpConcurrencyTestFramework::new(&cx, config).await.unwrap();

        // Test gradual load increase
        let phase1_results = framework
            .execute_accept_loop_with_concurrency_limit(&cx, Duration::from_secs(2))
            .await
            .unwrap();

        // Phase 1: Low load - should accept most connections
        assert!(
            phase1_results.back_pressure_events < 5,
            "Low back-pressure in phase 1"
        );

        // Increase concurrent clients for phase 2
        let high_load_config = IntegrationConfig {
            concurrent_clients: 25, // High load
            ..config
        };
        let high_load_framework = TcpConcurrencyTestFramework::new(&cx, high_load_config)
            .await
            .unwrap();

        let phase2_results = high_load_framework
            .execute_accept_loop_with_concurrency_limit(&cx, Duration::from_secs(2))
            .await
            .unwrap();

        // Phase 2: High load - should trigger back-pressure
        assert!(
            phase2_results.back_pressure_events > phase1_results.back_pressure_events,
            "Higher load should trigger more back-pressure"
        );
        assert!(
            phase2_results.saturation_events > 0,
            "High load should cause saturation"
        );

        cx.trace("Gradual load increase correctly triggers back-pressure")
            .await;
    }

    #[tokio::test]
    async fn test_burst_load_saturation_handling() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            concurrency_limit: 4,
            listener_port: find_available_port(),
            connection_duration: Duration::from_millis(400),
            concurrent_clients: 50, // Very high burst load
            back_pressure_threshold: 0.8,
            enable_monitoring: true,
        };

        let framework = TcpConcurrencyTestFramework::new(&cx, config).await.unwrap();
        let test_duration = Duration::from_secs(2);

        let results = framework
            .execute_accept_loop_with_concurrency_limit(&cx, test_duration)
            .await
            .unwrap();

        // Verify burst load handling
        assert!(
            results.saturation_events >= 10,
            "Burst load should cause immediate saturation"
        );
        assert!(
            results.back_pressure_events >= 20,
            "Should generate significant back-pressure"
        );

        // Verify system stability under burst
        assert!(
            results.total_accepted <= config.concurrency_limit as u64 * 10,
            "System should maintain concurrency limit under burst"
        );
        assert!(
            results.accept_loop_blocks > 0,
            "Accept loop should block frequently under burst"
        );

        // Verify graceful degradation
        let rejection_rate = results.total_rejected as f64 / results.total_attempted as f64;
        assert!(
            rejection_rate > 0.5,
            "Should reject majority of connections under burst load"
        );

        cx.trace("System handles burst load with proper back-pressure")
            .await;
    }

    #[tokio::test]
    async fn test_connection_duration_impact_on_back_pressure() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        // Test with short connection duration
        let short_config = IntegrationConfig {
            concurrency_limit: 6,
            listener_port: find_available_port(),
            connection_duration: Duration::from_millis(50), // Very short
            concurrent_clients: 15,
            back_pressure_threshold: 0.8,
            enable_monitoring: true,
        };

        let short_framework = TcpConcurrencyTestFramework::new(&cx, short_config)
            .await
            .unwrap();
        let short_results = short_framework
            .execute_accept_loop_with_concurrency_limit(&cx, Duration::from_secs(2))
            .await
            .unwrap();

        // Test with long connection duration
        let long_config = IntegrationConfig {
            connection_duration: Duration::from_millis(800), // Much longer
            listener_port: find_available_port(),
            ..short_config
        };

        let long_framework = TcpConcurrencyTestFramework::new(&cx, long_config)
            .await
            .unwrap();
        let long_results = long_framework
            .execute_accept_loop_with_concurrency_limit(&cx, Duration::from_secs(2))
            .await
            .unwrap();

        // Compare results
        assert!(
            long_results.back_pressure_events > short_results.back_pressure_events,
            "Longer connections should cause more back-pressure"
        );
        assert!(
            long_results.saturation_events > short_results.saturation_events,
            "Longer connections should cause more saturation"
        );
        assert!(
            short_results.total_completed > long_results.total_completed,
            "Shorter connections should complete more frequently"
        );

        cx.trace("Connection duration correctly impacts back-pressure patterns")
            .await;
    }

    #[tokio::test]
    async fn test_concurrency_limit_coordination_edge_cases() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            concurrency_limit: 1, // Very restrictive limit
            listener_port: find_available_port(),
            connection_duration: Duration::from_millis(100),
            concurrent_clients: 8,
            back_pressure_threshold: 0.9,
            enable_monitoring: true,
        };

        let framework = TcpConcurrencyTestFramework::new(&cx, config).await.unwrap();
        let test_duration = Duration::from_secs(3);

        let results = framework
            .execute_accept_loop_with_concurrency_limit(&cx, test_duration)
            .await
            .unwrap();

        // Verify edge case handling with restrictive limit
        assert!(
            results.back_pressure_events >= 15,
            "Very restrictive limit should cause frequent back-pressure"
        );
        assert!(
            results.total_accepted <= 30,
            "Should accept very few connections with limit of 1"
        );
        assert!(
            results.accept_loop_blocks >= 10,
            "Accept loop should block frequently"
        );

        // Verify system doesn't deadlock or crash
        assert!(
            results.total_completed > 0,
            "Should still complete some connections despite restrictions"
        );

        // Verify back-pressure is effective
        let effective_concurrency = results.total_accepted - results.total_completed;
        assert!(
            effective_concurrency <= 2,
            "Effective concurrency should be near the limit"
        );

        cx.trace("Edge case with restrictive concurrency limit handled correctly")
            .await;
    }
}
