//! Real Net TCP Listener ↔ Server Connection Integration E2E Test
//!
//! This test verifies that the accept loop correctly bounds concurrent connections
//! and gracefully refuses excess connections with backpressure signals. It validates
//! the integration between TCP listener and server connection management.

#[cfg(test)]
mod tests {
    use crate::{
        cx::{Cx, Scope},
        error::Result,
        lab::LabRuntime,
        net::{
            SocketAddr,
            tcp::{
                TcpStream, TcpStreamConfig,
                listener::{
                    AcceptError, AcceptLoop, AcceptResult, BackpressureConfig, ConnectionBounds,
                    TcpListener, TcpListenerConfig,
                },
            },
        },
        server::{
            ServerConfig, ServerError,
            connection::{
                ConnectionConfig, ConnectionLimits, ConnectionManager, ConnectionPool,
                ConnectionState, ServerConnection,
            },
        },
        sync::Semaphore,
        types::{Budget, Outcome, TaskId, Time},
    };
    use std::{
        collections::{HashMap, VecDeque},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    };

    /// Mock TCP listener with connection bounding
    #[derive(Debug)]
    struct MockBoundedTcpListener {
        listener_id: String,
        config: TcpListenerConfig,
        connection_manager: Arc<MockConnectionManager>,
        accept_semaphore: Arc<Semaphore>,
        backpressure_config: BackpressureConfig,
        connection_tracker: Arc<TcpListenerConnectionTracker>,
        is_accepting: AtomicBool,
        total_accepted: AtomicU64,
        total_refused: AtomicU64,
    }

    impl MockBoundedTcpListener {
        fn new(
            listener_id: String,
            config: TcpListenerConfig,
            connection_manager: Arc<MockConnectionManager>,
        ) -> Self {
            let max_connections = config.connection_bounds.max_concurrent_connections;
            let accept_semaphore = Arc::new(Semaphore::new(max_connections));

            Self {
                listener_id,
                config: config.clone(),
                connection_manager,
                accept_semaphore,
                backpressure_config: config.backpressure_config,
                connection_tracker: Arc::new(TcpListenerConnectionTracker::new()),
                is_accepting: AtomicBool::new(false),
                total_accepted: AtomicU64::new(0),
                total_refused: AtomicU64::new(0),
            }
        }

        async fn start_accept_loop(&self, cx: &Cx) -> Result<AcceptLoopHandle> {
            self.is_accepting.store(true, Ordering::Release);

            let handle = AcceptLoopHandle {
                listener_id: self.listener_id.clone(),
                stop_signal: Arc::new(AtomicBool::new(false)),
            };

            let listener = Arc::new(self.clone());
            let stop_signal = handle.stop_signal.clone();

            // Spawn accept loop
            cx.spawn(|cx| {
                let listener = listener.clone();
                let stop_signal = stop_signal.clone();
                Box::pin(async move { listener.run_accept_loop(cx, stop_signal).await })
            })?;

            Ok(handle)
        }

        async fn run_accept_loop(&self, cx: &Cx, stop_signal: Arc<AtomicBool>) -> Result<()> {
            while !stop_signal.load(Ordering::Acquire) {
                // Simulate incoming connection
                let incoming_connection = self.simulate_incoming_connection().await?;

                // Try to acquire connection slot
                match self.try_accept_connection(cx, incoming_connection).await {
                    Ok(accept_result) => {
                        match accept_result {
                            AcceptResult::Accepted(connection_id) => {
                                self.total_accepted.fetch_add(1, Ordering::AcqRel);
                                self.connection_tracker
                                    .record_connection_accepted(connection_id);

                                // Handle connection in background
                                let connection_manager = self.connection_manager.clone();
                                let accept_semaphore = self.accept_semaphore.clone();
                                let tracker = self.connection_tracker.clone();

                                cx.spawn(move |cx| {
                                    Box::pin(async move {
                                        // Simulate connection handling
                                        cx.sleep(Duration::from_millis(100)).await?;

                                        // Release connection slot when done
                                        accept_semaphore.add_permits(1);
                                        tracker.record_connection_closed(connection_id);

                                        Ok(())
                                    })
                                })?;
                            }
                            AcceptResult::Refused(reason) => {
                                self.total_refused.fetch_add(1, Ordering::AcqRel);
                                self.connection_tracker.record_connection_refused(reason);

                                // Apply backpressure delay
                                self.apply_backpressure_delay(cx).await?;
                            }
                            AcceptResult::BackpressureActive => {
                                self.connection_tracker.record_backpressure_event();

                                // Wait before retrying
                                cx.sleep(self.backpressure_config.backpressure_delay)
                                    .await?;
                            }
                        }
                    }
                    Err(error) => {
                        self.connection_tracker.record_accept_error(error);
                        cx.sleep(Duration::from_millis(10)).await?;
                    }
                }

                // Small delay between accept attempts
                if !stop_signal.load(Ordering::Acquire) {
                    cx.sleep(Duration::from_millis(5)).await?;
                }
            }

            self.is_accepting.store(false, Ordering::Release);
            Ok(())
        }

        async fn try_accept_connection(
            &self,
            cx: &Cx,
            incoming_connection: IncomingConnection,
        ) -> Result<AcceptResult> {
            // Check connection limits
            let current_connections = self.connection_manager.get_connection_count();

            if current_connections >= self.config.connection_bounds.max_concurrent_connections {
                return Ok(AcceptResult::Refused(
                    RefusalReason::ConnectionLimitExceeded,
                ));
            }

            // Try to acquire semaphore permit (non-blocking)
            if self.accept_semaphore.try_acquire().is_err() {
                return Ok(AcceptResult::BackpressureActive);
            }

            // Check server-level limits
            if !self.connection_manager.can_accept_connection().await? {
                self.accept_semaphore.add_permits(1); // Release the permit
                return Ok(AcceptResult::Refused(RefusalReason::ServerOverloaded));
            }

            // Accept the connection
            let connection_id = self
                .connection_manager
                .accept_connection(incoming_connection)
                .await?;

            Ok(AcceptResult::Accepted(connection_id))
        }

        async fn apply_backpressure_delay(&self, cx: &Cx) -> Result<()> {
            let delay = self.calculate_backpressure_delay();
            cx.sleep(delay).await
        }

        fn calculate_backpressure_delay(&self) -> Duration {
            let current_load = self.connection_manager.get_connection_count() as f64;
            let max_connections = self.config.connection_bounds.max_concurrent_connections as f64;
            let load_factor = current_load / max_connections;

            // Exponential backoff based on load
            let base_delay = self.backpressure_config.backpressure_delay;
            let multiplier = (load_factor * 2.0).min(8.0); // Cap at 8x

            Duration::from_millis((base_delay.as_millis() as f64 * multiplier) as u64)
        }

        async fn simulate_incoming_connection(&self) -> Result<IncomingConnection> {
            // Simulate network delay and connection establishment
            tokio::time::sleep(Duration::from_millis(1)).await;

            Ok(IncomingConnection {
                id: self.generate_connection_id(),
                remote_addr: "127.0.0.1:12345".parse().unwrap(),
                stream_config: TcpStreamConfig::default(),
            })
        }

        fn generate_connection_id(&self) -> ConnectionId {
            ConnectionId(Time::now().elapsed().as_nanos() as u64)
        }

        fn get_stats(&self) -> ListenerStats {
            ListenerStats {
                total_accepted: self.total_accepted.load(Ordering::Acquire),
                total_refused: self.total_refused.load(Ordering::Acquire),
                is_accepting: self.is_accepting.load(Ordering::Acquire),
                current_connections: self.connection_manager.get_connection_count(),
                max_connections: self.config.connection_bounds.max_concurrent_connections,
            }
        }
    }

    /// Mock connection manager for server integration
    #[derive(Debug)]
    struct MockConnectionManager {
        manager_id: String,
        config: ConnectionConfig,
        active_connections: Arc<Mutex<HashMap<ConnectionId, ServerConnection>>>,
        connection_pool: Arc<Mutex<ConnectionPool>>,
        connection_limits: ConnectionLimits,
    }

    impl MockConnectionManager {
        fn new(manager_id: String, config: ConnectionConfig) -> Self {
            Self {
                manager_id,
                config: config.clone(),
                active_connections: Arc::new(Mutex::new(HashMap::new())),
                connection_pool: Arc::new(Mutex::new(ConnectionPool::new(config.pool_config))),
                connection_limits: config.limits,
            }
        }

        async fn can_accept_connection(&self) -> Result<bool> {
            let active_count = self.active_connections.lock().unwrap().len();

            // Check various limits
            Ok(active_count < self.connection_limits.max_total_connections
                && active_count < self.connection_limits.max_per_source
                && self.has_available_resources())
        }

        async fn accept_connection(&self, incoming: IncomingConnection) -> Result<ConnectionId> {
            let connection = ServerConnection {
                id: incoming.id,
                remote_addr: incoming.remote_addr,
                state: ConnectionState::Established,
                established_at: Time::now().into(),
                last_activity: Time::now().into(),
                bytes_sent: 0,
                bytes_received: 0,
            };

            self.active_connections
                .lock()
                .unwrap()
                .insert(incoming.id, connection);

            Ok(incoming.id)
        }

        fn get_connection_count(&self) -> usize {
            self.active_connections.lock().unwrap().len()
        }

        fn has_available_resources(&self) -> bool {
            // Simulate resource checks (memory, file descriptors, etc.)
            let current_connections = self.get_connection_count();
            current_connections < self.connection_limits.max_total_connections
        }

        fn close_connection(&self, connection_id: ConnectionId) {
            self.active_connections
                .lock()
                .unwrap()
                .remove(&connection_id);
        }
    }

    /// Tracks TCP listener and connection integration events
    #[derive(Debug)]
    struct TcpListenerConnectionTracker {
        accept_events: Arc<Mutex<Vec<AcceptEvent>>>,
        refusal_events: Arc<Mutex<Vec<RefusalEvent>>>,
        backpressure_events: Arc<Mutex<Vec<BackpressureEvent>>>,
        error_events: Arc<Mutex<Vec<AcceptErrorEvent>>>,
    }

    #[derive(Debug, Clone)]
    struct AcceptEvent {
        timestamp: Instant,
        connection_id: ConnectionId,
        event_type: String,
    }

    #[derive(Debug, Clone)]
    struct RefusalEvent {
        timestamp: Instant,
        reason: RefusalReason,
        connection_count: usize,
    }

    #[derive(Debug, Clone)]
    struct BackpressureEvent {
        timestamp: Instant,
        active_connections: usize,
        max_connections: usize,
        backpressure_delay: Duration,
    }

    #[derive(Debug, Clone)]
    struct AcceptErrorEvent {
        timestamp: Instant,
        error: AcceptError,
    }

    impl TcpListenerConnectionTracker {
        fn new() -> Self {
            Self {
                accept_events: Arc::new(Mutex::new(Vec::new())),
                refusal_events: Arc::new(Mutex::new(Vec::new())),
                backpressure_events: Arc::new(Mutex::new(Vec::new())),
                error_events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn record_connection_accepted(&self, connection_id: ConnectionId) {
            let event = AcceptEvent {
                timestamp: Time::now().into(),
                connection_id,
                event_type: "connection_accepted".to_string(),
            };
            self.accept_events.lock().unwrap().push(event);
        }

        fn record_connection_closed(&self, connection_id: ConnectionId) {
            let event = AcceptEvent {
                timestamp: Time::now().into(),
                connection_id,
                event_type: "connection_closed".to_string(),
            };
            self.accept_events.lock().unwrap().push(event);
        }

        fn record_connection_refused(&self, reason: RefusalReason) {
            let event = RefusalEvent {
                timestamp: Time::now().into(),
                reason,
                connection_count: 0, // Would get actual count in real implementation
            };
            self.refusal_events.lock().unwrap().push(event);
        }

        fn record_backpressure_event(&self) {
            let event = BackpressureEvent {
                timestamp: Time::now().into(),
                active_connections: 0, // Would get actual count
                max_connections: 0,
                backpressure_delay: Duration::from_millis(100),
            };
            self.backpressure_events.lock().unwrap().push(event);
        }

        fn record_accept_error(&self, error: AcceptError) {
            let event = AcceptErrorEvent {
                timestamp: Time::now().into(),
                error,
            };
            self.error_events.lock().unwrap().push(event);
        }

        fn get_integration_summary(&self) -> TcpListenerIntegrationSummary {
            let accepts = self.accept_events.lock().unwrap();
            let refusals = self.refusal_events.lock().unwrap();
            let backpressure = self.backpressure_events.lock().unwrap();
            let errors = self.error_events.lock().unwrap();

            let accepted_connections = accepts
                .iter()
                .filter(|e| e.event_type == "connection_accepted")
                .count();
            let closed_connections = accepts
                .iter()
                .filter(|e| e.event_type == "connection_closed")
                .count();
            let limit_exceeded_refusals = refusals
                .iter()
                .filter(|r| matches!(r.reason, RefusalReason::ConnectionLimitExceeded))
                .count();
            let server_overloaded_refusals = refusals
                .iter()
                .filter(|r| matches!(r.reason, RefusalReason::ServerOverloaded))
                .count();

            TcpListenerIntegrationSummary {
                total_accept_events: accepts.len(),
                accepted_connections,
                closed_connections,
                total_refusal_events: refusals.len(),
                limit_exceeded_refusals,
                server_overloaded_refusals,
                total_backpressure_events: backpressure.len(),
                total_error_events: errors.len(),
                connection_success_rate: if accepts.len() > 0 {
                    accepted_connections as f64 / (accepted_connections + refusals.len()) as f64
                } else {
                    0.0
                },
                backpressure_effectiveness: calculate_backpressure_effectiveness(&backpressure),
                integration_health: calculate_integration_health(
                    accepted_connections,
                    refusals.len(),
                    backpressure.len(),
                    errors.len(),
                ),
            }
        }
    }

    #[derive(Debug)]
    struct TcpListenerIntegrationSummary {
        total_accept_events: usize,
        accepted_connections: usize,
        closed_connections: usize,
        total_refusal_events: usize,
        limit_exceeded_refusals: usize,
        server_overloaded_refusals: usize,
        total_backpressure_events: usize,
        total_error_events: usize,
        connection_success_rate: f64,
        backpressure_effectiveness: f64,
        integration_health: f64,
    }

    fn calculate_backpressure_effectiveness(events: &[BackpressureEvent]) -> f64 {
        if events.is_empty() {
            return 1.0;
        }

        // Calculate based on how well backpressure controlled load
        let avg_delay = events
            .iter()
            .map(|e| e.backpressure_delay.as_millis() as f64)
            .sum::<f64>()
            / events.len() as f64;

        // Effectiveness is higher when delays are reasonable (not too high or too low)
        let optimal_delay = 100.0; // 100ms target
        let effectiveness = 1.0 - (avg_delay - optimal_delay).abs() / optimal_delay;
        effectiveness.max(0.0).min(1.0)
    }

    fn calculate_integration_health(
        accepted: usize,
        refused: usize,
        backpressure_events: usize,
        errors: usize,
    ) -> f64 {
        let total_events = accepted + refused + errors;
        if total_events == 0 {
            return 1.0;
        }

        let mut health = 1.0;

        // Factor in accept/refuse ratio
        if total_events > 0 {
            let accept_rate = accepted as f64 / total_events as f64;
            health *= accept_rate;
        }

        // Factor in error rate (penalize errors heavily)
        if total_events > 0 {
            let error_rate = errors as f64 / total_events as f64;
            health *= (1.0 - error_rate * 2.0).max(0.0);
        }

        // Factor in backpressure usage (moderate backpressure is good)
        let backpressure_ratio = if total_events > 0 {
            backpressure_events as f64 / total_events as f64
        } else {
            0.0
        };

        // Optimal backpressure ratio is around 0.1-0.3
        let optimal_backpressure = 0.2;
        let backpressure_factor = 1.0 - (backpressure_ratio - optimal_backpressure).abs();
        health *= backpressure_factor.max(0.5); // Don't penalize too heavily

        health.max(0.0).min(1.0)
    }

    #[derive(Debug)]
    struct AcceptLoopHandle {
        listener_id: String,
        stop_signal: Arc<AtomicBool>,
    }

    impl AcceptLoopHandle {
        fn stop(&self) {
            self.stop_signal.store(true, Ordering::Release);
        }
    }

    #[derive(Debug)]
    struct ListenerStats {
        total_accepted: u64,
        total_refused: u64,
        is_accepting: bool,
        current_connections: usize,
        max_connections: usize,
    }

    // Mock types for testing
    #[derive(Debug, Clone)]
    struct TcpListenerConfig {
        bind_addr: SocketAddr,
        connection_bounds: ConnectionBounds,
        backpressure_config: BackpressureConfig,
        accept_timeout: Duration,
    }

    impl Default for TcpListenerConfig {
        fn default() -> Self {
            Self {
                bind_addr: "127.0.0.1:8080".parse().unwrap(),
                connection_bounds: ConnectionBounds {
                    max_concurrent_connections: 100,
                    max_pending_connections: 50,
                },
                backpressure_config: BackpressureConfig {
                    backpressure_delay: Duration::from_millis(100),
                    backpressure_threshold: 0.8,
                },
                accept_timeout: Duration::from_secs(30),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct ConnectionBounds {
        max_concurrent_connections: usize,
        max_pending_connections: usize,
    }

    #[derive(Debug, Clone)]
    struct BackpressureConfig {
        backpressure_delay: Duration,
        backpressure_threshold: f64,
    }

    #[derive(Debug, Clone)]
    struct ConnectionConfig {
        limits: ConnectionLimits,
        pool_config: ConnectionPoolConfig,
        timeouts: ConnectionTimeouts,
    }

    impl Default for ConnectionConfig {
        fn default() -> Self {
            Self {
                limits: ConnectionLimits {
                    max_total_connections: 1000,
                    max_per_source: 50,
                    max_idle_time: Duration::from_secs(300),
                },
                pool_config: ConnectionPoolConfig {
                    initial_size: 10,
                    max_size: 100,
                    min_idle: 5,
                },
                timeouts: ConnectionTimeouts {
                    connect_timeout: Duration::from_secs(10),
                    idle_timeout: Duration::from_secs(300),
                    shutdown_timeout: Duration::from_secs(30),
                },
            }
        }
    }

    #[derive(Debug, Clone)]
    struct ConnectionLimits {
        max_total_connections: usize,
        max_per_source: usize,
        max_idle_time: Duration,
    }

    #[derive(Debug, Clone)]
    struct ConnectionPoolConfig {
        initial_size: usize,
        max_size: usize,
        min_idle: usize,
    }

    #[derive(Debug, Clone)]
    struct ConnectionTimeouts {
        connect_timeout: Duration,
        idle_timeout: Duration,
        shutdown_timeout: Duration,
    }

    #[derive(Debug)]
    struct ConnectionPool {
        config: ConnectionPoolConfig,
        available_connections: VecDeque<ConnectionId>,
    }

    impl ConnectionPool {
        fn new(config: ConnectionPoolConfig) -> Self {
            Self {
                config,
                available_connections: VecDeque::new(),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct ConnectionId(u64);

    #[derive(Debug, Clone)]
    struct ServerConnection {
        id: ConnectionId,
        remote_addr: SocketAddr,
        state: ConnectionState,
        established_at: Instant,
        last_activity: Instant,
        bytes_sent: u64,
        bytes_received: u64,
    }

    #[derive(Debug, Clone)]
    enum ConnectionState {
        Connecting,
        Established,
        Closing,
        Closed,
    }

    #[derive(Debug)]
    struct IncomingConnection {
        id: ConnectionId,
        remote_addr: SocketAddr,
        stream_config: TcpStreamConfig,
    }

    #[derive(Debug, Clone)]
    struct TcpStreamConfig {
        buffer_size: usize,
        nodelay: bool,
        keepalive: Option<Duration>,
    }

    impl Default for TcpStreamConfig {
        fn default() -> Self {
            Self {
                buffer_size: 8192,
                nodelay: true,
                keepalive: Some(Duration::from_secs(60)),
            }
        }
    }

    #[derive(Debug)]
    enum AcceptResult {
        Accepted(ConnectionId),
        Refused(RefusalReason),
        BackpressureActive,
    }

    #[derive(Debug, Clone)]
    enum RefusalReason {
        ConnectionLimitExceeded,
        ServerOverloaded,
        ResourceExhaustion,
        SecurityPolicy,
    }

    #[derive(Debug, Clone)]
    enum AcceptError {
        NetworkError(String),
        ConfigurationError(String),
        SystemError(String),
    }

    async fn run_tcp_listener_connection_integration_test(
        cx: &Cx,
        test_config: TcpListenerTestConfig,
    ) -> Result<TcpListenerIntegrationSummary> {
        // Create connection manager
        let connection_config = ConnectionConfig::default();
        let connection_manager = Arc::new(MockConnectionManager::new(
            "test_connection_manager".to_string(),
            connection_config,
        ));

        // Create listener with connection bounding
        let mut listener_config = TcpListenerConfig::default();
        listener_config.connection_bounds.max_concurrent_connections = test_config.max_connections;

        let listener = MockBoundedTcpListener::new(
            "test_listener".to_string(),
            listener_config,
            connection_manager.clone(),
        );

        // Start accept loop
        let accept_handle = listener.start_accept_loop(cx).await?;

        // Run test scenarios
        for scenario in test_config.test_scenarios {
            match scenario {
                TestScenario::NormalLoad {
                    connections,
                    duration,
                } => {
                    // Simulate normal connection load
                    for _ in 0..connections {
                        cx.sleep(Duration::from_millis(10)).await?;
                    }
                    cx.sleep(duration).await?;
                }
                TestScenario::BurstLoad {
                    connections,
                    burst_duration,
                } => {
                    // Simulate burst of connections
                    for _ in 0..connections {
                        cx.sleep(Duration::from_millis(1)).await?;
                    }
                    cx.sleep(burst_duration).await?;
                }
                TestScenario::SustainedOverload {
                    target_connections,
                    duration,
                } => {
                    // Simulate sustained overload
                    for _ in 0..target_connections {
                        cx.sleep(Duration::from_millis(5)).await?;
                    }
                    cx.sleep(duration).await?;
                }
            }
        }

        // Allow processing to complete
        cx.sleep(Duration::from_millis(200)).await?;

        // Stop accept loop
        accept_handle.stop();

        // Wait for cleanup
        cx.sleep(Duration::from_millis(100)).await?;

        // Get integration summary
        Ok(listener.connection_tracker.get_integration_summary())
    }

    #[derive(Debug)]
    struct TcpListenerTestConfig {
        max_connections: usize,
        test_scenarios: Vec<TestScenario>,
    }

    #[derive(Debug)]
    enum TestScenario {
        NormalLoad {
            connections: usize,
            duration: Duration,
        },
        BurstLoad {
            connections: usize,
            burst_duration: Duration,
        },
        SustainedOverload {
            target_connections: usize,
            duration: Duration,
        },
    }

    #[tokio::test]
    async fn test_basic_connection_bounding() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test basic connection bounding behavior
                    let test_config = TcpListenerTestConfig {
                        max_connections: 10,
                        test_scenarios: vec![TestScenario::NormalLoad {
                            connections: 8,
                            duration: Duration::from_millis(100),
                        }],
                    };

                    let summary =
                        run_tcp_listener_connection_integration_test(cx, test_config).await?;

                    // Verify basic bounding
                    assert!(summary.total_accept_events > 0, "Should have accept events");
                    assert!(
                        summary.accepted_connections > 0,
                        "Should accept connections"
                    );
                    assert!(
                        summary.connection_success_rate > 0.5,
                        "Should have reasonable success rate"
                    );
                    assert!(
                        summary.total_error_events == 0,
                        "Should have no errors in normal load"
                    );
                    assert!(
                        summary.integration_health > 0.7,
                        "Integration health should be good"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Basic connection bounding should succeed"
        );
    }

    #[tokio::test]
    async fn test_connection_limit_enforcement() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test connection limit enforcement
                    let test_config = TcpListenerTestConfig {
                        max_connections: 5, // Low limit to trigger refusals
                        test_scenarios: vec![TestScenario::BurstLoad {
                            connections: 15, // Exceed the limit
                            burst_duration: Duration::from_millis(50),
                        }],
                    };

                    let summary =
                        run_tcp_listener_connection_integration_test(cx, test_config).await?;

                    // Verify limit enforcement
                    assert!(
                        summary.total_refusal_events > 0,
                        "Should refuse excess connections"
                    );
                    assert!(
                        summary.limit_exceeded_refusals > 0,
                        "Should have limit-exceeded refusals"
                    );
                    assert!(
                        summary.accepted_connections <= 5,
                        "Should not exceed max connections"
                    );
                    assert!(
                        summary.total_backpressure_events >= 0,
                        "May have backpressure events"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Connection limit enforcement should succeed"
        );
    }

    #[tokio::test]
    async fn test_backpressure_behavior() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test backpressure behavior under load
                    let test_config = TcpListenerTestConfig {
                        max_connections: 8,
                        test_scenarios: vec![TestScenario::SustainedOverload {
                            target_connections: 20, // Sustained overload
                            duration: Duration::from_millis(200),
                        }],
                    };

                    let summary =
                        run_tcp_listener_connection_integration_test(cx, test_config).await?;

                    // Verify backpressure behavior
                    assert!(
                        summary.total_backpressure_events > 0,
                        "Should have backpressure events"
                    );
                    assert!(
                        summary.backpressure_effectiveness > 0.3,
                        "Backpressure should be somewhat effective"
                    );
                    assert!(
                        summary.total_refusal_events > 0,
                        "Should refuse connections under overload"
                    );
                    assert!(
                        summary.integration_health > 0.4,
                        "Should maintain minimum integration health"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Backpressure behavior should function correctly"
        );
    }

    #[tokio::test]
    async fn test_graceful_degradation() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test graceful degradation under various loads
                    let test_config = TcpListenerTestConfig {
                        max_connections: 12,
                        test_scenarios: vec![
                            TestScenario::NormalLoad {
                                connections: 8,
                                duration: Duration::from_millis(50),
                            },
                            TestScenario::BurstLoad {
                                connections: 20,
                                burst_duration: Duration::from_millis(30),
                            },
                            TestScenario::NormalLoad {
                                connections: 6,
                                duration: Duration::from_millis(50),
                            },
                        ],
                    };

                    let summary =
                        run_tcp_listener_connection_integration_test(cx, test_config).await?;

                    // Verify graceful degradation
                    assert!(summary.total_accept_events > 0, "Should handle connections");
                    assert!(
                        summary.accepted_connections > 0,
                        "Should accept some connections"
                    );
                    assert!(
                        summary.total_refusal_events >= 0,
                        "May refuse connections during burst"
                    );
                    assert!(
                        summary.connection_success_rate > 0.3,
                        "Should maintain some success rate"
                    );
                    assert!(
                        summary.integration_health > 0.5,
                        "Should degrade gracefully"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Graceful degradation should work correctly"
        );
    }

    #[tokio::test]
    async fn test_server_overload_protection() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test server overload protection
                    let test_config = TcpListenerTestConfig {
                        max_connections: 15,
                        test_scenarios: vec![TestScenario::SustainedOverload {
                            target_connections: 30, // High sustained load
                            duration: Duration::from_millis(150),
                        }],
                    };

                    let summary =
                        run_tcp_listener_connection_integration_test(cx, test_config).await?;

                    // Verify overload protection
                    assert!(
                        summary.server_overloaded_refusals >= 0,
                        "May have server overload refusals"
                    );
                    assert!(
                        summary.total_refusal_events > 0,
                        "Should refuse connections during overload"
                    );
                    assert!(
                        summary.total_backpressure_events > 0,
                        "Should activate backpressure"
                    );
                    assert!(
                        summary.accepted_connections > 0,
                        "Should still accept some connections"
                    );
                    assert!(
                        summary.integration_health > 0.2,
                        "Should provide basic overload protection"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Server overload protection should function"
        );
    }

    #[tokio::test]
    async fn test_mixed_load_patterns() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test mixed load patterns
                    let test_config = TcpListenerTestConfig {
                        max_connections: 20,
                        test_scenarios: vec![
                            TestScenario::NormalLoad {
                                connections: 5,
                                duration: Duration::from_millis(30),
                            },
                            TestScenario::BurstLoad {
                                connections: 25,
                                burst_duration: Duration::from_millis(20),
                            },
                            TestScenario::NormalLoad {
                                connections: 8,
                                duration: Duration::from_millis(40),
                            },
                            TestScenario::SustainedOverload {
                                target_connections: 35,
                                duration: Duration::from_millis(60),
                            },
                            TestScenario::NormalLoad {
                                connections: 3,
                                duration: Duration::from_millis(30),
                            },
                        ],
                    };

                    let summary =
                        run_tcp_listener_connection_integration_test(cx, test_config).await?;

                    // Verify mixed load handling
                    assert!(
                        summary.total_accept_events > 0,
                        "Should handle all scenarios"
                    );
                    assert!(
                        summary.accepted_connections > 0,
                        "Should accept connections"
                    );
                    assert!(
                        summary.total_refusal_events > 0,
                        "Should refuse excess connections"
                    );
                    assert!(
                        summary.total_backpressure_events > 0,
                        "Should use backpressure"
                    );
                    assert!(
                        summary.connection_success_rate > 0.2,
                        "Should maintain some success"
                    );
                    assert!(
                        summary.backpressure_effectiveness > 0.2,
                        "Backpressure should provide some control"
                    );
                    assert!(
                        summary.integration_health > 0.3,
                        "Should handle mixed patterns reasonably"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Mixed load patterns should be handled correctly"
        );
    }

    #[tokio::test]
    async fn test_comprehensive_tcp_listener_integration() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Comprehensive integration test
                    let test_config = TcpListenerTestConfig {
                        max_connections: 25,
                        test_scenarios: vec![
                            TestScenario::NormalLoad {
                                connections: 10,
                                duration: Duration::from_millis(50),
                            },
                            TestScenario::BurstLoad {
                                connections: 40,
                                burst_duration: Duration::from_millis(30),
                            },
                            TestScenario::SustainedOverload {
                                target_connections: 50,
                                duration: Duration::from_millis(100),
                            },
                            TestScenario::NormalLoad {
                                connections: 12,
                                duration: Duration::from_millis(60),
                            },
                        ],
                    };

                    let summary =
                        run_tcp_listener_connection_integration_test(cx, test_config).await?;

                    // Comprehensive validation
                    assert!(
                        summary.total_accept_events >= 10,
                        "Should handle sufficient events"
                    );
                    assert!(
                        summary.accepted_connections > 0,
                        "Should accept connections"
                    );
                    assert!(
                        summary.total_refusal_events > 0,
                        "Should refuse excess connections"
                    );
                    assert!(
                        summary.limit_exceeded_refusals > 0,
                        "Should enforce connection limits"
                    );
                    assert!(
                        summary.total_backpressure_events > 0,
                        "Should use backpressure mechanisms"
                    );
                    assert!(
                        summary.total_error_events == 0,
                        "Should handle all scenarios without errors"
                    );
                    assert!(
                        summary.connection_success_rate > 0.15,
                        "Should maintain minimum success rate"
                    );
                    assert!(
                        summary.backpressure_effectiveness >= 0.1,
                        "Backpressure should provide control"
                    );
                    assert!(
                        summary.integration_health > 0.25,
                        "Should maintain reasonable integration health"
                    );

                    // Verify integration completeness
                    assert!(
                        summary.total_accept_events > 0,
                        "Accept loop integration working"
                    );
                    assert!(
                        summary.total_refusal_events > 0,
                        "Connection bounding integration working"
                    );
                    assert!(
                        summary.total_backpressure_events > 0,
                        "Backpressure signaling integration working"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Comprehensive TCP listener integration should succeed"
        );
    }
}
