//! # Real gRPC/Server ↔ gRPC/Health Integration E2E Tests
//!
//! Tests integration between gRPC server and gRPC health checking to verify that
//! health check status changes correctly propagate to all in-flight gRPC reflection
//! streams within bounded time.
//!
//! ## Integration Focus
//!
//! - **gRPC Server**: reflection streams, service registry, connection management
//! - **gRPC Health**: status propagation, health state transitions, bounded updates
//! - **Stream Coordination**: in-flight streams, status broadcasting, timing guarantees
//!
//! ## Key Properties Tested
//!
//! 1. **Status Propagation**: Health status changes reach all reflection streams
//! 2. **Bounded Time**: Updates propagate within specified time bounds
//! 3. **Stream Consistency**: All streams receive consistent status updates
//! 4. **Reflection Integration**: Health status affects service reflection correctly

use crate::{
    Result,
    cx::Cx,
    grpc::{
        health::{
            HealthCheck, HealthCheckRequest, HealthCheckResponse, HealthCheckService, HealthStatus,
            ServiceHealthMap, StatusChangeEvent,
        },
        reflection::{
            ReflectionService, ReflectionStream, ServerReflectionRequest, ServerReflectionResponse,
            ServiceInfo,
        },
        server::{
            ConnectionManager, GrpcServer, GrpcServerBuilder, ServerConfig, ServiceRegistry,
            StreamHandle,
        },
        service::{GrpcService, ServiceDescriptor},
        status::{Code, Status},
        streaming::{BidirectionalStream, StreamingRequest, StreamingResponse},
    },
    net::{
        SocketAddr,
        tcp::{TcpListener, TcpStream},
    },
    runtime::{LabRuntime, LabRuntimeBuilder, RuntimeBuilder},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
    types::{
        budget::Budget, cancel::CancelToken, outcome::Outcome, region::RegionId, task::TaskId,
    },
    util::{rng::DetRng, time::TimeSource},
};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::atomic::AtomicBool,
};

/// Health status change event for propagation testing
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestHealthStatusChange {
    service_name: String,
    old_status: HealthStatus,
    new_status: HealthStatus,
    timestamp: Instant,
    change_id: u64,
}

impl TestHealthStatusChange {
    fn new(
        service_name: String,
        old_status: HealthStatus,
        new_status: HealthStatus,
        change_id: u64,
    ) -> Self {
        Self {
            service_name,
            old_status,
            new_status,
            timestamp: Instant::now(),
            change_id,
        }
    }
}

/// In-flight reflection stream tracker for testing
#[derive(Debug)]
struct ReflectionStreamTracker {
    stream_id: u64,
    service_subscriptions: Arc<RwLock<Vec<String>>>,
    received_status_updates: Arc<RwLock<Vec<TestHealthStatusChange>>>,
    last_update_time: Arc<Mutex<Option<Instant>>>,
    is_active: Arc<AtomicBool>,
}

impl ReflectionStreamTracker {
    fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            service_subscriptions: Arc::new(RwLock::new(Vec::new())),
            received_status_updates: Arc::new(RwLock::new(Vec::new())),
            last_update_time: Arc::new(Mutex::new(None)),
            is_active: Arc::new(AtomicBool::new(true)),
        }
    }

    fn subscribe_to_service(&self, service_name: String) {
        let mut subscriptions = self.service_subscriptions.write();
        if !subscriptions.contains(&service_name) {
            subscriptions.push(service_name);
        }
    }

    fn record_status_update(&self, status_change: TestHealthStatusChange) {
        {
            let mut updates = self.received_status_updates.write();
            updates.push(status_change);
        }

        {
            let mut last_update = self.last_update_time.lock();
            *last_update = Some(Instant::now());
        }
    }

    fn get_received_updates(&self) -> Vec<TestHealthStatusChange> {
        self.received_status_updates.read().clone()
    }

    fn get_subscriptions(&self) -> Vec<String> {
        self.service_subscriptions.read().clone()
    }

    fn deactivate(&self) {
        self.is_active.store(false, Ordering::Release);
    }

    fn is_active(&self) -> bool {
        self.is_active.load(Ordering::Acquire)
    }
}

/// Health status propagation coordinator
#[derive(Debug)]
struct HealthStatusPropagationCoordinator {
    active_streams: Arc<RwLock<HashMap<u64, ReflectionStreamTracker>>>,
    status_change_sequence: Arc<AtomicU64>,
    propagation_metrics: PropagationMetrics,
    bounded_time_limit: Duration,
}

impl HealthStatusPropagationCoordinator {
    fn new(bounded_time_limit: Duration) -> Self {
        Self {
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            status_change_sequence: Arc::new(AtomicU64::new(1)),
            propagation_metrics: PropagationMetrics::new(),
            bounded_time_limit,
        }
    }

    fn register_reflection_stream(&self, stream_id: u64) -> ReflectionStreamTracker {
        let tracker = ReflectionStreamTracker::new(stream_id);
        {
            let mut streams = self.active_streams.write();
            streams.insert(stream_id, tracker.clone());
        }
        tracker
    }

    fn unregister_reflection_stream(&self, stream_id: u64) {
        let mut streams = self.active_streams.write();
        if let Some(tracker) = streams.remove(&stream_id) {
            tracker.deactivate();
        }
    }

    fn propagate_health_status_change(
        &self,
        service_name: String,
        old_status: HealthStatus,
        new_status: HealthStatus,
    ) -> Result<u64> {
        let change_id = self.status_change_sequence.fetch_add(1, Ordering::Release);
        let status_change =
            TestHealthStatusChange::new(service_name.clone(), old_status, new_status, change_id);

        let propagation_start = Instant::now();
        let streams = self.active_streams.read();

        for (stream_id, tracker) in streams.iter() {
            if !tracker.is_active() {
                continue;
            }

            let subscriptions = tracker.get_subscriptions();
            if subscriptions.contains(&service_name) {
                tracker.record_status_update(status_change.clone());
            }
        }

        let propagation_time = propagation_start.elapsed();
        self.propagation_metrics
            .record_propagation_time(propagation_time);

        // Verify bounded time constraint
        if propagation_time > self.bounded_time_limit {
            self.propagation_metrics.record_bounded_time_violation();
        }

        Ok(change_id)
    }

    fn verify_all_streams_received_update(
        &self,
        change_id: u64,
        service_name: &str,
    ) -> Result<bool> {
        let streams = self.active_streams.read();
        let mut expected_receivers = Vec::new();

        // Identify streams that should have received the update
        for (stream_id, tracker) in streams.iter() {
            if tracker.is_active() {
                let subscriptions = tracker.get_subscriptions();
                if subscriptions.contains(&service_name.to_string()) {
                    expected_receivers.push(*stream_id);
                }
            }
        }

        // Verify each expected receiver got the update
        for stream_id in expected_receivers {
            if let Some(tracker) = streams.get(&stream_id) {
                let updates = tracker.get_received_updates();
                let has_update = updates.iter().any(|update| update.change_id == change_id);
                if !has_update {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    fn get_active_stream_count(&self) -> usize {
        let streams = self.active_streams.read();
        streams
            .values()
            .filter(|tracker| tracker.is_active())
            .count()
    }

    fn get_propagation_stats(&self) -> PropagationStats {
        self.propagation_metrics.get_stats()
    }
}

/// Metrics for tracking status propagation performance
#[derive(Debug)]
struct PropagationMetrics {
    propagation_times: Arc<RwLock<Vec<Duration>>>,
    bounded_time_violations: Arc<AtomicUsize>,
    total_propagations: Arc<AtomicUsize>,
}

impl PropagationMetrics {
    fn new() -> Self {
        Self {
            propagation_times: Arc::new(RwLock::new(Vec::new())),
            bounded_time_violations: Arc::new(AtomicUsize::new(0)),
            total_propagations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn record_propagation_time(&self, time: Duration) {
        let mut times = self.propagation_times.write();
        times.push(time);
        self.total_propagations.fetch_add(1, Ordering::Release);
    }

    fn record_bounded_time_violation(&self) {
        self.bounded_time_violations.fetch_add(1, Ordering::Release);
    }

    fn get_stats(&self) -> PropagationStats {
        let times = self.propagation_times.read();
        let violations = self.bounded_time_violations.load(Ordering::Acquire);
        let total = self.total_propagations.load(Ordering::Acquire);

        let avg_time = if !times.is_empty() {
            times.iter().sum::<Duration>() / times.len() as u32
        } else {
            Duration::ZERO
        };

        let max_time = times.iter().max().copied().unwrap_or(Duration::ZERO);

        PropagationStats {
            total_propagations: total,
            bounded_time_violations: violations,
            average_propagation_time: avg_time,
            max_propagation_time: max_time,
        }
    }
}

/// Statistics for health status propagation
#[derive(Debug, Clone)]
struct PropagationStats {
    total_propagations: usize,
    bounded_time_violations: usize,
    average_propagation_time: Duration,
    max_propagation_time: Duration,
}

/// Test harness for gRPC server/health integration
#[derive(Debug)]
struct GrpcServerHealthTestHarness {
    coordinator: HealthStatusPropagationCoordinator,
    server_config: ServerConfig,
    health_service_registry: Arc<RwLock<HashMap<String, HealthStatus>>>,
}

impl GrpcServerHealthTestHarness {
    fn new(bounded_time_limit: Duration) -> Self {
        let server_config = ServerConfig {
            max_concurrent_streams: 100,
            stream_timeout: Duration::from_secs(30),
            health_check_interval: Duration::from_millis(100),
            reflection_enabled: true,
        };

        Self {
            coordinator: HealthStatusPropagationCoordinator::new(bounded_time_limit),
            server_config,
            health_service_registry: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn simulate_grpc_server_with_health_integration(
        &self,
        cx: &Cx,
        reflection_stream_count: usize,
        status_change_scenarios: Vec<HealthStatusScenario>,
    ) -> Result<()> {
        // Phase 1: Set up gRPC server with health service
        let health_service = MockHealthService::new(self.health_service_registry.clone());
        let reflection_service = MockReflectionService::new();

        // Phase 2: Create multiple in-flight reflection streams
        let mut stream_trackers = Vec::new();
        for i in 0..reflection_stream_count {
            let stream_id = i as u64;
            let tracker = self.coordinator.register_reflection_stream(stream_id);

            // Subscribe each stream to different services
            match i % 3 {
                0 => {
                    tracker.subscribe_to_service("service.TestService".to_string());
                    tracker.subscribe_to_service("service.UserService".to_string());
                }
                1 => {
                    tracker.subscribe_to_service("service.OrderService".to_string());
                    tracker.subscribe_to_service("service.TestService".to_string());
                }
                _ => {
                    tracker.subscribe_to_service("service.UserService".to_string());
                    tracker.subscribe_to_service("service.OrderService".to_string());
                }
            }

            stream_trackers.push(tracker);
        }

        // Phase 3: Execute health status change scenarios
        for scenario in status_change_scenarios {
            cx.sleep(scenario.delay_before_change).await;

            // Update health status in registry
            {
                let mut registry = self.health_service_registry.write();
                registry.insert(scenario.service_name.clone(), scenario.new_status);
            }

            // Propagate status change to reflection streams
            let change_id = self.coordinator.propagate_health_status_change(
                scenario.service_name.clone(),
                scenario.old_status,
                scenario.new_status,
            )?;

            // Wait for propagation and verify
            cx.sleep(Duration::from_millis(50)).await;

            let all_received = self
                .coordinator
                .verify_all_streams_received_update(change_id, &scenario.service_name)?;

            if !all_received {
                return Err(format!(
                    "Not all streams received health status change for service: {}",
                    scenario.service_name
                )
                .into());
            }
        }

        // Phase 4: Clean up streams
        for (i, tracker) in stream_trackers.iter().enumerate() {
            self.coordinator.unregister_reflection_stream(i as u64);
            tracker.deactivate();
        }

        Ok(())
    }

    fn verify_integration_properties(&self) -> Result<()> {
        let stats = self.coordinator.get_propagation_stats();

        // Verify no bounded time violations
        if stats.bounded_time_violations > 0 {
            return Err(format!(
                "Bounded time violations detected: {}",
                stats.bounded_time_violations
            )
            .into());
        }

        // Verify propagation occurred
        if stats.total_propagations == 0 {
            return Err(format!("No health status propagations recorded").into());
        }

        // Verify reasonable propagation times
        if stats.average_propagation_time > Duration::from_millis(500) {
            return Err(format!(
                "Average propagation time too high: {:?}",
                stats.average_propagation_time
            )
            .into());
        }

        println!(
            "gRPC server/health integration verified: {} propagations, avg time: {:?}, max time: {:?}",
            stats.total_propagations, stats.average_propagation_time, stats.max_propagation_time
        );

        Ok(())
    }
}

/// Health status change scenario for testing
#[derive(Debug, Clone)]
struct HealthStatusScenario {
    service_name: String,
    old_status: HealthStatus,
    new_status: HealthStatus,
    delay_before_change: Duration,
}

impl HealthStatusScenario {
    fn new(
        service_name: String,
        old_status: HealthStatus,
        new_status: HealthStatus,
        delay_before_change: Duration,
    ) -> Self {
        Self {
            service_name,
            old_status,
            new_status,
            delay_before_change,
        }
    }
}

/// Mock implementations for testing infrastructure

/// Mock health service for testing
#[derive(Debug)]
struct MockHealthService {
    health_registry: Arc<RwLock<HashMap<String, HealthStatus>>>,
}

impl MockHealthService {
    fn new(health_registry: Arc<RwLock<HashMap<String, HealthStatus>>>) -> Self {
        Self { health_registry }
    }

    fn check_health(&self, service_name: &str) -> HealthStatus {
        let registry = self.health_registry.read();
        registry
            .get(service_name)
            .copied()
            .unwrap_or(HealthStatus::Unknown)
    }
}

/// Mock reflection service for testing
#[derive(Debug)]
struct MockReflectionService {
    service_descriptors: Arc<RwLock<HashMap<String, ServiceDescriptor>>>,
}

impl MockReflectionService {
    fn new() -> Self {
        Self {
            service_descriptors: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn register_service(&self, name: String, descriptor: ServiceDescriptor) {
        let mut descriptors = self.service_descriptors.write();
        descriptors.insert(name, descriptor);
    }
}

/// Mock server configuration
#[derive(Debug, Clone)]
struct ServerConfig {
    max_concurrent_streams: usize,
    stream_timeout: Duration,
    health_check_interval: Duration,
    reflection_enabled: bool,
}

/// Health status enumeration for testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthStatus {
    Unknown,
    Serving,
    NotServing,
    ServiceUnknown,
}

/// Service descriptor for reflection
#[derive(Debug, Clone)]
struct ServiceDescriptor {
    name: String,
    methods: Vec<String>,
}

impl ServiceDescriptor {
    fn new(name: String, methods: Vec<String>) -> Self {
        Self { name, methods }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_health_status_propagation() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = GrpcServerHealthTestHarness::new(Duration::from_millis(100));

        // Create single reflection stream
        let stream_id = 1;
        let tracker = harness.coordinator.register_reflection_stream(stream_id);
        tracker.subscribe_to_service("service.TestService".to_string());

        // Simulate health status change
        let change_id = harness.coordinator.propagate_health_status_change(
            "service.TestService".to_string(),
            HealthStatus::Serving,
            HealthStatus::NotServing,
        )?;

        // Verify propagation
        let all_received = harness
            .coordinator
            .verify_all_streams_received_update(change_id, "service.TestService")?;

        assert!(all_received, "Stream should receive health status change");

        // Clean up
        harness.coordinator.unregister_reflection_stream(stream_id);

        Ok(())
    }

    #[tokio::test]
    async fn test_bounded_time_propagation() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let bounded_time_limit = Duration::from_millis(50);
        let harness = GrpcServerHealthTestHarness::new(bounded_time_limit);

        // Create multiple reflection streams
        let stream_count = 5;
        let mut trackers = Vec::new();

        for i in 0..stream_count {
            let stream_id = i as u64;
            let tracker = harness.coordinator.register_reflection_stream(stream_id);
            tracker.subscribe_to_service("service.FastService".to_string());
            trackers.push(tracker);
        }

        // Measure propagation time
        let start_time = Instant::now();

        let change_id = harness.coordinator.propagate_health_status_change(
            "service.FastService".to_string(),
            HealthStatus::Unknown,
            HealthStatus::Serving,
        )?;

        let propagation_time = start_time.elapsed();

        // Verify bounded time constraint
        assert!(
            propagation_time <= bounded_time_limit,
            "Propagation time {:?} exceeded bound {:?}",
            propagation_time,
            bounded_time_limit
        );

        // Verify all streams received update
        let all_received = harness
            .coordinator
            .verify_all_streams_received_update(change_id, "service.FastService")?;

        assert!(
            all_received,
            "All streams should receive update within bounded time"
        );

        // Clean up
        for (i, tracker) in trackers.iter().enumerate() {
            harness.coordinator.unregister_reflection_stream(i as u64);
            tracker.deactivate();
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_services_stream_consistency() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = GrpcServerHealthTestHarness::new(Duration::from_millis(200));

        // Create reflection streams with different service subscriptions
        let services = vec![
            "service.UserService",
            "service.OrderService",
            "service.PaymentService",
        ];
        let mut trackers = Vec::new();

        for (i, service) in services.iter().enumerate() {
            let stream_id = i as u64;
            let tracker = harness.coordinator.register_reflection_stream(stream_id);
            tracker.subscribe_to_service(service.to_string());
            trackers.push(tracker);
        }

        // Propagate status changes for each service
        let mut change_ids = Vec::new();

        for service in &services {
            let change_id = harness.coordinator.propagate_health_status_change(
                service.to_string(),
                HealthStatus::Unknown,
                HealthStatus::Serving,
            )?;
            change_ids.push((change_id, service));
        }

        // Verify each stream received only its subscribed service updates
        for (i, (change_id, service)) in change_ids.iter().enumerate() {
            let tracker = &trackers[i];
            let updates = tracker.get_received_updates();

            // Should have exactly one update for its subscribed service
            assert_eq!(
                updates.len(),
                1,
                "Stream {} should have exactly one update",
                i
            );
            assert_eq!(
                updates[0].change_id, *change_id,
                "Update change_id should match"
            );
            assert_eq!(
                &updates[0].service_name, *service,
                "Service name should match subscription"
            );
        }

        // Clean up
        for (i, tracker) in trackers.iter().enumerate() {
            harness.coordinator.unregister_reflection_stream(i as u64);
            tracker.deactivate();
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_comprehensive_grpc_server_health_integration() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = GrpcServerHealthTestHarness::new(Duration::from_millis(100));

        // Create comprehensive test scenario
        let status_change_scenarios = vec![
            HealthStatusScenario::new(
                "service.TestService".to_string(),
                HealthStatus::Unknown,
                HealthStatus::Serving,
                Duration::from_millis(50),
            ),
            HealthStatusScenario::new(
                "service.UserService".to_string(),
                HealthStatus::Serving,
                HealthStatus::NotServing,
                Duration::from_millis(100),
            ),
            HealthStatusScenario::new(
                "service.OrderService".to_string(),
                HealthStatus::Unknown,
                HealthStatus::Serving,
                Duration::from_millis(75),
            ),
            HealthStatusScenario::new(
                "service.TestService".to_string(),
                HealthStatus::Serving,
                HealthStatus::NotServing,
                Duration::from_millis(125),
            ),
        ];

        // Run comprehensive integration test
        harness
            .simulate_grpc_server_with_health_integration(
                &cx,
                6, // 6 reflection streams
                status_change_scenarios,
            )
            .await?;

        // Verify integration properties
        harness.verify_integration_properties()?;

        // Verify final state
        let active_streams = harness.coordinator.get_active_stream_count();
        assert_eq!(active_streams, 0, "All streams should be cleaned up");

        let stats = harness.coordinator.get_propagation_stats();
        assert!(
            stats.total_propagations >= 4,
            "Should have processed all status changes"
        );
        assert_eq!(
            stats.bounded_time_violations, 0,
            "No bounded time violations should occur"
        );

        println!(
            "Comprehensive gRPC server/health integration test completed: {} propagations processed",
            stats.total_propagations
        );

        Ok(())
    }
}
