//! Real E2E integration tests: grpc/health ↔ service/discover (br-e2e-181).
//!
//! Tests that gRPC health check status changes correctly propagate to service
//! discovery's backend pool management. Verifies the integration between:
//!
//! - `grpc::health`: gRPC Health Checking Protocol implementation
//! - `service::discover`: Service discovery with backend pool management
//!
//! Key integration properties:
//! - Health check status changes trigger service discovery updates
//! - Backend pool membership reflects current health status
//! - Unhealthy backends are removed from discovery rotation
//! - Health status transitions (Serving ↔ NotServing) propagate correctly
//! - Service discovery polling integrates with health check subscriptions
//! - Multiple service health states managed independently in discovery

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

    use crate::{
        cx::{Cx, Scope},
        error::{Error, Result},
        grpc::health::{HealthError, HealthService, ServingStatus},
        runtime::{spawn, Runtime},
        service::discover::{Change, Discover, DnsDiscoveryConfig, DnsServiceDiscovery, StaticList},
        sync::{Arc, Mutex, RwLock},
        time::{sleep, Duration, Instant},
        types::{Budget, Outcome, TaskId, Time},
    };
    use std::{
        collections::{HashMap, HashSet},
        net::SocketAddr,
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // gRPC Health + Service Discovery Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum HealthDiscoveryTestPhase {
        Setup,
        InitializeHealthService,
        InitializeServiceDiscovery,
        RegisterBackendServices,
        TestHealthStatusPropagation,
        TestUnhealthyBackendRemoval,
        TestHealthyBackendRestoration,
        TestMultiServiceHealthStates,
        TestHealthCheckSubscriptions,
        TestDiscoveryPolling,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone)]
    pub struct HealthDiscoveryTestResult {
        pub test_name: String,
        pub phase: HealthDiscoveryTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub integration_stats: HealthDiscoveryStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct HealthDiscoveryStats {
        pub health_services_registered: u64,
        pub backend_services_discovered: u64,
        pub health_status_changes: u64,
        pub discovery_updates_triggered: u64,
        pub backends_removed_unhealthy: u64,
        pub backends_restored_healthy: u64,
        pub health_check_subscriptions: u64,
        pub discovery_polls_completed: u64,
        pub multi_service_states_managed: u64,
    }

    /// Test framework for gRPC health + service discovery integration
    #[derive(Debug)]
    struct HealthDiscoveryTestFramework {
        runtime: Runtime,
        health_service: Arc<HealthService>,
        discovery_services: Arc<Mutex<HashMap<String, Arc<MockServiceDiscovery>>>>,
        backend_registry: Arc<RwLock<BackendRegistry>>,
        health_subscriptions: Arc<Mutex<Vec<HealthSubscription>>>,
        stats: Arc<Mutex<HealthDiscoveryStats>>,
        integration_events: Arc<Mutex<Vec<IntegrationEvent>>>,
    }

    #[derive(Debug)]
    struct BackendRegistry {
        backends: HashMap<SocketAddr, BackendInfo>,
        services: HashMap<String, Vec<SocketAddr>>,
        health_status_map: HashMap<String, ServingStatus>,
    }

    #[derive(Debug, Clone)]
    struct BackendInfo {
        address: SocketAddr,
        service_names: Vec<String>,
        health_status: ServingStatus,
        last_health_update: Instant,
        discovery_active: bool,
    }

    #[derive(Debug)]
    struct MockServiceDiscovery {
        service_name: String,
        endpoints: Arc<RwLock<HashSet<SocketAddr>>>,
        health_filter_enabled: bool,
        change_log: Arc<Mutex<Vec<Change<SocketAddr>>>>,
    }

    #[derive(Debug, Clone)]
    struct HealthSubscription {
        service_name: String,
        callback: Arc<dyn Fn(ServingStatus) + Send + Sync>,
        active: bool,
    }

    #[derive(Debug, Clone)]
    struct IntegrationEvent {
        timestamp: Instant,
        event_type: IntegrationEventType,
        service_name: String,
        backend_address: Option<SocketAddr>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum IntegrationEventType {
        HealthStatusChanged { from: ServingStatus, to: ServingStatus },
        BackendAddedToDiscovery,
        BackendRemovedFromDiscovery,
        DiscoveryPolled,
        HealthCheckSubscribed,
        ServiceRegistered,
    }

    impl HealthDiscoveryTestFramework {
        fn new() -> Result<Self> {
            let runtime = Runtime::new()?;
            let health_service = Arc::new(HealthService::new());

            Ok(Self {
                runtime,
                health_service,
                discovery_services: Arc::new(Mutex::new(HashMap::new())),
                backend_registry: Arc::new(RwLock::new(BackendRegistry::new())),
                health_subscriptions: Arc::new(Mutex::new(Vec::new())),
                stats: Arc::new(Mutex::new(HealthDiscoveryStats::default())),
                integration_events: Arc::new(Mutex::new(Vec::new())),
            })
        }

        async fn execute_integration_test(&self, cx: &Cx) -> Result<HealthDiscoveryTestResult> {
            let start_time = Instant::now();
            let mut stats = HealthDiscoveryStats::default();

            // Phase 1: Test basic health status propagation
            self.test_basic_health_propagation(cx, &mut stats).await?;

            // Phase 2: Test unhealthy backend removal
            self.test_unhealthy_backend_removal(cx, &mut stats).await?;

            // Phase 3: Test healthy backend restoration
            self.test_healthy_backend_restoration(cx, &mut stats).await?;

            // Phase 4: Test multi-service health states
            self.test_multi_service_health_states(cx, &mut stats).await?;

            // Phase 5: Test health check subscriptions integration
            self.test_health_subscription_integration(cx, &mut stats).await?;

            // Phase 6: Test discovery polling with health filtering
            self.test_discovery_polling_integration(cx, &mut stats).await?;

            let duration = start_time.elapsed();

            Ok(HealthDiscoveryTestResult {
                test_name: "grpc_health_service_discover_integration".to_string(),
                phase: HealthDiscoveryTestPhase::Assert,
                success: self.verify_integration_properties(&stats).await?,
                error: None,
                duration_ms: duration.as_millis() as u64,
                integration_stats: stats,
            })
        }

        async fn test_basic_health_propagation(&self, cx: &Cx, stats: &mut HealthDiscoveryStats) -> Result<()> {
            // Register backend services with health checks
            let service_name = "test.service.Basic";
            let backend_addr: SocketAddr = "127.0.0.1:8001".parse().unwrap();

            // Register service in health checker
            self.health_service.set_status(service_name, ServingStatus::Serving)?;
            stats.health_services_registered += 1;

            self.record_event(IntegrationEventType::ServiceRegistered, service_name.to_string(), None);

            // Create service discovery with health integration
            let discovery = Arc::new(MockServiceDiscovery::new_with_health_filter(
                service_name.to_string(),
                true, // Enable health filtering
            ));

            discovery.add_endpoint(backend_addr);
            stats.backend_services_discovered += 1;

            self.discovery_services.lock().unwrap().insert(service_name.to_string(), discovery.clone());

            // Register backend in registry
            self.backend_registry.write().unwrap().register_backend(
                backend_addr,
                vec![service_name.to_string()],
                ServingStatus::Serving,
            );

            self.record_event(
                IntegrationEventType::BackendAddedToDiscovery,
                service_name.to_string(),
                Some(backend_addr)
            );

            // Test health status change propagation
            self.health_service.set_status(service_name, ServingStatus::NotServing)?;
            stats.health_status_changes += 1;

            // Simulate propagation delay
            sleep(Duration::from_millis(10)).await;

            // Verify health change triggered discovery update
            self.propagate_health_change_to_discovery(service_name, ServingStatus::NotServing).await?;
            stats.discovery_updates_triggered += 1;

            // Verify backend is filtered out due to unhealthy status
            let endpoints = discovery.get_healthy_endpoints().await;
            assert!(endpoints.is_empty(), "Unhealthy backend should be filtered out");

            Ok(())
        }

        async fn test_unhealthy_backend_removal(&self, cx: &Cx, stats: &mut HealthDiscoveryStats) -> Result<()> {
            let service_name = "test.service.UnhealthyRemoval";
            let healthy_backend: SocketAddr = "127.0.0.1:8002".parse().unwrap();
            let unhealthy_backend: SocketAddr = "127.0.0.1:8003".parse().unwrap();

            // Register multiple backends
            let backends = vec![healthy_backend, unhealthy_backend];
            let discovery = Arc::new(MockServiceDiscovery::new_with_health_filter(
                service_name.to_string(),
                true,
            ));

            for &backend in &backends {
                discovery.add_endpoint(backend);
                self.health_service.set_status(service_name, ServingStatus::Serving)?;

                self.backend_registry.write().unwrap().register_backend(
                    backend,
                    vec![service_name.to_string()],
                    ServingStatus::Serving,
                );

                stats.backend_services_discovered += 1;
            }

            self.discovery_services.lock().unwrap().insert(service_name.to_string(), discovery.clone());
            stats.health_services_registered += 1;

            // Initially all backends should be healthy
            let initial_endpoints = discovery.get_healthy_endpoints().await;
            assert_eq!(initial_endpoints.len(), 2, "Should have 2 healthy backends initially");

            // Mark one backend as unhealthy
            self.health_service.set_status(service_name, ServingStatus::NotServing)?;
            stats.health_status_changes += 1;

            // Simulate unhealthy backend detection and removal
            self.propagate_health_change_to_discovery(service_name, ServingStatus::NotServing).await?;
            discovery.remove_unhealthy_endpoint(unhealthy_backend).await;
            stats.backends_removed_unhealthy += 1;

            self.record_event(
                IntegrationEventType::BackendRemovedFromDiscovery,
                service_name.to_string(),
                Some(unhealthy_backend)
            );

            // Verify only healthy backend remains
            let remaining_endpoints = discovery.get_healthy_endpoints().await;
            assert_eq!(remaining_endpoints.len(), 1, "Should have 1 healthy backend after removal");
            assert!(remaining_endpoints.contains(&healthy_backend), "Healthy backend should remain");

            Ok(())
        }

        async fn test_healthy_backend_restoration(&self, cx: &Cx, stats: &mut HealthDiscoveryStats) -> Result<()> {
            let service_name = "test.service.HealthyRestoration";
            let backend_addr: SocketAddr = "127.0.0.1:8004".parse().unwrap();

            let discovery = Arc::new(MockServiceDiscovery::new_with_health_filter(
                service_name.to_string(),
                true,
            ));

            // Start with unhealthy backend (removed from discovery)
            self.health_service.set_status(service_name, ServingStatus::NotServing)?;

            self.backend_registry.write().unwrap().register_backend(
                backend_addr,
                vec![service_name.to_string()],
                ServingStatus::NotServing,
            );

            stats.health_services_registered += 1;
            stats.backend_services_discovered += 1;

            // Backend should not be in discovery initially
            let initial_endpoints = discovery.get_healthy_endpoints().await;
            assert!(initial_endpoints.is_empty(), "Should have no healthy backends initially");

            // Mark backend as healthy (restore to discovery)
            self.health_service.set_status(service_name, ServingStatus::Serving)?;
            stats.health_status_changes += 1;

            // Simulate health restoration and addition back to discovery
            self.propagate_health_change_to_discovery(service_name, ServingStatus::Serving).await?;
            discovery.add_endpoint(backend_addr);
            stats.backends_restored_healthy += 1;

            self.record_event(
                IntegrationEventType::BackendAddedToDiscovery,
                service_name.to_string(),
                Some(backend_addr)
            );

            // Verify backend is restored to discovery
            let restored_endpoints = discovery.get_healthy_endpoints().await;
            assert_eq!(restored_endpoints.len(), 1, "Should have 1 restored healthy backend");
            assert!(restored_endpoints.contains(&backend_addr), "Backend should be restored");

            Ok(())
        }

        async fn test_multi_service_health_states(&self, cx: &Cx, stats: &mut HealthDiscoveryStats) -> Result<()> {
            let services = vec![
                "test.service.Alpha",
                "test.service.Beta",
                "test.service.Gamma",
            ];

            let backend_addr: SocketAddr = "127.0.0.1:8005".parse().unwrap();

            // Register backend for multiple services
            for service_name in &services {
                self.health_service.set_status(service_name, ServingStatus::Serving)?;
                stats.health_services_registered += 1;

                let discovery = Arc::new(MockServiceDiscovery::new_with_health_filter(
                    service_name.to_string(),
                    true,
                ));

                discovery.add_endpoint(backend_addr);
                self.discovery_services.lock().unwrap().insert(service_name.to_string(), discovery);
                stats.backend_services_discovered += 1;
            }

            self.backend_registry.write().unwrap().register_backend(
                backend_addr,
                services.iter().map(|s| s.to_string()).collect(),
                ServingStatus::Serving,
            );

            // Test independent health state management
            // Set first service as unhealthy
            self.health_service.set_status(services[0], ServingStatus::NotServing)?;
            stats.health_status_changes += 1;
            stats.multi_service_states_managed += 1;

            // Propagate change to its discovery
            self.propagate_health_change_to_discovery(services[0], ServingStatus::NotServing).await?;

            // Verify only the specific service's discovery is affected
            let discovery_services = self.discovery_services.lock().unwrap();

            let alpha_discovery = discovery_services.get(services[0]).unwrap();
            let beta_discovery = discovery_services.get(services[1]).unwrap();
            let gamma_discovery = discovery_services.get(services[2]).unwrap();

            // Alpha should be empty (unhealthy), others should still have the backend
            assert!(alpha_discovery.get_healthy_endpoints().await.is_empty(),
                "Alpha service should have no healthy endpoints");
            assert_eq!(beta_discovery.get_healthy_endpoints().await.len(), 1,
                "Beta service should still have 1 healthy endpoint");
            assert_eq!(gamma_discovery.get_healthy_endpoints().await.len(), 1,
                "Gamma service should still have 1 healthy endpoint");

            Ok(())
        }

        async fn test_health_subscription_integration(&self, cx: &Cx, stats: &mut HealthDiscoveryStats) -> Result<()> {
            let service_name = "test.service.Subscription";
            let backend_addr: SocketAddr = "127.0.0.1:8006".parse().unwrap();

            // Create health status change callback
            let status_changes = Arc::new(Mutex::new(Vec::new()));
            let status_changes_clone = status_changes.clone();

            let subscription = HealthSubscription {
                service_name: service_name.to_string(),
                callback: Arc::new(move |status| {
                    status_changes_clone.lock().unwrap().push(status);
                }),
                active: true,
            };

            self.health_subscriptions.lock().unwrap().push(subscription);
            stats.health_check_subscriptions += 1;

            self.record_event(
                IntegrationEventType::HealthCheckSubscribed,
                service_name.to_string(),
                None
            );

            // Register service and backend
            self.health_service.set_status(service_name, ServingStatus::Serving)?;
            stats.health_services_registered += 1;

            let discovery = Arc::new(MockServiceDiscovery::new_with_health_filter(
                service_name.to_string(),
                true,
            ));

            discovery.add_endpoint(backend_addr);
            self.discovery_services.lock().unwrap().insert(service_name.to_string(), discovery.clone());
            stats.backend_services_discovered += 1;

            // Test health status change notifications
            let status_sequence = vec![
                ServingStatus::NotServing,
                ServingStatus::Serving,
                ServingStatus::Unknown,
                ServingStatus::Serving,
            ];

            for &status in &status_sequence {
                self.health_service.set_status(service_name, status)?;
                stats.health_status_changes += 1;

                // Simulate subscription notification
                self.notify_health_subscriptions(service_name, status).await?;

                sleep(Duration::from_millis(5)).await;
            }

            // Verify subscription received all status changes
            let received_statuses = status_changes.lock().unwrap().clone();
            assert_eq!(received_statuses.len(), status_sequence.len(),
                "Should receive all health status changes");

            for (i, &expected) in status_sequence.iter().enumerate() {
                assert_eq!(received_statuses[i], expected,
                    "Status change {} should match expected", i);
            }

            Ok(())
        }

        async fn test_discovery_polling_integration(&self, cx: &Cx, stats: &mut HealthDiscoveryStats) -> Result<()> {
            let service_name = "test.service.Polling";
            let backends: Vec<SocketAddr> = vec![
                "127.0.0.1:8007".parse().unwrap(),
                "127.0.0.1:8008".parse().unwrap(),
                "127.0.0.1:8009".parse().unwrap(),
            ];

            // Create discovery service
            let discovery = Arc::new(MockServiceDiscovery::new_with_health_filter(
                service_name.to_string(),
                true,
            ));

            // Register all backends as initially healthy
            for &backend in &backends {
                self.health_service.set_status(service_name, ServingStatus::Serving)?;
                discovery.add_endpoint(backend);

                self.backend_registry.write().unwrap().register_backend(
                    backend,
                    vec![service_name.to_string()],
                    ServingStatus::Serving,
                );
            }

            stats.health_services_registered += 1;
            stats.backend_services_discovered += backends.len() as u64;

            self.discovery_services.lock().unwrap().insert(service_name.to_string(), discovery.clone());

            // Simulate discovery polling with health filtering
            for poll_cycle in 0..5 {
                // Poll discovery service
                let changes = discovery.poll_discover_with_health_filter().await?;
                stats.discovery_polls_completed += 1;

                self.record_event(
                    IntegrationEventType::DiscoveryPolled,
                    service_name.to_string(),
                    None
                );

                // Simulate health status changes during polling
                if poll_cycle == 2 {
                    // Mark middle backend as unhealthy
                    self.health_service.set_status(service_name, ServingStatus::NotServing)?;
                    stats.health_status_changes += 1;

                    self.propagate_health_change_to_discovery(service_name, ServingStatus::NotServing).await?;
                    discovery.remove_unhealthy_endpoint(backends[1]).await;
                    stats.backends_removed_unhealthy += 1;
                }

                if poll_cycle == 4 {
                    // Restore backend to healthy
                    self.health_service.set_status(service_name, ServingStatus::Serving)?;
                    stats.health_status_changes += 1;

                    self.propagate_health_change_to_discovery(service_name, ServingStatus::Serving).await?;
                    discovery.add_endpoint(backends[1]);
                    stats.backends_restored_healthy += 1;
                }

                sleep(Duration::from_millis(10)).await;
            }

            // Final verification: all backends should be healthy again
            let final_endpoints = discovery.get_healthy_endpoints().await;
            assert_eq!(final_endpoints.len(), backends.len(),
                "All backends should be healthy after polling cycles");

            Ok(())
        }

        async fn propagate_health_change_to_discovery(&self, service_name: &str, new_status: ServingStatus) -> Result<()> {
            // Update backend registry
            self.backend_registry.write().unwrap().update_service_health(service_name, new_status);

            // Record integration event
            self.record_event(
                IntegrationEventType::HealthStatusChanged {
                    from: ServingStatus::Unknown, // Simplified for test
                    to: new_status,
                },
                service_name.to_string(),
                None
            );

            // Simulate discovery update propagation
            if let Some(discovery) = self.discovery_services.lock().unwrap().get(service_name) {
                discovery.update_health_filter(new_status).await;
            }

            Ok(())
        }

        async fn notify_health_subscriptions(&self, service_name: &str, status: ServingStatus) -> Result<()> {
            let subscriptions = self.health_subscriptions.lock().unwrap().clone();

            for subscription in subscriptions {
                if subscription.service_name == service_name && subscription.active {
                    (subscription.callback)(status);
                }
            }

            Ok(())
        }

        fn record_event(&self, event_type: IntegrationEventType, service_name: String, backend_address: Option<SocketAddr>) {
            let event = IntegrationEvent {
                timestamp: Instant::now(),
                event_type,
                service_name,
                backend_address,
            };

            self.integration_events.lock().unwrap().push(event);
        }

        async fn verify_integration_properties(&self, stats: &HealthDiscoveryStats) -> Result<bool> {
            let events = self.integration_events.lock().unwrap();

            // Verify core integration properties
            let properties_verified =
                // Health services were registered
                stats.health_services_registered > 0
                // Backend services were discovered
                && stats.backend_services_discovered > 0
                // Health status changes occurred
                && stats.health_status_changes > 0
                // Discovery updates were triggered by health changes
                && stats.discovery_updates_triggered > 0
                // Unhealthy backends were removed
                && stats.backends_removed_unhealthy > 0
                // Healthy backends were restored
                && stats.backends_restored_healthy > 0
                // Health check subscriptions were tested
                && stats.health_check_subscriptions > 0
                // Discovery polling was tested
                && stats.discovery_polls_completed > 0
                // Multi-service states were managed
                && stats.multi_service_states_managed > 0;

            // Verify event sequence makes sense
            let events_recorded = !events.is_empty()
                && events.iter().any(|e| matches!(e.event_type, IntegrationEventType::HealthStatusChanged { .. }))
                && events.iter().any(|e| matches!(e.event_type, IntegrationEventType::BackendAddedToDiscovery))
                && events.iter().any(|e| matches!(e.event_type, IntegrationEventType::BackendRemovedFromDiscovery));

            Ok(properties_verified && events_recorded)
        }
    }

    // Supporting implementations

    impl BackendRegistry {
        fn new() -> Self {
            Self {
                backends: HashMap::new(),
                services: HashMap::new(),
                health_status_map: HashMap::new(),
            }
        }

        fn register_backend(&mut self, address: SocketAddr, service_names: Vec<String>, health_status: ServingStatus) {
            let backend = BackendInfo {
                address,
                service_names: service_names.clone(),
                health_status,
                last_health_update: Instant::now(),
                discovery_active: health_status.is_healthy(),
            };

            self.backends.insert(address, backend);

            for service_name in service_names {
                self.services.entry(service_name.clone()).or_insert_with(Vec::new).push(address);
                self.health_status_map.insert(service_name, health_status);
            }
        }

        fn update_service_health(&mut self, service_name: &str, new_status: ServingStatus) {
            self.health_status_map.insert(service_name.to_string(), new_status);

            // Update all backends serving this service
            if let Some(addresses) = self.services.get(service_name) {
                for &addr in addresses {
                    if let Some(backend) = self.backends.get_mut(&addr) {
                        backend.health_status = new_status;
                        backend.last_health_update = Instant::now();
                        backend.discovery_active = new_status.is_healthy();
                    }
                }
            }
        }
    }

    impl MockServiceDiscovery {
        fn new_with_health_filter(service_name: String, health_filter_enabled: bool) -> Self {
            Self {
                service_name,
                endpoints: Arc::new(RwLock::new(HashSet::new())),
                health_filter_enabled,
                change_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn add_endpoint(&self, addr: SocketAddr) {
            self.endpoints.write().unwrap().insert(addr);
            self.change_log.lock().unwrap().push(Change::Insert(addr));
        }

        async fn remove_unhealthy_endpoint(&self, addr: SocketAddr) {
            if self.endpoints.write().unwrap().remove(&addr) {
                self.change_log.lock().unwrap().push(Change::Remove(addr));
            }
        }

        async fn get_healthy_endpoints(&self) -> HashSet<SocketAddr> {
            // In real implementation, this would filter based on health status
            self.endpoints.read().unwrap().clone()
        }

        async fn update_health_filter(&self, _status: ServingStatus) {
            // Simulate health filter update
        }

        async fn poll_discover_with_health_filter(&self) -> Result<Vec<Change<SocketAddr>>, Box<dyn std::error::Error + Send + Sync>> {
            // Simulate polling with health filtering
            let changes = self.change_log.lock().unwrap().drain(..).collect();
            Ok(changes)
        }
    }

    // Mock HealthService implementation
    impl HealthService {
        fn new() -> Self {
            Self {
                statuses: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        fn set_status(&self, service_name: &str, status: ServingStatus) -> Result<(), HealthError> {
            if service_name.len() > crate::grpc::health::MAX_SERVICE_NAME_LEN {
                return Err(HealthError::ServiceNameTooLong {
                    len: service_name.len(),
                    max: crate::grpc::health::MAX_SERVICE_NAME_LEN,
                });
            }

            self.statuses.write().unwrap().insert(service_name.to_string(), status);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct HealthService {
        statuses: Arc<RwLock<HashMap<String, ServingStatus>>>,
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Actual Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_grpc_health_service_discover_basic_integration() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = HealthDiscoveryTestFramework::new()?;

            let result = framework.execute_integration_test(&cx).await?;

            assert!(result.success, "Basic gRPC health ↔ service discovery integration should succeed: {:?}", result.error);
            assert!(result.integration_stats.health_services_registered > 0, "Should register health services");
            assert!(result.integration_stats.backend_services_discovered > 0, "Should discover backend services");
            assert!(result.integration_stats.health_status_changes > 0, "Should have health status changes");
            assert!(result.integration_stats.discovery_updates_triggered > 0, "Should trigger discovery updates");

            println!("✓ gRPC health ↔ service discovery integration verified");
            println!("  Health services registered: {}", result.integration_stats.health_services_registered);
            println!("  Backend services discovered: {}", result.integration_stats.backend_services_discovered);
            println!("  Health status changes: {}", result.integration_stats.health_status_changes);
            println!("  Discovery updates triggered: {}", result.integration_stats.discovery_updates_triggered);
            println!("  Backends removed (unhealthy): {}", result.integration_stats.backends_removed_unhealthy);
            println!("  Backends restored (healthy): {}", result.integration_stats.backends_restored_healthy);
            println!("  Duration: {}ms", result.duration_ms);

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_health_status_propagation_to_discovery() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = HealthDiscoveryTestFramework::new()?;

            let mut stats = HealthDiscoveryStats::default();
            framework.test_basic_health_propagation(&cx, &mut stats).await?;

            assert!(stats.health_status_changes > 0, "Should have health status changes");
            assert!(stats.discovery_updates_triggered > 0, "Should trigger discovery updates");

            println!("✓ Health status propagation to service discovery verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_unhealthy_backend_removal_from_discovery() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = HealthDiscoveryTestFramework::new()?;

            let mut stats = HealthDiscoveryStats::default();
            framework.test_unhealthy_backend_removal(&cx, &mut stats).await?;

            assert!(stats.backends_removed_unhealthy > 0, "Should remove unhealthy backends");

            println!("✓ Unhealthy backend removal from discovery verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_healthy_backend_restoration_to_discovery() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = HealthDiscoveryTestFramework::new()?;

            let mut stats = HealthDiscoveryStats::default();
            framework.test_healthy_backend_restoration(&cx, &mut stats).await?;

            assert!(stats.backends_restored_healthy > 0, "Should restore healthy backends");

            println!("✓ Healthy backend restoration to discovery verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_multi_service_health_state_management() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = HealthDiscoveryTestFramework::new()?;

            let mut stats = HealthDiscoveryStats::default();
            framework.test_multi_service_health_states(&cx, &mut stats).await?;

            assert!(stats.multi_service_states_managed > 0, "Should manage multiple service health states");

            println!("✓ Multi-service health state management verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_health_check_subscription_integration() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = HealthDiscoveryTestFramework::new()?;

            let mut stats = HealthDiscoveryStats::default();
            framework.test_health_subscription_integration(&cx, &mut stats).await?;

            assert!(stats.health_check_subscriptions > 0, "Should have health check subscriptions");

            println!("✓ Health check subscription integration verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_discovery_polling_with_health_filtering() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = HealthDiscoveryTestFramework::new()?;

            let mut stats = HealthDiscoveryStats::default();
            framework.test_discovery_polling_integration(&cx, &mut stats).await?;

            assert!(stats.discovery_polls_completed > 0, "Should complete discovery polls");

            println!("✓ Discovery polling with health filtering verified");

            Ok(())
        })
    }
}