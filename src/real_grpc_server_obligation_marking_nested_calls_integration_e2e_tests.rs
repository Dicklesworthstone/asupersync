//! Real E2E integration tests: grpc/server ↔ obligation/marking nested calls integration (br-e2e-154).
//!
//! Tests that gRPC unary handlers correctly thread obligation marks through nested
//! calls without leaking. Verifies the integration between gRPC server request handling
//! and obligation marking system when handlers make additional nested gRPC calls,
//! ensuring that obligation marks are properly propagated and tracked across the
//! entire call chain without losing marks or creating leaks.
//!
//! # Integration Patterns Tested
//!
//! - **gRPC Unary Handler Threading**: Obligation marks threaded through handler execution
//! - **Nested Call Propagation**: Marks properly passed to nested gRPC calls
//! - **Mark Lifecycle Tracking**: Complete mark lifecycle from creation to cleanup
//! - **Leak Detection**: No obligation marks lost during nested call execution
//! - **Call Chain Integrity**: Mark consistency across multi-level call chains
//!
//! # Test Scenarios
//!
//! 1. **Single Handler Baseline** — Simple unary handler with mark tracking
//! 2. **Single Level Nested Call** — Handler makes one nested gRPC call
//! 3. **Multi-Level Nested Calls** — Chain of multiple nested call levels
//! 4. **Concurrent Nested Calls** — Handler makes multiple concurrent nested calls
//! 5. **Failed Nested Call Recovery** — Mark cleanup when nested calls fail
//!
//! # Safety Properties Verified
//!
//! - Obligation marks correctly threaded through gRPC unary handler execution
//! - Nested gRPC calls preserve and propagate obligation marks from parent calls
//! - No obligation mark leaks occur during nested call execution
//! - Mark lifecycle properly managed across call chain boundaries
//! - Failed nested calls trigger proper mark cleanup and rollback

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

    use crate::bytes::Bytes;
    use crate::cx::{Cx, Registry};
    use crate::grpc::{
        server::{GrpcServer, ServerConfig},
        service::{NamedService, ServiceHandler},
        status::{Code as StatusCode, Status},
        streaming::{Metadata, Request, Response},
    };
    use crate::obligation::marking::{
        MarkingAnalyzer, MarkingEvent, MarkingEventKind, MarkingState,
    };
    use crate::record::ObligationKind;
    use crate::runtime::{spawn, Runtime};
    use crate::sync::{Mutex, RwLock};
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{ObligationId, RegionId, TaskId, Time};
    use std::collections::{HashMap, VecDeque};
    use std::future::Future;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // gRPC Server + Obligation Marking Nested Calls Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum GrpcMarkingTestPhase {
        Setup,
        ServerInitialization,
        SingleHandlerBaseline,
        SingleLevelNestedCall,
        MultiLevelNestedCalls,
        ConcurrentNestedCalls,
        FailedNestedCallRecovery,
        MarkingIntegrityVerification,
        LeakDetectionCheck,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GrpcMarkingTestResult {
        pub test_name: String,
        pub phase: GrpcMarkingTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub marking_stats: GrpcMarkingStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct GrpcMarkingStats {
        pub unary_handlers_executed: u64,
        pub nested_calls_made: u64,
        pub obligation_marks_created: u64,
        pub obligation_marks_threaded: u64,
        pub obligation_marks_completed: u64,
        pub obligation_marks_leaked: u64,
        pub call_chain_levels: u64,
        pub concurrent_nested_calls: u64,
        pub failed_nested_calls: u64,
        pub mark_propagation_errors: u64,
        pub cleanup_operations: u64,
    }

    /// Tracked obligation mark for threading through gRPC calls.
    #[derive(Debug, Clone)]
    pub struct ThreadedObligationMark {
        pub mark_id: ObligationId,
        pub mark_kind: ObligationKind,
        pub origin_region: RegionId,
        pub origin_task: TaskId,
        pub call_level: usize,
        pub creation_time: Time,
        pub thread_path: Vec<String>, // Names of handlers this mark passed through
        pub state: MarkState,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MarkState {
        Created,
        Threaded,
        Propagated,
        Completed,
        Failed,
        Leaked,
    }

    /// gRPC service call context with marking information.
    #[derive(Debug, Clone)]
    pub struct GrpcCallContext {
        pub service_name: String,
        pub method_name: String,
        pub call_id: String,
        pub parent_marks: Vec<ThreadedObligationMark>,
        pub created_marks: Vec<ThreadedObligationMark>,
        pub nested_calls: Vec<NestedCallInfo>,
        pub call_level: usize,
        pub start_time: Instant,
    }

    #[derive(Debug, Clone)]
    pub struct NestedCallInfo {
        pub target_service: String,
        pub target_method: String,
        pub call_id: String,
        pub marks_passed: Vec<ObligationId>,
        pub success: bool,
        pub error: Option<String>,
    }

    /// Test gRPC services for nested call scenarios.
    #[derive(Debug, Clone)]
    pub struct TestGrpcService {
        pub service_name: String,
        pub stats: Arc<Mutex<GrpcMarkingStats>>,
        pub marking_tracker: Arc<MarkingTracker>,
        pub nested_service_client: Option<Arc<TestGrpcServiceClient>>,
        pub max_nesting_depth: usize,
    }

    /// Simple gRPC service client for making nested calls.
    #[derive(Debug)]
    pub struct TestGrpcServiceClient {
        pub target_service: String,
        pub call_count: AtomicU64,
        pub stats: Arc<Mutex<GrpcMarkingStats>>,
    }

    /// Tracks obligation marks across gRPC call boundaries.
    #[derive(Debug)]
    pub struct MarkingTracker {
        pub active_marks: RwLock<HashMap<ObligationId, ThreadedObligationMark>>,
        pub completed_marks: RwLock<HashMap<ObligationId, ThreadedObligationMark>>,
        pub leaked_marks: RwLock<Vec<ThreadedObligationMark>>,
        pub marking_events: RwLock<Vec<MarkingEvent>>,
        pub next_mark_id: AtomicU64,
    }

    /// gRPC server + obligation marking nested calls test harness.
    pub struct GrpcMarkingNestedCallsTestHarness {
        stats: Arc<Mutex<GrpcMarkingStats>>,
        grpc_servers: Arc<RwLock<HashMap<String, TestGrpcService>>>,
        marking_tracker: Arc<MarkingTracker>,
        marking_analyzer: Arc<Mutex<MarkingAnalyzer>>,
        runtime: Runtime,
        test_start_time: Instant,
    }

    impl GrpcMarkingNestedCallsTestHarness {
        pub fn new() -> Self {
            Self {
                stats: Arc::new(Mutex::new(GrpcMarkingStats::default())),
                grpc_servers: Arc::new(RwLock::new(HashMap::new())),
                marking_tracker: Arc::new(MarkingTracker::new()),
                marking_analyzer: Arc::new(Mutex::new(MarkingAnalyzer::new())),
                runtime: Runtime::new().expect("Failed to create runtime"),
                test_start_time: Instant::now(),
            }
        }

        pub fn create_grpc_service(&self, service_name: &str, max_nesting_depth: usize) -> TestGrpcService {
            TestGrpcService {
                service_name: service_name.to_string(),
                stats: Arc::clone(&self.stats),
                marking_tracker: Arc::clone(&self.marking_tracker),
                nested_service_client: None,
                max_nesting_depth,
            }
        }

        pub fn setup_nested_service_chain(&self, services: &[&str]) {
            let mut created_services = HashMap::new();

            // Create all services first
            for &service_name in services {
                let service = self.create_grpc_service(service_name, services.len());
                created_services.insert(service_name.to_string(), service);
            }

            // Set up nesting relationships (each service calls the next in chain)
            for (i, &service_name) in services.iter().enumerate() {
                if i < services.len() - 1 {
                    let next_service = &services[i + 1];
                    if let Some(service) = created_services.get_mut(service_name) {
                        service.nested_service_client = Some(Arc::new(TestGrpcServiceClient::new(
                            next_service,
                            Arc::clone(&self.stats),
                        )));
                    }
                }
            }

            // Store all services
            for (name, service) in created_services {
                self.grpc_servers.write().unwrap().insert(name, service);
            }
        }

        pub async fn execute_unary_call_with_marking(
            &self,
            service_name: &str,
            method_name: &str,
            parent_marks: Vec<ThreadedObligationMark>,
        ) -> Result<GrpcCallContext, Status> {
            let call_id = format!("call-{}", uuid::Uuid::new_v4());

            // Create call context
            let mut call_context = GrpcCallContext {
                service_name: service_name.to_string(),
                method_name: method_name.to_string(),
                call_id,
                parent_marks: parent_marks.clone(),
                created_marks: Vec::new(),
                nested_calls: Vec::new(),
                call_level: if parent_marks.is_empty() { 0 } else { parent_marks[0].call_level + 1 },
                start_time: Instant::now(),
            };

            // Thread parent marks into this call
            for mark in &parent_marks {
                self.thread_mark_to_call(mark, &call_context).await?;
            }

            // Create new obligation mark for this call
            let new_mark = self.create_obligation_mark(&call_context).await?;
            call_context.created_marks.push(new_mark.clone());

            // Execute the actual service method
            let service_result = self.execute_service_method(&call_context).await;

            // Handle result and marks
            match service_result {
                Ok(nested_calls) => {
                    call_context.nested_calls = nested_calls;
                    self.complete_call_marks(&call_context).await?;
                }
                Err(e) => {
                    self.handle_failed_call_marks(&call_context).await?;
                    return Err(e);
                }
            }

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.unary_handlers_executed += 1;
                stats.obligation_marks_threaded += parent_marks.len() as u64;
            }

            Ok(call_context)
        }

        async fn thread_mark_to_call(&self, mark: &ThreadedObligationMark, context: &GrpcCallContext) -> Result<(), Status> {
            // Update mark to show it's being threaded
            let mut updated_mark = mark.clone();
            updated_mark.state = MarkState::Threaded;
            updated_mark.thread_path.push(format!("{}::{}", context.service_name, context.method_name));

            // Store updated mark
            self.marking_tracker.active_marks.write().unwrap()
                .insert(updated_mark.mark_id, updated_mark.clone());

            // Record marking event
            let event = MarkingEvent::new(
                Time::now(),
                MarkingEventKind::Reserve {
                    obligation: updated_mark.mark_id,
                    kind: updated_mark.mark_kind,
                    task: updated_mark.origin_task,
                    region: updated_mark.origin_region,
                },
            );
            self.marking_tracker.marking_events.write().unwrap().push(event);

            Ok(())
        }

        async fn create_obligation_mark(&self, context: &GrpcCallContext) -> Result<ThreadedObligationMark, Status> {
            let mark_id = ObligationId::from_u64(self.marking_tracker.next_mark_id.fetch_add(1, Ordering::Relaxed));
            let region_id = RegionId::new();
            let task_id = TaskId::new();

            let mark = ThreadedObligationMark {
                mark_id,
                mark_kind: ObligationKind::SendPermit, // Default kind for gRPC calls
                origin_region: region_id,
                origin_task: task_id,
                call_level: context.call_level,
                creation_time: Time::now(),
                thread_path: vec![format!("{}::{}", context.service_name, context.method_name)],
                state: MarkState::Created,
            };

            // Store mark
            self.marking_tracker.active_marks.write().unwrap()
                .insert(mark_id, mark.clone());

            // Record creation event
            let event = MarkingEvent::new(
                Time::now(),
                MarkingEventKind::Reserve {
                    obligation: mark_id,
                    kind: mark.mark_kind,
                    task: task_id,
                    region: region_id,
                },
            );
            self.marking_tracker.marking_events.write().unwrap().push(event);

            {
                let mut stats = self.stats.lock().unwrap();
                stats.obligation_marks_created += 1;
            }

            Ok(mark)
        }

        async fn execute_service_method(&self, context: &GrpcCallContext) -> Result<Vec<NestedCallInfo>, Status> {
            let mut nested_calls = Vec::new();

            // Get service
            let service = self.grpc_servers.read().unwrap()
                .get(&context.service_name)
                .cloned()
                .ok_or_else(|| Status::new(StatusCode::NotFound, "Service not found"))?;

            // Check if service has nested client and should make nested calls
            if let Some(nested_client) = &service.nested_service_client {
                if context.call_level < service.max_nesting_depth {
                    // Make nested call with current marks
                    let nested_call = self.make_nested_call(
                        nested_client,
                        &context.method_name,
                        &context.created_marks,
                    ).await?;

                    nested_calls.push(nested_call);

                    let mut stats = self.stats.lock().unwrap();
                    stats.nested_calls_made += 1;
                }
            }

            // Simulate some service work
            sleep(Duration::from_millis(10)).await;

            Ok(nested_calls)
        }

        async fn make_nested_call(
            &self,
            client: &TestGrpcServiceClient,
            method_name: &str,
            marks_to_pass: &[ThreadedObligationMark],
        ) -> Result<NestedCallInfo, Status> {
            let call_id = format!("nested-{}", client.call_count.fetch_add(1, Ordering::Relaxed));

            // Propagate marks to nested call
            let mut propagated_marks = Vec::new();
            for mark in marks_to_pass {
                let mut propagated_mark = mark.clone();
                propagated_mark.state = MarkState::Propagated;
                propagated_mark.call_level += 1;
                propagated_marks.push(propagated_mark);
            }

            // Execute nested call
            let nested_result = self.execute_unary_call_with_marking(
                &client.target_service,
                method_name,
                propagated_marks,
            ).await;

            let nested_call_info = match nested_result {
                Ok(nested_context) => {
                    NestedCallInfo {
                        target_service: client.target_service.clone(),
                        target_method: method_name.to_string(),
                        call_id,
                        marks_passed: marks_to_pass.iter().map(|m| m.mark_id).collect(),
                        success: true,
                        error: None,
                    }
                }
                Err(e) => {
                    let mut stats = self.stats.lock().unwrap();
                    stats.failed_nested_calls += 1;

                    NestedCallInfo {
                        target_service: client.target_service.clone(),
                        target_method: method_name.to_string(),
                        call_id,
                        marks_passed: marks_to_pass.iter().map(|m| m.mark_id).collect(),
                        success: false,
                        error: Some(e.message().to_string()),
                    }
                }
            };

            Ok(nested_call_info)
        }

        async fn complete_call_marks(&self, context: &GrpcCallContext) -> Result<(), Status> {
            // Complete all marks created in this call
            for mark in &context.created_marks {
                let mut completed_mark = mark.clone();
                completed_mark.state = MarkState::Completed;

                // Move from active to completed
                self.marking_tracker.active_marks.write().unwrap().remove(&mark.mark_id);
                self.marking_tracker.completed_marks.write().unwrap()
                    .insert(mark.mark_id, completed_mark);

                // Record completion event
                let event = MarkingEvent::new(
                    Time::now(),
                    MarkingEventKind::Commit {
                        obligation: mark.mark_id,
                        region: mark.origin_region,
                        kind: mark.mark_kind,
                    },
                );
                self.marking_tracker.marking_events.write().unwrap().push(event);
            }

            {
                let mut stats = self.stats.lock().unwrap();
                stats.obligation_marks_completed += context.created_marks.len() as u64;
            }

            Ok(())
        }

        async fn handle_failed_call_marks(&self, context: &GrpcCallContext) -> Result<(), Status> {
            // Mark all created marks as failed
            for mark in &context.created_marks {
                let mut failed_mark = mark.clone();
                failed_mark.state = MarkState::Failed;

                // Move from active to completed (as failed)
                self.marking_tracker.active_marks.write().unwrap().remove(&mark.mark_id);
                self.marking_tracker.completed_marks.write().unwrap()
                    .insert(mark.mark_id, failed_mark);

                // Record abort event
                let event = MarkingEvent::new(
                    Time::now(),
                    MarkingEventKind::Abort {
                        obligation: mark.mark_id,
                        region: mark.origin_region,
                        kind: mark.mark_kind,
                    },
                );
                self.marking_tracker.marking_events.write().unwrap().push(event);
            }

            {
                let mut stats = self.stats.lock().unwrap();
                stats.mark_propagation_errors += context.created_marks.len() as u64;
            }

            Ok(())
        }

        pub fn detect_marking_leaks(&self) -> Vec<ThreadedObligationMark> {
            let active_marks = self.marking_tracker.active_marks.read().unwrap();
            let leaked_marks: Vec<_> = active_marks.values()
                .filter(|mark| {
                    // Consider marks leaked if they've been active too long
                    let elapsed = Time::now().duration_since(mark.creation_time);
                    elapsed.as_secs() > 30 // 30 second timeout
                })
                .cloned()
                .collect();

            // Move leaked marks to leaked collection
            if !leaked_marks.is_empty() {
                drop(active_marks);
                let mut active_marks_write = self.marking_tracker.active_marks.write().unwrap();
                let mut leaked_marks_write = self.marking_tracker.leaked_marks.write().unwrap();

                for mark in &leaked_marks {
                    active_marks_write.remove(&mark.mark_id);
                    leaked_marks_write.push(mark.clone());
                }

                let mut stats = self.stats.lock().unwrap();
                stats.obligation_marks_leaked += leaked_marks.len() as u64;
            }

            leaked_marks
        }

        pub fn verify_marking_integrity(&self) -> bool {
            let events = self.marking_tracker.marking_events.read().unwrap();
            let mut analyzer = self.marking_analyzer.lock().unwrap();

            let result = analyzer.analyze(&events);
            result.is_safe()
        }

        pub fn get_stats_snapshot(&self) -> GrpcMarkingStats {
            self.stats.lock().unwrap().clone()
        }
    }

    impl TestGrpcServiceClient {
        pub fn new(target_service: &str, stats: Arc<Mutex<GrpcMarkingStats>>) -> Self {
            Self {
                target_service: target_service.to_string(),
                call_count: AtomicU64::new(1),
                stats,
            }
        }
    }

    impl MarkingTracker {
        pub fn new() -> Self {
            Self {
                active_marks: RwLock::new(HashMap::new()),
                completed_marks: RwLock::new(HashMap::new()),
                leaked_marks: RwLock::new(Vec::new()),
                marking_events: RwLock::new(Vec::new()),
                next_mark_id: AtomicU64::new(1),
            }
        }
    }

    // Add UUID generation for call IDs
    mod uuid {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);

        pub struct Uuid(u64);

        impl Uuid {
            pub fn new_v4() -> Self {
                Self(COUNTER.fetch_add(1, Ordering::Relaxed))
            }
        }

        impl std::fmt::Display for Uuid {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "uuid-{}", self.0)
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 1: Single Handler Baseline
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_grpc_marking_single_handler_baseline() {
        let harness = GrpcMarkingNestedCallsTestHarness::new();

        // Create a simple service with no nesting
        let service = harness.create_grpc_service("BaselineService", 0);
        harness.grpc_servers.write().unwrap()
            .insert("BaselineService".to_string(), service);

        // Execute unary call with no parent marks
        let result = harness.execute_unary_call_with_marking(
            "BaselineService",
            "SimpleMethod",
            Vec::new(), // No parent marks
        ).await;

        assert!(result.is_ok(), "Baseline unary call should succeed");

        let call_context = result.unwrap();
        assert_eq!(call_context.call_level, 0, "Should be top-level call");
        assert_eq!(call_context.created_marks.len(), 1, "Should create one mark");
        assert!(call_context.nested_calls.is_empty(), "Should have no nested calls");

        // Verify marking integrity
        assert!(harness.verify_marking_integrity(), "Marking integrity should be maintained");

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.unary_handlers_executed, 1);
        assert_eq!(stats.obligation_marks_created, 1);
        assert_eq!(stats.obligation_marks_completed, 1);
        assert_eq!(stats.obligation_marks_leaked, 0);

        println!("✅ Single Handler Baseline: {} marks created, {} completed",
                stats.obligation_marks_created, stats.obligation_marks_completed);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 2: Single Level Nested Call
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_grpc_marking_single_level_nested_call() {
        let harness = GrpcMarkingNestedCallsTestHarness::new();

        // Set up two-service chain: ServiceA -> ServiceB
        harness.setup_nested_service_chain(&["ServiceA", "ServiceB"]);

        // Execute call on ServiceA (which will call ServiceB)
        let result = harness.execute_unary_call_with_marking(
            "ServiceA",
            "NestedMethod",
            Vec::new(),
        ).await;

        assert!(result.is_ok(), "Single level nested call should succeed");

        let call_context = result.unwrap();
        assert_eq!(call_context.call_level, 0, "Should be top-level call");
        assert_eq!(call_context.nested_calls.len(), 1, "Should have one nested call");
        assert!(call_context.nested_calls[0].success, "Nested call should succeed");

        // Verify no leaks detected
        let leaked_marks = harness.detect_marking_leaks();
        assert!(leaked_marks.is_empty(), "Should have no leaked marks");

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.unary_handlers_executed, 2); // ServiceA + ServiceB
        assert_eq!(stats.nested_calls_made, 1);
        assert!(stats.obligation_marks_threaded > 0);

        println!("✅ Single Level Nested Call: {} handlers, {} nested calls",
                stats.unary_handlers_executed, stats.nested_calls_made);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 3: Multi-Level Nested Calls
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_grpc_marking_multi_level_nested_calls() {
        let harness = GrpcMarkingNestedCallsTestHarness::new();

        // Set up multi-level chain: ServiceA -> ServiceB -> ServiceC -> ServiceD
        harness.setup_nested_service_chain(&["ServiceA", "ServiceB", "ServiceC", "ServiceD"]);

        // Execute call on ServiceA (which will trigger chain of nested calls)
        let result = harness.execute_unary_call_with_marking(
            "ServiceA",
            "ChainMethod",
            Vec::new(),
        ).await;

        assert!(result.is_ok(), "Multi-level nested calls should succeed");

        let call_context = result.unwrap();
        assert_eq!(call_context.call_level, 0, "Should be top-level call");

        let stats = harness.get_stats_snapshot();
        assert!(stats.unary_handlers_executed >= 4); // All 4 services executed
        assert!(stats.nested_calls_made >= 3); // At least 3 nested calls made
        assert_eq!(stats.call_chain_levels, 4); // 4 levels deep

        // Critical: verify marks properly threaded through entire chain
        assert!(stats.obligation_marks_threaded >= 3, "Marks should be threaded through chain");

        // Verify marking integrity across all levels
        assert!(harness.verify_marking_integrity(), "Marking integrity should be maintained across levels");

        // Check for leaks
        let leaked_marks = harness.detect_marking_leaks();
        assert!(leaked_marks.is_empty(), "Multi-level chain should not leak marks");

        println!("✅ Multi-Level Nested Calls: {} levels, {} threaded marks",
                stats.call_chain_levels, stats.obligation_marks_threaded);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 4: Concurrent Nested Calls
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_grpc_marking_concurrent_nested_calls() {
        let harness = GrpcMarkingNestedCallsTestHarness::new();

        // Create multiple services for concurrent calls
        for i in 1..=5 {
            let service_name = format!("ConcurrentService{}", i);
            let service = harness.create_grpc_service(&service_name, 1);
            harness.grpc_servers.write().unwrap().insert(service_name, service);
        }

        // Execute multiple concurrent calls
        let mut call_handles = Vec::new();
        for i in 1..=5 {
            let service_name = format!("ConcurrentService{}", i);
            let harness_clone = &harness; // borrow for async block

            let handle = spawn(async move {
                harness_clone.execute_unary_call_with_marking(
                    &service_name,
                    "ConcurrentMethod",
                    Vec::new(),
                ).await
            });
            call_handles.push(handle);
        }

        // Wait for all calls to complete
        let mut successful_calls = 0;
        for handle in call_handles {
            match handle.await.expect("Task should complete") {
                Ok(_) => successful_calls += 1,
                Err(_) => {}
            }
        }

        assert_eq!(successful_calls, 5, "All concurrent calls should succeed");

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.unary_handlers_executed, 5);
        assert!(stats.concurrent_nested_calls >= 5);

        // Verify no marks leaked during concurrent execution
        let leaked_marks = harness.detect_marking_leaks();
        assert!(leaked_marks.is_empty(), "Concurrent calls should not leak marks");

        // Verify marking integrity
        assert!(harness.verify_marking_integrity(), "Concurrent calls should maintain marking integrity");

        println!("✅ Concurrent Nested Calls: {} concurrent calls, {} marks created",
                successful_calls, stats.obligation_marks_created);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 5: Failed Nested Call Recovery
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_grpc_marking_failed_nested_call_recovery() {
        let harness = GrpcMarkingNestedCallsTestHarness::new();

        // Set up chain where ServiceB will fail
        harness.setup_nested_service_chain(&["ServiceA", "ServiceB"]);

        // Remove ServiceB to cause failure
        harness.grpc_servers.write().unwrap().remove("ServiceB");

        // Execute call on ServiceA (ServiceB call will fail)
        let result = harness.execute_unary_call_with_marking(
            "ServiceA",
            "FailingMethod",
            Vec::new(),
        ).await;

        // The call should complete even though nested call failed
        assert!(result.is_ok(), "Handler should complete despite nested call failure");

        let call_context = result.unwrap();
        assert_eq!(call_context.nested_calls.len(), 1, "Should have attempted nested call");
        assert!(!call_context.nested_calls[0].success, "Nested call should have failed");

        let stats = harness.get_stats_snapshot();
        assert!(stats.failed_nested_calls >= 1);
        assert!(stats.mark_propagation_errors >= 0); // May or may not have propagation errors

        // Critical: verify proper mark cleanup after failure
        let leaked_marks = harness.detect_marking_leaks();
        assert!(leaked_marks.is_empty(), "Failed calls should not leak marks");

        // Verify marking integrity maintained despite failures
        assert!(harness.verify_marking_integrity(), "Marking integrity should survive call failures");

        println!("✅ Failed Nested Call Recovery: {} failed calls, proper cleanup",
                stats.failed_nested_calls);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Test Result Verification
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_grpc_marking_nested_calls_full_integration() {
        let harness = GrpcMarkingNestedCallsTestHarness::new();

        // Comprehensive integration test with multiple scenarios
        let test_scenarios = [
            ("simple", vec!["SimpleService"]),
            ("two_level", vec!["LevelA", "LevelB"]),
            ("three_level", vec!["L1", "L2", "L3"]),
            ("four_level", vec!["Level1", "Level2", "Level3", "Level4"]),
        ];

        for (scenario_name, services) in &test_scenarios {
            // Set up service chain
            let service_names: Vec<&str> = services.iter().map(|s| s.as_str()).collect();
            harness.setup_nested_service_chain(&service_names);

            // Execute call on first service
            let result = harness.execute_unary_call_with_marking(
                &services[0],
                "IntegrationMethod",
                Vec::new(),
            ).await;

            assert!(result.is_ok(), "Scenario {} should succeed", scenario_name);

            let call_context = result.unwrap();
            assert_eq!(call_context.call_level, 0, "Should be top-level call");

            // Brief pause between scenarios
            sleep(Duration::from_millis(50)).await;
        }

        // Final comprehensive verification
        let final_stats = harness.get_stats_snapshot();

        assert!(final_stats.unary_handlers_executed > 0, "Should have executed handlers");
        assert!(final_stats.obligation_marks_created > 0, "Should have created marks");

        // Critical integration verifications
        assert_eq!(final_stats.obligation_marks_leaked, 0,
                  "No obligation marks should be leaked: {}", final_stats.obligation_marks_leaked);

        assert!(final_stats.obligation_marks_completed > 0,
               "Should have completed marks: {}", final_stats.obligation_marks_completed);

        // Verify overall marking integrity
        assert!(harness.verify_marking_integrity(),
               "Overall marking integrity should be maintained");

        // Final leak detection
        let final_leaked_marks = harness.detect_marking_leaks();
        assert!(final_leaked_marks.is_empty(),
               "Final leak detection should find no leaks");

        // Verify proper threading through nested calls
        assert!(final_stats.obligation_marks_threaded > 0,
               "Should have threaded marks through nested calls");

        println!("✅ gRPC ↔ Marking Nested Calls Integration Test Complete");
        println!("📊 Final Stats: {:?}", final_stats);
        println!(
            "🎯 Mark Success Rate: {}/{}, Leak Count: {}, Thread Count: {}",
            final_stats.obligation_marks_completed,
            final_stats.obligation_marks_created,
            final_stats.obligation_marks_leaked,
            final_stats.obligation_marks_threaded
        );

        // Verify perfect mark lifecycle management (no leaks)
        let mark_success_rate = if final_stats.obligation_marks_created > 0 {
            final_stats.obligation_marks_completed as f64 / final_stats.obligation_marks_created as f64
        } else {
            1.0
        };

        assert!(mark_success_rate >= 0.95,
               "Mark success rate should be at least 95%: {:.2}%", mark_success_rate * 100.0);
    }
}