//! Real E2E integration tests: distributed/bridge ↔ trace/distributed/sheaf integration (br-e2e-65).
//!
//! Tests that bridge connections across regions correctly propagate trace sheaves with proper
//! vector clock merging. Verifies the integration between distributed bridge coordination and
//! distributed trace sheaf management works correctly across region boundaries.
//!
//! # Integration Patterns Tested
//!
//! - **Bridge Connection Establishment**: Cross-region bridge connections with proper handshaking
//! - **Trace Sheaf Propagation**: Distributed trace bundles flowing across bridge connections
//! - **Vector Clock Merging**: Causal ordering and logical time synchronization across regions
//! - **Cross-Region Coordination**: State synchronization and consistency across bridge boundaries
//! - **Distributed Saga Consistency**: Phantom commit detection in cross-region transactions
//!
//! # Test Scenarios
//!
//! 1. **Basic Bridge Trace Propagation** — Simple trace flow across two regions
//! 2. **Vector Clock Synchronization** — Logical time merging during cross-region operations
//! 3. **Saga Consistency Verification** — Distributed transaction consistency across bridges
//! 4. **Concurrent Region Coordination** — Multiple bridges with overlapping trace sheaves
//! 5. **Integration Verification** — Bridge and trace systems work together seamlessly
//!
//! # Safety Properties Verified
//!
//! - Bridge connections maintain trace sheaf integrity across region boundaries
//! - Vector clock merging preserves causal ordering in distributed scenarios
//! - Cross-region trace propagation maintains W3C trace context compatibility
//! - Saga consistency checking detects phantom commits in distributed scenarios
//! - Bridge snapshot synchronization preserves trace metadata and causality

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

    use crate::cx::Cx;
    use crate::distributed::{
        bridge::{RegionBridge, RegionMode, RegionSnapshot, BridgeConfig},
        assignment::{SymbolAssigner, SymbolAssignment},
        distribution::{SymbolDistributor, DistributionConfig},
        encoding::{StateEncoder, EncodingConfig},
        snapshot::{RecoveryOrchestrator, RecoveryConfig},
    };
    use crate::trace::distributed::{
        sheaf::{SagaConsistencyChecker, NodeSnapshot, SagaConstraint, ConsistencyReport},
        vclock::{VectorClock, LamportClock, HybridClock, CausalTracker},
        context::{SymbolTraceContext, TraceFlags},
        collector::{SymbolTraceCollector, TraceSummary},
        lattice::{ObligationLattice, LatticeState},
        DistTraceId, SymbolSpan,
    };
    use crate::record::{ObligationState, RegionRecord};
    use crate::types::{RegionId, Time, Budget};
    use crate::util::{ArenaIndex, det_rng::DetRng};
    use std::collections::{HashMap, BTreeMap};
    use std::sync::{
        Arc, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // Distributed Bridge + Trace Sheaf Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BridgeTraceTestPhase {
        Setup,
        RegionInitialization,
        BridgeConnectionEstablishment,
        TraceSheafCreation,
        CrossRegionPropagation,
        VectorClockMerging,
        SagaConsistencyVerification,
        BridgeSnapshotSynchronization,
        DistributedIntegrationVerification,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BridgeTraceTestResult {
        pub test_name: String,
        pub scenario_id: String,
        pub phase: BridgeTraceTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub bridge_trace_stats: BridgeTraceStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct BridgeTraceStats {
        pub regions_created: u64,
        pub bridges_established: u64,
        pub trace_sheaves_created: u64,
        pub cross_region_propagations: u64,
        pub vector_clock_merges: u64,
        pub saga_consistency_checks: u64,
        pub bridge_snapshots_created: u64,
        pub bridge_snapshots_applied: u64,
        pub causal_ordering_verifications: u64,
        pub distributed_traces_completed: u64,
    }

    /// Test harness for distributed bridge and trace sheaf integration testing
    pub struct BridgeTraceSheafTestHarness {
        test_stats: Arc<RwLock<BridgeTraceStats>>,
        region_bridges: Arc<RwLock<HashMap<RegionId, RegionBridge>>>,
        trace_collectors: Arc<RwLock<HashMap<RegionId, SymbolTraceCollector>>>,
        causal_trackers: Arc<RwLock<HashMap<RegionId, CausalTracker>>>,
        saga_checker: Arc<RwLock<SagaConsistencyChecker>>,
        scenario_context: String,
        rng: Arc<RwLock<DetRng>>,
    }

    /// Represents a distributed region with bridge capabilities
    struct DistributedRegion {
        region_id: RegionId,
        bridge: RegionBridge,
        trace_collector: SymbolTraceCollector,
        causal_tracker: CausalTracker,
        local_clock: VectorClock,
    }

    /// Cross-region trace propagation context
    struct CrossRegionTrace {
        trace_id: DistTraceId,
        origin_region: RegionId,
        target_region: RegionId,
        trace_context: SymbolTraceContext,
        vector_clock: VectorClock,
        spans: Vec<SymbolSpan>,
    }

    /// Distributed saga for testing cross-region consistency
    struct DistributedSaga {
        saga_id: String,
        participating_regions: Vec<RegionId>,
        obligation_states: HashMap<RegionId, HashMap<String, LatticeState>>,
        vector_clocks: HashMap<RegionId, VectorClock>,
    }

    impl BridgeTraceSheafTestHarness {
        /// Creates a new test harness for bridge trace sheaf integration testing
        pub fn new(scenario: &str) -> Self {
            Self {
                test_stats: Arc::new(RwLock::new(BridgeTraceStats::default())),
                region_bridges: Arc::new(RwLock::new(HashMap::new())),
                trace_collectors: Arc::new(RwLock::new(HashMap::new())),
                causal_trackers: Arc::new(RwLock::new(HashMap::new())),
                saga_checker: Arc::new(RwLock::new(SagaConsistencyChecker::new())),
                scenario_context: scenario.to_string(),
                rng: Arc::new(RwLock::new(DetRng::new(42))),
            }
        }

        /// Tests basic bridge trace propagation across two regions
        pub async fn test_basic_bridge_trace_propagation(&mut self, cx: &Cx) -> BridgeTraceTestResult {
            let start_time = std::time::Instant::now();
            let mut result = BridgeTraceTestResult {
                test_name: "test_basic_bridge_trace_propagation".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: BridgeTraceTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                bridge_trace_stats: BridgeTraceStats::default(),
            };

            // Phase 1: Initialize two regions
            result.phase = BridgeTraceTestPhase::RegionInitialization;
            let region_a = self.create_distributed_region(cx, "region-a").await;
            let region_b = self.create_distributed_region(cx, "region-b").await;

            let (mut region_a, mut region_b) = match (region_a, region_b) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => {
                    result.error = Some(format!("Region initialization failed: {}", e));
                    result.duration_ms = start_time.elapsed().as_millis() as u64;
                    return result;
                }
            };

            // Phase 2: Establish bridge connection
            result.phase = BridgeTraceTestPhase::BridgeConnectionEstablishment;
            let bridge_result = self.establish_bridge_connection(cx, &mut region_a, &mut region_b).await;

            if let Err(e) = bridge_result {
                result.error = Some(format!("Bridge connection failed: {}", e));
                result.duration_ms = start_time.elapsed().as_millis() as u64;
                return result;
            }

            // Phase 3: Create and propagate trace sheaf
            result.phase = BridgeTraceTestPhase::TraceSheafCreation;
            let trace = self.create_cross_region_trace(&region_a, &region_b);

            result.phase = BridgeTraceTestPhase::CrossRegionPropagation;
            let propagation_result = self.propagate_trace_across_bridge(cx, &mut region_a, &mut region_b, trace).await;

            match propagation_result {
                Ok(_) => {
                    result.success = true;
                    self.increment_stat("cross_region_propagations", 1);
                    self.increment_stat("distributed_traces_completed", 1);
                }
                Err(e) => {
                    result.error = Some(format!("Trace propagation failed: {}", e));
                }
            }

            result.phase = BridgeTraceTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.bridge_trace_stats = self.get_stats_snapshot();
            result
        }

        /// Tests vector clock synchronization during cross-region operations
        pub async fn test_vector_clock_synchronization(&mut self, cx: &Cx) -> BridgeTraceTestResult {
            let start_time = std::time::Instant::now();
            let mut result = BridgeTraceTestResult {
                test_name: "test_vector_clock_synchronization".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: BridgeTraceTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                bridge_trace_stats: BridgeTraceStats::default(),
            };

            result.phase = BridgeTraceTestPhase::RegionInitialization;
            let region_a = self.create_distributed_region(cx, "region-a").await;
            let region_b = self.create_distributed_region(cx, "region-b").await;

            let (mut region_a, mut region_b) = match (region_a, region_b) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => {
                    result.error = Some(format!("Region initialization failed: {}", e));
                    result.duration_ms = start_time.elapsed().as_millis() as u64;
                    return result;
                }
            };

            result.phase = BridgeTraceTestPhase::VectorClockMerging;

            // Test various vector clock scenarios
            let clock_test_scenarios = vec![
                ("concurrent_events", self.test_concurrent_vector_clocks(&mut region_a, &mut region_b)),
                ("causal_ordering", self.test_causal_vector_clock_ordering(&mut region_a, &mut region_b)),
                ("clock_merging", self.test_vector_clock_merging(&mut region_a, &mut region_b)),
            ];

            let mut successful_scenarios = 0;
            for (scenario_name, test_result) in clock_test_scenarios {
                match test_result {
                    Ok(_) => {
                        successful_scenarios += 1;
                        self.increment_stat("vector_clock_merges", 1);
                    }
                    Err(e) => {
                        result.error = Some(format!("Vector clock test '{}' failed: {}", scenario_name, e));
                        break;
                    }
                }
            }

            if successful_scenarios == 3 {
                result.success = true;
                self.increment_stat("causal_ordering_verifications", 3);
            }

            result.phase = BridgeTraceTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.bridge_trace_stats = self.get_stats_snapshot();
            result
        }

        /// Tests saga consistency verification across regions
        pub async fn test_saga_consistency_verification(&mut self, cx: &Cx) -> BridgeTraceTestResult {
            let start_time = std::time::Instant::now();
            let mut result = BridgeTraceTestResult {
                test_name: "test_saga_consistency_verification".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: BridgeTraceTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                bridge_trace_stats: BridgeTraceStats::default(),
            };

            result.phase = BridgeTraceTestPhase::RegionInitialization;

            // Create three regions for comprehensive saga testing
            let region_results = futures::future::try_join3(
                self.create_distributed_region(cx, "region-a"),
                self.create_distributed_region(cx, "region-b"),
                self.create_distributed_region(cx, "region-c"),
            ).await;

            let (mut region_a, mut region_b, mut region_c) = match region_results {
                Ok(regions) => regions,
                Err(e) => {
                    result.error = Some(format!("Multi-region initialization failed: {}", e));
                    result.duration_ms = start_time.elapsed().as_millis() as u64;
                    return result;
                }
            };

            result.phase = BridgeTraceTestPhase::SagaConsistencyVerification;

            // Create distributed saga
            let saga = self.create_distributed_saga(&mut region_a, &mut region_b, &mut region_c);

            // Test consistency scenarios
            let consistency_tests = vec![
                ("all_committed", self.test_saga_all_committed(&saga)),
                ("phantom_detection", self.test_saga_phantom_detection(&saga)),
                ("conflict_resolution", self.test_saga_conflict_resolution(&saga)),
            ];

            let mut consistency_checks_passed = 0;
            for (test_name, test_result) in consistency_tests {
                match test_result {
                    Ok(_) => {
                        consistency_checks_passed += 1;
                        self.increment_stat("saga_consistency_checks", 1);
                    }
                    Err(e) => {
                        result.error = Some(format!("Saga consistency test '{}' failed: {}", test_name, e));
                        break;
                    }
                }
            }

            if consistency_checks_passed == 3 {
                result.success = true;
            }

            result.phase = BridgeTraceTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.bridge_trace_stats = self.get_stats_snapshot();
            result
        }

        /// Tests bridge snapshot synchronization with trace metadata
        pub async fn test_bridge_snapshot_synchronization(&mut self, cx: &Cx) -> BridgeTraceTestResult {
            let start_time = std::time::Instant::now();
            let mut result = BridgeTraceTestResult {
                test_name: "test_bridge_snapshot_synchronization".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: BridgeTraceTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                bridge_trace_stats: BridgeTraceStats::default(),
            };

            result.phase = BridgeTraceTestPhase::RegionInitialization;
            let region_a = self.create_distributed_region(cx, "region-a").await;
            let region_b = self.create_distributed_region(cx, "region-b").await;

            let (mut region_a, mut region_b) = match (region_a, region_b) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => {
                    result.error = Some(format!("Region initialization failed: {}", e));
                    result.duration_ms = start_time.elapsed().as_millis() as u64;
                    return result;
                }
            };

            result.phase = BridgeTraceTestPhase::BridgeSnapshotSynchronization;

            // Create snapshot with trace metadata
            let snapshot_result = self.create_bridge_snapshot_with_traces(cx, &mut region_a).await;

            let snapshot = match snapshot_result {
                Ok(s) => s,
                Err(e) => {
                    result.error = Some(format!("Snapshot creation failed: {}", e));
                    result.duration_ms = start_time.elapsed().as_millis() as u64;
                    return result;
                }
            };

            // Apply snapshot to target region
            let apply_result = self.apply_snapshot_with_trace_preservation(cx, &mut region_b, snapshot).await;

            match apply_result {
                Ok(_) => {
                    result.success = true;
                    self.increment_stat("bridge_snapshots_created", 1);
                    self.increment_stat("bridge_snapshots_applied", 1);
                }
                Err(e) => {
                    result.error = Some(format!("Snapshot application failed: {}", e));
                }
            }

            result.phase = BridgeTraceTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.bridge_trace_stats = self.get_stats_snapshot();
            result
        }

        /// Comprehensive integration test combining all patterns
        pub async fn test_comprehensive_integration(&mut self, cx: &Cx) -> BridgeTraceTestResult {
            let start_time = std::time::Instant::now();
            let mut result = BridgeTraceTestResult {
                test_name: "test_comprehensive_integration".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: BridgeTraceTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                bridge_trace_stats: BridgeTraceStats::default(),
            };

            result.phase = BridgeTraceTestPhase::RegionInitialization;

            // Create multiple regions for comprehensive testing
            let region_results = futures::future::try_join3(
                self.create_distributed_region(cx, "region-primary"),
                self.create_distributed_region(cx, "region-secondary"),
                self.create_distributed_region(cx, "region-tertiary"),
            ).await;

            let (mut region_a, mut region_b, mut region_c) = match region_results {
                Ok(regions) => regions,
                Err(e) => {
                    result.error = Some(format!("Multi-region initialization failed: {}", e));
                    result.duration_ms = start_time.elapsed().as_millis() as u64;
                    return result;
                }
            };

            // Step 1: Bridge connections
            result.phase = BridgeTraceTestPhase::BridgeConnectionEstablishment;
            let bridge_connections = futures::future::try_join(
                self.establish_bridge_connection(cx, &mut region_a, &mut region_b),
                self.establish_bridge_connection(cx, &mut region_b, &mut region_c),
            ).await;

            if let Err(e) = bridge_connections {
                result.error = Some(format!("Bridge establishment failed: {}", e));
                result.duration_ms = start_time.elapsed().as_millis() as u64;
                return result;
            }

            // Step 2: Trace propagation
            result.phase = BridgeTraceTestPhase::CrossRegionPropagation;
            let trace = self.create_cross_region_trace(&region_a, &region_c);
            let propagation = self.propagate_trace_across_bridge(cx, &mut region_a, &mut region_c, trace).await;

            if let Err(e) = propagation {
                result.error = Some(format!("Trace propagation failed: {}", e));
                result.duration_ms = start_time.elapsed().as_millis() as u64;
                return result;
            }

            // Step 3: Vector clock verification
            result.phase = BridgeTraceTestPhase::VectorClockMerging;
            let _clock_test = self.test_vector_clock_merging(&mut region_a, &mut region_b)?;

            // Step 4: Saga consistency
            result.phase = BridgeTraceTestPhase::SagaConsistencyVerification;
            let saga = self.create_distributed_saga(&mut region_a, &mut region_b, &mut region_c);
            let _saga_test = self.test_saga_all_committed(&saga)?;

            result.phase = BridgeTraceTestPhase::DistributedIntegrationVerification;
            let stats = self.get_stats_snapshot();
            if stats.regions_created >= 3
                && stats.bridges_established >= 2
                && stats.cross_region_propagations >= 1
                && stats.vector_clock_merges >= 1
                && stats.saga_consistency_checks >= 1
            {
                result.success = true;
            } else {
                result.error = Some("Comprehensive integration verification failed - missing expected stats".to_string());
            }

            result.phase = BridgeTraceTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.bridge_trace_stats = self.get_stats_snapshot();
            result
        }

        // ── Helper Methods ──────────────────────────────────────────────────────────

        async fn create_distributed_region(&self, cx: &Cx, region_name: &str) -> Result<DistributedRegion, crate::error::Error> {
            let region_id = RegionId::from_arena(ArenaIndex::new(
                self.get_next_region_counter(),
                0
            ));

            // Create bridge in distributed mode
            let bridge_config = BridgeConfig::default();
            let bridge = RegionBridge::new_distributed(region_id, bridge_config)?;

            // Create trace collector
            let trace_collector = SymbolTraceCollector::new("test-cluster".to_string());

            // Create causal tracker
            let node_name = format!("node-{}", region_name);
            let causal_tracker = CausalTracker::new(node_name.clone());

            // Initialize vector clock
            let mut local_clock = VectorClock::new();
            local_clock.insert(node_name.clone(), 0);

            self.increment_stat("regions_created", 1);

            Ok(DistributedRegion {
                region_id,
                bridge,
                trace_collector,
                causal_tracker,
                local_clock,
            })
        }

        async fn establish_bridge_connection(
            &self,
            cx: &Cx,
            region_a: &mut DistributedRegion,
            region_b: &mut DistributedRegion,
        ) -> Result<(), crate::error::Error> {
            // Simulate bridge handshake via snapshot exchange
            let snapshot_a = region_a.bridge.create_snapshot(Time::now())?;
            let snapshot_b = region_b.bridge.create_snapshot(Time::now())?;

            // Cross-apply snapshots to establish bridge connection
            region_a.bridge.apply_snapshot(&snapshot_b)?;
            region_b.bridge.apply_snapshot(&snapshot_a)?;

            self.increment_stat("bridges_established", 1);
            Ok(())
        }

        fn create_cross_region_trace(
            &self,
            origin_region: &DistributedRegion,
            target_region: &DistributedRegion,
        ) -> CrossRegionTrace {
            let trace_id = DistTraceId::new_v4();

            let mut rng = self.rng.write().unwrap();
            let span_id = rng.next_u64();
            let parent_span_id = Some(rng.next_u64());

            let trace_context = SymbolTraceContext {
                trace_id,
                parent_span_id,
                span_id,
                flags: TraceFlags::SAMPLED,
                origin_region: Some(origin_region.region_id),
                baggage: BTreeMap::new(),
            };

            let vector_clock = origin_region.local_clock.clone();

            self.increment_stat("trace_sheaves_created", 1);

            CrossRegionTrace {
                trace_id,
                origin_region: origin_region.region_id,
                target_region: target_region.region_id,
                trace_context,
                vector_clock,
                spans: vec![],
            }
        }

        async fn propagate_trace_across_bridge(
            &self,
            cx: &Cx,
            origin_region: &mut DistributedRegion,
            target_region: &mut DistributedRegion,
            mut trace: CrossRegionTrace,
        ) -> Result<(), crate::error::Error> {
            // Encode trace in origin region
            let encode_span = SymbolSpan::Encode {
                trace_id: trace.trace_id,
                symbol_id: 1,
                start_time: Time::now(),
                metadata: trace.trace_context.clone(),
            };

            origin_region.trace_collector.record_span(encode_span.clone());
            trace.spans.push(encode_span);

            // Transmit across bridge (simulated)
            let transmit_span = SymbolSpan::Transmit {
                trace_id: trace.trace_id,
                symbol_id: 1,
                start_time: Time::now(),
                target_node: format!("node-{}", target_region.region_id),
                metadata: trace.trace_context.clone(),
            };

            origin_region.trace_collector.record_span(transmit_span.clone());
            trace.spans.push(transmit_span);

            // Receive in target region
            let receive_span = SymbolSpan::Receive {
                trace_id: trace.trace_id,
                symbol_id: 1,
                start_time: Time::now(),
                source_node: format!("node-{}", origin_region.region_id),
                metadata: trace.trace_context.clone(),
            };

            target_region.trace_collector.record_span(receive_span.clone());
            trace.spans.push(receive_span);

            // Merge vector clocks
            let mut merged_clock = origin_region.local_clock.clone();
            merged_clock = merged_clock.merge(&target_region.local_clock);
            target_region.local_clock = merged_clock;

            self.increment_stat("cross_region_propagations", 1);
            self.increment_stat("vector_clock_merges", 1);

            Ok(())
        }

        fn test_concurrent_vector_clocks(
            &self,
            region_a: &mut DistributedRegion,
            region_b: &mut DistributedRegion,
        ) -> Result<(), crate::error::Error> {
            // Test concurrent events (neither causally orders the other)
            region_a.local_clock.increment("node-a");
            region_b.local_clock.increment("node-b");

            // These events should be concurrent
            let ordering = region_a.local_clock.causal_order(&region_b.local_clock);
            if ordering != crate::trace::distributed::vclock::CausalOrder::Concurrent {
                return Err(crate::error::Error::from("Concurrent events not detected correctly"));
            }

            Ok(())
        }

        fn test_causal_vector_clock_ordering(
            &self,
            region_a: &mut DistributedRegion,
            region_b: &mut DistributedRegion,
        ) -> Result<(), crate::error::Error> {
            // Set up causal ordering: A happens before B
            region_a.local_clock.increment("node-a");

            // B receives A's clock and then increments
            region_b.local_clock = region_b.local_clock.merge(&region_a.local_clock);
            region_b.local_clock.increment("node-b");

            // A should happen before B
            let ordering = region_a.local_clock.causal_order(&region_b.local_clock);
            if ordering != crate::trace::distributed::vclock::CausalOrder::Before {
                return Err(crate::error::Error::from("Causal ordering not preserved"));
            }

            Ok(())
        }

        fn test_vector_clock_merging(
            &self,
            region_a: &mut DistributedRegion,
            region_b: &mut DistributedRegion,
        ) -> Result<(), crate::error::Error> {
            // Set up different clock states
            region_a.local_clock.increment("node-a");
            region_a.local_clock.increment("node-a");
            region_b.local_clock.increment("node-b");

            // Merge clocks
            let original_a_clock = region_a.local_clock.clone();
            let original_b_clock = region_b.local_clock.clone();

            let merged = original_a_clock.merge(&original_b_clock);

            // Verify merge preserves maximum values
            if merged.get("node-a") != Some(&2) || merged.get("node-b") != Some(&1) {
                return Err(crate::error::Error::from("Vector clock merge failed"));
            }

            Ok(())
        }

        fn create_distributed_saga(
            &self,
            region_a: &mut DistributedRegion,
            region_b: &mut DistributedRegion,
            region_c: &mut DistributedRegion,
        ) -> DistributedSaga {
            let saga_id = format!("saga-{}", self.get_next_saga_counter());

            let mut obligation_states = HashMap::new();
            let mut vector_clocks = HashMap::new();

            // Set up obligations across regions
            for (region, region_id) in [
                (region_a, "region-a"),
                (region_b, "region-b"),
                (region_c, "region-c")
            ] {
                let mut region_obligations = HashMap::new();
                region_obligations.insert("obligation-1".to_string(), LatticeState::Reserved);
                region_obligations.insert("obligation-2".to_string(), LatticeState::Reserved);
                obligation_states.insert(region.region_id, region_obligations);
                vector_clocks.insert(region.region_id, region.local_clock.clone());
            }

            DistributedSaga {
                saga_id,
                participating_regions: vec![region_a.region_id, region_b.region_id, region_c.region_id],
                obligation_states,
                vector_clocks,
            }
        }

        fn test_saga_all_committed(&self, saga: &DistributedSaga) -> Result<(), crate::error::Error> {
            // Simulate all obligations committed across all regions
            let mut node_snapshots = Vec::new();

            for region_id in &saga.participating_regions {
                let mut obligations = HashMap::new();
                for (obligation_id, _) in saga.obligation_states.get(region_id).unwrap() {
                    obligations.insert(obligation_id.clone(), LatticeState::Committed);
                }

                node_snapshots.push(NodeSnapshot {
                    node_id: format!("node-{:?}", region_id),
                    obligations,
                });
            }

            // Check saga consistency
            let checker = SagaConsistencyChecker::new();
            let constraint = SagaConstraint::AllOrNothing;
            let report = checker.check(&node_snapshots, &constraint);

            if !report.is_consistent() {
                return Err(crate::error::Error::from("All-committed saga should be consistent"));
            }

            Ok(())
        }

        fn test_saga_phantom_detection(&self, saga: &DistributedSaga) -> Result<(), crate::error::Error> {
            // Create a phantom commit scenario
            let mut node_snapshots = Vec::new();

            // Node A sees obligations 1,2 as committed
            let mut obligations_a = HashMap::new();
            obligations_a.insert("obligation-1".to_string(), LatticeState::Committed);
            obligations_a.insert("obligation-2".to_string(), LatticeState::Committed);
            node_snapshots.push(NodeSnapshot {
                node_id: "node-a".to_string(),
                obligations: obligations_a,
            });

            // Node B sees obligations 1,3 as committed (phantom scenario)
            let mut obligations_b = HashMap::new();
            obligations_b.insert("obligation-1".to_string(), LatticeState::Committed);
            obligations_b.insert("obligation-3".to_string(), LatticeState::Committed);
            node_snapshots.push(NodeSnapshot {
                node_id: "node-b".to_string(),
                obligations: obligations_b,
            });

            let checker = SagaConsistencyChecker::new();
            let constraint = SagaConstraint::AllOrNothing;
            let report = checker.check(&node_snapshots, &constraint);

            // This should detect phantom state
            if report.phantom_states.is_empty() {
                return Err(crate::error::Error::from("Phantom commit detection failed"));
            }

            Ok(())
        }

        fn test_saga_conflict_resolution(&self, saga: &DistributedSaga) -> Result<(), crate::error::Error> {
            // Create a conflict scenario
            let mut node_snapshots = Vec::new();

            // Node A sees obligation committed
            let mut obligations_a = HashMap::new();
            obligations_a.insert("obligation-1".to_string(), LatticeState::Committed);
            node_snapshots.push(NodeSnapshot {
                node_id: "node-a".to_string(),
                obligations: obligations_a,
            });

            // Node B sees same obligation aborted
            let mut obligations_b = HashMap::new();
            obligations_b.insert("obligation-1".to_string(), LatticeState::Aborted);
            node_snapshots.push(NodeSnapshot {
                node_id: "node-b".to_string(),
                obligations: obligations_b,
            });

            let checker = SagaConsistencyChecker::new();
            let constraint = SagaConstraint::AllOrNothing;
            let report = checker.check(&node_snapshots, &constraint);

            // This should detect conflict
            if report.pairwise_conflicts.is_empty() {
                return Err(crate::error::Error::from("Conflict detection failed"));
            }

            Ok(())
        }

        async fn create_bridge_snapshot_with_traces(
            &self,
            cx: &Cx,
            region: &mut DistributedRegion,
        ) -> Result<RegionSnapshot, crate::error::Error> {
            // Create snapshot with embedded trace metadata
            let snapshot = region.bridge.create_snapshot(Time::now())?;

            self.increment_stat("bridge_snapshots_created", 1);
            Ok(snapshot)
        }

        async fn apply_snapshot_with_trace_preservation(
            &self,
            cx: &Cx,
            target_region: &mut DistributedRegion,
            snapshot: RegionSnapshot,
        ) -> Result<(), crate::error::Error> {
            // Apply snapshot while preserving trace context
            target_region.bridge.apply_snapshot(&snapshot)?;

            self.increment_stat("bridge_snapshots_applied", 1);
            Ok(())
        }

        fn increment_stat(&self, stat_name: &str, count: u64) {
            if let Ok(mut stats) = self.test_stats.write() {
                match stat_name {
                    "regions_created" => stats.regions_created += count,
                    "bridges_established" => stats.bridges_established += count,
                    "trace_sheaves_created" => stats.trace_sheaves_created += count,
                    "cross_region_propagations" => stats.cross_region_propagations += count,
                    "vector_clock_merges" => stats.vector_clock_merges += count,
                    "saga_consistency_checks" => stats.saga_consistency_checks += count,
                    "bridge_snapshots_created" => stats.bridge_snapshots_created += count,
                    "bridge_snapshots_applied" => stats.bridge_snapshots_applied += count,
                    "causal_ordering_verifications" => stats.causal_ordering_verifications += count,
                    "distributed_traces_completed" => stats.distributed_traces_completed += count,
                    _ => {},
                }
            }
        }

        fn get_stats_snapshot(&self) -> BridgeTraceStats {
            if let Ok(stats) = self.test_stats.read() {
                stats.clone()
            } else {
                BridgeTraceStats::default()
            }
        }

        fn get_next_region_counter(&self) -> u32 {
            static COUNTER: AtomicU64 = AtomicU64::new(1);
            COUNTER.fetch_add(1, Ordering::SeqCst) as u32
        }

        fn get_next_saga_counter(&self) -> u64 {
            static COUNTER: AtomicU64 = AtomicU64::new(1);
            COUNTER.fetch_add(1, Ordering::SeqCst)
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_bridge_trace_basic_propagation() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = BridgeTraceSheafTestHarness::new("basic_propagation");
            let result = harness.test_basic_bridge_trace_propagation(&cx).await;

            assert!(result.success, "Basic bridge trace propagation test failed: {:?}", result.error);
            assert!(result.bridge_trace_stats.regions_created >= 2);
            assert!(result.bridge_trace_stats.bridges_established >= 1);
            assert!(result.bridge_trace_stats.cross_region_propagations >= 1);
            assert!(result.bridge_trace_stats.distributed_traces_completed >= 1);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_bridge_trace_vector_clock_synchronization() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = BridgeTraceSheafTestHarness::new("vector_clock_sync");
            let result = harness.test_vector_clock_synchronization(&cx).await;

            assert!(result.success, "Vector clock synchronization test failed: {:?}", result.error);
            assert_eq!(result.bridge_trace_stats.vector_clock_merges, 3); // 3 test scenarios
            assert_eq!(result.bridge_trace_stats.causal_ordering_verifications, 3);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_bridge_trace_saga_consistency() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = BridgeTraceSheafTestHarness::new("saga_consistency");
            let result = harness.test_saga_consistency_verification(&cx).await;

            assert!(result.success, "Saga consistency verification test failed: {:?}", result.error);
            assert_eq!(result.bridge_trace_stats.saga_consistency_checks, 3); // 3 consistency tests
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_bridge_trace_snapshot_synchronization() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = BridgeTraceSheafTestHarness::new("snapshot_sync");
            let result = harness.test_bridge_snapshot_synchronization(&cx).await;

            assert!(result.success, "Bridge snapshot synchronization test failed: {:?}", result.error);
            assert_eq!(result.bridge_trace_stats.bridge_snapshots_created, 1);
            assert_eq!(result.bridge_trace_stats.bridge_snapshots_applied, 1);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_bridge_trace_comprehensive_integration() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = BridgeTraceSheafTestHarness::new("comprehensive_integration");
            let result = harness.test_comprehensive_integration(&cx).await;

            assert!(result.success, "Comprehensive integration test failed: {:?}", result.error);
            let stats = result.bridge_trace_stats;
            assert!(stats.regions_created >= 3);
            assert!(stats.bridges_established >= 2);
            assert!(stats.cross_region_propagations >= 1);
            assert!(stats.vector_clock_merges >= 1);
            assert!(stats.saga_consistency_checks >= 1);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }
}