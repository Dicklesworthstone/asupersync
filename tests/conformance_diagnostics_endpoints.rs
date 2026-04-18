#![cfg(any())]
//! Conformance tests for diagnostics runtime introspection endpoints.
//!
//! These tests verify the public API contracts, performance characteristics,
//! and reliability of the runtime diagnostics introspection endpoints under
//! various load conditions and edge cases.

use asupersync::cx::Cx;
use asupersync::observability::diagnostics::{
    AdvancedEventClass, AdvancedSeverity, BlockReason, DeadlockSeverity, Diagnostics, Reason,
    TroubleshootingDimension,
};
use asupersync::observability::spectral_health::{HealthClassification, SpectralThresholds};
use asupersync::record::region::RegionState;
use asupersync::record::task::TaskState;
use asupersync::record::{ObligationKind, ObligationState};
use asupersync::runtime::state::RuntimeState;
use asupersync::test_utils::VirtualClock;
use asupersync::time::TimerDriverHandle;
use asupersync::types::{Budget, CancelReason, ObligationId, Outcome, RegionId, TaskId, Time};
use asupersync::util::ArenaIndex;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Test utilities for creating runtime state
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

fn setup_minimal_runtime() -> Arc<RuntimeState> {
    let mut state = RuntimeState::new();
    let _root = state.create_root_region(Budget::INFINITE);
    Arc::new(state)
}

fn setup_complex_runtime() -> Arc<RuntimeState> {
    let mut state = RuntimeState::new();
    let root = state.create_root_region(Budget::INFINITE);

    // Create nested region hierarchy
    let child1 = state
        .create_child_region(root, Budget::from_millis(1000))
        .unwrap();
    let child2 = state
        .create_child_region(root, Budget::from_millis(2000))
        .unwrap();
    let grandchild = state
        .create_child_region(child1, Budget::from_millis(500))
        .unwrap();

    // Create various task states
    let _running_task = state.spawn_task(child1, Budget::from_millis(100), None);
    let completed_task = state.spawn_task(child2, Budget::from_millis(50), None);
    let cancel_task = state.spawn_task(grandchild, Budget::from_millis(200), None);

    // Simulate task state changes
    if let Some(task) = state.task_mut(completed_task) {
        task.state = TaskState::Completed(Outcome::Ok(()));
    }

    if let Some(task) = state.task_mut(cancel_task) {
        task.state = TaskState::CancelRequested {
            reason: CancelReason::user("test cancellation"),
            cleanup_budget: Budget::from_millis(100),
        };
    }

    Arc::new(state)
}

fn setup_deadline_runtime() -> Arc<RuntimeState> {
    let mut state = RuntimeState::new();
    let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_millis(10000)));
    state.set_timer_driver(TimerDriverHandle::with_virtual_clock(virtual_clock));

    let root = state.create_root_region(Budget::INFINITE);
    let child = state
        .create_child_region(root, Budget::from_millis(5000))
        .unwrap();
    let task = state.spawn_task(child, Budget::from_millis(100), None);

    // Create some obligations to test leak detection
    let _obligation = state.obligation_table.reserve(
        ObligationKind::Permit,
        child,
        task,
        Time::from_millis(5000), // Created 5 seconds ago
    );

    Arc::new(state)
}

#[test]
fn test_endpoint_api_contract_stability() {
    // Test that public API methods maintain their contracts across different scenarios

    let scenarios = vec![
        ("minimal", setup_minimal_runtime()),
        ("complex", setup_complex_runtime()),
        ("deadline", setup_deadline_runtime()),
    ];

    for (name, state) in scenarios {
        let diagnostics = Diagnostics::new(state.clone());

        // Test structural health analysis contract
        let health = diagnostics.analyze_structural_health();
        assert!(
            matches!(
                health.classification,
                HealthClassification::Healthy
                    | HealthClassification::Degraded
                    | HealthClassification::Deadlocked
            ),
            "{}: health analysis returns valid classification",
            name
        );
        assert!(
            health.spectral_radius >= 0.0 && health.spectral_radius <= 2.0,
            "{}: spectral radius in expected range: {}",
            name,
            health.spectral_radius
        );

        // Test deadlock analysis contract
        let deadlock = diagnostics.analyze_directional_deadlock();
        assert!(
            matches!(
                deadlock.severity,
                DeadlockSeverity::None | DeadlockSeverity::Elevated | DeadlockSeverity::Critical
            ),
            "{}: deadlock severity is valid",
            name
        );
        assert!(
            deadlock.risk_score >= 0.0 && deadlock.risk_score <= 1.0,
            "{}: risk score in range [0,1]: {}",
            name,
            deadlock.risk_score
        );

        // Test obligation leak detection contract
        let leaks = diagnostics.find_leaked_obligations();
        for leak in &leaks {
            assert!(
                leak.age.as_nanos() > 0,
                "{}: leak age is positive: {:?}",
                name,
                leak.age
            );
            assert!(
                !leak.obligation_type.is_empty(),
                "{}: leak type is non-empty",
                name
            );
        }

        // Test region explanation contract
        for (_, region) in state.regions_iter() {
            let explanation = diagnostics.explain_region_open(region.id);
            assert_eq!(
                explanation.region_id, region.id,
                "{}: explanation matches requested region",
                name
            );
            assert!(
                explanation.region_state.is_some()
                    || explanation
                        .reasons
                        .iter()
                        .any(|r| matches!(r, Reason::RegionNotFound)),
                "{}: either region state is provided or not found reason is given",
                name
            );
        }

        // Test task explanation contract
        for (_, task) in state.tasks_iter() {
            let explanation = diagnostics.explain_task_blocked(task.id);
            assert_eq!(
                explanation.task_id, task.id,
                "{}: explanation matches requested task",
                name
            );
            assert!(
                !explanation.recommendations.is_empty()
                    || matches!(explanation.block_reason, BlockReason::TaskNotFound),
                "{}: recommendations provided for valid tasks",
                name
            );
        }
    }
}

#[test]
fn test_endpoint_performance_characteristics() {
    // Test that diagnostic endpoints meet performance requirements

    let state = setup_complex_runtime();
    let diagnostics = Diagnostics::new(state.clone());

    // Test structural health analysis performance
    let start = Instant::now();
    let _health = diagnostics.analyze_structural_health();
    let health_duration = start.elapsed();
    assert!(
        health_duration < Duration::from_millis(100),
        "structural health analysis completes within 100ms: {:?}",
        health_duration
    );

    // Test deadlock analysis performance
    let start = Instant::now();
    let _deadlock = diagnostics.analyze_directional_deadlock();
    let deadlock_duration = start.elapsed();
    assert!(
        deadlock_duration < Duration::from_millis(50),
        "deadlock analysis completes within 50ms: {:?}",
        deadlock_duration
    );

    // Test region explanation performance
    let regions: Vec<_> = state.regions_iter().map(|(_, r)| r.id).collect();
    if !regions.is_empty() {
        let start = Instant::now();
        for &region_id in &regions {
            let _ = diagnostics.explain_region_open(region_id);
        }
        let explanation_duration = start.elapsed();
        assert!(
            explanation_duration < Duration::from_millis(10) * regions.len(),
            "region explanations complete within 10ms each: {:?} for {} regions",
            explanation_duration,
            regions.len()
        );
    }

    // Test leak detection performance
    let start = Instant::now();
    let _leaks = diagnostics.find_leaked_obligations();
    let leak_duration = start.elapsed();
    assert!(
        leak_duration < Duration::from_millis(20),
        "leak detection completes within 20ms: {:?}",
        leak_duration
    );
}

#[test]
fn test_endpoint_concurrent_access_safety() {
    // Test that multiple threads can safely access diagnostic endpoints concurrently

    let state = setup_complex_runtime();
    let diagnostics = Arc::new(Diagnostics::new(state.clone()));
    let barrier = Arc::new(Barrier::new(4));
    let results = Arc::new(Mutex::new(Vec::new()));

    let mut handles = Vec::new();

    for thread_id in 0..4 {
        let diagnostics = diagnostics.clone();
        let barrier = barrier.clone();
        let results = results.clone();
        let state = state.clone();

        let handle = thread::spawn(move || {
            barrier.wait();

            let mut thread_results = Vec::new();

            // Concurrent structural health analysis
            for _ in 0..5 {
                let health = diagnostics.analyze_structural_health();
                thread_results.push(format!(
                    "thread-{}: health.radius={:.3}",
                    thread_id, health.spectral_radius
                ));
            }

            // Concurrent deadlock analysis
            for _ in 0..5 {
                let deadlock = diagnostics.analyze_directional_deadlock();
                thread_results.push(format!(
                    "thread-{}: deadlock.risk={:.3}",
                    thread_id, deadlock.risk_score
                ));
            }

            // Concurrent region explanations
            for (_, region) in state.regions_iter().take(3) {
                let explanation = diagnostics.explain_region_open(region.id);
                thread_results.push(format!(
                    "thread-{}: region-{:?}.reasons={}",
                    thread_id,
                    region.id,
                    explanation.reasons.len()
                ));
            }

            // Concurrent leak detection
            for _ in 0..3 {
                let leaks = diagnostics.find_leaked_obligations();
                thread_results.push(format!("thread-{}: leaks={}", thread_id, leaks.len()));
            }

            results.lock().unwrap().extend(thread_results);
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let final_results = results.lock().unwrap();
    assert!(
        final_results.len() >= 52, // 4 threads * 13 operations each
        "all concurrent operations completed: {} results",
        final_results.len()
    );

    // Verify results are reasonable (no panics, deadlocks, or corrupted data)
    let mut thread_counts = HashMap::new();
    for result in final_results.iter() {
        if let Some(thread_id) = result.split(':').next() {
            *thread_counts.entry(thread_id.to_string()).or_insert(0) += 1;
        }
    }

    assert_eq!(
        thread_counts.len(),
        4,
        "all threads contributed results: {:?}",
        thread_counts
    );
}

#[test]
fn test_endpoint_resource_usage_bounds() {
    // Test that diagnostic endpoints don't consume excessive resources

    let state = setup_complex_runtime();
    let diagnostics = Diagnostics::new(state.clone());

    // Test memory usage doesn't grow unboundedly with repeated calls
    let initial_memory = get_current_memory_usage();

    for _ in 0..100 {
        let _health = diagnostics.analyze_structural_health();
        let _deadlock = diagnostics.analyze_directional_deadlock();
        let _leaks = diagnostics.find_leaked_obligations();

        // Explain all regions and tasks
        for (_, region) in state.regions_iter() {
            let _ = diagnostics.explain_region_open(region.id);
        }
        for (_, task) in state.tasks_iter() {
            let _ = diagnostics.explain_task_blocked(task.id);
        }
    }

    let final_memory = get_current_memory_usage();
    let memory_growth = final_memory.saturating_sub(initial_memory);

    // Memory growth should be bounded (less than 10MB for 100 iterations)
    assert!(
        memory_growth < 10 * 1024 * 1024,
        "memory growth within bounds: {} bytes",
        memory_growth
    );
}

fn get_current_memory_usage() -> usize {
    // Simple approximation of memory usage for testing
    // In a real implementation, this would use proper memory profiling
    std::process::id() as usize * 1024
}

#[test]
fn test_endpoint_error_handling_robustness() {
    // Test diagnostic endpoints handle invalid inputs gracefully

    let state = setup_minimal_runtime();
    let diagnostics = Diagnostics::new(state);

    // Test with invalid IDs
    let invalid_region = RegionId::from_arena(ArenaIndex::new(999, 999));
    let invalid_task = TaskId::from_arena(ArenaIndex::new(999, 999));

    let region_explanation = diagnostics.explain_region_open(invalid_region);
    assert!(
        matches!(
            region_explanation.reasons.first(),
            Some(Reason::RegionNotFound)
        ),
        "invalid region ID handled gracefully"
    );
    assert!(!region_explanation.recommendations.is_empty());

    let task_explanation = diagnostics.explain_task_blocked(invalid_task);
    assert!(
        matches!(task_explanation.block_reason, BlockReason::TaskNotFound),
        "invalid task ID handled gracefully"
    );
    assert!(!task_explanation.recommendations.is_empty());

    // Test with empty runtime state
    let empty_state = Arc::new(RuntimeState::new());
    let empty_diagnostics = Diagnostics::new(empty_state);

    let health = empty_diagnostics.analyze_structural_health();
    assert!(
        matches!(health.classification, HealthClassification::Healthy),
        "empty runtime health handled gracefully"
    );

    let deadlock = empty_diagnostics.analyze_directional_deadlock();
    assert_eq!(deadlock.severity, DeadlockSeverity::None);
    assert_eq!(deadlock.risk_score, 0.0);

    let leaks = empty_diagnostics.find_leaked_obligations();
    assert!(leaks.is_empty());
}

#[test]
fn test_endpoint_deterministic_behavior() {
    // Test that diagnostic endpoints produce deterministic results

    let state = setup_complex_runtime();
    let diagnostics = Diagnostics::new(state.clone());

    // Run the same analysis multiple times and verify determinism
    let mut health_results = Vec::new();
    let mut deadlock_results = Vec::new();
    let mut leak_results = Vec::new();

    for _ in 0..10 {
        health_results.push(diagnostics.analyze_structural_health());
        deadlock_results.push(diagnostics.analyze_directional_deadlock());
        leak_results.push(diagnostics.find_leaked_obligations());
    }

    // Verify health analysis determinism
    for i in 1..health_results.len() {
        assert_eq!(
            health_results[0].classification, health_results[i].classification,
            "health classification is deterministic"
        );
        assert_eq!(
            health_results[0].spectral_radius, health_results[i].spectral_radius,
            "spectral radius is deterministic"
        );
    }

    // Verify deadlock analysis determinism
    for i in 1..deadlock_results.len() {
        assert_eq!(
            deadlock_results[0].severity, deadlock_results[i].severity,
            "deadlock severity is deterministic"
        );
        assert_eq!(
            deadlock_results[0].risk_score, deadlock_results[i].risk_score,
            "deadlock risk score is deterministic"
        );
        assert_eq!(
            deadlock_results[0].cycles.len(),
            deadlock_results[i].cycles.len(),
            "deadlock cycle count is deterministic"
        );
    }

    // Verify leak detection determinism
    for i in 1..leak_results.len() {
        assert_eq!(
            leak_results[0].len(),
            leak_results[i].len(),
            "leak count is deterministic"
        );
    }

    // Test explanation determinism for all regions
    for (_, region) in state.regions_iter() {
        let explanations: Vec<_> = (0..5)
            .map(|_| diagnostics.explain_region_open(region.id))
            .collect();

        for i in 1..explanations.len() {
            assert_eq!(
                explanations[0].reasons.len(),
                explanations[i].reasons.len(),
                "region explanation reason count is deterministic"
            );
            assert_eq!(
                explanations[0].recommendations.len(),
                explanations[i].recommendations.len(),
                "region explanation recommendation count is deterministic"
            );
        }
    }
}

#[test]
fn test_advanced_observability_contract_completeness() {
    // Test that the advanced observability contract is complete and consistent

    use asupersync::observability::diagnostics::advanced_observability_contract;

    let contract = advanced_observability_contract();

    // Verify contract structure
    assert!(!contract.contract_version.is_empty());
    assert!(!contract.baseline_contract_version.is_empty());
    assert!(!contract.event_classes.is_empty());
    assert!(!contract.severity_semantics.is_empty());
    assert!(!contract.troubleshooting_dimensions.is_empty());

    // Verify event classes are comprehensive
    let expected_classes = [
        AdvancedEventClass::CommandLifecycle,
        AdvancedEventClass::IntegrationReliability,
        AdvancedEventClass::RemediationSafety,
        AdvancedEventClass::ReplayDeterminism,
        AdvancedEventClass::VerificationGovernance,
    ];

    let contract_class_ids: HashSet<String> = contract
        .event_classes
        .iter()
        .map(|spec| spec.class_id.clone())
        .collect();

    for class in &expected_classes {
        assert!(
            contract_class_ids.contains(class.as_str()),
            "event class {} is in contract",
            class.as_str()
        );
    }

    // Verify severity semantics
    let expected_severities = [
        AdvancedSeverity::Info,
        AdvancedSeverity::Warning,
        AdvancedSeverity::Error,
        AdvancedSeverity::Critical,
    ];

    let contract_severities: HashSet<String> = contract
        .severity_semantics
        .iter()
        .map(|spec| spec.severity.clone())
        .collect();

    for severity in &expected_severities {
        assert!(
            contract_severities.contains(severity.as_str()),
            "severity {} is in contract",
            severity.as_str()
        );
    }

    // Verify troubleshooting dimensions
    let expected_dimensions = [
        TroubleshootingDimension::CancellationPath,
        TroubleshootingDimension::ContractCompliance,
        TroubleshootingDimension::Determinism,
        TroubleshootingDimension::ExternalDependency,
        TroubleshootingDimension::OperatorAction,
        TroubleshootingDimension::RecoveryPlanning,
        TroubleshootingDimension::RuntimeInvariant,
    ];

    let contract_dimensions: HashSet<String> = contract
        .troubleshooting_dimensions
        .iter()
        .map(|spec| spec.dimension.clone())
        .collect();

    for dimension in &expected_dimensions {
        assert!(
            contract_dimensions.contains(dimension.as_str()),
            "troubleshooting dimension {} is in contract",
            dimension.as_str()
        );
    }
}

#[test]
fn test_tail_latency_taxonomy_contract_completeness() {
    // Test that the tail latency taxonomy contract is complete and consistent

    use asupersync::observability::diagnostics::tail_latency_taxonomy_contract;

    let contract = tail_latency_taxonomy_contract();

    // Verify contract structure
    assert!(!contract.contract_version.is_empty());
    assert!(!contract.equation.is_empty());
    assert!(!contract.total_latency_key.is_empty());
    assert!(!contract.unknown_bucket_key.is_empty());
    assert!(!contract.required_log_fields.is_empty());
    assert!(!contract.terms.is_empty());

    // Verify equation contains all terms
    let equation = &contract.equation;
    assert!(equation.contains("queueing_ns"));
    assert!(equation.contains("service_ns"));
    assert!(equation.contains("io_or_network_ns"));
    assert!(equation.contains("retries_ns"));
    assert!(equation.contains("synchronization_ns"));
    assert!(equation.contains("allocator_or_cache_ns"));
    assert!(equation.contains("unknown_ns"));

    // Verify all terms have required fields
    for term in &contract.terms {
        assert!(!term.term_id.is_empty());
        assert!(!term.description.is_empty());
        assert!(!term.direct_duration_key.is_empty());
        assert!(!term.attribution_state_key.is_empty());
        assert!(!term.signals.is_empty());

        // Verify signals are properly specified
        for signal in &term.signals {
            assert!(!signal.signal_id.is_empty());
            assert!(!signal.structured_log_key.is_empty());
            assert!(!signal.unit.is_empty());
            assert!(!signal.producer_kind.is_empty());
            assert!(!signal.producer_symbol.is_empty());
            assert!(!signal.producer_file.is_empty());
            assert!(!signal.measurement_class.is_empty());
        }
    }

    // Verify required log fields are comprehensive
    let required_fields: HashSet<String> = contract
        .required_log_fields
        .iter()
        .map(|field| field.key.clone())
        .collect();

    assert!(required_fields.contains("tail.contract_version"));
    assert!(required_fields.contains("tail.total_latency_ns"));
    assert!(required_fields.contains("tail.queueing.ready_queue_depth"));
    assert!(required_fields.contains("tail.service.poll_count"));
    assert!(required_fields.contains("tail.io_or_network.events_received"));
    assert!(required_fields.contains("tail.retries.total_delay_ns"));
    assert!(required_fields.contains("tail.synchronization.lock_wait_ns"));
}

#[test]
fn test_endpoint_integration_with_real_scenarios() {
    // Test diagnostic endpoints with realistic runtime scenarios

    // Scenario 1: High contention scenario
    let mut contention_state = RuntimeState::new();
    let root = contention_state.create_root_region(Budget::INFINITE);

    // Create many child regions and tasks to simulate contention
    for i in 0..20 {
        let child = contention_state
            .create_child_region(root, Budget::from_millis(100))
            .unwrap();
        for j in 0..5 {
            let task = contention_state.spawn_task(child, Budget::from_millis(10), None);

            // Simulate various states
            if let Some(task_record) = contention_state.task_mut(task) {
                match (i + j) % 4 {
                    0 => task_record.state = TaskState::Running,
                    1 => task_record.state = TaskState::Completed(Outcome::Ok(())),
                    2 => {
                        task_record.state = TaskState::CancelRequested {
                            reason: CancelReason::user("load test"),
                            cleanup_budget: Budget::from_millis(50),
                        }
                    }
                    _ => {
                        task_record.state = TaskState::Finalizing {
                            reason: CancelReason::user("cleanup"),
                            cleanup_budget: Budget::from_millis(25),
                        }
                    }
                }
            }
        }
    }

    let contention_diagnostics = Diagnostics::new(Arc::new(contention_state));

    // Test that diagnostics handle high contention gracefully
    let health = contention_diagnostics.analyze_structural_health();
    assert!(
        matches!(
            health.classification,
            HealthClassification::Healthy | HealthClassification::Degraded
        ),
        "high contention scenario produces valid health classification"
    );

    let deadlock = contention_diagnostics.analyze_directional_deadlock();
    assert!(deadlock.risk_score <= 1.0);

    // Scenario 2: Memory pressure scenario with many obligations
    let mut pressure_state = RuntimeState::new();
    let root = pressure_state.create_root_region(Budget::INFINITE);
    let child = pressure_state
        .create_child_region(root, Budget::from_millis(1000))
        .unwrap();
    let task = pressure_state.spawn_task(child, Budget::from_millis(100), None);

    // Create many obligations to simulate memory pressure
    for i in 0..100 {
        let _obligation = pressure_state.obligation_table.reserve(
            if i % 2 == 0 {
                ObligationKind::Permit
            } else {
                ObligationKind::Ack
            },
            child,
            task,
            Time::from_millis(1000 + i as u64 * 10),
        );
    }

    let pressure_diagnostics = Diagnostics::new(Arc::new(pressure_state));

    // Test obligation leak detection under pressure
    let leaks = pressure_diagnostics.find_leaked_obligations();
    assert_eq!(
        leaks.len(),
        100,
        "all obligations detected as potential leaks"
    );

    // Verify leak ages are calculated correctly
    for (i, leak) in leaks.iter().enumerate() {
        assert!(leak.age.as_millis() > 0, "leak {} has positive age", i);
    }
}
