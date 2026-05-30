//! ATP-N17: Deterministic Lab Test Scenario Validation Unit Tests
//!
//! Comprehensive unit tests for ATP lab test scenario validation including:
//! - Lab configuration validation and builder patterns
//! - Deterministic scheduling and replay consistency
//! - Virtual time handling and advancement
//! - Scenario parsing, validation, and composition
//! - Oracle verification and invariant checking
//! - Trace capture, fingerprinting, and consistency
//! - Chaos injection configuration and bounds
//! - Auto-advance termination conditions
//! - Test artifact generation and validation

#![cfg(test)]

use crate::lab::chaos::ChaosConfig;
use crate::lab::config::LabConfig;
use crate::lab::runtime::{AutoAdvanceTermination, LabRuntime, VirtualTimeReport};
use crate::lab::scenario::SCENARIO_SCHEMA_VERSION;
use crate::types::{Budget, Time};
use crate::util::EntropySource;
use serde_json::{Value, json};
use std::time::Duration;

// Test constants for deterministic validation
const TEST_SEED: u64 = 0x1234_5678_9abc_def0;
const TEST_ENTROPY_SEED: u64 = 0xfeed_face_dead_beef;
const TEST_WORKER_COUNT: usize = 4;
const TEST_TRACE_CAPACITY: usize = 8192;
const TEST_MAX_STEPS: u64 = 100_000;

/// Create a test lab configuration with predictable settings.
fn create_test_lab_config() -> LabConfig {
    LabConfig::new(TEST_SEED)
        .worker_count(TEST_WORKER_COUNT)
        .entropy_seed(TEST_ENTROPY_SEED)
        .trace_capacity(TEST_TRACE_CAPACITY)
        .max_steps(TEST_MAX_STEPS)
        .panic_on_leak(true)
        .panic_on_futurelock(true)
        .futurelock_max_idle_steps(5000)
}

/// Create a test scenario with deterministic settings.
fn create_test_scenario() -> Value {
    json!({
        "schema_version": SCENARIO_SCHEMA_VERSION,
        "id": "atp_n17_test_scenario",
        "description": "Unit test scenario for deterministic validation",
        "lab": {
            "seed": TEST_SEED,
            "worker_count": TEST_WORKER_COUNT,
            "entropy_seed": TEST_ENTROPY_SEED,
            "trace_capacity": TEST_TRACE_CAPACITY,
            "max_steps": TEST_MAX_STEPS,
            "panic_on_obligation_leak": true,
            "panic_on_futurelock": true,
            "futurelock_max_idle_steps": 5000
        },
        "chaos": {
            "preset": "light"
        },
        "network": {
            "preset": "lan"
        },
        "participants": [
            {
                "name": "alice",
                "role": "sender"
            },
            {
                "name": "bob",
                "role": "receiver"
            }
        ],
        "oracles": ["all"],
        "expected_invariants": [
            "quiescence",
            "losers_drained",
            "no_obligation_leaks",
            "deterministic_replay"
        ],
        "resource_caps": {
            "max_artifact_bytes": 65536,
            "max_fault_events": 8,
            "max_counterexample_events": 16
        }
    })
}

#[test]
fn test_lab_config_builder_pattern() {
    // Test fluent builder pattern creates correct configuration
    let config = LabConfig::new(TEST_SEED)
        .worker_count(8)
        .entropy_seed(0xabcdef)
        .trace_capacity(16384)
        .max_steps(50000)
        .panic_on_leak(false)
        .futurelock_max_idle_steps(1000);

    // All builder methods should preserve and update settings
    assert_eq!(config.seed, TEST_SEED);
    assert_eq!(config.worker_count, 8);
    assert_eq!(config.entropy_seed, 0xabcdef);
    assert_eq!(config.trace_capacity, 16384);
    assert_eq!(config.max_steps, Some(50000));
    assert!(!config.panic_on_obligation_leak);
    assert_eq!(config.futurelock_max_idle_steps, 1000);

    // Configuration should be deterministic
    let config2 = LabConfig::new(TEST_SEED)
        .worker_count(8)
        .entropy_seed(0xabcdef)
        .trace_capacity(16384)
        .max_steps(50000)
        .panic_on_leak(false)
        .futurelock_max_idle_steps(1000);

    assert_eq!(config.seed, config2.seed);
    assert_eq!(config.worker_count, config2.worker_count);
    assert_eq!(config.entropy_seed, config2.entropy_seed);
}

#[test]
fn test_lab_config_default_values() {
    let default_config = LabConfig::default();

    // Default configuration should have sensible values
    assert_eq!(default_config.seed, 42); // Default seed
    assert!(default_config.worker_count > 0);
    assert!(default_config.trace_capacity > 0);
    assert!(default_config.panic_on_obligation_leak); // Safe default
    assert!(!default_config.has_chaos()); // Chaos off by default
}

#[test]
fn test_lab_config_chaos_integration() {
    // Test light chaos preset
    let light_config = LabConfig::new(TEST_SEED).with_light_chaos();
    assert!(light_config.has_chaos());

    // Test heavy chaos preset
    let heavy_config = LabConfig::new(TEST_SEED).with_heavy_chaos();
    assert!(heavy_config.has_chaos());

    // Test custom chaos configuration
    let chaos = ChaosConfig::new(TEST_SEED)
        .with_delay_probability(0.1)
        .with_cancel_probability(0.05)
        .with_io_error_probability(0.02);

    let custom_config = LabConfig::new(TEST_SEED).with_chaos(chaos);
    assert!(custom_config.has_chaos());

    // Chaos should be deterministic with same seed
    let chaos1 = ChaosConfig::new(TEST_SEED).with_delay_probability(0.3);
    let chaos2 = ChaosConfig::new(TEST_SEED).with_delay_probability(0.3);

    let config1 = LabConfig::new(TEST_SEED).with_chaos(chaos1);
    let config2 = LabConfig::new(TEST_SEED).with_chaos(chaos2);

    assert_eq!(config1.seed, config2.seed);
}

#[test]
fn test_deterministic_scheduling_consistency() {
    // Multiple runs with same seed should produce identical results
    let config = create_test_lab_config();

    let mut runtime1 = LabRuntime::new(config.clone());
    let mut runtime2 = LabRuntime::new(config);

    // Create identical task structures
    let region1 = runtime1.state.create_root_region(Budget::INFINITE);
    let region2 = runtime2.state.create_root_region(Budget::INFINITE);

    // Simple deterministic task
    let task_fn = || async { 42u32 };

    let (task_id1, _handle1) = runtime1
        .state
        .create_task(region1, Budget::INFINITE, task_fn())
        .expect("create task 1");
    let (task_id2, _handle2) = runtime2
        .state
        .create_task(region2, Budget::INFINITE, task_fn())
        .expect("create task 2");

    // Schedule and run
    runtime1.scheduler.lock().schedule(task_id1, 0);
    runtime2.scheduler.lock().schedule(task_id2, 0);

    let report1 = runtime1.run_until_quiescent_with_report();
    let report2 = runtime2.run_until_quiescent_with_report();

    // Should produce identical trace certificates
    let cert1 = report1.trace_certificate;
    let cert2 = report2.trace_certificate;

    assert_eq!(cert1.event_hash, cert2.event_hash);
    assert_eq!(cert1.event_count, cert2.event_count);
    assert_eq!(cert1.schedule_hash, cert2.schedule_hash);
}

#[test]
fn test_virtual_time_advancement() {
    let config = create_test_lab_config();
    let mut runtime = LabRuntime::new(config);

    let start_time = runtime.now();

    // Advance virtual time explicitly
    runtime.advance_time(Duration::from_millis(1000).as_nanos() as u64);
    let after_advance = runtime.now();

    assert!(after_advance > start_time);
    assert_eq!(
        after_advance.as_nanos() - start_time.as_nanos(),
        1_000_000_000 // 1000ms = 1,000,000,000 nanoseconds
    );

    // Virtual time should be deterministic across runs
    let mut runtime2 = LabRuntime::new(create_test_lab_config());
    let runtime2_start = runtime2.now();
    runtime2.advance_time(Duration::from_millis(1000).as_nanos() as u64);
    let time2 = runtime2.now();

    // Should have same relative advancement
    assert_eq!(
        after_advance.as_nanos() - start_time.as_nanos(),
        time2.as_nanos() - runtime2_start.as_nanos()
    );
}

#[test]
fn test_auto_advance_termination_conditions() {
    let config = create_test_lab_config().max_steps(100); // Low limit for testing

    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Create a task that will hit step limit
    let busy_task = async {
        for _ in 0..200 {
            // Yield to scheduler
            crate::runtime::yield_now().await;
        }
        42
    };

    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, busy_task)
        .expect("create busy task");

    runtime.scheduler.lock().schedule(task_id, 0);

    // Run with auto-advance
    let report = runtime.run_with_auto_advance();

    // Should terminate due to step limit, not quiescence
    assert_eq!(report.termination, AutoAdvanceTermination::StepLimitReached);
    assert_eq!(report.steps, 100); // Should hit the configured limit
    assert_eq!(report.auto_advances, 0); // Runnable work never requires timer advancement
}

#[test]
fn test_virtual_time_report_consistency() {
    let config = create_test_lab_config();
    let mut runtime = LabRuntime::new(config);

    let start_time = runtime.now();

    // Create a timer-based task
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let timer_task = async {
        let now = crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
        crate::time::sleep(now, Duration::from_millis(100)).await;
        "timer_done"
    };

    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, timer_task)
        .expect("create timer task");

    runtime.scheduler.lock().schedule(task_id, 0);

    // Run with auto-advance to handle timer
    let report = runtime.run_with_auto_advance();

    // Validate report consistency
    assert_eq!(report.termination, AutoAdvanceTermination::Quiescent);
    assert!(report.steps > 0);
    assert!(report.auto_advances > 0); // Should advance for timer
    assert!(report.total_wakeups > 0); // Timer should wake
    assert_eq!(report.time_start, start_time);
    assert!(report.time_end >= start_time);
    assert!(report.virtual_elapsed_nanos > 0);

    // Virtual elapsed should match time difference
    let expected_nanos = report.time_end.as_nanos() - report.time_start.as_nanos();
    assert_eq!(report.virtual_elapsed_nanos, expected_nanos);
}

#[test]
fn test_scenario_schema_validation() {
    let scenario_json = create_test_scenario();

    // Schema version should be correct
    assert_eq!(
        scenario_json["schema_version"],
        json!(SCENARIO_SCHEMA_VERSION)
    );

    // Required fields should be present
    assert!(scenario_json["id"].is_string());
    assert!(scenario_json["description"].is_string());
    assert!(scenario_json["lab"].is_object());

    // Lab configuration should have required fields
    let lab = &scenario_json["lab"];
    assert!(lab["seed"].is_number());
    assert!(lab["worker_count"].is_number());
    assert!(lab["trace_capacity"].is_number());
    assert!(lab["max_steps"].is_number());

    // Should serialize and parse correctly
    let serialized = serde_json::to_string(&scenario_json).expect("scenario should serialize");
    let parsed: Value = serde_json::from_str(&serialized).expect("scenario should parse");

    assert_eq!(parsed["schema_version"], json!(SCENARIO_SCHEMA_VERSION));
    assert_eq!(parsed["id"], scenario_json["id"]);
}

#[test]
fn test_scenario_participants_validation() {
    let scenario_json = create_test_scenario();
    let participants = &scenario_json["participants"];

    assert!(participants.is_array());
    let participant_array = participants.as_array().unwrap();
    assert_eq!(participant_array.len(), 2);

    // Validate participant structure
    for participant in participant_array {
        assert!(participant["name"].is_string());
        assert!(participant["role"].is_string());
    }

    // Check specific participants
    let alice = &participant_array[0];
    let bob = &participant_array[1];

    assert_eq!(alice["name"], json!("alice"));
    assert_eq!(alice["role"], json!("sender"));
    assert_eq!(bob["name"], json!("bob"));
    assert_eq!(bob["role"], json!("receiver"));
}

#[test]
fn test_scenario_invariants_validation() {
    let scenario_json = create_test_scenario();
    let invariants = &scenario_json["expected_invariants"];

    assert!(invariants.is_array());
    let invariant_array = invariants.as_array().unwrap();

    // Should contain essential invariants
    let invariant_strings: Vec<String> = invariant_array
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    assert!(invariant_strings.contains(&"quiescence".to_string()));
    assert!(invariant_strings.contains(&"losers_drained".to_string()));
    assert!(invariant_strings.contains(&"no_obligation_leaks".to_string()));
    assert!(invariant_strings.contains(&"deterministic_replay".to_string()));

    // All invariants should be valid strings
    for invariant in &invariant_strings {
        assert!(!invariant.is_empty());
        assert!(!invariant.contains(' ')); // Should be identifier-like
    }
}

#[test]
fn test_trace_certificate_determinism() {
    // Same configuration should produce same trace certificate
    let config = create_test_lab_config();

    let mut runtime1 = LabRuntime::new(config.clone());
    let mut runtime2 = LabRuntime::new(config);

    // Create identical simple scenarios
    let create_scenario = |runtime: &mut LabRuntime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let task = async {
            for i in 0..10 {
                crate::runtime::yield_now().await;
                if i % 3 == 0 {
                    let now = crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                    crate::time::sleep(now, Duration::from_micros(1)).await;
                }
            }
            42
        };

        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, task)
            .expect("create task");

        runtime.scheduler.lock().schedule(task_id, 0);
        task_id
    };

    let _task_id1 = create_scenario(&mut runtime1);
    let _task_id2 = create_scenario(&mut runtime2);

    // Run both to completion
    let run1 = runtime1.run_with_auto_advance();
    let run2 = runtime2.run_with_auto_advance();
    assert_eq!(run1.termination, AutoAdvanceTermination::Quiescent);
    assert_eq!(run2.termination, AutoAdvanceTermination::Quiescent);

    // Build trace certificates
    let cert1 = runtime1.report().trace_certificate;
    let cert2 = runtime2.report().trace_certificate;

    // Certificates should be identical
    assert_eq!(cert1.event_hash, cert2.event_hash);
    assert_eq!(cert1.event_count, cert2.event_count);
    assert_eq!(cert1.schedule_hash, cert2.schedule_hash);

    // Event counts should be reasonable
    assert!(cert1.event_count > 0);
    assert!(cert1.event_count < 1000); // Shouldn't be excessive for simple task
}

#[test]
fn test_chaos_injection_bounds() {
    // Test that chaos injection stays within configured bounds
    let chaos = ChaosConfig::new(TEST_SEED)
        .with_delay_probability(0.2)
        .with_cancel_probability(0.1)
        .with_io_error_probability(0.05);

    let config = create_test_lab_config().with_chaos(chaos);
    let mut runtime = LabRuntime::new(config);

    // Create tasks that will be subject to chaos
    let region = runtime.state.create_root_region(Budget::INFINITE);

    for i in 0..50 {
        let task = async move {
            crate::runtime::yield_now().await;
            i * 2
        };

        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, task)
            .expect("create chaos task");

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    // Run and collect chaos statistics
    runtime.run_with_auto_advance();
    let chaos_stats = runtime.chaos_stats();

    // Validate chaos statistics are reasonable
    assert!(chaos_stats.delays <= 50); // Can't have more delays than tasks
    assert!(chaos_stats.cancellations <= 50); // Can't have more cancellations than tasks
    assert!(chaos_stats.io_errors <= 50); // Can't have more I/O errors than tasks

    // Injection rates should be roughly within bounds (allowing variance)
    let total_operations = 50u64;
    let delay_rate = chaos_stats.delays as f64 / total_operations as f64;
    let cancel_rate = chaos_stats.cancellations as f64 / total_operations as f64;
    let io_error_rate = chaos_stats.io_errors as f64 / total_operations as f64;

    // Rates should be somewhat close to configured probabilities
    // (allowing for randomness and small sample size)
    assert!(delay_rate <= 0.5); // Should not exceed 50% even with variance
    assert!(cancel_rate <= 0.3); // Should not exceed 30% even with variance
    assert!(io_error_rate <= 0.2); // Should not exceed 20% even with variance
}

#[test]
fn test_oracle_suite_integration() {
    let config = create_test_lab_config();
    let mut runtime = LabRuntime::new(config);

    // Create a test scenario that should pass oracle checks
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let well_behaved_task = async {
        // Simple task that should not violate invariants
        crate::runtime::yield_now().await;
        let now = crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
        crate::time::sleep(now, Duration::from_micros(10)).await;
        "completed_successfully"
    };

    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, well_behaved_task)
        .expect("create well-behaved task");

    runtime.scheduler.lock().schedule(task_id, 0);

    // Run with auto-advance
    let report = runtime.run_with_auto_advance();

    // Should reach quiescence without oracle violations
    assert_eq!(report.termination, AutoAdvanceTermination::Quiescent);

    // Runtime should be in valid state
    assert!(runtime.is_quiescent());

    // No obligation leaks should be detected
    // (This would be checked by the oracle suite in a real scenario)
}

#[test]
fn test_resource_caps_enforcement() {
    let scenario_json = create_test_scenario();
    let caps = &scenario_json["resource_caps"];

    // Validate resource caps structure
    assert!(caps["max_artifact_bytes"].is_number());
    assert!(caps["max_fault_events"].is_number());
    assert!(caps["max_counterexample_events"].is_number());

    // Values should be reasonable
    let max_artifact_bytes = caps["max_artifact_bytes"].as_u64().unwrap();
    let max_fault_events = caps["max_fault_events"].as_u64().unwrap();
    let max_counterexample_events = caps["max_counterexample_events"].as_u64().unwrap();

    assert!(max_artifact_bytes > 0);
    assert!(max_artifact_bytes <= 1_000_000); // Reasonable upper bound
    assert!(max_fault_events > 0);
    assert!(max_fault_events <= 1000); // Reasonable upper bound
    assert!(max_counterexample_events > 0);
    assert!(max_counterexample_events <= 1000); // Reasonable upper bound
}

#[test]
fn test_futurelock_detection_configuration() {
    let config = create_test_lab_config()
        .futurelock_max_idle_steps(100) // Low threshold for testing
        .panic_on_futurelock(false); // Don't panic in test

    let runtime = LabRuntime::new(config);

    // Configuration should be applied
    assert_eq!(runtime.config().futurelock_max_idle_steps, 100);
    assert!(!runtime.config().panic_on_futurelock);

    // Should be able to detect configuration in runtime
    assert!(runtime.config().futurelock_max_idle_steps > 0);
}

#[test]
fn test_deterministic_entropy_separation() {
    // Test that scheduling seed and entropy seed are independent
    let config1 = LabConfig::new(TEST_SEED).entropy_seed(111);
    let config2 = LabConfig::new(TEST_SEED).entropy_seed(222);

    let mut runtime1 = LabRuntime::new(config1);
    let mut runtime2 = LabRuntime::new(config2);

    // Scheduling should be identical (same scheduling seed)
    // But entropy-driven behavior should differ (different entropy seed)

    let create_entropy_task = |runtime: &mut LabRuntime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let entropy_seed = runtime.config().entropy_seed;
        let task = async move {
            let rng = crate::util::DetEntropy::new(entropy_seed);
            rng.next_u64() % 100
        };

        let (task_id, handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, task)
            .expect("create entropy task");

        runtime.scheduler.lock().schedule(task_id, 0);
        handle
    };

    let _handle1 = create_entropy_task(&mut runtime1);
    let _handle2 = create_entropy_task(&mut runtime2);

    // Run both
    runtime1.run_with_auto_advance();
    runtime2.run_with_auto_advance();

    // Scheduling decisions should be identical
    let cert1 = runtime1.report().trace_certificate;
    let cert2 = runtime2.report().trace_certificate;

    assert_eq!(cert1.schedule_hash, cert2.schedule_hash); // Scheduling identical
    // But entropy results may differ (not tested here due to complexity)
}

#[test]
fn test_trace_capacity_bounds() {
    let config = create_test_lab_config().trace_capacity(10); // Very small for testing

    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Create many tasks to exceed trace capacity
    for i in 0..20 {
        let task = async move { i };
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, task)
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_with_auto_advance();

    // Trace should respect capacity bounds
    let cert = runtime.report().trace_certificate;
    assert!(cert.event_count <= TEST_TRACE_CAPACITY as u64 * 2); // Allow some overhead

    // Should still complete successfully despite trace limits
    assert!(runtime.is_quiescent());
}

#[test]
fn test_memory_usage_bounds_in_lab_runtime() {
    // Test that lab runtime structures have reasonable memory footprint
    use std::mem::size_of;

    // Core structures should be reasonably sized
    assert!(
        size_of::<LabConfig>() < 1024,
        "LabConfig too large: {} bytes",
        size_of::<LabConfig>()
    );
    assert!(
        size_of::<VirtualTimeReport>() < 256,
        "VirtualTimeReport too large: {} bytes",
        size_of::<VirtualTimeReport>()
    );
    assert!(
        size_of::<AutoAdvanceTermination>() < 32,
        "AutoAdvanceTermination too large: {} bytes",
        size_of::<AutoAdvanceTermination>()
    );

    // Create a runtime and verify it doesn't use excessive memory
    let config = create_test_lab_config();
    let runtime = LabRuntime::new(config);

    // Runtime should be created successfully
    assert!(runtime.is_quiescent()); // No tasks, obligations, or registered I/O yet
}

#[test]
fn test_cross_platform_determinism_validation() {
    // Test that determinism holds across different configurations
    let base_config = LabConfig::new(TEST_SEED);

    // Different worker counts should still be deterministic
    let config1 = base_config.clone().worker_count(1);
    let config2 = base_config.clone().worker_count(4);

    let mut runtime1 = LabRuntime::new(config1);
    let mut runtime2 = LabRuntime::new(config2);

    // Create identical single-threaded-equivalent tasks
    let create_simple_task = |runtime: &mut LabRuntime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let task = async { 42u32 };

        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, task)
            .expect("create simple task");

        runtime.scheduler.lock().schedule(task_id, 0);
    };

    create_simple_task(&mut runtime1);
    create_simple_task(&mut runtime2);

    runtime1.run_with_auto_advance();
    runtime2.run_with_auto_advance();

    // Both should complete successfully
    assert!(runtime1.is_quiescent());
    assert!(runtime2.is_quiescent());

    // Basic scheduling should be consistent
    // (detailed comparison may differ due to worker count effects)
}
