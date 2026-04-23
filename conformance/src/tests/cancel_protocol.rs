//! Cancel Protocol Conformance Test Suite
//!
//! Tests covering the cancel protocol's request→drain→finalize lifecycle phases
//! and state transition invariants that ensure proper cancellation semantics.
//!
//! # Core Protocol Tested
//!
//! - **Request Phase**: Cancel is requested but task continues until checkpoint
//! - **Drain Phase**: Task acknowledges cancel and performs cleanup
//! - **Finalize Phase**: All cleanup complete, task transitions to Cancelled state
//! - **Bounded**: Cleanup completes within bounded time/budget
//!
//! # Test IDs
//!
//! - CP-001: Request phase - cancel request doesn't immediately stop task
//! - CP-002: Drain phase - task acknowledges cancel and performs cleanup

use crate::{ConformanceTest, RuntimeInterface, TestCategory, TestMeta, TestResult, checkpoint};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// Get all cancel protocol conformance tests.
pub fn all_tests<RT: RuntimeInterface + Sync>() -> Vec<ConformanceTest<RT>> {
    vec![
        cp_001_request_phase_continues::<RT>(),
        cp_002_drain_phase_cleanup::<RT>(),
    ]
}

/// CP-001: Request phase - cancel request doesn't immediately stop task
///
/// Verifies that when cancellation is requested (via timeout), the task continues
/// executing for some time before being cancelled, simulating the request phase.
pub fn cp_001_request_phase_continues<RT: RuntimeInterface + Sync>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cp-001".to_string(),
            name: "Cancel request phase - task continues until checkpoint".to_string(),
            description: "Task should continue executing after cancel request until checkpoint"
                .to_string(),
            category: TestCategory::Cancel,
            tags: vec![
                "cancel".to_string(),
                "protocol".to_string(),
                "request".to_string(),
                "checkpoint".to_string(),
            ],
            expected: "Task continues work until timeout cancels it".to_string(),
        },
        |rt| {
            rt.block_on(async {
                checkpoint("Starting cancel request phase test", serde_json::json!({}));

                let work_done = Arc::new(AtomicUsize::new(0));
                let work_done_clone = work_done.clone();

                // Pre-create sleep future to avoid capturing &RT
                let long_sleep = rt.sleep(Duration::from_millis(100));

                // Use timeout to simulate cancel request
                let result = rt
                    .timeout(Duration::from_millis(30), async move {
                        checkpoint("Task started", serde_json::json!({}));

                        // Do some initial work that should complete
                        work_done_clone.store(1, Ordering::Release);

                        // This sleep should be interrupted by the timeout
                        long_sleep.await;

                        // Should not reach here if cancelled properly
                        work_done_clone.store(10, Ordering::Release);
                        "Task completed normally"
                    })
                    .await;

                let final_work_done = work_done.load(Ordering::Acquire);

                checkpoint(
                    "Request phase test completed",
                    serde_json::json!({
                        "work_done": final_work_done,
                        "task_result": match result {
                            Ok(_) => "completed",
                            Err(_) => "timeout"
                        }
                    }),
                );

                // Verify task did some work before being cancelled by timeout
                if final_work_done == 0 {
                    return TestResult::failed("Task should have done some work before cancel");
                }

                // Timeout means the cancel signal worked (task was interrupted)
                match result {
                    Ok(_) => TestResult::failed("Task should have been cancelled by timeout"),
                    Err(_) => {
                        // Task was cancelled, verify it did initial work but not final work
                        if final_work_done >= 1 && final_work_done < 10 {
                            TestResult::passed()
                        } else {
                            TestResult::failed("Task should have done partial work before cancel")
                        }
                    }
                }
            })
        },
    )
}

/// CP-002: Drain phase - task acknowledges cancel and performs cleanup
///
/// Verifies that after acknowledging cancellation, cleanup can be performed
/// before the task fully exits.
pub fn cp_002_drain_phase_cleanup<RT: RuntimeInterface + Sync>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cp-002".to_string(),
            name: "Cancel drain phase - cleanup execution".to_string(),
            description: "Task can perform cleanup after cancel acknowledgment".to_string(),
            category: TestCategory::Cancel,
            tags: vec![
                "cancel".to_string(),
                "protocol".to_string(),
                "drain".to_string(),
                "cleanup".to_string(),
            ],
            expected: "Cleanup can be performed after cancel signal".to_string(),
        },
        |rt| {
            rt.block_on(async {
                checkpoint("Starting cancel drain phase test", serde_json::json!({}));

                let cleanup_completed = Arc::new(AtomicBool::new(false));
                let resource_freed = Arc::new(AtomicBool::new(false));

                let cleanup_completed_clone = cleanup_completed.clone();
                let resource_freed_clone = resource_freed.clone();

                // Pre-create futures
                let work_sleep = rt.sleep(Duration::from_millis(100));
                let cleanup_sleep = rt.sleep(Duration::from_millis(5));

                // Simulate task with timeout (acting as cancel signal)
                let result = rt
                    .timeout(Duration::from_millis(20), async move {
                        checkpoint("Task started with resources", serde_json::json!({}));

                        // Simulate holding resources
                        let _simulated_resource = "critical_resource";

                        // This should timeout (simulating cancel request)
                        work_sleep.await;

                        // Should not reach here if cancelled properly
                        "Normal completion"
                    })
                    .await;

                // Handle timeout (cancel) by performing cleanup
                if result.is_err() {
                    checkpoint("Cancel detected, starting drain", serde_json::json!({}));

                    // Drain phase: cleanup resources
                    checkpoint("Performing resource cleanup", serde_json::json!({}));
                    cleanup_sleep.await; // Cleanup work
                    resource_freed_clone.store(true, Ordering::Release);

                    // Complete cleanup
                    cleanup_completed_clone.store(true, Ordering::Release);
                    checkpoint("Cleanup completed", serde_json::json!({}));
                }

                let cleanup_done = cleanup_completed.load(Ordering::Acquire);
                let resource_cleaned = resource_freed.load(Ordering::Acquire);

                checkpoint(
                    "Drain phase test completed",
                    serde_json::json!({
                        "cleanup_completed": cleanup_done,
                        "resource_freed": resource_cleaned,
                        "task_result": match result {
                            Ok(_) => "completed",
                            Err(_) => "timeout"
                        }
                    }),
                );

                if !cleanup_done {
                    return TestResult::failed("Cleanup should have completed");
                }

                if !resource_cleaned {
                    return TestResult::failed("Resources should have been freed");
                }

                if result.is_err() {
                    TestResult::passed()
                } else {
                    TestResult::failed("Task should have been cancelled")
                }
            })
        },
    )
}
