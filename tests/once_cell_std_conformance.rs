//! Conformance test for asupersync::sync::OnceCell vs std::sync::OnceLock.
//!
//! Tests that both OnceCell implementations exhibit identical behavior for:
//! - Same init closure producing same results
//! - Same access patterns producing identical observable order
//! - Consistent initialization semantics
//! - Proper thread safety and coordination

use asupersync::sync::OnceCell as AsupersyncOnceCell;
use std::sync::{Arc, OnceLock as StdOnceLock};
use std::thread;
use std::time::Duration;

/// Result of a OnceCell conformance test comparing both implementations.
#[derive(Debug, Clone, PartialEq)]
struct OnceCellConformanceResult {
    /// Thread ID that performed the operation
    thread_id: usize,
    /// Operation type
    operation: ConformanceOp,
    /// Position of this operation within the thread's configured sequence
    operation_index: usize,
    /// Result of asupersync OnceCell operation
    asupersync_result: OpResult,
    /// Result of std OnceLock operation
    std_result: OpResult,
    /// Final observed value
    final_value: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
enum ConformanceOp {
    GetOrInit { init_value: u32 },
    Get,
    Set { value: u32 },
}

#[derive(Debug, Clone, PartialEq)]
enum OpResult {
    InitSuccess(u32), // get_or_init returned this value
    GetSome(u32),     // get() returned Some(value)
    GetNone,          // get() returned None
    SetOk,            // set() succeeded
    SetErr,           // set() failed (already initialized)
}

#[derive(Debug, Clone, Copy)]
enum Implementation {
    Asupersync,
    Std,
}

/// Test configuration for OnceCell conformance.
#[derive(Debug, Clone)]
struct ConformanceTestConfig {
    /// Number of threads
    thread_count: usize,
    /// Operations per thread
    operations_per_thread: Vec<ConformanceOp>,
    /// Stagger delay between thread starts (microseconds)
    stagger_delays: Vec<u64>,
}

/// Test context for running conformance tests.
struct OnceCellConformanceContext {
    config: ConformanceTestConfig,
}

impl OnceCellConformanceContext {
    fn new(config: ConformanceTestConfig) -> Self {
        Self { config }
    }

    /// Run the same OnceCell scenario on both implementations and compare results.
    fn run_differential_test(
        &self,
    ) -> (
        Vec<OnceCellConformanceResult>,
        Vec<OnceCellConformanceResult>,
    ) {
        let asupersync_results = self.test_asupersync_once_cell();
        let std_results = self.test_std_once_lock();

        (asupersync_results, std_results)
    }

    /// Test asupersync OnceCell behavior.
    fn test_asupersync_once_cell(&self) -> Vec<OnceCellConformanceResult> {
        let cell = Arc::new(AsupersyncOnceCell::<u32>::new());
        let results = Arc::new(parking_lot::Mutex::new(Vec::new()));

        let handles: Vec<_> = (0..self.config.thread_count)
            .map(|thread_id| {
                let cell = Arc::clone(&cell);
                let results = Arc::clone(&results);
                let operations = self.config.operations_per_thread.clone();
                let delay = self
                    .config
                    .stagger_delays
                    .get(thread_id)
                    .copied()
                    .unwrap_or(0);

                thread::spawn(move || {
                    // Apply stagger delay
                    if delay > 0 {
                        thread::sleep(Duration::from_micros(delay));
                    }

                    for (operation_index, operation) in operations.into_iter().enumerate() {
                        let asupersync_result = match &operation {
                            ConformanceOp::GetOrInit { init_value } => {
                                let value = *init_value;
                                let result = cell.get_or_init_blocking(|| value);
                                OpResult::InitSuccess(*result)
                            }
                            ConformanceOp::Get => match cell.get() {
                                Some(value) => OpResult::GetSome(*value),
                                None => OpResult::GetNone,
                            },
                            ConformanceOp::Set { value } => match cell.set(*value) {
                                Ok(()) => OpResult::SetOk,
                                Err(_) => OpResult::SetErr,
                            },
                        };

                        let final_value = cell.get().copied();

                        results.lock().push(OnceCellConformanceResult {
                            thread_id,
                            operation: operation.clone(),
                            operation_index,
                            asupersync_result: asupersync_result.clone(),
                            std_result: asupersync_result, // Mirror counterpart slot; not read for this run
                            final_value,
                        });
                    }
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        let mut results = results.lock().clone();
        results.sort_by_key(|r| (r.thread_id, r.operation_index));
        results
    }

    /// Test std::sync::OnceLock behavior.
    fn test_std_once_lock(&self) -> Vec<OnceCellConformanceResult> {
        let cell = Arc::new(StdOnceLock::<u32>::new());
        let results = Arc::new(parking_lot::Mutex::new(Vec::new()));

        let handles: Vec<_> = (0..self.config.thread_count)
            .map(|thread_id| {
                let cell = Arc::clone(&cell);
                let results = Arc::clone(&results);
                let operations = self.config.operations_per_thread.clone();
                let delay = self
                    .config
                    .stagger_delays
                    .get(thread_id)
                    .copied()
                    .unwrap_or(0);

                thread::spawn(move || {
                    // Apply stagger delay
                    if delay > 0 {
                        thread::sleep(Duration::from_micros(delay));
                    }

                    for (operation_index, operation) in operations.into_iter().enumerate() {
                        let std_result = match &operation {
                            ConformanceOp::GetOrInit { init_value } => {
                                let value = *init_value;
                                let result = cell.get_or_init(|| value);
                                OpResult::InitSuccess(*result)
                            }
                            ConformanceOp::Get => match cell.get() {
                                Some(value) => OpResult::GetSome(*value),
                                None => OpResult::GetNone,
                            },
                            ConformanceOp::Set { value } => match cell.set(*value) {
                                Ok(()) => OpResult::SetOk,
                                Err(_) => OpResult::SetErr,
                            },
                        };

                        let final_value = cell.get().copied();

                        results.lock().push(OnceCellConformanceResult {
                            thread_id,
                            operation: operation.clone(),
                            operation_index,
                            asupersync_result: std_result.clone(), // Mirror counterpart slot; not read for this run
                            std_result,
                            final_value,
                        });
                    }
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        let mut results = results.lock().clone();
        results.sort_by_key(|r| (r.thread_id, r.operation_index));
        results
    }
}

/// Verify that both OnceCell implementations have conformant behavior.
fn assert_once_cell_conformance(
    asupersync_results: &[OnceCellConformanceResult],
    std_results: &[OnceCellConformanceResult],
    test_name: &str,
) {
    assert_eq!(
        asupersync_results.len(),
        std_results.len(),
        "{}: Result count mismatch",
        test_name
    );

    // Check that operations happened in the same order
    for (i, (asupersync_result, std_result)) in asupersync_results
        .iter()
        .zip(std_results.iter())
        .enumerate()
    {
        assert_eq!(
            asupersync_result.thread_id, std_result.thread_id,
            "{} op {}: Thread ID differs",
            test_name, i
        );

        assert_eq!(
            asupersync_result.operation, std_result.operation,
            "{} op {}: Operation differs",
            test_name, i
        );

        assert_eq!(
            asupersync_result.operation_index, std_result.operation_index,
            "{} op {}: Operation index differs",
            test_name, i
        );

        // The key conformance check: same operation should produce same result
        assert_eq!(
            asupersync_result.asupersync_result,
            std_result.std_result,
            "{} op {}: Result differs\n\
             Operation: {:?}\n\
             asupersync: {:?}\n\
             std:        {:?}",
            test_name,
            i,
            asupersync_result.operation,
            asupersync_result.asupersync_result,
            std_result.std_result
        );

        // Final values should be identical
        assert_eq!(
            asupersync_result.final_value, std_result.final_value,
            "{} op {}: Final value differs",
            test_name, i
        );
    }

    // Check final state consistency
    let asupersync_final = asupersync_results.last().and_then(|r| r.final_value);
    let std_final = std_results.last().and_then(|r| r.final_value);

    assert_eq!(
        asupersync_final, std_final,
        "{}: Final states differ: asupersync={:?}, std={:?}",
        test_name, asupersync_final, std_final
    );
}

fn observed_result(
    result: &OnceCellConformanceResult,
    implementation: Implementation,
) -> &OpResult {
    match implementation {
        Implementation::Asupersync => &result.asupersync_result,
        Implementation::Std => &result.std_result,
    }
}

fn assert_set_vs_init_race_invariants(
    results: &[OnceCellConformanceResult],
    implementation: Implementation,
    test_name: &str,
) {
    assert_eq!(
        results.len(),
        6,
        "{test_name}: expected two operation sequences"
    );

    let mut set_ok = 0;
    let mut set_err = 0;
    let mut get_or_init = 0;
    let mut get = 0;

    for result in results {
        let observed = observed_result(result, implementation);
        match &result.operation {
            ConformanceOp::Set { value } => {
                assert_eq!(*value, 200, "{test_name}: set value changed");
                match observed {
                    OpResult::SetOk => set_ok += 1,
                    OpResult::SetErr => set_err += 1,
                    other => panic!("{test_name}: set produced unexpected result {other:?}"),
                }
            }
            ConformanceOp::GetOrInit { init_value } => {
                assert_eq!(*init_value, 300, "{test_name}: init value changed");
                assert_eq!(
                    observed,
                    &OpResult::InitSuccess(200),
                    "{test_name}: get_or_init must observe the first successful set"
                );
                get_or_init += 1;
            }
            ConformanceOp::Get => {
                assert_eq!(
                    observed,
                    &OpResult::GetSome(200),
                    "{test_name}: final get must observe the first successful set"
                );
                get += 1;
            }
        }

        assert_eq!(
            result.final_value,
            Some(200),
            "{test_name}: final value must be the first successful set"
        );
    }

    assert_eq!(set_ok, 1, "{test_name}: exactly one set should win");
    assert_eq!(set_err, 1, "{test_name}: exactly one set should lose");
    assert_eq!(
        get_or_init, 2,
        "{test_name}: expected two get_or_init calls"
    );
    assert_eq!(get, 2, "{test_name}: expected two get calls");
}

/// Test basic OnceCell initialization.
#[test]
fn conformance_basic_initialization() {
    let config = ConformanceTestConfig {
        thread_count: 1,
        operations_per_thread: vec![
            ConformanceOp::Get,
            ConformanceOp::GetOrInit { init_value: 42 },
            ConformanceOp::Get,
        ],
        stagger_delays: vec![0],
    };

    let ctx = OnceCellConformanceContext::new(config);
    let (asupersync_results, std_results) = ctx.run_differential_test();

    assert_once_cell_conformance(&asupersync_results, &std_results, "basic_initialization");

    // Should see: None, 42 (init), 42 (get after init)
    assert_eq!(asupersync_results.len(), 3);
    assert_eq!(asupersync_results[0].asupersync_result, OpResult::GetNone);
    assert_eq!(
        asupersync_results[1].asupersync_result,
        OpResult::InitSuccess(42)
    );
    assert_eq!(
        asupersync_results[2].asupersync_result,
        OpResult::GetSome(42)
    );
}

/// Test concurrent initialization race.
#[test]
fn conformance_concurrent_initialization() {
    let config = ConformanceTestConfig {
        thread_count: 3,
        operations_per_thread: vec![
            ConformanceOp::GetOrInit { init_value: 100 },
            ConformanceOp::Get,
        ],
        stagger_delays: vec![0, 10, 20], // Small stagger for race conditions
    };

    let ctx = OnceCellConformanceContext::new(config);
    let (asupersync_results, std_results) = ctx.run_differential_test();

    assert_once_cell_conformance(
        &asupersync_results,
        &std_results,
        "concurrent_initialization",
    );

    // All should see the same final value (first initializer wins)
    let final_values: Vec<_> = asupersync_results
        .iter()
        .filter_map(|r| r.final_value)
        .collect();

    assert!(!final_values.is_empty(), "Should have final values");
    let expected_value = final_values[0];
    for &value in &final_values {
        assert_eq!(
            value, expected_value,
            "All final values should be identical"
        );
    }
}

/// Test set vs get_or_init race.
#[test]
fn conformance_set_vs_init_race() {
    let config = ConformanceTestConfig {
        thread_count: 2,
        operations_per_thread: vec![
            ConformanceOp::Set { value: 200 },
            ConformanceOp::GetOrInit { init_value: 300 },
            ConformanceOp::Get,
        ],
        stagger_delays: vec![0, 5], // Tight race
    };

    let ctx = OnceCellConformanceContext::new(config);
    let (asupersync_results, std_results) = ctx.run_differential_test();

    assert_set_vs_init_race_invariants(
        &asupersync_results,
        Implementation::Asupersync,
        "set_vs_init_race/asupersync",
    );
    assert_set_vs_init_race_invariants(&std_results, Implementation::Std, "set_vs_init_race/std");
}

/// Test multiple get operations after initialization.
#[test]
fn conformance_multiple_gets_after_init() {
    let config = ConformanceTestConfig {
        thread_count: 4,
        operations_per_thread: vec![
            ConformanceOp::GetOrInit { init_value: 500 },
            ConformanceOp::Get,
            ConformanceOp::Get,
            ConformanceOp::Get,
        ],
        stagger_delays: vec![0, 0, 0, 0],
    };

    let ctx = OnceCellConformanceContext::new(config);
    let (asupersync_results, std_results) = ctx.run_differential_test();

    assert_once_cell_conformance(
        &asupersync_results,
        &std_results,
        "multiple_gets_after_init",
    );

    // All get operations should return the same value
    for result in &asupersync_results {
        if matches!(result.operation, ConformanceOp::Get) {
            assert_eq!(result.asupersync_result, OpResult::GetSome(500));
        }
    }
}

/// Test set operations on already initialized cell.
#[test]
fn conformance_set_after_initialization() {
    let config = ConformanceTestConfig {
        thread_count: 1,
        operations_per_thread: vec![
            ConformanceOp::GetOrInit { init_value: 600 },
            ConformanceOp::Set { value: 700 },
            ConformanceOp::Set { value: 800 },
            ConformanceOp::Get,
        ],
        stagger_delays: vec![0],
    };

    let ctx = OnceCellConformanceContext::new(config);
    let (asupersync_results, std_results) = ctx.run_differential_test();

    assert_once_cell_conformance(
        &asupersync_results,
        &std_results,
        "set_after_initialization",
    );

    // Should see: init succeeds, both sets fail, get returns init value
    assert_eq!(
        asupersync_results[0].asupersync_result,
        OpResult::InitSuccess(600)
    );
    assert_eq!(asupersync_results[1].asupersync_result, OpResult::SetErr);
    assert_eq!(asupersync_results[2].asupersync_result, OpResult::SetErr);
    assert_eq!(
        asupersync_results[3].asupersync_result,
        OpResult::GetSome(600)
    );
}

/// Comprehensive conformance test matrix.
#[test]
fn conformance_comprehensive_matrix() {
    let test_cases = vec![
        // (name, thread_count, operations, delays)
        (
            "single_thread_linear",
            1,
            vec![
                ConformanceOp::Get,
                ConformanceOp::GetOrInit { init_value: 1 },
                ConformanceOp::Get,
            ],
            vec![0],
        ),
        (
            "concurrent_double_init",
            2,
            vec![ConformanceOp::GetOrInit { init_value: 2 }],
            vec![0, 0],
        ),
        (
            "set_then_init",
            1,
            vec![
                ConformanceOp::Set { value: 3 },
                ConformanceOp::GetOrInit { init_value: 4 },
            ],
            vec![0],
        ),
        (
            "init_then_set",
            1,
            vec![
                ConformanceOp::GetOrInit { init_value: 5 },
                ConformanceOp::Set { value: 6 },
            ],
            vec![0],
        ),
    ];

    for (name, thread_count, operations, delays) in test_cases {
        let config = ConformanceTestConfig {
            thread_count,
            operations_per_thread: operations,
            stagger_delays: delays,
        };

        let ctx = OnceCellConformanceContext::new(config);
        let (asupersync_results, std_results) = ctx.run_differential_test();

        if name == "set_vs_init_race" {
            assert_set_vs_init_race_invariants(
                &asupersync_results,
                Implementation::Asupersync,
                "set_vs_init_race/asupersync",
            );
            assert_set_vs_init_race_invariants(
                &std_results,
                Implementation::Std,
                "set_vs_init_race/std",
            );
        } else {
            assert_once_cell_conformance(&asupersync_results, &std_results, name);
        }
    }
}

/// Verify the documented coverage matrix instead of printing a report that can
/// pass without exercising any implementation behavior.
#[test]
fn conformance_coverage_matrix_exercises_all_scenarios() {
    let test_cases = vec![
        (
            "basic_initialization",
            ConformanceTestConfig {
                thread_count: 1,
                operations_per_thread: vec![
                    ConformanceOp::Get,
                    ConformanceOp::GetOrInit { init_value: 42 },
                    ConformanceOp::Get,
                ],
                stagger_delays: vec![0],
            },
        ),
        (
            "concurrent_initialization",
            ConformanceTestConfig {
                thread_count: 3,
                operations_per_thread: vec![
                    ConformanceOp::GetOrInit { init_value: 100 },
                    ConformanceOp::Get,
                ],
                stagger_delays: vec![0, 10, 20],
            },
        ),
        (
            "set_vs_init_race",
            ConformanceTestConfig {
                thread_count: 2,
                operations_per_thread: vec![
                    ConformanceOp::Set { value: 200 },
                    ConformanceOp::GetOrInit { init_value: 300 },
                    ConformanceOp::Get,
                ],
                stagger_delays: vec![0, 5],
            },
        ),
        (
            "multiple_gets_after_init",
            ConformanceTestConfig {
                thread_count: 4,
                operations_per_thread: vec![
                    ConformanceOp::GetOrInit { init_value: 500 },
                    ConformanceOp::Get,
                    ConformanceOp::Get,
                    ConformanceOp::Get,
                ],
                stagger_delays: vec![0, 0, 0, 0],
            },
        ),
        (
            "set_after_initialization",
            ConformanceTestConfig {
                thread_count: 1,
                operations_per_thread: vec![
                    ConformanceOp::GetOrInit { init_value: 600 },
                    ConformanceOp::Set { value: 700 },
                    ConformanceOp::Set { value: 800 },
                    ConformanceOp::Get,
                ],
                stagger_delays: vec![0],
            },
        ),
    ];

    assert_eq!(test_cases.len(), 5, "coverage matrix should stay explicit");

    for (name, config) in test_cases {
        let ctx = OnceCellConformanceContext::new(config);
        let (asupersync_results, std_results) = ctx.run_differential_test();

        if name == "set_vs_init_race" {
            assert_set_vs_init_race_invariants(
                &asupersync_results,
                Implementation::Asupersync,
                "set_vs_init_race/asupersync",
            );
            assert_set_vs_init_race_invariants(
                &std_results,
                Implementation::Std,
                "set_vs_init_race/std",
            );
        } else {
            assert_once_cell_conformance(&asupersync_results, &std_results, name);
        }
    }
}
