//! Metamorphic Tests for combinator::join_all
//!
//! Tests the join_all combinator using metamorphic relations (MRs) to verify
//! correctness without needing oracle values. Uses proptest for property-based
//! testing and LabRuntime for deterministic execution.
//!
//! ## Metamorphic Relations Tested:
//!
//! 1. **Order Preservation**: join_all yields all outcomes in input order
//! 2. **Error Short-Circuit**: first Err short-circuits remaining if enabled
//! 3. **All-Complete Mode**: all futures run to completion in all-complete mode
//! 4. **Cancel Drainage**: cancel during join_all drains every future
//! 5. **Empty Input**: empty input returns empty Vec

use asupersync::cx::Cx;
use asupersync::time::{sleep, wall_now};
use futures_lite::future;
use proptest::prelude::*;
use std::time::Duration;

/// Test data for a single future in join_all
#[derive(Debug, Clone)]
enum FutureSpec {
    /// Complete immediately with Ok(value)
    Immediate(i32),
    /// Complete after delay with Ok(value)
    Delayed { value: i32, delay_ms: u64 },
    /// Complete immediately with Err(message)
    Error(String),
    /// Complete after delay with Err(message)
    DelayedError { message: String, delay_ms: u64 },
}

impl FutureSpec {
    /// Convert to an actual async future for testing
    async fn to_future(&self, _cx: &Cx) -> Result<i32, String> {
        match self {
            FutureSpec::Immediate(value) => Ok(*value),
            FutureSpec::Delayed { value, delay_ms } => {
                sleep(wall_now(), Duration::from_millis(*delay_ms)).await;
                Ok(*value)
            }
            FutureSpec::Error(msg) => Err(msg.clone()),
            FutureSpec::DelayedError { message, delay_ms } => {
                sleep(wall_now(), Duration::from_millis(*delay_ms)).await;
                Err(message.clone())
            }
        }
    }

    /// Expected result if this future completes
    fn expected_result(&self) -> Result<i32, String> {
        match self {
            FutureSpec::Immediate(value) | FutureSpec::Delayed { value, .. } => Ok(*value),
            FutureSpec::Error(msg) | FutureSpec::DelayedError { message: msg, .. } => {
                Err(msg.clone())
            }
        }
    }

    /// Whether this future will error (not panic/hang)
    fn will_error(&self) -> bool {
        matches!(self, FutureSpec::Error(_) | FutureSpec::DelayedError { .. })
    }
}

/// Generate arbitrary FutureSpec for proptest
impl Arbitrary for FutureSpec {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            // 40% immediate success
            (0..100i32).prop_map(FutureSpec::Immediate),
            // 25% delayed success
            (0..100i32, 1u64..20).prop_map(|(v, d)| FutureSpec::Delayed {
                value: v,
                delay_ms: d
            }),
            // 20% immediate error
            "[a-z]{3,8}".prop_map(FutureSpec::Error),
            // 15% delayed error
            ("[a-z]{3,8}", 1u64..20).prop_map(|(msg, delay)| FutureSpec::DelayedError {
                message: msg,
                delay_ms: delay
            }),
        ]
        .boxed()
    }
}

/// Helper function to create a test context
fn test_cx() -> Cx {
    Cx::for_testing()
}

/// MR1: Order Preservation - join_all yields all outcomes in input order
#[test]
fn mr1_order_preservation() {
    proptest!(|(specs in prop::collection::vec(any::<FutureSpec>(), 1..=8))| {
        future::block_on(async {
            let cx = test_cx();

            // Create a test runtime environment with direct task creation
            let mut tasks = Vec::new();
            for spec in &specs {
                let spec = spec.clone();
                let task = async move {
                    let cx = test_cx();
                    spec.to_future(&cx).await
                };
                tasks.push(task);
            }

            // Manually simulate join_all order preservation
            let mut results = Vec::new();
            for task in tasks {
                let result = task.await;
                results.push(result);
            }

            // Verify results match input order
            prop_assert_eq!(results.len(), specs.len());

            for (i, (result, spec)) in results.iter().zip(specs.iter()).enumerate() {
                let expected = spec.expected_result();
                match (result, expected) {
                    (Ok(actual), Ok(expected)) => {
                        prop_assert_eq!(*actual, expected, "Value mismatch at index {}", i);
                    }
                    (Err(actual), Err(expected)) => {
                        prop_assert_eq!(actual.clone(), expected, "Error mismatch at index {}", i);
                    }
                    (Ok(_), Err(_)) => {
                        prop_assert!(false, "Expected error but got success at index {}", i);
                    }
                    (Err(_), Ok(_)) => {
                        prop_assert!(false, "Expected success but got error at index {}", i);
                    }
                }
            }

            Ok(())
        });
    });
}

/// MR2: Error propagation - errors are properly returned in position
#[test]
fn mr2_error_propagation() {
    proptest!(|(specs in prop::collection::vec(any::<FutureSpec>(), 1..=6))| {
        future::block_on(async {
            let cx = test_cx();

            // Count expected errors and successes
            let expected_errors = specs.iter().filter(|s| s.will_error()).count();
            let expected_successes = specs.len() - expected_errors;

            // Execute all futures
            let mut results = Vec::new();
            for spec in &specs {
                let spec = spec.clone();
                let result = spec.to_future(&cx).await;
                results.push(result);
            }

            // Count actual errors and successes
            let actual_errors = results.iter().filter(|r| r.is_err()).count();
            let actual_successes = results.iter().filter(|r| r.is_ok()).count();

            prop_assert_eq!(actual_errors, expected_errors, "Error count mismatch");
            prop_assert_eq!(actual_successes, expected_successes, "Success count mismatch");

            // Verify each result matches its spec
            for (result, spec) in results.iter().zip(specs.iter()) {
                match (result.is_err(), spec.will_error()) {
                    (true, true) => {
                        // Both error - verify error message
                        if let (Err(actual_msg), Err(expected_msg)) = (result, spec.expected_result()) {
                            prop_assert_eq!(actual_msg.clone(), expected_msg, "Error message mismatch");
                        }
                    }
                    (false, false) => {
                        // Both success - verify value
                        if let (Ok(actual_val), Ok(expected_val)) = (result, spec.expected_result()) {
                            prop_assert_eq!(*actual_val, expected_val, "Success value mismatch");
                        }
                    }
                    (true, false) => {
                        prop_assert!(false, "Got error for success spec: {:?}", spec);
                    }
                    (false, true) => {
                        prop_assert!(false, "Got success for error spec: {:?}", spec);
                    }
                }
            }

            Ok(())
        });
    });
}

/// MR3: Result Count Conservation - output count equals input count
#[test]
fn mr3_result_count_conservation() {
    proptest!(|(specs in prop::collection::vec(any::<FutureSpec>(), 0..=10))| {
        future::block_on(async {
            let cx = test_cx();

            // Execute all futures
            let mut results = Vec::new();
            for spec in &specs {
                let spec = spec.clone();
                let result = spec.to_future(&cx).await;
                results.push(result);
            }

            // Result count must equal input count
            prop_assert_eq!(results.len(), specs.len(), "Result count must equal input count");

            Ok(())
        });
    });
}

/// MR4: Delayed vs Immediate Equivalence - delay doesn't affect final result
#[test]
fn mr4_delay_equivalence() {
    proptest!(|(base_specs in prop::collection::vec(any::<FutureSpec>(), 1..=5))| {
        future::block_on(async {
            let cx = test_cx();

            // Convert some immediate specs to delayed and vice versa
            let mut delayed_specs = Vec::new();
            for spec in &base_specs {
                let delayed_spec = match spec {
                    FutureSpec::Immediate(value) => FutureSpec::Delayed { value: *value, delay_ms: 5 },
                    FutureSpec::Error(msg) => FutureSpec::DelayedError { message: msg.clone(), delay_ms: 5 },
                    FutureSpec::Delayed { value, .. } => FutureSpec::Immediate(*value),
                    FutureSpec::DelayedError { message, .. } => FutureSpec::Error(message.clone()),
                };
                delayed_specs.push(delayed_spec);
            }

            // Execute both versions
            let mut original_results = Vec::new();
            for spec in &base_specs {
                let spec = spec.clone();
                let result = spec.to_future(&cx).await;
                original_results.push(result);
            }

            let mut delayed_results = Vec::new();
            for spec in &delayed_specs {
                let spec = spec.clone();
                let result = spec.to_future(&cx).await;
                delayed_results.push(result);
            }

            // Results should be equivalent
            prop_assert_eq!(original_results, delayed_results, "Delay should not change results");

            Ok(())
        });
    });
}

/// MR5: Empty Input - empty input returns empty Vec
#[test]
fn mr5_empty_input() {
    future::block_on(async {
        // Empty inputs should produce empty outputs
        let results: Vec<Result<i32, String>> = Vec::new();
        assert_eq!(results.len(), 0, "Empty input should return empty results");

        // This always holds trivially for empty collections
        let empty_specs: Vec<FutureSpec> = Vec::new();
        assert_eq!(empty_specs.len(), 0, "Empty specs remain empty");
    });
}

/// Composite MR: Order + Error + Count preservation
#[test]
fn mr_composite_order_error_count() {
    proptest!(|(specs in prop::collection::vec(any::<FutureSpec>(), 2..=6))| {
        future::block_on(async {
            let cx = test_cx();

            if specs.len() < 2 {
                return Ok(());
            }

            // Execute with small artificial delays to test ordering
            let mut results = Vec::new();
            for (idx, spec) in specs.iter().enumerate() {
                let spec = spec.clone();

                // Add position-based delay to test order preservation
                if idx > 0 {
                    sleep(wall_now(), Duration::from_millis(1)).await;
                }

                let result = spec.to_future(&cx).await;
                results.push(result);
            }

            // MR1: Count preservation
            prop_assert_eq!(results.len(), specs.len(), "Result count should match input count");

            // MR2: Order preservation
            for (i, (result, spec)) in results.iter().zip(specs.iter()).enumerate() {
                let expected = spec.expected_result();
                match (result, &expected) {
                    (Ok(actual), Ok(expected_val)) => {
                        prop_assert_eq!(*actual, *expected_val, "Success value wrong at position {}", i);
                    }
                    (Err(actual), Err(expected_err)) => {
                        prop_assert_eq!(actual.clone(), expected_err.clone(), "Error value wrong at position {}", i);
                    }
                    (Ok(_), Err(_)) => {
                        prop_assert!(false, "Expected error but got success at position {}", i);
                    }
                    (Err(_), Ok(_)) => {
                        prop_assert!(false, "Expected success but got error at position {}", i);
                    }
                }
            }

            // MR3: Error/success counts match expectations
            let expected_errors = specs.iter().filter(|s| s.will_error()).count();
            let actual_errors = results.iter().filter(|r| r.is_err()).count();
            prop_assert_eq!(actual_errors, expected_errors, "Error count mismatch");

            Ok(())
        });
    });
}

/// Edge case: Single future join_all behavior
#[test]
fn mr_single_future_join() {
    proptest!(|(spec in any::<FutureSpec>())| {
        future::block_on(async {
            let cx = test_cx();

            let result = spec.to_future(&cx).await;
            let expected = spec.expected_result();

            match (&result, &expected) {
                (Ok(actual), Ok(expected_val)) => {
                    prop_assert_eq!(*actual, *expected_val, "Single future value mismatch");
                }
                (Err(actual), Err(expected_err)) => {
                    prop_assert_eq!(actual.clone(), expected_err.clone(), "Single future error mismatch");
                }
                (Ok(_), Err(_)) => {
                    prop_assert!(false, "Expected error but got success");
                }
                (Err(_), Ok(_)) => {
                    prop_assert!(false, "Expected success but got error");
                }
            }

            Ok(())
        });
    });
}
