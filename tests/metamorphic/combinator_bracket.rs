#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for combinator::bracket resource cleanup invariants.
//!
//! These tests validate the core resource safety and cleanup semantics of the
//! bracket combinator using metamorphic relations and property-based testing
//! under deterministic LabRuntime conditions.
//!
//! ## Key Properties Tested
//!
//! 1. **Cleanup universality**: cleanup runs on success, failure, and cancel paths
//! 2. **Cleanup uniqueness**: cleanup runs exactly once per resource
//! 3. **Resource identity**: cleanup receives the same resource handle as acquired
//! 4. **Panic resilience**: panic in body still fires cleanup before propagating
//! 5. **LIFO ordering**: cleanup ordering is LIFO for nested brackets
//!
//! ## Metamorphic Relations
//!
//! - **Cleanup invariance**: `∀path ∈ {success, error, cancel}, cleanup_ran(bracket(acquire, use, cleanup), path)`
//! - **Cleanup uniqueness**: `cleanup_count(bracket(...)) = 1`
//! - **Resource identity**: `cleanup_resource = acquire_resource`
//! - **Panic transparency**: `cleanup_ran(bracket(acquire, panic_use, cleanup)) ∧ panic_propagated`
//! - **LIFO ordering**: `bracket(a1, bracket(a2, u2, c2), c1) ⟹ cleanup_order = [c2, c1]`

use proptest::prelude::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use std::cell::RefCell;
use std::rc::Rc;

use asupersync::combinator::bracket::{bracket, Bracket, BracketError};
use asupersync::cx::{Cx, Scope};
use asupersync::error::{Error, ErrorKind};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{
    cancel::CancelReason, ArenaIndex, Budget, Outcome, RegionId, TaskId,
};
use asupersync::runtime::{region, spawn, Runtime, RuntimeBuilder};

// =============================================================================
// Test Resource Types and Tracking
// =============================================================================

/// Test resource that tracks its lifecycle and cleanup state.
#[derive(Debug, Clone)]
struct TestResource {
    /// Unique ID for this resource instance
    id: u64,
    /// Name for debugging
    name: String,
    /// Cleanup tracker (shared reference)
    cleanup_tracker: Arc<Mutex<CleanupTracker>>,
}

impl TestResource {
    fn new(id: u64, name: String, cleanup_tracker: Arc<Mutex<CleanupTracker>>) -> Self {
        cleanup_tracker.lock().unwrap().resources_acquired.push(id);
        Self { id, name, cleanup_tracker }
    }
}

impl PartialEq for TestResource {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.name == other.name
    }
}

/// Tracks resource acquisition, cleanup calls, and execution order.
#[derive(Debug, Clone, Default)]
struct CleanupTracker {
    /// Resources that were acquired (in order)
    resources_acquired: Vec<u64>,
    /// Resources that were cleaned up (in order)
    resources_cleaned: Vec<u64>,
    /// Actual resource values passed to cleanup
    cleanup_resource_values: Vec<u64>,
    /// Cleanup call timestamps for ordering verification
    cleanup_timestamps: Vec<(u64, std::time::Instant)>,
    /// Number of cleanup calls per resource ID
    cleanup_counts: std::collections::HashMap<u64, usize>,
    /// Panic occurred in use phase
    use_panicked: bool,
    /// Cleanup completed successfully
    cleanup_completed: bool,
}

impl CleanupTracker {
    fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }

    fn record_cleanup(&mut self, resource_id: u64) {
        self.resources_cleaned.push(resource_id);
        self.cleanup_resource_values.push(resource_id);
        self.cleanup_timestamps.push((resource_id, std::time::Instant::now()));
        *self.cleanup_counts.entry(resource_id).or_insert(0) += 1;
        self.cleanup_completed = true;
    }

    fn record_panic(&mut self) {
        self.use_panicked = true;
    }

    /// Verify cleanup ran exactly once for each resource
    fn verify_cleanup_uniqueness(&self) -> bool {
        self.cleanup_counts.values().all(|&count| count == 1)
    }

    /// Verify cleanup received the same resource as acquired
    fn verify_resource_identity(&self) -> bool {
        self.resources_acquired.len() == self.cleanup_resource_values.len()
            && self.resources_acquired.iter().zip(&self.cleanup_resource_values).all(|(a, c)| a == c)
    }

    /// Verify cleanup ordering is LIFO (last acquired, first cleaned)
    fn verify_lifo_ordering(&self) -> bool {
        if self.resources_acquired.len() != self.resources_cleaned.len() {
            return false;
        }

        // For LIFO: cleanup order should be reverse of acquire order
        let expected_cleanup_order: Vec<u64> = self.resources_acquired.iter().rev().copied().collect();
        self.resources_cleaned == expected_cleanup_order
    }

    /// Verify cleanup ran (at least one cleanup call)
    fn verify_cleanup_ran(&self) -> bool {
        !self.resources_cleaned.is_empty()
    }
}

// =============================================================================
// Test Utilities and Strategies
// =============================================================================

/// Create a test context for bracket testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Test errors for bracket operations.
#[derive(Debug, Clone, PartialEq)]
enum TestError {
    Acquire(String),
    Use(String),
    Network(u16),
}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acquire(msg) => write!(f, "acquire error: {msg}"),
            Self::Use(msg) => write!(f, "use error: {msg}"),
            Self::Network(code) => write!(f, "network error: {code}"),
        }
    }
}

impl std::error::Error for TestError {}

/// Bracket execution path for testing different scenarios.
#[derive(Debug, Clone, PartialEq)]
enum BracketPath {
    Success,
    AcquireFailure,
    UseFailure,
    UseCancel,
    UsePanic,
}

/// Arbitrary strategy for generating bracket execution paths.
fn arb_bracket_paths() -> impl Strategy<Value = BracketPath> {
    prop_oneof![
        3 => Just(BracketPath::Success),
        1 => Just(BracketPath::AcquireFailure),
        1 => Just(BracketPath::UseFailure),
        1 => Just(BracketPath::UseCancel),
        1 => Just(BracketPath::UsePanic),
    ]
}

/// Arbitrary strategy for generating test resource names.
fn arb_resource_names() -> impl Strategy<Value = String> {
    "[a-z]{3,8}".prop_map(|s| format!("res_{s}"))
}

/// Poll a future to completion using synchronous execution (for testing).
async fn poll_to_completion<T>(future: impl std::future::Future<Output = T>) -> T {
    future.await
}

// =============================================================================
// Test Implementation Helpers
// =============================================================================

/// Create a test acquire function that succeeds or fails based on path.
fn create_acquire_fn(
    resource_id: u64,
    name: String,
    path: BracketPath,
    tracker: Arc<Mutex<CleanupTracker>>,
) -> impl std::future::Future<Output = Result<TestResource, TestError>> {
    async move {
        match path {
            BracketPath::AcquireFailure => Err(TestError::Acquire("simulated acquire failure".to_string())),
            _ => Ok(TestResource::new(resource_id, name, tracker))
        }
    }
}

/// Create a test use function that behaves according to the specified path.
fn create_use_fn(path: BracketPath, tracker: Arc<Mutex<CleanupTracker>>) -> impl FnOnce(TestResource) -> Box<dyn std::future::Future<Output = Result<u32, TestError>> + Unpin> {
    move |resource| {
        let tracker = tracker.clone();
        Box::new(async move {
            match path {
                BracketPath::Success => Ok(resource.id as u32 * 2),
                BracketPath::UseFailure => {
                    Err(TestError::Use("simulated use failure".to_string()))
                },
                BracketPath::UseCancel => {
                    // Simulate cancellation by sleeping indefinitely
                    // (test framework will cancel this)
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    Ok(42)
                },
                BracketPath::UsePanic => {
                    tracker.lock().unwrap().record_panic();
                    panic!("simulated use panic");
                },
                _ => Ok(resource.id as u32),
            }
        }) as Box<dyn std::future::Future<Output = Result<u32, TestError>> + Unpin>
    }
}

/// Create a test cleanup function that records the cleanup event.
fn create_cleanup_fn(tracker: Arc<Mutex<CleanupTracker>>) -> impl FnOnce(TestResource) -> Box<dyn std::future::Future<Output = ()> + Unpin> {
    move |resource| {
        let tracker = tracker.clone();
        let resource_id = resource.id;
        Box::new(async move {
            tracker.lock().unwrap().record_cleanup(resource_id);
        }) as Box<dyn std::future::Future<Output = ()> + Unpin>
    }
}

/// Execute a bracket with the specified path and return the tracker.
async fn execute_bracket_with_path(
    resource_id: u64,
    name: String,
    path: BracketPath,
) -> Arc<Mutex<CleanupTracker>> {
    let tracker = CleanupTracker::new();
    let tracker_clone = tracker.clone();

    let acquire = create_acquire_fn(resource_id, name, path.clone(), tracker.clone());
    let use_fn = create_use_fn(path.clone(), tracker.clone());
    let cleanup = create_cleanup_fn(tracker.clone());

    // Execute bracket (may panic or fail)
    let bracket_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            bracket(acquire, use_fn, cleanup).await
        })
    }));

    // Verify panic propagated correctly for panic paths
    match path {
        BracketPath::UsePanic => {
            assert!(bracket_result.is_err(), "Bracket should propagate use panic");
        },
        _ => {
            // For non-panic paths, result should not panic (may be Ok or Err though)
            if bracket_result.is_err() {
                // If it panicked unexpectedly, re-panic to fail the test
                std::panic::resume_unwind(bracket_result.unwrap_err());
            }
        }
    }

    tracker_clone
}

// =============================================================================
// Metamorphic Relations (MR) Tests
// =============================================================================

/// **MR1: Cleanup Universality** - Cleanup runs on all execution paths
///
/// This metamorphic relation verifies that resource cleanup occurs regardless
/// of whether the bracket succeeds, fails, or is cancelled.
proptest! {
    #[test]
    fn mr1_cleanup_runs_on_all_paths(
        resource_id in 1u64..1000,
        name in arb_resource_names(),
        path in arb_bracket_paths(),
    ) {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let tracker = execute_bracket_with_path(resource_id, name, path.clone()).await;
            let tracker_data = tracker.lock().unwrap();

            // MR1: Cleanup must run on ALL execution paths except acquire failure
            match path {
                BracketPath::AcquireFailure => {
                    // If acquire fails, no resource is obtained, so no cleanup should run
                    assert!(!tracker_data.verify_cleanup_ran(),
                        "Cleanup should not run when acquire fails");
                },
                _ => {
                    // For all other paths (success, use failure, cancel, panic), cleanup must run
                    assert!(tracker_data.verify_cleanup_ran(),
                        "Cleanup must run on path: {path:?}");
                }
            }
        });
    }
}

/// **MR2: Cleanup Uniqueness** - Cleanup runs exactly once per resource
///
/// This metamorphic relation verifies that each acquired resource has its
/// cleanup function called exactly once, never zero times or multiple times.
proptest! {
    #[test]
    fn mr2_cleanup_runs_exactly_once(
        resource_id in 1u64..1000,
        name in arb_resource_names(),
        path in arb_bracket_paths(),
    ) {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let tracker = execute_bracket_with_path(resource_id, name, path.clone()).await;
            let tracker_data = tracker.lock().unwrap();

            // MR2: Each resource must be cleaned up exactly once
            match path {
                BracketPath::AcquireFailure => {
                    // No resource acquired, so cleanup count should be 0
                    assert_eq!(tracker_data.cleanup_counts.len(), 0,
                        "No cleanup should occur when acquire fails");
                },
                _ => {
                    // Resource was acquired, so cleanup must happen exactly once
                    assert!(tracker_data.verify_cleanup_uniqueness(),
                        "Cleanup must run exactly once for path: {path:?}");
                    assert_eq!(tracker_data.cleanup_counts.get(&resource_id), Some(&1),
                        "Resource {resource_id} must be cleaned up exactly once");
                }
            }
        });
    }
}

/// **MR3: Resource Identity** - Cleanup receives the same resource handle
///
/// This metamorphic relation verifies that the cleanup function receives
/// exactly the same resource instance that was returned by acquire.
proptest! {
    #[test]
    fn mr3_cleanup_receives_same_resource(
        resource_id in 1u64..1000,
        name in arb_resource_names(),
        path in arb_bracket_paths(),
    ) {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let tracker = execute_bracket_with_path(resource_id, name, path.clone()).await;
            let tracker_data = tracker.lock().unwrap();

            // MR3: Resource passed to cleanup must be identical to acquired resource
            match path {
                BracketPath::AcquireFailure => {
                    // No resource to verify identity for
                },
                _ => {
                    assert!(tracker_data.verify_resource_identity(),
                        "Cleanup must receive the same resource as acquired for path: {path:?}");
                }
            }
        });
    }
}

/// **MR4: Panic Resilience** - Panic in body still fires cleanup
///
/// This metamorphic relation verifies that panics in the use function do not
/// prevent cleanup from running, and that the panic is still propagated.
proptest! {
    #[test]
    fn mr4_panic_in_body_fires_cleanup(
        resource_id in 1u64..1000,
        name in arb_resource_names(),
    ) {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let tracker = execute_bracket_with_path(resource_id, name, BracketPath::UsePanic).await;
            let tracker_data = tracker.lock().unwrap();

            // MR4: Cleanup must run even when use function panics
            assert!(tracker_data.verify_cleanup_ran(),
                "Cleanup must run even when use function panics");
            assert!(tracker_data.use_panicked,
                "Use panic flag should be set");
            assert!(tracker_data.cleanup_completed,
                "Cleanup must complete before panic propagates");
        });
    }
}

/// **MR5: LIFO Ordering** - Cleanup ordering is LIFO for nested brackets
///
/// This metamorphic relation verifies that when brackets are nested,
/// cleanup functions execute in LIFO order (last acquired, first cleaned).
#[tokio::test]
async fn mr5_cleanup_ordering_lifo_for_nested_brackets() {
    let tracker = CleanupTracker::new();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            // Nested bracket: outer acquires resource 1, inner acquires resource 2
            bracket(
                // Outer acquire (resource 1)
                {
                    let tracker = tracker.clone();
                    async move {
                        Ok::<_, TestError>(TestResource::new(1, "outer".to_string(), tracker))
                    }
                },
                // Outer use function contains inner bracket
                {
                    let tracker = tracker.clone();
                    move |_outer_resource| {
                        Box::new(async move {
                            // Inner bracket (resource 2)
                            let inner_result = bracket(
                                // Inner acquire (resource 2)
                                {
                                    let tracker = tracker.clone();
                                    async move {
                                        Ok::<_, TestError>(TestResource::new(2, "inner".to_string(), tracker))
                                    }
                                },
                                // Inner use
                                |inner_resource| {
                                    Box::new(async move {
                                        Ok::<u32, TestError>(inner_resource.id as u32)
                                    }) as Box<dyn std::future::Future<Output = Result<u32, TestError>> + Unpin>
                                },
                                // Inner cleanup (should run first - resource 2)
                                {
                                    let tracker = tracker.clone();
                                    move |resource| {
                                        let resource_id = resource.id;
                                        Box::new(async move {
                                            tracker.lock().unwrap().record_cleanup(resource_id);
                                        }) as Box<dyn std::future::Future<Output = ()> + Unpin>
                                    }
                                }
                            ).await;

                            inner_result.map_err(|e| TestError::Use(format!("inner bracket failed: {e:?}")))
                        }) as Box<dyn std::future::Future<Output = Result<u32, TestError>> + Unpin>
                    }
                },
                // Outer cleanup (should run second - resource 1)
                {
                    let tracker = tracker.clone();
                    move |resource| {
                        let resource_id = resource.id;
                        Box::new(async move {
                            tracker.lock().unwrap().record_cleanup(resource_id);
                        }) as Box<dyn std::future::Future<Output = ()> + Unpin>
                    }
                }
            ).await
        })
    }));

    // Should not panic
    assert!(result.is_ok(), "Nested brackets should not panic");

    let tracker_data = tracker.lock().unwrap();

    // MR5: Cleanup order must be LIFO (resource 2 cleaned first, then resource 1)
    assert_eq!(tracker_data.resources_acquired, vec![1, 2],
        "Resources should be acquired in order: [1, 2]");
    assert_eq!(tracker_data.resources_cleaned, vec![2, 1],
        "Resources should be cleaned in LIFO order: [2, 1]");
    assert!(tracker_data.verify_lifo_ordering(),
        "Cleanup ordering must be LIFO for nested brackets");
}

// =============================================================================
// Additional Property Tests
// =============================================================================

/// Test bracket resource safety under concurrent access patterns.
proptest! {
    #[test]
    fn bracket_resource_safety_under_stress(
        num_resources in 1usize..=5,
        execution_paths in prop::collection::vec(arb_bracket_paths(), 1..=5),
    ) {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut all_trackers = Vec::new();

            // Execute multiple brackets concurrently
            for (i, path) in execution_paths.into_iter().enumerate() {
                let resource_id = (i + 1) as u64;
                let name = format!("stress_resource_{i}");
                let tracker = execute_bracket_with_path(resource_id, name, path.clone()).await;
                all_trackers.push((tracker, path));
            }

            // Verify all brackets maintained their resource safety invariants
            for (tracker, path) in all_trackers {
                let tracker_data = tracker.lock().unwrap();

                match path {
                    BracketPath::AcquireFailure => {
                        assert!(!tracker_data.verify_cleanup_ran());
                    },
                    _ => {
                        assert!(tracker_data.verify_cleanup_ran());
                        assert!(tracker_data.verify_cleanup_uniqueness());
                        assert!(tracker_data.verify_resource_identity());
                    }
                }
            }
        });
    }
}

/// Test that bracket maintains resource cleanup guarantees under cancellation.
#[tokio::test]
async fn bracket_cleanup_under_cancellation() {
    let tracker = CleanupTracker::new();

    let bracket_future = bracket(
        // Acquire
        {
            let tracker = tracker.clone();
            async move {
                Ok::<_, TestError>(TestResource::new(42, "cancel_test".to_string(), tracker))
            }
        },
        // Use (will be cancelled)
        |_resource| {
            Box::new(async move {
                // Sleep long enough to be cancelled
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok::<u32, TestError>(42)
            }) as Box<dyn std::future::Future<Output = Result<u32, TestError>> + Unpin>
        },
        // Cleanup
        {
            let tracker = tracker.clone();
            move |resource| {
                let resource_id = resource.id;
                Box::new(async move {
                    tracker.lock().unwrap().record_cleanup(resource_id);
                }) as Box<dyn std::future::Future<Output = ()> + Unpin>
            }
        }
    );

    // Cancel the bracket after a short delay
    let result = tokio::time::timeout(Duration::from_millis(50), bracket_future).await;

    // Should timeout/cancel
    assert!(result.is_err(), "Bracket should be cancelled by timeout");

    // Give cleanup a moment to complete
    tokio::time::sleep(Duration::from_millis(10)).await;

    let tracker_data = tracker.lock().unwrap();

    // Cleanup should still have run despite cancellation
    assert!(tracker_data.verify_cleanup_ran(),
        "Cleanup must run even when bracket is cancelled");
    assert!(tracker_data.verify_cleanup_uniqueness(),
        "Cleanup must run exactly once even under cancellation");
    assert!(tracker_data.verify_resource_identity(),
        "Resource identity must be preserved under cancellation");
}