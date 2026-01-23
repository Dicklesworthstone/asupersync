//! Comprehensive cancel attribution test suite.
//!
//! This module tests the cancel attribution system including:
//! - CancelReason construction and manipulation
//! - CancelKind variants and behavior
//! - Cx API for cancel attribution access
//! - E2E debugging workflow scenarios
//! - Metrics collection patterns
//!
//! # Spec References
//!
//! - Spec 3.3: Cancel reason attribution and strengthening
//! - Spec 3.4: Nested cancellation semantics
//!
//! # Test Infrastructure
//!
//! All tests use the shared test utilities from `common`:
//! - `init_test_logging()` for trace-level output
//! - `test_phase!()` / `test_section!()` for structured output
//! - `assert_with_log!()` for detailed assertion messages

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::types::{CancelKind, CancelReason, RegionId, TaskId};
use common::*;
use std::collections::HashMap;

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// CancelReason Construction Tests
// ============================================================================

/// Test basic CancelReason construction with all fields.
#[test]
fn cancel_reason_basic_construction() {
    init_test("cancel_reason_basic_construction");

    test_section!("user cancellation");
    let reason = CancelReason::user("stop");
    assert_eq!(reason.kind, CancelKind::User);
    assert_eq!(reason.message, Some("stop"));
    tracing::info!(kind = ?reason.kind, "User cancellation constructed");

    test_section!("timeout cancellation");
    let reason = CancelReason::timeout();
    assert_eq!(reason.kind, CancelKind::Timeout);
    tracing::info!(kind = ?reason.kind, "Timeout cancellation constructed");

    test_section!("deadline cancellation");
    let reason = CancelReason::deadline();
    assert_eq!(reason.kind, CancelKind::Deadline);
    tracing::info!(kind = ?reason.kind, "Deadline cancellation constructed");

    test_section!("poll quota cancellation");
    let reason = CancelReason::poll_quota();
    assert_eq!(reason.kind, CancelKind::PollQuota);
    tracing::info!(kind = ?reason.kind, "Poll quota cancellation constructed");

    test_section!("cost budget cancellation");
    let reason = CancelReason::cost_budget();
    assert_eq!(reason.kind, CancelKind::CostBudget);
    tracing::info!(kind = ?reason.kind, "Cost budget cancellation constructed");

    test_section!("shutdown cancellation");
    let reason = CancelReason::shutdown();
    assert_eq!(reason.kind, CancelKind::Shutdown);
    tracing::info!(kind = ?reason.kind, "Shutdown cancellation constructed");

    test_section!("parent cancelled");
    let reason = CancelReason::parent_cancelled();
    assert_eq!(reason.kind, CancelKind::ParentCancelled);
    tracing::info!(kind = ?reason.kind, "Parent cancelled constructed");

    test_section!("resource unavailable");
    let reason = CancelReason::resource_unavailable();
    assert_eq!(reason.kind, CancelKind::ResourceUnavailable);
    tracing::info!(kind = ?reason.kind, "Resource unavailable constructed");

    test_section!("race lost");
    let reason = CancelReason::race_lost();
    assert_eq!(reason.kind, CancelKind::RaceLost);
    tracing::info!(kind = ?reason.kind, "Race lost constructed");

    test_section!("fail fast");
    let reason = CancelReason::fail_fast();
    assert_eq!(reason.kind, CancelKind::FailFast);
    tracing::info!(kind = ?reason.kind, "Fail fast constructed");

    test_complete!("cancel_reason_basic_construction");
}

/// Test CancelReason with builder methods.
#[test]
fn cancel_reason_builder_methods() {
    init_test("cancel_reason_builder_methods");

    test_section!("with_message");
    let reason = CancelReason::user("initial").with_message("updated message");
    assert_eq!(reason.message, Some("updated message"));
    tracing::info!(message = ?reason.message, "Message updated");

    test_section!("with_region");
    let region = RegionId::new_for_test(42, 0);
    let reason = CancelReason::timeout().with_region(region);
    assert_eq!(reason.origin_region, region);
    tracing::info!(region = ?reason.origin_region, "Region set");

    test_section!("with_task");
    let task = TaskId::new_for_test(123, 0);
    let reason = CancelReason::deadline().with_task(task);
    assert_eq!(reason.origin_task, Some(task));
    tracing::info!(task = ?reason.origin_task, "Task set");

    test_section!("chained builder calls");
    let region = RegionId::new_for_test(1, 0);
    let task = TaskId::new_for_test(2, 0);
    let reason = CancelReason::shutdown()
        .with_region(region)
        .with_task(task)
        .with_message("graceful shutdown");
    assert_eq!(reason.kind, CancelKind::Shutdown);
    assert_eq!(reason.origin_region, region);
    assert_eq!(reason.origin_task, Some(task));
    assert_eq!(reason.message, Some("graceful shutdown"));
    tracing::info!(
        kind = ?reason.kind,
        region = ?reason.origin_region,
        task = ?reason.origin_task,
        message = ?reason.message,
        "Fully configured reason"
    );

    test_complete!("cancel_reason_builder_methods");
}

// ============================================================================
// Cause Chain Tests
// ============================================================================

/// Test cause chain construction and traversal.
#[test]
fn cancel_reason_cause_chain_construction() {
    init_test("cancel_reason_cause_chain_construction");

    test_section!("single cause");
    let root = CancelReason::deadline().with_message("5 second timeout");
    let child = CancelReason::parent_cancelled().with_cause(root);

    let chain: Vec<_> = child.chain().collect();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].kind, CancelKind::ParentCancelled);
    assert_eq!(chain[1].kind, CancelKind::Deadline);
    tracing::info!(chain_len = chain.len(), "Two-level chain constructed");

    test_section!("multi-level cause chain");
    let root = CancelReason::deadline()
        .with_region(RegionId::new_for_test(1, 0))
        .with_message("5 second timeout");
    let middle1 = CancelReason::parent_cancelled()
        .with_region(RegionId::new_for_test(2, 0))
        .with_cause(root);
    let middle2 = CancelReason::parent_cancelled()
        .with_region(RegionId::new_for_test(3, 0))
        .with_cause(middle1);
    let leaf = CancelReason::parent_cancelled()
        .with_region(RegionId::new_for_test(4, 0))
        .with_cause(middle2);

    let chain: Vec<_> = leaf.chain().collect();
    assert_eq!(chain.len(), 4);

    // Order: leaf -> middle2 -> middle1 -> root
    assert_eq!(chain[0].origin_region, RegionId::new_for_test(4, 0));
    assert_eq!(chain[1].origin_region, RegionId::new_for_test(3, 0));
    assert_eq!(chain[2].origin_region, RegionId::new_for_test(2, 0));
    assert_eq!(chain[3].origin_region, RegionId::new_for_test(1, 0));

    tracing::info!("Cancel chain (4 levels):");
    for (depth, cause) in chain.iter().enumerate() {
        tracing::info!(
            depth = depth,
            kind = ?cause.kind,
            region = ?cause.origin_region,
            message = ?cause.message,
            "  {} {:?}",
            "└─".repeat(depth + 1),
            cause.kind
        );
    }

    test_complete!("cancel_reason_cause_chain_construction");
}

/// Test root_cause() with various chain depths.
#[test]
fn cancel_reason_root_cause() {
    init_test("cancel_reason_root_cause");

    test_section!("single reason (is its own root)");
    let single = CancelReason::timeout().with_message("request timeout");
    let root = single.root_cause();
    assert_eq!(root.kind, CancelKind::Timeout);
    assert_eq!(root.message, Some("request timeout"));
    tracing::info!(root_kind = ?root.kind, "Single reason is its own root");

    test_section!("two-level chain");
    let root = CancelReason::deadline().with_message("2 second deadline");
    let child = CancelReason::parent_cancelled().with_cause(root.clone());
    let found_root = child.root_cause();
    assert_eq!(found_root.kind, CancelKind::Deadline);
    assert_eq!(found_root.message, root.message);
    tracing::info!(root_kind = ?found_root.kind, "Two-level root found");

    test_section!("five-level chain");
    let deep_root = CancelReason::poll_quota()
        .with_message("exceeded 1000 polls")
        .with_region(RegionId::new_for_test(1, 0));
    let level2 = CancelReason::parent_cancelled()
        .with_region(RegionId::new_for_test(2, 0))
        .with_cause(deep_root.clone());
    let level3 = CancelReason::parent_cancelled()
        .with_region(RegionId::new_for_test(3, 0))
        .with_cause(level2);
    let level4 = CancelReason::parent_cancelled()
        .with_region(RegionId::new_for_test(4, 0))
        .with_cause(level3);
    let level5 = CancelReason::parent_cancelled()
        .with_region(RegionId::new_for_test(5, 0))
        .with_cause(level4);

    let found_root = level5.root_cause();
    assert_eq!(found_root.kind, CancelKind::PollQuota);
    assert_eq!(found_root.message, Some("exceeded 1000 polls"));
    assert_eq!(found_root.origin_region, RegionId::new_for_test(1, 0));
    tracing::info!(
        root_kind = ?found_root.kind,
        root_region = ?found_root.origin_region,
        "Found root cause through 5-level chain"
    );

    test_complete!("cancel_reason_root_cause");
}

/// Test any_cause_is() chain traversal.
#[test]
fn cancel_reason_any_cause_is() {
    init_test("cancel_reason_any_cause_is");

    test_section!("single reason");
    let single = CancelReason::timeout();
    assert!(single.any_cause_is(CancelKind::Timeout));
    assert!(!single.any_cause_is(CancelKind::Deadline));
    tracing::info!("Single reason: any_cause_is works");

    test_section!("chain with mixed kinds");
    let root = CancelReason::poll_quota();
    let middle = CancelReason::parent_cancelled().with_cause(root);
    let leaf = CancelReason::parent_cancelled().with_cause(middle);

    // Immediate is ParentCancelled
    assert_eq!(leaf.kind, CancelKind::ParentCancelled);

    // PollQuota is in the chain
    assert!(leaf.any_cause_is(CancelKind::PollQuota));
    assert!(leaf.any_cause_is(CancelKind::ParentCancelled));

    // These are not in the chain
    assert!(!leaf.any_cause_is(CancelKind::Deadline));
    assert!(!leaf.any_cause_is(CancelKind::Timeout));
    assert!(!leaf.any_cause_is(CancelKind::Shutdown));

    tracing::info!("any_cause_is() correctly traverses chain");

    test_complete!("cancel_reason_any_cause_is");
}

// ============================================================================
// CancelKind Tests
// ============================================================================

/// Test all CancelKind variants are constructible.
#[test]
fn cancel_kind_all_variants_constructible() {
    init_test("cancel_kind_all_variants_constructible");

    let kinds = vec![
        CancelKind::User,
        CancelKind::Timeout,
        CancelKind::Deadline,
        CancelKind::PollQuota,
        CancelKind::CostBudget,
        CancelKind::ParentCancelled,
        CancelKind::Shutdown,
        CancelKind::ResourceUnavailable,
        CancelKind::RaceLost,
        CancelKind::FailFast,
    ];

    for kind in kinds {
        let reason = CancelReason::new(kind);
        assert_eq!(reason.kind, kind);
        tracing::debug!(kind = ?kind, "CancelKind variant works");
    }

    tracing::info!(variant_count = 10, "All CancelKind variants constructible");

    test_complete!("cancel_kind_all_variants_constructible");
}

/// Test CancelKind implements Eq and Hash.
#[test]
fn cancel_kind_eq_and_hash() {
    init_test("cancel_kind_eq_and_hash");

    use std::collections::HashSet;

    test_section!("equality");
    assert_eq!(CancelKind::User, CancelKind::User);
    assert_ne!(CancelKind::User, CancelKind::Timeout);
    tracing::info!("Equality works");

    test_section!("hash set membership");
    let mut set = HashSet::new();
    set.insert(CancelKind::User);
    set.insert(CancelKind::Deadline);
    set.insert(CancelKind::Shutdown);

    assert!(set.contains(&CancelKind::User));
    assert!(set.contains(&CancelKind::Deadline));
    assert!(set.contains(&CancelKind::Shutdown));
    assert!(!set.contains(&CancelKind::Timeout));
    assert!(!set.contains(&CancelKind::PollQuota));

    tracing::info!(set_size = set.len(), "HashSet works with CancelKind");

    test_section!("hash map key");
    let mut map: HashMap<CancelKind, &str> = HashMap::new();
    map.insert(CancelKind::Timeout, "request timed out");
    map.insert(CancelKind::Deadline, "deadline exceeded");

    assert_eq!(map.get(&CancelKind::Timeout), Some(&"request timed out"));
    assert_eq!(map.get(&CancelKind::Deadline), Some(&"deadline exceeded"));
    assert_eq!(map.get(&CancelKind::Shutdown), None);

    tracing::info!(map_size = map.len(), "HashMap works with CancelKind");

    test_complete!("cancel_kind_eq_and_hash");
}

// ============================================================================
// Cx Cancel Attribution API Tests
// ============================================================================

/// Test cancel_with() stores reason correctly.
#[test]
fn cx_cancel_with_stores_reason() {
    init_test("cx_cancel_with_stores_reason");

    let cx = Cx::for_testing();
    assert!(cx.cancel_reason().is_none());

    test_section!("cancel with message");
    cx.cancel_with(CancelKind::User, Some("User pressed Ctrl+C"));

    assert!(cx.is_cancel_requested());
    let reason = cx.cancel_reason().expect("should have reason");

    assert_eq!(reason.kind, CancelKind::User);
    assert_eq!(reason.message, Some("User pressed Ctrl+C"));

    tracing::info!(
        kind = ?reason.kind,
        message = ?reason.message,
        "Cancel reason stored correctly"
    );

    test_complete!("cx_cancel_with_stores_reason");
}

/// Test cancel_with() without message.
#[test]
fn cx_cancel_with_no_message() {
    init_test("cx_cancel_with_no_message");

    let cx = Cx::for_testing();
    cx.cancel_with(CancelKind::Timeout, None);

    let reason = cx.cancel_reason().expect("should have reason");
    assert_eq!(reason.kind, CancelKind::Timeout);
    assert!(reason.message.is_none());

    tracing::info!(kind = ?reason.kind, "Cancel without message works");

    test_complete!("cx_cancel_with_no_message");
}

/// Test cancel_chain() API.
#[test]
fn cx_cancel_chain_api() {
    init_test("cx_cancel_chain_api");

    let cx = Cx::for_testing();

    test_section!("empty chain when not cancelled");
    let chain: Vec<_> = cx.cancel_chain().collect();
    assert!(chain.is_empty());
    tracing::info!("Empty chain when not cancelled");

    test_section!("chain with set reason");
    // Build: ParentCancelled -> ParentCancelled -> Deadline
    let deadline = CancelReason::deadline().with_message("handler timeout");
    let parent1 = CancelReason::parent_cancelled().with_cause(deadline);
    let parent2 = CancelReason::parent_cancelled().with_cause(parent1);

    cx.set_cancel_reason(parent2);

    let chain: Vec<_> = cx.cancel_chain().collect();
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].kind, CancelKind::ParentCancelled);
    assert_eq!(chain[1].kind, CancelKind::ParentCancelled);
    assert_eq!(chain[2].kind, CancelKind::Deadline);

    tracing::info!(chain_len = chain.len(), "Cancel chain traversed");
    for (i, cause) in chain.iter().enumerate() {
        tracing::debug!(
            depth = i,
            kind = ?cause.kind,
            message = ?cause.message,
            "Chain element"
        );
    }

    test_complete!("cx_cancel_chain_api");
}

/// Test root_cancel_cause() API.
#[test]
fn cx_root_cancel_cause_api() {
    init_test("cx_root_cancel_cause_api");

    let cx = Cx::for_testing();

    test_section!("none when not cancelled");
    assert!(cx.root_cancel_cause().is_none());
    tracing::info!("No root cause when not cancelled");

    test_section!("single reason is its own root");
    let cx = Cx::for_testing();
    cx.cancel_with(CancelKind::Shutdown, Some("graceful shutdown"));

    let root = cx.root_cancel_cause().expect("should have root");
    assert_eq!(root.kind, CancelKind::Shutdown);
    assert_eq!(root.message, Some("graceful shutdown"));
    tracing::info!(root_kind = ?root.kind, "Single reason is its own root");

    test_section!("deep chain root cause");
    let cx = Cx::for_testing();
    let deep_root = CancelReason::cost_budget().with_message("cost limit exceeded");
    let level1 = CancelReason::parent_cancelled().with_cause(deep_root);
    let level2 = CancelReason::parent_cancelled().with_cause(level1);
    let level3 = CancelReason::parent_cancelled().with_cause(level2);

    cx.set_cancel_reason(level3);

    let root = cx.root_cancel_cause().expect("should have root");
    assert_eq!(root.kind, CancelKind::CostBudget);
    assert_eq!(root.message, Some("cost limit exceeded"));
    tracing::info!(
        root_kind = ?root.kind,
        root_message = ?root.message,
        "Found root cause through nested regions"
    );

    test_complete!("cx_root_cancel_cause_api");
}

/// Test cancelled_by() API (immediate reason check).
#[test]
fn cx_cancelled_by_api() {
    init_test("cx_cancelled_by_api");

    let cx = Cx::for_testing();

    test_section!("false when not cancelled");
    assert!(!cx.cancelled_by(CancelKind::User));
    assert!(!cx.cancelled_by(CancelKind::Timeout));
    tracing::info!("Returns false when not cancelled");

    test_section!("checks immediate reason only");
    // Build: ParentCancelled -> Deadline
    let deadline = CancelReason::deadline();
    let parent = CancelReason::parent_cancelled().with_cause(deadline);

    cx.set_cancel_reason(parent);

    // Immediate reason is ParentCancelled
    assert!(cx.cancelled_by(CancelKind::ParentCancelled));
    // Deadline is in chain but not immediate
    assert!(!cx.cancelled_by(CancelKind::Deadline));
    // Other kinds are false
    assert!(!cx.cancelled_by(CancelKind::Timeout));
    assert!(!cx.cancelled_by(CancelKind::Shutdown));

    tracing::info!("cancelled_by() checks immediate reason only");

    test_complete!("cx_cancelled_by_api");
}

/// Test any_cause_is() API (chain traversal).
#[test]
fn cx_any_cause_is_api() {
    init_test("cx_any_cause_is_api");

    let cx = Cx::for_testing();

    test_section!("false when not cancelled");
    assert!(!cx.any_cause_is(CancelKind::Timeout));
    tracing::info!("Returns false when not cancelled");

    test_section!("searches entire chain");
    // Build: ParentCancelled -> ParentCancelled -> Timeout
    let timeout = CancelReason::timeout().with_message("request timeout");
    let parent1 = CancelReason::parent_cancelled().with_cause(timeout);
    let parent2 = CancelReason::parent_cancelled().with_cause(parent1);

    cx.set_cancel_reason(parent2);

    // All kinds in the chain return true
    assert!(cx.any_cause_is(CancelKind::ParentCancelled));
    assert!(cx.any_cause_is(CancelKind::Timeout));

    // Kinds not in chain return false
    assert!(!cx.any_cause_is(CancelKind::Deadline));
    assert!(!cx.any_cause_is(CancelKind::Shutdown));
    assert!(!cx.any_cause_is(CancelKind::PollQuota));

    tracing::info!("any_cause_is() searches entire chain");

    test_complete!("cx_any_cause_is_api");
}

/// Test cancel_fast() for performance-critical path.
#[test]
fn cx_cancel_fast_api() {
    init_test("cx_cancel_fast_api");

    let cx = Cx::for_testing();
    assert!(!cx.is_cancel_requested());

    test_section!("cancel_fast sets flag and reason");
    cx.cancel_fast(CancelKind::RaceLost);

    assert!(cx.is_cancel_requested());
    let reason = cx.cancel_reason().expect("should have reason");
    assert_eq!(reason.kind, CancelKind::RaceLost);
    tracing::info!(kind = ?reason.kind, "cancel_fast works");

    test_section!("cancel_fast has no cause chain");
    assert!(reason.cause.is_none());
    tracing::info!("cancel_fast creates minimal reason");

    test_section!("cancel_fast has no message");
    assert!(reason.message.is_none());
    tracing::info!("cancel_fast has no message");

    test_complete!("cx_cancel_fast_api");
}

// ============================================================================
// E2E Tests
// ============================================================================

/// E2E test demonstrating a real-world debugging workflow.
///
/// This test simulates what a developer would do when debugging a cancelled
/// request: inspect the cancel chain, find the root cause, and determine
/// actionable insights.
#[test]
fn e2e_debugging_workflow() {
    init_test("e2e_debugging_workflow");

    tracing::info!("═══════════════════════════════════════════");
    tracing::info!("E2E: Cancel Attribution Debugging Workflow");
    tracing::info!("═══════════════════════════════════════════");

    // Simulate a request that was cancelled due to a nested timeout structure:
    // - Service-level timeout: 5 seconds
    // - Handler timeout: 1 second
    // - Database timeout: 100ms (this triggered first)

    test_section!("Simulating nested timeout cancellation");

    // Build the cause chain representing what happened:
    // The database timeout (100ms) fired first, which propagated up
    let db_timeout = CancelReason::deadline()
        .with_region(RegionId::new_for_test(3, 0))
        .with_message("database query timeout (100ms)");

    let handler_cancelled = CancelReason::parent_cancelled()
        .with_region(RegionId::new_for_test(2, 0))
        .with_cause(db_timeout);

    let service_cancelled = CancelReason::parent_cancelled()
        .with_region(RegionId::new_for_test(1, 0))
        .with_cause(handler_cancelled);

    // Now simulate the debugging workflow
    let cx = Cx::for_testing();
    cx.set_cancel_reason(service_cancelled);

    test_section!("Debugging investigation");

    tracing::info!("Request was cancelled - investigating...");

    if let Some(reason) = cx.cancel_reason() {
        // Step 1: Print the full chain for observability
        tracing::info!("Cancel attribution chain:");
        for (depth, cause) in reason.chain().enumerate() {
            let indent = "  ".repeat(depth);
            tracing::info!(
                "{}{:?} at region {:?} ({:?})",
                indent,
                cause.kind,
                cause.origin_region,
                cause.message.unwrap_or("no message")
            );
        }

        // Step 2: Find the root cause
        let root = reason.root_cause();
        tracing::info!(
            "Root cause: {:?} at region {:?}",
            root.kind,
            root.origin_region
        );

        // Step 3: Determine actionable insight
        if root.kind == CancelKind::Deadline {
            tracing::warn!("Root cause: Deadline at region {:?}", root.origin_region);
            tracing::warn!("Consider: Increase timeout or optimize query");

            // Verify the chain structure
            assert_eq!(root.message, Some("database query timeout (100ms)"));
        }

        // Step 4: Check if any cause is a specific type
        if cx.any_cause_is(CancelKind::Deadline) {
            tracing::info!("Cancellation was due to a deadline somewhere in the chain");
        }
    }

    // Verify assertions
    assert!(cx.cancelled_by(CancelKind::ParentCancelled));
    assert!(cx.any_cause_is(CancelKind::Deadline));
    assert!(!cx.any_cause_is(CancelKind::Timeout));

    let root = cx.root_cancel_cause().expect("should have root");
    assert_eq!(root.kind, CancelKind::Deadline);
    assert_eq!(root.origin_region, RegionId::new_for_test(3, 0));

    tracing::info!("═══════════════════════════════════════════");
    tracing::info!("E2E debugging workflow completed");
    tracing::info!("═══════════════════════════════════════════");

    test_complete!("e2e_debugging_workflow");
}

/// E2E test demonstrating metrics collection from cancellation reasons.
///
/// This test shows how to aggregate cancellation statistics for monitoring
/// and observability dashboards.
#[test]
fn e2e_metrics_collection() {
    init_test("e2e_metrics_collection");

    tracing::info!("═══════════════════════════════════════════");
    tracing::info!("E2E: Cancel Attribution Metrics Collection");
    tracing::info!("═══════════════════════════════════════════");

    /// Simple metrics structure for tracking cancellation statistics.
    struct CancelMetrics {
        by_kind: HashMap<CancelKind, usize>,
        by_root_kind: HashMap<CancelKind, usize>,
        total_chain_depth: usize,
        count: usize,
    }

    impl CancelMetrics {
        fn new() -> Self {
            Self {
                by_kind: HashMap::new(),
                by_root_kind: HashMap::new(),
                total_chain_depth: 0,
                count: 0,
            }
        }

        fn record(&mut self, reason: &CancelReason) {
            // Count by immediate kind
            *self.by_kind.entry(reason.kind).or_insert(0) += 1;

            // Count by root cause kind
            let root = reason.root_cause();
            *self.by_root_kind.entry(root.kind).or_insert(0) += 1;

            // Track chain depth
            let depth = reason.chain().count();
            self.total_chain_depth += depth;
            self.count += 1;
        }

        fn average_chain_depth(&self) -> f64 {
            if self.count > 0 {
                self.total_chain_depth as f64 / self.count as f64
            } else {
                0.0
            }
        }
    }

    let mut metrics = CancelMetrics::new();

    test_section!("Simulating various cancellation scenarios");

    // Scenario 1: Direct timeout
    let timeout_reason = CancelReason::timeout().with_message("request timeout");
    metrics.record(&timeout_reason);
    tracing::debug!("Recorded: direct timeout");

    // Scenario 2: Deadline through one level of propagation
    let deadline = CancelReason::deadline();
    let propagated1 = CancelReason::parent_cancelled().with_cause(deadline);
    metrics.record(&propagated1);
    tracing::debug!("Recorded: deadline with 1 propagation level");

    // Scenario 3: Poll quota through two levels
    let poll_quota = CancelReason::poll_quota();
    let level1 = CancelReason::parent_cancelled().with_cause(poll_quota);
    let level2 = CancelReason::parent_cancelled().with_cause(level1);
    metrics.record(&level2);
    tracing::debug!("Recorded: poll quota with 2 propagation levels");

    // Scenario 4: Cost budget through three levels
    let cost = CancelReason::cost_budget();
    let c1 = CancelReason::parent_cancelled().with_cause(cost);
    let c2 = CancelReason::parent_cancelled().with_cause(c1);
    let c3 = CancelReason::parent_cancelled().with_cause(c2);
    metrics.record(&c3);
    tracing::debug!("Recorded: cost budget with 3 propagation levels");

    // Scenario 5: Direct shutdown
    let shutdown = CancelReason::shutdown();
    metrics.record(&shutdown);
    tracing::debug!("Recorded: direct shutdown");

    // Scenario 6: Another timeout with propagation
    let timeout2 = CancelReason::timeout();
    let t1 = CancelReason::parent_cancelled().with_cause(timeout2);
    metrics.record(&t1);
    tracing::debug!("Recorded: timeout with 1 propagation level");

    test_section!("Metrics summary");

    tracing::info!("═══════════════════════════════════════════");
    tracing::info!("Cancellation metrics collected:");
    tracing::info!("═══════════════════════════════════════════");

    tracing::info!("By immediate kind:");
    for (kind, count) in &metrics.by_kind {
        tracing::info!("  {:?}: {}", kind, count);
    }

    tracing::info!("By root cause kind:");
    for (kind, count) in &metrics.by_root_kind {
        tracing::info!("  {:?}: {}", kind, count);
    }

    tracing::info!("Average chain depth: {:.2}", metrics.average_chain_depth());
    tracing::info!("Total cancellations: {}", metrics.count);

    // Verify metrics
    assert_eq!(metrics.count, 6);
    assert_eq!(*metrics.by_kind.get(&CancelKind::Timeout).unwrap_or(&0), 1);
    assert_eq!(
        *metrics
            .by_kind
            .get(&CancelKind::ParentCancelled)
            .unwrap_or(&0),
        4
    );
    assert_eq!(*metrics.by_kind.get(&CancelKind::Shutdown).unwrap_or(&0), 1);

    // Root cause distribution should be different
    assert_eq!(
        *metrics.by_root_kind.get(&CancelKind::Timeout).unwrap_or(&0),
        2
    ); // 2 timeouts
    assert_eq!(
        *metrics
            .by_root_kind
            .get(&CancelKind::Deadline)
            .unwrap_or(&0),
        1
    );
    assert_eq!(
        *metrics
            .by_root_kind
            .get(&CancelKind::PollQuota)
            .unwrap_or(&0),
        1
    );
    assert_eq!(
        *metrics
            .by_root_kind
            .get(&CancelKind::CostBudget)
            .unwrap_or(&0),
        1
    );
    assert_eq!(
        *metrics
            .by_root_kind
            .get(&CancelKind::Shutdown)
            .unwrap_or(&0),
        1
    );

    // Total chain depth: 1 + 2 + 3 + 4 + 1 + 2 = 13
    // Average: 13 / 6 = 2.166...
    let avg = metrics.average_chain_depth();
    assert!(avg > 2.0 && avg < 2.5, "Average chain depth: {}", avg);

    tracing::info!("═══════════════════════════════════════════");
    tracing::info!("E2E metrics collection completed");
    tracing::info!("═══════════════════════════════════════════");

    test_complete!("e2e_metrics_collection");
}

/// E2E test demonstrating severity-based handling of cancellations.
///
/// Different cancel kinds have different severities and cleanup budgets,
/// which affects how handlers should respond.
#[test]
fn e2e_severity_based_handling() {
    init_test("e2e_severity_based_handling");

    tracing::info!("═══════════════════════════════════════════");
    tracing::info!("E2E: Severity-Based Cancellation Handling");
    tracing::info!("═══════════════════════════════════════════");

    test_section!("Testing cleanup budget for different reasons");

    // User cancellation - allows full cleanup
    let user_reason = CancelReason::user("graceful stop");
    let user_budget = user_reason.cleanup_budget();
    tracing::info!(
        budget = ?user_budget,
        kind = ?user_reason.kind,
        "User cancellation cleanup budget"
    );

    // Shutdown - more urgent, less cleanup budget
    let shutdown_reason = CancelReason::shutdown();
    let shutdown_budget = shutdown_reason.cleanup_budget();
    tracing::info!(
        budget = ?shutdown_budget,
        kind = ?shutdown_reason.kind,
        "Shutdown cancellation cleanup budget"
    );

    test_section!("Testing severity ordering");

    // Verify severity is properly ordered
    let severities: Vec<(CancelKind, _)> = vec![
        (CancelKind::User, CancelReason::user("test").severity()),
        (CancelKind::Timeout, CancelReason::timeout().severity()),
        (CancelKind::Deadline, CancelReason::deadline().severity()),
        (CancelKind::Shutdown, CancelReason::shutdown().severity()),
    ];

    tracing::info!("Severity ordering:");
    for (kind, severity) in &severities {
        tracing::info!("  {:?}: {:?}", kind, severity);
    }

    test_section!("Demonstrating strengthening");

    // When multiple cancellations occur, the more severe one should win
    let mut user = CancelReason::user("user stop");
    let shutdown = CancelReason::shutdown();

    let was_strengthened = user.strengthen(&shutdown);
    assert!(
        was_strengthened,
        "should be strengthened when shutdown > user"
    );
    assert_eq!(user.kind, CancelKind::Shutdown);
    tracing::info!(
        original = ?CancelKind::User,
        strengthened_to = ?user.kind,
        "Cancellation strengthened to more severe"
    );

    tracing::info!("═══════════════════════════════════════════");
    tracing::info!("E2E severity-based handling completed");
    tracing::info!("═══════════════════════════════════════════");

    test_complete!("e2e_severity_based_handling");
}

/// Integration test: realistic handler usage pattern.
#[test]
fn integration_realistic_handler_usage() {
    init_test("integration_realistic_handler_usage");

    // Simulate a realistic cancellation scenario:
    // 1. Root region times out
    // 2. Child task receives ParentCancelled
    // 3. Handler inspects the cause chain to log appropriately

    let cx = Cx::for_testing();

    // Simulate what the runtime would set up
    let timeout_reason = CancelReason::timeout()
        .with_region(RegionId::new_for_test(1, 0))
        .with_message("request timeout after 30s");

    let child_reason = CancelReason::parent_cancelled()
        .with_region(RegionId::new_for_test(2, 0))
        .with_cause(timeout_reason);

    cx.set_cancel_reason(child_reason);

    test_section!("Handler code pattern");

    // This is the pattern handlers should use:
    assert!(cx.is_cancel_requested());

    // Check immediate reason
    assert!(cx.cancelled_by(CancelKind::ParentCancelled));
    tracing::info!("Immediate reason: ParentCancelled");

    // But we want to know the root cause for logging
    if cx.any_cause_is(CancelKind::Timeout) {
        let root = cx.root_cancel_cause().unwrap();
        tracing::info!(
            root_kind = ?root.kind,
            root_message = ?root.message,
            "Request cancelled due to timeout"
        );

        // Log for observability
        assert_eq!(root.kind, CancelKind::Timeout);
        assert_eq!(root.message, Some("request timeout after 30s"));
    }

    // Full chain inspection for detailed logging
    let chain: Vec<_> = cx.cancel_chain().collect();
    assert_eq!(chain.len(), 2);
    tracing::info!(
        chain_len = chain.len(),
        "Full chain available for debugging"
    );

    test_complete!("integration_realistic_handler_usage");
}
