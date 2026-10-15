//! Metamorphic testing for SymbolCancelToken and cancellation protocol.
//!
//! This module implements comprehensive metamorphic relations for the symbol
//! cancellation system, testing critical properties like hierarchical propagation,
//! reason strengthening, timing consistency, and listener notification invariants.
//!
//! # Testing Philosophy
//!
//! Cancellation protocols involve complex race conditions, hierarchical relationships,
//! and timing constraints. Rather than testing exact sequences (oracle problem),
//! we verify that the system satisfies mathematical properties that MUST hold
//! regardless of specific timing or input ordering.
//!
//! # Metamorphic Relations Implemented
//!
//! - **MR1: Hierarchical Propagation** - Parent cancel → all children cancelled
//! - **MR2: Reason Strengthening** - Successive cancels only strengthen reasons
//! - **MR3: Timing Monotonicity** - Cancellation timestamps are stable once set
//! - **MR4: Token Identity Invariance** - Token/object IDs never change after creation
//! - **MR5: Listener Notification** - All listeners get notified on cancellation
//! - **MR6: Cancellation Idempotence** - Multiple cancels with same reason are stable
//! - **MR7: Child Independence** - Sibling tokens don't affect each other
//! - **MR8: Budget Preservation** - Cleanup budgets are preserved across operations

use crate::cancel::symbol_cancel::{CancelListener, SymbolCancelToken};
use crate::types::{Budget, CancelKind, CancelReason, ObjectId, Time};
use crate::util::DetRng;
use proptest::prelude::*;
use std::sync::Arc;

const EPSILON_NANOS: u64 = 1000; // 1µs tolerance for timing

/// Test listener that records notifications.
#[derive(Clone)]
struct TestListener {
    notifications: Arc<std::sync::Mutex<Vec<(CancelReason, Time)>>>,
    panic_on_notify: bool,
}

impl TestListener {
    fn new() -> Self {
        Self {
            notifications: Arc::new(std::sync::Mutex::new(Vec::new())),
            panic_on_notify: false,
        }
    }

    fn with_panic() -> Self {
        Self {
            notifications: Arc::new(std::sync::Mutex::new(Vec::new())),
            panic_on_notify: true,
        }
    }

    fn notifications(&self) -> Vec<(CancelReason, Time)> {
        self.notifications.lock().unwrap().clone()
    }

    fn notification_count(&self) -> usize {
        self.notifications.lock().unwrap().len()
    }
}

impl CancelListener for TestListener {
    fn on_cancel(&self, reason: &CancelReason, at: Time) {
        assert!(!self.panic_on_notify, "Test listener panic");
        self.notifications
            .lock()
            .unwrap()
            .push((reason.clone(), at));
    }
}

/// Helper to create cancel reasons with different severities.
fn create_reason(kind: CancelKind, _message: &str) -> CancelReason {
    CancelReason::new(kind)
}

fn object_id_from_u64(value: u64) -> ObjectId {
    ObjectId::from_u128(u128::from(value))
}

fn cancel_kind_strategy() -> impl Strategy<Value = CancelKind> {
    prop_oneof![
        Just(CancelKind::User),
        Just(CancelKind::Timeout),
        Just(CancelKind::Deadline),
        Just(CancelKind::Shutdown),
        Just(CancelKind::ParentCancelled),
        Just(CancelKind::ResourceUnavailable),
    ]
}

/// MR1: Hierarchical Propagation
///
/// Property: When a parent token is cancelled, all child tokens must also
/// become cancelled with appropriate parent cascade reasons.
///
/// Transformation: Create token hierarchy, cancel parent
/// Relation: ∀child ∈ children(parent), cancel(parent) → is_cancelled(child) = true
#[test]
fn mr1_hierarchical_propagation() {
    proptest!(|(
        parent_id in 1u64..1000,
        child_ids in prop::collection::vec(1u64..1000, 1..=10),
        cancel_kind in prop_oneof![
            Just(CancelKind::User),
            Just(CancelKind::Timeout),
            Just(CancelKind::Shutdown),
            Just(CancelKind::ParentCancelled),
        ]
    )| {
        prop_assume!(child_ids.iter().all(|&id| id != parent_id));

        let mut rng = DetRng::new(42);
        let now = Time::from_nanos(1_000_000_000);

        // Create parent token
        let parent = SymbolCancelToken::new(object_id_from_u64(parent_id), &mut rng);

        // Create child tokens and establish hierarchy
        let mut children = Vec::new();
        for _child_id in &child_ids {
            let child = parent.child(&mut rng);
            children.push(child);
        }

        // Verify initial state - no tokens should be cancelled
        prop_assert!(!parent.is_cancelled(), "Parent should start uncancelled");
        for (i, child) in children.iter().enumerate() {
            prop_assert!(!child.is_cancelled(),
                "Child {} should start uncancelled", i);
        }

        // Cancel parent
        let reason = create_reason(cancel_kind, "test cancellation");
        let was_first_cancel = parent.cancel(&reason, now);

        prop_assert!(was_first_cancel, "Should be first cancellation");
        prop_assert!(parent.is_cancelled(), "Parent should be cancelled");

        // Verify hierarchical propagation - all children must be cancelled
        for (i, child) in children.iter().enumerate() {
            prop_assert!(child.is_cancelled(),
                "Child {} must be cancelled when parent is cancelled", i);

            if let Some(child_reason) = child.reason() {
                // Child should have ParentCancelled or stronger reason
                prop_assert!(
                    child_reason.kind == CancelKind::ParentCancelled ||
                    child_reason.kind.severity() >= CancelKind::ParentCancelled.severity(),
                    "Child {} should have ParentCancelled or stronger reason, got {:?}",
                    i, child_reason.kind
                );
            }
        }
    });
}

/// MR2: Reason Strengthening Monotonicity
///
/// Property: Successive cancellation attempts should only strengthen the stored
/// reason, never weaken it.
///
/// Transformation: Cancel token multiple times with different severities
/// Relation: severity(reason_n+1) ≥ severity(reason_n)
#[test]
fn mr2_reason_strengthening_monotonicity() {
    proptest!(|(
        object_id in 1u64..1000,
        reasons in prop::collection::vec((cancel_kind_strategy(), ".*"), 1..=8)
    )| {
        prop_assume!(!reasons.is_empty() && reasons.len() <= 8);

        let mut rng = DetRng::new(42);
        let token = SymbolCancelToken::new(object_id_from_u64(object_id), &mut rng);
        let base_time = Time::from_nanos(1_000_000_000);

        let mut previous_severity = 0u8;
        let mut time_offset = 0;

        for (i, (kind, message)) in reasons.iter().enumerate() {
            let reason = create_reason(*kind, message);
            let now = Time::from_nanos(base_time.as_nanos() + time_offset);
            time_offset += 1_000_000; // 1ms between cancels

            let _ = token.cancel(&reason, now);

            // Token should always be cancelled after any cancel attempt
            prop_assert!(token.is_cancelled(),
                "Token should be cancelled after attempt {}", i);

            if let Some(stored_reason) = token.reason() {
                let current_severity = stored_reason.kind.severity();

                prop_assert!(current_severity >= previous_severity,
                    "Reason severity should be monotonic: attempt {} had severity {}, got {}",
                    i, previous_severity, current_severity);

                previous_severity = current_severity;
            }
        }
    });
}

/// MR3: Timing Monotonicity
///
/// Property: Cancellation timestamps should be stable once set and never
/// move backwards in time.
///
/// Transformation: Cancel token multiple times with different timestamps
/// Relation: cancelled_at() is stable after first cancellation
#[test]
fn mr3_timing_monotonicity() {
    proptest!(|(
        object_id in 1u64..1000,
        timestamps in prop::collection::vec(1u64..(u64::MAX / 2), 1..=5)
    )| {
        let mut rng = DetRng::new(42);
        let token = SymbolCancelToken::new(object_id_from_u64(object_id), &mut rng);

        let mut first_cancel_time = None;

        for (i, &timestamp) in timestamps.iter().enumerate() {
            let time = Time::from_nanos(timestamp);
            let reason = create_reason(CancelKind::User, &format!("cancel {}", i));

            let was_first = token.cancel(&reason, time);

            if was_first {
                first_cancel_time = Some(time);
            }

            // cancelled_at() should be stable after first cancellation
            if let Some(recorded_time) = token.cancelled_at() {
                if let Some(first_time) = first_cancel_time {
                    let time_diff = if recorded_time.as_nanos() >= first_time.as_nanos() {
                        recorded_time.as_nanos() - first_time.as_nanos()
                    } else {
                        first_time.as_nanos() - recorded_time.as_nanos()
                    };

                    prop_assert!(time_diff <= EPSILON_NANOS,
                        "Cancellation time should be stable: first={}, recorded={}, diff={}",
                        first_time.as_nanos(), recorded_time.as_nanos(), time_diff);
                }
            }
        }
    });
}

/// MR4: Token Identity Invariance
///
/// Property: Token and object IDs should never change after creation.
///
/// Transformation: Perform various operations on token
/// Relation: token_id() and object_id() remain constant
#[test]
fn mr4_token_identity_invariance() {
    proptest!(|(
        object_id in 1u64..1000,
        operations in prop::collection::vec(any::<u8>(), 1..=10)
    )| {
        let mut rng = DetRng::new(object_id);
        let token = SymbolCancelToken::new(object_id_from_u64(object_id), &mut rng);

        let initial_token_id = token.token_id();
        let initial_object_id = token.object_id();

        let now = Time::from_nanos(1_000_000_000);

        // Perform various operations
        for (i, &op) in operations.iter().enumerate() {
            match op % 4 {
                0 => {
                    // Cancel operation
                    let reason = create_reason(CancelKind::User, &format!("op {}", i));
                    let _ = token.cancel(&reason, now);
                }
                1 => {
                    // Check cancelled state
                    let _ = token.is_cancelled();
                }
                2 => {
                    // Add child
                    let _child = token.child(&mut rng);
                }
                3 => {
                    // Add listener
                    let listener = TestListener::new();
                    token.add_listener(listener);
                }
                _ => unreachable!(),
            }

            // Verify identities remain constant
            prop_assert_eq!(token.token_id(), initial_token_id,
                "Token ID should never change after operation {}", i);
            prop_assert_eq!(token.object_id(), initial_object_id,
                "Object ID should never change after operation {}", i);
        }
    });
}

/// MR5: Listener Notification Completeness
///
/// Property: All registered listeners should be notified when cancellation occurs.
///
/// Transformation: Register multiple listeners, then cancel
/// Relation: notification_count(listener_i) > 0 for all registered listeners
#[test]
fn mr5_listener_notification_completeness() {
    proptest!(|(
        object_id in 1u64..1000,
        listener_count in 1usize..8
    )| {
        let mut rng = DetRng::new(42);
        let token = SymbolCancelToken::new(object_id_from_u64(object_id), &mut rng);

        // Register multiple listeners
        let mut listeners = Vec::new();
        for _i in 0..listener_count {
            let listener = TestListener::new();
            let listener_clone = listener.clone();
            token.add_listener(listener_clone);
            listeners.push(listener);
        }

        // Initial state - no notifications
        for (i, listener) in listeners.iter().enumerate() {
            prop_assert_eq!(listener.notification_count(), 0,
                "Listener {} should have no initial notifications", i);
        }

        // Cancel the token
        let reason = create_reason(CancelKind::Timeout, "test timeout");
        let now = Time::from_nanos(1_000_000_000);
        let was_first = token.cancel(&reason, now);

        prop_assert!(was_first, "Should be first cancellation");

        // All listeners should be notified
        for (i, listener) in listeners.iter().enumerate() {
            prop_assert!(listener.notification_count() > 0,
                "Listener {} should be notified after cancellation", i);

            let notifications = listener.notifications();
            if let Some((notified_reason, notified_time)) = notifications.first() {
                prop_assert_eq!(notified_reason.kind, reason.kind,
                    "Listener {} should receive correct cancel reason", i);

                let time_diff = if notified_time.as_nanos() >= now.as_nanos() {
                    notified_time.as_nanos() - now.as_nanos()
                } else {
                    now.as_nanos() - notified_time.as_nanos()
                };
                prop_assert!(time_diff <= EPSILON_NANOS,
                    "Listener {} should receive correct time", i);
            }
        }
    });
}

/// MR6: Cancellation Idempotence
///
/// Property: Multiple cancellations with identical reasons should be idempotent
/// (produce the same final state).
///
/// Transformation: Cancel token n times with same reason
/// Relation: state after 1 cancel ≡ state after n cancels (same reason)
#[test]
fn mr6_cancellation_idempotence() {
    proptest!(|(
        object_id in 1u64..1000,
        repeat_count in 2usize..10
    )| {
        let mut rng = DetRng::new(42);

        // Token A: Single cancellation
        let token_a = SymbolCancelToken::new(object_id_from_u64(object_id), &mut rng);
        let listener_a = TestListener::new();
        token_a.add_listener(listener_a.clone());

        // Token B: Multiple identical cancellations
        let token_b = SymbolCancelToken::new(object_id_from_u64(object_id), &mut rng);
        let listener_b = TestListener::new();
        token_b.add_listener(listener_b.clone());

        let reason = create_reason(CancelKind::Deadline, "test deadline");
        let now = Time::from_nanos(1_000_000_000);

        // Single cancellation
        let was_first_a = token_a.cancel(&reason, now);

        // Multiple identical cancellations
        let mut was_first_b = false;
        for i in 0..repeat_count {
            let result = token_b.cancel(&reason, now);
            if i == 0 {
                was_first_b = result;
            }
        }

        // Both should report the same "first cancel" status
        prop_assert_eq!(was_first_a, was_first_b,
            "Both tokens should report same first-cancel status");

        // Final states should be equivalent
        prop_assert_eq!(token_a.is_cancelled(), token_b.is_cancelled(),
            "Both tokens should have same cancellation state");

        if let (Some(reason_a), Some(reason_b)) = (token_a.reason(), token_b.reason()) {
            prop_assert_eq!(reason_a.kind, reason_b.kind,
                "Both tokens should have same cancel reason");
        }

        // Notification counts should be the same (idempotent)
        // Note: This tests that repeated identical cancels don't trigger extra notifications
        prop_assert_eq!(listener_a.notification_count(), listener_b.notification_count(),
            "Listener notification counts should be identical");
    });
}

/// MR7: Child Independence
///
/// Property: Operations on sibling child tokens should not affect each other
/// unless they share a parent cancellation.
///
/// Transformation: Create siblings, operate on one
/// Relation: sibling state unchanged unless parent cancellation propagates
#[test]
fn mr7_child_independence() {
    proptest!(|(
        parent_id in 1u64..100,
        child_ids in prop::collection::vec(1u64..100, 2..=6)
    )| {
        prop_assume!(child_ids.iter().all(|&id| id != parent_id));

        let mut rng = DetRng::new(42);
        let parent = SymbolCancelToken::new(object_id_from_u64(parent_id), &mut rng);

        // Create sibling tokens
        let mut children = Vec::new();
        for _child_id in &child_ids {
            let child = parent.child(&mut rng);
            children.push(child);
        }

        // Record initial state of all siblings
        let initial_states: Vec<bool> = children.iter()
            .map(|child| child.is_cancelled())
            .collect();

        // Operate on first child only (not parent cancellation)
        if let Some(first_child) = children.first() {
            let reason = create_reason(CancelKind::User, "direct child cancel");
            let now = Time::from_nanos(1_000_000_000);
            let _ = first_child.cancel(&reason, now);

            // First child should be affected
            prop_assert!(first_child.is_cancelled(),
                "Directly cancelled child should be cancelled");

            // Siblings should be unaffected (child independence)
            for (i, child) in children.iter().enumerate().skip(1) {
                prop_assert_eq!(child.is_cancelled(), initial_states[i],
                    "Sibling {} should be unaffected by sibling 0 cancellation", i);
            }

            // Parent should be unaffected (no upward propagation)
            prop_assert!(!parent.is_cancelled(),
                "Parent should not be affected by child cancellation");
        }
    });
}

/// MR8: Budget Preservation
///
/// Property: Cleanup budgets associated with tokens should be preserved
/// across cancellation operations.
///
/// Transformation: Create token with budget, perform operations
/// Relation: cleanup_budget() remains constant
#[test]
fn mr8_budget_preservation() {
    proptest!(|(
        object_id in 1u64..1000,
        initial_budget in 1u64..1000000
    )| {
        let mut rng = DetRng::new(42);
        let budget = Budget::new().with_cost_quota(initial_budget);
        let token =
            SymbolCancelToken::with_budget(object_id_from_u64(object_id), budget, &mut rng);

        // Record initial budget
        let initial_budget_value = token.cleanup_budget().remaining_cost();

        // Perform various operations
        let reason1 = create_reason(CancelKind::User, "first cancel");
        let reason2 = create_reason(CancelKind::Timeout, "second cancel");
        let now = Time::from_nanos(1_000_000_000);

        // Cancel multiple times
        let _ = token.cancel(&reason1, now);
        let _ = token.cancel(&reason2, now);

        // Add children and listeners
        let _child = token.child(&mut rng);

        let listener = TestListener::new();
        token.add_listener(listener);

        // Budget should be preserved
        let final_budget_value = token.cleanup_budget().remaining_cost();
        prop_assert_eq!(initial_budget_value, final_budget_value,
            "Cleanup budget should be preserved across operations");
    });
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn mr_composition_hierarchical_with_strengthening() {
        // Composite MR: Combines hierarchical propagation with reason strengthening
        let mut rng = DetRng::new(42);
        let parent = SymbolCancelToken::new(object_id_from_u64(1), &mut rng);
        let child = parent.child(&mut rng);

        let weak_reason = create_reason(CancelKind::User, "weak");
        let strong_reason = create_reason(CancelKind::Shutdown, "strong");
        let now = Time::from_nanos(1_000_000_000);

        // Cancel parent with weak reason
        parent.cancel(&weak_reason, now);
        assert!(child.is_cancelled());

        // Strengthen parent reason
        parent.cancel(&strong_reason, now);

        // Child should reflect the stronger cascaded reason
        if let Some(child_reason) = child.reason() {
            assert!(child_reason.kind.severity() >= CancelKind::ParentCancelled.severity());
        }
    }

    #[test]
    fn mr_validation_catches_listener_panics() {
        let mut rng = DetRng::new(42);
        let token = SymbolCancelToken::new(object_id_from_u64(1), &mut rng);

        // Register panic listener
        let panic_listener = TestListener::with_panic();
        token.add_listener(panic_listener);

        let initial_panic_count = token.listener_panic_count();

        // Cancel should catch listener panic
        let reason = create_reason(CancelKind::User, "test");
        let now = Time::from_nanos(1_000_000_000);
        token.cancel(&reason, now);

        // Panic count should increase
        assert!(
            token.listener_panic_count() > initial_panic_count,
            "Panic count should increase when listener panics"
        );
    }
}
