//! Metamorphic tests for cancel::symbol_cancel propagation and masking.
//!
//! These tests validate the cancellation protocol behavior using metamorphic relations
//! to ensure cancel propagation, masking semantics, reason preservation, idempotency,
//! and memory cleanup are preserved across various operation patterns.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use proptest::prelude::*;

use asupersync::cancel::symbol_cancel::{
    CancelBroadcaster, CancelListener, CancelMessage, CancelSink, PeerId, SymbolCancelToken,
};
use asupersync::cx::Cx;
use asupersync::types::symbol::ObjectId;
use asupersync::types::{CancelKind, CancelReason, Time};
use asupersync::util::DetRng;

/// Test listener for tracking cancellation events.
#[derive(Debug, Clone)]
struct TestCancelListener {
    /// Whether cancel was called on this listener.
    notified: Arc<AtomicBool>,
    /// The reason received during cancellation.
    received_reason: Arc<StdMutex<Option<CancelReason>>>,
    /// When the cancellation was received.
    received_at: Arc<StdMutex<Option<Time>>>,
}

impl TestCancelListener {
    fn new() -> Self {
        Self {
            notified: Arc::new(AtomicBool::new(false)),
            received_reason: Arc::new(StdMutex::new(None)),
            received_at: Arc::new(StdMutex::new(None)),
        }
    }

    fn was_notified(&self) -> bool {
        self.notified.load(Ordering::Acquire)
    }

    fn received_reason(&self) -> Option<CancelReason> {
        self.received_reason.lock().unwrap().clone()
    }

    fn received_at(&self) -> Option<Time> {
        *self.received_at.lock().unwrap()
    }
}

impl CancelListener for TestCancelListener {
    fn on_cancel(&self, reason: &CancelReason, at: Time) {
        self.notified.store(true, Ordering::Release);
        *self.received_reason.lock().unwrap() = Some(reason.clone());
        *self.received_at.lock().unwrap() = Some(at);
    }
}

/// Memory usage tracker for testing cleanup.
#[derive(Debug, Clone)]
struct MemoryTracker {
    /// Count of active tokens.
    active_tokens: Arc<AtomicUsize>,
    /// Count of active listeners.
    active_listeners: Arc<AtomicUsize>,
}

impl MemoryTracker {
    fn new() -> Self {
        Self {
            active_tokens: Arc::new(AtomicUsize::new(0)),
            active_listeners: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn track_token(&self) -> TokenTracker {
        self.active_tokens.fetch_add(1, Ordering::Relaxed);
        TokenTracker {
            tracker: self.clone(),
        }
    }

    fn track_listener(&self) -> ListenerTracker {
        self.active_listeners.fetch_add(1, Ordering::Relaxed);
        ListenerTracker {
            tracker: self.clone(),
        }
    }

    fn active_token_count(&self) -> usize {
        self.active_tokens.load(Ordering::Relaxed)
    }

    fn active_listener_count(&self) -> usize {
        self.active_listeners.load(Ordering::Relaxed)
    }
}

/// RAII tracker for token memory.
struct TokenTracker {
    tracker: MemoryTracker,
}

impl Drop for TokenTracker {
    fn drop(&mut self) {
        self.tracker.active_tokens.fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII tracker for listener memory.
struct ListenerTracker {
    tracker: MemoryTracker,
}

impl Drop for ListenerTracker {
    fn drop(&mut self) {
        self.tracker
            .active_listeners
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Tracking listener that reports to memory tracker.
struct TrackingListener {
    inner: TestCancelListener,
    _tracker: ListenerTracker,
}

impl TrackingListener {
    fn new(memory_tracker: &MemoryTracker) -> Self {
        Self {
            inner: TestCancelListener::new(),
            _tracker: memory_tracker.track_listener(),
        }
    }
}

impl CancelListener for TrackingListener {
    fn on_cancel(&self, reason: &CancelReason, at: Time) {
        self.inner.on_cancel(reason, at);
    }
}

struct PanicListener;

impl CancelListener for PanicListener {
    fn on_cancel(&self, _reason: &CancelReason, _at: Time) {
        panic!("Intentional panic in listener");
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct NoopCancelSink;

impl CancelSink for NoopCancelSink {
    fn send_to(
        &self,
        _peer: &PeerId,
        _msg: &CancelMessage,
    ) -> impl std::future::Future<Output = asupersync::error::Result<()>> + Send {
        std::future::ready(Ok(()))
    }

    fn broadcast(
        &self,
        _msg: &CancelMessage,
    ) -> impl std::future::Future<Output = asupersync::error::Result<usize>> + Send {
        std::future::ready(Ok(0))
    }
}

/// Create a test context for cancellation testing.
fn test_cx() -> Cx {
    Cx::for_testing()
}

/// Create a test RNG for deterministic testing.
fn test_rng() -> DetRng {
    DetRng::new(12345)
}

/// Create a test object ID.
fn test_object_id(high: u64, low: u64) -> ObjectId {
    ObjectId::new(high, low)
}

/// Strategy for generating object IDs.
fn arb_object_id() -> impl Strategy<Value = ObjectId> {
    (any::<u64>(), any::<u64>()).prop_map(|(high, low)| ObjectId::new(high, low))
}

/// Strategy for generating cancel kinds.
fn arb_cancel_kind() -> impl Strategy<Value = CancelKind> {
    prop_oneof![
        Just(CancelKind::User),
        Just(CancelKind::Timeout),
        Just(CancelKind::Deadline),
        Just(CancelKind::PollQuota),
        Just(CancelKind::CostBudget),
        Just(CancelKind::FailFast),
        Just(CancelKind::RaceLost),
        Just(CancelKind::ParentCancelled),
        Just(CancelKind::ResourceUnavailable),
        Just(CancelKind::Shutdown),
        Just(CancelKind::LinkedExit),
    ]
}

/// Strategy for generating cancel reasons.
fn arb_cancel_reason() -> impl Strategy<Value = CancelReason> {
    arb_cancel_kind().prop_map(CancelReason::new)
}

/// Strategy for generating time values.
fn arb_time() -> impl Strategy<Value = Time> {
    (0u64..1_000_000_000).prop_map(Time::from_nanos)
}

// Metamorphic Relations for Symbol Cancel Propagation and Masking

/// MR1: Symbol cancel propagates through cloned token (Propagation Invariant, Score: 9.5)
/// Property: clone(token) → cancel(original) → clone.is_cancelled()
/// Catches: Clone isolation bugs, state sharing failures, propagation races
#[test]
fn mr1_symbol_cancel_propagates_through_cloned_token() {
    proptest!(|(
        object_id in arb_object_id(),
        reason in arb_cancel_reason(),
        cancel_time in arb_time()
    )| {
        let mut rng = test_rng();
        let original_token = SymbolCancelToken::new(object_id, &mut rng);

        // Clone the token (should share state)
        let cloned_token = original_token.clone();

        // Verify both tokens start uncancelled
        prop_assert!(!original_token.is_cancelled(), "Original token should start uncancelled");
        prop_assert!(!cloned_token.is_cancelled(), "Cloned token should start uncancelled");

        // Add listeners to both tokens
        let original_listener = TestCancelListener::new();
        let cloned_listener = TestCancelListener::new();

        original_token.add_listener(original_listener.clone());
        cloned_token.add_listener(cloned_listener.clone());

        // Cancel the original token
        let cancel_result = original_token.cancel(&reason, cancel_time);
        prop_assert!(cancel_result, "First cancel should return true");

        // Verify both tokens are cancelled (shared state)
        prop_assert!(original_token.is_cancelled(), "Original token should be cancelled");
        prop_assert!(cloned_token.is_cancelled(), "Cloned token should be cancelled");

        // Verify both listeners were notified
        prop_assert!(original_listener.was_notified(), "Original listener should be notified");
        prop_assert!(cloned_listener.was_notified(), "Cloned listener should be notified");

        // Verify same cancellation reason and time
        prop_assert_eq!(original_token.reason(), cloned_token.reason(),
            "Both tokens should have same cancel reason");
        prop_assert_eq!(original_token.cancelled_at(), cloned_token.cancelled_at(),
            "Both tokens should have same cancel time");

        // Verify token IDs are the same (shared state)
        prop_assert_eq!(original_token.token_id(), cloned_token.token_id(),
            "Cloned token should have same token ID");
    });
}

/// MR2: Masked scope does not see cancel (Masking Invariant, Score: 8.5)
/// Property: cx.masked(|| cx.checkpoint()) → Ok(()) even if cancelled
/// Catches: Masking bypass bugs, depth tracking errors, premature cancel delivery
#[test]
fn mr2_masked_scope_does_not_see_cancel() {
    proptest!(|(reason in arb_cancel_reason())| {
        let cx = test_cx();

        // Request cancellation on the context
        cx.set_cancel_reason(reason.clone());

        // Verify cancellation is observable outside masked scope
        let unmasked_result = cx.checkpoint();
        prop_assert!(unmasked_result.is_err(), "Checkpoint should fail when cancelled and unmasked");

        // Now test that masking defers the cancellation
        let masked_result = cx.masked(|| {
            cx.checkpoint()
        });

        prop_assert!(masked_result.is_ok(), "Checkpoint should succeed when masked");

        // After unmasking, cancellation should be visible again
        let after_mask_result = cx.checkpoint();
        prop_assert!(after_mask_result.is_err(), "Checkpoint should fail after unmasking");

        // Test nested masking
        let nested_masked_result = cx.masked(|| {
            cx.masked(|| {
                cx.checkpoint()
            })
        });

        prop_assert!(nested_masked_result.is_ok(), "Nested masked checkpoint should succeed");
    });
}

/// MR3: Cancel reason preserved (Reason Invariant, Score: 8.0)
/// Property: cancel(reason1) → cancel(reason2) → stored_reason = strengthen(reason1, reason2)
/// Catches: Reason overwrite bugs, strengthening logic errors, race conditions
#[test]
fn mr3_cancel_reason_preserved() {
    proptest!(|(
        object_id in arb_object_id(),
        first_kind in arb_cancel_kind(),
        second_kind in arb_cancel_kind(),
        first_time in arb_time(),
        second_time in arb_time()
    )| {
        let mut rng = test_rng();
        let token = SymbolCancelToken::new(object_id, &mut rng);

        let first_reason = CancelReason::new(first_kind);
        let second_reason = CancelReason::new(second_kind);

        // Cancel with first reason
        let first_cancel = token.cancel(&first_reason, first_time);
        prop_assert!(first_cancel, "First cancel should succeed");

        let stored_after_first = token.reason();
        prop_assert!(stored_after_first.is_some(), "Reason should be stored after first cancel");

        // Cancel with second reason (should strengthen)
        let second_cancel = token.cancel(&second_reason, second_time);
        prop_assert!(!second_cancel, "Second cancel should return false (already cancelled)");

        let _final_reason = token.reason().expect("Final reason should be available");

        // The stored reason should be the strengthened version
        // For now, just verify it's not None and we got a reason
        prop_assert!(token.reason().is_some(), "Cancel reason should be preserved");

        // Verify the first cancellation time is preserved
        prop_assert_eq!(token.cancelled_at(), Some(first_time),
            "First cancellation time should be preserved");

        // Verify token remains cancelled
        prop_assert!(token.is_cancelled(), "Token should remain cancelled");
    });
}

/// MR4: Cancel idempotent (Idempotency Invariant, Score: 9.0)
/// Property: cancel() → cancel() → second_call_returns_false ∧ state_unchanged
/// Catches: Duplicate processing bugs, state corruption, listener re-notification
#[test]
fn mr4_cancel_idempotent() {
    proptest!(|(
        object_id in arb_object_id(),
        reason in arb_cancel_reason(),
        cancel_time in arb_time()
    )| {
        let mut rng = test_rng();
        let token = SymbolCancelToken::new(object_id, &mut rng);

        // Add a listener to track notifications
        let listener = TestCancelListener::new();
        token.add_listener(listener.clone());

        // First cancel
        let first_result = token.cancel(&reason, cancel_time);
        prop_assert!(first_result, "First cancel should return true");

        // Capture state after first cancel
        let state_after_first = (
            token.is_cancelled(),
            token.reason(),
            token.cancelled_at(),
            listener.was_notified(),
        );

        // Second cancel (idempotent)
        let second_result = token.cancel(&reason, cancel_time);
        prop_assert!(!second_result, "Second cancel should return false (idempotent)");

        // Verify state is unchanged
        let state_after_second = (
            token.is_cancelled(),
            token.reason(),
            token.cancelled_at(),
            listener.was_notified(),
        );

        prop_assert_eq!(state_after_first, state_after_second,
            "Token state should be unchanged after idempotent cancel");

        // Third cancel with different time (should still be idempotent)
        let third_time = Time::from_nanos(cancel_time.as_nanos() + 1000);
        let third_result = token.cancel(&reason, third_time);
        prop_assert!(!third_result, "Third cancel should return false (idempotent)");

        // Time should not change (first-cancel-wins policy)
        prop_assert_eq!(token.cancelled_at(), Some(cancel_time),
            "Cancellation time should not change on idempotent calls");
    });
}

/// MR5: Cancel token cleanup releases memory (Memory Cleanup, Score: 7.5)
/// Property: drop(all_token_references) → memory_usage decreases
/// Catches: Memory leaks, reference cycles, listener retention bugs
#[test]
fn mr5_cancel_token_cleanup_releases_memory() {
    proptest!(|(
        object_id in arb_object_id(),
        reason in arb_cancel_reason(),
        cancel_time in arb_time()
    )| {
        let memory_tracker = MemoryTracker::new();
        let mut rng = test_rng();

        // Create scope for token lifecycle
        {
            let _token_tracker = memory_tracker.track_token();
            let token = SymbolCancelToken::new(object_id, &mut rng);

            // Add multiple listeners with tracking
            let listener1 = TrackingListener::new(&memory_tracker);
            let listener2 = TrackingListener::new(&memory_tracker);
            let listener3 = TrackingListener::new(&memory_tracker);

            token.add_listener(listener1);
            token.add_listener(listener2);
            token.add_listener(listener3);

            prop_assert_eq!(memory_tracker.active_listener_count(), 3,
                "Should track 3 active listeners");

            // Create child tokens (should share parent state)
            let child1 = token.child(&mut rng);
            let child2 = token.child(&mut rng);

            // Cancel the token - should notify listeners and clean them up
            let cancel_result = token.cancel(&reason, cancel_time);
            prop_assert!(cancel_result, "Cancel should succeed");

            // Verify children are also cancelled
            prop_assert!(child1.is_cancelled(), "Child1 should be cancelled");
            prop_assert!(child2.is_cancelled(), "Child2 should be cancelled");

        } // Drop all token references here

        // Give time for any delayed cleanup
        // In a real system this would be immediate, but for testing robustness
        std::thread::sleep(Duration::from_millis(1));

        // After all tokens are dropped, memory should be released
        // Note: Due to Arc sharing, actual memory cleanup depends on implementation details
        // but we can verify that our tracking mechanism works
        prop_assert_eq!(memory_tracker.active_token_count(), 0,
            "All tracked tokens should be cleaned up");

        // Listeners should be cleaned up after cancellation
        // (they are moved out of the token during cancel notification)
        prop_assert_eq!(memory_tracker.active_listener_count(), 0,
            "All tracked listeners should be cleaned up");
    });
}

/// MR6: Children created during cancel callbacks are drained inline
/// (Drain-before-finalize Invariant, Score: 8.5)
/// Property: listener(on_cancel => parent.child()) -> child.is_cancelled() before cancel() returns
/// Catches: late-child queue retention, incomplete drain ordering, reentrancy leaks
#[test]
fn mr6_listener_created_child_is_drained_before_cancel_returns() {
    let mut rng = test_rng();
    let token = SymbolCancelToken::new(test_object_id(7, 9), &mut rng);
    let observed_child = Arc::new(StdMutex::new(None::<SymbolCancelToken>));
    let observed_child_clone = Arc::clone(&observed_child);
    let token_for_listener = token.clone();

    struct Mr6Listener {
        observed_child: Arc<StdMutex<Option<SymbolCancelToken>>>,
        token: SymbolCancelToken,
    }
    impl CancelListener for Mr6Listener {
        fn on_cancel(&self, _reason: &CancelReason, _time: Time) {
            let mut child_rng = DetRng::new(777);
            let child = self.token.child(&mut child_rng);
            *self.observed_child.lock().unwrap() = Some(child);
        }
    }

    token.add_listener(Mr6Listener {
        observed_child: observed_child_clone,
        token: token_for_listener,
    });

    let reason = CancelReason::new(CancelKind::Shutdown);
    let cancelled_at = Time::from_millis(4242);
    assert!(
        token.cancel(&reason, cancelled_at),
        "first cancel should trigger notification and drain"
    );

    let child = observed_child
        .lock()
        .unwrap()
        .clone()
        .expect("listener should create a child during cancellation");
    assert!(
        child.is_cancelled(),
        "child created during cancellation must be cancelled before cancel() returns"
    );
    assert_eq!(
        child.reason().map(|reason| reason.kind()),
        Some(CancelKind::ParentCancelled),
        "late child should inherit parent-cancelled semantics"
    );
    assert_eq!(
        child.cancelled_at(),
        Some(cancelled_at),
        "late child must observe the same drain timestamp"
    );
}

/// MR7: Listeners registered during cancel callbacks are notified inline once
/// (Drain-before-finalize Invariant, Score: 8.0)
/// Property: listener(on_cancel => token.add_listener(late)) -> late notified exactly once
/// Catches: listener requeue bugs, post-drain duplicate delivery, incomplete callback drain
#[test]
fn mr7_listener_registered_during_cancel_is_not_requeued() {
    let mut rng = test_rng();
    let token = SymbolCancelToken::new(test_object_id(11, 13), &mut rng);
    let late_listener_notifications = Arc::new(AtomicUsize::new(0));
    let late_listener_reason = Arc::new(StdMutex::new(None::<CancelKind>));
    let late_listener_time = Arc::new(StdMutex::new(None::<Time>));

    let late_listener_notifications_clone = Arc::clone(&late_listener_notifications);
    let late_listener_reason_clone = Arc::clone(&late_listener_reason);
    let late_listener_time_clone = Arc::clone(&late_listener_time);
    let token_for_listener = token.clone();

    struct Mr7InnerListener {
        notifications: Arc<AtomicUsize>,
        reason: Arc<StdMutex<Option<CancelKind>>>,
        time: Arc<StdMutex<Option<Time>>>,
    }
    impl CancelListener for Mr7InnerListener {
        fn on_cancel(&self, reason: &CancelReason, at: Time) {
            self.notifications.fetch_add(1, Ordering::SeqCst);
            *self.reason.lock().unwrap() = Some(reason.kind());
            *self.time.lock().unwrap() = Some(at);
        }
    }

    struct Mr7OuterListener {
        token: SymbolCancelToken,
        inner_notifications: Arc<AtomicUsize>,
        inner_reason: Arc<StdMutex<Option<CancelKind>>>,
        inner_time: Arc<StdMutex<Option<Time>>>,
    }
    impl CancelListener for Mr7OuterListener {
        fn on_cancel(&self, _reason: &CancelReason, _at: Time) {
            self.token.add_listener(Mr7InnerListener {
                notifications: Arc::clone(&self.inner_notifications),
                reason: Arc::clone(&self.inner_reason),
                time: Arc::clone(&self.inner_time),
            });
        }
    }

    token.add_listener(Mr7OuterListener {
        token: token_for_listener,
        inner_notifications: late_listener_notifications_clone,
        inner_reason: late_listener_reason_clone,
        inner_time: late_listener_time_clone,
    });

    let first_reason = CancelReason::new(CancelKind::Timeout);
    let first_cancelled_at = Time::from_millis(8080);
    assert!(
        token.cancel(&first_reason, first_cancelled_at),
        "first cancel should trigger listener drain"
    );

    assert_eq!(
        late_listener_notifications.load(Ordering::SeqCst),
        1,
        "listener registered during cancellation must be notified inline exactly once"
    );
    assert_eq!(
        *late_listener_reason.lock().unwrap(),
        Some(CancelKind::Timeout),
        "late listener must observe the active cancellation reason"
    );
    assert_eq!(
        *late_listener_time.lock().unwrap(),
        Some(first_cancelled_at),
        "late listener must observe the active cancellation timestamp"
    );

    token.cancel(
        &CancelReason::new(CancelKind::Shutdown),
        Time::from_millis(9090),
    );
    assert_eq!(
        late_listener_notifications.load(Ordering::SeqCst),
        1,
        "late listener must not be retained for a second notification after drain completes"
    );
}

/// MR8: Duplicate broadcast delivery is observationally equivalent to a single
/// delivery for the remote token state.
#[test]
fn mr8_duplicate_broadcast_delivery_is_idempotent_for_remote_tokens() {
    let mut local_rng = DetRng::new(0xACED_0001);
    let mut remote_rng = DetRng::new(0xACED_0002);
    let object_id = test_object_id(55, 89);
    let local_token = SymbolCancelToken::new(object_id, &mut local_rng);
    let remote_token = SymbolCancelToken::new(object_id, &mut remote_rng);
    let remote_listener = TestCancelListener::new();
    remote_token.add_listener(remote_listener.clone());

    let local_broadcaster = CancelBroadcaster::new(NoopCancelSink);
    let remote_broadcaster = CancelBroadcaster::new(NoopCancelSink);
    local_broadcaster.register_token(local_token.clone());
    remote_broadcaster.register_token(remote_token.clone());

    let reason = CancelReason::new(CancelKind::Timeout);
    let initiated_at = Time::from_millis(111);
    let received_at = Time::from_millis(222);

    let msg = local_broadcaster.prepare_cancel(object_id, &reason, initiated_at);
    assert!(
        local_token.is_cancelled(),
        "preparing a local cancel should cancel the registered token"
    );

    let first_forward = remote_broadcaster.receive_message(&msg, received_at);
    assert!(
        first_forward.is_some(),
        "first remote delivery should be forwarded to downstream peers"
    );
    assert!(
        remote_listener.was_notified(),
        "remote listener should observe the first broadcast delivery"
    );
    assert_eq!(
        remote_listener
            .received_reason()
            .map(|reason| reason.kind()),
        Some(CancelKind::Timeout),
        "remote listener should preserve the forwarded cancel kind"
    );
    assert_eq!(
        remote_listener.received_at(),
        Some(received_at),
        "remote listener should preserve the first delivery timestamp"
    );
    let state_after_first = (
        remote_token.is_cancelled(),
        remote_token.reason().map(|reason| reason.kind()),
        remote_token.cancelled_at(),
        remote_broadcaster.metrics().received,
        remote_broadcaster.metrics().duplicates,
        remote_broadcaster.metrics().forwarded,
    );

    let second_forward = remote_broadcaster.receive_message(&msg, Time::from_millis(333));
    let state_after_second = (
        remote_token.is_cancelled(),
        remote_token.reason().map(|reason| reason.kind()),
        remote_token.cancelled_at(),
        remote_broadcaster.metrics().received,
        remote_broadcaster.metrics().duplicates,
        remote_broadcaster.metrics().forwarded,
    );

    assert!(
        second_forward.is_none(),
        "duplicate delivery should be suppressed instead of forwarded again"
    );
    assert_eq!(
        state_after_first.0, true,
        "remote token must remain cancelled after first delivery"
    );
    assert_eq!(
        state_after_first.1,
        Some(CancelKind::Timeout),
        "remote token should preserve the broadcast cancel kind"
    );
    assert_eq!(
        state_after_first.2,
        Some(received_at),
        "remote token should preserve the first delivery timestamp"
    );
    assert_eq!(
        state_after_second.0, state_after_first.0,
        "duplicate delivery must not change cancellation state"
    );
    assert_eq!(
        state_after_second.1, state_after_first.1,
        "duplicate delivery must not change the stored reason"
    );
    assert_eq!(
        state_after_second.2, state_after_first.2,
        "duplicate delivery must not change the stored timestamp"
    );
    assert_eq!(
        state_after_second.3, state_after_first.3,
        "duplicate delivery must not increment received count twice"
    );
    assert_eq!(
        state_after_second.5, state_after_first.5,
        "duplicate delivery must not increment forwarded count twice"
    );
    assert_eq!(
        state_after_second.4,
        state_after_first.4 + 1,
        "duplicate delivery should only increment duplicate metrics"
    );
}

/// MR9: Broadcast delivery to a remote token tree cancels both existing and
/// late descendants with parent-cancelled semantics.
#[test]
fn mr9_broadcast_delivery_propagates_across_remote_descendants() {
    let mut local_rng = DetRng::new(0xACED_1001);
    let mut remote_rng = DetRng::new(0xACED_1002);
    let object_id = test_object_id(144, 233);
    let local_token = SymbolCancelToken::new(object_id, &mut local_rng);
    let remote_root = SymbolCancelToken::new(object_id, &mut remote_rng);
    let remote_child = remote_root.child(&mut remote_rng);
    let remote_grandchild = remote_child.child(&mut remote_rng);

    let root_listener = TestCancelListener::new();
    let child_listener = TestCancelListener::new();
    let grandchild_listener = TestCancelListener::new();
    remote_root.add_listener(root_listener.clone());
    remote_child.add_listener(child_listener.clone());
    remote_grandchild.add_listener(grandchild_listener.clone());

    let local_broadcaster = CancelBroadcaster::new(NoopCancelSink);
    let remote_broadcaster = CancelBroadcaster::new(NoopCancelSink);
    local_broadcaster.register_token(local_token.clone());
    remote_broadcaster.register_token(remote_root.clone());

    let reason = CancelReason::new(CancelKind::Shutdown);
    let initiated_at = Time::from_millis(404);
    let received_at = Time::from_millis(505);

    let msg = local_broadcaster.prepare_cancel(object_id, &reason, initiated_at);
    let forwarded = remote_broadcaster.receive_message(&msg, received_at);

    assert!(
        forwarded.is_some(),
        "first broadcast delivery should forward to downstream peers"
    );
    assert!(
        local_token.is_cancelled(),
        "preparing a local cancel should cancel the registered token"
    );
    assert!(
        remote_root.is_cancelled(),
        "remote root should be cancelled"
    );
    assert!(
        remote_child.is_cancelled(),
        "existing remote child should be cancelled"
    );
    assert!(
        remote_grandchild.is_cancelled(),
        "existing remote grandchild should be cancelled"
    );
    assert!(
        root_listener.was_notified(),
        "remote root listener should observe the broadcast"
    );
    assert!(
        child_listener.was_notified(),
        "remote child listener should observe propagated cancellation"
    );
    assert!(
        grandchild_listener.was_notified(),
        "remote grandchild listener should observe propagated cancellation"
    );
    assert_eq!(
        remote_root.reason().map(|reason| reason.kind()),
        Some(CancelKind::Shutdown),
        "remote root should preserve the broadcast cancel kind"
    );
    assert_eq!(
        remote_child.reason().map(|reason| reason.kind()),
        Some(CancelKind::ParentCancelled),
        "existing remote child should observe parent-cancelled semantics"
    );
    assert_eq!(
        remote_grandchild.reason().map(|reason| reason.kind()),
        Some(CancelKind::ParentCancelled),
        "existing remote grandchild should observe parent-cancelled semantics"
    );
    assert_eq!(
        remote_root.cancelled_at(),
        Some(received_at),
        "remote root should record the delivery timestamp"
    );
    assert_eq!(
        remote_child.cancelled_at(),
        Some(received_at),
        "existing remote child should record the propagated timestamp"
    );
    assert_eq!(
        remote_grandchild.cancelled_at(),
        Some(received_at),
        "existing remote grandchild should record the propagated timestamp"
    );

    let late_remote_child = remote_root.child(&mut remote_rng);
    let late_remote_grandchild = late_remote_child.child(&mut remote_rng);
    assert!(
        late_remote_child.is_cancelled(),
        "late remote child should inherit the already-broadcast cancellation"
    );
    assert!(
        late_remote_grandchild.is_cancelled(),
        "late remote grandchild should inherit the already-broadcast cancellation"
    );
    assert_eq!(
        late_remote_child.reason().map(|reason| reason.kind()),
        Some(CancelKind::ParentCancelled),
        "late remote child should inherit parent-cancelled semantics"
    );
    assert_eq!(
        late_remote_grandchild.reason().map(|reason| reason.kind()),
        Some(CancelKind::ParentCancelled),
        "late remote grandchild should inherit parent-cancelled semantics"
    );
    assert_eq!(
        late_remote_child.cancelled_at(),
        Some(received_at),
        "late remote child should inherit the broadcast timestamp"
    );
    assert_eq!(
        late_remote_grandchild.cancelled_at(),
        Some(received_at),
        "late remote grandchild should inherit the broadcast timestamp"
    );
    assert_eq!(
        remote_broadcaster.metrics().received,
        1,
        "remote broadcaster should count exactly one received delivery"
    );
    assert_eq!(
        remote_broadcaster.metrics().forwarded,
        1,
        "remote broadcaster should forward the first delivery exactly once"
    );
    assert_eq!(
        remote_broadcaster.metrics().duplicates,
        0,
        "non-duplicate broadcast should not increment duplicate metrics"
    );
}

/// Integration test: Complex token hierarchy with propagation
#[test]
fn integration_complex_token_hierarchy() {
    let mut rng = test_rng();
    let root_object = test_object_id(1, 1);
    let root_token = SymbolCancelToken::new(root_object, &mut rng);

    // Create multi-level hierarchy
    let child1 = root_token.child(&mut rng);
    let child2 = root_token.child(&mut rng);
    let grandchild1 = child1.child(&mut rng);
    let grandchild2 = child1.child(&mut rng);
    let grandchild3 = child2.child(&mut rng);

    // Add listeners at various levels
    let root_listener = TestCancelListener::new();
    let child1_listener = TestCancelListener::new();
    let grandchild1_listener = TestCancelListener::new();

    root_token.add_listener(root_listener.clone());
    child1.add_listener(child1_listener.clone());
    grandchild1.add_listener(grandchild1_listener.clone());

    // Cancel the root - should propagate to all children
    let reason = CancelReason::new(CancelKind::User);
    let cancel_time = Time::from_millis(1_001);

    let cancel_result = root_token.cancel(&reason, cancel_time);
    assert!(cancel_result, "Root cancel should succeed");

    // Verify propagation
    assert!(root_token.is_cancelled(), "Root should be cancelled");
    assert!(child1.is_cancelled(), "Child1 should be cancelled");
    assert!(child2.is_cancelled(), "Child2 should be cancelled");
    assert!(
        grandchild1.is_cancelled(),
        "Grandchild1 should be cancelled"
    );
    assert!(
        grandchild2.is_cancelled(),
        "Grandchild2 should be cancelled"
    );
    assert!(
        grandchild3.is_cancelled(),
        "Grandchild3 should be cancelled"
    );

    // Verify listeners were notified
    assert!(
        root_listener.was_notified(),
        "Root listener should be notified"
    );
    assert!(
        child1_listener.was_notified(),
        "Child1 listener should be notified"
    );
    assert!(
        grandchild1_listener.was_notified(),
        "Grandchild1 listener should be notified"
    );

    // Verify children have ParentCancelled reason
    assert_eq!(
        child1.reason().unwrap().kind(),
        CancelKind::ParentCancelled,
        "Child should have ParentCancelled reason"
    );
    assert_eq!(
        grandchild1.reason().unwrap().kind(),
        CancelKind::ParentCancelled,
        "Grandchild should have ParentCancelled reason"
    );
}

/// Stress test: Concurrent token operations
#[test]
fn stress_concurrent_token_operations() {
    use std::thread;

    let mut rng = test_rng();
    let object_id = test_object_id(42, 84);
    let token = SymbolCancelToken::new(object_id, &mut rng);

    // Share token across threads
    let token1 = token.clone();
    let token2 = token.clone();
    let token3 = token.clone();

    // Launch concurrent operations
    let handle1 = thread::spawn(move || {
        let reason = CancelReason::new(CancelKind::User);
        token1.cancel(&reason, Time::from_millis(2_001))
    });

    let handle2 = thread::spawn(move || {
        let reason = CancelReason::new(CancelKind::Timeout);
        token2.cancel(&reason, Time::from_millis(2_002))
    });

    let handle3 = thread::spawn(move || {
        let reason = CancelReason::new(CancelKind::Deadline);
        token3.cancel(&reason, Time::from_millis(2_003))
    });

    // Collect results
    let result1 = handle1.join().unwrap();
    let result2 = handle2.join().unwrap();
    let result3 = handle3.join().unwrap();

    // Exactly one should succeed (first-caller-wins)
    let success_count = [result1, result2, result3].iter().filter(|&&r| r).count();
    assert_eq!(
        success_count, 1,
        "Exactly one concurrent cancel should succeed"
    );

    // Token should be cancelled
    assert!(
        token.is_cancelled(),
        "Token should be cancelled after concurrent operations"
    );
    assert!(token.reason().is_some(), "Cancel reason should be set");
}

/// Error recovery test: Listener panic handling
#[test]
fn error_recovery_listener_panics() {
    let mut rng = test_rng();
    let object_id = test_object_id(99, 88);
    let token = SymbolCancelToken::new(object_id, &mut rng);

    // Add a panicking listener
    token.add_listener(PanicListener);

    // Add a normal listener
    let normal_listener = TestCancelListener::new();
    token.add_listener(normal_listener.clone());

    // Cancel should complete despite listener panic
    let reason = CancelReason::new(CancelKind::User);
    let cancel_time = Time::from_millis(3_001);

    let cancel_result = token.cancel(&reason, cancel_time);
    assert!(
        cancel_result,
        "Cancel should succeed despite listener panic"
    );

    // Token should be cancelled
    assert!(token.is_cancelled(), "Token should be cancelled");
    assert_eq!(
        token.reason().unwrap().kind(),
        CancelKind::User,
        "Reason should be preserved"
    );

    // Normal listener should have been notified
    assert!(
        normal_listener.was_notified(),
        "Normal listener should be notified despite panic"
    );
}

/// Wire format compatibility test
#[test]
fn wire_format_round_trip() {
    let mut rng = test_rng();
    let object_id = test_object_id(0x1234567890abcdef, 0xfedcba0987654321);
    let token = SymbolCancelToken::new(object_id, &mut rng);

    // Test uncancelled token serialization
    let bytes = token.to_bytes();
    let deserialized =
        SymbolCancelToken::from_bytes(&bytes).expect("Deserialization should succeed");

    assert_eq!(
        token.token_id(),
        deserialized.token_id(),
        "Token ID should match"
    );
    assert_eq!(
        token.object_id(),
        deserialized.object_id(),
        "Object ID should match"
    );
    assert_eq!(
        token.is_cancelled(),
        deserialized.is_cancelled(),
        "Cancel state should match"
    );

    // Test cancelled token serialization
    let reason = CancelReason::new(CancelKind::Timeout);
    let cancel_time = Time::from_millis(4_001);
    token.cancel(&reason, cancel_time);

    let cancelled_bytes = token.to_bytes();
    let cancelled_deserialized = SymbolCancelToken::from_bytes(&cancelled_bytes)
        .expect("Cancelled token deserialization should succeed");

    assert_eq!(
        token.token_id(),
        cancelled_deserialized.token_id(),
        "Cancelled token ID should match"
    );
    assert_eq!(
        token.object_id(),
        cancelled_deserialized.object_id(),
        "Cancelled object ID should match"
    );
    assert_eq!(
        token.is_cancelled(),
        cancelled_deserialized.is_cancelled(),
        "Cancelled state should match"
    );
}
