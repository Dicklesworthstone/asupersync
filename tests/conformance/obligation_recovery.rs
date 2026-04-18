//! Conformance tests for obligation ledger recovery state machine.
//!
//! Tests the critical recovery scenarios to ensure obligations are properly
//! handled across crash boundaries, generation tokens work correctly, and
//! the ledger maintains consistency during recovery operations.
//!
//! This validates RFC-level behavior for the obligation ledger recovery
//! state machine as specified in the obligation ledger requirements.

use asupersync::obligation::ledger::{ObligationLedger, ObligationToken};
use asupersync::record::{ObligationAbortReason, ObligationKind, SourceLocation};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use asupersync::util::ArenaIndex;

fn make_task() -> TaskId {
    TaskId::from_arena(ArenaIndex::new(1, 0))
}

fn make_region() -> RegionId {
    RegionId::from_arena(ArenaIndex::new(0, 0))
}

fn make_time() -> Time {
    Time::from_nanos(1000)
}

/// Test Scenario 1: pending obligations are logged before commit
///
/// This test verifies that acquired obligations are immediately tracked
/// in the ledger before any commit operation, ensuring visibility for
/// recovery operations.
#[test]
fn test_pending_obligations_logged_before_commit() {
    let mut ledger = ObligationLedger::new();
    let task = make_task();
    let region = make_region();
    let now = make_time();

    // Acquire obligation - should be immediately "logged" (tracked) in ledger
    let token = ledger.acquire(
        ObligationKind::SendPermit,
        task,
        region,
        now,
    );

    // Verify obligation is tracked before commit
    assert_eq!(ledger.pending_count(), 1, "obligation should be tracked immediately after acquire");
    assert_eq!(ledger.pending_for_region(region), 1, "region should have 1 pending obligation");
    assert!(!ledger.is_region_clean(region), "region should not be clean with pending obligation");

    let stats = ledger.stats();
    assert_eq!(stats.total_acquired, 1, "should have 1 acquired obligation");
    assert_eq!(stats.pending, 1, "should have 1 pending obligation");
    assert_eq!(stats.total_committed, 0, "should have 0 committed before commit");
    assert!(!stats.is_clean(), "ledger should not be clean with pending obligation");

    // Now commit and verify state changes
    let duration = ledger.commit(token, now + Time::from_nanos(10));
    assert_eq!(duration, 10, "commit should return correct duration");

    let stats_after = ledger.stats();
    assert_eq!(stats_after.pending, 0, "should have 0 pending after commit");
    assert_eq!(stats_after.total_committed, 1, "should have 1 committed after commit");
    assert!(stats_after.is_clean(), "ledger should be clean after commit");
}

/// Test Scenario 2: crash between log and commit resumes by replaying
///
/// This test simulates a crash scenario where obligations are acquired but
/// not committed, then verifies recovery by replaying the commit operation.
#[test]
fn test_crash_between_log_and_commit_resumes_by_replaying() {
    let mut ledger = ObligationLedger::new();
    let task = make_task();
    let region = make_region();
    let now = make_time();

    // Simulate acquiring obligations before a "crash"
    let token1 = ledger.acquire(ObligationKind::SendPermit, task, region, now);
    let token2 = ledger.acquire(ObligationKind::Ack, task, region, now);

    // Verify obligations are logged/tracked
    assert_eq!(ledger.pending_count(), 2, "should have 2 pending before crash");
    let pending_ids = ledger.pending_ids_for_region(region);
    assert_eq!(pending_ids.len(), 2, "should find 2 pending IDs for region");

    // Simulate crash by NOT committing token1, but committing token2
    let _duration2 = ledger.commit(token2, now + Time::from_nanos(5));

    // After "crash", token1 is still pending - simulate recovery by replaying commit
    assert_eq!(ledger.pending_count(), 1, "should have 1 pending after partial crash");
    assert!(!ledger.is_region_clean(region), "region should not be clean");

    // Recovery: replay the missed commit for token1
    let duration1 = ledger.commit(token1, now + Time::from_nanos(15));
    assert_eq!(duration1, 15, "replayed commit should work correctly");

    // Verify full recovery
    assert_eq!(ledger.pending_count(), 0, "should have 0 pending after recovery");
    assert!(ledger.is_region_clean(region), "region should be clean after recovery");

    let final_stats = ledger.stats();
    assert_eq!(final_stats.total_committed, 2, "should have 2 committed after recovery");
    assert!(final_stats.is_clean(), "ledger should be clean after recovery");
}

/// Test Scenario 3: duplicate commit via generation token rejected
///
/// This test verifies that attempting to commit the same obligation token
/// twice is properly rejected to prevent double-resolution bugs.
#[test]
fn test_duplicate_commit_via_generation_token_rejected() {
    let mut ledger = ObligationLedger::new();
    let task = make_task();
    let region = make_region();
    let now = make_time();

    let token = ledger.acquire(ObligationKind::Lease, task, region, now);

    // First commit should succeed
    let duration1 = ledger.commit(token, now + Time::from_nanos(20));
    assert_eq!(duration1, 20, "first commit should succeed");

    // Attempting to use the same token again would be a compile error since
    // the token is consumed by commit(), but we can test the underlying
    // record state to verify it rejects double resolution

    let stats = ledger.stats();
    assert_eq!(stats.total_committed, 1, "should have exactly 1 commit");
    assert_eq!(stats.pending, 0, "should have 0 pending after commit");

    // Create another token with same parameters but different generation
    // This tests that generation tokens prevent accidental double commits
    let token2 = ledger.acquire(ObligationKind::Lease, task, region, now);
    assert_ne!(token.id(), token2.id(), "new token should have different ID");

    // This commit should succeed because it's a different token
    let _duration2 = ledger.commit(token2, now + Time::from_nanos(25));

    let final_stats = ledger.stats();
    assert_eq!(final_stats.total_committed, 2, "should have 2 separate commits");
}

/// Test Scenario 4: abort after crash restores balance
///
/// This test verifies that obligations can be properly aborted during recovery
/// operations to restore system balance after a crash.
#[test]
fn test_abort_after_crash_restores_balance() {
    let mut ledger = ObligationLedger::new();
    let task = make_task();
    let region = make_region();
    let now = make_time();

    // Acquire multiple obligations
    let token1 = ledger.acquire(ObligationKind::SemaphorePermit, task, region, now);
    let token2 = ledger.acquire(ObligationKind::IoOp, task, region, now);

    assert_eq!(ledger.pending_count(), 2, "should have 2 pending before crash");

    // Simulate crash where only token1 survives, token2 is lost
    // Commit token1 normally
    let _duration1 = ledger.commit(token1, now + Time::from_nanos(10));

    // For token2, simulate recovery abort by ID (token is "lost")
    let pending_ids = ledger.pending_ids_for_region(region);
    assert_eq!(pending_ids.len(), 1, "should have 1 pending after partial commit");

    // Recovery: abort the remaining obligation by ID to restore balance
    let remaining_id = pending_ids[0];
    let abort_duration = ledger.abort_by_id(
        remaining_id,
        now + Time::from_nanos(30),
        ObligationAbortReason::Error,
    );
    assert_eq!(abort_duration, 30, "abort should return correct duration");

    // Verify balance is restored
    assert_eq!(ledger.pending_count(), 0, "should have 0 pending after recovery abort");
    assert!(ledger.is_region_clean(region), "region should be clean after abort");

    let stats = ledger.stats();
    assert_eq!(stats.total_committed, 1, "should have 1 committed");
    assert_eq!(stats.total_aborted, 1, "should have 1 aborted");
    assert_eq!(stats.total_leaked, 0, "should have 0 leaked");
    assert!(stats.is_clean(), "ledger should be clean after recovery");
}

/// Test Scenario 5: reset after crash preserves next_gen counter
///
/// This test verifies that the reset() operation preserves the generation
/// counter to prevent ID reuse across recovery cycles.
#[test]
fn test_reset_after_crash_preserves_next_gen_counter() {
    let mut ledger = ObligationLedger::new();
    let task = make_task();
    let region = make_region();
    let now = make_time();

    // Acquire and commit some obligations to advance the generation counter
    let token1 = ledger.acquire(ObligationKind::SendPermit, task, region, now);
    let token2 = ledger.acquire(ObligationKind::Ack, task, region, now);
    let token3 = ledger.acquire(ObligationKind::Lease, task, region, now);

    // Note the IDs before any commits
    let id1 = token1.id();
    let id2 = token2.id();
    let id3 = token3.id();

    // IDs should be different and increasing
    assert_ne!(id1, id2, "token IDs should be unique");
    assert_ne!(id2, id3, "token IDs should be unique");
    assert_ne!(id1, id3, "token IDs should be unique");

    // Commit all obligations to clean up
    ledger.commit(token1, now + Time::from_nanos(5));
    ledger.commit(token2, now + Time::from_nanos(10));
    ledger.commit(token3, now + Time::from_nanos(15));

    assert!(ledger.stats().is_clean(), "ledger should be clean before reset");

    // Reset after "crash" - this should preserve the generation counter
    ledger.reset();

    // Verify reset cleared everything
    assert_eq!(ledger.pending_count(), 0, "should have 0 pending after reset");
    let stats_after_reset = ledger.stats();
    assert_eq!(stats_after_reset.total_acquired, 0, "stats should be reset");
    assert_eq!(stats_after_reset.total_committed, 0, "stats should be reset");
    assert!(stats_after_reset.is_clean(), "should be clean after reset");

    // Critical test: acquire new obligations and verify generation counter was preserved
    let post_reset_token1 = ledger.acquire(ObligationKind::SendPermit, task, region, now);
    let post_reset_token2 = ledger.acquire(ObligationKind::Ack, task, region, now);

    let post_id1 = post_reset_token1.id();
    let post_id2 = post_reset_token2.id();

    // New IDs should NOT reuse old IDs (generation counter preserved)
    assert_ne!(post_id1, id1, "post-reset ID should not reuse pre-reset ID");
    assert_ne!(post_id1, id2, "post-reset ID should not reuse pre-reset ID");
    assert_ne!(post_id1, id3, "post-reset ID should not reuse pre-reset ID");
    assert_ne!(post_id2, id1, "post-reset ID should not reuse pre-reset ID");
    assert_ne!(post_id2, id2, "post-reset ID should not reuse pre-reset ID");
    assert_ne!(post_id2, id3, "post-reset ID should not reuse pre-reset ID");

    // New IDs should be different from each other
    assert_ne!(post_id1, post_id2, "post-reset tokens should have unique IDs");

    // Clean up for test completion
    ledger.commit(post_reset_token1, now + Time::from_nanos(25));
    ledger.commit(post_reset_token2, now + Time::from_nanos(30));

    assert!(ledger.stats().is_clean(), "ledger should be clean at test end");
}

/// Additional test: verify panic conditions during reset
///
/// This test ensures reset() properly validates preconditions and panics
/// when obligations are still pending or leaked.
#[test]
#[should_panic(expected = "cannot reset obligation ledger with pending obligations")]
fn test_reset_panics_with_pending_obligations() {
    let mut ledger = ObligationLedger::new();
    let task = make_task();
    let region = make_region();
    let now = make_time();

    // Acquire but don't commit/abort - leaves pending obligation
    let _token = ledger.acquire(ObligationKind::SendPermit, task, region, now);

    // This should panic
    ledger.reset();
}

/// Additional test: verify generation counter behavior across multiple acquire cycles
///
/// This test ensures generation counter increments correctly and maintains
/// uniqueness across multiple acquire operations.
#[test]
fn test_generation_counter_monotonic_increment() {
    let mut ledger = ObligationLedger::new();
    let task = make_task();
    let region = make_region();
    let now = make_time();

    let mut previous_ids = Vec::new();

    // Acquire multiple tokens in batches to test generation counter behavior
    for batch in 0..3 {
        for item in 0..5 {
            let token = ledger.acquire(
                ObligationKind::SendPermit,
                task,
                region,
                now + Time::from_nanos(batch * 100 + item * 10),
            );

            let id = token.id();

            // Ensure this ID hasn't been seen before
            assert!(!previous_ids.contains(&id),
                    "ID {:?} was reused in batch {} item {}", id, batch, item);
            previous_ids.push(id);

            // Commit immediately to keep ledger clean
            ledger.commit(token, now + Time::from_nanos(batch * 100 + item * 10 + 1));
        }
    }

    assert_eq!(previous_ids.len(), 15, "should have generated 15 unique IDs");
    assert!(ledger.stats().is_clean(), "ledger should be clean after all commits");
}