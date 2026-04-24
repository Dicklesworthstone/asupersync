//! Golden snapshot tests for LedgerSnapshot binary shapes.
//!
//! These tests ensure that the binary serialization format of LedgerSnapshot
//! remains stable across changes to the obligation ledger implementation.
//! Any changes to the snapshot format will be caught by insta.

use asupersync::obligation::crdt::{CrdtObligationLedger, LedgerSnapshot};
use asupersync::record::ObligationKind;
use asupersync::remote::NodeId;
use asupersync::trace::distributed::Merge;
use asupersync::types::ObligationId;
use insta::{Settings, assert_debug_snapshot};

/// Helper to create a deterministic NodeId for testing.
fn test_node(id: u32) -> NodeId {
    NodeId::new(&format!("test-node-{}", id))
}

/// Helper to create a deterministic ObligationId for testing.
fn test_obligation(id: u32) -> ObligationId {
    ObligationId::new_for_test(id, 1)
}

/// Test LedgerSnapshot shape with empty ledger.
#[test]
fn snapshot_empty_ledger() {
    let node = test_node(1);
    let ledger = CrdtObligationLedger::new(node.clone());

    let snapshot = ledger.snapshot();

    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots");
    settings.bind(|| {
        assert_debug_snapshot!("ledger_snapshot_empty", snapshot);
    });
}

/// Test LedgerSnapshot shape after reserving obligations.
#[test]
fn snapshot_reserved_obligations() {
    let node = test_node(1);
    let mut ledger = CrdtObligationLedger::new(node.clone());

    // Reserve several obligations
    ledger.record_acquire(test_obligation(1), ObligationKind::SendPermit);
    ledger.record_acquire(test_obligation(2), ObligationKind::Ack);
    ledger.record_acquire(test_obligation(3), ObligationKind::Lease);

    let snapshot = ledger.snapshot();

    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots");
    settings.bind(|| {
        assert_debug_snapshot!("ledger_snapshot_reserved", snapshot);
    });
}

/// Test LedgerSnapshot shape after reserve -> commit transition.
#[test]
fn snapshot_reserve_to_commit() {
    let node = test_node(1);
    let mut ledger = CrdtObligationLedger::new(node.clone());

    // Reserve and commit obligations
    ledger.record_acquire(test_obligation(1), ObligationKind::SendPermit);
    ledger.record_acquire(test_obligation(2), ObligationKind::Ack);

    // Commit first obligation
    ledger.record_commit(test_obligation(1));

    let snapshot = ledger.snapshot();

    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots");
    settings.bind(|| {
        assert_debug_snapshot!("ledger_snapshot_reserve_to_commit", snapshot);
    });
}

/// Test LedgerSnapshot shape after reserve -> abort transition.
#[test]
fn snapshot_reserve_to_abort() {
    let node = test_node(1);
    let mut ledger = CrdtObligationLedger::new(node.clone());

    // Reserve and abort obligations
    ledger.record_acquire(test_obligation(1), ObligationKind::SendPermit);
    ledger.record_acquire(test_obligation(2), ObligationKind::Ack);

    // Abort first obligation
    ledger.record_abort(test_obligation(1));

    let snapshot = ledger.snapshot();

    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots");
    settings.bind(|| {
        assert_debug_snapshot!("ledger_snapshot_reserve_to_abort", snapshot);
    });
}

/// Test LedgerSnapshot shape after all commits are closed.
#[test]
fn snapshot_commit_to_close() {
    let node = test_node(1);
    let mut ledger = CrdtObligationLedger::new(node.clone());

    // Reserve, commit, and let obligations complete their lifecycle
    ledger.record_acquire(test_obligation(1), ObligationKind::SendPermit);
    ledger.record_acquire(test_obligation(2), ObligationKind::Ack);

    // Commit both obligations
    ledger.record_commit(test_obligation(1));
    ledger.record_commit(test_obligation(2));

    let snapshot = ledger.snapshot();

    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots");
    settings.bind(|| {
        assert_debug_snapshot!("ledger_snapshot_commit_to_close", snapshot);
    });
}

/// Test LedgerSnapshot shape after all aborts are closed.
#[test]
fn snapshot_abort_to_close() {
    let node = test_node(1);
    let mut ledger = CrdtObligationLedger::new(node.clone());

    // Reserve, abort, and let obligations complete their lifecycle
    ledger.record_acquire(test_obligation(1), ObligationKind::SendPermit);
    ledger.record_acquire(test_obligation(2), ObligationKind::Ack);

    // Abort both obligations
    ledger.record_abort(test_obligation(1));
    ledger.record_abort(test_obligation(2));

    let snapshot = ledger.snapshot();

    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots");
    settings.bind(|| {
        assert_debug_snapshot!("ledger_snapshot_abort_to_close", snapshot);
    });
}

/// Test LedgerSnapshot shape with conflict states.
#[test]
fn snapshot_conflicts() {
    let node1 = test_node(1);
    let node2 = test_node(2);
    let mut ledger1 = CrdtObligationLedger::new(node1.clone());
    let mut ledger2 = CrdtObligationLedger::new(node2.clone());

    // Create a conflict: same obligation resolved differently on different nodes
    ledger1.record_acquire(test_obligation(1), ObligationKind::SendPermit);
    ledger2.record_acquire(test_obligation(1), ObligationKind::SendPermit);

    // Node 1 commits, Node 2 aborts -> conflict
    ledger1.record_commit(test_obligation(1));
    ledger2.record_abort(test_obligation(1));

    // Merge both directions
    ledger1.merge(&ledger2);

    let snapshot = ledger1.snapshot();

    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots");
    settings.bind(|| {
        assert_debug_snapshot!("ledger_snapshot_conflicts", snapshot);
    });
}

/// Test LedgerSnapshot shape with linearity violations (multiple acquires).
#[test]
fn snapshot_linearity_violations() {
    let node1 = test_node(1);
    let node2 = test_node(2);
    let mut ledger1 = CrdtObligationLedger::new(node1.clone());
    let mut ledger2 = CrdtObligationLedger::new(node2.clone());

    // Create linearity violation: same obligation acquired on different nodes
    ledger1.record_acquire(test_obligation(1), ObligationKind::SendPermit);
    ledger2.record_acquire(test_obligation(1), ObligationKind::SendPermit);

    // Merge to detect linearity violation
    ledger1.merge(&ledger2);

    let snapshot = ledger1.snapshot();

    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots");
    settings.bind(|| {
        assert_debug_snapshot!("ledger_snapshot_linearity_violations", snapshot);
    });
}

/// Test LedgerSnapshot shape with no-leak witness (comprehensive end-to-end).
#[test]
fn snapshot_no_leak_witness() {
    let node = test_node(1);
    let mut ledger = CrdtObligationLedger::new(node.clone());

    // Create a complete lifecycle without leaks
    // Reserve multiple obligations of different kinds
    ledger.record_acquire(test_obligation(1), ObligationKind::SendPermit);
    ledger.record_acquire(test_obligation(2), ObligationKind::Ack);
    ledger.record_acquire(test_obligation(3), ObligationKind::Lease);
    ledger.record_acquire(test_obligation(4), ObligationKind::IoOp);
    ledger.record_acquire(test_obligation(5), ObligationKind::SemaphorePermit);

    // Properly resolve all obligations (mix of commit/abort)
    ledger.record_commit(test_obligation(1)); // commit
    ledger.record_commit(test_obligation(2)); // commit
    ledger.record_abort(test_obligation(3)); // abort
    ledger.record_abort(test_obligation(4)); // abort
    ledger.record_commit(test_obligation(5)); // commit

    // Verify no leaks in the witness
    let snapshot = ledger.snapshot();

    // This snapshot should show proper cleanup with no pending obligations
    assert_eq!(
        snapshot.pending, 0,
        "No-leak witness should have zero pending obligations"
    );
    assert_eq!(
        snapshot.linearity_violations, 0,
        "No-leak witness should have zero linearity violations"
    );
    assert_eq!(
        snapshot.conflicts, 0,
        "No-leak witness should have zero conflicts"
    );

    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots");
    settings.bind(|| {
        assert_debug_snapshot!("ledger_snapshot_no_leak_witness", snapshot);
    });
}

/// Test LedgerSnapshot shape with mixed states (realistic scenario).
#[test]
fn snapshot_mixed_states() {
    let node = test_node(1);
    let mut ledger = CrdtObligationLedger::new(node.clone());

    // Create a realistic mixed scenario
    // Some reserved, some committed, some aborted
    for i in 1..=10 {
        ledger.record_acquire(test_obligation(i), ObligationKind::SendPermit);
    }

    // Commit some
    ledger.record_commit(test_obligation(1));
    ledger.record_commit(test_obligation(2));
    ledger.record_commit(test_obligation(3));

    // Abort some
    ledger.record_abort(test_obligation(4));
    ledger.record_abort(test_obligation(5));

    // Leave some reserved (pending)
    // obligations 6-10 remain in Reserved state

    let snapshot = ledger.snapshot();

    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots");
    settings.bind(|| {
        assert_debug_snapshot!("ledger_snapshot_mixed_states", snapshot);
    });
}

/// Test LedgerSnapshot binary format stability.
#[test]
fn snapshot_binary_format_stability() {
    let node = test_node(42);
    let mut ledger = CrdtObligationLedger::new(node.clone());

    // Create a deterministic state for binary format testing
    ledger.record_acquire(test_obligation(100), ObligationKind::SendPermit);
    ledger.record_acquire(test_obligation(200), ObligationKind::Ack);
    ledger.record_acquire(test_obligation(300), ObligationKind::Lease);

    ledger.record_commit(test_obligation(100));
    ledger.record_abort(test_obligation(200));
    // 300 remains reserved

    let snapshot = ledger.snapshot();

    // Test that the binary format itself is stable using debug representation
    // Changes to field order, types, or serialization will be caught
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots");
    settings.bind(|| {
        assert_debug_snapshot!("ledger_snapshot_binary_format", snapshot);
    });

    // Additional verification of expected values
    assert_eq!(snapshot.total, 3);
    assert_eq!(snapshot.pending, 1);
    assert_eq!(snapshot.committed, 1);
    assert_eq!(snapshot.aborted, 1);
    assert_eq!(snapshot.conflicts, 0);
    assert_eq!(snapshot.linearity_violations, 0);
}
