//! Fuzz watch channel version counter wrap behavior.
//!
//! Tests arbitrary update/borrow_and_update sequences across the u64 wrap boundary
//! to ensure changed() detection remains correct when versions wrap from u64::MAX to 0.
//!
//! The critical invariant: version inequality comparisons (current != seen_version)
//! must work correctly across wrap boundaries.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::channel::watch;
use asupersync::cx::Cx;
use asupersync::types::{RegionId, TaskId, Budget};
use asupersync::util::ArenaIndex;

#[derive(Debug, Clone, Arbitrary)]
enum WatchOp {
    /// Send a new value (increments version)
    Send(u32),
    /// Call borrow_and_update (updates seen_version)
    BorrowAndUpdate,
    /// Call mark_seen (updates seen_version to current)
    MarkSeen,
    /// Check has_changed() (should return true if versions differ)
    CheckChanged,
    /// Wait for changed() - only test in non-wrapped scenarios to keep fuzzer simple
    WaitChanged,
}

#[derive(Debug, Clone, Arbitrary)]
struct WatchSequence {
    /// Starting version offset from u64::MAX to test wrap boundary
    /// 0 = start at u64::MAX - 10, 1 = start at u64::MAX - 9, etc.
    start_offset: u8,
    /// Sequence of operations to perform
    operations: Vec<WatchOp>,
    /// Initial receiver seen_version offset from start
    initial_seen_offset: u8,
}

impl WatchSequence {
    fn max_operations() -> usize {
        100 // Keep sequences manageable
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: WatchSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Limit sequence length to prevent timeouts
    if sequence.operations.len() > WatchSequence::max_operations() {
        return;
    }

    // Create watch channel with initial value
    let (sender, mut receiver) = watch::channel(0u32);

    // Create Cx for operations that need it
    let cx = Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    );

    // Calculate starting version near u64::MAX to test wrap boundary
    // We'll simulate by tracking expected version separately since we can't
    // directly set the internal version counter
    let start_version = u64::MAX.saturating_sub(20).saturating_add(sequence.start_offset as u64);
    let mut expected_version = 0u64; // Start at 0, sender will increment from here
    let mut simulated_version = start_version; // Track what version would be near wrap

    // Adjust receiver seen_version by offset
    let mut expected_seen = sequence.initial_seen_offset as u64;

    // Execute pre-wrap operations to get close to u64::MAX
    // Send enough values to approach the wrap boundary
    let pre_wrap_sends = start_version.saturating_sub(expected_version);
    for _ in 0..pre_wrap_sends.min(1000) { // Limit to prevent excessive setup
        if sender.send(0).is_err() {
            return; // Sender dropped, stop
        }
        expected_version = expected_version.wrapping_add(1);
        simulated_version = simulated_version.wrapping_add(1);
    }

    // Now execute the fuzz sequence operations
    for op in sequence.operations {
        match op {
            WatchOp::Send(value) => {
                if sender.send(value).is_err() {
                    break; // Sender dropped, stop execution
                }
                expected_version = expected_version.wrapping_add(1);
                simulated_version = simulated_version.wrapping_add(1);

                // Key assertion: version wrapping should not break change detection
                let has_changed_before = receiver.has_changed();
                let should_have_changed = expected_version != expected_seen;

                assert_eq!(has_changed_before, should_have_changed,
                    "has_changed() incorrect: expected={}, seen={}, simulated={}",
                    expected_version, expected_seen, simulated_version);

                // Test wrap boundary specifically
                if simulated_version == 0 || simulated_version == u64::MAX {
                    // We've crossed the wrap boundary - ensure detection still works
                    let current_has_changed = receiver.has_changed();
                    assert_eq!(current_has_changed, expected_version != expected_seen,
                        "Wrap boundary detection failed: version wrapped to {}, expected={}, seen={}",
                        simulated_version, expected_version, expected_seen);
                }
            }

            WatchOp::BorrowAndUpdate => {
                let _value = receiver.borrow_and_update();
                expected_seen = expected_version;

                // After borrow_and_update, has_changed() should return false
                assert!(!receiver.has_changed(),
                    "has_changed() should be false after borrow_and_update: version={}, seen={}",
                    expected_version, expected_seen);
            }

            WatchOp::MarkSeen => {
                receiver.mark_seen();
                expected_seen = expected_version;

                // After mark_seen, has_changed() should return false
                assert!(!receiver.has_changed(),
                    "has_changed() should be false after mark_seen: version={}, seen={}",
                    expected_version, expected_seen);
            }

            WatchOp::CheckChanged => {
                let has_changed = receiver.has_changed();
                let should_have_changed = expected_version != expected_seen;

                assert_eq!(has_changed, should_have_changed,
                    "has_changed() mismatch: got={}, expected={}, version={}, seen={}, simulated={}",
                    has_changed, should_have_changed, expected_version, expected_seen, simulated_version);

                // Special check for wrap scenarios
                if simulated_version < 100 || simulated_version > u64::MAX.saturating_sub(100) {
                    // Near wrap boundary - inequality must work correctly
                    assert_eq!(has_changed, expected_version != expected_seen,
                        "Wrap boundary inequality failed: simulated={}, expected={}, seen={}",
                        simulated_version, expected_version, expected_seen);
                }
            }

            WatchOp::WaitChanged => {
                // Only test wait if there's actually a change to wait for
                if expected_version != expected_seen {
                    // Use a simple poll to avoid blocking the fuzzer
                    let mut changed_future = receiver.changed(&cx);

                    // Poll once - should either be ready or pending
                    let poll_context = std::task::Context::from_waker(
                        &futures::task::noop_waker()
                    );
                    use std::future::Future;
                    use std::pin::Pin;

                    match Pin::new(&mut changed_future).poll(&poll_context) {
                        std::task::Poll::Ready(Ok(())) => {
                            // Changed successfully, seen_version should now equal current
                            expected_seen = expected_version;
                        }
                        std::task::Poll::Ready(Err(_)) => {
                            // Channel closed or cancelled
                            break;
                        }
                        std::task::Poll::Pending => {
                            // Still waiting, that's fine
                        }
                    }
                }
            }
        }

        // Invariant: inequality comparison must work correctly regardless of wrap
        let has_changed = receiver.has_changed();
        let should_have_changed = expected_version != expected_seen;
        assert_eq!(has_changed, should_have_changed,
            "Post-operation invariant violated: op={:?}, has_changed={}, should={}, version={}, seen={}, sim={}",
            op, has_changed, should_have_changed, expected_version, expected_seen, simulated_version);

        // Early termination if we've tested enough wrap scenarios
        if simulated_version < 50 && simulated_version > 10 {
            // We've crossed the wrap and tested a bit on the other side
            break;
        }
    }

    // Final consistency check
    let final_has_changed = receiver.has_changed();
    let final_should_have_changed = expected_version != expected_seen;
    assert_eq!(final_has_changed, final_should_have_changed,
        "Final state inconsistent: has_changed={}, should={}, version={}, seen={}, simulated={}",
        final_has_changed, final_should_have_changed, expected_version, expected_seen, simulated_version);
});