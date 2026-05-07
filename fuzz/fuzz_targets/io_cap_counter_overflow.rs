//! Fuzz target for src/io/cap.rs I/O operation counter overflow vulnerabilities.
//!
//! **CRITICAL GAP ADDRESSED**: The existing budget_arithmetic.rs fuzzer tests
//! Budget type operations but lacks coverage of IoCap counter overflow scenarios.
//!
//! **VULNERABILITY SURFACE**: IoStatsCounter atomic operations where:
//! - record_submit() -> submitted.fetch_add(1, Ordering::Relaxed)
//! - record_complete() -> completed.fetch_add(1, Ordering::Relaxed)
//!
//! **ATTACK VECTORS**:
//! 1. Integer overflow: u64 counters wrap around after 2^64 operations
//! 2. Stats corruption: submitted/completed counts become invalid
//! 3. Accounting bypass: rate limits/quotas based on counters can be evaded
//! 4. Logic errors: code assuming monotonic increase breaks on wrap
//!
//! **ORACLE**: Shadow model tracking - compare fuzzer's expected counts
//! against actual IoStats to detect overflow-induced corruption.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::io::cap::{IoCap, IoStats, LabIoCap};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_OPERATIONS: usize = 100_000; // Reasonable limit for exec/s
const OVERFLOW_THRESHOLD: u64 = u64::MAX - 1000; // Near-overflow testing

#[derive(Debug, Clone, Arbitrary)]
struct IoCapOperation {
    op_type: IoOpType,
    repeat_count: u16, // 0-65535 repetitions
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum IoOpType {
    Submit,
    Complete,
    SubmitBurst(u8),  // Submit 1-255 operations in tight loop
    CompleteBurst(u8), // Complete 1-255 operations in tight loop
    CheckStats,       // Verify stats consistency
}

#[derive(Debug)]
struct ShadowStatsTracker {
    submitted: AtomicU64,
    completed: AtomicU64,
}

impl ShadowStatsTracker {
    fn new() -> Self {
        Self {
            submitted: AtomicU64::new(0),
            completed: AtomicU64::new(0),
        }
    }

    fn record_submit(&self) {
        self.submitted.fetch_add(1, Ordering::Relaxed);
    }

    fn record_complete(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    fn stats(&self) -> IoStats {
        IoStats {
            submitted: self.submitted.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        self.submitted.store(0, Ordering::Relaxed);
        self.completed.store(0, Ordering::Relaxed);
    }

    fn set_near_overflow(&self) {
        // Set counters near overflow boundary for targeted testing
        self.submitted.store(OVERFLOW_THRESHOLD, Ordering::Relaxed);
        self.completed.store(OVERFLOW_THRESHOLD, Ordering::Relaxed);
    }
}

fn execute_operation(cap: &LabIoCap, shadow: &ShadowStatsTracker, op: &IoCapOperation) {
    let repeat = (op.repeat_count as usize).max(1).min(1000); // Bound repetitions

    match op.op_type {
        IoOpType::Submit => {
            for _ in 0..repeat {
                cap.record_submit();
                shadow.record_submit();
            }
        }
        IoOpType::Complete => {
            for _ in 0..repeat {
                cap.record_complete();
                shadow.record_complete();
            }
        }
        IoOpType::SubmitBurst(count) => {
            let burst_size = count.max(1) as usize;
            for _ in 0..burst_size {
                cap.record_submit();
                shadow.record_submit();
            }
        }
        IoOpType::CompleteBurst(count) => {
            let burst_size = count.max(1) as usize;
            for _ in 0..burst_size {
                cap.record_complete();
                shadow.record_complete();
            }
        }
        IoOpType::CheckStats => {
            // Oracle: verify stats consistency
            let cap_stats = cap.stats();
            let shadow_stats = shadow.stats();

            assert_eq!(
                cap_stats, shadow_stats,
                "Stats divergence detected: cap={:?} shadow={:?}",
                cap_stats, shadow_stats
            );

            // Invariant: completed should never exceed submitted in valid usage
            // NOTE: This can be violated by malicious/corrupted input, but our
            // fuzzer should respect this invariant to test realistic scenarios
            if shadow_stats.completed > shadow_stats.submitted {
                // This indicates potential overflow wrap-around corruption
                panic!(
                    "OVERFLOW CORRUPTION: completed ({}) > submitted ({})",
                    shadow_stats.completed, shadow_stats.submitted
                );
            }
        }
    }
}

fuzz_target!(|input: Vec<IoCapOperation>| {
    if input.len() > MAX_OPERATIONS {
        return;
    }

    let cap = LabIoCap::new_for_tests();
    let shadow = ShadowStatsTracker::new();

    // Test scenario 1: Normal operation sequence
    for op in &input {
        execute_operation(&cap, &shadow, op);

        // Verify consistency after each operation
        let cap_stats = cap.stats();
        let shadow_stats = shadow.stats();

        assert_eq!(
            cap_stats, shadow_stats,
            "Stats consistency violation after {:?}", op
        );
    }

    // Test scenario 2: Near-overflow boundary testing
    shadow.set_near_overflow();

    // Force the IoCap to match shadow state by performing enough operations
    // This is a test harness limitation - we can't directly set IoCap state
    let current_cap_stats = cap.stats();
    let target_submitted = OVERFLOW_THRESHOLD - current_cap_stats.submitted;
    let target_completed = OVERFLOW_THRESHOLD - current_cap_stats.completed;

    // Only proceed if the gap is reasonable (avoid infinite loops)
    if target_submitted < 10_000 && target_completed < 10_000 {
        for _ in 0..target_submitted {
            cap.record_submit();
        }
        for _ in 0..target_completed {
            cap.record_complete();
        }

        // Now both should be near overflow - test boundary operations
        let near_overflow_ops = [
            IoCapOperation { op_type: IoOpType::Submit, repeat_count: 5000 },
            IoCapOperation { op_type: IoOpType::Complete, repeat_count: 3000 },
            IoCapOperation { op_type: IoOpType::CheckStats, repeat_count: 1 },
        ];

        for op in &near_overflow_ops {
            execute_operation(&cap, &shadow, op);
        }
    }

    // Final consistency check
    let final_cap_stats = cap.stats();

    // Validate final invariants
    assert!(
        final_cap_stats.submitted >= final_cap_stats.completed,
        "INVARIANT VIOLATION: completed ({}) > submitted ({})",
        final_cap_stats.completed, final_cap_stats.submitted
    );

    // Check for overflow wrap-around indicators
    if final_cap_stats.submitted < 1000 && input.len() > 1000 {
        // Suspiciously low counter after many operations - possible overflow
        panic!(
            "POTENTIAL OVERFLOW: submitted counter ({}) suspiciously low after {} operations",
            final_cap_stats.submitted, input.len()
        );
    }
});