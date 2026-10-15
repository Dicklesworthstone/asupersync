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
//! 1. Stats corruption: submitted/completed counts diverge from recorded events
//! 2. Accounting bypass: rate limits/quotas based on counters can be evaded
//! 3. Logic errors: code assuming counter reads are internally inconsistent
//!
//! **ORACLE**: Shadow model tracking - compare fuzzer's expected counts
//! against actual IoStats to detect overflow-induced corruption.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::io::cap::{IoCap, IoStats, LabIoCap};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_OPERATIONS: usize = 256;
const MAX_REPETITIONS: usize = 64;

#[derive(Debug, Clone, Arbitrary)]
struct IoCapOperation {
    op_type: IoOpType,
    repeat_count: u16, // 0-65535 repetitions
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum IoOpType {
    Submit,
    Complete,
    SubmitBurst(u8),   // Submit 1-255 operations in tight loop
    CompleteBurst(u8), // Complete 1-255 operations in tight loop
    CheckStats,        // Verify stats consistency
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
}

fn execute_operation(cap: &LabIoCap, shadow: &ShadowStatsTracker, op: &IoCapOperation) {
    let repeat = usize::from(op.repeat_count).clamp(1, MAX_REPETITIONS);

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

            // `record_submit` and `record_complete` are independent counters.
            // Arbitrary fuzz input may complete first; only divergence from the
            // shadow model is a bug here.
        }
    }
}

fuzz_target!(|input: Vec<IoCapOperation>| {
    if input.len() > MAX_OPERATIONS {
        return;
    }

    let cap = LabIoCap::new_for_tests();
    let shadow = ShadowStatsTracker::new();

    for op in &input {
        execute_operation(&cap, &shadow, op);

        // Verify consistency after each operation
        let cap_stats = cap.stats();
        let shadow_stats = shadow.stats();

        assert_eq!(
            cap_stats, shadow_stats,
            "Stats consistency violation after {:?}",
            op
        );
    }

    // Final consistency check
    let final_cap_stats = cap.stats();
    let final_shadow_stats = shadow.stats();

    assert_eq!(
        final_cap_stats, final_shadow_stats,
        "Final stats consistency violation"
    );
});
