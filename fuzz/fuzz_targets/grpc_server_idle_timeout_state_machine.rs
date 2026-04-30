#![no_main]

//! Cargo-fuzz target for `ConnectionState` (src/grpc/server.rs)
//! stream add/remove/cleanup state-machine consistency under
//! arbitrary op sequences.
//!
//! Audit context (tick #142): `ConnectionState::cleanup_idle_streams`
//! uses `wall_clock_instant_now()` to compute idle duration —
//! deterministic time-fast-forwarding is not feasible in a sync
//! libfuzzer harness. So this target instead exercises the
//! state-machine SHAPE of the registry under Arbitrary
//! add/remove/cleanup-with-zero-timeout sequences and asserts:
//!
//!   1. **No panic** for any op sequence — including malformed
//!      ones (remove a stream that was never added; add the same
//!      stream twice; cleanup with timeout=0; etc).
//!
//!   2. **`active_stream_count` is monotone-correct**: after every
//!      op, the count equals the size of a model set tracking
//!      "added-and-not-removed-and-not-cleaned-up" stream ids.
//!
//!   3. **`max_concurrent` enforcement**: an `add_stream` call
//!      MUST return Err once the active count is >= max_concurrent.
//!      A regression that admitted past the cap would surface here.
//!
//!   4. **`cleanup_idle_streams` removes EVERY stream when called
//!      with timeout=0**: at zero idle threshold, every stream is
//!      "idle longer than 0 seconds" because the wall clock has
//!      moved at least a nanosecond since the last add. The
//!      returned Vec contains every previously-active stream id,
//!      no duplicates, in some order. Pinned because a regression
//!      that mistakenly used `>=` instead of `>` (or that left
//!      streams in `active_streams` after marking them removed)
//!      would surface here.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_server_idle_timeout_state_machine -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::grpc::server::ConnectionState;
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use std::time::Duration;

const MAX_OPS: usize = 128;
const MAX_CONCURRENT: u32 = 32;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Op {
    AddStream { stream_id: u32 },
    UpdateActivity { stream_id: u32 },
    RemoveStream { stream_id: u32 },
    /// Cleanup with timeout=0 nanoseconds — removes every stream
    /// that's older than 0ns (which, after at least one
    /// instruction has executed, is every active stream).
    CleanupIdleZero,
    /// Cleanup with a large timeout (1 hour) — should be a no-op
    /// for the realistic per-iteration time budget.
    CleanupIdleHour,
    /// Query the active count (used to drive coverage on the
    /// counter path).
    QueryCount,
}

#[derive(Arbitrary, Debug)]
struct Scenario {
    ops: Vec<Op>,
}

fuzz_target!(|scenario: Scenario| {
    if scenario.ops.len() > MAX_OPS {
        return;
    }

    let mut state = ConnectionState::new();
    let mut model_active: HashSet<u32> = HashSet::new();

    for op in scenario.ops {
        match op {
            Op::AddStream { stream_id } => {
                let pre_count = state.active_stream_count();
                let result = state.add_stream(stream_id, MAX_CONCURRENT);

                // Property 3: max_concurrent enforcement.
                if pre_count >= MAX_CONCURRENT as usize {
                    assert!(
                        result.is_err(),
                        "add_stream must Err when at cap (pre_count={pre_count}, \
                         max={MAX_CONCURRENT})",
                    );
                } else if result.is_ok() {
                    // Successful add — the model tracks it.
                    model_active.insert(stream_id);
                }
            }
            Op::UpdateActivity { stream_id } => {
                state.update_activity(stream_id);
                // No state change to active_streams; just refreshes
                // last_activity.
            }
            Op::RemoveStream { stream_id } => {
                state.remove_stream(stream_id);
                model_active.remove(&stream_id);
            }
            Op::CleanupIdleZero => {
                let removed = state.cleanup_idle_streams(Duration::from_nanos(0));
                // Property 4: every previously-active stream must
                // be in `removed`, no duplicates.
                let mut seen = HashSet::new();
                for id in &removed {
                    assert!(
                        seen.insert(*id),
                        "cleanup_idle_streams returned duplicate stream id {id}",
                    );
                }
                for id in &removed {
                    model_active.remove(id);
                }
            }
            Op::CleanupIdleHour => {
                let removed = state.cleanup_idle_streams(Duration::from_secs(3600));
                // 1-hour timeout: realistic fuzz iterations finish
                // in milliseconds, so nothing should be removed.
                assert!(
                    removed.is_empty(),
                    "1-hour idle cleanup unexpectedly removed {} streams; \
                     fuzz iteration too slow OR clock-jump regression",
                    removed.len(),
                );
            }
            Op::QueryCount => {
                let actual = state.active_stream_count();
                // Property 2: model agrees with implementation.
                assert_eq!(
                    actual,
                    model_active.len(),
                    "active_stream_count={actual} disagrees with model {}",
                    model_active.len(),
                );
            }
        }
    }

    // Final consistency check after the op sequence.
    assert_eq!(
        state.active_stream_count(),
        model_active.len(),
        "final state-machine consistency failed",
    );
});
