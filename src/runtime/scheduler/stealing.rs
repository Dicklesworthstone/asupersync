//! Work stealing logic.

use crate::runtime::scheduler::local_queue::Stealer;
use crate::types::TaskId;
use crate::util::DetRng;

/// Tries to steal a task from a list of stealers.
///
/// Implements "The Power of Two Choices" randomized load balancing.
/// Instead of a sequential scan, this selects two candidates at random,
/// queries their lengths, and attempts to steal from the more loaded queue.
/// If that queue is empty or fails, it falls back to the other candidate.
/// This drastically reduces tail-latency on task distribution and minimizes
/// lock contention compared to linear probing or pure random choice.
#[inline]
pub fn steal_task(stealers: &[Stealer], rng: &mut DetRng) -> Option<TaskId> {
    let len = stealers.len();
    if len == 0 {
        return None;
    }
    if len == 1 {
        return stealers[0].steal();
    }

    // Alien Artifact: Power of Two Choices (Mitzenmacher 2001)
    // Select two distinct random queues.
    let idx1 = rng.next_usize(len);
    let mut idx2 = rng.next_usize(len);
    if idx1 == idx2 {
        idx2 = (idx1 + 1) % len;
    }

    let len1 = stealers[idx1].stealable_len_hint();
    let len2 = stealers[idx2].stealable_len_hint();

    // Prefer the queue that appears to have more work.
    let (primary, primary_hint, secondary, secondary_hint) = if len1 >= len2 {
        (idx1, len1, idx2, len2)
    } else {
        (idx2, len2, idx1, len1)
    };

    // `stealable_len_hint()` and `steal()` inspect the same bounded frontier.
    // When the hint is zero, an immediate steal would just rescan that same
    // prefix and return `None` unless the queue mutates concurrently.
    if primary_hint > 0
        && let Some(task) = stealers[primary].steal()
    {
        return Some(task);
    }

    if secondary_hint > 0
        && let Some(task) = stealers[secondary].steal()
    {
        return Some(task);
    }

    // Fallback to linear scan if both failed but there might be hidden work
    // (e.g. they had tasks but they were local, so steal() returned None).
    let start = rng.next_usize(len);
    for i in 0..len {
        let idx = circular_index(start, i, len);
        if idx == primary || idx == secondary {
            continue; // Already tried
        }
        if let Some(task) = stealers[idx].steal() {
            return Some(task);
        }
    }

    None
}

#[inline]
fn circular_index(start: usize, offset: usize, len: usize) -> usize {
    debug_assert!(len > 0);
    // start is in [0, len) and offset is in [0, len).
    // Thus start + offset < 2 * len. Since len is the length of a Vec,
    // 2 * len cannot overflow usize. We do not need wrapping_add,
    // and using it would be mathematically incorrect if start was large
    // because (x + y) % len != (x % len + y % len) % len across overflow.
    (start + offset) % len
}

#[cfg(test)]
#[path = "stealing_inline_tests.rs"]
mod tests;
