//! Focused metamorphic test for `asupersync::trace::buffer`.
//!
//! `TraceBuffer` is a fixed-capacity ring buffer: once full, each push evicts
//! the oldest event. Its one defining invariant is a **sliding window** —
//! after pushing `n` events into a capacity-`c` buffer, the buffer holds
//! exactly the most recent `min(n, c)` of them, in insertion order. The
//! inline unit tests check this on a couple of hand-picked sizes; this file
//! sweeps the capacity × push-count grid so an off-by-one in the wrap
//! arithmetic cannot hide in an untested size combination.

use asupersync::trace::{TraceBuffer, TraceBufferHandle, TraceData, TraceEvent, TraceEventKind};
use asupersync::types::Time;

/// A trace event whose `seq` doubles as its identity in assertions.
fn ev(seq: u64) -> TraceEvent {
    TraceEvent::new(seq, Time::ZERO, TraceEventKind::UserTrace, TraceData::None)
}

const CAPS: &[usize] = &[1, 2, 3, 5, 8, 16, 64];

// ---------------------------------------------------------------------------
// The sliding-window invariant
// ---------------------------------------------------------------------------

#[test]
fn ring_holds_exactly_the_last_min_n_cap_events_in_order() {
    for &cap in CAPS {
        // Push from 0 up to 3*cap events, checking the window after each push.
        for n in 0..=(3 * cap) {
            let mut buf = TraceBuffer::new(cap);
            for seq in 0..n {
                buf.push(ev(seq as u64));
            }
            let kept: Vec<u64> = buf.iter().map(|e| e.seq).collect();

            let expected_len = n.min(cap);
            let first_kept = n - expected_len; // seq of the oldest survivor
            let expected: Vec<u64> = (first_kept..n).map(|x| x as u64).collect();

            assert_eq!(
                kept, expected,
                "ring window wrong (cap={cap}, pushed={n}): got {kept:?}"
            );
            assert_eq!(buf.len(), expected_len, "len wrong (cap={cap}, pushed={n})");
            assert_eq!(buf.is_empty(), n == 0);
            assert_eq!(
                buf.is_full(),
                n >= cap,
                "is_full wrong (cap={cap}, pushed={n})"
            );
        }
    }
}

#[test]
fn iter_is_strictly_increasing_and_capacity_bounded() {
    // Because we push strictly increasing seqs, the retained window must be
    // strictly increasing, and its length never exceeds capacity.
    for &cap in CAPS {
        let mut buf = TraceBuffer::new(cap);
        for seq in 0..=(2 * cap) {
            buf.push(ev(seq as u64));
            let seqs: Vec<u64> = buf.iter().map(|e| e.seq).collect();
            assert!(seqs.len() <= cap, "len exceeded capacity (cap={cap})");
            for w in seqs.windows(2) {
                assert!(w[0] < w[1], "iter not strictly increasing (cap={cap})");
            }
            assert_eq!(seqs.len(), buf.iter().count(), "iter length unstable");
        }
    }
}

#[test]
fn last_is_always_the_most_recent_push() {
    for &cap in CAPS {
        let mut buf = TraceBuffer::new(cap);
        assert!(buf.last().is_none(), "empty buffer must have no last");
        for seq in 0..(3 * cap) {
            buf.push(ev(seq as u64));
            assert_eq!(
                buf.last().map(|e| e.seq),
                Some(seq as u64),
                "last() not the newest push (cap={cap}, seq={seq})"
            );
        }
    }
}

#[test]
fn clear_returns_the_buffer_to_the_empty_state() {
    for &cap in CAPS {
        let mut buf = TraceBuffer::new(cap);
        for seq in 0..(cap + 3) {
            buf.push(ev(seq as u64));
        }
        buf.clear();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert!(!buf.is_full() || cap == 0, "cleared buffer is not full");
        assert!(buf.last().is_none());
        assert_eq!(buf.iter().count(), 0);

        // The buffer is fully reusable after a clear — the window restarts.
        buf.push(ev(999));
        assert_eq!(buf.last().map(|e| e.seq), Some(999));
        assert_eq!(buf.len(), 1);
    }
}

#[test]
fn capacity_is_clamped_to_at_least_one() {
    // `new(0)` must not yield a zero-length buffer (its push/iter math takes
    // `% capacity`, which would divide by zero).
    let mut buf = TraceBuffer::new(0);
    assert_eq!(buf.capacity(), 1);
    buf.push(ev(1));
    buf.push(ev(2));
    assert_eq!(
        buf.len(),
        1,
        "capacity-1 buffer keeps only the newest event"
    );
    assert_eq!(buf.last().map(|e| e.seq), Some(2));
}

// ---------------------------------------------------------------------------
// TraceBufferHandle — the same window, plus the eviction-counting tally
// ---------------------------------------------------------------------------

#[test]
fn handle_snapshot_matches_the_sliding_window_and_counts_evictions() {
    for &cap in CAPS {
        for n in 0..=(2 * cap + 1) {
            let handle = TraceBufferHandle::new(cap);
            for seq in 0..n {
                handle.push_event(ev(seq as u64));
            }
            let snap: Vec<u64> = handle.snapshot().iter().map(|e| e.seq).collect();

            let expected_len = n.min(cap);
            let expected: Vec<u64> = ((n - expected_len)..n).map(|x| x as u64).collect();
            assert_eq!(
                snap, expected,
                "handle window wrong (cap={cap}, pushed={n})"
            );
            assert_eq!(handle.len(), expected_len);
            assert_eq!(handle.is_empty(), n == 0);

            // total_pushed counts every push, including events later evicted.
            assert_eq!(
                handle.total_pushed(),
                n as u64,
                "total_pushed must count evicted events too (cap={cap}, pushed={n})"
            );
        }
    }
}

#[test]
fn handle_record_event_assigns_monotonic_sequence_numbers() {
    // `record_event` allocates the next seq under the buffer lock; sequential
    // calls must see 0, 1, 2, … and the buffer must keep them in that order.
    let handle = TraceBufferHandle::new(16);
    for _ in 0..10 {
        handle.record_event(ev);
    }
    let seqs: Vec<u64> = handle.snapshot().iter().map(|e| e.seq).collect();
    assert_eq!(seqs, (0..10).collect::<Vec<u64>>());
    assert_eq!(handle.total_pushed(), 10);
}
