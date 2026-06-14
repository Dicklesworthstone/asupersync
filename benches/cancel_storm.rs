//! Cancel-storm benchmark for the three_lane local-ready cancel path
//! (br-asupersync-ayg4ot).
//!
//! When the scheduler cancels a task that is sitting in a worker's local ready
//! queue, it locates it with `VecDeque::iter().position()` (an O(n) scan) and
//! removes it with `VecDeque::remove(pos)` (an O(n) mid-vector shift). Per
//! single cancel that is O(n); cancelling all N tasks in the queue is O(N^2).
//! The structured-concurrency mass-cancel cases — region close cancelling all
//! live children, FailFast cancelling siblings, runtime shutdown — hit exactly
//! this, so cleanup latency degrades quadratically in queue depth.
//!
//! This bench measures the CURRENT approach (`scan_remove`) against the proposed
//! lazy-tombstone approach (`tombstone`: O(1) cancel via a membership set plus an
//! O(N) skip-on-drain, which is what the dispatch ready-pop performs). Both
//! produce the same logical result (every queued task cancelled), so the
//! O(N^2) -> O(N) improvement is a measured before/after, not a claim.
//!
//! Cancel ORDER matters and is modeled honestly: the local ready queue is FIFO
//! (wake order), but mass-cancel iterates a region's child set, whose order is
//! UNCORRELATED with wake order. The worst (and realistic) case is cancelling
//! opposite to queue order — every `iter().position()` then scans the full
//! remaining queue, giving the O(N^2) the bead describes. (Cancelling in queue
//! order would find each target at the front, an O(N) best case that hides the
//! defect; this bench deliberately does NOT do that.) The tombstone approach is
//! cancel-order-independent.

#![cfg(feature = "test-internals")]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::collections::{HashSet, VecDeque};
use std::hint::black_box;

use asupersync::types::TaskId;

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

/// Current scheduler approach: per-cancel `iter().position()` + `VecDeque::remove`.
/// Cancelling every task in an N-deep queue is O(N^2).
fn cancel_storm_scan_remove(n: u32) {
    let mut queue: VecDeque<TaskId> = (0..n).map(task).collect();
    // Cancel opposite to queue order (realistic worst case: each scan must
    // traverse the full remaining queue) -> O(N^2).
    for id in (0..n).rev().map(task) {
        if let Some(pos) = queue.iter().position(|t| *t == id) {
            queue.remove(pos);
        }
    }
    black_box(&queue);
}

/// Proposed lazy-tombstone approach: O(1) cancel (membership-set insert) plus an
/// O(N) skip-on-drain (the work the dispatch ready-pop does). O(N) overall.
fn cancel_storm_tombstone(n: u32) {
    let queue: VecDeque<TaskId> = (0..n).map(task).collect();
    let mut cancelled: HashSet<TaskId> = HashSet::with_capacity(n as usize);
    // Same workload (cancel every task); order is irrelevant for the tombstone
    // approach since each cancel is an O(1) set insert.
    for id in (0..n).rev().map(task) {
        cancelled.insert(id);
    }
    let mut survivors: VecDeque<TaskId> = VecDeque::with_capacity(queue.len());
    for t in queue {
        if !cancelled.contains(&t) {
            survivors.push_back(t);
        }
    }
    black_box(&survivors);
}

fn bench_cancel_storm(c: &mut Criterion) {
    let mut group = c.benchmark_group("cancel_storm");
    for &n in &[64u32, 512, 4096] {
        group.bench_with_input(BenchmarkId::new("scan_remove", n), &n, |b, &n| {
            b.iter(|| cancel_storm_scan_remove(black_box(n)));
        });
        group.bench_with_input(BenchmarkId::new("tombstone", n), &n, |b, &n| {
            b.iter(|| cancel_storm_tombstone(black_box(n)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_cancel_storm);
criterion_main!(benches);
