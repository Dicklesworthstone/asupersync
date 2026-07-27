//! Seen-IO-token dedup benchmarks
//! (br-asupersync-sched-hot-path-perf-bt4y5f.1; decision instrument for the
//! seen-token upgrade lever br-asupersync-sched-hot-path-perf-bt4y5f.9).
//!
//! The I/O driver deduplicates event tokens per reactor turn before waker
//! dispatch. Two shapes exist in `src/runtime/io_driver.rs` today:
//!
//! - the live turn path builds a **fresh `HashSet<Token>` every turn**
//!   (`turn_with`, io_driver.rs:309) — per-turn allocation plus hashing;
//! - the restore path uses a **`SmallVec<[Token; 64]>` linear `contains`**
//!   (io_driver.rs:392) — allocation-free below 64 tokens but O(n·m).
//!
//! This bench pins both strategies over the same deterministic event batches
//! so the lever's replacement (bounded LRU / generation ring) has a recorded
//! comparator. Batches: {16, 64, 256, 1024} events × duplicate share
//! {0%, 25%, 75%}. Duplicate tokens repeat within a small window, matching
//! how multiple readiness events for one fd cluster inside a single turn.
//! Token values are synthesized deterministically — no randomness, identical
//! input every iteration.

#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group};
use std::collections::HashSet;
use std::hint::black_box;

use asupersync::runtime::reactor::Token;
use smallvec::SmallVec;

const BATCH_SIZES: [usize; 4] = [16, 64, 256, 1024];
const DUP_PERCENTS: [usize; 3] = [0, 25, 75];

/// Deterministic event-token batch: `dup_percent` of slots repeat a token from
/// a small trailing window (fd readiness events cluster within a turn); the
/// rest are unique slab keys.
fn token_batch(len: usize, dup_percent: usize) -> Vec<Token> {
    let mut tokens = Vec::with_capacity(len);
    for i in 0..len {
        // Fixed-point pseudo-pattern: deterministic, uniform-ish, seed-free.
        let roll = (i * 7919 + 104_729) % 100;
        if roll < dup_percent && i > 0 {
            let back = (i * 31 + 7) % i.min(8).max(1) + 1;
            let repeated = tokens[i - back.min(i)];
            tokens.push(repeated);
        } else {
            tokens.push(Token(4096 + i));
        }
    }
    tokens
}

/// The live `turn_with` shape: fresh `HashSet` per turn, insert-as-check.
fn dedup_hashset_per_turn(batch: &[Token]) -> usize {
    let mut seen_tokens = HashSet::<Token>::new();
    let mut dispatched = 0usize;
    for token in batch {
        if !seen_tokens.insert(*token) {
            continue;
        }
        dispatched += 1;
    }
    dispatched
}

/// The restore-path shape: `SmallVec` linear membership.
fn dedup_smallvec_contains(batch: &[Token]) -> usize {
    let mut seen_tokens = SmallVec::<[Token; 64]>::new();
    let mut dispatched = 0usize;
    for token in batch {
        if seen_tokens.contains(token) {
            continue;
        }
        seen_tokens.push(*token);
        dispatched += 1;
    }
    dispatched
}

fn bench_token_dedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("sched/io_token_dedup");
    group.sample_size(20);

    for batch_len in BATCH_SIZES {
        for dup_percent in DUP_PERCENTS {
            let batch = token_batch(batch_len, dup_percent);
            let expected = dedup_hashset_per_turn(&batch);
            assert_eq!(
                expected,
                dedup_smallvec_contains(&batch),
                "both strategies must agree on the kept-token count"
            );

            group.throughput(Throughput::Elements(batch_len as u64));
            group.bench_function(
                BenchmarkId::new("hashset_per_turn", format!("{batch_len}x{dup_percent}pct")),
                |b| {
                    b.iter(|| {
                        let dispatched = dedup_hashset_per_turn(black_box(&batch));
                        assert_eq!(dispatched, expected);
                    });
                },
            );
            group.bench_function(
                BenchmarkId::new("smallvec_contains", format!("{batch_len}x{dup_percent}pct")),
                |b| {
                    b.iter(|| {
                        let dispatched = dedup_smallvec_contains(black_box(&batch));
                        assert_eq!(dispatched, expected);
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_token_dedup);

fn main() {
    benches();
    Criterion::default().configure_from_args().final_summary();
    // COMPARATOR-ONLY: this binary is deliberately NOT Phase-6 gated. Its
    // value is the RELATIVE hashset-vs-smallvec strategy data for the
    // seen-token lever (bt4y5f.9), which is robust because both strategies
    // measure back-to-back under identical load. The ABSOLUTE cell costs are
    // cache-resident microbenches that drifted +15..111% between same-host
    // runs under co-tenant fleet compile load (2026-07-27, ovh-a) — a 5%
    // hard gate on them would be a flake generator, not a regression net.
    // See docs/perf_runbook.md and artifacts/baseline.json note_sched.
}
