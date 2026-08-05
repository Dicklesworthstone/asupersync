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
//! and separately compares the worker's bounded generation-aware direct table
//! with the retired generation ring and full-clear set. Batches:
//! {16, 64, 256, 1024} events × duplicate share {0%, 25%, 75%}. Duplicate
//! tokens repeat within a small window, matching how multiple readiness events
//! for one fd cluster inside a single turn. Token values are synthesized
//! deterministically — no randomness, identical input every iteration.

#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hint::black_box;

use asupersync::runtime::reactor::Token;
use asupersync::runtime::scheduler::worker::{MAX_SEEN_IO_TOKENS, SeenIoTokens};
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

/// The retired full-clear-at-cap strategy (br-asupersync-414j0b, commit
/// 3d6bb2104): bounded `HashSet` that clears ALL history when the cap is
/// reached. Kept as a historical CPU comparator; unlike the bounded direct
/// table, it also re-admits the complete retained set at a cap crossing.
struct FullClearReplica {
    seen: HashSet<u64>,
}

impl FullClearReplica {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity),
        }
    }

    fn observe(&mut self, token: u64) -> bool {
        if self.seen.len() >= MAX_SEEN_IO_TOKENS {
            self.seen.clear();
        }
        self.seen.insert(token)
    }
}

/// The generation-ring strategy shipped in b976af66a and retired by
/// br-asupersync-9y4yup. Keeping the replica preserves the measured 128 ns/op
/// comparison row while the live [`SeenIoTokens`] implementation moves to a
/// generation-aware direct table.
struct GenerationRingReplica {
    latest_generation: HashMap<u64, u64>,
    generation_order: VecDeque<(u64, u64)>,
    next_generation: u64,
}

impl GenerationRingReplica {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            latest_generation: HashMap::with_capacity(capacity),
            generation_order: VecDeque::with_capacity(capacity),
            next_generation: 0,
        }
    }

    fn observe(&mut self, token: u64) -> bool {
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        let generation = self.next_generation;
        let is_first_observation = match self.latest_generation.entry(token) {
            Entry::Occupied(mut entry) => {
                *entry.get_mut() = generation;
                false
            }
            Entry::Vacant(entry) => {
                entry.insert(generation);
                true
            }
        };

        self.generation_order.push_back((token, generation));
        while self.generation_order.len() > MAX_SEEN_IO_TOKENS {
            if let Some((old_token, old_generation)) = self.generation_order.pop_front() {
                if self.latest_generation.get(&old_token) == Some(&old_generation) {
                    self.latest_generation.remove(&old_token);
                }
            }
        }

        is_first_observation
    }
}

/// Cap-boundary comparator for the per-worker seen-token structures
/// (br-asupersync-sched-hot-path-perf-bt4y5f.9 AC2): fill the structure to
/// exactly the cap in setup, then measure a 256-observe window of fresh
/// tokens that crosses the boundary. The rows retain both historical
/// strategies and add the generation-aware direct table from
/// br-asupersync-9y4yup. Deterministic token sequences; setup excluded from
/// measurement.
fn bench_worker_seen_tokens_cap_boundary(c: &mut Criterion) {
    const WINDOW: usize = 256;
    let mut group = c.benchmark_group("sched/io_token_dedup");
    group.throughput(Throughput::Elements(WINDOW as u64));
    group.sample_size(10);

    group.bench_function("worker_generation_table_cap_boundary_window", |b| {
        b.iter_batched(
            || {
                let mut seen = SeenIoTokens::with_capacity(MAX_SEEN_IO_TOKENS);
                for token in 0..MAX_SEEN_IO_TOKENS as u64 {
                    seen.observe(token);
                }
                seen
            },
            |mut seen| {
                let base = MAX_SEEN_IO_TOKENS as u64;
                let mut first_sights = 0usize;
                for i in 0..WINDOW as u64 {
                    if seen.observe(base + i) {
                        first_sights += 1;
                    }
                }
                assert_eq!(first_sights, WINDOW);
                black_box(seen)
            },
            criterion::BatchSize::PerIteration,
        );
    });

    group.bench_function("worker_ring_cap_boundary_window", |b| {
        b.iter_batched(
            || {
                let mut seen = GenerationRingReplica::with_capacity(MAX_SEEN_IO_TOKENS);
                for token in 0..MAX_SEEN_IO_TOKENS as u64 {
                    seen.observe(token);
                }
                seen
            },
            |mut seen| {
                let base = MAX_SEEN_IO_TOKENS as u64;
                let mut first_sights = 0usize;
                for i in 0..WINDOW as u64 {
                    if seen.observe(base + i) {
                        first_sights += 1;
                    }
                }
                assert_eq!(first_sights, WINDOW);
                black_box(seen)
            },
            criterion::BatchSize::PerIteration,
        );
    });

    group.bench_function("worker_full_clear_cap_boundary_window", |b| {
        b.iter_batched(
            || {
                let mut seen = FullClearReplica::with_capacity(MAX_SEEN_IO_TOKENS);
                for token in 0..MAX_SEEN_IO_TOKENS as u64 {
                    seen.observe(token);
                }
                seen
            },
            |mut seen| {
                let base = MAX_SEEN_IO_TOKENS as u64;
                let mut first_sights = 0usize;
                for i in 0..WINDOW as u64 {
                    if seen.observe(base + i) {
                        first_sights += 1;
                    }
                }
                assert_eq!(first_sights, WINDOW);
                black_box(seen)
            },
            criterion::BatchSize::PerIteration,
        );
    });

    // Steady-state floors far from the boundary, same window shape.
    group.bench_function("worker_generation_table_steady_state_window", |b| {
        b.iter_batched(
            || {
                let mut seen = SeenIoTokens::with_capacity(MAX_SEEN_IO_TOKENS);
                for token in 0..(MAX_SEEN_IO_TOKENS / 2) as u64 {
                    seen.observe(token);
                }
                seen
            },
            |mut seen| {
                let base = MAX_SEEN_IO_TOKENS as u64;
                for i in 0..WINDOW as u64 {
                    black_box(seen.observe(base + i));
                }
                black_box(seen)
            },
            criterion::BatchSize::PerIteration,
        );
    });

    group.bench_function("worker_ring_steady_state_window", |b| {
        b.iter_batched(
            || {
                let mut seen = GenerationRingReplica::with_capacity(MAX_SEEN_IO_TOKENS);
                for token in 0..(MAX_SEEN_IO_TOKENS / 2) as u64 {
                    seen.observe(token);
                }
                seen
            },
            |mut seen| {
                let base = MAX_SEEN_IO_TOKENS as u64;
                for i in 0..WINDOW as u64 {
                    black_box(seen.observe(base + i));
                }
                black_box(seen)
            },
            criterion::BatchSize::PerIteration,
        );
    });

    group.bench_function("worker_full_clear_steady_state_window", |b| {
        b.iter_batched(
            || {
                let mut seen = FullClearReplica::with_capacity(MAX_SEEN_IO_TOKENS);
                for token in 0..(MAX_SEEN_IO_TOKENS / 2) as u64 {
                    seen.observe(token);
                }
                seen
            },
            |mut seen| {
                let base = MAX_SEEN_IO_TOKENS as u64;
                for i in 0..WINDOW as u64 {
                    black_box(seen.observe(base + i));
                }
                black_box(seen)
            },
            criterion::BatchSize::PerIteration,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_token_dedup,
    bench_worker_seen_tokens_cap_boundary
);

fn main() {
    benches();
    Criterion::default().configure_from_args().final_summary();
    // COMPARATOR-ONLY: this binary is deliberately NOT Phase-6 gated. Its
    // value is the RELATIVE strategy data for the I/O-driver and worker
    // seen-token levers, whose alternatives measure back-to-back under
    // identical load. The ABSOLUTE cell costs are cache-resident microbenches
    // that drifted +15..111% between same-host runs under co-tenant fleet
    // compile load (2026-07-27, ovh-a) — a 5% hard gate on them would be a
    // flake generator, not a regression net.
    // See docs/perf_runbook.md and artifacts/baseline.json note_sched.
}
