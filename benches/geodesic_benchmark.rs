//! Geodesic normalization benchmark suite.
//!
//! Measures normalization performance across trace sizes and algorithms:
//! - Runtime vs trace length n (exact/beam/greedy crossover)
//! - Switch-cost improvement ratios
//! - Poset construction overhead
//!
//! All inputs are deterministic (fixed seeds).

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use asupersync::trace::event_structure::{OwnerKey, TracePoset};
use asupersync::trace::{GeodesicConfig, TraceEvent};
use asupersync::types::{RegionId, TaskId, Time};

// ============================================================================
// Deterministic trace generators
// ============================================================================

/// Generate a synthetic trace with `n` events spread across `owners` tasks.
/// Uses a deterministic interleaving pattern seeded by `seed`.
fn generate_interleaved_trace(n: usize, owners: usize, seed: u64) -> Vec<TraceEvent> {
    let mut events = Vec::with_capacity(n);
    let region = RegionId::new_for_test(0, 0);

    for i in 0..n {
        // Deterministic owner assignment: mix seed into index
        let owner_idx = ((i as u64).wrapping_mul(seed.wrapping_add(7)) % owners as u64) as u32;
        let task = TaskId::new_for_test(owner_idx, 0);
        let time = Time::from_nanos(i as u64 * 1000);
        events.push(TraceEvent::spawn((i + 1) as u64, time, task, region));
    }
    events
}

/// Generate a trace with high contention (frequent owner switches).
fn generate_high_contention_trace(n: usize, owners: usize) -> Vec<TraceEvent> {
    let region = RegionId::new_for_test(0, 0);
    let mut events = Vec::with_capacity(n);

    for i in 0..n {
        // Round-robin across owners: worst case for switch cost
        let owner_idx = (i % owners) as u32;
        let task = TaskId::new_for_test(owner_idx, 0);
        let time = Time::from_nanos(i as u64 * 1000);
        events.push(TraceEvent::spawn((i + 1) as u64, time, task, region));
    }
    events
}

/// Generate a trace with low contention (long runs of same owner).
fn generate_low_contention_trace(n: usize, owners: usize) -> Vec<TraceEvent> {
    let region = RegionId::new_for_test(0, 0);
    let mut events = Vec::with_capacity(n);

    let chunk_size = (n / owners).max(1);
    for i in 0..n {
        let owner_idx = (i / chunk_size).min(owners - 1) as u32;
        let task = TaskId::new_for_test(owner_idx, 0);
        let time = Time::from_nanos(i as u64 * 1000);
        events.push(TraceEvent::spawn((i + 1) as u64, time, task, region));
    }
    events
}

fn count_switches(events: &[TraceEvent]) -> usize {
    if events.len() < 2 {
        return 0;
    }
    events
        .windows(2)
        .filter(|w| OwnerKey::for_event(&w[0]) != OwnerKey::for_event(&w[1]))
        .count()
}

// ============================================================================
// Poset construction benchmark
// ============================================================================

fn bench_poset_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("geodesic_poset_build");

    for &n in &[10, 20, 50, 100, 200, 500] {
        group.throughput(Throughput::Elements(n as u64));

        let trace = generate_interleaved_trace(n, 4, 42);

        group.bench_with_input(BenchmarkId::new("from_trace", n), &trace, |b, trace| {
            b.iter(|| {
                let poset = TracePoset::from_trace(black_box(trace));
                black_box(poset)
            });
        });
    }

    group.finish();
}

// ============================================================================
// Exact A* search benchmark (small traces only)
// ============================================================================

fn bench_exact_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("geodesic_exact");

    let config = GeodesicConfig {
        exact_threshold: 64,
        beam_threshold: 0,
        beam_width: 0,
        step_budget: 1_000_000,
    };

    // Exact is exponential; keep sizes small
    for &n in &[5, 8, 10, 12, 15, 20, 25, 30] {
        let trace = generate_interleaved_trace(n, 3, 42);
        let poset = TracePoset::from_trace(&trace);

        group.bench_with_input(
            BenchmarkId::new("interleaved_3own", n),
            &poset,
            |b, poset| {
                b.iter(|| {
                    let result = asupersync::trace::geodesic_normalize(black_box(poset), &config);
                    black_box(result)
                });
            },
        );
    }

    // High contention (worst case for exact: many switches to optimize)
    for &n in &[5, 8, 10, 15, 20] {
        let trace = generate_high_contention_trace(n, 4);
        let poset = TracePoset::from_trace(&trace);

        group.bench_with_input(
            BenchmarkId::new("high_contention_4own", n),
            &poset,
            |b, poset| {
                b.iter(|| {
                    let result = asupersync::trace::geodesic_normalize(black_box(poset), &config);
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Beam search benchmark (medium traces)
// ============================================================================

fn bench_beam_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("geodesic_beam");

    for &width in &[4, 8, 16, 32] {
        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 1000,
            beam_width: width,
            step_budget: 1_000_000,
        };

        for &n in &[20, 50, 100, 200] {
            let trace = generate_interleaved_trace(n, 4, 42);
            let poset = TracePoset::from_trace(&trace);

            group.bench_with_input(
                BenchmarkId::new(format!("w={width}"), n),
                &poset,
                |b, poset| {
                    b.iter(|| {
                        let result =
                            asupersync::trace::geodesic_normalize(black_box(poset), &config);
                        black_box(result)
                    });
                },
            );
        }
    }

    group.finish();
}

// ============================================================================
// Greedy benchmark (large traces)
// ============================================================================

fn bench_greedy(c: &mut Criterion) {
    let mut group = c.benchmark_group("geodesic_greedy");

    let config = GeodesicConfig {
        exact_threshold: 0,
        beam_threshold: 0,
        beam_width: 0,
        step_budget: 1_000_000,
    };

    for &n in &[10, 50, 100, 200, 500, 1000] {
        group.throughput(Throughput::Elements(n as u64));

        let trace = generate_interleaved_trace(n, 4, 42);
        let poset = TracePoset::from_trace(&trace);

        group.bench_with_input(
            BenchmarkId::new("interleaved_4own", n),
            &poset,
            |b, poset| {
                b.iter(|| {
                    let result = asupersync::trace::geodesic_normalize(black_box(poset), &config);
                    black_box(result)
                });
            },
        );
    }

    // Also test with different owner counts
    for &owners in &[2, 4, 8, 16] {
        let n = 200;
        let trace = generate_interleaved_trace(n, owners, 42);
        let poset = TracePoset::from_trace(&trace);

        group.bench_with_input(
            BenchmarkId::new(format!("n=200_{owners}own"), owners),
            &poset,
            |b, poset| {
                b.iter(|| {
                    let result = asupersync::trace::geodesic_normalize(black_box(poset), &config);
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Algorithm crossover comparison
// ============================================================================

fn bench_algorithm_crossover(c: &mut Criterion) {
    let mut group = c.benchmark_group("geodesic_crossover");

    let exact_config = GeodesicConfig {
        exact_threshold: 64,
        beam_threshold: 0,
        beam_width: 0,
        step_budget: 1_000_000,
    };

    let beam_config = GeodesicConfig {
        exact_threshold: 0,
        beam_threshold: 1000,
        beam_width: 8,
        step_budget: 1_000_000,
    };

    let greedy_config = GeodesicConfig::greedy_only();

    // Crossover region: where exact becomes too slow and beam/greedy take over
    for &n in &[10, 15, 20, 25, 30] {
        let trace = generate_interleaved_trace(n, 3, 42);
        let poset = TracePoset::from_trace(&trace);

        group.bench_with_input(BenchmarkId::new("exact", n), &poset, |b, poset| {
            b.iter(|| {
                let result = asupersync::trace::geodesic_normalize(black_box(poset), &exact_config);
                black_box(result)
            });
        });

        group.bench_with_input(BenchmarkId::new("beam_w8", n), &poset, |b, poset| {
            b.iter(|| {
                let result = asupersync::trace::geodesic_normalize(black_box(poset), &beam_config);
                black_box(result)
            });
        });

        group.bench_with_input(BenchmarkId::new("greedy", n), &poset, |b, poset| {
            b.iter(|| {
                let result =
                    asupersync::trace::geodesic_normalize(black_box(poset), &greedy_config);
                black_box(result)
            });
        });
    }

    group.finish();
}

// ============================================================================
// Switch-cost improvement measurement
// ============================================================================

fn bench_switch_cost_improvement(c: &mut Criterion) {
    let mut group = c.benchmark_group("geodesic_cost_improvement");

    let default_config = GeodesicConfig::default();

    // Measure end-to-end: build poset + normalize + count improvement
    for &(label, n, owners) in &[
        ("low_contention", 100usize, 4usize),
        ("high_contention", 100, 4),
        ("many_owners", 100, 16),
        ("large_trace", 500, 4),
    ] {
        let trace = if label == "high_contention" {
            generate_high_contention_trace(n, owners)
        } else if label == "low_contention" {
            generate_low_contention_trace(n, owners)
        } else {
            generate_interleaved_trace(n, owners, 42)
        };

        let original_switches = count_switches(&trace);
        let poset = TracePoset::from_trace(&trace);
        let result = asupersync::trace::geodesic_normalize(&poset, &default_config);

        // Print cost data (visible with --nocapture)
        eprintln!(
            "  [{label:>20}] n={n:<4} owners={owners:<3} orig_sw={:<4} norm_sw={:<4} reduction={:<4} algo={:?}",
            original_switches,
            result.switch_count,
            original_switches.saturating_sub(result.switch_count),
            result.algorithm,
        );

        group.bench_function(BenchmarkId::new("e2e", label), |b| {
            b.iter(|| {
                let poset = TracePoset::from_trace(black_box(&trace));
                let result =
                    asupersync::trace::geodesic_normalize(black_box(&poset), &default_config);
                black_box(result)
            });
        });
    }

    group.finish();
}

// ============================================================================
// Criterion setup
// ============================================================================

criterion_group!(
    benches,
    bench_poset_construction,
    bench_exact_search,
    bench_beam_search,
    bench_greedy,
    bench_algorithm_crossover,
    bench_switch_cost_improvement,
);

criterion_main!(benches);
