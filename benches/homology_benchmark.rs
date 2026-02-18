//! Homology scoring overhead benchmarks for Asupersync (bd-2528).
//!
//! Profiles the persistent homology pipeline used by `TopologyExplorer` to
//! prioritize schedule exploration. Isolates each stage so hotspots are
//! actionable:
//!
//! - Square complex construction from edge lists
//! - Boundary operator computation (∂₁, ∂₂)
//! - Column reduction (GF(2) elimination)
//! - Persistence pair extraction
//! - Topological scoring (novelty + persistence sum)
//! - End-to-end pipeline: edges → complex → boundary → reduce → score
//! - TracePoset construction from synthetic traces
//!
//! Performance targets:
//! - Complex construction: < 100µs for 100-vertex grids
//! - Column reduction: < 1ms for matrices with ~100 columns
//! - End-to-end scoring: < 2ms for typical exploration step

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use asupersync::trace::TraceEvent;
use asupersync::trace::boundary::SquareComplex;
use asupersync::trace::event_structure::TracePoset;
use asupersync::trace::gf2::{BoundaryMatrix, PersistencePairs};
use asupersync::trace::scoring::{
    ClassId, score_boundary_matrix, score_persistence, seed_fingerprint,
};
use asupersync::types::{RegionId, TaskId, Time};
use std::collections::BTreeSet;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Build a grid lattice with `n` rows and `n` columns.
///
/// Vertices: `n*n`, indexed as `i*n + j`.
/// Edges: right `(i,j)→(i,j+1)` and down `(i,j)→(i+1,j)`.
/// Squares: `(n-1)*(n-1)` commuting diamonds.
fn build_grid_edges(n: usize) -> (usize, Vec<(usize, usize)>) {
    let idx = |i: usize, j: usize| i * n + j;
    let mut edges = Vec::new();
    for i in 0..n {
        for j in 0..n {
            if j + 1 < n {
                edges.push((idx(i, j), idx(i, j + 1)));
            }
            if i + 1 < n {
                edges.push((idx(i, j), idx(i + 1, j)));
            }
        }
    }
    (n * n, edges)
}

/// Build a diamond chain: n sequential commuting diamonds.
///
/// Each diamond shares a vertex with the next, giving `3n+1` vertices
/// and `n` squares.
fn build_diamond_chain(n: usize) -> (usize, Vec<(usize, usize)>) {
    // Vertices: 0, then for each diamond k: top=3k+1, bottom=3k+2, right=3k+3
    let num_verts = 3 * n + 1;
    let mut edges = Vec::new();
    for k in 0..n {
        let left = 3 * k;
        let top = 3 * k + 1;
        let bot = 3 * k + 2;
        let right = 3 * k + 3;
        edges.push((left, top));
        edges.push((left, bot));
        edges.push((top, right));
        edges.push((bot, right));
    }
    (num_verts, edges)
}

/// Generate a synthetic trace with `num_tasks` tasks, each performing
/// `events_per_task` lifecycle events (spawn, poll, complete) on separate regions.
///
/// Independent tasks on separate regions create commutative structure.
fn build_synthetic_trace(num_tasks: u32, events_per_task: u32) -> Vec<TraceEvent> {
    let mut events = Vec::new();
    let mut seq = 1u64;
    let mut time_ns = 10u64;

    for t in 0..num_tasks {
        let task_id = TaskId::new_for_test(t, 0);
        let region_id = RegionId::new_for_test(t, 0);

        // Spawn
        events.push(TraceEvent::spawn(
            seq,
            Time::from_nanos(time_ns),
            task_id,
            region_id,
        ));
        seq += 1;
        time_ns += 10;

        // Intermediate polls
        for _ in 1..events_per_task.saturating_sub(1) {
            events.push(TraceEvent::poll(
                seq,
                Time::from_nanos(time_ns),
                task_id,
                region_id,
            ));
            seq += 1;
            time_ns += 10;
        }

        // Complete
        if events_per_task >= 2 {
            events.push(TraceEvent::complete(
                seq,
                Time::from_nanos(time_ns),
                task_id,
                region_id,
            ));
            seq += 1;
            time_ns += 10;
        }
    }
    events
}

// =============================================================================
// COMPLEX CONSTRUCTION
// =============================================================================

/// Benchmarks `SquareComplex::from_edges()` for grid lattices of varying size.
fn bench_complex_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("homology_complex_construction");

    for &n in &[4u32, 8, 16, 32] {
        let n_usize = n as usize;
        let (num_verts, edges) = build_grid_edges(n_usize);
        let total_cells = num_verts + edges.len() + (n_usize - 1) * (n_usize - 1);
        group.throughput(Throughput::Elements(total_cells as u64));

        group.bench_with_input(
            BenchmarkId::new("grid", format!("{n}x{n}")),
            &(num_verts, edges),
            |b, (nv, e)| b.iter(|| black_box(SquareComplex::from_edges(*nv, e.clone()))),
        );
    }

    // Diamond chains
    for &count in &[10u32, 50, 200] {
        let (num_verts, edges) = build_diamond_chain(count as usize);
        group.throughput(Throughput::Elements(num_verts as u64));

        group.bench_with_input(
            BenchmarkId::new("diamond_chain", count),
            &(num_verts, edges),
            |b, (nv, e)| b.iter(|| black_box(SquareComplex::from_edges(*nv, e.clone()))),
        );
    }

    group.finish();
}

// =============================================================================
// BOUNDARY OPERATOR COMPUTATION
// =============================================================================

/// Benchmarks boundary operator construction (∂₁ and ∂₂) for grid complexes.
fn bench_boundary_operators(c: &mut Criterion) {
    let mut group = c.benchmark_group("homology_boundary_operators");

    for &n in &[4u32, 8, 16, 32] {
        let n_usize = n as usize;
        let (num_verts, edges) = build_grid_edges(n_usize);
        let cx = SquareComplex::from_edges(num_verts, edges);

        group.bench_with_input(
            BenchmarkId::new("boundary_1", format!("{n}x{n}")),
            &cx,
            |b, cx| b.iter(|| black_box(cx.boundary_1())),
        );

        group.bench_with_input(
            BenchmarkId::new("boundary_2", format!("{n}x{n}")),
            &cx,
            |b, cx| b.iter(|| black_box(cx.boundary_2())),
        );
    }

    group.finish();
}

// =============================================================================
// COLUMN REDUCTION
// =============================================================================

/// Benchmarks GF(2) column reduction on boundary matrices of varying size.
fn bench_column_reduction(c: &mut Criterion) {
    let mut group = c.benchmark_group("homology_column_reduction");

    for &n in &[4u32, 8, 16, 32] {
        let n_usize = n as usize;
        let (num_verts, edges) = build_grid_edges(n_usize);
        let cx = SquareComplex::from_edges(num_verts, edges);
        let d2 = cx.boundary_2();

        group.throughput(Throughput::Elements(d2.cols() as u64));

        group.bench_with_input(
            BenchmarkId::new("reduce_d2", format!("{n}x{n}")),
            &d2,
            |b, d2| b.iter(|| black_box(d2.reduce())),
        );

        // Also benchmark reducing the combined boundary (∂₁)
        let d1 = cx.boundary_1();
        group.bench_with_input(
            BenchmarkId::new("reduce_d1", format!("{n}x{n}")),
            &d1,
            |b, d1| b.iter(|| black_box(d1.reduce())),
        );
    }

    group.finish();
}

// =============================================================================
// PERSISTENCE PAIR EXTRACTION
// =============================================================================

/// Build a combined filtration boundary matrix for an NxN grid.
///
/// The combined matrix includes vertex, edge, and square columns in filtration
/// order, producing a square-ish matrix where persistence_pairs() is safe.
fn build_combined_filtration(n: usize) -> BoundaryMatrix {
    let (num_verts, edges) = build_grid_edges(n);
    let cx = SquareComplex::from_edges(num_verts, edges);
    let num_edges = cx.edges.len();
    let num_squares = cx.squares.len();
    let total = num_verts + num_edges + num_squares;

    let mut d = BoundaryMatrix::zeros(total, total);

    // Edge columns: ∂₁(edge) = source + target (vertex rows)
    for (col_offset, &(s, t)) in cx.edges.iter().enumerate() {
        let col = num_verts + col_offset;
        d.set(s, col);
        d.set(t, col);
    }

    // Square columns: ∂₂(square) = sum of 4 bounding edges (edge rows)
    for (col_offset, &(a, b, c, dd)) in cx.squares.iter().enumerate() {
        let col = num_verts + num_edges + col_offset;
        let edge_indices = [(a, b), (a, c), (b, dd), (c, dd)]
            .map(|(u, v)| cx.edges.binary_search(&(u, v)).unwrap());
        d.set(num_verts + edge_indices[0], col);
        d.set(num_verts + edge_indices[1], col);
        d.set(num_verts + edge_indices[2], col);
        d.set(num_verts + edge_indices[3], col);
    }

    d
}

/// Benchmarks persistence pair extraction from pre-reduced combined-filtration matrices.
fn bench_persistence_pairs(c: &mut Criterion) {
    let mut group = c.benchmark_group("homology_persistence_pairs");

    for &n in &[4u32, 8, 16] {
        let d = build_combined_filtration(n as usize);
        let reduced = d.reduce();

        group.throughput(Throughput::Elements(d.cols() as u64));

        group.bench_with_input(
            BenchmarkId::new("extract_pairs", format!("{n}x{n}")),
            &reduced,
            |b, reduced| b.iter(|| black_box(reduced.persistence_pairs())),
        );
    }

    group.finish();
}

// =============================================================================
// SCORING
// =============================================================================

/// Build synthetic persistence pairs of a given count with realistic structure.
fn build_synthetic_pairs(count: usize) -> PersistencePairs {
    let mut pairs = Vec::new();
    let mut unpaired = Vec::new();

    // 80% finite persistence pairs with varying intervals
    let finite_count = count * 4 / 5;
    for i in 0..finite_count {
        let birth = i * 2;
        let death = birth + 1 + (i % 7); // varying persistence lengths
        pairs.push((birth, death));
    }

    // 20% unpaired (infinite persistence)
    for i in finite_count..count {
        unpaired.push(i * 2 + 1);
    }

    PersistencePairs { pairs, unpaired }
}

/// Benchmarks the topological scoring function in isolation.
fn bench_scoring(c: &mut Criterion) {
    let mut group = c.benchmark_group("homology_scoring");

    for &count in &[5u32, 20, 100, 500] {
        let pairs = build_synthetic_pairs(count as usize);
        group.throughput(Throughput::Elements(u64::from(count)));

        // Fresh scoring (all classes novel)
        group.bench_with_input(
            BenchmarkId::new("score_fresh", count),
            &pairs,
            |b, pairs| {
                b.iter_batched(
                    BTreeSet::new,
                    |mut seen| black_box(score_persistence(pairs, &mut seen, 42)),
                    BatchSize::SmallInput,
                )
            },
        );

        // Warm scoring (classes already seen → no novelty)
        let mut pre_seen: BTreeSet<ClassId> = BTreeSet::new();
        let _ = score_persistence(&pairs, &mut pre_seen, 42);

        group.bench_with_input(
            BenchmarkId::new("score_warm", count),
            &(pairs.clone(), pre_seen.clone()),
            |b, (pairs, pre)| {
                b.iter_batched(
                    || pre.clone(),
                    |mut seen| black_box(score_persistence(pairs, &mut seen, 42)),
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // End-to-end score_boundary_matrix with combined filtration
    for &n in &[4u32, 8] {
        let d = build_combined_filtration(n as usize);

        group.bench_with_input(
            BenchmarkId::new("score_boundary_matrix", format!("{n}x{n}")),
            &d,
            |b, d| {
                b.iter_batched(
                    BTreeSet::new,
                    |mut seen| black_box(score_boundary_matrix(d, &mut seen, 42)),
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// END-TO-END PIPELINE
// =============================================================================

/// Benchmarks the complete scoring pipeline using combined-filtration matrices.
///
/// This measures the full cost from complex construction through to scoring,
/// mirroring the hot path in `TopologyExplorer::run_once()`.
fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("homology_end_to_end");

    // Complex construction + boundary + reduce (no persistence_pairs call)
    for &n in &[4u32, 8, 16, 32] {
        let n_usize = n as usize;
        let (num_verts, edges) = build_grid_edges(n_usize);
        group.throughput(Throughput::Elements(num_verts as u64));

        // Pipeline through column reduction (the dominant cost)
        group.bench_with_input(
            BenchmarkId::new("complex_to_reduce", format!("{n}x{n}")),
            &(num_verts, edges),
            |b, (nv, e)| {
                b.iter_batched(
                    || e.clone(),
                    |edges| {
                        let cx = SquareComplex::from_edges(*nv, edges);
                        let d2 = cx.boundary_2();
                        black_box(d2.reduce())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Full pipeline with combined filtration (includes persistence_pairs + scoring)
    for &n in &[4u32, 8, 16] {
        let n_usize = n as usize;

        group.bench_function(format!("full_pipeline/{n}x{n}"), |b| {
            b.iter_batched(
                BTreeSet::<ClassId>::new,
                |mut seen| {
                    let d = build_combined_filtration(n_usize);
                    let reduced = d.reduce();
                    let pairs = reduced.persistence_pairs();
                    let fp = seed_fingerprint(42);
                    black_box(score_persistence(&pairs, &mut seen, fp))
                },
                BatchSize::SmallInput,
            )
        });
    }

    // Diamond chains: complex + boundary + reduce
    for &count in &[10u32, 50, 200] {
        let (num_verts, edges) = build_diamond_chain(count as usize);
        group.throughput(Throughput::Elements(num_verts as u64));

        group.bench_with_input(
            BenchmarkId::new("diamond_to_reduce", count),
            &(num_verts, edges),
            |b, (nv, e)| {
                b.iter_batched(
                    || e.clone(),
                    |edges| {
                        let cx = SquareComplex::from_edges(*nv, edges);
                        let d2 = cx.boundary_2();
                        black_box(d2.reduce())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// TRACE POSET CONSTRUCTION
// =============================================================================

/// Benchmarks `TracePoset::from_trace()` for synthetic traces of varying size.
///
/// This is the first stage of the explorer's scoring pipeline: converting raw
/// trace events into a dependency DAG before complex construction.
fn bench_trace_poset(c: &mut Criterion) {
    let mut group = c.benchmark_group("homology_trace_poset");

    // Vary number of tasks (each with 3 events: spawn, poll, complete)
    for &num_tasks in &[4u32, 10, 20, 50] {
        let events_per_task = 3;
        let trace = build_synthetic_trace(num_tasks, events_per_task);
        let total_events = trace.len();
        group.throughput(Throughput::Elements(total_events as u64));

        group.bench_with_input(
            BenchmarkId::new("from_trace", format!("{num_tasks}t_x_{events_per_task}e")),
            &trace,
            |b, trace| b.iter(|| black_box(TracePoset::from_trace(trace))),
        );
    }

    // Dense trace: few tasks, many events each
    for &events_per_task in &[5u32, 10, 20] {
        let num_tasks = 4;
        let trace = build_synthetic_trace(num_tasks, events_per_task);
        let total_events = trace.len();
        group.throughput(Throughput::Elements(total_events as u64));

        group.bench_with_input(
            BenchmarkId::new(
                "from_trace_dense",
                format!("{num_tasks}t_x_{events_per_task}e"),
            ),
            &trace,
            |b, trace| b.iter(|| black_box(TracePoset::from_trace(trace))),
        );
    }

    group.finish();
}

// =============================================================================
// TRACE → COMPLEX (FULL EXPLORER PATH)
// =============================================================================

/// Benchmarks the path from trace events through poset to square complex.
///
/// This measures the combined cost of `TracePoset::from_trace()` +
/// `SquareComplex::from_trace_poset()`, which is what the explorer calls
/// before scoring.
fn bench_trace_to_complex(c: &mut Criterion) {
    let mut group = c.benchmark_group("homology_trace_to_complex");

    for &num_tasks in &[4u32, 10, 20] {
        let trace = build_synthetic_trace(num_tasks, 3);
        let total = trace.len();
        group.throughput(Throughput::Elements(total as u64));

        group.bench_with_input(
            BenchmarkId::new("poset_plus_complex", format!("{num_tasks}tasks")),
            &trace,
            |b, trace| {
                b.iter(|| {
                    let poset = TracePoset::from_trace(trace);
                    let cx = SquareComplex::from_trace_poset(&poset);
                    black_box(cx)
                })
            },
        );
    }

    group.finish();
}

// =============================================================================
// BITVEC MICROBENCHMARKS
// =============================================================================

/// Benchmarks core BitVec operations that dominate column reduction.
fn bench_bitvec_ops(c: &mut Criterion) {
    use asupersync::trace::gf2::BitVec;

    let mut group = c.benchmark_group("homology_bitvec");

    for &size in &[64u32, 256, 1024, 4096] {
        let size_usize = size as usize;
        group.throughput(Throughput::Elements(u64::from(size)));

        // XOR-assign (the core operation in column reduction)
        group.bench_with_input(
            BenchmarkId::new("xor_assign", size),
            &size_usize,
            |b, &sz| {
                b.iter_batched(
                    || {
                        let mut a = BitVec::zeros(sz);
                        let mut bv = BitVec::zeros(sz);
                        // Set every 3rd bit in a, every 5th in b
                        for i in (0..sz).step_by(3) {
                            a.set(i);
                        }
                        for i in (0..sz).step_by(5) {
                            bv.set(i);
                        }
                        (a, bv)
                    },
                    |(mut a, bv)| {
                        a.xor_assign(&bv);
                        black_box(a)
                    },
                    BatchSize::SmallInput,
                )
            },
        );

        // Pivot finding (used in every reduction step)
        group.bench_with_input(BenchmarkId::new("pivot", size), &size_usize, |b, &sz| {
            let mut v = BitVec::zeros(sz);
            // Set a bit near the middle
            v.set(sz / 2);
            v.set(sz / 2 + 1);
            b.iter(|| black_box(v.pivot()))
        });

        // Count ones (used in density checks)
        group.bench_with_input(
            BenchmarkId::new("count_ones", size),
            &size_usize,
            |b, &sz| {
                let mut v = BitVec::zeros(sz);
                for i in (0..sz).step_by(3) {
                    v.set(i);
                }
                b.iter(|| black_box(v.count_ones()))
            },
        );
    }

    group.finish();
}

// =============================================================================
// MAIN
// =============================================================================

criterion_group!(
    benches,
    bench_complex_construction,
    bench_boundary_operators,
    bench_column_reduction,
    bench_persistence_pairs,
    bench_scoring,
    bench_end_to_end,
    bench_trace_poset,
    bench_trace_to_complex,
    bench_bitvec_ops,
);

criterion_main!(benches);
