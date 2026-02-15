//! Benchmarks for e-graph operations: add, merge, extraction.
//!
//! These benchmarks establish baseline performance before arena optimization
//! (bd-29tf) and serve as regression gates afterward.

#![allow(missing_docs)]

use asupersync::plan::{EGraph, Extractor};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a chain of `n` leaves joined together: Join(L0, L1, ..., L_{n-1}).
fn build_flat_join(n: usize) -> EGraph {
    let mut eg = EGraph::new();
    let leaves: Vec<_> = (0..n).map(|i| eg.add_leaf(format!("leaf_{i}"))).collect();
    let _join = eg.add_join(leaves);
    eg
}

fn build_tree_recurse(
    eg: &mut EGraph,
    depth: u32,
    counter: &mut usize,
) -> asupersync::plan::EClassId {
    if depth == 0 {
        let id = eg.add_leaf(format!("leaf_{counter}"));
        *counter += 1;
        id
    } else {
        let left = build_tree_recurse(eg, depth - 1, counter);
        let right = build_tree_recurse(eg, depth - 1, counter);
        eg.add_join(vec![left, right])
    }
}

/// Build a balanced binary tree of depth `d`.
/// Total nodes = 2^d leaves + 2^d - 1 inner joins.
fn build_balanced_tree(depth: u32) -> EGraph {
    let mut eg = EGraph::new();
    let mut counter = 0;
    let _root = build_tree_recurse(&mut eg, depth, &mut counter);
    eg
}

/// Build a race-of-joins structure: Race(Join(shared, a), Join(shared, b), ...).
#[allow(dead_code)]
fn build_race_of_joins(branches: usize) -> EGraph {
    let mut eg = EGraph::new();
    let shared = eg.add_leaf("shared");
    let joins: Vec<_> = (0..branches)
        .map(|i| {
            let branch = eg.add_leaf(format!("branch_{i}"));
            eg.add_join(vec![shared, branch])
        })
        .collect();
    let _race = eg.add_race(joins);
    eg
}

// ---------------------------------------------------------------------------
// Benchmarks: node insertion
// ---------------------------------------------------------------------------

fn bench_add_leaf(c: &mut Criterion) {
    let mut group = c.benchmark_group("egraph_add_leaf");
    for n in [10, 100, 1_000, 10_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut eg = EGraph::new();
                for i in 0..n {
                    eg.add_leaf(format!("leaf_{i}"));
                }
                std::hint::black_box(&eg);
            });
        });
    }
    group.finish();
}

fn bench_add_join(c: &mut Criterion) {
    let mut group = c.benchmark_group("egraph_add_join");
    for n in [10, 100, 500] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let eg = build_flat_join(n);
                std::hint::black_box(&eg);
            });
        });
    }
    group.finish();
}

fn bench_build_balanced_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("egraph_balanced_tree");
    for depth in [4, 6, 8, 10] {
        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &depth| {
            b.iter(|| {
                let eg = build_balanced_tree(depth);
                std::hint::black_box(&eg);
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: hashconsing (deduplication)
// ---------------------------------------------------------------------------

fn bench_hashcons_dedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("egraph_hashcons_dedup");
    for n in [100, 1_000, 5_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut eg = EGraph::new();
                let a = eg.add_leaf("a");
                let b_node = eg.add_leaf("b");
                // Insert the same join n times - should deduplicate
                for _ in 0..n {
                    eg.add_join(vec![a, b_node]);
                }
                std::hint::black_box(&eg);
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: merge (union-find + rebuild)
// ---------------------------------------------------------------------------

fn bench_merge_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("egraph_merge_chain");
    for n in [10, 50, 100, 500] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let mut eg = EGraph::new();
                    let leaves: Vec<_> = (0..n).map(|i| eg.add_leaf(format!("leaf_{i}"))).collect();
                    (eg, leaves)
                },
                |(mut eg, leaves)| {
                    // Merge all leaves into a single class (chain merge)
                    for window in leaves.windows(2) {
                        eg.merge(window[0], window[1]);
                    }
                    std::hint::black_box(&eg);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_merge_with_congruence(c: &mut Criterion) {
    let mut group = c.benchmark_group("egraph_merge_congruence");
    for n in [10, 50, 100] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let mut eg = EGraph::new();
                    let c_node = eg.add_leaf("c");
                    let leaves: Vec<_> = (0..n).map(|i| eg.add_leaf(format!("leaf_{i}"))).collect();
                    // Create joins pairing each leaf with c
                    let joins: Vec<_> = leaves
                        .iter()
                        .map(|&leaf| eg.add_join(vec![leaf, c_node]))
                        .collect();
                    (eg, leaves, joins)
                },
                |(mut eg, leaves, _joins)| {
                    // Merge leaves pairwise - should trigger congruence rebuilds
                    for window in leaves.windows(2) {
                        eg.merge(window[0], window[1]);
                    }
                    std::hint::black_box(&eg);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: extraction
// ---------------------------------------------------------------------------

fn bench_extract_flat(c: &mut Criterion) {
    let mut group = c.benchmark_group("egraph_extract_flat");
    for n in [5, 10, 50, 100] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let mut eg = EGraph::new();
                    let leaves: Vec<_> = (0..n).map(|i| eg.add_leaf(format!("leaf_{i}"))).collect();
                    let root = eg.add_join(leaves);
                    (eg, root)
                },
                |(mut eg, root)| {
                    let mut extractor = Extractor::new(&mut eg);
                    let (dag, cert) = extractor.extract(root);
                    std::hint::black_box((&dag, &cert));
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_extract_balanced_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("egraph_extract_tree");
    for depth in [4, 6, 8] {
        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &depth| {
            b.iter_batched(
                || {
                    let mut eg = EGraph::new();
                    let mut counter = 0;
                    let root = build_tree_recurse(&mut eg, depth, &mut counter);
                    (eg, root)
                },
                |(mut eg, root)| {
                    let mut extractor = Extractor::new(&mut eg);
                    let (dag, cert) = extractor.extract(root);
                    std::hint::black_box((&dag, &cert));
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_extract_after_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("egraph_extract_after_merge");
    group.bench_function("race_of_joins_merged", |b| {
        b.iter_batched(
            || {
                let mut eg = EGraph::new();
                let a = eg.add_leaf("a");
                let b_node = eg.add_leaf("b");
                let c_node = eg.add_leaf("c");

                // Two representations of the same computation
                let flat = eg.add_join(vec![a, b_node, c_node]);
                let nested_inner = eg.add_join(vec![a, b_node]);
                let nested = eg.add_join(vec![nested_inner, c_node]);

                eg.merge(flat, nested);
                (eg, flat)
            },
            |(mut eg, root)| {
                let mut extractor = Extractor::new(&mut eg);
                let (dag, cert) = extractor.extract(root);
                std::hint::black_box((&dag, &cert));
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: combined operations (add + merge + extract)
// ---------------------------------------------------------------------------

fn bench_full_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("egraph_full_workflow");
    for n in [5, 10, 20] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut eg = EGraph::new();

                // Build a race of joins with a shared leaf
                let shared = eg.add_leaf("shared");
                let joins: Vec<_> = (0..n)
                    .map(|i| {
                        let branch = eg.add_leaf(format!("b_{i}"));
                        eg.add_join(vec![shared, branch])
                    })
                    .collect();
                let root = eg.add_race(joins);

                // Also add some timeout wrappers
                let timed = eg.add_timeout(root, Duration::from_secs(30));

                // Extract best plan
                let mut extractor = Extractor::new(&mut eg);
                let (dag, cert) = extractor.extract(timed);

                std::hint::black_box((&dag, &cert));
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: plan DAG rewrite engine (bd-123x)
// ---------------------------------------------------------------------------

use asupersync::plan::{PlanDag, RewritePolicy, RewriteRule};

/// Build a nested join tree: Join(Join(Join(...), leaf), leaf).
fn build_nested_join_plan(depth: usize) -> PlanDag {
    let mut dag = PlanDag::new();
    let mut current = dag.leaf("leaf_0");
    for i in 1..depth {
        let leaf = dag.leaf(format!("leaf_{i}"));
        current = dag.join(vec![current, leaf]);
    }
    dag.set_root(current);
    dag
}

/// Build a race-of-joins structure for DedupRaceJoin benchmarking.
fn build_race_of_joins_plan(branches: usize) -> PlanDag {
    let mut dag = PlanDag::new();
    let shared = dag.leaf("shared");
    let joins: Vec<_> = (0..branches)
        .map(|i| {
            let branch = dag.leaf(format!("branch_{i}"));
            dag.join(vec![shared, branch])
        })
        .collect();
    let race = dag.race(joins);
    dag.set_root(race);
    dag
}

fn bench_rewrite_assoc(c: &mut Criterion) {
    let mut group = c.benchmark_group("plan_rewrite_assoc");
    for depth in [5, 10, 20, 50, 100] {
        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &depth| {
            b.iter_batched(
                || build_nested_join_plan(depth),
                |mut dag| {
                    let report =
                        dag.apply_rewrites(RewritePolicy::assume_all(), &[RewriteRule::JoinAssoc]);
                    std::hint::black_box(report);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_rewrite_commute(c: &mut Criterion) {
    let mut group = c.benchmark_group("plan_rewrite_commute");
    for depth in [5, 10, 20, 50] {
        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &depth| {
            b.iter_batched(
                || build_nested_join_plan(depth),
                |mut dag| {
                    let report = dag
                        .apply_rewrites(RewritePolicy::assume_all(), &[RewriteRule::JoinCommute]);
                    std::hint::black_box(report);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_rewrite_dedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("plan_rewrite_dedup");
    for branches in [2, 5, 10, 20] {
        group.bench_with_input(
            BenchmarkId::from_parameter(branches),
            &branches,
            |b, &branches| {
                b.iter_batched(
                    || build_race_of_joins_plan(branches),
                    |mut dag| {
                        let report = dag.apply_rewrites(
                            RewritePolicy::conservative(),
                            &[RewriteRule::DedupRaceJoin],
                        );
                        std::hint::black_box(report);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_rewrite_all_rules(c: &mut Criterion) {
    let all_rules = &[
        RewriteRule::JoinAssoc,
        RewriteRule::RaceAssoc,
        RewriteRule::JoinCommute,
        RewriteRule::RaceCommute,
        RewriteRule::TimeoutMin,
        RewriteRule::DedupRaceJoin,
    ];
    let mut group = c.benchmark_group("plan_rewrite_all_rules");
    for depth in [5, 10, 20, 50] {
        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &depth| {
            b.iter_batched(
                || build_nested_join_plan(depth),
                |mut dag| {
                    let report = dag.apply_rewrites(RewritePolicy::assume_all(), all_rules);
                    std::hint::black_box(report);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_certified_rewrite(c: &mut Criterion) {
    let mut group = c.benchmark_group("plan_certified_rewrite");
    for branches in [2, 5, 10] {
        group.bench_with_input(
            BenchmarkId::from_parameter(branches),
            &branches,
            |b, &branches| {
                b.iter_batched(
                    || build_race_of_joins_plan(branches),
                    |mut dag| {
                        let (report, cert) = dag.apply_rewrites_certified(
                            RewritePolicy::conservative(),
                            &[RewriteRule::DedupRaceJoin],
                        );
                        std::hint::black_box((report, cert));
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion configuration
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_add_leaf,
    bench_add_join,
    bench_build_balanced_tree,
    bench_hashcons_dedup,
    bench_merge_chain,
    bench_merge_with_congruence,
    bench_extract_flat,
    bench_extract_balanced_tree,
    bench_extract_after_merge,
    bench_full_workflow,
    bench_rewrite_assoc,
    bench_rewrite_commute,
    bench_rewrite_dedup,
    bench_rewrite_all_rules,
    bench_certified_rewrite,
);
criterion_main!(benches);
