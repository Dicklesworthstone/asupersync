//! `for_each_concurrent` vs the manual `buffer_unordered` baseline
//! (br-asupersync-dx-core-api-v2-u1z5hn.8, AC7).
//!
//! What is being priced: `for_each_concurrent` runs every item as a **region
//! task**, so in-flight work participates in region-close quiescence and is
//! drained — not dropped — on cancellation or error. `buffer_unordered` polls
//! plain futures inline with none of that machinery. Both sides here run the
//! same workload (N items, each yielding to the scheduler exactly once), so
//! the measured delta is the cost of the drain guarantee: task spawn, region
//! accounting, join collection, and cancellation bookkeeping per item.
//!
//! Both sides run under the deterministic lab runtime with a fixed seed, so
//! the schedule is identical across samples and the comparison measures
//! runtime overhead rather than scheduling noise. The lab setup itself is
//! shared by both sides and cancels out of the comparison.

#![cfg(feature = "test-internals")]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use asupersync::lab::run_async_under_lab;
use asupersync::runtime::yield_now;
use asupersync::stream::{StreamExt, for_each_concurrent, iter};
use asupersync::types::Outcome;

const SEED: u64 = 0xAC7;

/// Region-task-backed terminal: every item is spawned, joined, and would be
/// drained on cancellation or failure.
fn run_region_task_terminal(items: usize, limit: usize) {
    let (outcome, report) = run_async_under_lab(SEED, move |cx| async move {
        let source = iter(0..items);
        for_each_concurrent(&cx, source, limit, |_item_cx, item| async move {
            black_box(item);
            yield_now().await;
        })
        .await
    });
    assert!(
        matches!(outcome, Outcome::Ok(())),
        "bench workload must succeed"
    );
    assert!(report.quiescent, "bench workload must reach quiescence");
}

/// Inline-future baseline: identical workload, no spawn, no drain guarantee.
fn run_buffer_unordered_baseline(items: usize, limit: usize) {
    // No `&Cx` in the baseline: that asymmetry IS the thing being priced. The
    // inline futures need no capability context because they are never tasks.
    let (count, report) = run_async_under_lab(SEED, move |_cx| async move {
        let mut visited = 0usize;
        iter(0..items)
            .map(|item| {
                black_box(item);
                yield_now()
            })
            .buffer_unordered(limit)
            .for_each(|()| visited += 1)
            .await;
        visited
    });
    assert_eq!(count, items, "baseline must visit every item");
    assert!(report.quiescent, "bench workload must reach quiescence");
}

fn bench_stream_concurrency(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_concurrency");
    for &(items, limit) in &[(64usize, 4usize), (256, 4), (256, 16)] {
        let label = format!("{items}items_limit{limit}");
        group.bench_with_input(
            BenchmarkId::new("for_each_concurrent", &label),
            &(items, limit),
            |b, &(items, limit)| b.iter(|| run_region_task_terminal(items, limit)),
        );
        group.bench_with_input(
            BenchmarkId::new("buffer_unordered_for_each", &label),
            &(items, limit),
            |b, &(items, limit)| b.iter(|| run_buffer_unordered_baseline(items, limit)),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_stream_concurrency);
criterion_main!(benches);
