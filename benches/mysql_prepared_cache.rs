//! Benchmark: MySQL prepared-statement cache benefit on a repeated-query workload.
//!
//! AC8 of `br-asupersync-server-stack-hardening-eeexl1.5`: "Bench: repeated-query
//! workload shows cache benefit on mysql (record %)."
//!
//! Real MySQL infra is not available in this environment, so the bench drives the
//! production [`MySqlPreparedStatementCache`] directly through its `test-internals`
//! workload helper. The cache's hit/miss/eviction counters are genuine, so the
//! reported "% prepares avoided" is the real benefit the cache delivers at each
//! locality/capacity regime — exactly the fraction of `COM_STMT_PREPARE`
//! round-trips a live server would skip. The bench prints that headline figure
//! per regime (recorded in the bead close notes) and times the lookup workload.
//!
//! Regimes:
//!   * `hot_fits`    — working set << capacity: steady state ~all hits.
//!   * `exact_fit`   — working set == capacity: first pass misses, rest hits.
//!   * `thrash`      — sequential scan, working set > capacity: LRU worst case,
//!                     0 reuse — proves the measurement is honest, not hard-coded.

use asupersync::database::mysql::bench_prepared_cache_repeated_workload;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_repeated_query_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("mysql_prepared_cache");

    // (label, capacity, distinct_queries, repetitions)
    let regimes = [
        ("hot_fits_256cap_32q", 256_usize, 32_usize, 64_usize),
        ("exact_fit_64cap_64q", 64, 64, 8),
        ("thrash_16cap_64q", 16, 64, 8),
    ];

    for (label, cap, distinct, reps) in regimes {
        // Deterministic — record the realized cache benefit once so the bench
        // output carries the headline "% prepares avoided" figure for AC8.
        let report = bench_prepared_cache_repeated_workload(cap, distinct, reps);
        println!(
            "[mysql_prepared_cache] {label}: {:.1}% prepares avoided \
             ({} avoided / {} executions, {} evictions)",
            report.prepares_avoided_ratio() * 100.0,
            report.prepares_avoided,
            report.executions,
            report.stats.evictions,
        );

        group.bench_function(label, |b| {
            b.iter(|| {
                black_box(bench_prepared_cache_repeated_workload(
                    black_box(cap),
                    black_box(distinct),
                    black_box(reps),
                ))
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_repeated_query_workload);
criterion_main!(benches);
