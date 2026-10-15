//! MySQL prepared-statement cache benefit on a repeated-query workload.
//!
//! Bead: `br-asupersync-server-stack-hardening-eeexl1.5` (AC8 — "Bench:
//! repeated-query workload shows cache benefit on mysql (record %)").
//!
//! The `mysql_prepared_cache` criterion bench reports the headline figure;
//! this integration test pins the underlying measurement so it cannot silently
//! regress. It drives the *production* `MySqlPreparedStatementCache` through
//! its `test-internals` workload helper, so the hit/miss/eviction counters are
//! genuine — the "% prepares avoided" is the real fraction of `COM_STMT_PREPARE`
//! round-trips a live server would skip at each locality/capacity regime.
//!
//! It lives in `tests/*.rs` (links the library in normal, non-`cfg(test)`
//! mode) so it builds as a small standalone crate — immune both to in-crate
//! `#[cfg(test)]` churn from concurrent work and to the OOM-prone full
//! lib-unittest binary.

#![cfg(all(test, feature = "mysql", feature = "test-internals"))]

use asupersync::database::mysql::bench_prepared_cache_repeated_workload;

/// Regime 1 — hot working set fits in cache: after the first pass every query
/// is a hit, so the steady-state benefit approaches 100% with zero eviction.
#[test]
fn hot_working_set_avoids_nearly_all_prepares() {
    let report = bench_prepared_cache_repeated_workload(256, 32, 64);
    assert_eq!(report.executions, 2048);
    assert_eq!(
        report.prepares_issued, 32,
        "each distinct query prepared once"
    );
    assert_eq!(report.prepares_avoided, 2016);
    assert_eq!(report.stats.evictions, 0, "working set fits — no eviction");
    // Every execution is exactly one hit or one miss.
    assert_eq!(
        report.prepares_issued + report.prepares_avoided,
        report.executions
    );
    assert!(
        (report.prepares_avoided_ratio() - 2016.0 / 2048.0).abs() < 1e-12,
        "hot ratio = {}",
        report.prepares_avoided_ratio()
    );
    assert!(report.prepares_avoided_ratio() > 0.95);
}

/// Regime 2 — capacity exactly equals the working set: still zero evictions,
/// first pass all misses, every subsequent pass all hits.
#[test]
fn exact_fit_working_set_reuses_after_first_pass() {
    let report = bench_prepared_cache_repeated_workload(64, 64, 8);
    assert_eq!(report.executions, 512);
    assert_eq!(report.prepares_issued, 64);
    assert_eq!(report.prepares_avoided, 448);
    assert_eq!(report.stats.evictions, 0);
    assert!((report.prepares_avoided_ratio() - 0.875).abs() < 1e-12);
}

/// Regime 3 — sequential scan over a working set larger than the cache is the
/// LRU pathological case: every access misses, so the cache delivers no benefit
/// and churns. This proves the measurement is honest, not a hard-coded win.
#[test]
fn sequential_scan_larger_than_cache_yields_no_benefit() {
    let report = bench_prepared_cache_repeated_workload(16, 64, 8);
    assert_eq!(report.executions, 512);
    assert_eq!(
        report.prepares_avoided, 0,
        "sequential scan > cap = 0 reuse"
    );
    assert_eq!(report.prepares_issued, 512);
    assert_eq!(report.prepares_avoided_ratio(), 0.0);
    assert!(report.stats.evictions > 0, "thrash churns the cache");
}
