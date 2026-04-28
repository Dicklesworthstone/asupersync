//! Canonical Prometheus-text-format snapshot for `Metrics` at a fixed
//! point-in-time.
//!
//! The existing in-tree snapshots (mixed_registry, full_registry,
//! runtime_scheduler_region) cover a happy-path subset of metric kinds.
//! This integration test extends coverage to the boundary cases the
//! exposition format must handle without drift:
//!
//!   * Histogram observations placed *exactly* on a bucket boundary
//!     (le=0.5 with an observed `0.5`) — Prometheus semantics require
//!     `le="0.5"` to be *inclusive*, so this fixture pins that policy.
//!   * Histogram observations that fall into the implicit `+Inf` bucket
//!     (value above the last finite bucket).
//!   * Negative gauges, zero gauges, and `i64::MIN` gauges — sign,
//!     zero, and the most-negative-int corner all share one snapshot.
//!   * Summary quantile readout for an asymmetric, deterministic
//!     observation sequence so the 0.5 / 0.9 / 0.99 quantile values are
//!     stable.
//!   * Tag-bearing names (`scheduler_dispatch_total{lane="ready",...}`)
//!     mixed with bare names so the sort+dedup behavior in the
//!     exposition output is locked.
//!
//! Lives under `tests/` so it compiles into its own integration-test
//! binary against the public crate surface, independent of the
//! currently-broken in-tree `cfg(test)` modules in `src/`.

use asupersync::observability::Metrics;

/// Reorder `# TYPE`-delimited metric blocks so the snapshot is stable
/// against the BTreeMap iteration order Metrics happens to use today.
/// Lifted from the equivalent helper inside `metrics.rs::tests` so this
/// integration binary stays self-contained.
fn sorted_metric_blocks(rendered: &str) -> String {
    let mut blocks = Vec::new();
    let mut current = Vec::new();

    for line in rendered.lines() {
        if line.starts_with("# TYPE ") && !current.is_empty() {
            blocks.push(current.join("\n"));
            current.clear();
        }
        current.push(line);
    }

    if !current.is_empty() {
        blocks.push(current.join("\n"));
    }

    blocks.sort_unstable();
    let mut snapshot = blocks.join("\n");
    if !snapshot.is_empty() {
        snapshot.push('\n');
    }
    snapshot
}

#[test]
fn metrics_canonical_prometheus_snapshot_with_boundary_fixtures() {
    let mut metrics = Metrics::new();

    // Counters — bare and tagged, including the high-value corner so a
    // future signed-overflow rewrite of the exposition path is forced
    // to either preserve current behavior or update the snapshot.
    metrics.counter("requests_total").add(42);
    metrics
        .counter("scheduler_dispatch_total{lane=\"ready\",worker=\"primary\"}")
        .add(11);
    metrics
        .counter("scheduler_dispatch_total{lane=\"cancel\",worker=\"primary\"}")
        .add(2);
    metrics.counter("near_max_counter").add(u64::MAX - 3);

    // Gauges — positive, zero, negative, i64::MIN. The spread pins
    // sign/zero/extreme-negative formatting in one snapshot block.
    metrics.gauge("active_connections").set(7);
    metrics.gauge("pending_drain").set(0);
    metrics.gauge("queue_offset").set(-15);
    metrics.gauge("clock_skew_floor").set(i64::MIN);

    // Histogram — observations chosen to exercise:
    //   * value == bucket boundary (0.5 → le="0.5" inclusive)
    //   * value strictly inside a bucket (0.75 → le="1")
    //   * value above last finite bucket → +Inf
    //   * a small value below the first boundary (0.001 → le="0.5")
    let latency = metrics.histogram("latency_seconds", vec![0.5, 1.0, 5.0]);
    latency.observe(0.001);
    latency.observe(0.5);
    latency.observe(0.75);
    latency.observe(3.5);
    latency.observe(42.0);

    // Summary — five distinct ascending observations so the 0.5 / 0.9
    // / 0.99 quantiles are deterministic. Picking ascending integers
    // also keeps the formatted floats short so an accidental switch
    // to scientific notation surfaces as a snapshot diff.
    let sizes = metrics.summary("request_size_bytes");
    for value in [128.0_f64, 256.0, 512.0, 1024.0, 2048.0] {
        sizes.observe(value);
    }

    let rendered = metrics.export_prometheus();
    insta::assert_snapshot!(
        "metrics_canonical_prometheus_boundary_fixtures",
        sorted_metric_blocks(&rendered)
    );
}
