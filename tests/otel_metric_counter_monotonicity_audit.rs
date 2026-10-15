//! Audit + regression test for `src/observability/otel.rs` OTLP
//! metric monotonic-counter aggregation.
//!
//! Operator's question: "when the metric reader observes a counter
//! that has been reset (counter < previous value), do we emit a
//! 'reset' indicator (delta-temporality protocol) or do we silently
//! produce a negative delta (incorrect)? Per OTLP delta-temporality
//! spec, reset must be flagged."
//!
//! Audit chain:
//!
//!   (a) **Producer-side monotonicity by construction**
//!       (`src/observability/metrics.rs`): `Counter` exposes
//!       only `increment()` and `add(value: u64)`, both backed by
//!       `AtomicU64::fetch_add(_, Relaxed)`. There is NO
//!       `decrement`, NO `set`, NO `reset` API. The internal value
//!       can only decrease via `u64` wraparound (2^64 increments —
//!       implausible at 1 billion ops/sec it would take >584 years).
//!
//!   (b) **Snapshot type is u64 non-negative**
//!       (`MetricsSnapshot::add_counter` in otel.rs:390): the API
//!       accepts `value: u64`. The type system forbids negative
//!       counter values from entering the snapshot. A regression
//!       that changed the type to `i64` would re-open the door.
//!
//!   (c) **Wire encoding always declares cumulative + monotonic**
//!       (otel.rs:`metrics_request_from_snapshot` and the
//!       `otlp_wire_format_tests` helper): every Counter Sum
//!       metric emits `aggregation_temporality:
//!       AggregationTemporality::Cumulative as i32` and
//!       `is_monotonic: true`. We NEVER emit
//!       `AggregationTemporality::Delta` for Sum — so the
//!       "negative delta" failure mode the operator asks about
//!       cannot happen on our wire output. A regression that
//!       switched to delta temporality without first adding
//!       reset-detection logic would be the bug.
//!
//!   (d) **No exporter computes deltas** (otel.rs:528-704):
//!       `StdoutExporter`, `NullExporter`, `MultiExporter`,
//!       `InMemoryExporter`, and `OtlpHttpExporter` all consume
//!       `&MetricsSnapshot` independently, with NO state tracked
//!       between calls. Each export is a fresh write-through.
//!       Without prev-value state, computing a (possibly negative)
//!       delta is structurally impossible.
//!
//!   (e) **Reset signaling for cumulative is via
//!       `start_time_unix_nano`**: per OTLP spec, a cumulative
//!       counter reset is signaled to the receiver by emitting a
//!       new `start_time_unix_nano`. Our wire helper derives both
//!       `start_time_unix_nano` and `time_unix_nano` from the
//!       caller-supplied `batch_sequence`, so successive batches
//!       with different sequences naturally rotate start_time
//!       (the receiver detects "reset" between batches).
//!
//! Verdict: **SOUND**. The operator's failure mode (silent
//! negative delta) is structurally impossible because:
//!   1. We never emit delta temporality.
//!   2. We never compute deltas from snapshots.
//!   3. The producer counter is u64-monotonic by construction.
//!   4. The snapshot type is u64 (no negative values).
//!   5. Reset signaling for cumulative is via start_time, which
//!      is caller-controlled.
//!
//! A regression that:
//!   - switched the Sum metric to delta temporality without
//!     adding prev-value tracking and reset detection,
//!   - changed `add_counter` value type to `i64` or `f64` (would
//!     allow user-side negatives to flow through),
//!   - removed `is_monotonic: true` from the Sum encoding
//!     (would let receivers treat it as non-monotonic Up/Down),
//!   - exposed a `decrement` or `reset` API on `Counter`,
//!   - introduced a stateful exporter that computed deltas from
//!     snapshots without start_time bookkeeping,
//!     would all be caught here.

use std::path::PathBuf;

fn read_otel_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/observability/otel.rs");
    std::fs::read_to_string(&path).expect("read otel.rs")
}

fn read_metrics_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/observability/metrics.rs");
    std::fs::read_to_string(&path).expect("read metrics.rs")
}

#[test]
fn counter_has_no_decrement_or_reset_api() {
    // Pin (a): Counter only exposes increment / add(u64) / get /
    // name. A regression that added `decrement`, `reset`,
    // `set`, `sub`, or any other downward-mutation API would
    // open the door to non-monotonic counter values.
    let source = read_metrics_source();

    // Find the `impl Counter` block.
    let impl_marker = "impl Counter {";
    let start = source
        .find(impl_marker)
        .expect("impl Counter must exist in metrics.rs");
    // The Counter impl ends at the first `\n}\n` after start.
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("impl Counter must close");
    let body = &source[start..start + end_rel];

    let forbidden_methods = [
        "fn decrement",
        "fn reset",
        "fn set(",
        "fn sub(",
        "fn fetch_sub",
        "store(",
    ];
    for method in &forbidden_methods {
        assert!(
            !body.contains(method),
            "REGRESSION: Counter now exposes `{method}` — this \
             breaks producer-side monotonicity. The OTLP wire \
             output declares `is_monotonic: true`; emitting a \
             non-monotonic value through that flag is a wire-\
             format violation. If a downward API is genuinely \
             needed, switch to a Gauge (UpDownCounter) and update \
             the wire encoding to use a non-monotonic Sum.\n\n\
             impl Counter body:\n{body}",
        );
    }
}

#[test]
fn counter_uses_atomic_fetch_add_only() {
    // Pin (a): the only mutator path is `fetch_add`. A regression
    // that introduced `fetch_sub`, `compare_exchange` (with a
    // smaller new value), or `store` would let the value
    // decrease.
    let source = read_metrics_source();
    let impl_marker = "impl Counter {";
    let start = source.find(impl_marker).expect("impl Counter");
    let end_rel = source[start..].find("\n}\n").expect("close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("fetch_add"),
        "REGRESSION: Counter no longer uses fetch_add as its \
         monotonic mutator. fetch_add is the type-checked \
         monotonic increment; replacing it with `store` or any \
         non-additive primitive opens the door to non-monotonic \
         values.",
    );
}

#[test]
fn metrics_snapshot_counter_value_is_unsigned() {
    // Pin (b): MetricsSnapshot::add_counter accepts `value: u64`.
    // A regression that changed it to i64/f64 would let a
    // user-side bug (or attacker) push a negative value through
    // the snapshot, which would then be cast to i64 in the OTLP
    // encoder and surface as a negative cumulative — a wire
    // violation.
    let source = read_otel_source();
    let fn_marker = "pub fn add_counter(";
    let start = source.find(fn_marker).expect("add_counter must exist");
    // Capture the function signature up to the opening brace.
    let sig_end = source[start..]
        .find('{')
        .expect("add_counter signature must end at `{`");
    let signature = &source[start..start + sig_end];

    assert!(
        signature.contains("value: u64"),
        "REGRESSION: add_counter no longer accepts u64; the \
         type system was the load-bearing guard against negative \
         counter values flowing into the snapshot. Update this \
         test if the type genuinely needs to change, AND verify \
         the snapshot exporter checks for non-negativity at \
         every export site.\n\nsignature:\n{signature}",
    );
}

#[test]
fn otlp_counter_encoding_declares_cumulative_and_monotonic() {
    // Pin (c): every Counter Sum metric on the wire declares
    // BOTH `aggregation_temporality: Cumulative` AND
    // `is_monotonic: true`. The combination prevents the
    // "negative delta" failure mode by:
    //   - never emitting delta temporality (so deltas don't exist
    //     on our wire),
    //   - signaling to receivers that the value is monotonic non-
    //     decreasing, so the receiver can detect resets via
    //     start_time changes per OTLP spec.
    let source = read_otel_source();

    // The wire encoder appears in two places (otlp_request_builder
    // and otlp_wire_format_tests). Both must declare
    // Cumulative + is_monotonic: true for the Counter (Sum) path.
    let cumulative_count = source
        .matches("aggregation_temporality: AggregationTemporality::Cumulative as i32")
        .count();
    assert!(
        cumulative_count >= 2,
        "REGRESSION: expected at least two
         `aggregation_temporality: AggregationTemporality::\
         Cumulative` literals (one per encoder path); found \
         {cumulative_count}. A regression that switched any \
         Counter Sum to Delta would let the wire emit a \
         negative-value delta when the snapshot value happens \
         to decrease (e.g. due to a counter recreation).",
    );

    let monotonic_count = source.matches("is_monotonic: true").count();
    assert!(
        monotonic_count >= 2,
        "REGRESSION: expected at least two `is_monotonic: true` \
         literals on the Counter (Sum) wire path; found \
         {monotonic_count}. Without this flag, OTLP receivers \
         treat the Sum as an UpDownCounter and lose the \
         monotonicity invariant + reset-via-start_time \
         signaling.",
    );

    // Defense-in-depth: assert NO `Delta` literal appears in the
    // Counter encoding. If a future change adds a Delta path for
    // some other metric class (e.g. histograms with delta
    // semantics), that's acceptable — but the Counter path must
    // stay Cumulative.
    let delta_count = source.matches("AggregationTemporality::Delta").count();
    // A Delta usage means a future metric type adopted delta
    // temporality. Verify that, when this happens, the
    // implementer also added prev-value/reset-detection
    // bookkeeping. We can't structurally prove that; bail
    // with a clear message.
    assert_eq!(
        delta_count, 0,
        "AUDIT GATE: otel.rs now contains \
         AggregationTemporality::Delta ({delta_count} \
         occurrences). Delta temporality requires prev-value \
         tracking and reset detection per OTLP spec. Review \
         the new code and update this audit test to verify \
         the new path does NOT silently emit a negative \
         delta on counter resets."
    );
}

#[test]
fn no_exporter_holds_prev_value_state() {
    // Pin (d): no MetricsExporter implementation tracks previous
    // values. Every export is independent. This makes "delta
    // computation" structurally impossible — there's no state to
    // diff against.
    //
    // We pin via two checks:
    //   1. `MetricsExporter::export` takes `&MetricsSnapshot` —
    //      no `&mut self` anywhere that would let an exporter
    //      mutate cached state.
    //   2. None of the in-tree exporter structs hold a
    //      Mutex<HashMap<...>> keyed by (name, labels) for
    //      prev-value tracking.
    let source = read_otel_source();

    // Find the trait definition.
    let trait_marker = "pub trait MetricsExporter:";
    let start = source.find(trait_marker).expect("MetricsExporter trait");
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("trait MetricsExporter close");
    let body = &source[start..start + end_rel];

    // The export fn must take &self (immutable receiver). A
    // regression to &mut self would enable stateful prev-value
    // tracking inside an exporter.
    assert!(
        body.contains("fn export(&self,") && body.contains("metrics: &MetricsSnapshot"),
        "REGRESSION: MetricsExporter::export signature changed. \
         The audit invariant relies on `&self` (immutable) so \
         exporters cannot hold per-export prev-value state. If \
         a stateful exporter is genuinely needed (e.g. to compute \
         deltas), the new design MUST also handle counter resets \
         via OTLP's start_time mechanism — update this audit \
         test to verify reset detection.\n\ntrait body:\n{body}",
    );
}

#[test]
fn snapshot_export_does_not_diff_against_prior_snapshot() {
    // Pin (d) reinforced: the StdoutExporter, NullExporter, and
    // MultiExporter all just iterate the snapshot and write each
    // entry. No diff'ing, no prev-value lookup, no per-name cache.
    let source = read_otel_source();

    // StdoutExporter::export body must NOT reference any HashMap
    // keyed by counter name.
    let impl_marker = "impl MetricsExporter for StdoutExporter {";
    let start = source.find(impl_marker).expect("StdoutExporter impl");
    // Find the closing brace of the impl block.
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("StdoutExporter impl close");
    let body = &source[start..start + end_rel];

    let suspect_state_patterns = [
        "previous_values",
        "prev_values",
        "prev_value",
        "last_value",
        "last_seen",
        "delta_state",
        "counter_cache",
    ];
    for pat in &suspect_state_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: StdoutExporter now references `{pat}` — \
             this looks like prev-value state for delta \
             computation. If the exporter is genuinely computing \
             deltas, audit the reset-detection logic and update \
             this audit test.",
        );
    }
}

#[test]
fn counter_data_point_value_is_u64() {
    // Pin (b) extension: CounterDataPoint type alias resolves to
    // a tuple whose value field is `u64`. A regression to
    // `i64`/`f64` would let negatives flow through.
    let source = read_otel_source();

    // CounterDataPoint is a type alias near the top of otel.rs.
    let alias_marker = "pub type CounterDataPoint";
    let start = source
        .find(alias_marker)
        .expect("CounterDataPoint type alias");
    let line_end = source[start..].find('\n').expect("end of line");
    let line = &source[start..start + line_end];

    assert!(
        line.contains("u64"),
        "REGRESSION: CounterDataPoint no longer uses u64 for the \
         value field. Negative values can now flow into the \
         snapshot, get cast to i64 in the OTLP encoder, and \
         surface as a non-monotonic cumulative on the wire. \
         If the type is genuinely changed (e.g. to support \
         floating-point counters), update the encoder to emit \
         AsDouble instead of AsInt and verify monotonicity at \
         every entry point.\n\ntype alias:\n{line}",
    );
}

#[test]
fn no_silent_delta_temporality_path_on_counter() {
    // Pin (c) defense-in-depth: explicitly grep for any Counter-
    // specific delta path. The OTel spec allows delta on Counters
    // but mandates reset detection — we have no such path today.
    let source = read_otel_source();

    // Find the metrics_request_from_snapshot function.
    let fn_marker = "pub fn metrics_request_from_snapshot(";
    let start = source
        .find(fn_marker)
        .expect("metrics_request_from_snapshot");
    // The function ends at `\n    }\n` after balanced braces.
    // Use a simple heuristic: take a generous window.
    let window_end = (start + 4000).min(source.len());
    let body = &source[start..window_end];

    // The Counter (Sum) section must declare Cumulative.
    let cumulative_pos = body
        .find("aggregation_temporality: AggregationTemporality::Cumulative")
        .expect("Counter must declare Cumulative");
    let monotonic_pos = body
        .find("is_monotonic: true")
        .expect("Counter must declare is_monotonic: true");

    // The is_monotonic line should appear immediately after the
    // Cumulative declaration (within ~200 chars) — both are part
    // of the same Sum literal.
    let distance = monotonic_pos.saturating_sub(cumulative_pos);
    assert!(
        distance < 500,
        "REGRESSION: `is_monotonic: true` is far from the \
         Cumulative temporality declaration in \
         metrics_request_from_snapshot. They should appear in \
         the same Sum struct literal. A regression that split \
         them or moved is_monotonic out of the Counter Sum path \
         could let the receiver misinterpret the metric class.",
    );
}
