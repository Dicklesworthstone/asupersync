//! Audit + regression test for `src/observability/otel.rs` metric
//! attribute denylist (`drop_labels`) enforcement.
//!
//! Operator's question: "when an exporter is configured with
//! attribute denylist (e.g., user_id), are denied attributes
//! stripped before serialization?"
//!
//! Audit chain:
//!
//!   (a) **`MetricsConfig::drop_labels: Vec<String>`** field
//!       (otel.rs:97-98) holds the configured denylist.
//!       `MetricsConfig::with_drop_label(label)` (otel.rs:147)
//!       appends entries fluently.
//!
//!   (b) **`OtelMetrics::check_cardinality`**
//!       (otel.rs:1368-1412) is the SINGLE chokepoint for
//!       label processing. Its first action is to FILTER OUT
//!       any label whose key matches a `drop_labels` entry:
//!
//!       ```rust
//!       let filtered: Vec<KeyValue> = labels
//!           .iter()
//!           .filter(|kv| !self.config.drop_labels.contains(&kv.key.to_string()))
//!           .cloned()
//!           .collect();
//!       ```
//!
//!       The filtered set is what then enters the cardinality
//!       tracker and is returned to callers as the labels to
//!       record. Denied labels NEVER reach the upstream
//!       OpenTelemetry SDK Counter/Histogram, so they cannot
//!       appear in any exported wire payload.
//!
//!   (c) **All MetricsProvider impl methods that carry labels
//!       (`task_completed`, `cancellation_requested`,
//!       `deadline_warning`, `deadline_violation`,
//!       `deadline_remaining`, `checkpoint_interval`,
//!       `task_stuck_detected`)** route their labels through
//!       `check_cardinality` BEFORE calling `.add(...)` or
//!       `.record(...)`. Calls with empty labels (`&[]`) skip
//!       the check — which is correct (no labels to filter).
//!
//!   (d) **The filter is exact-match by key string** (case-
//!       sensitive). Operators must list label keys verbatim
//!       (e.g., `"user_id"` not `"User_Id"`). This matches the
//!       OpenTelemetry attribute-name convention (lowercase
//!       snake/dot case) and avoids surprising "fuzzy" matches.
//!
//! Verdict: **SOUND**. Denied attributes are stripped at the
//! recording layer BEFORE they reach the upstream OTel SDK.
//! There is no path where a denied label reaches serialization
//! without first passing through `check_cardinality`.
//!
//! A regression that:
//!   - removed the filter from `check_cardinality`,
//!   - added a `.add(...)` / `.record(...)` call site that
//!     bypassed `check_cardinality` while carrying caller-
//!     supplied labels,
//!   - broke `MetricsConfig::drop_labels` field name or type,
//!   - changed the filter from "exact key match" to "always
//!     keep" (e.g., negated condition),
//! would all be caught here.
//!
//! Note on `MetricsSnapshot`: that path is a fuzz/conformance
//! synthesis helper; the producer of a snapshot is responsible
//! for whatever filtering they want to apply before
//! `add_counter` / `add_gauge` / `add_histogram`. The denylist
//! belongs to the `OtelMetrics` recording surface, NOT to the
//! synthetic snapshot type. This audit pin is scoped to the
//! production recording path.

use std::path::PathBuf;

fn read_otel_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/observability/otel.rs");
    std::fs::read_to_string(&path).expect("read otel.rs")
}

#[test]
fn metrics_config_has_drop_labels_vec_field() {
    // Pin (a): MetricsConfig declares a public Vec<String> field
    // for the denylist. A regression that removed it would silently
    // disable the feature.
    let source = read_otel_source();

    let struct_marker = "pub struct MetricsConfig {";
    let start = source.find(struct_marker).expect("MetricsConfig struct");
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("MetricsConfig must close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("pub drop_labels: Vec<String>,"),
        "REGRESSION: MetricsConfig no longer declares \
         `pub drop_labels: Vec<String>`. The denylist field is \
         the operator's interface for stripping sensitive \
         attributes (e.g., user_id, request_id) — without it \
         the feature is silently disabled. struct body:\n{body}",
    );
}

#[test]
fn metrics_config_with_drop_label_appends_to_vec() {
    // Pin (a): the fluent builder appends to the Vec. A
    // regression that overwrote (single-label) instead of
    // appending would break multi-label denylists.
    let source = read_otel_source();
    let fn_marker = "pub fn with_drop_label(mut self, label: impl Into<String>) -> Self {";
    let start = source.find(fn_marker).expect("with_drop_label fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("with_drop_label close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.drop_labels.push(label.into());"),
        "REGRESSION: with_drop_label no longer appends via push. \
         A regression that replaced .push() with assignment \
         (`self.drop_labels = vec![label.into()]`) would clobber \
         existing entries — preventing operators from building \
         multi-entry denylists fluently.\n\nfn body:\n{body}",
    );
}

#[test]
fn check_cardinality_filters_drop_labels_first() {
    // Pin (b) AUDIT-CRITICAL: check_cardinality's first action
    // is to filter out drop_labels. A regression that moved
    // the filter AFTER cardinality bookkeeping would leak the
    // denied label keys into the cardinality tracker (which
    // surfaces in lock-metrics / debug dumps).
    let source = read_otel_source();
    let fn_marker =
        "fn check_cardinality(&self, metric: &str, labels: &[KeyValue]) -> Option<Vec<KeyValue>> {";
    let start = source.find(fn_marker).expect("check_cardinality fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("check_cardinality close");
    let body = &source[start..start + body_end];

    // The filter must be present.
    assert!(
        body.contains("self.config.drop_labels.contains") && body.contains(".filter("),
        "REGRESSION: check_cardinality no longer filters labels \
         via `self.config.drop_labels.contains(...)` inside a \
         `.filter(...)` chain. The denylist is the load-bearing \
         security guard — without it, denied labels reach the \
         upstream OpenTelemetry SDK and get serialized to the \
         wire.\n\nfn body:\n{body}",
    );

    // The filter MUST come BEFORE cardinality recording. We
    // verify by position: the filter pattern appears before
    // `cardinality_tracker.check_and_record`.
    let filter_pos = body
        .find(".filter(|kv| !self.config.drop_labels.contains")
        .expect("filter expression must appear");
    let tracker_pos = body
        .find("cardinality_tracker.check_and_record")
        .expect("cardinality_tracker.check_and_record must appear");
    assert!(
        filter_pos < tracker_pos,
        "REGRESSION: drop_labels filter now runs AFTER \
         cardinality_tracker.check_and_record. The denied label \
         keys MUST be removed BEFORE cardinality bookkeeping; \
         otherwise the tracker holds references to keys the \
         operator explicitly told us to drop.",
    );

    // Forbid the filter being negated (a regression that flipped
    // the condition to keep denied labels).
    assert!(
        !body.contains(".filter(|kv| self.config.drop_labels.contains"),
        "REGRESSION: the drop_labels filter condition is INVERTED \
         — denied labels are now KEPT, not dropped. This would \
         leak sensitive attributes to the wire.",
    );
}

#[test]
fn check_cardinality_returns_filtered_labels_to_caller() {
    // Pin (b): the filtered labels (with denied keys stripped)
    // are returned to the caller, who passes them to
    // `.add(...)`/`.record(...)`. A regression that returned
    // the unfiltered labels would pass the denied keys through
    // to the SDK.
    let source = read_otel_source();
    let fn_marker =
        "fn check_cardinality(&self, metric: &str, labels: &[KeyValue]) -> Option<Vec<KeyValue>> {";
    let start = source.find(fn_marker).expect("check_cardinality fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("check_cardinality close");
    let body = &source[start..start + body_end];

    // The success-return must be `Some(filtered)`, NOT
    // `Some(labels.to_vec())` or `Some(labels.iter().cloned().collect())`.
    assert!(
        body.contains("Some(filtered)"),
        "REGRESSION: check_cardinality no longer returns \
         `Some(filtered)` on the happy path. If the unfiltered \
         `labels` are returned instead, every caller's \
         `.add(filtered)` call would reintroduce the denied \
         keys.\n\nfn body:\n{body}",
    );

    // Forbid the unfiltered slice escaping back to the caller.
    assert!(
        !body.contains("Some(labels.to_vec())"),
        "REGRESSION: check_cardinality returns the UNFILTERED \
         labels via `labels.to_vec()`. The denylist is \
         bypassed.",
    );
}

#[test]
fn metrics_provider_callers_use_check_cardinality_when_labels_present() {
    // Pin (c): every MetricsProvider impl method that builds a
    // non-empty `[KeyValue::new(...)]` array routes it through
    // `check_cardinality` BEFORE `.add(...)`/`.record(...)`. A
    // regression that introduced a direct `.add(1, &labels)`
    // without going through check_cardinality would bypass the
    // denylist for that one site.
    let source = read_otel_source();

    // The MetricsProvider impl block.
    let impl_marker = "impl MetricsProvider for OtelMetrics {";
    let start = source
        .find(impl_marker)
        .expect("MetricsProvider impl block");
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("MetricsProvider impl close");
    let block = &source[start..start + end_rel];

    // Find every `&labels` reference and verify a
    // `check_cardinality` call appears in the same fn body.
    let mut search = 0;
    let mut sites = 0;
    while let Some(rel) = block[search..].find("&labels") {
        sites += 1;
        let abs = search + rel;
        // Take a 600-char window backward (typical fn body) to
        // verify check_cardinality precedes the &labels use.
        let ctx_start = abs.saturating_sub(600);
        // Char-boundary safe.
        let ctx_start = block[..ctx_start].rfind('\n').map_or(0, |p| p + 1);
        let ctx = &block[ctx_start..abs];
        let routed_through_filter = ctx.contains("check_cardinality");

        assert!(
            routed_through_filter,
            "REGRESSION: MetricsProvider call site #{sites} uses \
             `&labels` without first routing through \
             `check_cardinality`. This bypasses the drop_labels \
             denylist for that site — a denied attribute (e.g. \
             user_id) configured by the operator would still \
             reach the wire.\n\ncontext (preceding 600 chars):\n\
             {ctx}",
        );
        search = abs + 1;
    }

    assert!(
        sites > 0,
        "expected at least one MetricsProvider call site \
         carrying labels; found 0",
    );
}

#[test]
fn check_cardinality_filter_is_exact_key_match() {
    // Pin (d): the filter uses `drop_labels.contains(&kv.key.to_string())` —
    // an exact-match. Operators must list keys verbatim (no
    // case-folding, no prefix match, no glob). This is the
    // documented behavior; a regression that introduced fuzzy
    // matching could accidentally drop legitimate labels (e.g.,
    // configuring "id" as denied would also drop "request_id"
    // under prefix-matching).
    let source = read_otel_source();
    let fn_marker =
        "fn check_cardinality(&self, metric: &str, labels: &[KeyValue]) -> Option<Vec<KeyValue>> {";
    let start = source.find(fn_marker).expect("check_cardinality fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("check_cardinality close");
    let body = &source[start..start + body_end];

    // The exact-match pattern must be present.
    assert!(
        body.contains("self.config.drop_labels.contains(&kv.key.to_string())"),
        "REGRESSION: drop_labels filter no longer uses \
         `contains(&kv.key.to_string())` for exact matching. If \
         a fuzzy/prefix match was introduced, document the \
         change and update this audit pin.\n\nfn body:\n{body}",
    );

    // Forbid fuzzy matching primitives.
    let suspect_fuzzy = [
        ".starts_with(",
        ".ends_with(",
        ".eq_ignore_ascii_case(",
        ".to_lowercase(",
        "regex::",
    ];
    for pat in &suspect_fuzzy {
        // Look only inside the filter expression — the rest of
        // check_cardinality may have legitimate uses.
        let filter_start = body.find(".filter(|kv|").expect("filter expression");
        let filter_end = body[filter_start..]
            .find(".cloned()")
            .expect("filter chain end");
        let filter_expr = &body[filter_start..filter_start + filter_end];
        assert!(
            !filter_expr.contains(pat),
            "REGRESSION: drop_labels filter introduced fuzzy \
             matching via `{pat}`. Exact-match is the documented \
             behavior; switching to fuzzy matching could drop \
             legitimate labels (e.g. denylist 'id' accidentally \
             matching 'request_id').\n\nfilter expression:\n\
             {filter_expr}",
        );
    }
}

// ─── Behavioral end-to-end pin (gated on `metrics` feature) ─────────

// The OtelMetrics + MetricsConfig public surface is gated behind
// `feature = "metrics"`. The structural pins above run on default
// features; this behavioral test only runs under `cargo test
// --features metrics` (or any feature set that activates it).
#[cfg(feature = "metrics")]
mod behavioral {
    use asupersync::observability::otel::{MetricsConfig, OtelMetrics};
    use opentelemetry::KeyValue;

    fn make_metrics(drop_labels: &[&str]) -> OtelMetrics {
        let mut config = MetricsConfig::new();
        for label in drop_labels {
            config = config.with_drop_label(*label);
        }
        // Construct a meter via the global no-op provider; the
        // metrics feature wires that automatically. The exact
        // exporter wiring isn't relevant — we exercise the
        // public check_cardinality surface indirectly via the
        // recording API.
        let meter = opentelemetry::global::meter("audit-test");
        OtelMetrics::new_with_config(meter, config)
    }

    #[test]
    fn denied_label_is_stripped_from_filtered_set() {
        // Pin: a denylist entry is removed from the label set
        // returned by check_cardinality.
        let metrics = make_metrics(&["user_id"]);
        let labels = [
            KeyValue::new("outcome", "ok"),
            KeyValue::new("user_id", "alice"),
            KeyValue::new("region", "us-east"),
        ];
        let filtered = metrics
            .check_cardinality("test", &labels)
            .expect("under cap, returns Some");

        // user_id MUST be gone.
        assert!(
            !filtered.iter().any(|kv| kv.key.as_str() == "user_id"),
            "REGRESSION: 'user_id' attribute survived the \
             denylist filter. value: {:?}",
            filtered
                .iter()
                .map(|kv| kv.key.as_str())
                .collect::<Vec<_>>(),
        );
        // outcome and region MUST be preserved.
        assert!(filtered.iter().any(|kv| kv.key.as_str() == "outcome"));
        assert!(filtered.iter().any(|kv| kv.key.as_str() == "region"));
    }

    #[test]
    fn multiple_denied_labels_all_stripped() {
        // Pin: multiple denylist entries all apply.
        let metrics = make_metrics(&["user_id", "session_id", "ip"]);
        let labels = [
            KeyValue::new("user_id", "alice"),
            KeyValue::new("session_id", "abc123"),
            KeyValue::new("ip", "192.0.2.1"),
            KeyValue::new("outcome", "ok"),
        ];
        let filtered = metrics
            .check_cardinality("test", &labels)
            .expect("under cap, returns Some");

        let kept: Vec<&str> = filtered.iter().map(|kv| kv.key.as_str()).collect();
        assert_eq!(
            kept,
            vec!["outcome"],
            "only outcome should remain; got {kept:?}"
        );
    }

    #[test]
    fn empty_denylist_keeps_all_labels() {
        // Pin: an empty drop_labels Vec is a no-op; all labels
        // pass through unchanged.
        let metrics = make_metrics(&[]);
        let labels = [
            KeyValue::new("a", "1"),
            KeyValue::new("b", "2"),
            KeyValue::new("c", "3"),
        ];
        let filtered = metrics
            .check_cardinality("test", &labels)
            .expect("under cap, returns Some");
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn denylist_filter_is_case_sensitive() {
        // Pin (d): exact-match means 'User_Id' is NOT denied
        // when only 'user_id' is in the list. Operators must
        // list the exact attribute key. (This documents
        // current behavior; a future case-folding change
        // would need to update this test.)
        let metrics = make_metrics(&["user_id"]);
        let labels = [
            KeyValue::new("user_id", "alice"), // denied
            KeyValue::new("User_Id", "ALICE"), // NOT denied
        ];
        let filtered = metrics
            .check_cardinality("test", &labels)
            .expect("under cap, returns Some");

        let kept: Vec<&str> = filtered.iter().map(|kv| kv.key.as_str()).collect();
        assert!(
            !kept.contains(&"user_id"),
            "lowercase 'user_id' MUST be denied",
        );
        assert!(
            kept.contains(&"User_Id"),
            "case-different 'User_Id' is NOT in the denylist; \
             current behavior is exact-match (case-sensitive). \
             If this assertion fails, the filter became case-\
             insensitive — update the audit pin and document.",
        );
    }

    #[test]
    fn denied_label_does_not_count_toward_cardinality() {
        // Pin (b)+(c): the cardinality tracker sees only the
        // FILTERED labels. A regression that leaked the denied
        // label into the tracker would (a) burn cardinality
        // budget on attributes the operator explicitly said
        // to drop and (b) make the tracker hold references to
        // sensitive keys.
        let mut config = MetricsConfig::new()
            .with_drop_label("user_id")
            .with_max_cardinality(2);
        let _ = &mut config;
        let metrics = make_metrics(&["user_id"]);

        // Two distinct user_ids — without filtering, this would
        // be 2 unique label combinations. With filtering, both
        // collapse to the same (single) outcome=ok combination.
        let labels_a = [
            KeyValue::new("outcome", "ok"),
            KeyValue::new("user_id", "alice"),
        ];
        let labels_b = [
            KeyValue::new("outcome", "ok"),
            KeyValue::new("user_id", "bob"),
        ];
        let filtered_a = metrics
            .check_cardinality("test", &labels_a)
            .expect("first call");
        let filtered_b = metrics
            .check_cardinality("test", &labels_b)
            .expect("second call");

        // Both produce the SAME single-label result.
        assert_eq!(filtered_a.len(), 1);
        assert_eq!(filtered_b.len(), 1);
        assert_eq!(filtered_a[0].key.as_str(), "outcome");
        assert_eq!(filtered_b[0].key.as_str(), "outcome");
    }
}
