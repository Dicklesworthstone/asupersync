//! Audit + regression test for `src/observability/otel.rs` OTLP
//! span attribute-cap drop accounting.
//!
//! Operator's question: "when span attribute count exceeds OTLP
//! limit (default 128), is `dropped_attributes_count` set,
//! attributes deterministically dropped, and no leak to subsequent
//! spans?"
//!
//! Audit findings (DEFECT FOUND + FIXED in this commit):
//!
//!   (a) **PRE-FIX BUG**: `TestSpan::set_attribute_value`
//!       (otel.rs:set_attribute_value) silently dropped attributes
//!       when the span was at the per-span cap, WITHOUT bumping
//!       any counter. The wire-format `proto_span`
//!       (otel.rs:proto_span) emitted `dropped_attributes_count:
//!       0` via `..Default::default()`. Result: a TestSpan with
//!       max_attributes=128 that received 200 set_attribute calls
//!       would emit 128 attributes on the wire with
//!       `dropped_attributes_count = 0`, losing track of the 72
//!       dropped attributes. OTLP receivers would have no signal
//!       that anything was lost.
//!
//!   (b) **POST-FIX BEHAVIOR**:
//!       - `TestSpan` now has a public
//!         `dropped_attributes_count: u32` field.
//!       - `set_attribute_value` saturating-increments the
//!         counter when an attribute is dropped due to cap.
//!       - Updates (existing-key writes) do NOT bump the counter.
//!       - `proto_span` emits the counter to the OTLP wire.
//!       - Each TestSpan (parent or child) starts with
//!         `dropped_attributes_count = 0`; the counter is NOT
//!         inherited from parent → child (no leak).
//!       - Drop semantics are deterministic: the FIRST
//!         `max_attributes` distinct keys win; subsequent keys
//!         are dropped (HashMap insert order doesn't matter
//!         because `attributes.len() < max_attributes` is the
//!         gate).
//!
//! This file pins:
//!   (1) the count is bumped on cap-overflow drops,
//!   (2) the count is NOT bumped on updates (existing keys),
//!   (3) the counter saturates rather than wraps at u32::MAX,
//!   (4) parent → child does NOT inherit the counter,
//!   (5) the proto_span encoder propagates the counter to the
//!       OTLP wire (verified at the source level since the
//!       wire-encoding helpers are feature-gated; the in-crate
//!       tests under `--features tracing-integration` exercise
//!       the wire path directly).

use std::path::PathBuf;

fn read_otel_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/observability/otel.rs");
    std::fs::read_to_string(&path).expect("read otel.rs")
}

#[test]
fn test_span_struct_has_dropped_attributes_count_field() {
    // Pin: TestSpan declares a public dropped_attributes_count
    // field so callers and the proto_span encoder can read it.
    let source = read_otel_source();
    let struct_marker = "pub struct TestSpan {";
    let start = source
        .find(struct_marker)
        .expect("TestSpan struct must exist");
    let end = source[start..]
        .find("\n    }\n")
        .expect("TestSpan struct must close");
    let body = &source[start..start + end];

    assert!(
        body.contains("pub dropped_attributes_count: u32,"),
        "REGRESSION: TestSpan no longer declares \
         `pub dropped_attributes_count: u32`. The proto_span \
         wire encoder reads this field directly; a regression \
         that removed it would silently zero the OTLP \
         dropped_attributes_count and lose attribute-drop \
         visibility.\n\nstruct body:\n{body}",
    );
}

#[test]
fn test_set_attribute_value_bumps_dropped_count_on_cap() {
    // Pin (1): when a NEW attribute is dropped due to cap, the
    // counter is saturating-incremented. We verify by reading
    // the source — the else-branch of the cap check must
    // saturating_add(1) the counter.
    let source = read_otel_source();
    let fn_marker = "pub fn set_attribute_value(&mut self, key: &str, value: AttributeValue) {";
    let start = source
        .find(fn_marker)
        .expect("set_attribute_value must exist");
    let body_end = source[start..]
        .find("\n        }\n")
        .expect("function body close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.dropped_attributes_count") && body.contains("saturating_add(1)"),
        "REGRESSION: set_attribute_value no longer increments \
         dropped_attributes_count via saturating_add(1) in the \
         drop branch. The OTLP spec requires the SDK to count \
         dropped attributes; without this, receivers can't \
         detect truncation.\n\nfunction body:\n{body}",
    );

    // Also verify the bump is in the ELSE branch (drop), not
    // the if-branch (insert/update).
    let else_pos = body.find("} else {").expect("else branch must exist");
    let else_body = &body[else_pos..];
    assert!(
        else_body.contains("saturating_add(1)"),
        "REGRESSION: the saturating_add(1) is no longer in the \
         drop (else) branch — if it moved to the insert branch, \
         every successful write would falsely bump the dropped \
         count. else branch:\n{else_body}",
    );
}

#[test]
fn test_proto_span_propagates_dropped_attributes_count() {
    // Pin (5): the proto_span function emits the counter on
    // the wire. Without this, the field defaults to 0 via
    // ..Default::default() and the SDK accounting is invisible
    // at the wire layer.
    let source = read_otel_source();
    let fn_marker = "fn proto_span(span: &TestSpan) -> ProtoSpan {";
    let mut occurrences = 0;
    let mut search_pos = 0;
    while let Some(rel) = source[search_pos..].find(fn_marker) {
        occurrences += 1;
        let abs_start = search_pos + rel;
        let body_end = source[abs_start..]
            .find("\n    }\n")
            .expect("proto_span body close");
        let body = &source[abs_start..abs_start + body_end];
        assert!(
            body.contains("dropped_attributes_count: span.dropped_attributes_count"),
            "REGRESSION: occurrence #{occurrences} of proto_span \
             does NOT propagate span.dropped_attributes_count to \
             the OTLP wire. A regression that left the field as \
             ..Default::default() would lose the drop count even \
             when set_attribute_value bumped it.\n\n\
             function body:\n{body}",
        );
        search_pos = abs_start + body_end;
    }
    assert!(
        occurrences >= 1,
        "expected at least one proto_span definition in otel.rs",
    );
}

#[test]
fn test_from_parts_initializes_dropped_count_to_zero() {
    // Pin (4): the constructor initializes the counter to 0,
    // ensuring no inherited or stale state from prior spans
    // (parent → child or sibling → sibling).
    let source = read_otel_source();
    let fn_marker = "fn from_parts(";
    let start = source.find(fn_marker).expect("from_parts must exist");
    // Find the constructor body's closing brace at indent 8.
    let body_end = source[start..]
        .find("\n        }\n")
        .expect("from_parts body close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("dropped_attributes_count: 0,"),
        "REGRESSION: from_parts does not initialize \
         dropped_attributes_count to 0. A child span could \
         inherit a non-zero count from arbitrary memory or \
         from the parent constructor frame, leaking attribute-\
         drop accounting across span boundaries.\n\n\
         function body:\n{body}",
    );
}

// ─── Behavioral pins (require feature = "tracing-integration") ──────

#[cfg(feature = "tracing-integration")]
mod behavioral {
    use asupersync::observability::otel::span_semantics::{SpanConformanceConfig, TestSpan};
    use opentelemetry::trace::SpanKind;

    fn small_cap_config(max: usize) -> SpanConformanceConfig {
        SpanConformanceConfig {
            max_attributes: max,
            max_events: 16,
            max_attribute_length: None,
            test_sampling: false,
            test_context_propagation: false,
        }
    }

    #[test]
    fn drop_count_bumps_when_attribute_overflows_cap() {
        // Pin (1): cap=2; insert 5 distinct keys; expect
        // attributes.len() == 2 and dropped_attributes_count == 3.
        let cfg = small_cap_config(2);
        let mut span = TestSpan::new_with_config("test", SpanKind::Internal, &cfg);

        span.set_attribute("k1", "v1");
        span.set_attribute("k2", "v2");
        assert_eq!(span.attributes.len(), 2);
        assert_eq!(
            span.dropped_attributes_count, 0,
            "no drops yet — both writes fit under cap",
        );

        span.set_attribute("k3", "v3");
        span.set_attribute("k4", "v4");
        span.set_attribute("k5", "v5");
        assert_eq!(span.attributes.len(), 2, "cap holds at 2");
        assert_eq!(
            span.dropped_attributes_count, 3,
            "MUST count 3 dropped attributes (k3, k4, k5)",
        );
    }

    #[test]
    fn drop_count_does_not_bump_when_updating_existing_key() {
        // Pin (2): re-assigning an existing attribute key is an
        // UPDATE — it must NOT bump dropped_attributes_count.
        let cfg = small_cap_config(2);
        let mut span = TestSpan::new_with_config("test", SpanKind::Internal, &cfg);

        span.set_attribute("k1", "v1");
        span.set_attribute("k2", "v2");
        for _ in 0..50 {
            span.set_attribute("k1", "v1-updated");
        }
        assert_eq!(span.attributes.len(), 2);
        assert_eq!(
            span.dropped_attributes_count, 0,
            "REGRESSION: updates to existing keys MUST NOT bump \
             dropped_attributes_count — only NEW keys past the \
             cap count as drops",
        );
    }

    #[test]
    fn child_span_does_not_inherit_parent_drop_count() {
        // Pin (4): each span starts with drop_count = 0.
        // Parent→child must not leak the counter.
        let cfg = small_cap_config(2);
        let mut parent = TestSpan::new_with_config("p", SpanKind::Server, &cfg);
        for i in 0..20 {
            parent.set_attribute(&format!("k{i}"), "v");
        }
        assert!(parent.dropped_attributes_count >= 18);

        let child = parent.new_child("c", SpanKind::Internal);
        assert_eq!(
            child.dropped_attributes_count, 0,
            "REGRESSION: child span inherited drop count from \
             parent — this leaks attribute-drop accounting \
             across span boundaries",
        );
    }

    #[test]
    fn drop_count_starts_at_zero_for_fresh_span() {
        // Pin (4) sibling: a fresh, never-touched span starts
        // at 0.
        let cfg = small_cap_config(128);
        let span = TestSpan::new_with_config("fresh", SpanKind::Internal, &cfg);
        assert_eq!(span.dropped_attributes_count, 0);
    }

    #[test]
    fn drop_count_saturates_does_not_wrap() {
        // Pin (3): when the counter is at u32::MAX, adding one
        // more drop must STAY at u32::MAX (saturating), not
        // wrap to 0. We can't realistically push 4-billion
        // distinct keys, but we can pre-set the field and verify
        // saturating semantics.
        let cfg = small_cap_config(0);
        let mut span = TestSpan::new_with_config("sat", SpanKind::Internal, &cfg);
        span.dropped_attributes_count = u32::MAX;

        // Cap=0 → every set_attribute hits the drop branch.
        span.set_attribute("any", "value");
        assert_eq!(
            span.dropped_attributes_count,
            u32::MAX,
            "REGRESSION: drop counter wrapped past u32::MAX. \
             saturating_add(1) at MAX must stay at MAX — \
             wrapping to 0 would falsely tell the receiver \
             nothing was dropped after exactly 2^32 drops",
        );
    }

    #[test]
    fn drop_count_visible_via_default_128_cap() {
        // Pin: the default SpanConformanceConfig has
        // max_attributes = 128 (the OTel SDK default). At that
        // cap, inserting 200 distinct keys should produce
        // attributes.len() == 128 and dropped_attributes_count
        // == 72.
        let cfg = SpanConformanceConfig::default();
        assert_eq!(cfg.max_attributes, 128, "default cap is OTel-spec 128");

        let mut span = TestSpan::new_with_config("d", SpanKind::Internal, &cfg);
        for i in 0..200 {
            span.set_attribute(&format!("attr_{i:03}"), "v");
        }
        assert_eq!(span.attributes.len(), 128);
        assert_eq!(
            span.dropped_attributes_count, 72,
            "REGRESSION: at default 128-attribute cap, 200 \
             distinct keys must produce exactly 72 drops",
        );
    }
}
