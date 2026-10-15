//! Audit + regression test for `src/observability/otel.rs` OTLP
//! span-link cardinality handling.
//!
//! Operator's question: "when a span has > 128 links, do we drop
//! excess (per OTLP spec recommendation) or send all? If we send
//! all, verify the receiving spec allows it. If we drop, ensure
//! `dropped_links_count` is set correctly."
//!
//! Audit findings:
//!
//!   (a) **The legacy `TestSpan` encoder remains link-free.** That
//!       compatibility surface has no `links` field or link mutator, so its
//!       `proto_span` conversion still emits the protobuf defaults.
//!
//!   (b) **The production OTLP encoder unconditionally emits
//!       empty links.** The legacy `proto_span` mapper builds
//!       a `ProtoSpan` from a `TestSpan` and uses
//!       `..Default::default()` for the trailing fields, which
//!       sets:
//!         - `links: vec![]` (no link entries)
//!         - `dropped_links_count: 0` (no links were dropped)
//!         - `flags: 0`
//!         - `trace_state: ""`
//!
//!   (c) **The legacy conformance reference path also emits empty
//!       links.** `build_our_otlp_export` and
//!       `build_reference_otlp_export` both produce `links: vec![]` /
//!       `SpanLinks::default()`, byte-identical to the upstream
//!       opentelemetry-proto reference transformer.
//!
//!   (d) **The additive owned OTLP trace path supports bounded links.**
//!       `OtlpTraceSpanInput::with_links` feeds `OwnedOtlpTraces`, whose
//!       immutable configuration defaults to and may not exceed
//!       `OWNED_OTLP_MAX_LINKS_PER_SPAN == 128`. Preflight rejects a sampled
//!       span above that bound before owned allocation or wire emission, while
//!       the caller-provided `dropped_links_count` is preserved.
//!
//! Verdict: **SOUND**. The legacy path emits zero links, and the owned path has
//! an explicit finite 128-link ceiling with preflight enforcement.
//!
//! Per OTLP/Proto spec (proto/opentelemetry/proto/trace/v1/
//! trace.proto), the `links` field on a Span is `repeated Link`
//! and the spec does not mandate any minimum number. An empty
//! `links` array is valid; a `dropped_links_count` of 0 in
//! conjunction with empty `links` correctly signals "no links
//! exist for this span", as opposed to "links existed but were
//! dropped".
//!
//! The OTel SDK SpanLimits default is 128 links per span. The structural pins
//! below catch a regression
//! that:
//!   - adds an unbounded link push API on TestSpan,
//!   - replaces `..Default::default()` in `proto_span` with an
//!     explicit `links: ...` that bypasses the cap,
//!   - leaks links through the encoder without bumping the
//!     dropped count,
//!   - or otherwise breaks the invariant that the wire output's
//!     link count is `<= dropped_links_count + emitted`.
//!
//! This test is a STRUCTURAL pin — it inspects the source file
//! to verify the invariants documented above. It does NOT
//! exercise the runtime exporter at the wire level (that is
//! covered by the in-crate `otlp_export_conformance_byte_
//! identical` test, which runs only with
//! `tracing-integration` + `metrics` features). The structural
//! pin runs unconditionally and catches API drift early.

use std::path::PathBuf;

fn read_otel_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/observability/otel.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read otel.rs at {}: {err}", path.display());
    })
}

#[test]
fn test_span_struct_has_no_links_field() {
    // Pin (a): the TestSpan struct must not gain a `links` field
    // until the cardinality cap is wired. A regression that adds
    // `pub links: Vec<SpanLink>` without enforcement would let
    // unbounded-cardinality spans propagate to the OTLP wire.
    let source = read_otel_source();

    // Find the TestSpan struct block.
    let struct_marker = "pub struct TestSpan {";
    let start = source
        .find(struct_marker)
        .expect("TestSpan struct must exist in otel.rs");
    let end = source[start..]
        .find("\n    }\n")
        .expect("TestSpan struct must have a closing brace");
    let body = &source[start..start + end];

    assert!(
        !body.contains("links:") && !body.contains("links :"),
        "REGRESSION: TestSpan now has a `links` field. Adding a \
         link API requires also: (1) a per-span cap aligned with \
         OTel SDK SpanLimits default (128), (2) a \
         dropped_links_count counter, (3) an update to proto_span \
         to emit the populated links + count, (4) an update to \
         this audit test to verify the cap is enforced. Update \
         all four together — DO NOT silently expose an unbounded \
         link API. (operator audit, legacy TestSpan)\n\nstruct body:\n{body}",
    );
}

#[test]
fn test_span_struct_has_no_link_setter_methods() {
    // Pin (a) extension: even if a `links` field is added, the
    // public setter methods must enforce a cap. Until then,
    // there should be no `add_link`, `with_link`, `push_link`,
    // `set_links` methods on TestSpan.
    let source = read_otel_source();
    let impl_marker = "impl TestSpan {";
    let impl_start = source
        .find(impl_marker)
        .expect("TestSpan impl must exist in otel.rs");
    let impl_end = source[impl_start..]
        .find("\n    }\n\n")
        .expect("TestSpan impl must have a closing brace");
    let test_span_impl = &source[impl_start..impl_start + impl_end];

    let forbidden_method_names = [
        "fn add_link",
        "fn with_link",
        "fn push_link",
        "fn set_links",
        "fn add_links",
    ];

    for name in &forbidden_method_names {
        assert!(
            !test_span_impl.contains(name),
            "REGRESSION: otel.rs now exposes `{name}` — a public \
             link-add method. Confirm: (1) the implementation \
             enforces the OTel SDK 128-link cap, (2) over-cap \
             links bump dropped_links_count, (3) the wire \
             encoder propagates both the (capped) links list and \
             the dropped count. Then update this audit test.",
        );
    }
}

#[test]
fn test_proto_span_emits_default_link_fields() {
    // Pin (b): the proto_span function (production span encoder)
    // builds a ProtoSpan with `..Default::default()` at its
    // trailing edge. That defaults `links: vec![]` and
    // `dropped_links_count: 0`. A regression that replaced the
    // default with an explicit `links: <something>` without
    // also enforcing a cap would be a wire-format hazard.
    let source = read_otel_source();

    let proto_span_marker = "fn proto_span(span: &TestSpan) -> ProtoSpan {";
    let start = source
        .find(proto_span_marker)
        .expect("proto_span function must exist in otel.rs");
    // Find the end of this function (next top-level fn or closing brace at indent 4).
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("proto_span must have a closing brace");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("..Default::default()"),
        "REGRESSION: proto_span no longer uses ..Default::default() \
         to fill its trailing fields. The default fill was the \
         load-bearing part of the audit invariant — without it, \
         the function must explicitly set `links` and \
         `dropped_links_count`. Verify both are set correctly \
         and that any explicit `links` value is bounded by the \
         128-link OTel SDK cap before updating this test.\n\n\
         function body:\n{body}",
    );

    // Also explicitly catch a regression that adds links: <any
    // non-empty pattern> without bounds.
    let suspect_patterns = [
        "links: span.",
        "links: vec![",
        "links: tree.",
        "links: self.",
    ];
    for pat in &suspect_patterns {
        if body.contains(pat) {
            assert!(
                body.contains("// audit-ok") || body.contains("dropped_links_count"),
                "REGRESSION: proto_span body contains `{pat}` — \
                 it now constructs links explicitly. The function \
                 MUST also set dropped_links_count and enforce the \
                 128-link cap. Audit the change and add this \
                 invariant to the test before merging.\n\n\
                 function body:\n{body}",
            );
        }
    }
}

#[test]
fn test_otlp_request_builder_default_init_for_links() {
    // Pin (b)+(c): both the test-conformance and reference OTLP
    // builders MUST emit empty links by default. Specifically:
    //   - build_our_otlp_export uses `links: vec![]` and
    //     `dropped_links_count: 0` explicitly.
    //   - build_reference_otlp_export uses `links: SpanLinks::
    //     default()` (which is also empty).
    //
    // A regression where one path emits links and the other
    // doesn't would break the byte-identical conformance test
    // (`otlp_export_conformance_byte_identical`).
    let source = read_otel_source();

    // The conformance test pins both paths. Verify the `links:
    // vec![]` line still exists in the our-impl branch.
    assert!(
        source.contains("links: vec![],") || source.contains("links: vec ! [ ],"),
        "REGRESSION: build_our_otlp_export no longer emits \
         `links: vec![]` explicitly. If a real link-construction \
         path was added, ensure it is bounded by the OTel SDK \
         128-link cap and that dropped_links_count tracks any \
         over-cap drops. Update this audit test together with \
         the wire change.",
    );

    // The reference branch uses SpanLinks::default(); pin that.
    assert!(
        source.contains("links: SpanLinks::default(),"),
        "REGRESSION: build_reference_otlp_export no longer uses \
         SpanLinks::default(). The byte-identical conformance \
         test depends on both paths emitting equivalent empty \
         links — diverging here would break the conformance \
         test. Audit and update.",
    );
}

#[test]
fn test_dropped_links_count_explicitly_set_to_zero() {
    // Pin (b) reinforced: the `dropped_links_count: 0` literal
    // must be present in the our-impl OTLP builder. A regression
    // that removed the explicit zero (e.g. via
    // ..Default::default() replacement) would lose the wire-
    // format pin. The default would still produce 0, but the
    // explicit literal documents intent.
    let source = read_otel_source();
    assert!(
        source.contains("dropped_links_count: 0"),
        "REGRESSION: explicit `dropped_links_count: 0` literal is \
         no longer present in otel.rs. If links became dynamic, \
         this counter MUST track over-cap drops; if the field \
         was made implicit via ..Default::default(), the \
         conformance test should still pass but the audit \
         intent is no longer documented in the source. Update \
         this audit test to match the new structure.",
    );
}

#[test]
fn owned_link_surface_has_a_finite_enforced_cap() {
    let source = read_otel_source();
    assert!(
        source.contains("pub const OWNED_OTLP_MAX_LINKS_PER_SPAN: usize = 128;")
            && source.contains("pub const fn with_links(")
            && source.contains("pub const fn with_dropped_links_count(")
            && source.contains("span.links.len() > config.max_links_per_span")
            && source.contains("self.max_links_per_span > OWNED_OTLP_MAX_LINKS_PER_SPAN"),
        "REGRESSION: the owned OTLP link surface must retain its public 128-link \
         ceiling, explicit dropped-count input, configuration upper bound, and \
         per-span preflight enforcement before wire emission.",
    );
}
