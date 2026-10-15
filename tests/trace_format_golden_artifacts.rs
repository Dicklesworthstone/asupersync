//! Golden-artifact harness for `asupersync::trace::format`.
//!
//! `GoldenTraceFixture` freezes a canonical summary of a trace run —
//! fingerprint, event count, canonical Foata-layer prefix, and oracle
//! violations — so a later run can be diffed against the recorded baseline.
//! It is the regression spine for deterministic-replay testing, so its own
//! comparison logic must obey a few non-negotiable properties:
//!
//! - **Self-verification**: a fixture always verifies clean against itself
//!   (`verify` is reflexive) — a golden that rejects its own baseline is
//!   useless.
//! - **Determinism**: `from_events` is a pure function of `(config, events,
//!   violations)` — rebuilding yields a byte-identical fixture.
//! - **verify ⇔ clean delta report**: the boolean `verify` result and the
//!   structured `delta_report` agree.
//! - **Drift detection**: a fixture built from a different event stream does
//!   *not* verify against the baseline.
//! - **Oracle-violation canonicalization**: violation tags are sorted and
//!   deduplicated regardless of input order/multiplicity.
//!
//! It also pins `trace_to_string` / `format_trace` determinism and agreement.
//!
//! Focused single-module test; no `proptest` dependency.

use std::io::Cursor;

use asupersync::trace::TraceBuffer;
use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
use asupersync::trace::format::{
    GoldenTraceConfig, GoldenTraceFixture, format_trace, trace_to_string,
};
use asupersync::types::{RegionId, TaskId, Time};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn tid(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}
fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn cfg() -> GoldenTraceConfig {
    GoldenTraceConfig {
        seed: 0x5EED,
        entropy_seed: 0xE17,
        worker_count: 3,
        trace_capacity: 256,
        max_steps: Some(10_000),
        canonical_prefix_layers: 8,
        canonical_prefix_events: 64,
    }
}

/// A short, structurally varied trace.
fn trace_a() -> Vec<TraceEvent> {
    let t = |n| Time::from_nanos(n);
    vec![
        TraceEvent::spawn(1, t(10), tid(1), rid(1)),
        TraceEvent::spawn(2, t(20), tid(2), rid(1)),
        TraceEvent::schedule(3, t(30), tid(1), rid(1)),
        TraceEvent::poll(4, t(40), tid(2), rid(1)),
        TraceEvent::complete(5, t(50), tid(1), rid(1)),
        TraceEvent::complete(6, t(60), tid(2), rid(1)),
    ]
}

/// A trace that differs from `trace_a` in length and content.
fn trace_b() -> Vec<TraceEvent> {
    let t = |n| Time::from_nanos(n);
    vec![
        TraceEvent::spawn(1, t(10), tid(9), rid(7)),
        TraceEvent::wake(2, t(25), tid(9), rid(7)),
        TraceEvent::complete(3, t(99), tid(9), rid(7)),
    ]
}

fn no_violations() -> Vec<String> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// GoldenTraceFixture — verification contract
// ---------------------------------------------------------------------------

#[test]
fn a_fixture_verifies_clean_against_itself() {
    let fixture = GoldenTraceFixture::from_events(cfg(), &trace_a(), no_violations());
    assert!(
        fixture.verify(&fixture).is_ok(),
        "a golden fixture must verify against its own baseline"
    );
    assert!(
        fixture.delta_report(&fixture).is_clean(),
        "self delta report must be clean"
    );
}

#[test]
fn from_events_is_deterministic() {
    let a = GoldenTraceFixture::from_events(cfg(), &trace_a(), no_violations());
    let b = GoldenTraceFixture::from_events(cfg(), &trace_a(), no_violations());
    assert_eq!(a, b, "from_events must be a pure function of its inputs");
    assert_eq!(a.fingerprint, b.fingerprint);
    assert_eq!(a.canonical_prefix, b.canonical_prefix);
}

#[test]
fn event_count_matches_the_input_length() {
    for trace in [trace_a(), trace_b(), Vec::new()] {
        let fixture = GoldenTraceFixture::from_events(cfg(), &trace, no_violations());
        assert_eq!(
            fixture.event_count,
            trace.len() as u64,
            "event_count must equal the number of events"
        );
    }
}

#[test]
fn verify_agrees_with_the_delta_report() {
    // The boolean `verify` and the structured `delta_report` must never
    // disagree about whether two fixtures match.
    let base = GoldenTraceFixture::from_events(cfg(), &trace_a(), no_violations());
    let cases = [
        GoldenTraceFixture::from_events(cfg(), &trace_a(), no_violations()), // identical
        GoldenTraceFixture::from_events(cfg(), &trace_b(), no_violations()), // different events
    ];
    for actual in &cases {
        let verify_ok = base.verify(actual).is_ok();
        let delta_clean = base.delta_report(actual).is_clean();
        assert_eq!(
            verify_ok, delta_clean,
            "verify() and delta_report().is_clean() disagree"
        );
    }
}

#[test]
fn a_divergent_event_stream_fails_verification() {
    let baseline = GoldenTraceFixture::from_events(cfg(), &trace_a(), no_violations());
    let drifted = GoldenTraceFixture::from_events(cfg(), &trace_b(), no_violations());

    assert!(
        baseline.verify(&drifted).is_err(),
        "a fixture from a different event stream must not verify clean"
    );
    let report = baseline.delta_report(&drifted);
    assert!(!report.is_clean(), "delta report must record the drift");
    assert!(
        !report.deltas.is_empty(),
        "drift must surface at least one delta"
    );
}

#[test]
fn oracle_violations_are_sorted_and_deduplicated() {
    // Tags are supplied out of order and with duplicates; the fixture must
    // store a sorted, duplicate-free list so two runs with the same violation
    // *set* produce equal fixtures regardless of discovery order.
    let messy = GoldenTraceFixture::from_events(
        cfg(),
        &trace_a(),
        vec!["zebra", "alpha", "zebra", "mango", "alpha"],
    );
    assert_eq!(
        messy.oracle_summary.violations,
        vec![
            "alpha".to_string(),
            "mango".to_string(),
            "zebra".to_string()
        ],
        "violations must be sorted and deduplicated"
    );

    // Same set, different input order ⇒ equal fixtures.
    let other_order =
        GoldenTraceFixture::from_events(cfg(), &trace_a(), vec!["mango", "zebra", "alpha"]);
    assert_eq!(
        messy, other_order,
        "violation discovery order must not affect the fixture"
    );
}

#[test]
fn a_clean_run_has_no_oracle_violations() {
    let fixture = GoldenTraceFixture::from_events(cfg(), &trace_a(), no_violations());
    assert!(
        fixture.oracle_summary.violations.is_empty(),
        "a run with no violations must record an empty violation list"
    );
}

// ---------------------------------------------------------------------------
// trace_to_string / format_trace — determinism and agreement
// ---------------------------------------------------------------------------

fn buffer_from(trace: &[TraceEvent]) -> TraceBuffer {
    let mut buf = TraceBuffer::new(256);
    for ev in trace {
        buf.push(ev.clone());
    }
    buf
}

#[test]
fn trace_to_string_is_deterministic() {
    let buf = buffer_from(&trace_a());
    let s1 = trace_to_string(&buf);
    let s2 = trace_to_string(&buf);
    assert_eq!(s1, s2, "trace_to_string must be deterministic");
    assert!(
        !s1.is_empty(),
        "a non-empty trace should render non-empty text"
    );
}

#[test]
fn format_trace_agrees_with_trace_to_string() {
    let buf = buffer_from(&trace_a());
    let mut sink: Vec<u8> = Vec::new();
    format_trace(&buf, &mut Cursor::new(&mut sink)).expect("format_trace must succeed");
    let written = String::from_utf8(sink).expect("format_trace output must be UTF-8");
    assert_eq!(
        written,
        trace_to_string(&buf),
        "format_trace and trace_to_string must produce the same text"
    );
}

#[test]
fn empty_buffer_formats_without_error() {
    let buf = TraceBuffer::new(16);
    let s = trace_to_string(&buf);
    let mut sink: Vec<u8> = Vec::new();
    format_trace(&buf, &mut Cursor::new(&mut sink)).expect("format_trace on empty buffer");
    assert_eq!(String::from_utf8(sink).unwrap(), s);
}

// ---------------------------------------------------------------------------
// Trace-data sanity: unused import guard for TraceData/TraceEventKind.
// ---------------------------------------------------------------------------

#[test]
fn user_trace_events_round_trip_through_the_buffer() {
    let ev = TraceEvent::new(
        42,
        Time::ZERO,
        TraceEventKind::UserTrace,
        TraceData::Message("hello".to_string()),
    );
    let buf = buffer_from(&[ev]);
    let fixture = GoldenTraceFixture::from_events(
        cfg(),
        &[TraceEvent::new(
            42,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("hello".to_string()),
        )],
        no_violations(),
    );
    assert_eq!(fixture.event_count, 1);
    assert!(!trace_to_string(&buf).is_empty());
}
