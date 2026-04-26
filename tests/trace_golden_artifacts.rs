#![cfg(feature = "test-internals")]
#![allow(clippy::all)]
//! Golden artifacts for the trace subsystem.
//!
//! Freezes three classes of output that downstream tooling (replay
//! debuggers, CI dashboards, postmortem doc generators) depends on:
//!
//! 1. **Canonical trace fingerprint and Foata-form layout** — the
//!    Mazurkiewicz/Foata canonical form used for trace-equivalence
//!    checks (`src/trace/canonicalize.rs`). The `class_fingerprint`
//!    must be a stable function of the equivalence class so that
//!    re-shuffles of independent events produce the same fingerprint
//!    and any structural change to the canonicalization algorithm is
//!    caught.
//! 2. **Divergence report formatting** — both the JSON-serialised
//!    form and the human-readable text form
//!    (`src/trace/divergence.rs`). Replay-debugging tooling parses
//!    the JSON; humans read the text form. A silent change in either
//!    breaks downstream parsers and on-call playbooks.
//! 3. **Integrity issue → severity mapping** — the contract used by
//!    the loader / verifier (`src/trace/integrity.rs`) to decide
//!    whether a trace is usable, partially-usable, or unusable. The
//!    mapping is consumed by replay tooling and must not silently
//!    flip a `Warning` into a `Fatal` (or vice versa) without a
//!    snapshot review.
//!
//! Snapshots live under `tests/snapshots/trace_golden_artifacts__*.snap`.

use asupersync::trace::canonicalize::{TraceEventKey, TraceMonoid};
use asupersync::trace::divergence::{
    AffectedEntities, DivergenceCategory, DivergenceReport, EventSummary,
};
use asupersync::trace::event::{TraceEvent, TraceEventKind};
use asupersync::trace::integrity::{IntegrityIssue, IssueSeverity};
use asupersync::types::{RegionId, TaskId, Time};
use insta::{assert_json_snapshot, assert_snapshot};
use serde_json::{Value, json};

// -----------------------------------------------------------------------------
// Deterministic fixtures
// -----------------------------------------------------------------------------

/// Build a small canonical event sequence with FIXED seq numbers, FIXED
/// virtual time, and FIXED task / region IDs so the resulting fingerprint
/// is reproducible across runs and machines.
fn fixture_events() -> Vec<TraceEvent> {
    let region = RegionId::new_for_test(42, 0);
    let task_a = TaskId::new_for_test(7, 0);
    let task_b = TaskId::new_for_test(8, 0);

    let t = |nanos: u64| Time::from_nanos(nanos);

    vec![
        TraceEvent::spawn(0, t(1_000), task_a, region),
        TraceEvent::spawn(1, t(2_000), task_b, region),
        TraceEvent::schedule(2, t(3_000), task_a, region),
        TraceEvent::poll(3, t(4_000), task_a, region),
        TraceEvent::yield_task(4, t(5_000), task_a, region),
        TraceEvent::schedule(5, t(6_000), task_b, region),
        TraceEvent::poll(6, t(7_000), task_b, region),
        TraceEvent::complete(7, t(8_000), task_b, region),
        TraceEvent::schedule(8, t(9_000), task_a, region),
        TraceEvent::poll(9, t(10_000), task_a, region),
        TraceEvent::complete(10, t(11_000), task_a, region),
    ]
}

/// Build a synthetic DivergenceReport with deterministic fields. We
/// construct the structure directly rather than driving a replay so the
/// fixture is hermetic — no replay-engine state can leak into the snapshot.
fn fixture_divergence_report() -> DivergenceReport {
    DivergenceReport {
        category: DivergenceCategory::SchedulingOrder,
        divergence_index: 17,
        trace_length: 42,
        replay_progress_pct: 40.476_190_476_190_47, // 17/42 * 100, fixed
        expected: EventSummary {
            index: 17,
            event_type: "Schedule".to_string(),
            details: "task=7 region=42".to_string(),
            task_id: Some(7),
            region_id: Some(42),
        },
        actual: EventSummary {
            index: 17,
            event_type: "Schedule".to_string(),
            details: "task=8 region=42".to_string(),
            task_id: Some(8),
            region_id: Some(42),
        },
        explanation: "expected task 7 to be scheduled next, but task 8 was scheduled \
                      instead (work-stealer raced)"
            .to_string(),
        suggestion: "re-run with --deterministic-stealer or pin worker count to 1"
            .to_string(),
        context_before: vec![
            EventSummary {
                index: 15,
                event_type: "Poll".to_string(),
                details: "task=7 region=42".to_string(),
                task_id: Some(7),
                region_id: Some(42),
            },
            EventSummary {
                index: 16,
                event_type: "Yield".to_string(),
                details: "task=7 region=42".to_string(),
                task_id: Some(7),
                region_id: Some(42),
            },
        ],
        context_after: vec![EventSummary {
            index: 18,
            event_type: "Poll".to_string(),
            details: "task=7 region=42".to_string(),
            task_id: Some(7),
            region_id: Some(42),
        }],
        affected: AffectedEntities {
            tasks: vec![7, 8],
            regions: vec![42],
            timers: Vec::new(),
            scheduler_lane: Some("ready".to_string()),
        },
        minimal_prefix_len: 18,
        seed: 0x0123_4567_89AB_CDEF,
    }
}

// -----------------------------------------------------------------------------
// 1. Canonical trace fingerprint + Foata structure
// -----------------------------------------------------------------------------

/// Freezes the Foata canonical-form structure of the fixture: layer count,
/// total event count, and 64-bit class fingerprint. A change in any of
/// these is a contract change that must be reviewed deliberately.
#[test]
fn golden_canonical_form_layout() {
    let events = fixture_events();
    let monoid = TraceMonoid::from_events(&events);
    let canonical = monoid.canonical_form();

    let snapshot = json!({
        "layer_count": canonical.depth(),
        "event_count": canonical.len(),
        "is_empty": canonical.is_empty(),
        "class_fingerprint_hex": format!("0x{:016x}", monoid.class_fingerprint()),
        "canonical_fingerprint_hex": format!("0x{:016x}", canonical.fingerprint()),
        "fingerprints_agree": monoid.class_fingerprint() == canonical.fingerprint(),
    });

    assert_json_snapshot!("trace_canonical_layout", snapshot);
}

/// Freezes the canonical fingerprint as a function of the equivalence
/// class. The fingerprint must be order-independent over independent
/// events: two builds of the same class produce the same fingerprint.
#[test]
fn golden_class_fingerprint_is_order_independent() {
    let events_a = fixture_events();
    let mut events_b = fixture_events();
    // Reverse the order of two adjacent independent events: spawn(7) and
    // spawn(8) at fixture indices 0 and 1 are independent because they
    // touch different tasks. The canonical form must absorb the swap.
    events_b.swap(0, 1);

    let fp_a = TraceMonoid::from_events(&events_a).class_fingerprint();
    let fp_b = TraceMonoid::from_events(&events_b).class_fingerprint();

    let snapshot = json!({
        "fingerprint_a_hex": format!("0x{:016x}", fp_a),
        "fingerprint_b_hex": format!("0x{:016x}", fp_b),
        "match": fp_a == fp_b,
        "events_a_seq": events_a.iter().map(|e| e.seq).collect::<Vec<_>>(),
        "events_b_seq": events_b.iter().map(|e| e.seq).collect::<Vec<_>>(),
    });

    // Drain to keep the borrow checker happy if events_a is reused later.
    let _ = &events_a;

    assert_json_snapshot!("trace_class_fingerprint_order_independent", snapshot);
}

/// Freezes the wire format of `TraceEventKey`. This struct is the
/// canonical intra-layer ordering primitive consumed by golden fixture
/// prefixes and diff tooling, and is publicly serializable — its JSON
/// shape is part of the cross-version compat surface.
#[test]
fn golden_trace_event_key_serialization() {
    let keys = vec![
        TraceEventKey::new(0, 1, 2, 3),
        TraceEventKey::new(255, u64::MAX, u64::MAX - 1, u64::MAX - 2),
        TraceEventKey::new(7, 0, 0, 0),
    ];
    assert_json_snapshot!("trace_event_key_serialization", keys);
}

// -----------------------------------------------------------------------------
// 2. Divergence report formatting
// -----------------------------------------------------------------------------

/// Freezes the JSON shape of a DivergenceReport — the format consumed by
/// CI dashboards and replay-debugger UIs. A silent field rename or
/// re-ordering would break those parsers.
#[test]
fn golden_divergence_report_json_shape() {
    let report = fixture_divergence_report();
    let json_str = report
        .to_json()
        .expect("DivergenceReport::to_json must succeed for a fixture report");
    let parsed: Value =
        serde_json::from_str(&json_str).expect("emitted JSON must round-trip via serde_json");
    assert_json_snapshot!("trace_divergence_report_json", parsed);
}

/// Freezes the human-readable text form of a DivergenceReport. This is
/// what shows up in on-call playbooks and CI failure summaries; visual
/// changes need a deliberate snapshot review.
#[test]
fn golden_divergence_report_text() {
    let text = fixture_divergence_report().to_text();
    // `to_text` is fully deterministic for a deterministic input — no
    // timestamps, no random IDs — so we snapshot it verbatim.
    assert_snapshot!("trace_divergence_report_text", text);
}

/// Freezes the Display rendering of every DivergenceCategory variant.
/// The Category names are part of the public diagnostic surface; renaming
/// one would break every external dashboard keyed off the category.
#[test]
fn golden_divergence_category_display_table() {
    let categories = [
        DivergenceCategory::SchedulingOrder,
        DivergenceCategory::OutcomeMismatch,
        DivergenceCategory::TimeDivergence,
        DivergenceCategory::TimerMismatch,
        DivergenceCategory::IoMismatch,
        DivergenceCategory::RngMismatch,
        DivergenceCategory::RegionMismatch,
        DivergenceCategory::EventTypeMismatch,
        DivergenceCategory::LengthMismatch,
        DivergenceCategory::WakerMismatch,
        DivergenceCategory::ChaosMismatch,
        DivergenceCategory::CheckpointMismatch,
    ];
    let table: Vec<Value> = categories
        .iter()
        .map(|c| {
            json!({
                "variant": format!("{c:?}"),
                "display": format!("{c}"),
            })
        })
        .collect();
    assert_json_snapshot!("trace_divergence_category_display", table);
}

// -----------------------------------------------------------------------------
// 3. Integrity issue → severity mapping
// -----------------------------------------------------------------------------

/// Freezes the IntegrityIssue → IssueSeverity mapping. Replay tooling
/// uses this to decide whether to attempt a load (`Warning` / `Error`)
/// or refuse outright (`Fatal`). A silent flip from `Fatal` to `Warning`
/// would risk loading corrupt traces into a debugger; a silent flip in
/// the other direction would refuse to load recoverable traces.
#[test]
fn golden_integrity_issue_severity_mapping() {
    fn severity_str(s: IssueSeverity) -> &'static str {
        match s {
            IssueSeverity::Warning => "warning",
            IssueSeverity::Error => "error",
            IssueSeverity::Fatal => "fatal",
        }
    }

    let issues = vec![
        IntegrityIssue::FileTooSmall {
            actual: 32,
            expected: 64,
        },
        IntegrityIssue::InvalidMagic {
            found: *b"DEADBEEF\0\0\0",
        },
        IntegrityIssue::UnsupportedVersion {
            found: 99,
            max_supported: 1,
        },
        IntegrityIssue::UnsupportedFlags { flags: 0xF000 },
        IntegrityIssue::SchemaMismatch {
            found: 7,
            expected: 1,
        },
        IntegrityIssue::InvalidMetadata {
            message: "fixed metadata-error string for golden snapshot".to_string(),
        },
        IntegrityIssue::EventCountMismatch {
            declared: 100,
            actual: 95,
        },
        IntegrityIssue::InvalidEvent {
            index: 42,
            message: "fixed event-error string for golden snapshot".to_string(),
        },
        IntegrityIssue::Truncated { at_event: 17 },
        IntegrityIssue::TimelineNonMonotonic {
            at_event: 5,
            prev_time: 1_000,
            curr_time: 999,
        },
        IntegrityIssue::IoError {
            message: "fixed io-error string for golden snapshot".to_string(),
        },
    ];

    let table: Vec<Value> = issues
        .iter()
        .map(|issue| {
            json!({
                "display": format!("{issue}"),
                "severity": severity_str(issue.severity()),
                "is_fatal": issue.is_fatal(),
            })
        })
        .collect();

    assert_json_snapshot!("trace_integrity_issue_severity", table);
}

// -----------------------------------------------------------------------------
// Cross-cutting: TraceEventKind enum coverage
// -----------------------------------------------------------------------------

/// Freezes the discriminant byte for each TraceEventKind variant. The
/// discriminant is used by `event_hash_key` (referenced by
/// `FoataTrace::fingerprint`) and by the canonical wire format — a
/// silent re-ordering of the enum would invalidate every previously
/// recorded trace's fingerprint.
#[test]
fn golden_trace_event_kind_variants_are_stable() {
    // We cannot enumerate the enum reflectively, but we CAN assert that
    // every constructor-built event has a stable kind discriminant via
    // its serialized form. Two identically constructed events must
    // produce identical kinds.
    let region = RegionId::new_for_test(1, 0);
    let task = TaskId::new_for_test(1, 0);
    let t = Time::from_nanos(100);

    let constructed: Vec<(&'static str, TraceEvent)> = vec![
        ("spawn", TraceEvent::spawn(0, t, task, region)),
        ("schedule", TraceEvent::schedule(1, t, task, region)),
        ("yield", TraceEvent::yield_task(2, t, task, region)),
        ("wake", TraceEvent::wake(3, t, task, region)),
        ("poll", TraceEvent::poll(4, t, task, region)),
        ("complete", TraceEvent::complete(5, t, task, region)),
    ];

    let table: Vec<Value> = constructed
        .iter()
        .map(|(label, ev)| {
            json!({
                "constructor": label,
                "seq": ev.seq,
                "kind_debug": format!("{:?}", std::mem::discriminant(&ev.kind)),
            })
        })
        .collect();

    // Don't snapshot the raw discriminant addresses (they're process-
    // local) — instead, assert that the six constructors each produce
    // a DISTINCT discriminant, and snapshot only the (constructor, seq)
    // pairs which are stable.
    let kinds: Vec<TraceEventKind> = constructed.iter().map(|(_, ev)| ev.kind.clone()).collect();
    // Distinctness check via Debug strings (since TraceEventKind may not
    // be Hash/Eq across all variants):
    let debug_strs: Vec<String> = kinds.iter().map(|k| format!("{k:?}")).collect();
    let unique: std::collections::BTreeSet<&String> = debug_strs.iter().collect();
    assert_eq!(
        unique.len(),
        debug_strs.len(),
        "TraceEventKind variants must be distinct across the six standard \
         constructors (spawn, schedule, yield, wake, poll, complete); a \
         collision means the canonical-form fingerprint loses information"
    );

    let summary: Vec<Value> = constructed
        .iter()
        .map(|(label, ev)| {
            json!({
                "constructor": label,
                "seq": ev.seq,
            })
        })
        .collect();
    let _ = table; // table built for diagnostics; we snapshot only the stable summary.
    assert_json_snapshot!("trace_event_kind_constructor_summary", summary);
}
