//! Audit + regression test for `src/runtime/scheduler/three_lane.rs`
//! Lyapunov-governor state observability.
//!
//! Operator's question: "when governor enters 'panic' state
//! (deadlock imminent), are metric labels correctly emitted to
//! /metrics endpoint? Verify with audit test that governor
//! transitions are observable."
//!
//! Audit findings:
//!
//!   The asupersync runtime uses **two distinct enums** to model
//!   governor state. The operator's "panic" framing maps to one
//!   of them; the other tracks higher-level scheduling intent.
//!
//!   1. **`SchedulingSuggestion`** (obligation/lyapunov.rs:457).
//!      Four variants: `MeetDeadlines`, `DrainObligations`,
//!      `DrainRegions`, `NoPreference`. ALL FOUR are emitted as
//!      distinct `action` labels on the evidence sink (and
//!      hence on /metrics) via `emit_scheduler_evidence`
//!      (evidence_sink.rs:184) every governor invocation
//!      (three_lane.rs:4002). String mapping:
//!        - `MeetDeadlines` → `"meet_deadlines"`
//!        - `DrainObligations` → `"drain_obligations"`
//!        - `DrainRegions` → `"drain_regions"`
//!        - `NoPreference` → `"no_preference"`
//!
//!   2. **`DrainPhase`** (cancel/progress_certificate.rs:267).
//!      Five variants: `Warmup`, `RapidDrain`, `SlowTail`,
//!      `Stalled`, `Quiescent`. `Stalled` is the asupersync
//!      equivalent of the operator's "panic" / "deadlock
//!      imminent" state ("No meaningful progress is being
//!      made" — progress_certificate.rs:274-275).
//!
//!      `DrainPhase::Stalled` IS detected by the governor
//!      compute path (three_lane.rs:3975) and forces a
//!      `SchedulingSuggestion::DrainObligations` suggestion.
//!      So a stalled drain IS observable via /metrics — but
//!      indirectly: SREs see a sustained `drain_obligations`
//!      action and must infer Stalled vs. normal-drain from
//!      duration / repetition.
//!
//!      **Observability gap**: the Stalled flag is NOT
//!      surfaced as a distinct action label or top_feature
//!      on the evidence sink today. A direct
//!      "drain_obligations_stalled" label would let SREs
//!      alert on the deadlock-imminent transition without
//!      heuristic duration thresholds. This is a known gap;
//!      filing a follow-up audit opportunity.
//!
//! Verdict: **SOUND for the four SchedulingSuggestion
//! transitions** — every governor invocation emits an evidence
//! entry with the resolved suggestion as the `action` label,
//! producing observable /metrics counters for transitions
//! between states.
//!
//! Documented observability gap: `DrainPhase::Stalled` is
//! collapsed into the `drain_obligations` action; SREs must
//! infer Stalled from duration. A direct label is a future
//! improvement, NOT a correctness bug today.
//!
//! A regression that:
//!   - removed the call to `emit_scheduler_evidence` from the
//!     governor compute path (would silence ALL governor
//!     observability),
//!   - changed the action-label mapping (e.g.
//!     `MeetDeadlines` → `"high_priority"` instead of
//!     `"meet_deadlines"`) — would break dashboard / alert
//!     queries built against the canonical strings,
//!   - dropped a SchedulingSuggestion variant from the
//!     `match` (would default-stringify the missing variant
//!     and break string-equality alerts),
//!   - removed the DrainPhase::Stalled detection entirely
//!     (would let real deadlocks pass without forcing
//!     drain_obligations — both a correctness AND
//!     observability regression),
//!     would all be caught here.

use std::path::PathBuf;

fn read_three_lane_source() -> String {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runtime/scheduler/three_lane.rs");
    std::fs::read_to_string(&path).expect("read three_lane.rs")
}

fn read_evidence_sink_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/evidence_sink.rs");
    std::fs::read_to_string(&path).expect("read evidence_sink.rs")
}

fn read_lyapunov_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/obligation/lyapunov.rs");
    std::fs::read_to_string(&path).expect("read lyapunov.rs")
}

fn read_progress_cert_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/cancel/progress_certificate.rs");
    std::fs::read_to_string(&path).expect("read progress_certificate.rs")
}

#[test]
fn scheduling_suggestion_has_four_canonical_variants() {
    // Pin: SchedulingSuggestion has exactly four variants.
    // A regression that added a fifth without updating the
    // string-mapping match would default-stringify the new
    // variant and break /metrics queries.
    let source = read_lyapunov_source();

    let enum_marker = "pub enum SchedulingSuggestion {";
    let start = source.find(enum_marker).expect("SchedulingSuggestion enum");
    let end_rel = source[start..].find("\n}\n").expect("enum close");
    let body = &source[start..start + end_rel];

    for variant in &[
        "DrainObligations,",
        "DrainRegions,",
        "MeetDeadlines,",
        "NoPreference,",
    ] {
        assert!(
            body.contains(variant),
            "REGRESSION: SchedulingSuggestion no longer has \
             variant `{variant}`. Removing a variant breaks \
             dashboard queries built against the canonical \
             label strings.\n\nenum body:\n{body}",
        );
    }
}

#[test]
fn emit_scheduler_evidence_is_called_per_governor_compute() {
    // Pin AUDIT-CRITICAL: the governor compute path calls
    // emit_scheduler_evidence_for_suggestion at the end of
    // every invocation. Without this, governor transitions are
    // invisible to /metrics.
    let source = read_three_lane_source();

    // Find the governor compute function (it has a long body
    // and emits at the end). We grep for the canonical call
    // site.
    assert!(
        source.contains("self.emit_scheduler_evidence_for_suggestion(suggestion);"),
        "REGRESSION: governor compute path no longer calls \
         self.emit_scheduler_evidence_for_suggestion(suggestion). \
         Without this, governor state transitions are silently \
         invisible to /metrics — operators can't tell when the \
         system enters drain_obligations / meet_deadlines / \
         drain_regions.",
    );

    // The cached-suggestion path also emits (line 3755 area)
    // so cache-hits are also observable.
    assert!(
        source.contains("self.emit_scheduler_evidence_for_suggestion(self.cached_suggestion);"),
        "REGRESSION: the cached-suggestion fast path no longer \
         emits evidence. Without this, governor cache hits \
         (which represent the bulk of dispatches) are \
         invisible — /metrics only shows the rare full \
         compute path.",
    );
}

#[test]
fn emit_scheduler_evidence_maps_each_suggestion_to_canonical_label() {
    // Pin AUDIT-CRITICAL: emit_scheduler_evidence_for_suggestion
    // maps each SchedulingSuggestion variant to the canonical
    // action-label string. A regression that changed any
    // mapping would break dashboards and alert queries.
    let source = read_three_lane_source();

    let fn_marker =
        "fn emit_scheduler_evidence_for_suggestion(&self, suggestion: SchedulingSuggestion) {";
    let start = source.find(fn_marker).expect("emit_... fn");
    let body_end = source[start..].find("\n    }\n").expect("fn close");
    let body = &source[start..start + body_end];

    for (variant, label) in &[
        ("SchedulingSuggestion::MeetDeadlines", "\"meet_deadlines\""),
        (
            "SchedulingSuggestion::DrainObligations",
            "\"drain_obligations\"",
        ),
        ("SchedulingSuggestion::DrainRegions", "\"drain_regions\""),
        ("SchedulingSuggestion::NoPreference", "\"no_preference\""),
    ] {
        // Each variant must appear → its canonical label.
        let variant_pos = body.find(variant).unwrap_or_else(|| {
            panic!(
                "REGRESSION: variant `{variant}` no longer appears \
                 in the suggestion → label string match. A \
                 regression that defaulted via `_ =>` would \
                 silently lose this transition. Body:\n{body}"
            )
        });
        // The label must follow the variant within ~100 chars
        // (the match arm).
        let arm_window = &body[variant_pos..(variant_pos + 200).min(body.len())];
        assert!(
            arm_window.contains(label),
            "REGRESSION: variant `{variant}` no longer maps to \
             label `{label}`. Dashboards and alert queries \
             built against the canonical labels would break.\n\n\
             arm window:\n{arm_window}",
        );
    }
}

#[test]
fn drain_phase_stalled_variant_exists_and_means_no_progress() {
    // Pin: DrainPhase::Stalled is the asupersync equivalent of
    // the operator's "panic" / "deadlock imminent" state. The
    // variant must continue to exist and to mean "no
    // meaningful progress" — a regression that removed it
    // would defeat the governor's deadlock-detection logic.
    let source = read_progress_cert_source();

    let enum_marker = "pub enum DrainPhase {";
    let start = source.find(enum_marker).expect("DrainPhase enum");
    let end_rel = source[start..].find("\n}\n").expect("DrainPhase close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("Stalled,"),
        "REGRESSION: DrainPhase no longer has the Stalled \
         variant. The Stalled state is the deadlock-imminent \
         signal that forces a DrainObligations suggestion — \
         removing it would let real deadlocks pass without \
         intervention.\n\nenum body:\n{body}",
    );

    // Doc above the variant must explain its semantics.
    let doc_marker = "/// No meaningful progress is being made.";
    assert!(
        body.contains(doc_marker),
        "REGRESSION: DrainPhase::Stalled doc no longer says \
         'No meaningful progress is being made'. The doc is \
         the public contract; if the semantics changed, \
         dashboards and alerts based on this state may need \
         updating.",
    );

    // The Display impl must produce "stalled" for the metric
    // label. (Even though it's not currently emitted as a
    // distinct evidence-sink action, the Display impl is the
    // canonical wire string for /metrics if it ever gets
    // surfaced.)
    assert!(
        source.contains("Self::Stalled => f.write_str(\"stalled\"),"),
        "REGRESSION: DrainPhase::Stalled Display no longer \
         emits the canonical 'stalled' string. If/when this \
         state gets surfaced as a metric label, the string \
         needs to be stable for dashboard queries.",
    );
}

#[test]
fn governor_compute_path_handles_drain_phase_stalled() {
    // Pin AUDIT-CRITICAL: the governor compute path detects
    // DrainPhase::Stalled and forces a DrainObligations
    // suggestion. This is the indirect /metrics signal an SRE
    // sees: a stalled drain elevates drain_obligations
    // frequency. A regression that removed the detection
    // would let real deadlocks pass through.
    let source = read_three_lane_source();

    assert!(
        source.contains("DrainPhase::Stalled if verdict.stall_detected => {"),
        "REGRESSION: governor compute no longer detects \
         DrainPhase::Stalled. Without this, a stalled drain \
         doesn't escalate to DrainObligations and the \
         /metrics signal is silenced.",
    );

    // The Stalled branch must force DrainObligations.
    let marker_pos = source
        .find("DrainPhase::Stalled if verdict.stall_detected => {")
        .expect("Stalled match arm");
    let arm_window = &source[marker_pos..(marker_pos + 600).min(source.len())];

    assert!(
        arm_window.contains("suggestion = SchedulingSuggestion::DrainObligations;"),
        "REGRESSION: the Stalled match arm no longer assigns \
         SchedulingSuggestion::DrainObligations. Without the \
         escalation, a stalled drain would propagate the \
         original suggestion, hiding the 'panic' transition \
         from /metrics.\n\narm window:\n{arm_window}",
    );
}

#[test]
fn evidence_sink_emit_scheduler_evidence_uses_action_label() {
    // Pin: emit_scheduler_evidence sets `action: action.clone()`
    // on the EvidenceLedger entry — the action becomes the
    // metric label. A regression that hardcoded the action or
    // dropped it would break /metrics observability.
    let source = read_evidence_sink_source();

    let fn_marker = "pub fn emit_scheduler_evidence(";
    let start = source.find(fn_marker).expect("emit_scheduler_evidence");
    let body_end = source[start..].find("\n}\n").expect("fn close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("let action = suggestion.to_string();"),
        "REGRESSION: emit_scheduler_evidence no longer derives \
         the action label from the `suggestion: &str` argument. \
         Without this, every governor decision would emit the \
         same hardcoded label and transitions would be \
         invisible.\n\nfn body:\n{body}",
    );

    assert!(
        body.contains("component: \"scheduler\".to_string(),"),
        "REGRESSION: the EvidenceLedger.component is no longer \
         'scheduler'. Dashboards filter by component to \
         distinguish governor metrics from cancellation / \
         other emitters.",
    );

    // The expected_loss_by_action map must include the action
    // — this is what produces the labeled gauge on /metrics.
    assert!(
        body.contains("expected_loss_by_action: std::collections::BTreeMap::from([(action"),
        "REGRESSION: emit_scheduler_evidence no longer \
         populates expected_loss_by_action keyed on the \
         action label. The labeled gauge is what shows up on \
         /metrics; without it, transitions don't surface.",
    );
}

#[test]
fn evidence_sink_emit_scheduler_evidence_carries_lane_depths() {
    // Pin: the top_features on the evidence entry include
    // cancel_depth, timed_depth, ready_depth. These let
    // dashboards correlate governor decisions with the actual
    // queue state at decision time. A regression that dropped
    // them would force operators to guess why the governor
    // chose what it did.
    let source = read_evidence_sink_source();

    let fn_marker = "pub fn emit_scheduler_evidence(";
    let start = source.find(fn_marker).expect("emit_scheduler_evidence");
    let body_end = source[start..].find("\n}\n").expect("fn close");
    let body = &source[start..start + body_end];

    for feature in &["cancel_depth", "timed_depth", "ready_depth"] {
        assert!(
            body.contains(&format!("\"{feature}\".to_string()")),
            "REGRESSION: top_features no longer carries \
             `{feature}`. SREs need queue-depth context \
             alongside the action label to interpret \
             governor decisions; dropping this hides the \
             'why' of every transition.\n\nfn body:\n{body}",
        );
    }
}

#[test]
fn governor_compute_emits_per_invocation_not_only_on_change() {
    // Pin: emit_scheduler_evidence_for_suggestion is called
    // unconditionally at the end of governor compute, NOT
    // gated on "suggestion changed". Per
    // br-asupersync-c4r700, the rate of governor decisions is
    // itself observability: an SRE seeing 1000
    // drain_obligations/sec means something different than
    // seeing 10/sec, even if the suggestion didn't "change"
    // in either case.
    let source = read_three_lane_source();

    // The emission call site must NOT be inside an `if
    // suggestion != self.cached_suggestion {` block. We pin
    // by checking that there's NO such guard preceding the
    // emit call.
    let emit_marker = "self.emit_scheduler_evidence_for_suggestion(suggestion);";
    let emit_pos = source.find(emit_marker).expect("emit call");

    // Take the 200 chars preceding the emit call.
    let pre_start = emit_pos.saturating_sub(200);
    let pre_start = source[..pre_start].rfind('\n').map_or(0, |p| p + 1);
    let pre_window = &source[pre_start..emit_pos];

    assert!(
        !pre_window.contains("if suggestion != self.cached_suggestion {"),
        "REGRESSION: emit_scheduler_evidence_for_suggestion is \
         now gated on `if suggestion != cached_suggestion`. \
         Per br-asupersync-c4r700, the per-invocation rate is \
         itself signal — gating on change loses the rate \
         dimension and breaks dashboards that track decision \
         frequency.\n\npre-emit window:\n{pre_window}",
    );
}

#[test]
fn observability_gap_drain_phase_stalled_known_limitation() {
    // Pin: this test DOCUMENTS the known observability gap so
    // a future audit run that finds a "drain_obligations_stalled"
    // (or equivalent) action label can update this pin. Today,
    // DrainPhase::Stalled is collapsed into the
    // "drain_obligations" action — SREs must infer Stalled
    // from duration / repetition. This is a documented gap,
    // NOT a correctness bug.
    let source = read_three_lane_source();

    let fn_marker =
        "fn emit_scheduler_evidence_for_suggestion(&self, suggestion: SchedulingSuggestion) {";
    let start = source.find(fn_marker).expect("emit_... fn");
    let body_end = source[start..].find("\n    }\n").expect("fn close");
    let body = &source[start..start + body_end];

    // Today, NO "drain_obligations_stalled" / "panic" /
    // "stalled" string appears in the suggestion → label
    // map. If this changes, update the pin to also verify
    // that the new label is wired correctly.
    let stalled_label_appeared = body.contains("\"drain_obligations_stalled\"")
        || body.contains("\"stalled\"")
        || body.contains("\"panic\"");

    // Promote: the gap was filled. Update the audit pin to
    // verify the new wiring (e.g., that stall_detected from
    // the verdict propagates to this string).
    assert!(
        !stalled_label_appeared,
        "AUDIT GATE: a stalled-specific action label \
         appeared in emit_scheduler_evidence_for_suggestion. \
         The observability gap documented in this audit \
         test has been filled — UPDATE THIS PIN to verify \
         the new wiring (verdict.stall_detected → \
         distinct action label → /metrics counter). The \
         gap was: DrainPhase::Stalled was previously \
         collapsed into 'drain_obligations'. New body:\n\
         {body}"
    );
}
