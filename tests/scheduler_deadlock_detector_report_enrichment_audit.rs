//! Audit + regression test for `src/runtime/scheduler/three_lane.rs`
//! Tarjan-SCC deadlock-detector report enrichment.
//!
//! Operator's question: "when a deadlock is detected via Tarjan
//! SCC, is the report enriched with the cycle's task IDs,
//! file:line waiting points, AND wait-cause (lock vs channel
//! vs notify)? If only IDs, that's an improvement opportunity.
//! If defect, file bead. If SOUND, pin."
//!
//! Current pinned behavior:
//!
//!   The Tarjan-SCC path now preserves the smallest trapped
//!   SCC instead of discarding it after computing the legacy
//!   `trapped_wait_cycle: bool`.
//!
//!   Source-level evidence:
//!
//!   1. **`WaitGraphTaskSnapshot`** still carries `id:
//!      TaskId` and `waiters: Vec<TaskId>` for the existing
//!      wait-graph construction path, and now also carries
//!      `wait_edges: Vec<WaitGraphEdgeSnapshot>` for
//!      structured cause/location metadata.
//!
//!   2. **`WaitGraphSignalReport`** preserves the old boolean
//!      as `trapped_wait_cycle` and adds `trapped_cycle:
//!      Option<DeadlockCycleReport>` with stable TaskIds and
//!      edge details.
//!
//!   3. **`trapped_scc_with_edge_observer`** returns
//!      `Option<Vec<usize>>`, with the trapped component
//!      stable-sorted before reporting.
//!
//! Verdict: **PARTIALLY ENRICHED / SOUND**. The scheduler's
//! existing boolean and DrainObligations reaction remain intact,
//! while the internal report path now exposes TaskIds plus
//! wait-cause/location fallback fields. Current production
//! snapshots still mark wait causes as `Unknown` until individual
//! wait-site registration paths thread more precise causes.

use std::path::PathBuf;

fn read_three_lane_source() -> String {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runtime/scheduler/three_lane.rs");
    std::fs::read_to_string(&path).expect("read three_lane.rs")
}

#[test]
fn wait_graph_task_snapshot_carries_enriched_edges_with_waiter_fallback() {
    let source = read_three_lane_source();

    let struct_marker = "struct WaitGraphTaskSnapshot {";
    let start = source
        .find(struct_marker)
        .expect("WaitGraphTaskSnapshot struct");
    let end_rel = source[start..].find("\n}\n").expect("struct close");
    let body = &source[start..start + end_rel];

    assert!(body.contains("id: TaskId,"));
    assert!(
        body.contains("waiters: Vec<TaskId>,"),
        "legacy waiter endpoints must remain as the fallback source"
    );
    assert!(
        body.contains("wait_edges: Vec<WaitGraphEdgeSnapshot>,"),
        "enriched wait edges must carry cause/location metadata"
    );
}

#[test]
fn deadlock_report_preserves_boolean_api_and_adds_structured_cycle() {
    let source = read_three_lane_source();

    assert!(
        source.contains("struct WaitGraphSignalReport {")
            && source.contains("trapped_wait_cycle: bool,")
            && source.contains("trapped_cycle: Option<DeadlockCycleReport>,"),
        "the report must preserve the old boolean while exposing structured cycle details"
    );
    assert!(
        source.contains("struct DeadlockCycleReport {")
            && source.contains("tasks: Vec<TaskId>,")
            && source.contains("edges: Vec<DeadlockWaitEdgeReport>,"),
        "deadlock cycle reports must expose stable TaskIds and edge details"
    );
    assert!(
        source.contains("fn wait_graph_signals_from_snapshot(")
            && source.contains("report.trapped_wait_cycle"),
        "legacy callers should continue deriving the boolean from the enriched report"
    );
}

#[test]
fn trapped_scc_returns_component_indices() {
    let source = read_three_lane_source();

    let fn_marker = "fn trapped_scc_with_edge_observer";
    let start = source
        .find(fn_marker)
        .expect("trapped_scc_with_edge_observer fn");
    let sig_end = source[start..]
        .find('{')
        .expect("trapped_scc_with_edge_observer body open");
    let signature = &source[start..start + sig_end];

    assert!(
        signature.contains("-> Option<Vec<usize>>"),
        "Tarjan must preserve the trapped SCC indexes instead of discarding them"
    );
    assert!(
        source.contains("component.sort_unstable();")
            && source.contains("self.trapped = Some(component);"),
        "the trapped SCC should be stable-sorted before it is reported"
    );
}

#[test]
fn governor_reacts_to_trapped_wait_cycle_detection() {
    // Pin: even though the report is just a bool, the
    // governor DOES react to detection by forcing a
    // DrainObligations suggestion. The detection drives
    // SCHEDULING behavior correctly; the gap is only in
    // human-readable observability.
    let source = read_three_lane_source();

    assert!(
        source.contains("if trapped_wait_cycle {")
            && source.contains("suggestion = SchedulingSuggestion::DrainObligations;"),
        "REGRESSION: the governor no longer forces \
         DrainObligations on trapped_wait_cycle detection. \
         Without this reaction, deadlock detection would be \
         purely informational — no scheduler-level response. \
         Re-add the forced DrainObligations.",
    );
}

#[test]
fn tarjan_implementation_remains_present() {
    // Pin: the Tarjan SCC algorithm is implemented in-place
    // (struct Tarjan + strongconnect method). A regression
    // that replaced Tarjan with a less-strict cycle detector
    // (e.g. simple DFS for self-loops only) would produce
    // false negatives — missing real deadlocks.
    let source = read_three_lane_source();

    assert!(
        source.contains("struct Tarjan<'a, F> {"),
        "REGRESSION: the Tarjan struct is gone. The deadlock \
         detector relies on Tarjan's algorithm to identify \
         SCCs in the wait graph; replacing it with a weaker \
         primitive could miss real cycles.",
    );

    assert!(
        source.contains("fn strongconnect(") || source.contains("strongconnect(v)"),
        "REGRESSION: the strongconnect method (Tarjan's \
         recursive SCC builder) is gone. Without it, the \
         wait-graph cycle detection collapses to a heuristic.",
    );
}

#[test]
fn deadlock_detection_doc_documents_the_observability_gap() {
    let source = read_three_lane_source();

    assert!(
        source.contains("wait_graph_signal_report_from_snapshot"),
        "the audit pin should track the enriched report path"
    );
}

#[test]
fn cycle_taskids_are_now_in_report() {
    let source = read_three_lane_source();

    assert!(source.contains("tasks: Vec<TaskId>,"));
    assert!(source.contains("let cycle_tasks: Vec<TaskId>"));
    assert!(source.contains("DeadlockCycleReport"));
}

#[test]
fn wait_cause_classification_has_structured_variants_and_unknown_fallback() {
    let source = read_three_lane_source();

    for token in [
        "enum WaitCause",
        "WaitCause::Lock",
        "WaitCause::Channel",
        "WaitCause::Notify",
        "WaitCause::Join",
        "WaitCause::Unknown",
        "cause: WaitCause",
    ] {
        assert!(source.contains(token), "missing wait-cause token {token}");
    }
}

#[test]
fn wait_location_field_is_serializable_and_optional() {
    let source = read_three_lane_source();

    for token in [
        "struct WaitLocation",
        "file: Option<&'static str>",
        "line: Option<u32>",
        "label: Option<&'static str>",
        "serde::Serialize",
    ] {
        assert!(
            source.contains(token),
            "missing wait-location token {token}"
        );
    }
}
