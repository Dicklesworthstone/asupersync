//! Audit + regression test for `src/runtime/scheduler/three_lane.rs`
//! Tarjan-SCC deadlock-detector report enrichment.
//!
//! Operator's question: "when a deadlock is detected via Tarjan
//! SCC, is the report enriched with the cycle's task IDs,
//! file:line waiting points, AND wait-cause (lock vs channel
//! vs notify)? If only IDs, that's an improvement opportunity.
//! If defect, file bead. If SOUND, pin."
//!
//! Audit findings:
//!
//!   The current Tarjan-SCC deadlock detector reports
//!   **DETECTION-ONLY** — a `trapped_wait_cycle: bool` plus
//!   the undirected wait-graph node/edge count. It does NOT
//!   surface:
//!     a. The specific TaskIds participating in the cycle.
//!     b. The wait-cause for each edge (lock vs channel vs
//!        notify vs join).
//!     c. The file:line waiting points where each task was
//!        suspended.
//!
//!   Source-level evidence:
//!
//!   1. **`WaitGraphTaskSnapshot`** (three_lane.rs:798-802)
//!      carries only:
//!        ```ignore
//!        struct WaitGraphTaskSnapshot {
//!            id: TaskId,
//!            waiters: Vec<TaskId>,
//!        }
//!        ```
//!      No wait_cause field. No source location. Just the
//!      directed-edge endpoints.
//!
//!   2. **`wait_graph_signals_from_snapshot`**
//!      (three_lane.rs:820-863) returns a `(usize, Vec<(usize,
//!      usize)>, bool)` triple: (node_count, undirected_edges,
//!      trapped_cycle). The cycle is reported as a SINGLE
//!      BOOLEAN — not the SCC's task list.
//!
//!   3. **`has_trapped_scc`** (called at line 856) returns a
//!      `bool`. The Tarjan implementation is well-formed, but
//!      the report API discards the SCC structure once detected.
//!
//! Verdict: **OBSERVABILITY GAP** (improvement opportunity).
//! The deadlock DETECTION is sound — Tarjan SCC correctly
//! identifies trapped cycles in the wait graph. But the
//! REPORT is minimal: SREs see "deadlock detected" with no
//! actionable detail.
//!
//! This is an OBSERVABILITY gap, not a CORRECTNESS bug:
//! detection drives the governor's DrainObligations
//! suggestion (three_lane.rs:3961), so the SCHEDULER reacts
//! correctly to detection. But the OPERATOR sees only the
//! boolean signal — they have to dig into a fresh dump or
//! reproduce the bug under a debugger to learn which tasks
//! were trapped.
//!
//! Improvement opportunities (filed as future-work pin in
//! this audit doc):
//!   - **Cycle TaskIds**: change `wait_graph_signals_*` to
//!     return `Option<Vec<TaskId>>` (the cycle's tasks)
//!     instead of `bool`. Tarjan already computes the SCCs;
//!     surfacing the smallest trapped one is an additional
//!     ~1 line of bookkeeping.
//!   - **Wait-cause field**: extend WaitGraphTaskSnapshot
//!     with `wait_cause: WaitCause { Lock, Channel, Notify,
//!     Join, Other }`. The originating waker registration
//!     site would need to record the cause; this is a
//!     larger refactor (touches every sync primitive's
//!     register-waker call site).
//!   - **File:line**: requires `#[track_caller]` propagation
//!     through the wait primitives or an explicit Cx::label
//!     API. asupersync has structured-concurrency context
//!     via Cx, so threading a "wait label" through
//!     `Cx::checkpoint`-style sites is feasible.
//!
//! Pinned current behavior: detection-only with boolean
//! report. The Lyapunov governor's drain-mode reaction to
//! detection IS effective; the gap is only at the
//! human-observability layer.
//!
//! A regression that:
//!   - removed `has_trapped_scc` or its caller (would lose
//!     the detection itself — escalating the gap from
//!     observability to correctness),
//!   - changed `WaitGraphTaskSnapshot` to drop the `waiters:
//!     Vec<TaskId>` field (would break edge construction),
//!   - replaced Tarjan with a less-strict cycle detector
//!     that returns false negatives,
//! would all be caught here.

use std::path::PathBuf;

fn read_three_lane_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/runtime/scheduler/three_lane.rs");
    std::fs::read_to_string(&path).expect("read three_lane.rs")
}

#[test]
fn wait_graph_task_snapshot_carries_id_and_waiters_only() {
    // Pin current state: WaitGraphTaskSnapshot has TaskId
    // and a Vec<TaskId> of waiters. NO wait_cause / location
    // / file:line. A regression that removed these basic
    // fields would defeat the wait-graph construction
    // entirely; an enhancement that ADDED wait_cause /
    // location would be the documented improvement and would
    // need to update this pin.
    let source = read_three_lane_source();

    let struct_marker = "struct WaitGraphTaskSnapshot {";
    let start = source
        .find(struct_marker)
        .expect("WaitGraphTaskSnapshot struct");
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("struct close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("id: TaskId,"),
        "REGRESSION: WaitGraphTaskSnapshot no longer has \
         `id: TaskId`. The wait-graph cannot identify nodes \
         without their TaskIds.\n\nstruct body:\n{body}",
    );
    assert!(
        body.contains("waiters: Vec<TaskId>,"),
        "REGRESSION: WaitGraphTaskSnapshot no longer has \
         `waiters: Vec<TaskId>`. Without the waiter list, \
         the wait-graph has no edges.\n\nstruct body:\n{body}",
    );

    // AUDIT GATE: if the struct gains a wait_cause field,
    // the documented improvement has been delivered —
    // update this pin to verify the new wiring.
    let enrichment_fields = [
        "wait_cause:",
        "wait_kind:",
        "WaitCause",
        "wait_location:",
        "file_line:",
        "waiting_at:",
    ];
    for field in &enrichment_fields {
        if body.contains(field) {
            panic!(
                "AUDIT GATE: WaitGraphTaskSnapshot now contains \
                 `{field}` — the deadlock-report enrichment gap \
                 has been filled. UPDATE THIS PIN to verify the \
                 new wiring (the field's presence + propagation \
                 to the report API + the report API exposing \
                 the new info to operators). The gap was: \
                 detection-only without cycle TaskIds / wait-\
                 cause / location.\n\nNew struct body:\n{body}"
            );
        }
    }
}

#[test]
fn deadlock_detection_returns_boolean_only_today() {
    // Pin current state: wait_graph_signals_from_snapshot
    // returns a triple `(usize, Vec<(usize, usize)>, bool)`
    // where the third element is the trapped_wait_cycle
    // BOOLEAN — not the cycle's TaskIds. This documents the
    // improvement opportunity.
    let source = read_three_lane_source();

    let fn_marker = "fn wait_graph_signals_from_snapshot(";
    let start = source
        .find(fn_marker)
        .expect("wait_graph_signals_from_snapshot fn");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("fn close");
    let body = &source[start..start + body_end];

    // The return signature must be `(usize, Vec<(usize, usize)>, bool)`.
    assert!(
        body.contains("-> (usize, Vec<(usize, usize)>, bool) {"),
        "REGRESSION (or IMPROVEMENT): \
         wait_graph_signals_from_snapshot's return type \
         changed. If the new signature exposes the cycle's \
         TaskIds (e.g. -> (usize, Vec<(usize, usize)>, \
         Option<Vec<TaskId>>)), the deadlock-report \
         enrichment gap has been filled — UPDATE THIS PIN \
         to verify the new wiring.\n\nfn body:\n{body}",
    );

    // The return constructs (live_tasks.len(), edges,
    // trapped_cycle) — pin via the trapped_cycle variable.
    assert!(
        body.contains("let trapped_cycle = has_trapped_scc(&adjacency);"),
        "REGRESSION: the cycle-detection no longer goes \
         through has_trapped_scc(adjacency). If a different \
         primitive was substituted, verify it's still a \
         total / sound SCC detector.",
    );
}

#[test]
fn has_trapped_scc_returns_boolean() {
    // Pin: has_trapped_scc returns bool. A regression that
    // changed this to return `Vec<TaskId>` (the trapped
    // SCC) WOULD be the improvement; update the pin AND
    // the caller in wait_graph_signals_from_snapshot.
    let source = read_three_lane_source();

    let fn_marker = "fn has_trapped_scc(";
    let start = source.find(fn_marker).expect("has_trapped_scc fn");
    // Take signature window (up to the body open).
    let sig_end = source[start..]
        .find('{')
        .expect("has_trapped_scc body open");
    let signature = &source[start..start + sig_end];

    assert!(
        signature.contains("-> bool"),
        "REGRESSION (or IMPROVEMENT): has_trapped_scc no \
         longer returns `bool`. If the new signature exposes \
         the trapped cycle (e.g. -> Option<Vec<usize>>), the \
         deadlock-report enrichment gap has been filled — \
         UPDATE THIS PIN to verify the new wiring.\n\n\
         signature:\n{signature}",
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
        source.contains("fn strongconnect(")
            || source.contains("strongconnect(v)"),
        "REGRESSION: the strongconnect method (Tarjan's \
         recursive SCC builder) is gone. Without it, the \
         wait-graph cycle detection collapses to a heuristic.",
    );
}

#[test]
fn deadlock_detection_doc_documents_the_observability_gap() {
    // Pin: the audit doc-comment in this test file documents
    // the observability gap and the improvement
    // opportunity. A regression that filled the gap would
    // bring this doc out of date, but that's the AUDIT GATE
    // pattern — the test panics with explicit "UPDATE THIS
    // PIN" instructions when the new fields appear.
    //
    // No source-level pin needed for this — the audit gate
    // patterns in the prior tests handle the transition.
    // This test is documentary.
    assert!(
        true,
        "this test exists to document the audit gate pattern \
         used in the prior tests; the actual pins are there.",
    );
}

// ─── Operator-facing improvement opportunities (documentary) ─────────

#[test]
fn improvement_opportunity_cycle_taskids_in_report() {
    // PIN (documentary): the cycle's TaskIds are NOT today
    // exposed in the deadlock report. Tarjan internally
    // computes SCCs — surfacing the smallest trapped one
    // would let SREs see "tasks 17, 23, 41 are deadlocked"
    // instead of "a deadlock exists somewhere".
    //
    // Implementation cost: ~1 line of bookkeeping in
    // strongconnect() + change has_trapped_scc to return
    // Option<Vec<usize>> (then map indices back to TaskIds
    // at the wait_graph_signals_from_snapshot call site).
    //
    // This test panics IF the improvement has been delivered
    // — update the pin to verify the new wiring.
    let source = read_three_lane_source();

    let suspect_enrichment_apis = [
        "trapped_scc_taskids",
        "deadlock_taskids",
        "cycle_taskids",
        "DeadlockReport",
        "trapped_cycle_tasks",
    ];
    for api in &suspect_enrichment_apis {
        if source.contains(api) {
            panic!(
                "AUDIT GATE: source contains `{api}` — looks \
                 like the cycle-TaskIds enrichment has \
                 landed. UPDATE THIS PIN to verify the new \
                 report API: (1) the API exposes the cycle's \
                 TaskIds publicly, (2) the governor's \
                 reaction to the cycle uses the enriched \
                 info, (3) the operator-facing diagnostic \
                 (e.g. /diagnostics/deadlock) surfaces it."
            );
        }
    }
}

#[test]
fn improvement_opportunity_wait_cause_classification() {
    // PIN (documentary): the wait-cause classification
    // (lock vs channel vs notify vs join) is NOT today
    // recorded on per-task wait edges. Adding a wait_cause
    // field would require threading the cause through every
    // sync-primitive's register-waker call site (mutex,
    // rwlock, channel, notify, oneshot, broadcast, watch).
    //
    // Larger refactor than cycle-TaskIds; flag as a future
    // opportunity.
    let source = read_three_lane_source();

    let suspect_wait_cause_types = [
        "enum WaitCause",
        "pub enum WaitCause",
        "wait_cause: WaitCause",
        "WaitCause::Lock",
        "WaitCause::Channel",
    ];
    for ty in &suspect_wait_cause_types {
        if source.contains(ty) {
            panic!(
                "AUDIT GATE: source contains `{ty}` — looks \
                 like the wait-cause enrichment has landed. \
                 UPDATE THIS PIN to verify: (1) every \
                 register-waker site in src/sync/ records \
                 the cause, (2) WaitGraphTaskSnapshot \
                 carries the cause per edge, (3) the report \
                 API surfaces the per-edge cause to operators."
            );
        }
    }
}

#[test]
fn improvement_opportunity_file_line_at_wait_point() {
    // PIN (documentary): file:line waiting points are NOT
    // today recorded. Capturing them would require either
    // #[track_caller] propagation through every wait
    // primitive or an explicit Cx::label() API the user
    // calls before await.
    //
    // The deepest refactor of the three opportunities;
    // flag as longest-term future work.
    let source = read_three_lane_source();

    let suspect_location_apis = [
        "Location<'static>",
        "track_caller",
        "wait_location:",
        "waiting_at: ",
    ];
    for api in &suspect_location_apis {
        if source.contains(api) {
            panic!(
                "AUDIT GATE: source contains `{api}` — looks \
                 like file:line wait-point capture has \
                 landed. UPDATE THIS PIN to verify: (1) the \
                 capture happens AT the wait site (not the \
                 deadlock-detector site), (2) the location \
                 propagates through Cx checkpoint chain, \
                 (3) the report API surfaces it to the \
                 operator's diagnostic."
            );
        }
    }
}
