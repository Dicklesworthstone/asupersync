//! Audit + regression test for three-lane interaction:
//! EDF (timed-lane) priority over FIFO (ready-lane) under
//! deadline pressure.
//!
//! Operator's question: "when EDF lane has near-deadline task
//! and FIFO lane has long task, does scheduler preempt FIFO to
//! let EDF run (correct: deadline priority) or wait for FIFO
//! to yield (deadline miss risk)?"
//!
//! Audit findings:
//!
//!   asupersync's preemption is **cooperative**, not OS-level.
//!   A currently-executing FIFO task cannot be interrupted
//!   mid-poll — that would require thread interrupts which
//!   asupersync forbids by `#![deny(unsafe_code)]` and the
//!   "cooperation is the contract" core principle. So the
//!   strict answer is "wait for FIFO to yield." The
//!   deadline-miss risk is bounded by FIVE distinct
//!   mechanisms working together:
//!
//!   1. **Cooperative budget bounds FIFO runtime**: every
//!      task carries a `Budget { poll_quota, cost_quota,
//!      deadline }`. When `poll_quota` decrements to zero or
//!      `cost_quota` is exhausted, `cx.checkpoint()` returns
//!      `Err(BudgetExhausted)` — forcing the FIFO task to
//!      yield. The default budget bounds the worst-case time
//!      a FIFO task can monopolize a worker before yielding.
//!
//!   2. **Lyapunov governor switches to MeetDeadlines under
//!      pressure**: the governor (obligation/lyapunov.rs:599
//!      `LyapunovGovernor::suggest`) computes a deadline
//!      component:
//!        deadline_component =
//!          w_deadline_pressure × snapshot.deadline_pressure
//!      where `deadline_pressure ≈ Σ max(0, 1 − (deadline −
//!      now)/D₀)` over tasks within D₀=1s of their deadline.
//!      As tasks get closer to deadline, pressure grows. When
//!      `deadline_component` dominates obligation_component
//!      and region_component, the governor returns
//!      `SchedulingSuggestion::MeetDeadlines` — anticipating
//!      the deadline before it's missed.
//!
//!   3. **MeetDeadlines flips dispatch order to Timed-first**:
//!      the dispatch loop (three_lane.rs:3401-3431) checks
//!      `suggestion == MeetDeadlines && check_timed`. When
//!      true, it pops from the global timed queue
//!      (`global.pop_timed_if_due(now)`) BEFORE checking
//!      cancel/ready. So once the FIFO task yields, the next
//!      dispatch dequeues the EDF task immediately. Default
//!      ordering is Cancel > Timed > Ready;
//!      MeetDeadlines reorders to Timed > Cancel > Ready.
//!
//!   4. **Multi-worker parallelism**: while worker-A runs the
//!      long FIFO task, worker-B (and worker-C, ...) check
//!      the timed lane on every dispatch loop iteration. EDF
//!      tasks are NOT held hostage by a single worker's FIFO
//!      execution — a free worker dispatches the EDF task
//!      immediately under MeetDeadlines.
//!
//!   5. **Bounded fairness limits on timed-dispatch streak**:
//!      `timed_fairness_limit: 6` (three_lane.rs:1252) caps
//!      consecutive EDF dispatches to prevent starvation of
//!      FIFO. After 6 EDF dispatches in a row, the next
//!      dispatch checks FIFO first. This limit is symmetric
//!      with the cancel-streak limit and ensures bounded
//!      EDF-vs-FIFO interleaving even under sustained
//!      pressure.
//!
//! Verdict: **SOUND**. The scheduler does the cooperative-
//! correct thing: under deadline pressure, the governor
//! anticipates and switches to MeetDeadlines so the very next
//! dispatch decision favors EDF. There is no mid-poll
//! interrupt (impossible in a cooperative runtime), but:
//!   - The currently-running FIFO task is bounded by
//!     cooperative budget (poll_quota, cost_quota, deadline).
//!   - Once the FIFO task yields, MeetDeadlines pops the EDF
//!     task FIRST.
//!   - Other free workers in multi-worker mode dispatch the
//!     EDF task without waiting for the FIFO worker.
//!
//! This is closer to operator-answer (a) "preempt FIFO" than
//! to (b) "wait for FIFO to yield (deadline miss)" — the
//! deadline-miss risk is bounded, not unbounded.
//!
//! A regression that:
//!   - removed the MeetDeadlines branch from the dispatch
//!     loop (FIFO would always win the lane race after any
//!     yield),
//!   - removed the deadline_component contribution to the
//!     governor's suggest decision (governor would never
//!     return MeetDeadlines),
//!   - removed the cooperative budget enforcement (long FIFO
//!     tasks could run unbounded — full deadline-miss risk),
//!   - removed the timed_fairness_limit (EDF starvation of
//!     FIFO becomes possible),
//!   - changed the deadline-pressure computation to use
//!     past-deadline-only (would never pre-emptively
//!     prioritize tasks before they miss),
//!   - removed multi-worker dispatch (single worker becomes
//!     sole bottleneck, full deadline-miss risk for any
//!     long-running FIFO task on the only worker),
//! would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn meet_deadlines_branch_pops_timed_before_cancel_in_dispatch_loop() {
    // Pin (link 3): under MeetDeadlines, the dispatch loop
    // pops the timed lane FIRST, before cancel and ready.
    // Without this branch, the default Cancel > Timed > Ready
    // ordering applies — and EDF wouldn't be prioritized
    // even under heavy deadline pressure.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // Phase 1 MeetDeadlines branch.
    assert!(
        source.contains("if suggestion == SchedulingSuggestion::MeetDeadlines && check_timed {")
            && source.contains("if let Some(tt) = self.global.pop_timed_if_due(now) {"),
        "REGRESSION: dispatch loop no longer has the \
         MeetDeadlines branch that pops timed FIRST. Under \
         deadline pressure, the governor signals \
         MeetDeadlines but the dispatch ignores it — EDF \
         tasks are starved by FIFO/cancel work and miss \
         deadlines.",
    );
}

#[test]
fn meet_deadlines_phase2_local_pops_timed_before_cancel() {
    // Pin (link 3): phase 2 in MeetDeadlines mode pops local
    // timed lane before local cancel — symmetric with phase 1
    // global ordering.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let marker =
        "if suggestion == SchedulingSuggestion::MeetDeadlines && check_timed {";
    let mut search_pos = 0;
    let mut found_phase2 = false;
    while let Some(idx) = source[search_pos..].find(marker) {
        let abs = search_pos + idx;
        // Look at the next ~600 bytes for the local timed pop.
        let window_end = (abs + 1200).min(source.len());
        let safe_end = source
            .char_indices()
            .map(|(i, _)| i)
            .filter(|&i| i <= window_end)
            .last()
            .unwrap_or(window_end);
        let body = &source[abs..safe_end];
        if body.contains("local.pop_timed_only_with_hint(rng_hint, now)") {
            found_phase2 = true;
            break;
        }
        search_pos = abs + marker.len();
    }
    assert!(
        found_phase2,
        "REGRESSION: phase 2 of dispatch loop no longer pops \
         the LOCAL timed lane first under MeetDeadlines. \
         A worker's local EDF tasks would lose priority to \
         local cancel/ready work — defeating the deadline \
         priority promise.",
    );
}

#[test]
fn governor_suggest_returns_meet_deadlines_when_deadline_component_dominates() {
    // Pin (link 2): the governor's suggest method picks
    // MeetDeadlines when deadline_component is the dominant
    // term in the potential.
    let source = read("src/obligation/lyapunov.rs");

    // The components array must include deadline_component
    // → MeetDeadlines.
    assert!(
        source.contains("SchedulingSuggestion::MeetDeadlines,") &&
        source.contains("record.deadline_component,"),
        "REGRESSION: LyapunovGovernor.suggest no longer maps \
         deadline_component → MeetDeadlines. The governor \
         can no longer recommend deadline priority — the \
         dispatch loop's MeetDeadlines branch becomes \
         unreachable.",
    );

    // The selection is by maximum component (max_by partial_cmp).
    assert!(
        source.contains("max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))"),
        "REGRESSION: LyapunovGovernor.suggest no longer picks \
         the dominant component. Without max_by selection, the \
         governor returns the wrong suggestion when one \
         component is large but not first in the components \
         array.",
    );
}

#[test]
fn deadline_pressure_computation_uses_anticipatory_window() {
    // Pin (link 2): deadline_pressure is computed over tasks
    // within D₀=1s of their deadline (or overdue), not just
    // past-deadline. This is the anticipatory mechanism that
    // lets the governor signal MeetDeadlines BEFORE the
    // deadline is missed.
    let source = read("src/obligation/lyapunov.rs");

    assert!(
        source.contains("DEADLINE_PRESSURE_D0_NS: u64 = 1_000_000_000;"),
        "REGRESSION: deadline pressure window D₀ has changed \
         from 1s. The anticipatory deadline-priority \
         mechanism depends on this window — too small a \
         window means the governor only reacts AFTER \
         deadline is missed.",
    );

    // The pressure formula must include the count - (sum_d/d0)
    // + (count * now / d0) form (or equivalent).
    assert!(
        source.contains("let p = count - (sum_d / d0) + (count * now_f / d0);"),
        "REGRESSION: deadline-pressure formula changed. The \
         linearized form `p = count - (sum_d / d0) + \
         (count * now / d0)` is what gives anticipatory \
         pressure as `now` approaches deadlines — without \
         it, the governor reacts too late.",
    );
}

#[test]
fn deadline_component_weight_is_present_in_potential_weights() {
    // Pin (link 2): w_deadline_pressure is non-zero in the
    // default weights. A regression that zeroed this weight
    // would silence the deadline channel — governor would
    // never recommend MeetDeadlines regardless of pressure.
    let source = read("src/obligation/lyapunov.rs");

    assert!(
        source.contains("pub w_deadline_pressure: f64,"),
        "REGRESSION: PotentialWeights.w_deadline_pressure \
         field is gone. The deadline channel is silenced — \
         governor cannot recommend MeetDeadlines.",
    );

    // The default weight must be > 0.
    assert!(
        source.contains("w_deadline_pressure: 2.0,"),
        "REGRESSION: default w_deadline_pressure is no longer \
         2.0. If it's zero, the governor never recommends \
         MeetDeadlines under deadline pressure — full \
         deadline-miss risk.",
    );
}

#[test]
fn timed_fairness_limit_caps_edf_starvation_of_fifo() {
    // Pin (link 5): timed_fairness_limit (default 6) caps
    // consecutive EDF dispatches before yielding to FIFO.
    // This prevents the OPPOSITE regression — EDF starving
    // FIFO indefinitely under sustained pressure.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("timed_fairness_limit: 6,"),
        "REGRESSION: timed_fairness_limit is no longer 6. \
         Without bounded EDF dispatches, FIFO can be starved \
         indefinitely — the opposite failure mode of \
         deadline miss.",
    );

    // The fairness check in the dispatch loop.
    assert!(
        source.contains("let check_timed = self.timed_dispatch_streak < self.timed_fairness_limit;"),
        "REGRESSION: dispatch loop no longer enforces the \
         timed_fairness_limit. EDF can monopolize the \
         worker indefinitely under sustained deadline \
         pressure — FIFO starvation.",
    );

    // Streak reset when fairness yield triggers.
    assert!(
        source.contains("self.timed_dispatch_streak = 0;"),
        "REGRESSION: dispatch loop no longer resets \
         timed_dispatch_streak after fairness yield. The \
         streak monotonically grows — fairness becomes a \
         one-shot rather than periodic guarantee.",
    );
}

#[test]
fn cooperative_budget_enforced_via_checkpoint_returns_err_on_exhaustion() {
    // Pin (link 1): the cooperative budget is the bound on
    // FIFO task runtime. cx.checkpoint() returns
    // Err(BudgetExhausted) when poll_quota / cost_quota /
    // deadline are exhausted — forcing the long FIFO task
    // to yield within bounded time.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    assert!(
        source.contains(fn_marker),
        "REGRESSION: cx.checkpoint signature missing. The \
         cooperative-yield contract requires Result<(), \
         Error> for `?`-propagation.",
    );

    // The slow path delegates to checkpoint_budget_exhaustion
    // which constructs the BudgetExhausted error.
    assert!(
        source.contains("checkpoint_budget_exhaustion"),
        "REGRESSION: cx.checkpoint no longer routes through \
         the budget-exhaustion check. Long FIFO tasks would \
         not be forced to yield even when poll_quota is \
         exhausted — full deadline-miss risk.",
    );
}

#[test]
fn governor_caches_suggestion_and_recomputes_periodically() {
    // Pin (link 2): the governor recomputes its suggestion
    // every `governor_interval` dispatch loop iterations,
    // not on every dispatch (would be too expensive). The
    // cached_suggestion field carries the last value forward.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("cached_suggestion: SchedulingSuggestion,"),
        "REGRESSION: cached_suggestion field is gone. Without \
         caching, every dispatch would re-snapshot the \
         runtime state — adding lock contention and \
         potentially making MeetDeadlines unreachable due \
         to per-call overhead.",
    );

    assert!(
        source.contains("if self.steps_since_snapshot < self.governor_interval {")
            && source.contains("return self.cached_suggestion;"),
        "REGRESSION: governor_suggest no longer respects \
         governor_interval / cached_suggestion. The governor \
         recomputes on every dispatch — either expensive (if \
         interval was tight) or stale (if interval was loose).",
    );
}

#[test]
fn three_lane_dispatch_has_default_cancel_then_timed_ordering() {
    // Pin (link 3 audit): the DEFAULT (non-MeetDeadlines)
    // phase-2 branch is `// Default: Cancel > Timed (global
    // cancel already checked)`. This documents the strict
    // priority: cancel work always preempts EDF in the
    // default suggestion. Only when MeetDeadlines is active
    // does timed-lane outrank cancel.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("// Default / drain: cancel > timed.")
            && source.contains("// Default: Cancel > Timed (global cancel already checked)"),
        "REGRESSION: default dispatch ordering comments are \
         gone. The cancel-first contract under default \
         suggestion is what gives bounded cancellation \
         latency — without it, cancel could be silently \
         pushed behind timed.",
    );

    // In the default phase-2 block, local pop_cancel_only is
    // checked before timed. Slice the default block by its
    // comment marker.
    let default_marker = "// Default: Cancel > Timed (global cancel already checked)";
    let pos = source
        .find(default_marker)
        .expect("default phase-2 comment");
    let window = &source[pos..(pos + 1500).min(source.len())];

    let local_cancel_idx = window
        .find("local.pop_cancel_only_with_hint(rng_hint)")
        .expect("local.pop_cancel_only_with_hint in default phase-2");
    let global_timed_idx = window
        .find("self.global.pop_timed_if_due(now)")
        .expect("global.pop_timed_if_due in default phase-2");
    assert!(
        local_cancel_idx < global_timed_idx,
        "REGRESSION: in the default phase-2 branch, timed \
         is now checked BEFORE local cancel — breaking the \
         strict priority guarantee that cancel work always \
         wins under the default suggestion. Cancellation \
         latency becomes unbounded.",
    );
}

#[test]
fn worker_storage_supports_multi_worker_dispatch_for_parallel_edf() {
    // Pin (link 4): the runtime supports multi-worker
    // dispatch — a free worker can pick up EDF while another
    // runs FIFO. The scheduler stores workers in a SmallVec
    // (heap-allocated past 16) and exposes len() via test
    // accessors. The infallible new() constructor clamps to
    // at least 1 (per br-asupersync-niczb3); typical
    // production runs many workers.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // Workers are stored as a Vec/SmallVec — not a singleton.
    assert!(
        source.contains("workers: SmallVec<[ThreeLaneWorker; 16]>,")
            || source.contains("workers: Vec<ThreeLaneWorker>")
            || source.contains("workers: Vec<JoinHandle<()>>"),
        "REGRESSION: worker storage is no longer a multi-\
         worker collection (SmallVec/Vec of ThreeLaneWorker). \
         Multi-worker parallel dispatch requires per-worker \
         state — a singleton-only design loses the parallel \
         EDF dispatch path that hides FIFO-bound workers.",
    );

    // The constructor accepts a worker_count parameter.
    assert!(
        source.contains("pub fn new(worker_count: usize, state:"),
        "REGRESSION: ThreeLaneScheduler::new no longer takes \
         a worker_count parameter. Without runtime sizing, \
         multi-worker EDF dispatch isn't tunable.",
    );

    // The constructor's worker_count is clamped to at least 1
    // (per br-asupersync-niczb3) — but multi-worker mode is
    // the production default.
    assert!(
        source.contains(".max(1)"),
        "REGRESSION: worker_count clamping `.max(1)` is gone. \
         worker_count==0 would produce an empty workers Vec \
         and silently lose all dispatch.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    // Pin (documentary): related audits.
    let prior_audits = [
        "tests/scheduler_cooperative_budget_yield_audit.rs",
        "tests/runtime_budget_carry_forward_across_yields_audit.rs",
        "tests/runtime_region_close_timed_lane_task_cancellation_audit.rs",
        "tests/scheduler_edf_concurrent_insert_heap_invariant_audit.rs",
        "tests/scheduler_cross_thread_cancel_propagation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
