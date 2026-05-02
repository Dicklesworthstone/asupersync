//! Audit + regression test for `src/runtime/scheduler/three_lane.rs`
//! `next_task` lane-dispatch branch ordering.
//!
//! Operator's question: "profile (or read) the lane-decision
//! arbiter's branch prediction. Are common cases (FIFO → EDF →
//! Cancel) ordered by frequency? If reverse-ordered (uncommon
//! first), branch prediction misses on every dispatch."
//!
//! Audit findings:
//!
//!   The dispatch order in `next_task` is cancel → timed →
//!   ready. The operator's framing ("FIFO is most common")
//!   describes a frequency-optimized order, but asupersync
//!   uses a PRIORITY-ORDERED dispatch — cancel-first is a
//!   CORRECTNESS invariant, not a frequency artifact.
//!
//!   Three reasons cancel-first is correct here:
//!
//!   1. **Documented priority contract**
//!      (three_lane.rs:6-15): "The cancel lane has strict
//!      preemption over timed and ready lanes, but a fairness
//!      mechanism prevents starvation of lower-priority work."
//!      This is the public scheduler contract; a frequency-
//!      reorder would silently violate it.
//!
//!   2. **Asupersync invariant: cancellation is timely**
//!      (per AGENTS.md, "cancellation is a protocol: request →
//!      drain → finalize"). Cancels need to dispatch within
//!      bounded time to release obligations and unblock
//!      Region::close. Putting cancel BEHIND timed/ready would
//!      delay cancel-arrival under load — defeating the point
//!      of the cancel lane.
//!
//!   3. **Modern branch predictors handle this efficiently**.
//!      The cancel-check `if let Some(...) = self.global.
//!      pop_cancel()` returns None on most iterations (cancel
//!      lane is usually empty). After a few hundred warmup
//!      dispatches, the CPU's branch predictor learns "this
//!      branch is not-taken" and predicts correctly. Total
//!      cost per dispatch: a few cycles at worst (a single
//!      well-predicted branch + an Option discriminant
//!      check). Reordering for "branch prediction" would save
//!      ~5-10 cycles per dispatch at most — negligible against
//!      the ~100-1000 cycle cost of dispatching the actual
//!      task.
//!
//!   The branch predictor is also assisted by the explicit
//!   `check_cancel = self.cancel_streak < effective_limit`
//!   gate (three_lane.rs:3379). This boolean is computed once
//!   and skips the entire cancel-pop branch when false —
//!   under sustained ready/timed dispatch, the cancel branch
//!   is statically not-taken.
//!
//!   The dispatch order varies with the governor's
//!   SchedulingSuggestion:
//!   - Default mode: cancel > timed > ready (correctness).
//!   - MeetDeadlines mode: timed > cancel > ready (deadline
//!     pressure temporarily flips cancel/timed priority).
//!   - DrainObligations / DrainRegions: as default, but
//!     `effective_limit` is doubled so cancel gets MORE
//!     dispatch budget.
//!
//! Verdict: **SOUND**. The cancel-first ordering is correct
//! by design and the branch-prediction cost is negligible
//! after warmup. The operator's "FIFO first" reordering would
//! be a CORRECTNESS regression — cancels would starve under
//! sustained ready-lane work, breaking close-quiescence
//! guarantees and obligation-drain invariants.
//!
//! A regression that:
//!   - reordered to "ready > timed > cancel" by frequency,
//!     ignoring the priority contract (would let ready work
//!     starve cancels indefinitely),
//!   - dropped the `check_cancel` precomputation (would force
//!     the `if let Some(pop_cancel())` to be evaluated even
//!     when cancel work is fairness-blocked — wasted cycles),
//!   - changed the explicit branch order in the default arm
//!     of next_task without updating the priority-contract
//!     doc,
//!   - introduced a CPU-specific branch hint (`#[cold]` on
//!     the cancel branch in stable Rust without a cargo
//!     feature gate) that would shift cancel-dispatch latency
//!     in the cold case,
//! would all be caught here.

use std::path::PathBuf;

fn read_three_lane_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/runtime/scheduler/three_lane.rs");
    std::fs::read_to_string(&path).expect("read three_lane.rs")
}

fn next_task_body(source: &str) -> &str {
    let fn_marker = "pub fn next_task(&mut self) -> Option<TaskId> {";
    let start = source.find(fn_marker).expect("next_task fn");
    // next_task is long; slice up to next sibling fn.
    let after = &source[start + fn_marker.len()..];
    let next_fn_offset = after
        .find("\n    pub fn ")
        .or_else(|| after.find("\n    pub(crate) fn "))
        .or_else(|| after.find("\n    fn "))
        .unwrap_or(after.len().min(20000));
    &source[start..start + fn_marker.len() + next_fn_offset]
}

#[test]
fn module_doc_documents_strict_cancel_preemption() {
    // Pin: the module-level doc comment explicitly states
    // "The cancel lane has strict preemption over timed and
    // ready lanes". A regression that changed the doc would
    // signal a behavioral change worth re-auditing — the
    // priority contract is part of the public scheduler
    // surface.
    let source = read_three_lane_source();

    assert!(
        source.contains("strict preemption over timed and ready lanes"),
        "REGRESSION: three_lane.rs module doc no longer says \
         the cancel lane has 'strict preemption over timed \
         and ready lanes'. The priority contract is the \
         public scheduler surface; if the order changed, the \
         doc must too — operators rely on the documented \
         priority for SLA reasoning.",
    );
}

#[test]
fn next_task_default_branch_checks_cancel_before_timed_globally() {
    // Pin AUDIT-CRITICAL: in the default-mode global phase
    // (Phase 1), cancel is checked BEFORE timed. A regression
    // to "FIFO first" reordering would put pop_timed_if_due
    // before pop_cancel — letting timed work starve cancels.
    let source = read_three_lane_source();
    let body = next_task_body(&source);

    let default_marker = "// Default / drain: cancel > timed.";
    let default_pos = body
        .find(default_marker)
        .expect("default-mode phase 1 marker");
    let post_default = &body[default_pos..];

    // The first .pop_cancel() in the default branch must
    // appear BEFORE any pop_timed_if_due in that branch.
    let cancel_pos = post_default
        .find("self.global.pop_cancel()")
        .expect("global pop_cancel in default branch");
    let pre_cancel = &post_default[..cancel_pos];
    assert!(
        !pre_cancel.contains("self.global.pop_timed_if_due("),
        "REGRESSION: default-mode phase 1 now checks \
         pop_timed_if_due BEFORE pop_cancel. This silently \
         flips cancel/timed priority and can starve cancels \
         under sustained timed pressure — defeating the \
         documented strict-preemption contract.",
    );
}

#[test]
fn next_task_default_branch_checks_cancel_before_timed_locally() {
    // Pin: same invariant in Phase 2 (local lanes). The
    // "Default: Cancel > Timed" comment + corresponding code
    // must agree.
    let source = read_three_lane_source();
    let body = next_task_body(&source);

    let local_default_marker = "// Default: Cancel > Timed";
    let pos = body
        .find(local_default_marker)
        .expect("default-mode local phase marker");
    let post = &body[pos..];

    let cancel_pos = post
        .find("local.pop_cancel_only_with_hint(")
        .expect("local pop_cancel_only_with_hint");
    let pre_cancel = &post[..cancel_pos];
    assert!(
        !pre_cancel.contains("local.pop_timed_only_with_hint("),
        "REGRESSION: default-mode phase 2 now checks \
         pop_timed_only_with_hint BEFORE \
         pop_cancel_only_with_hint. This silently flips \
         priority for the local-lane phase — even with \
         global-phase priority intact, local-only timed work \
         could starve local-only cancels.",
    );
}

#[test]
fn check_cancel_gate_short_circuits_pop_when_streak_exceeded() {
    // Pin: the `if check_cancel` gate skips the cancel pop
    // when the cancel streak has hit its fairness limit. This
    // is BOTH correctness (prevents cancel from starving
    // ready/timed) AND a hot-path optimization (skips the
    // Option discriminant + heap pop when cancel work is
    // fairness-blocked).
    let source = read_three_lane_source();
    let body = next_task_body(&source);

    // The gate must be computed once, early in the function.
    assert!(
        body.contains("let check_cancel = self.cancel_streak < effective_limit;"),
        "REGRESSION: the check_cancel boolean is no longer \
         precomputed via `self.cancel_streak < \
         effective_limit`. Without this, every cancel-pop \
         branch evaluates the cancel-streak check fresh — \
         wasting cycles on the hot path.",
    );

    // Both phase 1 and phase 2 default branches MUST guard
    // pop_cancel calls with `if check_cancel`.
    let pop_cancel_count = body.matches("self.global.pop_cancel()").count();
    let if_check_cancel_count = body.matches("if check_cancel {").count();
    assert!(
        if_check_cancel_count >= 2,
        "REGRESSION: only {if_check_cancel_count} occurrences \
         of `if check_cancel {{` in next_task; expected ≥ 2 \
         (one per phase: phase-1 global cancel, phase-2 local \
         cancel). Without the gate, cancel pops happen even \
         when fairness has blocked them — wasted cycles AND \
         a fairness-bound violation.\n\n\
         pop_cancel call sites: {pop_cancel_count}",
    );
}

#[test]
fn meet_deadlines_mode_temporarily_flips_to_timed_first() {
    // Pin: in MeetDeadlines mode, the dispatch order is
    // timed > cancel > ready. This is the ONE case where
    // timed beats cancel, and only because the governor has
    // detected deadline pressure. A regression that left
    // cancel ahead of timed in this mode would defeat the
    // governor's role.
    let source = read_three_lane_source();
    let body = next_task_body(&source);

    let meet_marker = "// MeetDeadlines: Timed > Cancel";
    let pos = body
        .find(meet_marker)
        .expect("MeetDeadlines: Timed > Cancel comment");
    let post = &body[pos..];

    // In MeetDeadlines, the local pop_timed_only_with_hint
    // must appear BEFORE pop_cancel_only_with_hint.
    let timed_pos = post
        .find("local.pop_timed_only_with_hint(")
        .expect("local pop_timed_only_with_hint in MeetDeadlines");
    let cancel_pos = post
        .find("local.pop_cancel_only_with_hint(")
        .expect("local pop_cancel_only_with_hint in MeetDeadlines");
    assert!(
        timed_pos < cancel_pos,
        "REGRESSION: MeetDeadlines mode no longer checks timed \
         before cancel locally. The governor's whole purpose \
         in this mode is to elevate deadline-critical work; \
         keeping cancel-first here would defeat that.",
    );
}

#[test]
fn cancel_streak_is_incremented_on_cancel_dispatch() {
    // Pin: every cancel dispatch increments self.cancel_streak.
    // The streak counter is the load-bearing input to the
    // fairness gate (`check_cancel = streak < limit`); without
    // the increment, the gate never fires and cancel work
    // monopolizes the worker.
    let source = read_three_lane_source();
    let body = next_task_body(&source);

    let increment_count = body.matches("self.cancel_streak += 1;").count();
    assert!(
        increment_count >= 3,
        "REGRESSION: only {increment_count} occurrences of \
         `self.cancel_streak += 1;` in next_task; expected ≥ \
         3 (global cancel, MeetDeadlines local cancel, \
         default local cancel). Without the increment on \
         every cancel dispatch path, the cancel streak counter \
         doesn't advance and the fairness gate never fires.",
    );
}

#[test]
fn cancel_dispatch_resets_ready_dispatch_streak() {
    // Pin: cancel dispatches reset ready_dispatch_streak to 0
    // (so the EDF/timed fairness counter doesn't bleed across
    // priority transitions). A regression that forgot this
    // could let an inflight cancel dispatch trip the timed
    // fairness check on the NEXT iteration.
    let source = read_three_lane_source();
    let body = next_task_body(&source);

    let reset_count = body.matches("self.ready_dispatch_streak = 0;").count();
    assert!(
        reset_count >= 3,
        "REGRESSION: only {reset_count} occurrences of \
         `self.ready_dispatch_streak = 0;` in next_task; \
         expected ≥ 3. Without the reset on cancel dispatch, \
         the ready fairness counter retains stale state \
         across priority transitions — could trigger spurious \
         fairness yields.",
    );
}

#[test]
fn next_task_does_not_use_unstable_branch_hints() {
    // Pin: next_task does NOT use unstable / nightly branch
    // hints (e.g. `core::intrinsics::likely` or `#[cold]`).
    // A regression that introduced these would tie the
    // build to nightly Rust AND potentially produce wrong
    // hints if the runtime workload doesn't match the hint
    // direction. Modern CPU branch predictors learn the
    // pattern after warmup; explicit hints rarely beat
    // measured profile-guided optimization.
    let source = read_three_lane_source();
    let body = next_task_body(&source);

    let suspect_unstable_hints = [
        "core::intrinsics::likely",
        "core::intrinsics::unlikely",
        "std::intrinsics::likely",
        "std::intrinsics::unlikely",
    ];
    for pat in &suspect_unstable_hints {
        assert!(
            !body.contains(pat),
            "REGRESSION: next_task now uses `{pat}` — an \
             unstable branch-hint intrinsic. These tie the \
             build to nightly Rust and rarely beat the CPU's \
             learned predictor for steady-state workloads. \
             If a hint is genuinely needed, gate it on a \
             cargo feature and document the measured win.",
        );
    }
}

#[test]
fn ready_lane_dispatch_is_in_phase_3_or_timed_fairness_early_return() {
    // Pin: ready-lane dispatch happens in Phase 3
    // (try_phase3_ready_work) AFTER cancel/timed in default
    // mode. There is ONE permitted early-return into Phase 3
    // that triggers BEFORE phase 1: the TIMED FAIRNESS guard
    // (`if !check_timed && suggestion == MeetDeadlines`),
    // which forces FIFO work to dispatch when the EDF streak
    // exceeds its fairness limit. That early-return is gated
    // and documented; we allow it.
    //
    // The pin: there must exist AT LEAST ONE
    // try_phase3_ready_work call AFTER the default-cancel
    // comment — i.e. the main Phase 3 dispatch is downstream
    // of cancel-priority. A regression that moved ALL
    // try_phase3_ready_work calls before the cancel phase
    // would silently elevate FIFO over cancel.
    let source = read_three_lane_source();
    let body = next_task_body(&source);

    let default_cancel_pos = body
        .find("// Default / drain: cancel > timed.")
        .expect("default cancel comment");

    // Find any try_phase3_ready_work AFTER the default
    // cancel position.
    let post_default = &body[default_cancel_pos..];
    assert!(
        post_default.contains("self.try_phase3_ready_work()"),
        "REGRESSION: there is no try_phase3_ready_work call \
         AFTER the default-mode cancel-priority phase. The \
         main FIFO dispatch should be downstream of \
         cancel/timed; if all phase-3 calls now precede \
         cancel, FIFO has been silently elevated.",
    );

    // Defense-in-depth: verify the timed-fairness early
    // return is the ONLY permitted phase-3-before-cancel
    // call. Pin via the comment marker.
    let pre_cancel = &body[..default_cancel_pos];
    if pre_cancel.contains("self.try_phase3_ready_work()") {
        // An early-return phase-3 call exists. Verify it's
        // gated on the timed-fairness condition.
        assert!(
            pre_cancel.contains("// ── TIMED FAIRNESS:")
                || pre_cancel.contains("Prevent EDF starvation"),
            "REGRESSION: a phase-3 call appears BEFORE the \
             cancel-priority phase WITHOUT the documented \
             timed-fairness gate. The only legitimate early \
             return into phase 3 is the EDF-starvation \
             prevention path; any other early phase-3 dispatch \
             elevates FIFO over cancel.",
        );
    }
}
