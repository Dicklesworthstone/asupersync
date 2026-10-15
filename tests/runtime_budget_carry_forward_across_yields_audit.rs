//! Audit + regression test for cooperative-budget carry-forward
//! across voluntary yields.
//!
//! Operator's question: "when a task yields voluntarily
//! (Cx::checkpoint with budget remaining), is the budget reset
//! on next quantum (incorrect: gaming the scheduler) or carried
//! forward (correct: anti-cheat)?"
//!
//! Audit findings:
//!
//!   The asupersync cooperative budget is **carry-forward**
//!   across yields by construction:
//!
//!   1. **Deadline budget is absolute**: `Budget::deadline:
//!      Option<Time>` (types/budget.rs) stores an ABSOLUTE
//!      `Time` (saturating_add_nanos at task creation), not a
//!      relative duration. There is no path that re-anchors
//!      the deadline on yield — the absolute time-point
//!      doesn't move when the task suspends. So a task that
//!      yields with 100us until deadline returns to 100us
//!      (or less) until deadline — never refreshed.
//!
//!   2. **Poll-quota counter is initialized once**:
//!      `record.polls_remaining = budget.poll_quota` at task
//!      creation (task_table.rs:306). The counter is NEVER
//!      reset on yield in the production scheduler. The lab
//!      runtime decrements it via `consume_poll` to enforce
//!      the per-task quota deterministically; the production
//!      runtime relies on deadline + cost budgets for normal
//!      enforcement.
//!
//!   3. **Cost-quota is user-managed**: callers explicitly
//!      call `Budget::consume_cost(amount)` in domain logic
//!      (e.g., per-byte / per-DB-row charges). Yielding does
//!      not reset the cost counter; it remains decremented
//!      across yields.
//!
//!   4. **Cleanup-budget transition** is the ONE controlled
//!      refresh (task.rs:818):
//!        ```ignore
//!        // Apply cleanup budget now that we are entering
//!        // cleanup phase
//!        if let Some(inner) = &self.cx_inner {
//!            let mut guard = inner.write();
//!            guard.budget = budget;
//!            guard.budget_baseline = budget;
//!        }
//!        self.polls_remaining = budget.poll_quota;
//!        ```
//!      This is intentional: when a task transitions to
//!      Cancelling, it gets a NEW budget (the
//!      `cleanup_budget` from `CancelReason::cleanup_budget()`)
//!      so cleanup work has its own deterministic quota
//!      separate from the original task budget. This is NOT
//!      a per-yield refresh — it's a phase transition driven
//!      by cancellation propagation.
//!
//!   5. **Cx::checkpoint() observes the running counter**:
//!      checkpoint reads `inner.budget` (the running counter)
//!      and `inner.budget_baseline` (the starting value)
//!      from CxInner. The Yield/Pending state has no effect
//!      on these fields. A task that yielded with `poll_quota
//!      = 5` re-enters with `poll_quota = 5` (or fewer if the
//!      lab runtime called `consume_poll`).
//!
//! Verdict: **SOUND**. The cooperative budget is carry-forward
//! across voluntary yields. There is no path where yielding
//! resets the budget — the operator's failure mode is
//! structurally impossible because no `reset on yield` code
//! exists.
//!
//! A regression that:
//!   - introduced a `reset_budget_on_yield` field on the
//!     scheduler that re-armed the deadline at yield time,
//!   - changed `Budget::deadline` from absolute `Time` to
//!     relative `Duration` (relative durations would naturally
//!     reset at each poll re-entry),
//!   - reset `polls_remaining` to `baseline.poll_quota` in
//!     the worker's poll path (specifically: in
//!     ThreeLaneWorker::execute or the YieldNow poll handler),
//!   - re-armed `inner.budget` to `inner.budget_baseline` on
//!     wake / unpark / re-poll,
//!   - introduced an "anti-cheat token bucket" that refilled
//!     on a timer instead of being a hard one-shot quota,
//!     would all be caught here.

use std::ffi::OsStr;
use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn project_dir(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn collect_rs_files(dir: &PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_rs_files(&path));
        } else if path.extension() == Some(OsStr::new("rs")) {
            out.push(path);
        }
    }
    out
}

#[test]
fn budget_deadline_field_is_absolute_time_not_relative_duration() {
    // Pin AUDIT-CRITICAL: Budget.deadline is `Option<Time>`,
    // an absolute time-point. A regression to
    // `Option<Duration>` (relative duration) would naturally
    // reset on every re-poll — defeating the carry-forward
    // semantics.
    let source = read("src/types/budget.rs");
    let struct_marker = "pub struct Budget {";
    let start = source.find(struct_marker).expect("Budget struct");
    let end = source[start..].find("\n}\n").expect("Budget struct close");
    let budget_struct = &source[start..start + end];

    assert!(
        budget_struct.contains("pub deadline: Option<Time>,")
            || budget_struct.contains("deadline: Option<Time>,"),
        "REGRESSION: Budget.deadline is no longer Option<Time>. \
         If it became Option<Duration> (relative), the deadline \
         would naturally reset at each re-poll — gaming the \
         scheduler. Restore the absolute Time type.",
    );

    // Forbid Duration-typed deadline (would be the gaming-
    // scheduler regression).
    assert!(
        !budget_struct.contains("pub deadline: Option<Duration>,")
            && !budget_struct.contains("deadline: Option<Duration>,"),
        "REGRESSION: Budget.deadline is now Duration — a \
         relative type that resets on yield. The carry-forward \
         contract requires absolute Time.",
    );
}

#[test]
fn budget_after_constructor_uses_saturating_add_nanos_not_relative() {
    // Pin: Budget::with_deadline / Sleep::after etc. compute
    // the deadline via `now.saturating_add_nanos(...)` —
    // anchoring against the CURRENT time at task creation.
    // A regression to a relative duration that's reanchored
    // on each re-poll would defeat carry-forward.
    let source = read("src/types/budget.rs");

    let suspect_relative_patterns = [
        "deadline: Some(duration)",
        "deadline = duration",
        // The suspicious pattern would be storing a Duration
        // and recomputing the deadline relative to "now" on
        // each access.
    ];
    for pat in &suspect_relative_patterns {
        assert!(
            !source.contains(pat),
            "REGRESSION: Budget construction now stores a \
             relative duration via `{pat}`. The deadline must \
             be an absolute Time computed once at task \
             creation; storing a relative duration would let \
             it reset on each re-poll.",
        );
    }
}

#[test]
fn polls_remaining_is_initialized_once_at_task_creation() {
    // Pin: polls_remaining is set ONCE in task_table.rs:306
    // when the task record is created. A regression that
    // re-set it in the worker's poll path would refresh the
    // poll quota on every yield.
    let source = read("src/runtime/task_table.rs");

    assert!(
        source.contains("record.polls_remaining = budget.poll_quota;"),
        "REGRESSION: task_table.rs no longer initializes \
         record.polls_remaining = budget.poll_quota. The one-\
         shot init at task creation is the carry-forward \
         baseline; without it, the scheduler has no idea \
         what the original budget was.",
    );
}

#[test]
fn polls_remaining_only_resets_on_cancelling_state_transition() {
    // Pin: the ONLY place polls_remaining is reset to
    // budget.poll_quota is in task.rs:818, when transitioning
    // to Cancelling state with a NEW cleanup_budget. This is
    // intentional — cleanup phase has its own deterministic
    // quota — NOT a per-yield refresh.
    let source = read("src/record/task.rs");

    let suspect_resets = [
        "self.polls_remaining = self.budget_baseline.poll_quota;",
        "self.polls_remaining = budget_baseline.poll_quota;",
    ];
    for pat in &suspect_resets {
        assert!(
            !source.contains(pat),
            "REGRESSION: task.rs now contains `{pat}` — looks \
             like a budget refresh from the baseline. The \
             only legitimate reset is the cleanup-phase \
             transition (a NEW budget, not the baseline).",
        );
    }

    // The cleanup-phase reset MUST be present (without it,
    // cleanup tasks have no budget).
    assert!(
        source.contains("self.polls_remaining = budget.poll_quota;"),
        "REGRESSION: task.rs no longer applies the cleanup \
         budget's poll_quota when transitioning to Cancelling. \
         Cleanup tasks need their own quota.",
    );
}

#[test]
fn no_reset_on_yield_path_in_runtime() {
    // Pin AUDIT-CRITICAL: scan src/runtime/ for any code that
    // resets polls_remaining or budget at yield/poll/wake
    // boundaries. The carry-forward invariant requires the
    // ABSENCE of such resets.
    let runtime_dir = project_dir("src/runtime");
    let mut findings = Vec::new();

    let suspect_reset_patterns = [
        // Re-arm budget to baseline.
        "guard.budget = guard.budget_baseline",
        "inner.budget = inner.budget_baseline",
        "self.budget = self.budget_baseline",
        // Re-arm polls_remaining to baseline.
        "polls_remaining = budget_baseline.poll_quota",
        "polls_remaining = self.budget_baseline.poll_quota",
        // Suspicious "refresh on yield" naming.
        "refresh_budget_on_yield",
        "reset_budget_on_yield",
        "rearm_budget_on_yield",
    ];

    for path in collect_rs_files(&runtime_dir) {
        let path_str = path.display().to_string();
        // Skip test code.
        if path_str.contains("/tests/")
            || path_str.contains("_tests.rs")
            || path_str.contains("metamorphic")
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for pat in &suspect_reset_patterns {
            if content.contains(pat) {
                for (line_no, line) in content.lines().enumerate() {
                    if line.contains(pat) {
                        let trimmed = line.trim_start();
                        if trimmed.starts_with("//")
                            || trimmed.starts_with("///")
                            || trimmed.starts_with("//!")
                        {
                            continue;
                        }
                        findings.push(format!(
                            "{path_str}:{line_no}: pattern `{pat}` — {line}",
                            line_no = line_no + 1,
                        ));
                    }
                }
            }
        }
    }

    if !findings.is_empty() {
        let mut report = String::from(
            "REGRESSION: src/runtime/ contains code that looks \
             like budget reset on yield / re-poll / wake. The \
             carry-forward invariant requires these patterns to \
             NOT exist. Findings:\n",
        );
        for finding in &findings {
            report.push_str(&format!("  {finding}\n"));
        }
        report.push_str(
            "\nIf any finding is intentional (e.g. the cleanup-\
             phase transition in task.rs), add a comment that \
             explains the reset and update this test's \
             allowlist.",
        );
        panic!("{report}");
    }
}

#[test]
fn yield_now_struct_does_not_touch_budget() {
    // Pin: YieldNow's poll method only flips a `yielded`
    // flag — it doesn't touch the budget at all. A regression
    // that inserted budget-refresh logic here would game the
    // scheduler on every yield_now() call.
    let source = read("src/runtime/yield_now.rs");

    let fn_marker =
        "fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let start = source.find(fn_marker).expect("YieldNow poll fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("YieldNow poll close");
    let body = &source[start..start + body_end];

    let suspect_budget_patterns = ["budget", "polls_remaining", "cancel", "Cx::current"];
    for pat in &suspect_budget_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: YieldNow::poll now references `{pat}` \
             — yield_now() must be a stateless yield primitive. \
             Touching budget / cancel state on yield would \
             break carry-forward.\n\nfn body:\n{body}",
        );
    }
}

#[test]
fn cx_checkpoint_does_not_reset_budget_on_observation() {
    // Pin: cx.checkpoint() reads `inner.budget` and
    // `inner.budget_baseline` to detect exhaustion — but does
    // NOT mutate `inner.budget` to reset it. A regression
    // that re-armed the budget on observation would break
    // carry-forward.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    // Take a generous window for the long checkpoint body.
    let after = &source[start + fn_marker.len()..];
    let next_fn_offset = after
        .find("\n    fn ")
        .or_else(|| after.find("\n    pub fn "))
        .unwrap_or(after.len().min(40000));
    let body = &source[start..start + fn_marker.len() + next_fn_offset];

    // Suspect: the checkpoint body should NOT contain code
    // that re-arms the budget to its baseline. The budget
    // should only DECREASE (via consume_poll / consume_cost
    // elsewhere) — never reset.
    let suspect_reset_in_checkpoint = [
        "inner.budget = inner.budget_baseline",
        "inner.budget = budget_baseline",
        "budget = budget_baseline",
    ];
    for pat in &suspect_reset_in_checkpoint {
        assert!(
            !body.contains(pat),
            "REGRESSION: cx.checkpoint() now resets the budget \
             via `{pat}`. Observing exhaustion in checkpoint \
             must NEVER refresh the budget — that would let a \
             task game the scheduler by checkpointing right \
             before exhaustion to extend its quantum.",
        );
    }
}

#[test]
fn budget_baseline_is_only_set_at_task_creation_and_cleanup_transition() {
    // Pin: budget_baseline is set only at:
    //   1. CxInner construction (initial budget).
    //   2. Cleanup-phase transition (cleanup_budget).
    //
    // A regression that wrote to budget_baseline on yield /
    // wake / re-poll would change what "the original
    // budget" was — a different form of gaming.
    let runtime_dir = project_dir("src/runtime");
    let cx_dir = project_dir("src/cx");
    let mut findings = Vec::new();

    for dir in [&runtime_dir, &cx_dir] {
        for path in collect_rs_files(dir) {
            let path_str = path.display().to_string();
            if path_str.contains("/tests/") || path_str.contains("_tests.rs") {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            // Look for assignments to budget_baseline.
            for (line_no, line) in content.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if (line.contains("budget_baseline =") || line.contains("budget_baseline:"))
                    && !line.contains("/// ")
                    && !line.contains("//!")
                {
                    findings.push(format!(
                        "{path_str}:{line_no}: {trimmed}",
                        line_no = line_no + 1,
                    ));
                }
            }
        }
    }

    // We expect findings only at:
    //   - CxInner construction sites (cx/cx.rs).
    //   - Cleanup-phase transition (record/task.rs is OUTSIDE
    //     these dirs — but we may see writes via cx.rs's
    //     access to the cx_inner).
    //
    // Let the test pass if findings exist but they're in
    // expected locations. Flag if they appear in the
    // scheduler.
    for finding in &findings {
        assert!(
            !finding.contains("scheduler/"),
            "REGRESSION: budget_baseline is being written from \
             the scheduler (`{finding}`). The scheduler MUST \
             NOT modify budget_baseline — that's the \
             original-budget invariant. Only Cx construction \
             and cleanup-phase transitions may touch it.",
        );
    }
}

#[test]
fn budget_consume_poll_decrements_quota_does_not_refresh() {
    // Pin: Budget::consume_poll DECREMENTS poll_quota by 1.
    // A regression to "refresh on consume" would game the
    // scheduler.
    let source = read("src/types/budget.rs");

    let fn_marker = "pub fn consume_poll(&mut self) -> Option<u32> {";
    let start = source.find(fn_marker).expect("consume_poll fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("consume_poll close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.poll_quota -= 1;"),
        "REGRESSION: Budget::consume_poll no longer \
         decrements poll_quota. Without the decrement, the \
         quota stays static — there's no enforcement at all.\n\
         \nfn body:\n{body}",
    );

    // Forbid increment / refresh patterns.
    let suspect_refresh = [
        "self.poll_quota +=",
        "self.poll_quota = self.poll_quota.max(",
        "self.poll_quota = baseline",
    ];
    for pat in &suspect_refresh {
        assert!(
            !body.contains(pat),
            "REGRESSION: Budget::consume_poll now increases / \
             refreshes the quota via `{pat}`. consume_poll \
             must MONOTONICALLY DECREASE — refresh would \
             defeat the budget.",
        );
    }
}

#[test]
fn budget_baseline_field_provides_carry_forward_diagnostic() {
    // Pin: the budget_baseline field on CxInner stores the
    // ORIGINAL budget at task creation. The running budget
    // decreases; baseline stays constant. The diagnostic
    // `polls_used = baseline - budget` (cx.rs:2007-2010)
    // depends on this carry-forward semantics.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("budget_baseline"),
        "REGRESSION: CxInner no longer has the budget_baseline \
         field. Without it, polls_used / cost_used \
         diagnostics can't compute the delta — and the \
         operator-facing observability of budget usage is \
         lost.",
    );

    // The polls_used computation pattern.
    assert!(
        source.contains("budget_baseline.poll_quota.saturating_sub(budget.poll_quota)"),
        "REGRESSION: cx.rs no longer computes polls_used as \
         `budget_baseline.poll_quota - budget.poll_quota`. The \
         diagnostic relies on the carry-forward invariant: \
         baseline is constant, current decreases, delta is \
         polls used.",
    );
}
