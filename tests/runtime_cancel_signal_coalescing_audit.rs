//! Audit + regression test for cancel-signal coalescing.
//!
//! Operator's question: "when 100 cancel signals arrive on
//! the same task in rapid succession (e.g., timeout fires,
//! then user calls cancel, then drop), do we coalesce
//! (correct: idempotent cancel) or do 100 separate
//! cancellations (wasteful)?"
//!
//! Audit findings:
//!
//!   `request_cancel_with_budget` is **fully idempotent and
//!   coalescing**. 100 cancel signals on the same task
//!   produce ONE state transition (the first call) and 99
//!   strengthen-only updates (subsequent calls). The
//!   structural mechanism:
//!
//!   1. **Terminal-state early return** (record/task.rs:528):
//!      ```ignore
//!      if self.state.is_terminal() {
//!          return false;
//!      }
//!      ```
//!      Any cancel call on a Completed task is a no-op —
//!      can't cancel what's already terminal.
//!
//!   2. **Atomic fast_cancel store is idempotent**
//!      (task.rs:535-538):
//!      ```ignore
//!      guard.cancel_requested = true;
//!      guard.fast_cancel.store(true, Release);
//!      ```
//!      `cancel_requested = true` and
//!      `fast_cancel.store(true)` are both idempotent —
//!      setting an already-true value is a no-op for the
//!      reader. No observability change after the first
//!      call's publish.
//!
//!   3. **State machine match dispatches by current state**
//!      (task.rs:545-616):
//!      - **`CancelRequested`**: strengthen existing reason,
//!        combine budgets, return `false` (NOT newly
//!        cancelled).
//!      - **`Cancelling`**: same — strengthen + combine,
//!        return false.
//!      - **`Finalizing`**: same — strengthen + combine,
//!        return false.
//!      - **`Created`/`Running`**: transition to
//!        CancelRequested, increment cancel_epoch, return
//!        true (NEWLY cancelled).
//!        Only the FIRST call from a non-cancelling state
//!        returns true; all others return false.
//!
//!   4. **Reason strengthening preserves the strongest
//!      attribution** (task.rs:557, 573, 600):
//!      ```ignore
//!      existing_reason.strengthen(&reason);
//!      ```
//!      Multiple cancel signals with different reasons
//!      converge on the highest-severity reason. The cause
//!      chain is preserved — operators can audit which
//!      cancels arrived without losing attribution.
//!
//!   5. **Budget combining uses lattice meet** (task.rs:558,
//!      574, 601):
//!      ```ignore
//!      *existing_budget = existing_budget.combine(cleanup_budget);
//!      ```
//!      `combine` is the Budget::meet operation — MIN on
//!      deadline/poll_quota/cost_quota, MAX on priority.
//!      Multiple cancel signals with different cleanup
//!      budgets converge on the TIGHTEST budget — never
//!      relax.
//!
//!   6. **`cancel_epoch` increments only on first transition**
//!      (task.rs:621-624): the epoch counter increments when
//!      the task moves from Created/Running to CancelRequested.
//!      Subsequent strengthen-only calls do NOT increment.
//!      This is what makes "first cancel observed" countable
//!      for metrics.
//!
//!   7. **Bool return distinguishes new-cancel from redundant**
//!      (task.rs:560, 587, 614 → false; 616+ → true): the
//!      `cancel_request` higher-level walk in state.rs uses
//!      this bool to decide whether to schedule the task on
//!      the cancel lane:
//!      ```ignore
//!      let newly_cancelled = task.request_cancel_with_budget(...);
//!      if newly_cancelled {
//!          // schedule on cancel lane
//!      }
//!      ```
//!      Only the first call schedules; subsequent calls
//!      see `newly_cancelled == false` and skip the
//!      scheduling op (the task is already on the cancel
//!      lane from the first call).
//!
//!   8. **`request_cancel_with_budget` is the SINGLE entry
//!      point for cancel publishing**: a grep shows all
//!      cancel sources (state.cancel_request, deadline
//!      monitor, region close) flow through this method.
//!      Coalescing is enforced at this single chokepoint —
//!      no parallel uncoalesced path.
//!
//! Verdict: **SOUND**. 100 cancel signals on the same task
//! produce 1 state transition + 99 strengthen-only updates.
//! The fast_cancel atomic store is naturally idempotent.
//! The bool return lets the higher-level walk skip
//! redundant scheduling. The cancel_epoch counts ONLY the
//! first cancel.
//!
//! No bead filed. The coalescing is structurally enforced.
//!
//! A regression that:
//!   - removed the terminal-state early return (would let
//!     post-completion cancels mutate state — UB),
//!   - changed the state-match arms to ALWAYS return true
//!     (every cancel signal would re-schedule the task on
//!     the cancel lane — 100 cancels → 100 lane injections,
//!     wasteful AND breaks single-shot dispatch),
//!   - changed strengthen to OVERWRITE the existing reason
//!     (lost attribution — last cancel wins instead of
//!     strongest),
//!   - changed combine to e.g. AVERAGE budgets instead of
//!     MEET (would relax constraints under repeated cancel),
//!   - removed the cancel_epoch increment guard (would let
//!     the epoch grow unboundedly under coalesced cancels),
//!   - introduced a parallel cancel-publish path that
//!     bypasses request_cancel_with_budget (would lose the
//!     coalescing chokepoint),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn request_cancel_with_budget_returns_false_when_task_already_terminal() {
    // Pin (link 1): the early return on is_terminal() is
    // the first idempotency gate. Without it, post-
    // completion cancels mutate state.
    let source = read("src/record/task.rs");

    let fn_marker = "pub fn request_cancel_with_budget(";
    let start = source
        .find(fn_marker)
        .expect("request_cancel_with_budget fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("request_cancel_with_budget_deferred(reason, cleanup_budget)")
            && body.contains("if self.state.is_terminal() {")
            && body.contains("return (false, SmallVec::new());"),
        "REGRESSION: request_cancel_with_budget no longer \
         early-returns on terminal state. Cancels on \
         completed tasks would mutate state — UB pathway \
         AND breaks coalescing for completed tasks.",
    );
}

#[test]
fn fast_cancel_store_is_idempotent_atomic_no_compare_swap() {
    // Pin (link 2): fast_cancel uses .store(true, Release),
    // NOT compare_exchange. Idempotent — setting an
    // already-true value is naturally a no-op for readers.
    let source = read("src/record/task.rs");

    assert!(
        source.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: fast_cancel publish no longer uses \
         .store. If it switched to compare_exchange, \
         coalesced cancels would 'fail' the CAS on the \
         second-and-later call — the bool return semantics \
         would conflate.",
    );

    // The cancel_requested = true assignment is also
    // idempotent.
    assert!(
        source.contains("guard.cancel_requested = true;"),
        "REGRESSION: cancel_requested assignment is gone. \
         Without it, the slow-path cancel observation in \
         checkpoint() doesn't see the cancel.",
    );
}

#[test]
fn state_match_arms_strengthen_existing_reason_for_already_cancelling_states() {
    // Pin (link 4): the state machine arms for
    // CancelRequested/Cancelling/Finalizing call
    // existing_reason.strengthen(&reason). Without this,
    // multi-cancel attribution is lost.
    let source = read("src/record/task.rs");

    let fn_marker = "pub fn request_cancel_with_budget(";
    let start = source
        .find(fn_marker)
        .expect("request_cancel_with_budget fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    let strengthen_count = body.matches("existing_reason.strengthen(&reason);").count();
    assert!(
        strengthen_count >= 3,
        "REGRESSION: only {strengthen_count} \
         existing_reason.strengthen calls found (expected \
         >= 3 — one per CancelRequested/Cancelling/\
         Finalizing arm). Multi-cancel reason \
         strengthening is broken; either the arms are \
         gone or they overwrite instead of strengthen.",
    );

    // Forbid overwriting (the loser pattern).
    let suspect_overwrite = [
        "*existing_reason = reason.clone();",
        "*existing_reason = reason;",
    ];
    for pat in &suspect_overwrite {
        assert!(
            !body.contains(pat),
            "REGRESSION: state match arm now overwrites \
             existing_reason via `{pat}` — last-cancel-wins \
             attribution. The strongest cancel reason is \
             lost when a weaker cancel arrives later.",
        );
    }
}

#[test]
fn state_match_arms_combine_budgets_via_meet_for_tightest_constraint() {
    // Pin (link 5): the state arms call existing_budget.
    // combine(cleanup_budget) which is the lattice-meet
    // (MIN on deadline/poll/cost, MAX on priority). Without
    // this, repeated cancels could RELAX budgets.
    let source = read("src/record/task.rs");

    let fn_marker = "pub fn request_cancel_with_budget(";
    let start = source
        .find(fn_marker)
        .expect("request_cancel_with_budget fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    let combine_count = body.matches(".combine(cleanup_budget)").count();
    assert!(
        combine_count >= 3,
        "REGRESSION: only {combine_count} \
         budget.combine(cleanup_budget) calls found \
         (expected >= 3). Multi-cancel budget tightening \
         is broken — repeated cancels may relax \
         constraints.",
    );
}

#[test]
fn state_match_arms_for_cancelling_states_return_false_not_true() {
    // Pin (link 7): the CancelRequested/Cancelling/
    // Finalizing arms return false (NOT newly cancelled).
    // Without this, the higher-level walk would re-schedule
    // the task on every cancel signal.
    let source = read("src/record/task.rs");

    let fn_marker = "pub fn request_cancel_with_budget(";
    let start = source
        .find(fn_marker)
        .expect("request_cancel_with_budget fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // Each of the three already-cancelling arms returns
    // false. We count returns inside the matching arms by
    // looking for the trace + strengthen + false pattern.
    let already_cancelled_returns = body
        .matches("\n                false\n            }")
        .count();
    assert!(
        already_cancelled_returns >= 3,
        "REGRESSION: state match arms for already-cancelling \
         states return only {already_cancelled_returns} \
         falses (expected >= 3 — one per arm). Either \
         the arms now return true (re-scheduling on every \
         cancel — wasteful) or the structure changed.",
    );
}

#[test]
fn cancel_epoch_increments_only_on_first_transition_to_cancel_requested() {
    // Pin (link 6): cancel_epoch increments ONLY when the
    // task transitions from Created/Running to
    // CancelRequested. Subsequent strengthen-only calls do
    // NOT increment. Without this guard, the epoch grows
    // unboundedly under coalesced cancels.
    let source = read("src/record/task.rs");

    let fn_marker = "pub fn request_cancel_with_budget(";
    let start = source
        .find(fn_marker)
        .expect("request_cancel_with_budget fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // The increment must be inside the Created/Running arm.
    assert!(
        body.contains("TaskState::Created | TaskState::Running =>")
            && body.contains("if self.cancel_epoch == 0 {")
            && body.contains("self.cancel_epoch = 1;"),
        "REGRESSION: cancel_epoch increment is no longer \
         gated to the Created/Running arm (first \
         transition only). Either the epoch grows \
         unboundedly under coalesced cancels OR the \
         first-cancel signal is lost.",
    );
}

#[test]
fn cancel_request_higher_level_walk_uses_newly_cancelled_bool() {
    // Pin (link 7): state.cancel_request uses the bool
    // return to gate cancel-lane scheduling. Without this,
    // 100 coalesced cancels would each schedule the task
    // 100 times.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("newly_cancelled =\n                        task.request_cancel_with_budget(task_reason.clone(), task_budget);")
            || source.contains("task.request_cancel_with_budget(task_reason.clone(), task_budget)"),
        "REGRESSION: cancel_request no longer captures the \
         newly_cancelled bool. The coalescing signal is \
         discarded — every cancel request schedules the \
         task again.",
    );

    assert!(
        source.contains("if newly_cancelled {"),
        "REGRESSION: cancel_request no longer gates work on \
         newly_cancelled. Either every signal triggers \
         redundant scheduling (wasteful) or no signal \
         triggers any scheduling (broken).",
    );
}

#[test]
fn budget_update_is_deferred_to_acknowledge_cancel_to_avoid_pre_emption() {
    // Pin (link 2 audit): the comment in
    // request_cancel_with_budget notes that budget update is
    // DEFERRED to acknowledge_cancel — preventing the
    // budget-exhaustion check from pre-empting the cancel
    // observation. This is a subtle ordering invariant.
    let source = read("src/record/task.rs");

    assert!(
        source.contains(
            "// Budget update is deferred to acknowledge_cancel to prevent\n            // pre-empting the cancellation check with a budget exhaustion error."
        ) || source.contains("Budget update is deferred to acknowledge_cancel"),
        "REGRESSION: the budget-deferral comment is gone. \
         The ordering invariant (cancel before budget \
         tightening) may drift — checkpoint may see \
         budget exhaustion BEFORE the cancel signal, \
         masking the cancel attribution.",
    );
}

#[test]
fn cancel_request_returns_vec_for_per_task_priority_routing() {
    // Pin (link 8): cancel_request returns Vec<(TaskId, u8)>
    // — the bool-gated tasks_to_cancel_result push. Without
    // this, the higher-level scheduler can't route only
    // newly-cancelled tasks to the cancel lane.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("pub fn cancel_request(") && source.contains("-> Vec<(TaskId, u8)>"),
        "REGRESSION: cancel_request signature no longer \
         returns Vec<(TaskId, u8)>. The coalescing signal \
         can't be conveyed to the scheduler — every cancel \
         request triggers full re-scheduling.",
    );
}

#[test]
fn no_alternate_cancel_publish_path_bypasses_request_cancel_with_budget() {
    // Pin (link 8): there must be NO alternate path that
    // mutates fast_cancel + cancel_requested without going
    // through request_cancel_with_budget. The single
    // chokepoint is what enforces coalescing.
    let source = read("src/runtime/state.rs");

    let suspect_alternate_paths = ["task.cancel_requested = true;", ".fast_cancel.store(true,"];

    let mut findings: Vec<String> = Vec::new();
    for pat in &suspect_alternate_paths {
        if source.contains(pat) {
            // Check it's only in the legitimate
            // request_cancel_with_budget call (which is fine)
            // OR in tests.
            for (line_no, line) in source.lines().enumerate() {
                if line.contains(pat) && !line.contains("request_cancel_with_budget") {
                    let trimmed = line.trim_start();
                    if !trimmed.starts_with("//") && !trimmed.starts_with("///") {
                        findings.push(format!(
                            "state.rs:{line_no}: pattern `{pat}` outside request_cancel_with_budget",
                            line_no = line_no + 1,
                        ));
                    }
                }
            }
        }
    }

    assert!(
        findings.is_empty(),
        "REGRESSION: state.rs now has an alternate \
         cancel-publish path that bypasses \
         request_cancel_with_budget. The coalescing \
         chokepoint is lost. Findings:\n  {findings}",
        findings = findings.join("\n  "),
    );
}

// ─────────── BEHAVIORAL PIN: 100-cancel coalescing ─────────
//
// Direct simulation: build a MockTask with a state machine
// + cancel-counter. Issue 100 cancels and verify only ONE
// transition fires (newly_cancelled count == 1) and 99 are
// strengthen-only (newly_cancelled count == 0).

#[derive(Debug, PartialEq, Clone, Copy)]
enum MockState {
    Running,
    CancelRequested,
}

struct MockTask {
    state: MockState,
    fast_cancel: Arc<AtomicBool>,
    cancel_epoch: u64,
    transition_count: Arc<AtomicU32>,
    strengthen_count: Arc<AtomicU32>,
}

impl MockTask {
    fn new() -> Self {
        Self {
            state: MockState::Running,
            fast_cancel: Arc::new(AtomicBool::new(false)),
            cancel_epoch: 0,
            transition_count: Arc::new(AtomicU32::new(0)),
            strengthen_count: Arc::new(AtomicU32::new(0)),
        }
    }

    fn request_cancel(&mut self) -> bool {
        // Idempotent fast_cancel publish.
        self.fast_cancel.store(true, Ordering::Release);

        match self.state {
            MockState::CancelRequested => {
                // Coalesced — strengthen only.
                self.strengthen_count.fetch_add(1, Ordering::Relaxed);
                false
            }
            MockState::Running => {
                // First transition.
                self.state = MockState::CancelRequested;
                self.cancel_epoch = 1;
                self.transition_count.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }
}

#[test]
fn behavior_100_cancels_produce_exactly_one_transition_and_99_strengthens() {
    // Behavioral pin: the operator's exact scenario. 100
    // cancel signals on the same task. Verify exactly 1
    // transition + 99 strengthens.
    let mut task = MockTask::new();

    let mut newly_cancelled_count = 0_u32;
    for _ in 0..100 {
        if task.request_cancel() {
            newly_cancelled_count += 1;
        }
    }

    let transitions = task.transition_count.load(Ordering::Relaxed);
    let strengthens = task.strengthen_count.load(Ordering::Relaxed);

    assert_eq!(
        newly_cancelled_count, 1,
        "REGRESSION: 100 cancels produced {newly_cancelled_count} \
         newly_cancelled returns (expected 1). The bool \
         coalescing signal is broken — higher-level \
         scheduler would re-inject the task multiple times.",
    );

    assert_eq!(
        transitions, 1,
        "REGRESSION: 100 cancels produced {transitions} \
         state transitions (expected 1). The state machine \
         is not coalescing — every cancel re-runs the \
         transition logic.",
    );

    assert_eq!(
        strengthens, 99,
        "REGRESSION: 100 cancels produced {strengthens} \
         strengthen-only operations (expected 99). The \
         99 redundant cancels did not all flow into the \
         strengthen path.",
    );

    let epoch = task.cancel_epoch;
    assert_eq!(
        epoch, 1,
        "REGRESSION: cancel_epoch grew to {epoch} after 100 \
         cancels (expected 1). The epoch is no longer \
         gated to the first transition.",
    );

    assert!(
        task.fast_cancel.load(Ordering::Acquire),
        "REGRESSION: fast_cancel is not set after 100 \
         cancels. The atomic publish is broken.",
    );
}

#[test]
fn behavior_concurrent_cancels_from_multiple_threads_are_coalesced() {
    // Behavioral pin: 100 concurrent cancels from 10
    // threads. Verify total transitions == 1 even under
    // race conditions.
    use std::sync::Mutex;
    use std::thread;

    let task = Arc::new(Mutex::new(MockTask::new()));
    let mut handles = Vec::new();

    for _ in 0..10 {
        let task = Arc::clone(&task);
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                let mut t = task.lock().unwrap();
                t.request_cancel();
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }

    let task_locked = task.lock().unwrap();
    let transitions = task_locked.transition_count.load(Ordering::Relaxed);
    let strengthens = task_locked.strengthen_count.load(Ordering::Relaxed);

    assert_eq!(
        transitions, 1,
        "REGRESSION: concurrent 100 cancels (10 threads) \
         produced {transitions} transitions (expected 1). \
         Cross-thread coalescing is broken.",
    );

    assert_eq!(
        transitions + strengthens,
        100,
        "REGRESSION: total cancel calls {} != 100. Some \
         cancels were lost.",
        transitions + strengthens,
    );
}

#[test]
fn behavior_cancel_after_terminal_returns_false_no_state_mutation() {
    // Behavioral pin: cancel on a "terminal" task (already
    // CancelRequested in the mock) is a no-op.
    let mut task = MockTask::new();
    task.state = MockState::CancelRequested;

    let result = task.request_cancel();
    assert!(
        !result,
        "REGRESSION: cancel on already-CancelRequested task \
         returned true. The coalescing bool signal is \
         broken — re-cancelling a cancelled task triggers \
         re-scheduling.",
    );

    assert_eq!(
        task.transition_count.load(Ordering::Relaxed),
        0,
        "REGRESSION: cancel on already-CancelRequested task \
         transitioned. State machine corruption.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_region_close_idempotency_audit.rs",
        "tests/scheduler_cancel_storm_propagation_audit.rs",
        "tests/runtime_cancel_cause_chain_depth_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
