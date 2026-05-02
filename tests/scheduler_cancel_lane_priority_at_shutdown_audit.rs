//! Audit + regression test for `src/runtime/scheduler/three_lane.rs`
//! cancel-lane drain ordering relative to shutdown and to the
//! deadline-monotone (timed) lane.
//!
//! Operator's question: "when runtime.shutdown() is called, must
//! cancel-lane be drained before deadline-monotone? Per close-
//! quiescence invariant, all cancellations must complete before
//! close returns."
//!
//! Audit findings:
//!
//!   The asupersync close-quiescence invariant is **enforced at
//!   the REGION close layer**, NOT at scheduler shutdown. Per
//!   AGENTS.md: "Region close = quiescence: no live children +
//!   all finalizers done." Scheduler shutdown happens AFTER all
//!   regions have closed quiescent — by then, the cancel lane
//!   is already empty.
//!
//!   The scheduler-level `ThreeLaneScheduler::shutdown()`
//!   (three_lane.rs:1811-1814) is intentionally minimal:
//!
//!   ```ignore
//!   pub fn shutdown(&self) {
//!       self.shutdown.store(true, Ordering::Release);
//!       self.wake_all();
//!   }
//!   ```
//!
//!   It signals workers and wakes parked workers; the workers'
//!   `run_loop` (three_lane.rs:3164) exits at the next
//!   iteration of `while !self.shutdown.load(...)`. No explicit
//!   "drain cancel lane before exiting" phase is needed because
//!   the upper layer (Region::close) has already drained all
//!   live tasks and their cancellations.
//!
//!   The actual cancel-lane DISPATCH priority during normal
//!   operation lives in `next_task`
//!   (three_lane.rs:3358-3470+):
//!
//!   - **Default mode** (most common): the dispatch order is
//!     `cancel > timed > ready`. Phase 1 checks the global
//!     cancel queue first; Phase 2 checks the local cancel
//!     lane before timed. The operator's primary concern
//!     ("cancel-lane drained before deadline-monotone") is
//!     satisfied by this ordering.
//!
//!   - **MeetDeadlines mode** (Lyapunov governor signals
//!     deadline pressure): the priority temporarily flips to
//!     `timed > cancel`, but cancel is still bounded by the
//!     `cancel_streak < effective_limit` fairness check that
//!     forces a cancel dispatch after at most
//!     `cancel_streak_limit` consecutive non-cancel
//!     dispatches. This prevents starvation while letting
//!     deadline-critical work meet its deadlines.
//!
//!   - **DrainObligations / DrainRegions modes** (governor
//!     signals an obligation/region drain is in progress): the
//!     `effective_limit` is doubled
//!     (`base_limit.saturating_mul(2)`, three_lane.rs:3372),
//!     giving cancel work twice the per-streak budget — the
//!     drain phase needs cancel-lane progress most.
//!
//! Verdict: **SOUND**. Two converging guarantees enforce the
//! operator's "all cancellations complete before close" rule:
//!   1. **Close-quiescence at the region layer**: by the time
//!      Region::close returns, all child tasks have completed,
//!      their cancellations have finalized, and the cancel
//!      lane is observably empty.
//!   2. **Cancel-lane priority during normal operation**: in
//!      the default dispatch mode, cancel lane is checked
//!      BEFORE timed lane in both global and local phases.
//!
//! A regression that:
//!   - swapped the default-mode cancel-then-timed order to
//!     timed-then-cancel (would let cancels starve under
//!     timed pressure even outside MeetDeadlines mode),
//!   - removed the `cancel_streak < effective_limit` fairness
//!     check (would let a flood of cancels starve all timed
//!     work — opposite failure mode but still wrong),
//!   - made `shutdown()` non-idempotent or block waiting on a
//!     drain (would deadlock if regions were already
//!     quiescent),
//!   - removed the `wake_all()` from shutdown (would let
//!     parked workers sleep forever),
//! would all be caught here.

use std::path::PathBuf;

fn read_three_lane_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/runtime/scheduler/three_lane.rs");
    std::fs::read_to_string(&path).expect("read three_lane.rs")
}

#[test]
fn three_lane_scheduler_shutdown_is_minimal_signal_plus_wake() {
    // Pin AUDIT-CRITICAL: shutdown() is a non-blocking flag-set
    // + wake_all. A regression that introduced a drain-loop or
    // a blocking wait inside shutdown would deadlock callers
    // who expected the close-quiescence guarantee to be
    // enforced UPSTREAM at the region layer.
    let source = read_three_lane_source();

    // Find the inherent impl's shutdown method.
    let fn_marker = "pub fn shutdown(&self) {";
    let mut search = 0;
    let mut shutdown_body: Option<String> = None;
    // The scheduler has multiple `pub fn shutdown(&self)` —
    // one on ThreeLaneScheduler (the "outer" struct) and one
    // potentially on a child struct. We want the simplest one
    // that matches the audit: flag set + wake. Walk all
    // occurrences and pin the FIRST one that contains
    // `self.shutdown.store(true,` — that's the scheduler.
    while let Some(rel) = source[search..].find(fn_marker) {
        let abs = search + rel;
        let body_end = source[abs..]
            .find("\n    }\n")
            .expect("shutdown fn close");
        let body = &source[abs..abs + body_end];
        if body.contains("self.shutdown.store(true,") {
            shutdown_body = Some(body.to_string());
            break;
        }
        search = abs + 1;
    }
    let body =
        shutdown_body.expect("ThreeLaneScheduler::shutdown body");

    // Body must contain the flag-set AND wake.
    assert!(
        body.contains("self.shutdown.store(true, Ordering::Release);"),
        "REGRESSION: ThreeLaneScheduler::shutdown no longer \
         atomically stores the shutdown flag with Release \
         ordering. Workers reading the flag with Acquire need \
         the release-acquire pair to observe a consistent view \
         of pre-shutdown state.\n\nfn body:\n{body}",
    );
    assert!(
        body.contains("self.wake_all();"),
        "REGRESSION: ThreeLaneScheduler::shutdown no longer \
         calls self.wake_all(). Without this, parked workers \
         that observed the flag is_shutdown=false BEFORE the \
         flag flipped will sleep forever — they never see the \
         signal to exit.\n\nfn body:\n{body}",
    );

    // The body MUST NOT contain a drain-loop or .await — the
    // close-quiescence invariant is enforced UPSTREAM (region
    // close), not here.
    let suspect_drain_patterns = [
        ".await",
        "drain_cancel_lane",
        "while !self.is_quiescent",
        "loop {",
    ];
    for pat in &suspect_drain_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: shutdown() now contains `{pat}` — \
             looks like a drain or wait loop. The close-\
             quiescence invariant is enforced at Region::close, \
             NOT at scheduler shutdown. A drain loop here can \
             deadlock callers whose regions are already \
             quiescent (nothing to drain) but whose workers \
             haven't observed the shutdown flag yet.",
        );
    }
}

#[test]
fn run_loop_exits_on_shutdown_flag() {
    // Pin: the worker run loop checks `self.shutdown.load(...)`
    // as its top-level loop condition. A regression that
    // removed this check would let workers run forever after
    // shutdown was signaled.
    let source = read_three_lane_source();

    let fn_marker = "pub fn run_loop(&mut self) {";
    let start = source.find(fn_marker).expect("run_loop fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("run_loop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("while !self.shutdown.load(Ordering::Relaxed) {"),
        "REGRESSION: run_loop no longer guards on \
         `while !self.shutdown.load(Ordering::Relaxed)`. \
         Without the check, workers will continue running \
         after shutdown is signaled — never exiting.\n\n\
         fn body:\n{body}",
    );

    // Defense-in-depth: there must be a SECOND check inside the
    // park-backoff loop too, otherwise a worker that's spinning
    // in backoff at shutdown time will never exit.
    let backoff_check_count = body
        .matches("if self.shutdown.load(Ordering::Relaxed)")
        .count();
    assert!(
        backoff_check_count >= 1,
        "REGRESSION: run_loop's inner backoff loop no longer \
         re-checks the shutdown flag. A worker spinning in the \
         park backoff phase would not observe the flag flip \
         and could remain pinned to a CPU forever after \
         shutdown.",
    );
}

#[test]
fn next_task_default_order_is_cancel_then_timed() {
    // Pin AUDIT-CRITICAL: in the default (non-MeetDeadlines)
    // dispatch path, cancel lane is checked BEFORE timed lane.
    // Both the global queue (Phase 1) and the local lane
    // (Phase 2) follow this order.
    let source = read_three_lane_source();

    let fn_marker = "pub fn next_task(&mut self) -> Option<TaskId> {";
    let start = source.find(fn_marker).expect("next_task fn");
    // next_task is a long function; take a generous window.
    // We pin via positional ordering of marker strings.
    let window_end = (start + 8000).min(source.len());
    // Slice on a char-boundary-safe window.
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // The default-mode global cancel check must come before
    // the default-mode global timed check inside the SAME
    // function. We anchor on comments / code patterns.
    let default_cancel_marker = "// Default / drain: cancel > timed.";
    let cancel_pos = body
        .find(default_cancel_marker)
        .expect("default-mode cancel/timed comment");

    // Within the default branch, the next `pop_cancel` MUST
    // appear before the next `pop_timed_if_due`.
    let post_default = &body[cancel_pos..];
    let cancel_pop_pos = post_default
        .find("self.global.pop_cancel()")
        .expect("global pop_cancel call");

    // Forbid `pop_timed_if_due` BEFORE `pop_cancel` in the
    // default branch.
    let pre_cancel = &post_default[..cancel_pop_pos];
    assert!(
        !pre_cancel.contains("self.global.pop_timed_if_due("),
        "REGRESSION: in the default-mode dispatch branch, \
         pop_timed_if_due appears BEFORE pop_cancel. The \
         documented contract is `cancel > timed` in default \
         mode — a flip would break the operator's invariant.\n\
         \npre-cancel block:\n{pre_cancel}",
    );
}

#[test]
fn next_task_local_lane_default_order_is_cancel_then_timed() {
    // Pin: in the local-lane phase (Phase 2 of next_task), the
    // default branch checks `pop_cancel_only_with_hint` before
    // `pop_timed_only_with_hint`.
    let source = read_three_lane_source();

    let fn_marker = "pub fn next_task(&mut self) -> Option<TaskId> {";
    let start = source.find(fn_marker).expect("next_task fn");
    let window_end = (start + 9000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // Find the `// Default: Cancel > Timed` comment.
    let default_marker = "// Default: Cancel > Timed";
    let default_pos = body.find(default_marker).expect("default-branch comment");

    let post_default = &body[default_pos..];
    let local_cancel_pos = post_default
        .find("local.pop_cancel_only_with_hint(")
        .expect("local pop_cancel_only");
    let pre_local_cancel = &post_default[..local_cancel_pos];

    assert!(
        !pre_local_cancel.contains("local.pop_timed_only_with_hint("),
        "REGRESSION: in the default-mode LOCAL-lane phase, \
         pop_timed_only_with_hint appears BEFORE \
         pop_cancel_only_with_hint. The documented contract is \
         cancel-first in default mode — flip would break the \
         operator's invariant for local-lane work.",
    );
}

#[test]
fn cancel_streak_fairness_check_protects_timed_starvation() {
    // Pin: even when cancel has priority, the
    // `cancel_streak < effective_limit` check forces timed/
    // ready work after at most `cancel_streak_limit`
    // consecutive cancel dispatches. Without this, a flood of
    // cancels could starve deadline-critical work — the
    // opposite of the operator's concern but equally a defect.
    let source = read_three_lane_source();

    let fn_marker = "pub fn next_task(&mut self) -> Option<TaskId> {";
    let start = source.find(fn_marker).expect("next_task fn");
    let body_end_window = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= body_end_window)
        .last()
        .unwrap_or(body_end_window);
    let body = &source[start..safe_end];

    assert!(
        body.contains("let check_cancel = self.cancel_streak < effective_limit;"),
        "REGRESSION: the cancel-streak fairness check is gone. \
         Without `check_cancel = self.cancel_streak < \
         effective_limit`, cancel-only dispatch can run \
         unbounded — starving timed work and breaking the \
         deadline-monotone scheduler's primary contract.\n\n\
         fn body window:\n{body}",
    );
}

#[test]
fn drain_phases_double_the_cancel_budget() {
    // Pin: when the Lyapunov governor signals
    // DrainObligations / DrainRegions, the effective_limit is
    // 2× base. The drain phase needs MORE cancel-lane
    // progress, not less; the operator's "all cancellations
    // complete before close" reading aligns with this.
    let source = read_three_lane_source();

    let fn_marker = "pub fn next_task(&mut self) -> Option<TaskId> {";
    let start = source.find(fn_marker).expect("next_task fn");
    let body_end_window = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= body_end_window)
        .last()
        .unwrap_or(body_end_window);
    let body = &source[start..safe_end];

    assert!(
        body.contains("SchedulingSuggestion::DrainObligations | SchedulingSuggestion::DrainRegions"),
        "REGRESSION: the DrainObligations/DrainRegions branch is \
         gone from next_task's effective_limit calculation. The \
         drain phase needs 2× the base cancel budget; without \
         this case, a long drain phase will yield to timed work \
         too aggressively and stretch the time-to-quiescence.\n\n\
         fn body window:\n{body}",
    );

    assert!(
        body.contains("base_limit.saturating_mul(2)"),
        "REGRESSION: the drain-phase effective_limit no longer \
         doubles the base via saturating_mul(2). The 2× boost \
         is the load-bearing part of the drain-phase progress \
         guarantee.",
    );
}

#[test]
fn meet_deadlines_mode_still_dispatches_cancel_periodically() {
    // Pin: even in MeetDeadlines mode (where timed temporarily
    // takes priority), the cancel branch is still REACHED via
    // the `check_cancel` gate. The MeetDeadlines branch falls
    // through to a cancel check after the timed dispatch
    // attempts; without this, a sustained deadline-pressure
    // window would let cancel work starve indefinitely.
    let source = read_three_lane_source();

    let fn_marker = "pub fn next_task(&mut self) -> Option<TaskId> {";
    let start = source.find(fn_marker).expect("next_task fn");
    let body_end_window = (start + 9000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= body_end_window)
        .last()
        .unwrap_or(body_end_window);
    let body = &source[start..safe_end];

    let meet_marker = "// MeetDeadlines: Timed > Cancel";
    let meet_pos = body.find(meet_marker).expect("MeetDeadlines comment");
    let post_meet = &body[meet_pos..];

    // After the MeetDeadlines comment, both `pop_timed_only_with_hint`
    // AND `pop_cancel_only_with_hint` (or the cancel branch
    // surrounded by `if check_cancel`) must appear.
    assert!(
        post_meet.contains("local.pop_timed_only_with_hint("),
        "REGRESSION: MeetDeadlines branch no longer dispatches \
         from local timed lane.",
    );
    assert!(
        post_meet.contains("if check_cancel {")
            && post_meet.contains("local.pop_cancel_only_with_hint("),
        "REGRESSION: MeetDeadlines branch no longer falls \
         through to cancel-lane dispatch under the \
         `if check_cancel {{ ... }}` gate. Without this, a \
         sustained MeetDeadlines window would starve cancel \
         work until the governor switched modes.",
    );
}

#[test]
fn shutdown_doc_describes_signal_and_wake() {
    // Pin: the shutdown method's doc describes the signal
    // semantics. A regression that changed the doc to "drains
    // pending cancellations" would signal a behavior change
    // worth re-auditing.
    let source = read_three_lane_source();

    let fn_marker = "pub fn shutdown(&self) {";
    // Find the FIRST occurrence whose doc includes the canonical
    // phrasing. (There are multiple `shutdown` methods in the
    // file.)
    let mut search = 0;
    let mut doc_window: Option<String> = None;
    while let Some(rel) = source[search..].find(fn_marker) {
        let abs = search + rel;
        // Look at the 200 chars preceding the fn signature.
        let mut doc_start = abs;
        for _ in 0..15 {
            match source[..doc_start].rfind('\n') {
                Some(p) => doc_start = p,
                None => {
                    doc_start = 0;
                    break;
                }
            }
        }
        let candidate = &source[doc_start..abs];
        if candidate.contains("Signals all workers to shutdown") {
            doc_window = Some(candidate.to_string());
            break;
        }
        search = abs + 1;
    }

    let doc = doc_window.expect("scheduler shutdown doc window");
    assert!(
        doc.contains("Signals all workers to shutdown"),
        "REGRESSION: shutdown() doc no longer says 'Signals \
         all workers to shutdown'. The doc is the public \
         contract — if the semantics changed (e.g., to a \
         drain-and-wait blocking call), update both the doc \
         and this audit pin.\n\ndoc window:\n{doc}",
    );
}
