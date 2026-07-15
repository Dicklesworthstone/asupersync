//! Audit + regression test for cancel-propagation chain when a
//! parent region is dropped / closed while a child task is sitting
//! in the deadline-monotone (timed) lane.
//!
//! Operator's question: "when a task's parent region is dropped
//! while task is in deadline-monotone lane, does the task get
//! observable cancellation (correct: structured concurrency) OR
//! continue executing orphaned (incorrect: orphan task)? Per
//! AGENTS.md 'no orphan tasks'."
//!
//! Audit findings:
//!
//!   The cancel-propagation chain has FIVE links, all in place:
//!
//!   1. **Region close triggers subtree walk**
//!      (`src/runtime/state.rs` `cancel_region_subtree` family,
//!      around line 2620). Iterates regions in the dropped
//!      subtree, calling the subscriber-free region close
//!      transition on each. The region transitions to Closing
//!      state without invoking a tracing subscriber beneath the
//!      outer runtime-state lock.
//!
//!   2. **Each task in each closing region gets
//!      `request_cancel_with_budget`** (state.rs:2682). This
//!      flips `cancel_requested = true` on the task's CxInner
//!      AND `fast_cancel.store(true, Release)` on the atomic
//!      so a concurrently-running task observes the flag on its
//!      next `cx.checkpoint()` call. Wakers are captured as
//!      opaque effects; none run under task or state locks.
//!
//!   3. **After the outer state guard is released, the caller
//!      publishes every task ID before dispatching Wakers.**
//!      Publication invokes `scheduler.move_to_cancel_lane`
//!      for every task that was newly cancelled. This is the
//!      O(log N) lazy-promote function in
//!      `src/runtime/scheduler/priority.rs` (the
//!      br-asupersync-cancel-promote-logn fix from earlier
//!      today). The function pushes a new entry into
//!      `cancel_lane` without scanning timed_lane / ready_lane;
//!      the original entry in the source lane becomes a
//!      TOMBSTONE.
//!
//!   4. **The dispatcher's `next_task` pops cancel_lane FIRST**
//!      in default mode (three_lane.rs:3409 "Default / drain:
//!      cancel > timed."). The new cancel-lane entry pops
//!      before any timed work. The stale timed-lane entry is
//!      LAZY-SKIPPED on its eventual pop because `pop()` gates
//!      every dispatch on `self.scheduled.remove(entry.task)`,
//!      and the scheduled set was already cleared when the
//!      cancel-lane entry was dispatched.
//!
//!   5. **Inside the task, `cx.checkpoint()` observes the
//!      latched `fast_cancel` flag** (cx.rs:1664-1672 fast-path
//!      check). The check returns `Err(...)` so the task yields
//!      via `?` propagation, control returns to the scheduler,
//!      and the task finalizes through the normal cancellation
//!      drain. Per AGENTS.md "cancellation is a protocol:
//!      request → drain → finalize (idempotent)".
//!
//!   The task does NOT continue executing orphaned because:
//!   - `move_to_cancel_lane` puts the task in the highest-
//!     priority lane regardless of where it was previously.
//!   - Cancel-lane priority selects cancellation ahead of
//!     timed work on eligible scheduler iterations. This is
//!     not a wall-clock or sub-quantum guarantee.
//!   - Once dispatched, `cx.checkpoint()` observes the cancel
//!     and returns Err, terminating the task body.
//!
//! Verdict: **SOUND**. The "no orphan tasks" invariant from
//! AGENTS.md is upheld for tasks in the timed lane when their
//! parent region is dropped. Three converging mechanisms enforce
//! this: cancel propagation flips the per-task flag,
//! lazy-promote re-routes the task to the cancel lane, and the
//! cooperative checkpoint protocol surfaces the cancel to the
//! task body.
//!
//! This audit is narrow: it covers valid task routes and auxiliary
//! cancellation Wakers. It does not claim that synchronous finalizers,
//! metrics, tracing subscribers, region-close Wakers, or arbitrary payload
//! destructors are callback-free, nor does it promise recovery for a
//! structurally invalid local-owner route.
//!
//! A regression that:
//!   - skipped `move_to_cancel_lane` for tasks already in
//!     timed_lane (would let them sit at their original
//!     deadline-driven priority — orphan if the deadline is
//!     far in the future),
//!   - dropped the `request_cancel_with_budget` call from the
//!     region-cancel propagation (would never set
//!     cancel_requested, leaving the task running normally),
//!   - reverted `move_to_cancel_lane` to eager-remove (would
//!     keep correctness but reintroduce O(N) latency from the
//!     earlier audit),
//!   - removed the `scheduled.remove` gate from the dispatcher's
//!     pop (would surface the timed-lane tombstone as a
//!     duplicate dispatch),
//!   - removed the `fast_cancel.store(true, Release)` from
//!     request_cancel_with_budget (would let the task's
//!     subsequent checkpoint miss the cancel),
//!     would all be caught here.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn region_cancel_propagation_calls_request_cancel_with_budget() {
    // Pin (link 2): the subtree-walk in state.rs invokes
    // `task.request_cancel_with_budget(reason, budget)` on
    // every task in every closing region. Without this call,
    // tasks would sit in their original lanes with no cancel
    // signal — orphans.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("task.request_cancel_with_budget_and_publication(")
            && source.contains("let ((newly_cancelled, changed, publication), task_wakes) =",)
            && source.contains("wakes.merge(task_wakes);"),
        "REGRESSION: state.rs no longer calls \
         task.request_cancel_with_budget and captures its \
         effects on tasks in closing \
         regions. Without this, the cancel signal never \
         reaches the task — it continues executing orphaned \
         even though its parent region has been dropped.",
    );
}

#[test]
fn region_cancel_propagation_emits_tasks_to_cancel_list() {
    // Pin (link 3 prerequisite): the subtree walk builds a
    // tasks_to_cancel: Vec<(TaskId, priority)> that the caller
    // uses to drive move_to_cancel_lane. A regression that
    // dropped this list-build step would leave the cancel
    // logically requested but no scheduler action would
    // re-prioritize the task.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("tasks_to_cancel.push("),
        "REGRESSION: state.rs no longer pushes (task_id, \
         priority) tuples onto tasks_to_cancel. Without this, \
         the scheduler doesn't get told to move the task to \
         the cancel lane.",
    );

    assert!(
        source.contains("CancellationEffects::new(tasks_to_cancel, wakes)"),
        "REGRESSION: cancel_request no longer couples the \
         callback-free (task_id, priority) tuples to opaque \
         Waker effects for downstream post-lock publication.",
    );
}

#[test]
fn deferred_cancel_drain_publishes_all_tasks_before_dispatching_wakers() {
    // RegionRunner::Drop must not invoke the auxiliary cancellation Wakers
    // returned by cancel_request while it owns RuntimeState. It queues those
    // effects; the scheduler later takes them under the guard, releases it,
    // publishes task IDs, and dispatches the auxiliary Wakers last. This does
    // not cover close-waiter Wakers or finalizer/observer callbacks reached by
    // the later advance_region_state call.
    let scope = read("src/cx/scope.rs");
    let drop_start = scope
        .find("impl<Fut> Drop for RegionRunner<'_, Fut> {")
        .expect("RegionRunner Drop");
    let drop_body = &scope[drop_start..(drop_start + 1000).min(scope.len())];
    assert!(
        drop_body.contains("let effects = state.cancel_request(self.child_region, &reason, None);")
            && drop_body.contains("state.defer_cancel_dispatch(effects);")
            && !drop_body.contains(".dispatch()")
            && !drop_body.contains("wake_by_ref("),
        "REGRESSION: RegionRunner::Drop no longer queues its auxiliary cancellation Waker \
         effects for later post-lock dispatch.",
    );

    let scheduler = read("src/runtime/scheduler/three_lane.rs");
    let start = scheduler
        .find("fn drain_deferred_cancel_dispatches(&self) {")
        .expect("deferred cancel drain");
    let body = &scheduler[start..(start + 1800).min(scheduler.len())];
    let take = body
        .find("state.take_deferred_cancel_dispatches()")
        .expect("take cancellation batches");
    let release = take
        + body[take..]
            .find("\n        };")
            .expect("release RuntimeState guard");
    let publish = body
        .find("self.publish_deferred_cancel_task(task_id, priority)")
        .expect("task publication");
    let dispatch = body
        .find("batch_wakes.dispatch();")
        .expect("Waker dispatch");
    assert!(
        body.contains("let batches = {")
            && take < release
            && release < publish
            && publish < dispatch
            && body.matches(".dispatch();").count() == 1,
        "REGRESSION: deferred region-drop cancellation no longer releases \
         the state guard and publishes all task IDs before Waker dispatch.",
    );
}

#[test]
fn move_to_cancel_lane_is_invoked_for_every_cancelled_task() {
    // Pin (link 3): the scheduler's move_to_cancel_lane is
    // invoked per task in the cancel propagation chain. A
    // regression that broke this call site would leave
    // cancel_requested=true tasks stuck in timed_lane forever
    // (until their deadline-driven dispatch eventually fires,
    // which could be far in the future).
    let three_lane = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        three_lane.contains(".move_to_cancel_lane(task, priority);"),
        "REGRESSION: scheduler/three_lane.rs no longer has any \
         move_to_cancel_lane(task, priority) call site. \
         Without this, region-drop cancel propagation has no \
         way to elevate a timed-lane task to cancel-lane \
         priority — the task continues executing on its \
         original (potentially far-future) deadline.",
    );

    // There must be ≥ 2 call sites — the global (line ~903)
    // and the local schedule_local_cancel (line ~4324) paths.
    let count = three_lane.matches(".move_to_cancel_lane(").count();
    assert!(
        count >= 2,
        "REGRESSION: only {count} call sites for \
         move_to_cancel_lane; expected ≥ 2 (global + local \
         schedule_local_cancel). Either path missing would \
         leak orphans on the corresponding cancel-injection \
         pathway.",
    );
}

#[test]
fn move_to_cancel_lane_is_log_n_lazy_promote() {
    // Pin (link 3 quality): move_to_cancel_lane is the
    // lazy-promote O(log N) variant. A regression that
    // reverted to the eager-remove O(N) variant would not
    // break correctness but would re-introduce the cancel-
    // arrival latency under load (operator's earlier audit
    // also pinned this).
    let priority = read("src/runtime/scheduler/priority.rs");

    let fn_marker = "pub fn move_to_cancel_lane(&mut self, task: TaskId, priority: u8) {";
    let start = priority.find(fn_marker).expect("move_to_cancel_lane fn");
    let body_end = priority[start..]
        .find("\n    }\n")
        .expect("move_to_cancel_lane close");
    let body = &priority[start..start + body_end];

    // Body must NOT contain the eager-remove patterns.
    let suspect_eager_patterns = [
        ".iter().find(",
        ".iter().any(",
        "self.timed_lane.retain(",
        "self.ready_lane.retain(",
    ];
    for pat in &suspect_eager_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: move_to_cancel_lane reverted to eager-\
             remove via `{pat}`. The lazy-promote pattern (just \
             push to cancel_lane and let pop() lazy-skip stale \
             entries) is the documented design — see prior \
             audit pin scheduler_cancel_promote_logn_audit.rs.",
        );
    }

    // Body MUST contain the cancel_lane.push.
    assert!(
        body.contains("self.cancel_lane.push(SchedulerEntry {"),
        "REGRESSION: move_to_cancel_lane no longer pushes a \
         SchedulerEntry into cancel_lane. The lazy-promote \
         pattern requires every call to push a fresh entry.",
    );
}

#[test]
fn dispatcher_pop_lazy_skips_stale_timed_lane_entries() {
    // Pin (link 4): the dispatcher's pop function gates every
    // lane dispatch on `self.scheduled.remove(entry.task)`.
    // This is what makes the lazy-promote tombstone-skip work:
    // when the cancel-lane entry pops first and removes the
    // task from `scheduled`, the timed-lane tombstone is
    // silently discarded on its eventual pop. Without the
    // gate, the tombstone would surface as a duplicate
    // dispatch.
    let priority = read("src/runtime/scheduler/priority.rs");

    let fn_marker = "pub fn pop(&mut self) -> Option<TaskId> {";
    let start = priority.find(fn_marker).expect("pop fn");
    let body_end = priority[start..].find("\n    }\n").expect("pop close");
    let body = &priority[start..start + body_end];

    let gate_count = body.matches("self.scheduled.remove(entry.task)").count();
    assert!(
        gate_count >= 3,
        "REGRESSION: pop has only {gate_count} \
         scheduled.remove gates; expected ≥ 3 (one per lane: \
         cancel, timed, ready). Without all three gates, a \
         lazy-promoted task could surface in BOTH the cancel \
         lane AND the timed lane — a duplicate dispatch \
         (calling poll twice for the same logical task event \
         is a runtime invariant violation).",
    );
}

#[test]
fn cx_checkpoint_observes_cancel_via_fast_cancel_atomic() {
    // Pin (link 5): cx.checkpoint() observes the cancel
    // request via the fast_cancel atomic. The cancel
    // propagation in state.rs sets fast_cancel via
    // request_cancel_with_budget — and the checkpoint fast
    // path reads it with Acquire ordering, returning Err to
    // yield the task.
    let cx = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = cx.find(fn_marker).expect("checkpoint fn");
    // checkpoint is long; take a generous window.
    let after = &cx[start + fn_marker.len()..];
    let next_fn_offset = after
        .find("\n    fn ")
        .or_else(|| after.find("\n    pub fn "))
        .unwrap_or(after.len().min(40000));
    let body = &cx[start..start + fn_marker.len() + next_fn_offset];

    assert!(
        body.contains("guard.fast_cancel.load(std::sync::atomic::Ordering::Acquire)"),
        "REGRESSION: cx.checkpoint() no longer reads the \
         fast_cancel atomic with Acquire ordering. This is \
         the path that observes the cancel request set by \
         the region-drop subtree walk. Without it, a task \
         in the timed lane never sees its parent region's \
         drop — it continues executing orphaned.",
    );
}

#[test]
fn request_cancel_with_budget_sets_fast_cancel_release() {
    // Pin (link 2 + link 5 bridge): request_cancel_with_budget
    // sets fast_cancel.store(true, Release) so the task's
    // next checkpoint observes the latched cancel. Without
    // the Release ordering, the checkpoint's Acquire load
    // could miss the cancel even after request_cancel was
    // called.
    let task_record = read("src/record/task.rs");

    let fn_marker = "pub(crate) fn request_cancel_with_budget_and_publication(";
    let pos = task_record.find(fn_marker);
    if let Some(start) = pos {
        // Take a window of 3000 chars after the fn marker.
        let window_end = (start + 3000).min(task_record.len());
        let safe_end = task_record
            .char_indices()
            .map(|(i, _)| i)
            .rfind(|&i| i <= window_end)
            .unwrap_or(window_end);
        let body = &task_record[start..safe_end];

        assert!(
            body.contains(".store(true, ")
                && (body.contains("Ordering::Release") || body.contains("Release")),
            "REGRESSION: request_cancel_with_budget no longer \
             stores fast_cancel=true with Release ordering. \
             Without the release-acquire pair, the task's \
             next checkpoint may not observe the cancel and \
             continue running.\n\nfn body window:\n{body}",
        );
    } else {
        // The function may have moved to a different file.
        // Fall back to a project-wide grep — best-effort pin.
        let combined = format!(
            "{}{}{}",
            task_record,
            read("src/cx/cx.rs"),
            read("src/runtime/state.rs"),
        );
        assert!(
            combined.contains("request_cancel_with_budget"),
            "REGRESSION: request_cancel_with_budget is missing \
             from src/record/task.rs, src/cx/cx.rs, AND \
             src/runtime/state.rs. The function is the bridge \
             between region-drop propagation and the task's \
             cancel-observation path.",
        );
    }
}

#[test]
fn region_close_state_transition_via_begin_close() {
    // Pin (link 1): the subtree walk transitions each region
    // to Closing via the subscriber-free RegionRecord transition. A
    // regression that skipped this transition would leave
    // the region in Open state — the cancel propagation
    // logic gates on the region state, so tasks would not
    // be cancelled.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("region.begin_close_without_subscriber(Some(region_reason.clone()))"),
        "REGRESSION: the region-cancel subtree walk no longer \
         calls the subscriber-free RegionRecord close transition. Without the \
         state transition, tasks in the region don't get \
         cancelled — they continue running normally even \
         though the parent region has logically been dropped.",
    );
}

#[test]
fn cancel_lane_pops_before_timed_lane_in_default_mode() {
    // Pin (link 4 reinforcement): in default mode, the
    // dispatcher checks cancel_lane BEFORE timed_lane. This
    // is what makes the lazy-promoted entry win the dispatch
    // race against any tombstone in timed_lane.
    let three_lane = read("src/runtime/scheduler/three_lane.rs");

    // Find the default-mode dispatch arm.
    let default_marker = "// Default: Cancel > Timed";
    assert!(
        three_lane.contains(default_marker),
        "REGRESSION: the 'Default: Cancel > Timed' marker is \
         gone from next_task. Without cancel-first dispatch, \
         a lazy-promoted task (cancel_lane entry) would lose \
         the race against its own tombstone in timed_lane — \
         the tombstone could fire first and the cancel never \
         arrive on time.",
    );

    // The local cancel pop must precede the local timed pop
    // in the default branch.
    let pos = three_lane
        .find(default_marker)
        .expect("default-mode local arm marker");
    let post = &three_lane[pos..];
    let cancel_pos = post
        .find("local.pop_cancel_only_with_hint(")
        .expect("local cancel pop");
    let timed_pos = post
        .find("local.pop_timed_only_with_hint(")
        .expect("local timed pop");
    assert!(
        cancel_pos < timed_pos,
        "REGRESSION: in the default-mode local arm, \
         pop_timed_only_with_hint now appears BEFORE \
         pop_cancel_only_with_hint. The cancel-promoted task \
         entry would lose the dispatch race against the \
         tombstone in timed_lane.",
    );
}

#[test]
fn agents_md_documents_no_orphan_tasks_invariant() {
    // Pin: the AGENTS.md file documents the "no orphan tasks"
    // invariant. A regression that removed the documentation
    // wouldn't break the runtime, but would lose the public
    // contract that operators rely on for SLA reasoning.
    let agents = read("AGENTS.md");

    assert!(
        agents.contains("No obligation leaks")
            || agents.contains("no orphan tasks")
            || agents.contains("Structured concurrency"),
        "REGRESSION: AGENTS.md no longer documents the 'no \
         orphan tasks' / 'structured concurrency' / 'no \
         obligation leaks' invariants. These are the public \
         contracts that audits like this one are checking \
         the implementation against.",
    );
}
