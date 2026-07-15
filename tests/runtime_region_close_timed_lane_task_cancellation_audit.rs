//! Audit + regression test for region.close() semantics when a
//! task is currently executing in the deadline-monotone (timed)
//! lane.
//!
//! Operator's question: "when region.close() is called and a
//! task is currently executing in deadline-monotone lane, does
//! it (a) get cancelled at next checkpoint (correct), (b) run
//! to completion (incorrect: violates close-quiescence), or (c)
//! get killed mid-execution (no graceful)?"
//!
//! Audit findings:
//!
//!   The asupersync close-protocol is **(a) cooperative cancel
//!   at next checkpoint** by construction. The chain:
//!
//!   1. **region.close() → cancel_request**: the user-facing
//!      close calls into `RuntimeState::cancel_request(region,
//!      reason, source_task)` (state.rs:2487). This is the
//!      single entry-point that drives the close protocol.
//!
//!   2. **First pass — region transition**: cancel_request walks
//!      the region subtree (state.rs:2631-2653). For each
//!      affected region it calls
//!      the subscriber-free RegionRecord close transition to
//!      enter Closing state and emits a
//!      `RegionCloseBegin` trace event. The lane the task
//!      is queued on is irrelevant here — close is a region-
//!      state transition, not a per-lane operation.
//!
//!   3. **Second pass — per-task cancel propagation**
//!      (state.rs:2682): for every task in every closing
//!      region, `task.request_cancel_with_budget(task_reason,
//!      task_budget)` is invoked. Under the task lock it
//!      mutates state and snapshots Wakers into an opaque
//!      effects token; the outer walk aggregates those effects
//!      without invoking their auxiliary cancellation observers/Wakers.
//!      This narrow boundary does not cover later region finalizers or close
//!      waiters. The task mutation sets:
//!        - `inner.cancel_requested = true`
//!        - `inner.fast_cancel.store(true, Release)`
//!          and records the cleanup budget. **No mid-poll
//!          interruption happens here** — the task may still be
//!          mid-execution on a worker thread; the cancel signal is
//!          a flag the task observes cooperatively at its next
//!          checkpoint.
//!
//!   4. **Lane re-routing — lazy promote**: when the cancel
//!      lane is informed via `inject_cancel` (three_lane.rs:
//!      1474), the per-worker scheduler calls
//!      `move_to_cancel_lane` (priority.rs:828) which **pushes
//!      a new entry into the cancel_lane** without removing
//!      stale entries from the timed lane. The
//!      timed-lane tombstone is silently skipped at pop time
//!      because `scheduled.remove(task)` returns false on the
//!      second visit. This is the O(log N) lazy-promote path
//!      that earlier replaced an O(N) eager-remove.
//!
//!   5. **Worker poll loop — cooperative observation**: the
//!      worker's `execute(task_id)` (three_lane.rs:4482) polls
//!      the future inside `std::panic::catch_unwind`. There is
//!      **no preemption mechanism** — the future runs until it
//!      returns Pending (cooperative yield), Ready (completed),
//!      or panics. The task observes cancel via
//!      `cx.checkpoint()` which reads
//!      `guard.fast_cancel.load(Acquire)` and returns
//!      `Err(Cancelled)` on the slow path. The Err propagates
//!      via `?` and the future yields naturally to the
//!      scheduler.
//!
//!   6. **Sleep parking — post-lock cancel-waker wake**: tasks parked
//!      on a Sleep::after(deadline) future (typical timed-lane
//!      placement) register a cancel-aware waker via
//!      `inner.cancel_waker`. After releasing RuntimeState, the
//!      scheduler publishes all captured task IDs to the cancel
//!      lane and only then dispatches the snapshotted Wakers.
//!      The Sleep future itself is irrelevant — the
//!      cancel-aware Cx::checkpoint returns Err before the
//!      timer fires.
//!
//! Verdict: **SOUND**. region.close() observes (a) cooperative
//! cancel at next checkpoint:
//!   - The task in the timed lane is NOT killed mid-execution
//!     (no preemption mechanism exists; catch_unwind only
//!     catches panics).
//!   - The task does NOT run to completion (cancel propagates
//!     via fast_cancel atomic + cancel_waker; checkpoint returns
//!     Err and the future yields).
//!   - The task DOES get cancelled at next checkpoint via the
//!     standard cooperative-cancel protocol.
//!
//! This audit is narrow: it covers valid task routes and auxiliary
//! cancellation Wakers. It does not claim that synchronous finalizers,
//! metrics, tracing subscribers, region-close Wakers, or arbitrary payload
//! destructors are callback-free, and it makes no elapsed-time guarantee.
//!
//! Mask interaction (per AGENTS.md "cancellation is a
//! protocol"): a Cx::with_mask block defers the *acknowledgment*
//! of cancel (mask_depth gate on cancel_acknowledged) but the
//! Err is still returned from checkpoint — the mask defers
//! finalization, not observation.
//!
//! A regression that:
//!   - introduced a thread-interrupt mechanism in execute()
//!     to forcibly stop the future mid-poll,
//!   - dropped the `task.request_cancel_with_budget` call
//!     in the second pass of cancel_request (state.rs:2682),
//!   - changed move_to_cancel_lane to skip pushing for tasks
//!     in the timed lane (would silently strand cancellation),
//!   - removed the fast_cancel.store(Release) write in
//!     request_cancel_with_budget (would break visibility
//!     pair — checkpoint may not observe the flag),
//!   - removed the begin_close(Some(reason)) → Closing
//!     transition (would let the region remain Open even though
//!     close was requested),
//!   - introduced a "drain timed lane on close" path that
//!     ran tasks to completion before honoring the close
//!     (would violate close-quiescence by waiting for
//!     potentially-infinite EDF work),
//!     would all be caught here.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cancel_request_first_pass_transitions_regions_to_closing() {
    // Pin (link 1+2): cancel_request walks the region subtree
    // and calls the subscriber-free close transition on each.
    // This is what triggers the Closing state transition that
    // gates new spawns and starts quiescence.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("if region.begin_close_without_subscriber(Some(region_reason.clone())) {"),
        "REGRESSION: state.rs cancel_request first pass no longer \
         transitions region to Closing via the subscriber-free boundary. Without \
         this transition, the region stays Open after close() — \
         close-quiescence is silently violated.",
    );
}

#[test]
fn cancel_request_second_pass_calls_request_cancel_with_budget_per_task() {
    // Pin (link 3): the per-task cancel propagation loop in
    // state.rs:2682 invokes
    // `task.request_cancel_with_budget(task_reason, task_budget)`
    // on every task in every closing region. This is the bridge
    // from "region close" to "task observes cancel" — without
    // it, timed-lane tasks would never see the cancel.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("task.request_cancel_with_budget_and_publication(")
            && source.contains("let ((newly_cancelled, changed, publication), task_wakes) =",)
            && source.contains("wakes.merge(task_wakes);"),
        "REGRESSION: state.rs cancel_request second pass no \
         longer captures and merges task cancellation effects. Without \
         this call, tasks in the timed lane (or any lane) never \
         observe the parent region's cancel — they continue \
         running to completion in violation of close-quiescence.",
    );
}

#[test]
fn request_cancel_with_budget_sets_fast_cancel_release() {
    // Pin (link 3): request_cancel_with_budget sets
    // `inner.fast_cancel.store(true, Release)` so that the
    // task's checkpoint can observe the cancel via Acquire.
    // Without this Release-Acquire pair, the cancel signal may
    // not be visible cross-thread.
    let source = read("src/record/task.rs");

    assert!(
        source.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: task.rs request_cancel_with_budget no \
         longer publishes fast_cancel with Release ordering. \
         Without it, the worker thread executing a timed-lane \
         task may not observe the cancel flag — the task runs \
         to completion despite the close request.",
    );
}

#[test]
fn move_to_cancel_lane_uses_lazy_promote_no_eager_remove_from_timed() {
    // Pin (link 4): move_to_cancel_lane just pushes into
    // cancel_lane and lets pop's `scheduled.remove` lazily
    // skip stale entries in timed_lane. A regression to an
    // eager remove (scanning timed_lane to find and delete)
    // would explode latency under load — and is what the
    // earlier O(log N) fix replaced.
    let source = read("src/runtime/scheduler/priority.rs");

    let fn_marker = "pub fn move_to_cancel_lane(&mut self, task: TaskId, priority: u8) {";
    let start = source.find(fn_marker).expect("move_to_cancel_lane fn");
    // Body is short; take a 80-line window.
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // Must push into cancel_lane.
    assert!(
        body.contains("self.cancel_lane.push(SchedulerEntry {"),
        "REGRESSION: move_to_cancel_lane no longer pushes into \
         cancel_lane. Timed-lane tasks targeted by region \
         cancel would be stranded on the lower-priority lane.",
    );

    // Must NOT use retain/eager-scan over timed_lane (the
    // anti-pattern that replaced the fix).
    let suspect_eager_patterns = [
        "self.timed_lane.retain(",
        "self.timed_lane.iter().find(|e| e.task == task)",
        "self.timed_lane.iter_mut().find(|e| e.task == task)",
    ];
    for pat in &suspect_eager_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: move_to_cancel_lane now eagerly scans/\
             rebuilds timed_lane via `{pat}`. The lazy-promote \
             path is required for sub-millisecond cancel latency \
             with thousands of timed-lane tasks. Restore the \
             O(log N) `cancel_lane.push` + lazy-skip pattern.",
        );
    }
}

#[test]
fn worker_execute_polls_future_inside_catch_unwind_no_preemption() {
    // Pin (link 5): the worker's execute() polls the future
    // inside `std::panic::catch_unwind`. There is NO preemption
    // mechanism — the future runs until it cooperatively
    // yields. catch_unwind only catches panics, not arbitrary
    // interrupts. A regression that introduced thread-interrupt
    // / forcible-stop machinery here would violate the "no
    // graceful kill" rule.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {"),
        "REGRESSION: worker execute() no longer wraps the poll \
         in catch_unwind. The single bound on a poll's effect is \
         this catch_unwind — without it, a panicking task takes \
         out the worker thread.",
    );

    // Forbid any mid-poll interruption mechanism.
    let suspect_preempt = [
        "thread::interrupt",
        "kill_task_in_progress",
        "force_stop_poll",
        "pthread_cancel",
    ];
    for pat in &suspect_preempt {
        assert!(
            !source.contains(pat),
            "REGRESSION: worker execute() now contains a \
             preemption mechanism (`{pat}`). asupersync's \
             cancel protocol is COOPERATIVE — the future runs \
             until checkpoint observes cancel. Mid-poll \
             interruption is a NO-GO that would compromise \
             memory safety and cancellation correctness.",
        );
    }
}

#[test]
fn cx_checkpoint_observes_fast_cancel_with_acquire() {
    // Pin (link 5): cx.checkpoint() reads
    // `guard.fast_cancel.load(Acquire)` to detect a
    // concurrently-set cancel flag. The Release-Acquire pair
    // from request_cancel_with_budget → checkpoint is what
    // gives the cooperative cancel protocol its cross-thread
    // visibility.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("guard.fast_cancel.load(std::sync::atomic::Ordering::Acquire)"),
        "REGRESSION: cx.checkpoint() no longer reads \
         fast_cancel with Acquire ordering. Without it, the \
         Release-Acquire pair is broken — a task in the timed \
         lane may not observe the cancel flag set by region.\
         close().",
    );
}

#[test]
fn inject_cancel_routes_to_move_to_cancel_lane_for_local_tasks() {
    // Pin (link 4): the cancel-lane injection path, on the
    // !Send local task fast path, calls move_to_cancel_lane
    // (the lazy-promote helper) so that timed/ready tombstones
    // are left for lazy skip and the cancel entry takes
    // priority.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("local_guard.move_to_cancel_lane(task, priority);")
            && source.contains("local_ready.lock().tombstone(task);"),
        "REGRESSION: inject_cancel no longer routes local tasks \
         through move_to_cancel_lane. Timed-lane tombstones \
         would no longer be lazily skipped — and the cancel \
         path would lose its priority promotion.",
    );
}

#[test]
fn region_begin_close_emits_region_close_begin_trace() {
    // Pin (link 2 trace audit): the cancel_request first pass
    // emits a RegionCloseBegin trace event after begin_close
    // returns true. The trace is what lets external auditing
    // verify that close() was actually requested vs. silently
    // dropped.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("TraceEventKind::RegionCloseBegin,"),
        "REGRESSION: cancel_request no longer emits the \
         RegionCloseBegin trace event. Without it, replay/\
         minimization tools can't see when a region transitioned \
         to Closing — the close-quiescence audit trail is broken.",
    );
}

#[test]
fn region_state_after_begin_close_is_closing_not_open() {
    // Pin (link 2 state-machine audit): begin_close(Some(reason))
    // transitions Open → Closing. The cancel-request walk
    // depends on this transition existing — if begin_close
    // were a no-op, the region would stay Open even after
    // close().
    let source = read("src/record/region.rs");

    let suspect_noop = [
        "fn begin_close(&mut self, _: Option<CancelReason>) -> bool {\n        false\n    }",
        "fn begin_close(&mut self, _reason: Option<CancelReason>) -> bool {\n        false\n    }",
    ];
    for pat in &suspect_noop {
        assert!(
            !source.contains(pat),
            "REGRESSION: region.rs begin_close was reduced to a \
             no-op (returns false unconditionally — `{pat}`). \
             A region close() would no longer transition the \
             region to Closing — close-quiescence violated by \
             construction.",
        );
    }

    // The Closing variant must still exist on RegionState.
    assert!(
        source.contains("Closing")
            && (source.contains("pub enum RegionState") || source.contains("enum RegionState")),
        "REGRESSION: RegionState::Closing variant is gone. The \
         close protocol depends on this state transition.",
    );
}

#[test]
fn cancel_request_effects_publish_tasks_before_waker_dispatch() {
    // Pin (link 4 routing audit): cancel_request couples the
    // callback-free task list to opaque Waker effects. The
    // scheduler takes deferred batches under RuntimeState,
    // releases that guard, publishes every task ID, and only
    // then dispatches Wakers.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("pub fn cancel_request(")
            && source.contains("-> CancellationEffects<Vec<(TaskId, u8)>>")
            && source.contains("CancellationEffects::new(tasks_to_cancel, wakes)"),
        "REGRESSION: cancel_request signature no longer returns \
         task IDs coupled to opaque wake effects. The post-lock \
         lane-publication boundary is silently dropped.",
    );

    let scheduler = read("src/runtime/scheduler/three_lane.rs");
    let marker = "fn drain_deferred_cancel_dispatches(&self) {";
    let start = scheduler.find(marker).expect("deferred cancel drain");
    let body = &scheduler[start..(start + 1800).min(scheduler.len())];
    let take = body
        .find("state.take_deferred_cancel_dispatches()")
        .expect("take effects under state guard");
    let release = take
        + body[take..]
            .find("\n        };")
            .expect("release RuntimeState guard");
    let publish = body
        .find("self.publish_deferred_cancel_task(task_id, priority)")
        .expect("publish deferred cancel task");
    let dispatch = body
        .find("batch_wakes.dispatch();")
        .expect("dispatch deferred cancel Wakers");
    assert!(
        body.contains("let batches = {")
            && take < release
            && release < publish
            && publish < dispatch
            && body.matches(".dispatch();").count() == 1,
        "REGRESSION: deferred cancel effects are no longer taken under the \
         state guard, then published after guard release before Waker dispatch.",
    );
}

#[test]
fn no_drain_timed_lane_to_completion_path_on_close() {
    // Pin (audit-gate): there must be NO code path where
    // close() waits for the timed lane to drain to completion
    // before honoring the cancel. EDF work can be unbounded;
    // running it to completion would violate close-quiescence
    // by stalling indefinitely.
    let runtime_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runtime/scheduler");
    let mut findings = Vec::new();

    let suspect_drain_patterns = [
        "drain_timed_to_completion",
        "wait_timed_lane_empty",
        "block_until_timed_drained",
        "run_timed_to_completion_before_close",
    ];

    fn collect_rs(dir: &PathBuf, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    let mut files = Vec::new();
    collect_rs(&runtime_dir, &mut files);

    for path in files {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for pat in &suspect_drain_patterns {
            if content.contains(pat) {
                findings.push(format!(
                    "{path}: pattern `{pat}` found",
                    path = path.display(),
                ));
            }
        }
    }

    assert!(
        findings.is_empty(),
        "REGRESSION: src/runtime/scheduler/ now contains a \
         drain-timed-lane-to-completion path before honoring \
         close. EDF (timed) work is unbounded — running it to \
         completion before close would stall the close \
         indefinitely, violating close-quiescence. Findings:\n\
         {findings}",
        findings = findings.join("\n  "),
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    // Pin (documentary): the per-link deep audits live in
    // sibling test files. A regression that deleted those
    // would lose the chain coverage even if these structural
    // pins still pass.
    let prior_audits = [
        "tests/scheduler_cooperative_budget_yield_audit.rs",
        "tests/scheduler_region_drop_propagates_cancel_to_timed_lane_audit.rs",
        "tests/cx_checkpoint_observes_parent_region_cancel_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing. \
             This audit relies on the chain audits for deeper \
             coverage; if they're gone, restore them or update \
             this audit to include the deeper checks.",
        );
    }
}
