//! Audit + regression test for `src/runtime/scheduler/three_lane.rs`
//! per-worker FIFO lane fairness and work-locality.
//!
//! Operator's question: "when worker-A spawns task X and worker-B
//! spawns task Y at the same instant, does each worker dispatch
//! its own first (work-locality, correct) or is there a global
//! FIFO that serializes (incorrect: bottleneck)?"
//!
//! Audit findings:
//!
//!   The asupersync 3-lane scheduler uses **per-worker FIFO lanes
//!   with thread-local routing**, NOT a single global FIFO.
//!   Workers dispatch their own spawns first; the global injector
//!   is consulted only as a fallback for cross-thread spawns.
//!
//!   Architecture:
//!
//!   1. **Each `ThreeLaneWorker` has its OWN `fast_queue:
//!      LocalQueue`** (three_lane.rs:1837). The fast_queue is a
//!      per-worker SPMC LocalQueue: only the owning worker
//!      pushes; other workers can steal but cannot push.
//!
//!   2. **Workers bind their fast_queue thread-locally** at
//!      run_loop start (three_lane.rs:3158): `let _queue_guard
//!      = LocalQueue::set_current(self.fast_queue.clone())`.
//!      The bind sets a thread-local `CURRENT_QUEUE` slot to
//!      the worker's own fast_queue.
//!
//!   3. **`LocalQueue::schedule_local(task)`**
//!      (local_queue.rs:144) is the in-worker spawn-routing
//!      primitive. It pushes to the THREAD-LOCAL queue —
//!      i.e., the calling worker's own fast_queue. So a task
//!      running on worker A that calls `spawn(future)` ends
//!      up pushing to A's fast_queue, NOT a global queue.
//!
//!   4. **Worker dispatch in `try_phase3_ready_work`**
//!      (three_lane.rs:3541-3616) consults `self.fast_queue`
//!      BEFORE the global injector:
//!      self.local_ready first, then self.fast_queue.pop()
//!      for this worker's own fast queue, then
//!      self.take_global_ready_task() only if local_ready and
//!      fast_queue are both empty, and finally
//!      self.local.lock().pop_ready_only_with_hint(...) as the
//!      PriorityScheduler heap slow path.
//!
//!   5. **The GlobalInjector is only used for cross-thread
//!      spawns** (e.g., main thread spawns BEFORE the worker
//!      pool starts, or wakeups from non-worker threads).
//!      `Scheduler::inject_ready` (three_lane.rs:1597) calls
//!      `inject_global_ready_checked` which feeds the global
//!      injector — but this path is only taken when the
//!      caller is NOT inside a worker thread (no thread-local
//!      CURRENT_QUEUE bound).
//!
//!   So when worker A spawns task X and worker B spawns task Y
//!   simultaneously:
//!     - X lands in A's fast_queue (A's `LocalQueue::
//!       schedule_local` push).
//!     - Y lands in B's fast_queue (B's push).
//!     - A's next_task pops X from A's fast_queue first.
//!     - B's next_task pops Y from B's fast_queue first.
//!     - No global FIFO serialization.
//!
//! Verdict: **SOUND**. Work-locality is preserved per worker.
//! The architecture is the standard work-stealing pattern
//! (per-thread queue + global fallback + cross-worker stealing)
//! used by tokio, Go, and most production async runtimes.
//!
//! A regression that:
//!   - replaced per-worker fast_queues with a single global
//!     queue (would serialize all spawns through a single
//!     mutex — catastrophic on multi-core systems),
//!   - changed `LocalQueue::schedule_local` to push to a
//!     global slot instead of CURRENT_QUEUE (would route
//!     in-worker spawns through the global injector,
//!     defeating work-locality),
//!   - reordered `try_phase3_ready_work` to check global
//!     before fast_queue (would let cross-thread spawns
//!     starve in-worker spawns under load),
//!   - removed `LocalQueue::set_current` from worker
//!     run_loop (would leave CURRENT_QUEUE unset, forcing
//!     all in-worker spawns through the global path),
//!     would all be caught here.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn source_window(source: &str, start: usize, len: usize) -> &str {
    let mut end = start.saturating_add(len).min(source.len());
    while !source.is_char_boundary(end) {
        end -= 1;
    }
    &source[start..end]
}

#[test]
fn each_worker_has_its_own_fast_queue_field() {
    // Pin: ThreeLaneWorker has a `fast_queue: LocalQueue`
    // field — per-worker, not shared. A regression that
    // replaced this with a shared `Arc<GlobalInjector>`
    // would serialize all spawns through a single queue.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let struct_marker = "pub struct ThreeLaneWorker {";
    let start = source.find(struct_marker).expect("ThreeLaneWorker struct");
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("ThreeLaneWorker close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("pub fast_queue: LocalQueue,"),
        "REGRESSION: ThreeLaneWorker no longer has a \
         `pub fast_queue: LocalQueue` field. Without per-\
         worker fast queues, all spawns serialize through \
         the global injector — work-locality is gone, and \
         multi-core scaling collapses.\n\nstruct body:\n{body}",
    );

    // Forbid suspect shared-queue patterns that would imply
    // global serialization.
    let suspect_shared_patterns = [
        "fast_queue: Arc<Mutex<",
        "fast_queue: Arc<GlobalInjector",
        "fast_queue: SharedQueue",
    ];
    for pat in &suspect_shared_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: fast_queue field type changed to \
             shared `{pat}`. Per-worker fast queues are SPMC \
             (only the owning worker pushes) — wrapping in a \
             shared mutex would force all spawns through a \
             single critical section.",
        );
    }
}

#[test]
fn worker_run_loop_sets_thread_local_fast_queue() {
    // Pin AUDIT-CRITICAL: worker run_loop binds its own
    // fast_queue to the thread-local CURRENT_QUEUE via
    // LocalQueue::set_current(self.fast_queue.clone()). This
    // is what makes in-worker spawns route to the calling
    // worker's queue (work-locality). A regression that
    // dropped this bind would leave CURRENT_QUEUE unset,
    // forcing all in-worker spawns through the global path.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "pub fn run_loop(&mut self) {";
    let start = source.find(fn_marker).expect("run_loop fn");
    // run_loop is long; take the first ~500 lines for the
    // setup section.
    let body = source_window(&source, start, 500);

    assert!(
        body.contains("LocalQueue::set_current(self.fast_queue.clone())"),
        "REGRESSION: run_loop no longer binds the worker's \
         fast_queue to the thread-local CURRENT_QUEUE via \
         LocalQueue::set_current. Without this bind, \
         schedule_local has no thread-local queue to push \
         to — every in-worker spawn falls through to the \
         global injector, defeating work-locality.\n\n\
         run_loop setup:\n{body}",
    );
}

#[test]
fn schedule_local_pushes_to_current_thread_local_queue() {
    // Pin AUDIT-CRITICAL: LocalQueue::schedule_local reads
    // the thread-local CURRENT_QUEUE slot and pushes to it.
    // This is the load-bearing in-worker spawn primitive.
    // A regression that pushed to a shared queue instead
    // would silently break work-locality.
    let source = read("src/runtime/scheduler/local_queue.rs");

    let fn_marker = "pub(crate) fn schedule_local(task: TaskId) -> bool {";
    let start = source.find(fn_marker).expect("schedule_local fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("schedule_local close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("CURRENT_QUEUE.with("),
        "REGRESSION: LocalQueue::schedule_local no longer \
         reads CURRENT_QUEUE.with(...). Without thread-local \
         dispatch, the function has no way to find the \
         calling worker's fast_queue — falls through to a \
         shared / global path.\n\nfn body:\n{body}",
    );

    assert!(
        body.contains("schedule_local_push(task)"),
        "REGRESSION: schedule_local no longer calls \
         schedule_local_push on the thread-local queue. The \
         _push is the SPMC-safe push primitive that only the \
         owning worker can call.",
    );
}

#[test]
fn try_phase3_checks_fast_queue_before_global() {
    // Pin AUDIT-CRITICAL: try_phase3_ready_work checks
    // self.fast_queue.pop() BEFORE take_global_ready_task().
    // This is the per-worker locality preference: worker A
    // dispatches its OWN spawned tasks before consulting the
    // shared global injector / prefetch buffer boundary.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "fn try_phase3_ready_work(&mut self) -> Option<TaskId> {";
    let start = source.find(fn_marker).expect("try_phase3_ready_work");
    let body_end = source[start..].find("\n    }\n").expect("phase3 close");
    let body = &source[start..start + body_end];

    let fast_pos = body
        .find("self.fast_queue.pop()")
        .expect("self.fast_queue.pop() call");
    let global_pos = body
        .find("self.take_global_ready_task()")
        .expect("take_global_ready_task call");

    assert!(
        fast_pos < global_pos,
        "REGRESSION: try_phase3_ready_work now checks the \
         global injector BEFORE the per-worker fast_queue. \
         This silently elevates cross-thread spawns over \
         in-worker spawns — under load, a worker's own \
         spawned tasks could starve while it dispatches \
         work injected from main().\n\n\
         fast_queue position: {fast_pos}\n\
         global-ready position: {global_pos}",
    );
}

#[test]
fn try_phase3_checks_local_ready_before_anything_else() {
    // Pin: !Send pinned local tasks (in self.local_ready)
    // are checked BEFORE both fast_queue and global. These
    // tasks are pinned to a specific worker and CAN'T be
    // stolen — the owner must dispatch them. A regression
    // that put them after fast_queue would let stealable
    // tasks starve pinned ones.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "fn try_phase3_ready_work(&mut self) -> Option<TaskId> {";
    let start = source.find(fn_marker).expect("try_phase3_ready_work");
    let body_end = source[start..].find("\n    }\n").expect("phase3 close");
    let body = &source[start..start + body_end];

    let local_ready_pos = body
        .find("self.local_ready.lock().pop_front()")
        .expect("local_ready pop_front call");
    let fast_pos = body.find("self.fast_queue.pop()").expect("fast_queue pop");
    let global_pos = body
        .find("self.take_global_ready_task()")
        .expect("take_global_ready_task call");

    assert!(
        local_ready_pos < fast_pos && local_ready_pos < global_pos,
        "REGRESSION: try_phase3_ready_work no longer checks \
         self.local_ready FIRST. !Send pinned local tasks \
         must dispatch before stealable / global work; \
         otherwise pinned tasks starve while their owning \
         worker dispatches work-stolen tasks.",
    );
}

#[test]
fn fast_queue_fairness_limit_breaks_stolen_starvation() {
    // Pin: try_phase3 has a fairness mechanism — after
    // `fast_queue_fairness_limit` consecutive STOLEN
    // dispatches, force a local-work check. Without this,
    // a worker that was once a "donor" could perpetually
    // steal back from others, never dispatching its own
    // newly-spawned work.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "fn try_phase3_ready_work(&mut self) -> Option<TaskId> {";
    let start = source.find(fn_marker).expect("try_phase3_ready_work");
    let body_end = source[start..].find("\n    }\n").expect("phase3 close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.fast_queue_dispatch_streak >= self.fast_queue_fairness_limit"),
        "REGRESSION: try_phase3_ready_work no longer checks \
         the fast_queue_dispatch_streak fairness limit. \
         Without this, a worker that drained its own fast \
         queue could keep stealing from others indefinitely \
         — its own new spawns never get dispatched.\n\n\
         fn body:\n{body}",
    );
}

#[test]
fn inject_ready_routes_cross_thread_spawns_through_global_injector() {
    // Pin: Scheduler::inject_ready (the cross-thread spawn
    // entry point) routes through inject_global_ready_checked
    // → self.global.inject_ready. This is the CORRECT path
    // for spawns that originate OUTSIDE a worker thread (no
    // CURRENT_QUEUE bound). Under-worker spawns use
    // schedule_local instead.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "pub fn inject_ready(&self, task: TaskId, priority: u8) {";
    let start = source.find(fn_marker).expect("inject_ready fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("inject_ready close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.inject_global_ready_checked(task, priority);"),
        "REGRESSION: Scheduler::inject_ready no longer calls \
         inject_global_ready_checked. Cross-thread spawns \
         (e.g., from main(), from a non-worker thread) need \
         to land in the global injector since they have no \
         worker's CURRENT_QUEUE binding.\n\nfn body:\n{body}",
    );
}

#[test]
fn local_queue_is_spmc_with_owning_worker_push_only() {
    // Pin: LocalQueue is an SPMC structure — only the owning
    // worker pushes (via schedule_local_push), and other
    // workers can only steal via the Stealer handle. A
    // regression to MPMC (allowing cross-worker pushes)
    // would re-introduce the global-FIFO bottleneck through
    // the back door.
    let source = read("src/runtime/scheduler/local_queue.rs");

    // schedule_local_push is the canonical push method.
    assert!(
        source.contains("fn schedule_local_push(")
            || source.contains("fn schedule_local_push_internal("),
        "REGRESSION: LocalQueue no longer has a \
         schedule_local_push method. The push side is the \
         load-bearing SPMC primitive — without it, the \
         queue's locality semantics are gone.",
    );

    // The queue must have a separate Stealer type for the
    // non-owning workers.
    assert!(
        source.contains("pub struct Stealer") || source.contains("pub(crate) struct Stealer"),
        "REGRESSION: LocalQueue no longer exposes a Stealer \
         handle. Without the stealer/owner split, work-\
         stealing is broken.",
    );
}

#[test]
fn worker_pool_creates_independent_local_queues_per_worker() {
    // Pin: at scheduler construction, EACH worker gets its
    // OWN LocalQueue instance via .push() into a Vec. A
    // regression that shared a single LocalQueue across
    // workers would re-create the global-FIFO bottleneck.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // Find the scheduler builder's worker construction loop.
    // Each worker is constructed with its own fast_queue
    // (typically `LocalQueue::new()` per iteration).
    let local_queues_marker = "let mut local_schedulers";
    let pos = source
        .find(local_queues_marker)
        .expect("local_schedulers initialization");
    let window = source_window(&source, pos, 3000);

    // Look for either LocalQueue::new() or LocalQueue::with_capacity
    // calls inside the construction window.
    assert!(
        window.contains("LocalQueue::new(") || window.contains("LocalQueue::with_capacity("),
        "REGRESSION: scheduler construction does not appear to \
         create per-worker LocalQueue instances. If a single \
         LocalQueue is now shared, all workers' spawns serialize \
         through it — the operator's bottleneck failure mode.\n\n\
         construction window (first 3000 chars):\n{window}",
    );
}
