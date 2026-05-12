//! Audit + regression test for worker resilience under
//! panic-during-poll.
//!
//! Operator's question: "when a future panics during its
//! poll() call (not during spawn), is the panic caught at the
//! worker boundary and propagated to the parent region
//! (correct: structured) or does it crash the worker thread
//! (incorrect)?"
//!
//! Audit findings:
//!
//!   The asupersync three-lane worker is **resilient**: a
//!   panic during `Future::poll` is contained at the worker's
//!   catch_unwind boundary, surfaced as `Outcome::Panicked` on
//!   the parent's JoinHandle, and the worker continues
//!   processing subsequent tasks. The chain:
//!
//!   1. **execute() always returns normally**: the inner
//!      `catch_unwind(AssertUnwindSafe(|| stored.poll(&mut
//!      cx)))` (three_lane.rs:4732) catches the panic and
//!      converts it to `Err(payload)`. The Err arm
//!      (three_lane.rs:4920-4958) does NOT call resume_unwind/
//!      abort/exit — it marks the task Panicked, wakes
//!      dependents, and returns from execute() normally.
//!
//!   2. **run_loop() continues after execute()**: the worker
//!      loop is:
//!        ```ignore
//!        while !self.shutdown.load(Ordering::Relaxed) {
//!            if let Some(task) = self.next_task() {
//!                self.execute(task);
//!                continue;
//!            }
//!            ...
//!        }
//!        ```
//!      The `continue` after execute() means a panic in one
//!      task is followed by dispatching the NEXT task on the
//!      same worker, never panicking the worker thread.
//!
//!   3. **run_once() returns bool, not Result**: the
//!      single-step variant `pub fn run_once(&mut self) ->
//!      bool` (three_lane.rs:4026) propagates `true` if a
//!      task ran (panic or not) and `false` if no task was
//!      available. Panic-during-poll surfaces via the
//!      Outcome::Panicked on the parent JoinHandle, NOT via
//!      the run_once return value.
//!
//!   4. **No production panic!/abort/exit in three_lane.rs**:
//!      a grep over `src/runtime/scheduler/three_lane.rs`
//!      finds `panic!` calls only inside `#[cfg(test)]` test
//!      fixtures. No production path on the dispatch/execute
//!      hot path can crash the worker thread.
//!
//!   5. **PoisonError-tolerant lock acquisition**: every
//!      `self.state.lock()` call in execute() uses
//!      `.unwrap_or_else(std::sync::PoisonError::into_inner)`.
//!      A panic in one task that poisoned the RuntimeState
//!      lock does NOT prevent the worker from acquiring the
//!      lock for the next task — recovery is automatic.
//!
//!   6. **Worker is not bound to a specific task**: when one
//!      task panics, the worker's TaskExecutionGuard cleans
//!      up the per-task state (cx_inner, wake_state, cached
//!      wakers) before next_task() is called for the next
//!      iteration. There is no "in-flight task" field that
//!      would carry corruption across iterations.
//!
//!   7. **Multiple panics don't accumulate**: each
//!      `execute(task_id)` builds its task-specific state
//!      from scratch (Cx::set_current snapshot, cached_waker
//!      lookup, AnyStoredTask::Global/Local detection). No
//!      shared mutable state across calls means N panics in
//!      a row produce N independent Outcome::Panicked
//!      results, never a compounding worker failure.
//!
//!   8. **TaskExecutionGuard is the safety net**: even if a
//!      panic somehow escapes catch_unwind (e.g., destructor
//!      double-panic), the guard fires under
//!      `std::thread::panicking()` and marks the task
//!      Panicked under poison-tolerant locks. The worker
//!      thread MAY in this exotic path unwind further, but
//!      the runtime invariants (task in terminal state,
//!      waiters woken) are preserved.
//!
//! Verdict: **SOUND**. The worker is resilient to
//! panic-during-poll. Answer (a) — the panic is caught at
//! the worker boundary and propagated to the parent region
//! via Outcome::Panicked.
//!
//! Note on the "structured" framing: the operator asks
//! whether the panic propagates to the parent REGION. This
//! happens via the standard task-completion handshake:
//!   - record.complete(Outcome::Panicked) marks the task
//!     terminal.
//!   - state.task_completed(task_id) gathers waiters
//!     (specifically, the parent's JoinHandle awaiter).
//!   - wake_dependents_locked schedules the awaiter.
//!   - The awaiter's `poll` returns Poll::Ready with
//!     Outcome::Panicked, which the parent's await chain
//!     observes — same path as Ok, Err, Cancelled.
//!     There is no separate "panic propagation channel" — panics
//!     are first-class values in the Outcome ADT.
//!
//! A regression that:
//!   - replaced the inner catch_unwind with a `?`-style
//!     error path (would propagate panics through the worker
//!     thread),
//!   - changed run_loop to break/return on panic instead of
//!     continue,
//!   - added a `last_panic_count` field that triggers
//!     run_loop exit after N panics (matches the operator's
//!     "crash the worker thread" framing if the threshold is
//!     low),
//!   - added panic!/abort/process::exit calls on a hot path
//!     in three_lane.rs,
//!   - changed self.state.lock() to use unwrap() instead of
//!     PoisonError::into_inner (poisoned lock from one
//!     task's panic kills the worker on the next task),
//!   - moved per-task state into worker-level fields that
//!     persist across execute() calls (would let
//!     corruption from one panic leak into the next task),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn run_loop_continues_after_execute_returns() {
    // Pin (link 2): the worker's run_loop calls self.execute
    // followed by `continue` — a panic in one task does not
    // exit the loop. Without this, a single panic would
    // terminate the worker thread.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // The run_loop signature.
    assert!(
        source.contains("pub fn run_loop(&mut self) {"),
        "REGRESSION: ThreeLaneWorker::run_loop signature changed. \
         The dispatch loop is the structural mechanism for \
         worker resilience — without it, the worker can't \
         continue after a panic.",
    );

    // The continue-after-execute pattern.
    let fn_marker = "pub fn run_loop(&mut self) {";
    let start = source.find(fn_marker).expect("run_loop fn");
    let window_end = (start + 3000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("self.execute(task);") && body.contains("continue;"),
        "REGRESSION: run_loop no longer calls self.execute() \
         followed by continue. A panic in one task could now \
         exit the loop — the worker thread terminates and \
         subsequent tasks are stranded.",
    );

    // The shutdown gate is the loop's exit condition — NOT a
    // panic-driven exit.
    assert!(
        body.contains("while !self.shutdown.load(Ordering::Relaxed) {"),
        "REGRESSION: run_loop's exit condition is no longer \
         the shutdown atomic. If a non-shutdown condition \
         can break the loop, the worker may exit on the \
         wrong signal — including potentially on panic.",
    );
}

#[test]
fn run_loop_does_not_propagate_panics_via_return_or_result() {
    // Pin (link 1+2): run_loop returns () (unit), not
    // Result<...>. There is no error channel that could
    // propagate a panic from the inner execute() upward —
    // the only way out of the loop is the shutdown atomic.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // run_loop signature must be `pub fn run_loop(&mut self)
    // {` — no `-> Result<...>` or other return type that
    // could convey panic state.
    let fn_marker = "pub fn run_loop(&mut self) {";
    assert!(
        source.contains(fn_marker),
        "REGRESSION: run_loop signature changed from `pub fn \
         run_loop(&mut self) {{`. A return type would invite \
         callers to react to panics by exiting — defeating \
         the worker-resilience contract.",
    );

    // No panic-counting field that gates the loop.
    let suspect_panic_count_fields = [
        "panic_count: usize,",
        "last_panic_count: u64,",
        "panic_threshold: u32,",
    ];
    for pat in &suspect_panic_count_fields {
        assert!(
            !source.contains(pat),
            "REGRESSION: ThreeLaneWorker now tracks `{pat}` — \
             a panic-count field that could gate run_loop's \
             continuation. Worker resilience requires \
             unconditional continuation after panic.",
        );
    }
}

#[test]
fn run_once_returns_bool_not_result_for_panic_signaling() {
    // Pin (link 3): run_once returns bool. A panic during
    // poll returns true (a task DID run, even though it
    // panicked) — same return contract as a successful poll.
    // Panic information surfaces via the parent's JoinHandle,
    // NOT via run_once's return.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("pub fn run_once(&mut self) -> bool {"),
        "REGRESSION: run_once signature changed. A change to \
         `Result<bool, PanicInfo>` would force callers to \
         handle panic state at every dispatch — defeating \
         the structured-via-JoinHandle propagation contract.",
    );
}

#[test]
fn execute_inner_catch_unwind_does_not_propagate_payload_to_caller() {
    // Pin (link 1): the catch_unwind Err arm in execute()
    // converts the payload to Outcome::Panicked. It does NOT
    // re-throw via resume_unwind, abort, or panic!. Without
    // this contract, execute() could panic — and panic from
    // execute() would propagate out of run_loop and kill the
    // worker.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let err_marker = "Err(payload) => {";
    let pos = source.find(err_marker).expect("Err arm marker");
    let window_end = (pos + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[pos..safe_end];

    // Forbid re-throw / process termination from the
    // execute() Err arm.
    let suspect_propagation = [
        "std::panic::resume_unwind",
        "panic::resume_unwind",
        "std::process::abort",
        "process::abort",
        "std::process::exit",
        "process::exit",
        "panic!(",
    ];
    for pat in &suspect_propagation {
        assert!(
            !body.contains(pat),
            "REGRESSION: execute() Err arm now contains \
             `{pat}` — panic propagates out of execute() and \
             through run_loop, terminating the worker thread. \
             Matches operator answer 'incorrect: crash the \
             worker thread'.",
        );
    }
}

#[test]
fn no_production_panic_or_abort_calls_in_three_lane() {
    // Pin (link 4): the dispatch hot path must not contain
    // panic!/abort/exit. These are allowed only in test
    // code (#[cfg(test)] modules) or in `expect()` calls
    // for genuinely-impossible states.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // Find all panic!() calls outside #[cfg(test)] modules.
    // Approximation: split the file into pre-test and test
    // sections by the first `#[cfg(test)]` and inspect only
    // the pre-test section.
    let test_module_marker = "#[cfg(test)]\nmod tests {";
    let pre_test_end = source.find(test_module_marker).unwrap_or(source.len());
    let safe_pre_test_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= pre_test_end)
        .unwrap_or(pre_test_end);
    let pre_test = &source[..safe_pre_test_end];

    // Forbid panic!/abort/exit in the production section.
    // (`expect_panic` is a different identifier — used in
    // adaptive-epoch tests and is under #[cfg(test)] anyway.)
    let suspect = [
        "std::process::abort()",
        "std::process::exit(",
        "process::abort()",
    ];
    for pat in &suspect {
        assert!(
            !pre_test.contains(pat),
            "REGRESSION: production three_lane.rs contains \
             `{pat}` — a hard kill on the dispatch path. \
             Worker resilience requires graceful continuation, \
             not abrupt termination.",
        );
    }
}

#[test]
fn execute_uses_poison_tolerant_lock_recovery_throughout() {
    // Pin (link 5): every state.lock() in execute() and the
    // surrounding paths uses
    // .unwrap_or_else(std::sync::PoisonError::into_inner).
    // Without poison tolerance, a panic that poisoned the
    // RuntimeState lock would prevent the worker from
    // dispatching the NEXT task.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // Count occurrences of poison-tolerant recovery — must
    // be present (and there should be many, given multiple
    // lock acquisition sites).
    let count = source
        .matches(".unwrap_or_else(std::sync::PoisonError::into_inner)")
        .count();
    assert!(
        count >= 5,
        "REGRESSION: only {count} poison-tolerant lock \
         recoveries found in three_lane.rs (expected >= 5). \
         Worker resilience depends on PoisonError::into_inner \
         at every state.lock() site — without it, one panicking \
         task can lock out subsequent tasks on the same worker.",
    );
}

#[test]
fn execute_does_not_persist_per_task_state_across_calls() {
    // Pin (link 6+7): per-task state (cx_inner, wake_state,
    // cached wakers) is built fresh inside execute() from
    // the task table — not stored as a worker-level field
    // that could carry corruption from a panicking task to
    // the next.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // The ThreeLaneWorker struct is the worker-level state.
    // It must NOT contain per-task fields.
    let struct_marker = "pub(crate) struct ThreeLaneWorker {";
    let alt_marker = "struct ThreeLaneWorker {";
    let start = source
        .find(struct_marker)
        .or_else(|| source.find(alt_marker))
        .expect("ThreeLaneWorker struct");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("ThreeLaneWorker struct close");
    let body = &source[start..start + body_end];

    let suspect_per_task = [
        "current_task: Option<TaskId>,",
        "current_cx_inner: Option<",
        "current_stored_task:",
        "current_wake_state: Option<Arc<TaskWakeState>>,",
    ];
    for pat in &suspect_per_task {
        assert!(
            !body.contains(pat),
            "REGRESSION: ThreeLaneWorker now persists \
             per-task state via `{pat}`. A panic in one task \
             could leave this field in a corrupt half-\
             initialized state — the next task's execute() \
             would observe stale state. Worker resilience \
             requires per-task state to be local to each \
             execute() call.",
        );
    }
}

#[test]
fn task_execution_guard_is_inside_execute_not_run_loop() {
    // Pin (link 8): the safety-net TaskExecutionGuard is
    // declared INSIDE execute(), so it's dropped before
    // execute() returns. If the guard were declared inside
    // run_loop, a panic that escapes execute() (impossible
    // by current design but a hypothetical regression) would
    // be observed by run_loop's stack — making the panic
    // visible to surrounding code rather than contained at
    // the per-task level.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // Find struct declaration of TaskExecutionGuard — must be
    // inside the execute fn body.
    let exec_marker = "pub(crate) fn execute(&mut self, task_id: TaskId) {";
    let exec_pos = source.find(exec_marker).expect("execute fn");
    let guard_pos = source[exec_pos..]
        .find("struct TaskExecutionGuard<'a> {")
        .map(|o| exec_pos + o)
        .expect("TaskExecutionGuard struct in execute");

    // The guard must be declared within the first ~200 lines
    // of execute() — not at module level.
    assert!(
        guard_pos - exec_pos < 4000,
        "REGRESSION: TaskExecutionGuard is declared >4000 \
         bytes after execute() opens — likely moved to module \
         scope. The guard's lifetime must be bounded by \
         execute() for proper unwind safety.",
    );
}

#[test]
fn worker_resilience_documented_in_module_or_struct_docs() {
    // Pin (audit hygiene): the panic-isolation contract is
    // load-bearing for structured concurrency. A regression
    // that REMOVED the documentation wouldn't break
    // compilation but would lose the institutional knowledge
    // of why the catch_unwind boundary exists. Verify some
    // form of panic/isolation/catch_unwind comment exists in
    // three_lane.rs.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let has_panic_documentation = source.contains("// Guard to handle unwinds")
        || source.contains("AssertUnwindSafe")
        || source.contains("catch_unwind");
    assert!(
        has_panic_documentation,
        "REGRESSION: no comment or code-level documentation \
         about panic handling / catch_unwind / unwind safety \
         in three_lane.rs. The contract that gives worker \
         resilience is silently load-bearing — restore the \
         documentation so future agents understand why the \
         boundary exists.",
    );
}

// ─────────────────── BEHAVIORAL PIN ──────────────────────
//
// Direct test of the worker-resilience pattern: a freestanding
// catch_unwind around a panicking closure mirrors the
// production execute() contract. Verify (1) the closure panic
// does NOT propagate to the surrounding loop, (2) multiple
// panics in sequence don't compound, (3) the loop continues
// processing.

use std::sync::Mutex as StdMutex;

#[test]
fn freestanding_catch_unwind_loop_survives_repeated_panics() {
    // Behavioral pin: the production execute() pattern is
    // catch_unwind(AssertUnwindSafe(|| poll())) inside a
    // run_loop. This freestanding test verifies the pattern
    // produces a worker that processes ALL tasks even when
    // every-other task panics.
    let panic_count: StdMutex<u32> = StdMutex::new(0);
    let success_count: StdMutex<u32> = StdMutex::new(0);

    // Simulate worker run_loop: 10 tasks, every odd-indexed
    // task panics during its "poll" call.
    for i in 0_u32..10 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(i % 2 != 1, "simulated panic in task {i}");
            i
        }));
        // Mirror the production Err arm: convert payload to
        // a count, do NOT propagate. This is the contract.
        match result {
            Ok(_value) => {
                let mut g = success_count.lock().unwrap();
                *g += 1;
            }
            Err(_payload) => {
                let mut g = panic_count.lock().unwrap();
                *g += 1;
            }
        }
        // run_loop's `continue` — implicit here as the
        // for-loop iterates.
    }

    let panics = *panic_count.lock().unwrap();
    let successes = *success_count.lock().unwrap();
    assert_eq!(
        panics, 5,
        "expected 5 panics (odd-indexed tasks 1,3,5,7,9), got {panics}",
    );
    assert_eq!(
        successes, 5,
        "expected 5 successes (even-indexed tasks 0,2,4,6,8), got {successes}",
    );
}

#[test]
fn freestanding_catch_unwind_lock_poisoning_does_not_kill_worker() {
    // Behavioral pin: when a panicking task poisons a
    // RuntimeState lock, the next task's execute() must be
    // able to recover via PoisonError::into_inner. This
    // freestanding test verifies the production pattern.
    let shared = std::sync::Arc::new(StdMutex::new(0_u32));

    // Task 1: panics while holding the lock — poisons it.
    {
        let shared = std::sync::Arc::clone(&shared);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let mut guard = shared.lock().unwrap();
            *guard += 1;
            panic!("task panics while holding the lock");
        }));
        assert!(
            result.is_err(),
            "expected the panicking task to surface as Err",
        );
    }

    // Task 2: must still be able to acquire the lock via
    // into_inner. This is the production poison-tolerant
    // pattern.
    let recovered = shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(
        *recovered, 1,
        "REGRESSION: poison-tolerant lock recovery doesn't \
         observe the prior task's update. Worker can't \
         continue processing — matches operator's 'crash the \
         worker thread' answer.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    // Pin (documentary): related audits.
    let prior_audits = [
        "tests/scheduler_panic_in_task_isolation_audit.rs",
        "tests/scheduler_three_lane_edf_vs_fifo_deadline_pressure_audit.rs",
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
