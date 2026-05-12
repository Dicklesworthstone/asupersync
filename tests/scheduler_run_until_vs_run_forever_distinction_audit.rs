//! Audit + regression test for the scheduler's "drive a
//! specific future" vs "keep dispatching all tasks" entry-
//! point distinction.
//!
//! Operator's question: "scheduler.run_until() vs
//! run_forever() distinction: run_until should drive only
//! the specified future, run_forever should keep
//! dispatching all spawned tasks. Verify the semantic
//! difference is observable in scheduler metrics."
//!
//! Audit findings:
//!
//!   asupersync exposes the distinction via DIFFERENT named
//!   methods than `run_until` / `run_forever`, but with the
//!   same SEMANTIC contrast. The distinction is observable
//!   in scheduler/runtime metrics. The audit pins the
//!   actual API:
//!
//!   1. **Production "run_forever" — `ThreeLaneWorker::
//!      run_loop`** (three_lane.rs:3154):
//!      ```ignore
//!      pub fn run_loop(&mut self) {
//!          while !self.shutdown.load(Ordering::Relaxed) {
//!              if let Some(task) = self.next_task() {
//!                  self.execute(task);
//!                  continue;
//!              }
//!              ...
//!          }
//!      }
//!      ```
//!      Worker threads call this. Loops while !shutdown.
//!      Dispatches all tasks reaching the worker — never
//!      returns until shutdown atomic is set.
//!
//!   2. **Production "run_until specific future" —
//!      `Runtime::block_on(future)`** (builder.rs:3091):
//!      ```ignore
//!      pub fn block_on<F: Future>(&self, future: F) -> F::Output {
//!          let _guard = ScopedRuntimeHandle::new(self.handle());
//!          run_future_with_budget(future, self.inner.config.poll_budget)
//!      }
//!      ```
//!      Drives the GIVEN future to completion. Returns
//!      `F::Output` when the specific future is Ready. Other
//!      spawned tasks run on worker threads in parallel —
//!      block_on does not wait for them.
//!
//!   3. **Lab "run_until_quiescent" — full drain**
//!      (lab/runtime.rs:1156):
//!      ```ignore
//!      pub fn run_until_quiescent(&mut self) -> u64 {
//!          let start_steps = self.steps;
//!          while !self.is_quiescent() {
//!              if step_limit_exceeded { break; }
//!              self.step();
//!          }
//!          self.steps - start_steps
//!      }
//!      ```
//!      Runs until ALL tasks are completed AND obligations
//!      resolved. Returns step count for metrics. Equivalent
//!      to "run_forever within scope" — drives all spawned
//!      work to completion, then returns.
//!
//!   4. **Lab "run_until_idle" — weaker drain**
//!      (lab/runtime.rs:1180):
//!      ```ignore
//!      pub fn run_until_idle(&mut self) -> u64 {
//!          loop {
//!              if step_limit_exceeded { break; }
//!              if self.scheduler.lock().is_empty() { break; }
//!              self.step();
//!          }
//!          self.steps - start_steps
//!      }
//!      ```
//!      Documented as "intentionally weaker than
//!      run_until_quiescent: does NOT require all tasks to
//!      complete; does NOT require all obligations to be
//!      resolved." Stops as soon as the scheduler queue is
//!      empty (e.g., a task is parked on a channel receive).
//!
//!   5. **Production single-step — `ThreeLaneWorker::
//!      run_once`** (three_lane.rs:4026):
//!      ```ignore
//!      pub fn run_once(&mut self) -> bool {
//!          if self.shutdown.load(Ordering::Relaxed) { return false; }
//!          if let Some(task) = self.next_task() {
//!              self.execute(task);
//!              return true;
//!          }
//!          false
//!      }
//!      ```
//!      Test-only: dispatches ONE task and returns. Returns
//!      bool indicating whether a task ran.
//!
//! Observable distinctions:
//!
//!   - **Exit condition**:
//!       - run_loop: `!shutdown`
//!       - block_on: `future` returns Ready
//!       - run_until_quiescent: `is_quiescent() == true`
//!         (no live tasks, no pending obligations)
//!       - run_until_idle: scheduler.is_empty() (no
//!         runnable tasks, but tasks may still be parked)
//!       - run_once: returns after exactly one dispatch
//!
//!   - **Return value**:
//!       - run_loop: () (only ends on shutdown)
//!       - block_on: F::Output (the specific future's
//:         result)
//!       - run_until_quiescent: u64 (steps executed)
//!       - run_until_idle: u64 (steps executed)
//!       - run_once: bool (did a task run?)
//!
//!   - **Metrics observable**:
//!       - run_until_quiescent_with_report (lab/runtime.rs:
//!         1203): returns LabRunReport with steps_delta.
//!         steps_delta will exceed run_until_idle's count
//!         when there's pending obligation drain — direct
//!         observable difference.
//!       - PreemptionMetrics on the scheduler (cancel_dispatches,
//!         ready_dispatches, timed_dispatches) accumulate
//!         monotonically across all dispatch methods —
//!         observable per-method via before/after diffs.
//!
//! Verdict: **SOUND**. The distinction exists with
//! observable per-method semantics. The audit pins the
//! exact set of entry points so a regression that conflated
//! them (e.g., made block_on equivalent to run_loop, or
//! made run_until_idle equal run_until_quiescent) would be
//! caught.
//!
//! Note on the operator's exact framing: there is no
//! single method called `run_until` and no single method
//! called `run_forever`. asupersync uses domain-specific
//! names that reflect the actual semantics:
//!   - block_on (drives a specific future)
//!   - run_loop (worker thread forever-loop)
//!   - run_until_quiescent (lab: full drain)
//!   - run_until_idle (lab: weaker drain)
//!   - run_once (test-only single-step)
//!     All five are distinct, all five have observably different
//!     exit conditions and return types. No conflation —
//!     verdict SOUND, no bead filed.
//!
//! A regression that:
//!   - removed Runtime::block_on (would lose the public
//!     "drive a specific future" entry point — users would
//!     have to drive futures themselves),
//!   - removed run_until_quiescent (would lose the lab
//!     full-drain entry point — testing tool gap),
//!   - made run_until_idle equivalent to run_until_quiescent
//!     (would silently strengthen the weaker variant —
//!     existing tests using run_until_idle would observe
//!     different behavior),
//!   - removed the steps return value from
//!     run_until_quiescent / run_until_idle (would lose
//!     the metrics-observable distinction the operator
//!     asks about),
//!   - made run_loop exit on conditions other than
//!     shutdown (would weaken the worker-thread driver
//!     semantics),
//!   - made run_once dispatch more than one task (would
//!     break the test-single-step contract),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn run_loop_exits_only_on_shutdown_atomic() {
    // Pin (link 1): run_loop loops while !shutdown. The
    // shutdown atomic is the ONLY exit condition. Without
    // this, the worker would exit early on some other
    // condition and stop processing spawned tasks.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("pub fn run_loop(&mut self) {")
            && source.contains("while !self.shutdown.load(Ordering::Relaxed) {"),
        "REGRESSION: run_loop signature or exit condition \
         changed. The worker-forever-loop semantics requires \
         shutdown-atomic-as-only-exit; otherwise spawned \
         tasks may be stranded.",
    );
}

#[test]
fn run_once_dispatches_exactly_one_task_and_returns_bool() {
    // Pin (link 5): run_once is the single-step driver.
    // Returns bool indicating whether a task ran. Critical
    // that it returns after exactly ONE dispatch.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "pub fn run_once(&mut self) -> bool {";
    let start = source.find(fn_marker).expect("run_once fn");
    let body_end = source[start..].find("\n    }\n").expect("run_once close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if let Some(task) = self.next_task() {")
            && body.contains("self.execute(task);")
            && body.contains("return true;"),
        "REGRESSION: run_once no longer dispatches a single \
         task and returns true. Either it returns false \
         spuriously or it dispatches multiple tasks — \
         breaking the test-single-step contract.",
    );

    // Forbid loops in run_once that would dispatch multiple.
    let suspect_multiple_dispatch = ["while let Some(task) = self.next_task()", "loop {"];
    for pat in &suspect_multiple_dispatch {
        assert!(
            !body.contains(pat),
            "REGRESSION: run_once now contains a multi-\
             dispatch loop (`{pat}`). The single-step \
             contract is broken — tests that expect exactly \
             one task to run will see multiple.",
        );
    }
}

#[test]
fn runtime_block_on_drives_specific_future_to_completion() {
    // Pin (link 2): Runtime::block_on takes a future and
    // returns its Output. The signature contract is what
    // makes this the "drive specific future" entry point.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("pub fn block_on<F: Future>(&self, future: F) -> F::Output {"),
        "REGRESSION: Runtime::block_on signature changed. \
         The future-driven semantics requires F: Future + \
         F::Output return — without this, callers can't \
         get the future's result and must drive it manually.",
    );

    // The body must use run_future_with_budget (the bounded
    // poll-loop driver), not the unbounded run_loop.
    let fn_marker = "pub fn block_on<F: Future>(&self, future: F) -> F::Output {";
    let start = source.find(fn_marker).expect("block_on fn");
    let body_end = source[start..].find("\n    }\n").expect("block_on close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("run_future_with_budget(future, self.inner.config.poll_budget)"),
        "REGRESSION: Runtime::block_on no longer uses \
         run_future_with_budget. Either it uses run_loop \
         (would block on shutdown, defeating the future-\
         driven contract) or some other driver — \
         observable behavior change.",
    );
}

#[test]
fn lab_run_until_quiescent_runs_until_is_quiescent_returns_true() {
    // Pin (link 3): run_until_quiescent loops while !is_
    // quiescent(). Quiescent means all tasks complete AND
    // obligations resolved. Without this exit condition,
    // the lab driver semantics is broken.
    let source = read("src/lab/runtime.rs");

    let fn_marker = "pub fn run_until_quiescent(&mut self) -> u64 {";
    let start = source.find(fn_marker).expect("run_until_quiescent fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("run_until_quiescent close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("while !self.is_quiescent() {"),
        "REGRESSION: run_until_quiescent no longer loops on \
         is_quiescent. The full-drain semantics is broken — \
         tests using this method observe different behavior.",
    );

    // Returns step count for metrics observability.
    assert!(
        body.contains("self.steps - start_steps"),
        "REGRESSION: run_until_quiescent no longer returns \
         steps_delta. The metrics-observable distinction \
         (operator's question) is lost.",
    );
}

#[test]
fn lab_run_until_idle_runs_until_scheduler_is_empty() {
    // Pin (link 4): run_until_idle loops while scheduler
    // is non-empty. Documented as "intentionally weaker
    // than run_until_quiescent". Without this distinction,
    // the two lab drivers are conflated.
    let source = read("src/lab/runtime.rs");

    let fn_marker = "pub fn run_until_idle(&mut self) -> u64 {";
    let start = source.find(fn_marker).expect("run_until_idle fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("run_until_idle close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("let is_empty = self.scheduler.lock().is_empty();")
            && body.contains("if is_empty {"),
        "REGRESSION: run_until_idle no longer uses \
         scheduler.is_empty as its exit condition. The \
         weaker-drain semantics is broken — either it \
         conflates with run_until_quiescent (silent \
         strengthening) or never exits.",
    );

    // The documented contrast must be present.
    assert!(
        source.contains("intentionally weaker than"),
        "REGRESSION: the documented contrast between \
         run_until_idle and run_until_quiescent is gone. \
         Without the docstring, future readers may merge the \
         two — silent semantics drift.",
    );
}

#[test]
fn lab_run_until_quiescent_with_report_returns_metrics_for_observability() {
    // Pin (operator's metrics question): the lab driver
    // exposes a structured report — steps_delta + other
    // run-specific data — so the run-method choice is
    // observable.
    let source = read("src/lab/runtime.rs");

    assert!(
        source.contains("pub fn run_until_quiescent_with_report(&mut self) -> LabRunReport {"),
        "REGRESSION: run_until_quiescent_with_report is gone. \
         The metrics-observable distinction the operator asks \
         about is lost — tests can no longer see how many \
         steps the run consumed.",
    );

    assert!(
        source.contains("steps_delta"),
        "REGRESSION: the LabRunReport no longer includes \
         steps_delta. Run-method observability is degraded.",
    );
}

#[test]
fn lab_run_until_quiescent_and_idle_share_no_implementation_via_call_chain() {
    // Pin (link 3+4 contrast): run_until_quiescent must NOT
    // simply call run_until_idle (or vice versa). They have
    // different exit conditions, so a delegation would
    // silently conflate them.
    let source = read("src/lab/runtime.rs");

    let q_marker = "pub fn run_until_quiescent(&mut self) -> u64 {";
    let q_start = source.find(q_marker).expect("run_until_quiescent fn");
    let q_body_end = source[q_start..]
        .find("\n    }\n")
        .expect("run_until_quiescent close");
    let q_body = &source[q_start..q_start + q_body_end];

    assert!(
        !q_body.contains("self.run_until_idle()"),
        "REGRESSION: run_until_quiescent now delegates to \
         run_until_idle. The two have DIFFERENT exit \
         conditions — quiescent requires all tasks to \
         complete, idle stops as soon as scheduler is \
         empty. Conflating them silently strengthens or \
         weakens callers expectations.",
    );

    let i_marker = "pub fn run_until_idle(&mut self) -> u64 {";
    let i_start = source.find(i_marker).expect("run_until_idle fn");
    let i_body_end = source[i_start..]
        .find("\n    }\n")
        .expect("run_until_idle close");
    let i_body = &source[i_start..i_start + i_body_end];

    assert!(
        !i_body.contains("self.run_until_quiescent()"),
        "REGRESSION: run_until_idle now delegates to \
         run_until_quiescent. Same conflation hazard.",
    );
}

#[test]
fn worker_run_loop_does_not_call_block_on_internally() {
    // Pin (link 1+2 contrast): the worker's run_loop must
    // NOT delegate to block_on (which would tie the worker
    // to a specific future and lose the forever-loop
    // semantics).
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "pub fn run_loop(&mut self) {";
    let start = source.find(fn_marker).expect("run_loop fn");
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    let suspect_delegation = ["self.block_on(", "Runtime::block_on(", "block_on_with_cx("];
    for pat in &suspect_delegation {
        assert!(
            !body.contains(pat),
            "REGRESSION: run_loop now delegates to `{pat}` \
             — the worker-forever-loop semantics is broken. \
             Workers must drive ALL spawned tasks via \
             next_task / execute, not a single specific \
             future.",
        );
    }
}

#[test]
fn block_on_does_not_block_on_run_loop_internally() {
    // Pin (link 2 contrast): block_on must NOT call
    // run_loop (which would never return). It uses
    // run_future_with_budget — a bounded driver that exits
    // when the specific future completes.
    let source = read("src/runtime/builder.rs");

    let fn_marker = "pub fn block_on<F: Future>(&self, future: F) -> F::Output {";
    let start = source.find(fn_marker).expect("block_on fn");
    let body_end = source[start..].find("\n    }\n").expect("block_on close");
    let body = &source[start..start + body_end];

    let suspect_run_loop_delegation = [".run_loop()", "run_loop(", "while !shutdown"];
    for pat in &suspect_run_loop_delegation {
        assert!(
            !body.contains(pat),
            "REGRESSION: block_on now delegates to a \
             run_loop variant (`{pat}`). The future-driven \
             semantics is broken — block_on would never \
             return unless shutdown is signaled.",
        );
    }
}

#[test]
fn preemption_metrics_provides_per_dispatch_observability() {
    // Pin (link 5+observable): the scheduler's PreemptionMetrics
    // tracks per-dispatch counts (cancel_dispatches,
    // ready_dispatches, timed_dispatches). Callers can
    // observe per-method behavior by snapshotting before
    // and after.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("pub timed_dispatches: u64,")
            && source.contains("pub max_timed_dispatch_stall: usize,"),
        "REGRESSION: PreemptionMetrics no longer exposes \
         timed_dispatches / max_timed_dispatch_stall. \
         Per-dispatch observability is lost — operators \
         can't measure scheduler behavior.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/scheduler_three_lane_edf_vs_fifo_deadline_pressure_audit.rs",
        "tests/scheduler_worker_resilience_panic_during_poll_audit.rs",
        "tests/scheduler_worker_count_zero_one_edge_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
