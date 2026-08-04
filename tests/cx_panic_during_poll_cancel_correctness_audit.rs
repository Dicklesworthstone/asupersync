//! Audit + regression test for cancel-correctness when a
//! future panics during `Future::poll()`.
//!
//! Operator's question: "when a future panics during poll()
//! (not during spawn), is the panic caught and the task
//! cancelled cleanly OR does it crash the worker? Per
//! asupersync structured concurrency spec."
//!
//! Audit findings:
//!
//!   A panic during `Future::poll()` is **caught at the
//!   worker boundary** (`catch_unwind` in `execute()`),
//!   converted to a structured terminal outcome, and the
//!   task is cleanly drained. Critically, the terminal
//!   outcome is **`Outcome::Panicked(PanicPayload)` —
//!   a SEPARATE variant from `Outcome::Cancelled`**. The
//!   operator's "cancelled cleanly" framing is loose
//!   language for "terminated cleanly under structured
//!   concurrency"; the runtime DISTINGUISHES panic from
//!   cancel because they have different debugging /
//!   audit / supervision implications.
//!
//!   Chain:
//!
//!   1. **`catch_unwind` boundary** (three_lane.rs:4732):
//!      ```ignore
//!      let poll_result = std::panic::catch_unwind(
//!          std::panic::AssertUnwindSafe(|| {
//!              let mut cx = Context::from_waker(&waker);
//!              stored.poll(&mut cx)
//!          })
//!      );
//!      ```
//!      The poll IS the panic boundary. The Err arm matches
//!      `Err(payload)` and converts to a structured terminal.
//!
//!   2. **Outcome::Panicked terminal** (three_lane.rs:4920-
//!      4958):
//!      ```ignore
//!      Err(payload) => {
//!          credit_adaptive_epoch = false;
//!          let panic_payload = PanicPayload::new(
//!              crate::cx::scope::payload_to_string(&payload)
//!          );
//!          state.update_task(task_id, |record| {
//!              if !record.state.is_terminal() {
//:                  record.complete(Outcome::Panicked(panic_payload));
//!              }
//!          });
//!          ...
//!      }
//!      ```
//!      The task transitions to `TaskState::Completed(
//!      Outcome::Panicked(...))`. This is a DISTINCT terminal
//!      from `Outcome::Cancelled` — important for:
//!        - Supervisors that decide whether to restart based
//!          on panic vs cancel.
//!        - Audit trails that need to attribute task
//!          failures (panic = bug; cancel = protocol event).
//!        - Tracing: `outcome_kind = "Panicked"` (record/
//!          task.rs:749) is distinct from "Cancelled".
//!
//!   3. **`is_terminal()` includes Panicked** (record/task.rs:
//!      281): the terminal-state predicate returns true for
//!      `TaskState::Completed(Outcome::Panicked(_))`. This
//!      is critical for region quiescence:
//!      `can_region_finalize` (state.rs:2785) checks
//!      `state.is_terminal()` for ALL tasks. A panicked task
//!      counts as terminal — the region's
//!      advance_region_state can proceed past Closing →
//!      Drained → Closed.
//!
//!   4. **Waiters woken via `task_completed`** (three_lane.rs:
//!      4941):
//!      ```ignore
//!      let (waiters, completion_observer) = state.task_completed(task_id).into_parts();
//!      let finalizers = state.drain_ready_async_finalizers();
//!      self.wake_dependents_locked(&state, waiters);
//!      // after waiter publication, guard completion, and lock release:
//!      completion_observer.dispatch();
//!      ```
//!      The parent's `JoinHandle::await` is scheduled. The
//!      parent observes `Outcome::Panicked(...)` via the
//!      JoinHandle outcome — same delivery path as Ok / Err
//:      / Cancelled.
//!
//!   5. **Finalizers drained even on panic** (three_lane.rs:
//!      4946-4954): `drain_ready_async_finalizers` returns
//!      the list of region/obligation finalizers that became
//!      ready when the panicked task transitioned to
//!      terminal. They're scheduled via `inject_ready_uncounted
//!      + wake_many` — region cleanup proceeds even if the
//!        task itself crashed.
//!
//!   6. **Worker thread continues** (three_lane.rs:4956): the
//!      Err arm sets `guard.completed = true`, clears the
//!      wake_state, drops the state lock, and returns from
//!      execute. The worker's run_loop continues to dispatch
//!      the next task — NO crash, NO worker thread death.
//!
//!   7. **`credit_adaptive_epoch = false`** (three_lane.rs:
//!      4926): the adaptive policy doesn't learn from a
//!      panic-induced potential drop. Subtle but important:
//!      a panic shouldn't bias the policy toward longer
//!      cancel streaks.
//!
//!   8. **TaskExecutionGuard safety net** (three_lane.rs:
//!      4485): even if a panic somehow escapes catch_unwind
//!      (destructor double-panic during the catch_unwind
//!      dance), the Drop guard fires under
//!      `std::thread::panicking()` and marks the task
//!      Panicked under poison-tolerant lock recovery. The
//!      runtime invariants (task in terminal state, waiters
//!      woken) are preserved even in this exotic case.
//!
//! Verdict: **SOUND**. A panic during `Future::poll()` is:
//!   - Caught at the worker boundary (catch_unwind).
//!   - Converted to `Outcome::Panicked(PanicPayload)` — a
//!     STRUCTURED terminal that distinguishes panic from
//!     cancel.
//!   - Cleanly drained: parent waiters woken, finalizers
//!     scheduled, region quiescence advances normally.
//!   - The worker thread continues to dispatch subsequent
//:     tasks — NO crash.
//!
//! The "cancelled cleanly" framing is technically incorrect
//! — the task is `Panicked`, not `Cancelled`. The DISTINCTION
//! is part of the spec: `Outcome` is a four-valued ADT (Ok /
//! Err / Cancelled / Panicked) for exactly this reason.
//! Conflating Panicked with Cancelled would erase important
//! supervision and audit information.
//!
//! A regression that:
//!   - removed the catch_unwind boundary (would unwind
//:     through the worker thread → crash),
//!   - mapped Outcome::Panicked to Outcome::Cancelled in the
//!     terminal transition (would erase the panic-vs-cancel
//!     distinction; supervisors couldn't tell crashes from
//!     protocol events),
//!   - dropped the wake_dependents call after panic (parent
//!     JoinHandle never fires — silent task hang),
//!   - removed Panicked from is_terminal() (region would
//:     never reach quiescence after a task panic — full
//!     deadlock pathway),
//!   - removed credit_adaptive_epoch = false on panic (the
//!     adaptive policy learns from fabricated reward
//!     signals — subtle correctness drift),
//!   - removed the TaskExecutionGuard safety net (escaping
//!     panics would leave the task in non-terminal state),
//!     would all be caught by the structural pins below.
//!
//! Cross-reference: this audit complements
//! tests/scheduler_panic_in_task_isolation_audit.rs (which
//! pins the panic-isolation chain) and
//! tests/scheduler_worker_resilience_panic_during_poll_audit.rs
//! (which pins worker-thread continuation). This audit's
//! focus is the cancel-correctness slant: Panicked is a
//: SEPARATE terminal from Cancelled, and structured
//! concurrency invariants (region quiescence, parent
//! observability, finalizer drain) hold for both.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn outcome_has_distinct_panicked_and_cancelled_variants() {
    // Pin (link 2): Outcome is a four-valued ADT. Panicked
    // and Cancelled are SEPARATE variants — conflation
    // would erase supervision/audit information.
    let source = read("src/types/outcome.rs");

    assert!(
        source.contains("Cancelled(") && source.contains("Panicked("),
        "REGRESSION: Outcome no longer has both Cancelled \
         and Panicked variants. Either one was removed (and \
         the other now subsumes panicked tasks → operator's \
         'cancelled cleanly' framing becomes literal but \
         loses semantic distinction) or both renamed.",
    );
}

#[test]
fn worker_panic_path_marks_outcome_panicked_not_cancelled() {
    // Pin (link 2): the catch_unwind Err arm marks the task
    // Outcome::Panicked, NOT Outcome::Cancelled. Conflating
    // them would erase the panic-vs-cancel distinction.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // E1.2 subsystem 3b (br-asupersync-sched-hot-path-perf-bt4y5f.2.2): the
    // Err arm builds `panic_outcome` once and routes it into the single
    // ordered completion seam as `PolledCompletion::Panicked`; the terminal
    // transition itself is applied by the shared `apply_polled_completion`
    // arm (`record.complete(outcome)` guarded by `is_terminal`). The window
    // from the Err arm covers both the routing and the shared apply arm.
    let err_marker = "Err(payload) => {";
    let pos = source.find(err_marker).expect("Err arm marker");
    let window_end = (pos + 9000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[pos..safe_end];

    assert!(
        body.contains("let panic_outcome = crate::types::Outcome::Panicked(panic_payload);")
            && body.contains("PolledCompletion::Panicked(panic_outcome),")
            && body.contains("record.complete(outcome);"),
        "REGRESSION: catch_unwind Err arm no longer marks \
         the task Outcome::Panicked (routing through the \
         ordered completion seam). Either it marks \
         Outcome::Cancelled (conflation) or doesn't mark a \
         terminal at all (region never quiesces).",
    );

    // Forbid conflation: the Err arm must NOT use
    // Outcome::Cancelled for panic-payload paths.
    assert!(
        !body.contains("record.complete(crate::types::Outcome::Cancelled("),
        "REGRESSION: catch_unwind Err arm now marks \
         Outcome::Cancelled for panic-payload paths. The \
         spec requires distinct variants — supervisors and \
         audit logs lose the panic-vs-cancel distinction.",
    );
}

#[test]
fn task_state_is_terminal_includes_completed_panicked() {
    // Pin (link 3): is_terminal() returns true for
    // TaskState::Completed regardless of the Outcome variant.
    // This is what makes panicked tasks count as terminal
    // for region quiescence.
    let source = read("src/record/task.rs");

    let fn_marker = "pub fn is_terminal(&self) -> bool {";
    let start = source.find(fn_marker).expect("is_terminal fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("is_terminal close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("TaskState::Completed(_)") || body.contains("matches!(self,"),
        "REGRESSION: is_terminal no longer treats \
         Completed(_) as terminal. A panicked task would \
         not count as terminal — region.quiesce() would \
         loop forever, deadlocking the close protocol.",
    );
}

#[test]
fn worker_panic_path_wakes_dependents_so_parent_observes_panicked() {
    // Pin (link 4): after marking Panicked, the worker
    // wakes dependents (parent's JoinHandle awaiter) so
    // the parent observes the Panicked outcome. Without
    // this, the parent silently hangs waiting on the join.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // E1.2 subsystem 3b: the Err arm delegates to the single ordered
    // completion seam (`complete_polled_task_ordered`); waiter gathering and
    // dependent wakes live in the seam's two arms (external-record and
    // unified fallback), so the audit scans the arm routing first and then
    // the seam function itself.
    let err_marker = "Err(payload) => {";
    let pos = source.find(err_marker).expect("Err arm marker");
    let arm_end = (pos + 2000).min(source.len());
    let safe_arm_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= arm_end)
        .unwrap_or(arm_end);
    let arm = &source[pos..safe_arm_end];
    assert!(
        arm.contains("self.complete_polled_task_ordered(")
            && arm.contains("PolledCompletion::Panicked(panic_outcome),")
            && arm.contains("artifacts.dispatch_post_lock(self);"),
        "REGRESSION: panic Err arm no longer routes through the ordered \
         completion seam. Completion effects (waiter wakes, observer) are \
         no longer guaranteed — the parent's JoinHandle may never resolve.",
    );

    let seam_marker = "fn complete_polled_task_ordered(";
    let seam_pos = source.find(seam_marker).expect("ordered completion seam");
    let seam_end = source[seam_pos..]
        .find("fn complete_task_after_unwind_ordered")
        .map_or(source.len(), |offset| seam_pos + offset);
    let seam = &source[seam_pos..seam_end];

    assert!(
        seam.contains("let (waiters, completion_observer)")
            && seam.contains("state.task_completed_from_external_record(record)")
            && seam.contains("state.task_completed(task_id).into_parts();"),
        "REGRESSION: the ordered completion seam no longer gathers waiters \
         and the owned completion observer via task_completed (external-\
         record arm or unified fallback). The parent's JoinHandle never \
         resolves — silent task hang.",
    );

    assert!(
        seam.matches("self.wake_dependents_locked(&state, waiters);")
            .count()
            >= 2,
        "REGRESSION: the ordered completion seam no longer wakes \
         dependents in both completion arms. Parent JoinHandle never \
         re-enters the dispatch loop — silent task hang.",
    );
}

#[test]
fn worker_panic_path_drains_finalizers_for_region_cleanup() {
    // Pin (link 5): the panic Err arm calls
    // drain_ready_async_finalizers and schedules them via
    // inject_ready_uncounted + wake_many. Without this,
    // region cleanup is stranded after a task panic.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // E1.2 subsystem 3b: every completion path drains through the single
    // gated B→A seam `drain_ready_finalizers_locked` (external-table arm and
    // unified fallback both call it inside `complete_polled_task_ordered`),
    // and scheduling routes through publish_ready_finalizers plus the
    // post-unlock finish_ready_finalizer_publication half carried by the
    // completion artifacts.
    let seam_marker = "fn complete_polled_task_ordered(";
    let seam_pos = source.find(seam_marker).expect("ordered completion seam");
    let seam_end = source[seam_pos..]
        .find("fn complete_task_after_unwind_ordered")
        .map_or(source.len(), |offset| seam_pos + offset);
    let seam = &source[seam_pos..seam_end];

    assert!(
        seam.matches("self.drain_ready_finalizers_locked(&mut state)")
            .count()
            >= 2,
        "REGRESSION: the ordered completion seam no longer drains \
         finalizers in both arms (external-table and unified fallback). \
         Region cleanup is stranded — the region stays in Closing state \
         forever after a task panic.",
    );

    let drain_marker = "fn drain_ready_finalizers_locked(";
    let drain_pos = source.find(drain_marker).expect("finalizer drain seam");
    let drain_end = (drain_pos + 2500).min(source.len());
    let safe_drain_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= drain_end)
        .unwrap_or(drain_end);
    let drain = &source[drain_pos..safe_drain_end];
    assert!(
        drain.contains("state.has_finalizing_regions()")
            && drain.contains("state.drain_ready_async_finalizers_in(")
            && drain.contains("&mut finalizer_tasks,"),
        "REGRESSION: the B→A finalizer drain seam no longer routes drained \
         finalizers through the minting-table target. Finalizer tasks mint \
         in a table the dispatching workers never consult — region cleanup \
         silently never runs.",
    );

    assert!(
        seam.matches("self.publish_ready_finalizers(finalizers)")
            .count()
            >= 2
            && source
                .contains("worker.finish_ready_finalizer_publication(self.finalizer_publication);"),
        "REGRESSION: panic completion no longer schedules \
         drained finalizers. Even if the drain happens, the \
         finalizers don't run — region cleanup is silently \
         dropped.",
    );
}

#[test]
fn worker_panic_path_does_not_propagate_panic_via_resume_unwind() {
    // Pin (link 6): the panic Err arm must NOT call
    // resume_unwind / abort / panic — that would propagate
    // the panic through the worker thread and crash the
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

    let suspect_propagation = [
        "std::panic::resume_unwind(payload)",
        "panic::resume_unwind(",
        "std::process::abort(",
        "process::abort(",
        "panic!(",
    ];
    for pat in &suspect_propagation {
        assert!(
            !body.contains(pat),
            "REGRESSION: panic Err arm now contains `{pat}` \
             — the panic propagates through the worker \
             thread. The worker crashes — operator's \
             'crash the worker' answer is now true.",
        );
    }
}

#[test]
fn worker_panic_disables_credit_adaptive_epoch_to_protect_policy_learning() {
    // Pin (link 7): credit_adaptive_epoch = false on panic.
    // Subtle but important: the adaptive cancel-streak
    // policy doesn't learn from a panic-induced potential
    // drop.
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

    assert!(
        body.contains("credit_adaptive_epoch = false;"),
        "REGRESSION: panic Err arm no longer disables \
         credit_adaptive_epoch. The adaptive policy learns \
         from a fabricated 'good' reward signal — subtle \
         correctness drift over many panics.",
    );
}

#[test]
fn task_execution_guard_safety_net_marks_panicked_under_unwind() {
    // Pin (link 8): TaskExecutionGuard's Drop fires under
    // std::thread::panicking() and marks the task Panicked.
    // This is the safety net for panics that somehow escape
    // catch_unwind.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("if !self.completed && std::thread::panicking() {"),
        "REGRESSION: TaskExecutionGuard safety net check is \
         gone. Panics that escape catch_unwind (e.g., from \
         destructor double-panic) leave the task non-\
         terminal — region.quiesce hangs.",
    );

    // E1.2 subsystem 3b: the guard drop delegates to the unwind-ordered
    // completion seam, which synthesizes the Panicked terminal state and
    // routes it through the shared apply arm. Pin the routing first, then
    // the synthesis inside the seam.
    let net_pos = source
        .find("if !self.completed && std::thread::panicking() {")
        .expect("safety net marker");
    let net_end = (net_pos + 1500).min(source.len());
    let net_body = &source[net_pos..net_end];
    assert!(
        net_body.contains(".complete_task_after_unwind_ordered(self.task_id);")
            && net_body.contains("artifacts.dispatch_post_lock(self.worker);"),
        "REGRESSION: TaskExecutionGuard safety net no longer routes through \
         the unwind-ordered completion seam. The escape path leaves the \
         task in a non-terminal state.",
    );

    let unwind_pos = source
        .find("fn complete_task_after_unwind_ordered(")
        .expect("unwind completion seam");
    let unwind_end = (unwind_pos + 4000).min(source.len());
    let unwind_body = &source[unwind_pos..unwind_end];
    assert!(
        unwind_body.contains("crate::types::Outcome::Panicked(")
            && unwind_body.contains("crate::types::outcome::PanicPayload::new(")
            && unwind_body.contains("PolledCompletion::Panicked(panic_outcome)"),
        "REGRESSION: the unwind completion seam no longer \
         marks Outcome::Panicked. The escape path leaves \
         the task in a non-terminal state.",
    );
}

#[test]
fn panic_payload_carries_message_for_parent_join_observation() {
    // Pin (link 4 supporting): the PanicPayload carries the
    // panic message via PanicPayload::new(msg). Without this,
    // the parent's JoinHandle await observes Panicked but
    // can't see the panic reason.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // E1.2: the message is extracted once into `panic_message` (the opaque
    // payload is then leaked fail-closed) and the PanicPayload is built
    // from that string.
    let err_marker = "Err(payload) => {";
    let pos = source.find(err_marker).expect("Err arm marker");
    let window_end = (pos + 9000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[pos..safe_end];

    assert!(
        body.contains("let panic_message = crate::cx::scope::payload_to_string(&payload);")
            && body.contains("crate::types::outcome::PanicPayload::new(panic_message)"),
        "REGRESSION: panic Err arm no longer constructs \
         PanicPayload from the downcast payload string. The \
         Panicked outcome carries an empty payload — \
         debugging panic causes is degraded.",
    );
}

#[test]
fn worker_panic_path_releases_state_lock_with_drop_state() {
    // Pin (link 6): the panic Err arm explicitly drops the
    // state lock before returning. Without this, the lock
    // would be held until the function exits — but more
    // importantly, the explicit drop documents the
    // ordering invariant.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // E1.2 subsystem 3b: both arms of the ordered completion seam end their
    // state critical section with an explicit drop before the artifacts'
    // observer/wake dispatch runs post-lock.
    let seam_marker = "fn complete_polled_task_ordered(";
    let seam_pos = source.find(seam_marker).expect("ordered completion seam");
    let seam_end = source[seam_pos..]
        .find("fn complete_task_after_unwind_ordered")
        .map_or(source.len(), |offset| seam_pos + offset);
    let seam = &source[seam_pos..seam_end];

    assert!(
        seam.matches("drop(state);").count() >= 2,
        "REGRESSION: the ordered completion seam no longer explicitly \
         drops the state lock in both completion arms. The implicit drop \
         at scope end may delay other workers waiting for the lock — \
         minor performance issue but signals a control-flow \
         change worth investigating.",
    );

    // guard.completed = true is the final action that
    // suppresses the safety-net guard's Drop.
    let err_marker = "Err(payload) => {";
    let pos = source.find(err_marker).expect("Err arm marker");
    let window_end = (pos + 2000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[pos..safe_end];
    assert!(
        body.contains("guard.completed = true;"),
        "REGRESSION: panic Err arm no longer sets \
         guard.completed = true. The safety-net Drop will \
         re-mark the task Panicked unnecessarily — \
         duplicate work, potential lock contention.",
    );
}

#[test]
fn region_quiescence_advances_after_panicked_task_via_is_terminal() {
    // Pin (link 3): can_region_finalize uses is_terminal()
    // for the all-tasks-done check. Since is_terminal()
    // returns true for Panicked, the region can quiesce
    // even if some tasks panicked.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("pub fn can_region_finalize(&self, region_id: RegionId) -> bool {"),
        "REGRESSION: can_region_finalize is gone. Region \
         quiescence after task panic depends on this check.",
    );

    // E2 S4b-1a (br-asupersync-m9wsza) split the finalize gate into a
    // target-threaded core: the public wrapper delegates to
    // can_region_finalize_in, which owns the per-task terminal check. Pin
    // both links so the chain public-entry → core → is_terminal() stays
    // intact regardless of the wrapper/core split.
    let fn_marker = "pub fn can_region_finalize(&self, region_id: RegionId) -> bool {";
    let start = source.find(fn_marker).expect("can_region_finalize fn");
    let wrapper_end = source[start..]
        .find("\n    }\n")
        .expect("can_region_finalize close");
    let wrapper_body = &source[start..start + wrapper_end];
    assert!(
        wrapper_body.contains("can_region_finalize_in("),
        "REGRESSION: can_region_finalize no longer delegates to the \
         target-threaded core. The per-task terminal check below is \
         pinned on the core; if the wrapper grew its own logic the two \
         can drift.",
    );

    let core_marker = "fn can_region_finalize_in(";
    let core_start = source
        .find(core_marker)
        .expect("can_region_finalize_in core");
    let core_end = source[core_start..]
        .find("\n    }\n")
        .expect("can_region_finalize_in close");
    let core_body = &source[core_start..core_start + core_end];
    assert!(
        core_body.contains("t.state.is_terminal()"),
        "REGRESSION: the finalize gate no longer uses \
         is_terminal() for the per-task check. If it now \
         requires a specific outcome variant (e.g., only Ok \
         counts as terminal), panicked tasks would prevent \
         region quiescence — full close-protocol deadlock.",
    );
}

#[test]
fn cross_reference_to_prior_panic_audits() {
    // Pin (documentary): the panic-isolation chain is also
    // covered in two prior audits with different focal
    // points (isolation chain / worker resilience). This
    // audit's slant is cancel-correctness (Panicked is
    // distinct from Cancelled, structured-concurrency
    // invariants hold for both).
    let prior_audits = [
        "tests/scheduler_panic_in_task_isolation_audit.rs",
        "tests/scheduler_worker_resilience_panic_during_poll_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior panic audit `{audit}` is \
             missing. This audit relies on the prior chain \
             coverage; if they're gone, restore them or \
             update this audit to include the deeper \
             checks.",
        );
    }
}
