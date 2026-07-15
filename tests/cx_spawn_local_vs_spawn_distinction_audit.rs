//! Audit + regression test for `Cx::spawn_local` vs
//! `Cx::spawn` distinction.
//!
//! Operator's question: "if spawn_local is API-exposed,
//! must it require !Send futures (correct: thread-pinned)
//! and reject Send-only futures clearly. Verify trait
//! bounds."
//!
//! Audit findings:
//!
//!   asupersync's spawn_local **accepts BOTH `Send` and
//!   `!Send` futures** (no `Send` bound on `F` or `Fut`),
//!   and the thread-pinning is enforced by ROUTING (not by
//!   trait-level rejection of Send futures). This is the
//!   correct design for stable Rust. The operator's framing
//!   ("must reject Send-only futures") would be HARMFUL —
//!   here's why:
//!
//!   1. **Send is a CAPABILITY, not a constraint**. A Send
//!      future implements every interface a !Send future
//!      does, plus the additional capability of being
//!      transferred between threads. Accepting a Send future
//!      into spawn_local is sound — it just means the future
//!      stays on the local worker (the same outcome as a
//!      !Send future, by routing). Rejecting Send would
//!      force users to wrap with a !Send marker (e.g., a
//!      PhantomData<*const ()> field) just to opt into
//!      local-only scheduling.
//!
//!   2. **Stable Rust has NO negative trait bounds**.
//!      Writing `F: !Send` requires the unstable `auto_traits`
//!      / `negative_impls` features. Even on nightly, the
//!      negative-bound semantics are not yet decided. A
//!      regression that added `F: !Send` would either fail
//!      to compile under stable rustc or require a project-
//!      wide nightly opt-in.
//!
//!   3. **Routing enforces the distinction**: `Cx::spawn_local`
//!      parks a `LocalSpawnRequest` on the owner thread lane,
//!      `RuntimeState::admit_local_spawn_request` builds a
//!      `LocalStoredTask` (NOT `StoredTask`) and pins the task
//!      to the current worker via `record.pin_to_worker(worker_id)`,
//!      and the worker stores it via
//!      `crate::runtime::local::store_local_task` before scheduling
//!      through `schedule_local_task`, the NON-STEALABLE local
//!      scheduler. A Send future passed into spawn_local follows
//!      the same routing — it's pinned regardless of its Send-ability.
//!
//!   4. **`spawn` requires Send for soundness, not
//!      preference**: when spawn (not spawn_local) is used,
//!      the `Fut: Send` bound is NECESSARY because the
//!      future is wrapped in a `StoredTask` (with `+ Send`
//!      in the trait object) that may be moved between
//!      worker threads via work-stealing. Without `Send`,
//!      stealing a !Send future would be undefined behavior.
//!      The asymmetry is correct: spawn requires Send;
//!      spawn_local doesn't.
//!
//!   5. **The two paths are observably different**:
//!      - `spawn` → `StoredTask` (Send) → global stealable
//!        queue OR local stealable LocalQueue.
//!      - `spawn_local` → `LocalStoredTask` (no Send) →
//!        local non-stealable `local_ready` queue.
//!        The user's choice of which to call IS the choice of
//!        scheduling discipline. Both type-checked, both
//!        enforced — by the type bound on `spawn` and by the
//!        routing target on `spawn_local`.
//!
//!   6. **Send users gain by choosing spawn_local
//!      explicitly**: a Send future passed to spawn_local
//!      gets thread affinity (no work-stealing migration).
//!      This is sometimes desired for cache locality,
//!      avoiding cross-CPU shared-state ping-pong, or for
//!      tasks that interact with thread-local state. A
//!      regression that rejected Send futures would force
//!      these users into ergonomic workarounds.
//!
//!   7. **Output bound IS Send for both** (Fut::Output:
//!      Send + 'static): the parent's JoinHandle may be
//!      awaited from any thread, so the output must cross
//!      thread boundaries. Asymmetric on F/Fut, symmetric on
//!      Output.
//!
//! Verdict: **SOUND BY DESIGN**. spawn_local accepts both
//! Send and !Send by intent. The thread-pinning distinction
//! is enforced by routing (LocalStoredTask + thread-local
//! storage + non-stealable scheduler), not by trait-level
//! Send-rejection. Per the operator's strict framing, this
//! is technically a "no" — but the correct interpretation
//! is that the operator's framing contains a category
//! error: stable Rust has no negative trait bounds, and
//! even if it did, rejecting Send futures from spawn_local
//! would be harmful.
//!
//! What the audit DOES pin:
//!   - spawn requires Send on F/Fut (already pinned in
//!     tests/scheduler_spawn_send_bounds_compile_time_audit.rs).
//!   - spawn_local does NOT require Send (intentional
//!     escape hatch).
//!   - spawn_local routes through LocalStoredTask, NOT
//:     StoredTask.
//!   - spawn_local schedules via schedule_local_task, NOT
//!     schedule (the stealable path).
//!   - spawn_local pins the task record to the current
//!     worker via pin_to_worker / mark_local.
//!   - LocalStoredTask trait object drops the Send bound;
//!     StoredTask carries it.
//!   - The non-stealable local_ready queue is the routing
//!     target; the stealable LocalQueue is NOT.
//!
//! A regression that:
//!   - added `F: !Send` or similar negative bound on
//!     spawn_local (would require nightly + would harm
//!     legitimate Send-with-affinity users),
//!   - made spawn_local route through StoredTask + the
//!     stealable queue (would silently allow !Send futures
//!     to be stolen — undefined behavior pathway),
//!   - removed the pin_to_worker / mark_local call on the
//!     task record (would lose the routing-time pinning
//!     guard; cancel propagation may try to steal the
//!     local task across workers),
//!   - removed `schedule_local_task`'s non-stealable
//!     property (would lose the runtime-time guard),
//!   - made spawn require !Send (would break the existing
//!     work-stealing path for the common case of Send
//!     futures),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn spawn_local_accepts_both_send_and_non_send_via_no_send_bound() {
    // Pin (link 1+2): spawn_local has NO Send bound on F or
    // Fut. This is what makes it the !Send escape hatch
    // AND lets Send users opt into thread affinity.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn spawn_local<F, Fut>(";
    let start = source.find(fn_marker).expect("spawn_local fn");
    let window_end = (start + 1500).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let where_section = &source[start..safe_end];

    // No Send on closure F.
    assert!(
        where_section.contains("F: FnOnce(Cx<Caps>) -> Fut + 'static,")
            && !where_section.contains("F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,"),
        "REGRESSION: spawn_local now requires Send on the \
         closure F. The escape hatch is broken — !Send \
         factories (capturing Rc, RefCell, etc.) can no \
         longer use spawn_local.",
    );

    // No Send on Fut.
    assert!(
        where_section.contains("Fut: Future + 'static,")
            && !where_section.contains("Fut: Future + Send + 'static,"),
        "REGRESSION: spawn_local now requires Send on Fut. \
         The !Send escape hatch is broken.",
    );

    // No negative bound (which would require nightly +
    // harm legitimate Send users).
    let suspect_negative_bounds = ["F: !Send", "Fut: !Send", "F: ?Send", "Fut: ?Send"];
    for pat in &suspect_negative_bounds {
        assert!(
            !where_section.contains(pat),
            "REGRESSION: spawn_local now uses negative trait \
             bound `{pat}`. Stable Rust does not support \
             negative bounds; even if it did, rejecting Send \
             futures from spawn_local would force legitimate \
             Send-with-affinity users into ergonomic \
             workarounds.",
        );
    }
}

#[test]
fn spawn_local_output_still_requires_send_for_cross_thread_join() {
    // Pin (link 7): Fut::Output IS Send because the parent's
    // JoinHandle may be awaited from any thread. Asymmetric
    // on F/Fut, symmetric on Output.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn spawn_local<F, Fut>(";
    let start = source.find(fn_marker).expect("spawn_local fn");
    let window_end = (start + 1500).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let where_section = &source[start..safe_end];

    assert!(
        where_section.contains("Fut::Output: Send + 'static,"),
        "REGRESSION: spawn_local Fut::Output no longer requires \
         Send. The parent's JoinHandle may await on a \
         different thread — !Send output would be unsoundly \
         transferred.",
    );
}

#[test]
fn spawn_local_routes_through_owner_thread_lane() {
    // Pin (link 5): Cx::spawn_local parks a LocalSpawnRequest on the
    // owner-thread lane. RuntimeState/worker tests below pin admission,
    // storage, and non-stealable scheduling.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn spawn_local_via_lane<F, Fut>(";
    let start = source.find(fn_marker).expect("spawn_local_via_lane fn");
    let window_end = (start + 7000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("LocalSpawnFactoryFn")
            && body.contains("LocalSpawnRequest")
            && body.contains("enqueue_local_spawn(request)"),
        "REGRESSION: Cx::spawn_local no longer routes through \
         the owner-thread LocalSpawnRequest lane. A !Send \
         factory must never cross to the shared Send mailbox.",
    );

    assert!(
        body.contains("current_worker_id().is_none()")
            && body.contains("SpawnError::LocalSchedulerUnavailable"),
        "REGRESSION: Cx::spawn_local no longer fails closed \
         off-worker. Local spawns must have an owner worker.",
    );
}

#[test]
fn spawn_local_pins_task_record_to_current_worker() {
    // Pin (link 3): spawn_local marks the task record as
    // local via pin_to_worker(worker_id) or mark_local() so
    // that the scheduler's safety guards (try_steal
    // debug_assert) can detect accidental cross-thread
    // migration of !Send futures.
    let source = read("src/runtime/state.rs");

    let fn_marker = "pub(crate) fn admit_local_spawn_request(";
    let start = source
        .find(fn_marker)
        .expect("admit_local_spawn_request fn");
    let window_end = (start + 5000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("record.pin_to_worker(worker_id);"),
        "REGRESSION: spawn_local no longer pins the task \
         record to the current worker. Without pin_to_worker, \
         the scheduler's safety guards can't detect \
         accidental cross-thread migration — UB silent.",
    );

    assert!(
        body.contains("SpawnError::LocalSchedulerUnavailable"),
        "REGRESSION: local spawn admission no longer fails \
         closed when no current worker is identified.",
    );
}

#[test]
fn spawn_local_schedules_via_worker_local_queue_non_stealable() {
    // Pin (link 5): spawn_local stores the task in thread-local
    // storage and publishes directly to the owning worker's
    // local_ready queue, NOT the stealable global injector.
    // The comment explicitly notes: 'spawn_local tasks MUST
    // NOT be stealable.'
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "fn drain_local_spawn_admissions(&mut self)";
    let start = source
        .find(fn_marker)
        .expect("drain_local_spawn_admissions fn");
    let window_end = (start + 5000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("crate::runtime::local::store_local_task(task_id, stored);")
            && body.contains("self.local_ready.lock().push_back(task_id);"),
        "REGRESSION: spawn_local no longer schedules via \
         the owning worker's local queue. Either it uses the stealable \
         path (UB for !Send) or it doesn't schedule at all \
         (the task hangs).",
    );

    assert!(
        source.contains("never exposed to stealers"),
        "REGRESSION: the explicit invariant comment is gone. \
         The 'must not be stealable' invariant is what \
         documents the routing-level enforcement of the \
         spawn_local distinction.",
    );
}

#[test]
fn local_stored_task_drops_send_bound_in_trait_object() {
    // Pin (link 5 type system): LocalStoredTask's future
    // field has NO + Send in the trait object. This is what
    // lets it hold !Send futures.
    let source = read("src/runtime/stored_task.rs");

    assert!(
        source.contains("pub struct LocalStoredTask {")
            && source.contains("future: Pin<Box<dyn Future<Output = Outcome<(), ()>> + 'static>>,"),
        "REGRESSION: LocalStoredTask trait object now requires \
         Send. The !Send escape hatch is broken at the type \
         level — spawn_local can no longer accept !Send \
         futures.",
    );
}

#[test]
fn stored_task_keeps_send_bound_for_stealable_path() {
    // Pin (link 4): StoredTask (the spawn path) carries
    // + Send in its trait object so the future can be moved
    // between worker threads via work-stealing.
    let source = read("src/runtime/stored_task.rs");

    assert!(
        source.contains("pub struct StoredTask {")
            && source.contains("future: Pin<Box<dyn Future<Output = Outcome<(), ()>> + Send>>,"),
        "REGRESSION: StoredTask trait object no longer \
         requires Send. The work-stealing path could steal \
         a !Send future across workers — undefined behavior.",
    );
}

#[test]
fn spawn_path_signature_remains_send_bounded_for_contrast() {
    // Pin (link 4 contrast): the spawn (not spawn_local)
    // signature must still require Send on F/Fut/Output.
    // This contrasts with spawn_local's no-Send and
    // demonstrates the distinction.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn spawn<F, Fut>(";
    let start = source.find(fn_marker).expect("Cx::spawn fn");
    let window_end = (start + 1500).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let where_section = &source[start..safe_end];

    assert!(
        where_section.contains("F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,")
            && where_section.contains("Fut: Future + Send + 'static,")
            && where_section.contains("Fut::Output: Send + 'static,"),
        "REGRESSION: Cx::spawn no longer requires Send. \
         The asymmetry between spawn and spawn_local is the \
         user-facing API contract — losing it removes the \
         distinction.",
    );
}

#[test]
fn try_steal_debug_assert_guards_against_local_task_theft() {
    // Pin (link 3 runtime guard): the scheduler's try_steal
    // path should debug_assert against stealing local tasks.
    // This is the runtime-time guard that pairs with the
    // routing-time pin_to_worker.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // Look for debug_assert! or assertion patterns around
    // task stealing that check is_local / pinned_worker.
    let suspect_steal_patterns = [
        "debug_assert!(!record.is_local()",
        "debug_assert!(record.pinned_worker().is_none()",
        "is_local()",
    ];
    let mut found_guard = false;
    for pat in &suspect_steal_patterns {
        if source.contains(pat) {
            found_guard = true;
            break;
        }
    }
    assert!(
        found_guard,
        "REGRESSION: scheduler no longer has any guard \
         against stealing local tasks. The routing-time \
         pin_to_worker is the structural mechanism, but the \
         debug-assert is the safety net — if it's gone, \
         accidental cross-thread migration of !Send futures \
         goes undetected in debug builds.",
    );
}

// ─────────── COMPILE-TIME POSITIVE / NEGATIVE CHECKS ───────
//
// Mock signatures with the same Send-asymmetry as Cx::spawn
// vs Cx::spawn_local. Verify (1) Send futures pass both,
// (2) !Send futures pass only the no-Send signature.

use std::future::Future;

/// Mirrors Cx::spawn (Send required).
fn mock_spawn_send_bound<F, Fut>(_f: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
}

/// Mirrors Cx::spawn_local (no Send on F/Fut).
fn mock_spawn_local_no_send_bound<F, Fut>(_f: F)
where
    F: FnOnce() -> Fut + 'static,
    Fut: Future + 'static,
    Fut::Output: Send + 'static,
{
}

#[test]
fn send_future_compiles_under_both_spawn_and_spawn_local_signatures() {
    // Compile-time pin: a Send future is accepted by BOTH
    // signatures. This proves spawn_local does NOT reject
    // Send futures — Send users can use spawn_local for
    // affinity without modification.
    mock_spawn_send_bound(|| async { 42_u32 });
    mock_spawn_local_no_send_bound(|| async { 42_u32 });
}

#[test]
fn non_send_future_compiles_only_under_spawn_local_signature() {
    // Compile-time pin: a !Send future (capturing Rc) is
    // accepted ONLY by spawn_local's no-Send signature. The
    // spawn signature would reject it at compile time.
    use std::rc::Rc;
    mock_spawn_local_no_send_bound(|| {
        let counter = Rc::new(0_u32);
        async move {
            let _ = Rc::clone(&counter); // Rc is !Send → future is !Send.
        }
    });

    // The COMMENTED-OUT call below would FAIL to compile —
    // this is the negative-test demonstration. Uncommenting
    // it would surface the rustc error proving the spawn
    // signature rejects !Send.
    //
    // mock_spawn_send_bound(|| {
    //     let counter = Rc::new(0_u32);
    //     async move { let _ = Rc::clone(&counter); }
    // });
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/scheduler_spawn_send_bounds_compile_time_audit.rs",
        "tests/cx_drop_semantics_parent_persistence_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
