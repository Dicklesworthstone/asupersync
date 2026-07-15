//! Audit + regression test for `TaskHandle::abort` vs
//! `Cx::cancel*` semantics.
//!
//! Operator's question: "abort is hard-kill (bypass drop
//! guards), cancel is graceful (deliver via cancel-bit).
//! Verify these are distinct paths and abort doesn't
//! accidentally trigger cancel-handlers. Per asupersync
//! spec."
//!
//! Audit findings:
//!
//!   The operator's framing contains a **category error**:
//!   asupersync has NO "hard-kill bypass drop guards"
//!   pathway. In stable Rust under
//:   `#![deny(unsafe_code)]`, you cannot kill a thread or
//!   forcibly terminate a future — there is no syscall, no
//:   library primitive, no language construct that does
//!   this without UB.
//!
//!   Both `TaskHandle::abort()` and `Cx::cancel*()` are
//!   **graceful cancellations via the SAME fast_cancel
//!   atomic store**. Drop guards / destructors / Drop impls
//!   ALL run normally — there's no "bypass" path. The
//!   "abort" naming is borrowed from tokio's API where it
//!   has identical semantics.
//!
//!   Both paths set:
//!     - `inner.cancel_requested = true`
//!     - `inner.fast_cancel.store(true, Release)`
//!     - `inner.cancel_reason = Some(reason)` (or strengthen
//!       existing)
//!
//!   `Cx::cancel*()` captures and dispatches its cancel Waker
//!   directly. Runtime-managed `TaskHandle` cancellation has
//!   one extra ownership boundary: the caller updates only
//!   checkpoint-visible Cx state and enqueues a callback-free
//!   command. The runtime transitions the authoritative
//!   TaskRecord, publishes the cancel lane, and only then
//!   dispatches panic-isolated Waker effects. The cancellation
//!   protocol is the same; its scheduling boundary differs.
//!
//!   1. **Caller**: `TaskHandle::abort` is called from
//!      OUTSIDE the task (the parent holds the handle and
//!      requests cancel). `Cx::cancel*` is called from
//!      INSIDE the task (self-cancel by the running future).
//!
//!   2. **Reason kind**:
//!      - `abort()` → `CancelReason::user("abort")` (=
//:        CancelKind::User).
//!      - `abort_with_reason(r)` → user-supplied reason.
//!      - `cancel_with(kind, msg)` → user-specified kind +
//!        message.
//!      - `cancel_fast(kind)` → minimal-attribution kind +
//!        region.
//!
//!   3. **Handle access**: `TaskHandle::abort` operates on
//:      a `Weak<RwLock<CxInner>>` (parent's handle to the
//!      child); `Cx::cancel*` operates on the running task's
//!      own `Arc<RwLock<CxInner>>`.
//!
//!   The TaskHandle chain is:
//!
//!     1. Acquire the CxInner write lock.
//!     2. Set cancel_requested = true.
//!     3. fast_cancel.store(true, Release).
//!     4. Set/strengthen cancel_reason; do not snapshot Wakers.
//!     5. Release the Cx and admission-cache locks.
//!     6. Enqueue `{task_id, effective_reason}` on the runtime gateway.
//!     7. The runtime-owned consumer reconciles the TaskRecord and returns
//!        effects. If the task checkpoints first, that checkpoint materializes
//!        the same authoritative request and a delayed command is idempotent.
//!     8. Scheduler publishes the cancel lane, then dispatches effects. A
//!        structurally invalid delegated route remains fail-closed in
//!        `DelegatedCancel` and requires a fresh command after repair; it does
//!        not self-requeue and monopolize the mailbox.
//!     9. The task's NEXT cx.checkpoint() returns Err(Cancelled).
//!
//!   "Drop guards" (Rust destructors, finalizer guards,
//!   panic-recovery TaskExecutionGuard, RegionRunner::Drop)
//!   ALL fire normally on cancel via either path. There is
//!   NO "bypass" — that would require unsafe-code thread
//!   termination which asupersync forbids.
//!
//! Verdict: **SOUND BY DESIGN**. The operator's hard-kill
//! framing is a category error — asupersync has no such
//! path. abort and cancel are SEMANTIC SYNONYMS via the
//: same fast_cancel mechanism, differentiated only by:
//!   - WHO requests (parent holding handle vs self).
//!   - WHAT reason kind (User by default for abort; varies
//:     for cancel).
//!   - HOW handle access works (Weak vs Arc).
//!
//! Drop guards run on BOTH paths. Cancel-handlers run on
//: BOTH paths. There is no "abort doesn't trigger cancel-
//! handlers" semantic — the cancel-handlers ARE the
//: graceful-cancel mechanism, and BOTH apis trigger them.
//!
//! No bead filed. The two APIs are both graceful-cancel
//! variants serving different user contexts (parent vs
//! self).
//!
//! A regression that:
//!   - introduced a true hard-kill bypass via unsafe code
//!     (would violate #![deny(unsafe_code)] AND would be a
//:     soundness hazard — destructors must run for
//:     resource safety),
//!   - added a separate "abort_force" path that bypasses
//!     the cancel-waker (would skip cross-thread
//!     observability — parked tasks would miss the abort),
//!   - made `abort()` and `cancel_with()` differ in
//!     observable behavior beyond the reason kind (would
//!     introduce subtle semantic divergence — debugging
//!     gets harder),
//!   - dispatched TaskHandle Wakers in the caller/Drop stack,
//!     or before cancel-lane publication (would permit lock
//!     reentrancy or miss the parked-task scheduling boundary),
//!   - introduced std::process::abort or libc::pthread_cancel
//!     in the abort path (UB pathway; thread terminates
//!     without destructor unwinding),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn task_handle_abort_publishes_via_same_fast_cancel_release_store_as_cancel() {
    // Pin (link 1): TaskHandle::abort_with_reason uses the
    // same fast_cancel.store(true, Release) + cancel_reason
    // mechanism as Cx::cancel_with. This is the structural
    // proof that abort is a graceful-cancel synonym, NOT
    // a hard-kill.
    let source = read("src/runtime/task_handle.rs");

    let fn_marker = "pub fn abort_with_reason(&self, reason: CancelReason) {";
    let start = source.find(fn_marker).expect("abort_with_reason fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("abort_with_reason close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("apply_or_defer_cancel_reason(")
            && !body.contains(".dispatch()")
            && source.contains("let mut cached = requested.write();")
            && source.contains(".filter(|task| task.is_published())")
            && source.contains("strengthen_cancel_reason_locked(&mut lock, &strongest_requested);")
            && source.contains("lock.cancel_requested = true;")
            && source.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: abort_with_reason no longer publishes \
         through the admission gate and cancel_requested + \
         fast_cancel.store(Release). \
         Either abort is now a true hard-kill (impossible \
         in stable Rust, would require unsafe code) OR the \
         publish mechanism diverged from Cx::cancel_with.",
    );
}

#[test]
fn task_handle_abort_strengthens_existing_cancel_reason() {
    // Pin (link 1 idempotency): abort_with_reason strengthens
    // the existing cancel_reason — preserves attribution
    // when called multiple times. Same coalescing as
    // request_cancel_with_budget.
    let source = read("src/runtime/task_handle.rs");

    let fn_marker = "pub fn abort_with_reason(&self, reason: CancelReason) {";
    let start = source.find(fn_marker).expect("abort_with_reason fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("abort_with_reason close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("apply_or_defer_cancel_reason(")
            && !body.contains(".dispatch()")
            && source.contains("if let Some(existing) = cached.as_mut() {")
            && source.contains("if let Some(existing) = &mut lock.cancel_reason {")
            && source.contains("existing.strengthen(reason)"),
        "REGRESSION: abort no longer strengthens existing \
         cancel_reason. Multi-abort attribution lost — \
         last-abort-wins instead of strongest.",
    );
}

#[test]
fn task_handle_abort_defers_panic_isolated_wakers_to_runtime_publication() {
    // Pin (link 2): the caller-side helper updates only
    // checkpoint-visible Cx state and enqueues plain data after
    // both locks are gone. The runtime snapshots Wakers during the
    // authoritative TaskRecord transition, publishes every cancel
    // lane, and only then panic-isolating dispatches the effects.
    let source = read("src/runtime/task_handle.rs");
    let mailbox = read("src/runtime/spawn_mailbox.rs");
    let state = read("src/runtime/state.rs");
    let scheduler = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "pub fn abort_with_reason(&self, reason: CancelReason) {";
    let start = source.find(fn_marker).expect("abort_with_reason fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("abort_with_reason close");
    let body = &source[start..start + body_end];
    let gate_start = source
        .find("fn apply_or_defer_cancel_reason(")
        .expect("admission-aware abort helper");
    let gate_end = source[gate_start..]
        .find("\n}\n")
        .expect("admission-aware abort helper close");
    let gate_body = &source[gate_start..gate_start + gate_end];

    assert!(
        body.contains("apply_or_defer_cancel_reason(")
            && !body.contains(".dispatch()")
            && source.matches("apply_or_defer_cancel_reason(").count() >= 3
            && gate_body.contains("let mut cached = requested.write();")
            && gate_body.contains(".filter(|task| task.is_published())")
            && !gate_body.contains(".dispatch()")
            && !gate_body.contains("cancel_waker_snapshot")
            && gate_body.contains("drop(cached);")
            && gate_body.contains("changed || lock.runnable_publication.is_delegated_cancel()")
            && gate_body.contains("gateway.enqueue_handle_cancel(task_id, effective_reason)")
            && mailbox.contains("pub(crate) fn enqueue_handle_cancel(")
            && state.contains("pub(crate) fn cancel_task_for_handle(")
            && state.contains("record.request_cancel_for_handle(reason)")
            && scheduler.contains("record.publish_delegated_cancel_lane(")
            && scheduler.contains("publication_wakes.retire_without_dispatch();")
            && !scheduler.contains("mailbox.enqueue_handle_cancel(task_id, reason);")
            && scheduler.contains("for wakes in wakes_to_dispatch")
            && scheduler.contains("wakes.dispatch();"),
        "REGRESSION: TaskHandle/JoinFuture abort no longer crosses the \
         callback-free runtime gateway before TaskRecord transition, \
         cancel-lane publication, and post-publication Waker dispatch. \
         Caller locks may be reentered or parked tasks may miss cancellation.",
    );
}

#[test]
fn task_handle_abort_default_reason_is_user_kind_not_force_kill() {
    // Pin (link 1): the default abort() (no-args) uses
    // CancelReason::user("abort") — CancelKind::User.
    // There is NO "ForceKill" or "Abort" CancelKind variant.
    let source = read("src/runtime/task_handle.rs");

    let fn_marker = "pub fn abort(&self) {";
    let start = source.find(fn_marker).expect("abort fn");
    let body_end = source[start..].find("\n    }\n").expect("abort close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.abort_with_reason(CancelReason::user(\"abort\"));"),
        "REGRESSION: abort default reason changed. The \
         User kind is the documented graceful-cancel \
         attribution; if abort now uses a different kind, \
         it would silently change cancel-cause chain \
         attribution.",
    );

    // Forbid hard-kill kinds.
    let cancel_kinds = read("src/types/cancel.rs");
    let suspect_force_kinds = ["ForceKill,", "HardAbort,", "Force,"];
    for pat in &suspect_force_kinds {
        assert!(
            !cancel_kinds.contains(pat),
            "REGRESSION: CancelKind now has `{pat}` — a \
             hard-kill variant. asupersync forbids unsafe \
             thread termination; this variant has no \
             implementation path that satisfies the \
             contract.",
        );
    }
}

#[test]
fn cx_cancel_with_publishes_via_same_fast_cancel_release_store_as_abort() {
    // Pin (link 1+2 symmetry): Cx::cancel_with uses the
    // SAME fast_cancel.store(true, Release) mechanism as
    // TaskHandle::abort. The ONLY differences are the
    // reason kind/message and the handle access pattern.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {";
    let start = source.find(fn_marker).expect("cancel_with fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("cancel_with close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("inner.cancel_requested = true;")
            && body.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: Cx::cancel_with no longer publishes via \
         cancel_requested + fast_cancel.store(Release). The \
         self-cancel API diverges from abort — observable \
         behavior conflation or split.",
    );

    assert!(
        body.contains("inner.cancel_reason = Some(reason);"),
        "REGRESSION: Cx::cancel_with no longer sets \
         cancel_reason. Self-cancel cant carry attribution.",
    );
}

#[test]
fn cx_cancel_fast_uses_same_publish_mechanism_minimal_attribution() {
    // Pin (link 1+2): Cx::cancel_fast is the perf-tuned
    // self-cancel — minimal attribution but SAME publish
    // mechanism. NOT a separate hard-kill.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn cancel_fast(&self, kind: CancelKind) {";
    let start = source.find(fn_marker).expect("cancel_fast fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("cancel_fast close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("inner.cancel_requested = true;"),
        "REGRESSION: Cx::cancel_fast no longer sets \
         cancel_requested. The fast-path self-cancel \
         diverged from the slow-path cancel_with.",
    );
}

#[test]
fn no_unsafe_thread_termination_in_abort_or_cancel_paths() {
    // Pin (link 5): neither abort nor cancel paths use
    // unsafe code for thread termination. asupersync
    // forbids unsafe code; any pthread_cancel /
    // process::abort / TerminateThread call would be a
    // soundness hazard.
    for rel in &["src/runtime/task_handle.rs", "src/cx/cx.rs"] {
        let source = read(rel);
        let suspect_force_paths = [
            "libc::pthread_cancel",
            "libc::pthread_kill",
            "TerminateThread",
            "std::process::abort()",
            "std::process::exit(",
            "std::intrinsics::abort",
        ];
        for pat in &suspect_force_paths {
            assert!(
                !source.contains(pat),
                "REGRESSION: {rel} now contains `{pat}` — a \
                 hard-kill path. This violates \
                 #![deny(unsafe_code)] AND breaks \
                 destructor unwinding contracts. Resource \
                 safety hazard.",
            );
        }
    }
}

#[test]
fn abort_path_uses_weak_handle_to_avoid_keeping_task_alive() {
    // Pin (link 3): TaskHandle resolves cancellation through
    // Weak<RwLock<CxInner>> handles — either the mailbox
    // admission weak handle or the original construction-time
    // weak. The parent's reference doesn't keep the child task
    // alive. Symmetric with the rest of the cancel/abort contract.
    let source = read("src/runtime/task_handle.rs");

    let helper_start = source
        .find("fn apply_or_defer_cancel_reason(")
        .expect("admission-aware abort helper");
    let helper_end = source[helper_start..]
        .find("\n}\n")
        .expect("admission-aware abort helper close");
    let helper_body = &source[helper_start..helper_start + helper_end];

    assert!(
        helper_body.contains("admitted.cx_inner.upgrade()")
            && helper_body.contains("fallback_inner.upgrade()"),
        "REGRESSION: abort no longer upgrades the canonical admitted weak \
         handle or the construction-time fallback weak at the gateway \
         boundary.",
    );

    assert!(
        !helper_body.contains("fallback_inner.write()")
            && !helper_body.contains("fallback_inner.read()"),
        "REGRESSION: the cancellation helper no longer upgrades only weak \
         handles. The weak-handle pattern is broken — abort \
         either keeps the task alive (semantic leak) or panics \
         on no-upgrade.",
    );
}

#[test]
fn cancel_handlers_run_on_both_abort_and_cancel_via_same_checkpoint_path() {
    // Pin (link 4 - same observation): both abort and
    // cancel set fast_cancel + cancel_reason. The user's
    // checkpoint observes via the SAME path — there is no
    // separate handler routing for "abort vs cancel".
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // checkpoint reads fast_cancel via Acquire — the same
    // atomic that abort/cancel publish.
    assert!(
        body.contains("guard.fast_cancel.load(std::sync::atomic::Ordering::Acquire)"),
        "REGRESSION: checkpoint no longer reads fast_cancel \
         with Acquire. The single-observation-path contract \
         is broken — abort and cancel may now route through \
         different observation mechanisms.",
    );
}

#[test]
fn abort_does_not_have_separate_force_kill_method() {
    // Pin (link 5 anti-conflation): there must be NO method
    // like `abort_force` / `abort_now` / `terminate` that
    // claims to bypass drop guards. Such a method would be
    // a soundness hazard.
    let source = read("src/runtime/task_handle.rs");

    let suspect_methods = [
        "pub fn abort_force(",
        "pub fn abort_now(",
        "pub fn terminate(",
        "pub fn force_kill(",
        "pub fn hard_abort(",
    ];
    for pat in &suspect_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: TaskHandle now has `{pat}` — \
             claiming hard-kill semantics. asupersync \
             cannot soundly implement this; the method must \
             either be a synonym for graceful abort \
             (confusing API) or a soundness hazard.",
        );
    }
}

#[test]
fn abort_with_reason_does_not_call_drop_guard_bypass_machinery() {
    // Pin (link 5): abort_with_reason does NOT call any
    // mem::forget or ManuallyDrop pattern that would skip
    // destructor execution. The graceful-cancel contract
    // requires destructors to run.
    let source = read("src/runtime/task_handle.rs");

    let fn_marker = "pub fn abort_with_reason(&self, reason: CancelReason) {";
    let start = source.find(fn_marker).expect("abort_with_reason fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("abort_with_reason close");
    let body = &source[start..start + body_end];

    let suspect_drop_bypass = [
        "std::mem::forget(",
        "mem::forget(",
        "ManuallyDrop::new(",
        "std::ptr::drop_in_place(",
    ];
    for pat in &suspect_drop_bypass {
        assert!(
            !body.contains(pat),
            "REGRESSION: abort_with_reason now contains \
             drop-bypass machinery (`{pat}`). Resources \
             held by the task may leak; structured-\
             concurrency cleanup is silently skipped.",
        );
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_cancel_signal_coalescing_audit.rs",
        "tests/runtime_cancel_cause_kinds_distinct_audit.rs",
        "tests/cx_checkpoint_cancel_fail_fast_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
