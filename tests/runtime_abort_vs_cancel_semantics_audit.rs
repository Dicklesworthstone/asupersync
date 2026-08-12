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
//!   `#![deny(unsafe_code)]`, you cannot kill a thread or
//!   forcibly terminate a future — there is no syscall, no
//!   library primitive, no language construct that does
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
//!        CancelKind::User).
//!      - `abort_with_reason(r)` → user-supplied reason.
//!      - `cancel_with(kind, msg)` → user-specified kind +
//!        message.
//!      - `cancel_fast(kind)` → minimal-attribution kind +
//!        region.
//!
//!   3. **Handle access**: `TaskHandle::abort` operates on
//!      a `Weak<RwLock<CxInner>>` (parent's handle to the
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
//! Verdict on the original hard-kill question: abort and
//! cancel are graceful-cancellation variants via the same
//! fast_cancel mechanism, differentiated only by:
//!   - WHO requests (parent holding handle vs self).
//!   - WHAT reason kind (User by default for abort; varies
//!     for cancel).
//!   - HOW handle access works (Weak vs Arc).
//!
//! Drop guards run on BOTH paths. Cancel-handlers run on
//! BOTH paths. There is no "abort doesn't trigger cancel-
//! handlers" semantic — the cancel-handlers ARE the
//! graceful-cancel mechanism, and BOTH APIs trigger them.
//!
//! The native behavioral expansion of this audit nevertheless
//! exposed a serious implementation defect (asupersync-yqlhh7):
//! a parked cancel-aware operation could return its typed
//! cancellation value, only for its spawn wrapper to discard
//! that value by publishing through the now-cancelled child Cx.
//! The repair makes mailbox and scope spawn adapters classify completion before
//! one non-cancellable terminal-publication boundary. The tests below prove the
//! actual native parked state, exact nested result, pre-poll and structured
//! task-level cancellation, and resource cleanup without changing cooperative
//! cancellation or acknowledged-cleanup semantics.
//!
//! A regression that:
//!   - introduced a true hard-kill bypass via unsafe code
//!     (would violate #![deny(unsafe_code)] AND would be a
//!     soundness hazard — destructors must run for
//!     resource safety),
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
//!     would all be caught by the behavioral and structural pins below.

use asupersync::channel::mpsc::{self, SendError};
use asupersync::cx::Cx;
use asupersync::runtime::{JoinError, RuntimeBuilder, yield_now};
use asupersync::sync::{
    AcquireError, LockError, Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore,
};
use asupersync::types::CancelKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn abort_repolls_a_mutex_parked_operation_to_graceful_cancellation() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");

    runtime.block_on(runtime.handle().spawn(async {
        let cx: Cx = Cx::current().expect("runtime task installs a current Cx");
        let mutex = Arc::new(Mutex::new(()));
        let holder = mutex
            .try_lock_owned()
            .expect("seed mutex must be available");
        let waiter_mutex = Arc::clone(&mutex);
        let mut waiter = cx
            .spawn(move |waiter_cx| async move {
                OwnedMutexGuard::lock(waiter_mutex, &waiter_cx)
                    .await
                    .map(drop)
            })
            .expect("runtime-backed Cx must admit waiter task");

        for _ in 0..256 {
            if mutex.waiters() == 1 {
                break;
            }
            yield_now().await;
        }
        assert_eq!(
            mutex.waiters(),
            1,
            "waiter must be genuinely parked before abort so this test cannot pass via an admission race",
        );

        waiter.abort();
        let result = waiter.join(&cx).await;
        assert!(
            matches!(result, Ok(Err(LockError::Cancelled))),
            "aborting a mutex-parked operation must repoll it to its graceful inner cancellation result; got {result:?}",
        );

        drop(holder);
        assert_eq!(
            mutex.waiters(),
            0,
            "graceful cancellation must unlink the parked mutex waiter",
        );
    }));
}

#[test]
fn acknowledged_cancellation_can_finish_async_cleanup_before_join_completes() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");

    runtime.block_on(runtime.handle().spawn(async {
        let cx: Cx = Cx::current().expect("runtime task installs a current Cx");
        let mutex = Arc::new(Mutex::new(()));
        let holder = mutex
            .try_lock_owned()
            .expect("seed mutex must be available");
        let cleanup_completed = Arc::new(AtomicBool::new(false));
        let waiter_mutex = Arc::clone(&mutex);
        let waiter_cleanup_completed = Arc::clone(&cleanup_completed);
        let mut waiter = cx
            .spawn(move |waiter_cx| async move {
                let result = OwnedMutexGuard::lock(waiter_mutex, &waiter_cx)
                    .await
                    .map(drop);
                if matches!(result, Err(LockError::Cancelled)) {
                    // Deliberately cross another Pending after the primitive's
                    // checkpoint acknowledged cancellation. The spawn/result
                    // boundary must not mistake protocol cleanup for an
                    // unresponsive cancellation-blind future.
                    yield_now().await;
                    waiter_cleanup_completed.store(true, Ordering::Release);
                }
                result
            })
            .expect("runtime-backed Cx must admit waiter task");

        for _ in 0..256 {
            if mutex.waiters() == 1 {
                break;
            }
            yield_now().await;
        }
        assert_eq!(
            mutex.waiters(),
            1,
            "waiter must be genuinely parked before abort",
        );

        waiter.abort();
        let result = waiter.join(&cx).await;
        assert!(
            matches!(result, Ok(Err(LockError::Cancelled))),
            "cleanup must preserve the operation-level cancellation result; got {result:?}",
        );
        assert!(
            cleanup_completed.load(Ordering::Acquire),
            "a task that acknowledged cancellation must finish asynchronous protocol cleanup",
        );

        drop(holder);
        assert_eq!(mutex.waiters(), 0, "cleanup must unlink the mutex waiter");
    }));
}

#[test]
fn local_spawn_abort_preserves_mutex_cancellation_and_waiter_cleanup() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");

    runtime.block_on(runtime.handle().spawn(async {
        let cx: Cx = Cx::current().expect("runtime task installs a current Cx");
        let mutex = Arc::new(Mutex::new(()));
        let holder = mutex
            .try_lock_owned()
            .expect("seed mutex must be available");
        let waiter_mutex = Arc::clone(&mutex);
        let mut waiter = cx
            .spawn_local(move |waiter_cx| async move {
                OwnedMutexGuard::lock(waiter_mutex, &waiter_cx)
                    .await
                    .map(drop)
            })
            .expect("worker-owned Cx must admit local waiter task");

        for _ in 0..256 {
            if mutex.waiters() == 1 {
                break;
            }
            yield_now().await;
        }
        assert_eq!(
            mutex.waiters(),
            1,
            "local waiter must be genuinely parked before abort",
        );

        waiter.abort();
        let result = waiter.join(&cx).await;
        assert!(
            matches!(result, Ok(Err(LockError::Cancelled))),
            "local-spawn abort must preserve the mutex operation's typed cancellation; got {result:?}",
        );

        drop(holder);
        assert_eq!(
            mutex.waiters(),
            0,
            "local-spawn cancellation must unlink the parked mutex waiter",
        );
    }));
}

#[test]
fn cross_worker_abort_preserves_mutex_cancellation_and_waiter_cleanup() {
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .build()
        .expect("build two-worker runtime");

    runtime.block_on(runtime.handle().spawn(async {
        let cx: Cx = Cx::current().expect("runtime task installs a current Cx");
        let mutex = Arc::new(Mutex::new(()));
        let holder = mutex
            .try_lock_owned()
            .expect("seed mutex must be available");
        let waiter_mutex = Arc::clone(&mutex);
        let mut waiter = cx
            .spawn(move |waiter_cx| async move {
                OwnedMutexGuard::lock(waiter_mutex, &waiter_cx)
                    .await
                    .map(drop)
            })
            .expect("runtime-backed Cx must admit waiter task");

        for _ in 0..512 {
            if mutex.waiters() == 1 {
                break;
            }
            yield_now().await;
        }
        assert_eq!(
            mutex.waiters(),
            1,
            "cross-worker waiter must be genuinely parked before abort",
        );

        waiter.abort();
        let result = waiter.join(&cx).await;
        assert!(
            matches!(result, Ok(Err(LockError::Cancelled))),
            "cross-worker abort must preserve the mutex operation's typed cancellation; got {result:?}",
        );

        drop(holder);
        assert_eq!(
            mutex.waiters(),
            0,
            "cross-worker cancellation must unlink the parked mutex waiter",
        );
    }));
}

#[test]
fn abort_before_first_poll_keeps_task_level_cancellation_attribution() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");

    runtime.block_on(runtime.handle().spawn(async {
        let cx: Cx = Cx::current().expect("runtime task installs a current Cx");
        let polls = Arc::new(AtomicUsize::new(0));
        let child_polls = Arc::clone(&polls);
        let mut child = cx
            .spawn(move |child_cx| async move {
                child_polls.fetch_add(1, Ordering::AcqRel);
                assert!(
                    child_cx.checkpoint().is_err(),
                    "an abort requested before first poll must be visible to the child"
                );
                "cancelled-before-first-work"
            })
            .expect("runtime-backed Cx must admit child task");

        // The current task retains the only worker until it awaits below, so
        // this abort is deterministically published before the child's first
        // poll rather than racing a second executor thread.
        child.abort();
        let result = child.join(&cx).await;
        assert!(
            matches!(
                result,
                Err(JoinError::Cancelled(ref reason)) if reason.kind == CancelKind::User
            ),
            "pre-poll abort must remain task-level cancellation even though user code receives one cleanup poll; got {result:?}",
        );
        assert_eq!(
            polls.load(Ordering::Acquire),
            1,
            "the cancelled child must not be polled again after returning"
        );
    }));
}

#[test]
fn cancellation_published_at_the_end_of_pending_repolls_user_code() {
    struct CancelAtEndOfFirstPoll {
        cx: Cx,
        polls: Arc<AtomicUsize>,
    }

    impl std::future::Future for CancelAtEndOfFirstPoll {
        type Output = &'static str;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _poll_cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            let poll = self.polls.fetch_add(1, Ordering::AcqRel);
            if poll == 0 {
                // Force the cancellation publication into the exact race
                // window after user code has begun this poll but before the
                // task returns its Pending result to the scheduler.
                self.cx
                    .cancel_with(CancelKind::User, Some("cancel at end of first poll"));
                return std::task::Poll::Pending;
            }

            assert!(
                self.cx.checkpoint().is_err(),
                "the follow-up poll must deliver cancellation to user code",
            );
            std::task::Poll::Ready("observed-racing-cancellation")
        }
    }

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");

    runtime.block_on(runtime.handle().spawn(async {
        let cx: Cx = Cx::current().expect("runtime task installs a current Cx");
        let polls = Arc::new(AtomicUsize::new(0));
        let child_polls = Arc::clone(&polls);
        let mut child = cx
            .spawn(move |child_cx| CancelAtEndOfFirstPoll {
                cx: child_cx,
                polls: child_polls,
            })
            .expect("runtime-backed Cx must admit child task");

        assert_eq!(
            child.join(&cx).await,
            Ok("observed-racing-cancellation"),
            "a cancellation racing with the end of a Pending poll must not skip user delivery",
        );
        assert_eq!(
            polls.load(Ordering::Acquire),
            2,
            "cancellation publication must schedule exactly one follow-up poll before return",
        );
    }));
}

#[test]
fn terminal_publication_boundary_preserves_panics_as_join_errors() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");

    runtime.block_on(runtime.handle().spawn(async {
        let cx: Cx = Cx::current().expect("runtime task installs a current Cx");
        let mut child = cx
            .spawn(|_child_cx| async move {
                panic!("native-task-boundary-panic-sentinel");
            })
            .expect("runtime-backed Cx must admit child task");

        match child.join(&cx).await {
            Err(JoinError::Panicked(payload)) => assert!(
                payload
                    .message()
                    .contains("native-task-boundary-panic-sentinel"),
                "join must preserve the original panic payload"
            ),
            other => panic!("spawned panic must remain a JoinError::Panicked; got {other:?}"),
        }
    }));
}

#[test]
fn abort_repolls_a_capacity_parked_send_to_graceful_cancellation() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");

    runtime.block_on(runtime.handle().spawn(async {
        let cx: Cx = Cx::current().expect("runtime task installs a current Cx");
        let (sender, _receiver) = mpsc::channel(1);
        sender.try_send(1_u8).expect("fill bounded channel");
        let waiter_sender = sender.clone();
        let mut waiter = cx
            .spawn(move |waiter_cx| async move { waiter_sender.send(&waiter_cx, 2_u8).await })
            .expect("runtime-backed Cx must admit sender task");

        for _ in 0..256 {
            if sender.telemetry_snapshot(7).send_waiter_count == 1 {
                break;
            }
            yield_now().await;
        }
        assert_eq!(
            sender.telemetry_snapshot(7).send_waiter_count,
            1,
            "sender must be queued on channel capacity before abort",
        );

        waiter.abort();
        let result = waiter.join(&cx).await;
        assert!(
            matches!(result, Ok(Err(SendError::Cancelled(2)))),
            "aborting a capacity-parked send must preserve its value-bearing inner cancellation result; got {result:?}",
        );
        assert_eq!(
            sender.telemetry_snapshot(7).send_waiter_count,
            0,
            "cancelled sender must unlink its channel waiter",
        );
    }));
}

#[test]
fn abort_repolls_a_semaphore_parked_acquire_to_graceful_cancellation() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");

    runtime.block_on(runtime.handle().spawn(async {
        let cx: Cx = Cx::current().expect("runtime task installs a current Cx");
        let semaphore = Arc::new(Semaphore::new(0));
        let waiter_semaphore = Arc::clone(&semaphore);
        let mut waiter = cx
            .spawn(move |waiter_cx| async move {
                OwnedSemaphorePermit::acquire(waiter_semaphore, &waiter_cx, 1)
                    .await
                    .map(drop)
            })
            .expect("runtime-backed Cx must admit semaphore task");

        for _ in 0..256 {
            if semaphore.telemetry_snapshot(11).waiter_count == 1 {
                break;
            }
            yield_now().await;
        }
        assert_eq!(
            semaphore.telemetry_snapshot(11).waiter_count,
            1,
            "acquirer must be queued on the semaphore before abort",
        );

        waiter.abort();
        let result = waiter.join(&cx).await;
        assert!(
            matches!(result, Ok(Err(AcquireError::Cancelled))),
            "aborting a semaphore-parked acquire must preserve its inner cancellation result; got {result:?}",
        );
        let telemetry = semaphore.telemetry_snapshot(11);
        assert_eq!(
            telemetry.waiter_count, 0,
            "cancelled acquirer must unlink its semaphore waiter",
        );
        assert_eq!(
            telemetry.cancellation_count, 1,
            "semaphore cancellation cleanup must remain observable",
        );
    }));
}

#[test]
fn mailbox_and_scope_spawn_paths_classify_before_terminal_publication() {
    let task_handle = read("src/runtime/task_handle.rs");
    assert!(
        task_handle.contains("pub(crate) fn publish_terminal_result<T>(")
            && task_handle.contains("sender.send_blocking(result)"),
        "the authoritative TaskHandle terminal-publication boundary must remain centralized",
    );

    for rel in ["src/cx/cx.rs", "src/cx/scope.rs"] {
        let source = read(rel);
        let active_lines: Vec<_> = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        assert!(
            source.contains("publish_terminal_result("),
            "{rel} must publish TaskHandle results through the authoritative boundary",
        );
        assert!(
            !active_lines.iter().any(|line| {
                line.contains("result_tx.send(")
                    || line.contains("tx.send(&child")
                    || line.contains("tx.send(&cx")
            }),
            "{rel} must not route terminal bookkeeping through a cancelled task Cx",
        );
    }

    let cx = read("src/cx/cx.rs");
    assert!(
        cx.contains("PreserveReturnedValueAfterStart")
            && cx.contains("CancellationDominant")
            && cx.contains("cancelled_before_first_poll")
            && cx.contains("classify_spawn_completion("),
        "mailbox spawn must explicitly distinguish post-start typed results, structured task cancellation, and pre-poll cancellation",
    );
    let join_set = read("src/combinator/join_set.rs");
    assert!(
        join_set.contains("spawn_in_cancellation_dominant")
            && join_set.contains("spawn_local_in_cancellation_dominant"),
        "JoinSet must opt into task-level cancellation attribution for both send and local members",
    );

    // Keep the complete production constructor census explicit. A new
    // TaskHandle producer must make this test fail until its terminal-
    // publication behavior is added to the matrix above.
    for (rel, constructor, expected) in [
        ("src/cx/cx.rs", "TaskHandle::new_pending(", 2_usize),
        ("src/cx/scope.rs", "TaskHandle::new(", 1),
        ("src/runtime/state.rs", "TaskHandle::new(", 1),
        ("src/runtime/builder.rs", "TaskHandle::new(", 0),
    ] {
        let active_count = read(rel)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| line.contains(constructor))
            .count();
        assert_eq!(
            active_count, expected,
            "{rel} TaskHandle constructor census changed; extend the native cancellation matrix before accepting a new spawn adapter",
        );
    }
}

#[test]
fn task_handle_abort_publishes_via_same_stable_envelope_as_cancel() {
    // Pin (link 1): TaskHandle::abort_with_reason uses the
    // same fast_cancel.store(true, Release) + cancel_reason
    // mechanism as Cx::cancel_with. This is the structural
    // proof that abort is a graceful-cancel synonym, NOT
    // a hard-kill.
    let source = read("src/runtime/task_handle.rs");
    let task_context = read("src/types/task_context.rs");

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
            && source.contains("lock.set_cancel_requested(true);")
            && task_context.contains("self.publish_cancel_requested(value);")
            && task_context.contains(".store(value, std::sync::atomic::Ordering::Release);"),
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
fn cx_cancel_with_publishes_via_same_stable_envelope_as_abort() {
    // Pin (link 1+2 symmetry): Cx::cancel_with uses the
    // SAME fast_cancel.store(true, Release) mechanism as
    // TaskHandle::abort. The ONLY differences are the
    // reason kind/message and the handle access pattern.
    let source = read("src/cx/cx.rs");
    let task_context = read("src/types/task_context.rs");

    let fn_marker = "pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {";
    let start = source.find(fn_marker).expect("cancel_with fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("cancel_with close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("inner.set_cancel_requested(true);")
            && task_context.contains("self.publish_cancel_requested(value);")
            && task_context.contains(".store(value, std::sync::atomic::Ordering::Release);"),
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
        body.contains("inner.set_cancel_requested(true);"),
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
    let task_context = read("src/types/task_context.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // checkpoint queries the same stable envelope that abort/cancel publish.
    assert!(
        body.contains("let cancelled = guard.is_cancel_requested();")
            && task_context.contains(
                "self.cancel_requested || self.fast_cancel.load(std::sync::atomic::Ordering::Acquire)",
            )
            && task_context.contains("self.publish_cancel_requested(value);"),
        "REGRESSION: checkpoint no longer reads stable cancellation publication \
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
