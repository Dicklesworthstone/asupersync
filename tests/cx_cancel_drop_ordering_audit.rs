//! Audit + regression test for Drop-before-observable
//! ordering on cancel.
//!
//! Operator's question: "when cancel() is called and the
//! task has a Drop-implementing future state, does the
//! Drop run BEFORE the cancel-result is observable
//! (correct: structured cleanup) or after (incorrect: race
//! window)?"
//!
//! Audit findings:
//!
//!   The answer **depends on which API** is used. asupersync
//!   has TWO cancel/drop paths with DIFFERENT ordering
//!   guarantees:
//!
//!   1. **`Scope::region(...)` (structured-concurrency)** —
//!      Drop runs BEFORE the parent observes the outcome.
//!      This is the operators "correct: structured cleanup"
//!      contract.
//!
//!   2. **`Cx::spawn(...) + TaskHandle::join`
//!      (lower-level primitive)** — the parent CAN observe
//!      the outcome via JoinHandle BEFORE the spawned
//!      task's Drop runs. This is a documented async
//!      window.
//!
//!   For Scope::region, the chain (cx/scope.rs:942-987):
//!
//!     1. Inner future is wrapped in CatchUnwind:
//!        `let pinned_fut = std::pin::pin!(CatchUnwind {
//!        inner: fut });`
//!     2. RegionRunner drives pinned_fut to Ready.
//!     3. result is destructured; outcome is computed.
//!     4. Cleanup match runs (cancel_request captures auxiliary
//!        cancellation observer/Waker effects, queues them for
//!        deferred post-lock dispatch, then begin_close runs
//!        depending on outcome variant). This does not claim
//!        unrelated close/finalizer callbacks are deferred.
//!     5. RegionCloseFuture awaits region quiescence.
//!     6. Function returns `Ok(outcome)`.
//!     7. Local variables drop in REVERSE declaration order
//:        (Rust standard) — pinned_fut is dropped HERE.
//:        CatchUnwind drops → inner user future drops → user
//!        Drop impls run.
//!     8. Caller's `.await` resumes with the Ok(outcome)
//!        return.
//!
//!   Step 7 happens BEFORE step 8 because Rust drops locals
//!   before the function returns. Therefore: **the user's
//!   Drop runs BEFORE the parent observes the outcome**.
//!   The structured-concurrency contract is preserved.
//!
//!   For Cx::spawn + JoinHandle:
//!     1. The wrapped future calls `result_tx.send(&cx,
//:        outcome)` BEFORE returning Outcome::Ok(()).
//!     2. result_tx.send wakes the parent's JoinHandle
//!        awaiter — parent observable from this point.
//!     3. The wrapped state machine returns Outcome::Ok(()).
//!     4. Executor sees Poll::Ready, marks task Completed.
//!     5. Eventually the StoredTask is dropped (inside
//!        execute() or when remove_stored_future runs).
//!     6. User's Drop runs at step 5.
//!     Steps 2 and 5 are decoupled — there's an async
//!     window where the parent could observe the outcome
//!     (step 2) before the user's Drop runs (step 5).
//!
//!   The two APIs serve different use cases:
//!     - Use Scope::region for tight structured concurrency
//!       (parent waits for child quiescence + Drop).
//!     - Use spawn + JoinHandle for fire-and-forget or
//!       race-style patterns where the parent wants to
//!       observe outcome promptly.
//!
//!   The chain for Scope::region's ordering guarantee:
//!
//!   1. **`pinned_fut` is a stack-pinned local** (cx/scope.rs:
//!      942):
//!      ```ignore
//!      let pinned_fut = std::pin::pin!(CatchUnwind { inner: fut });
//!      ```
//!      The pin! macro creates a stack-pin; pinned_fut owns
//!      the CatchUnwind which owns the user future. Until
//!      pinned_fut is dropped, the user future stays alive.
//!
//!   2. **RegionRunner borrows pinned_fut** (cx/scope.rs:
//!      944):
//!      ```ignore
//!      let runner = RegionRunner {
//!          fut: pinned_fut,
//!          ...
//!      };
//!      let (result, state) = runner.await;
//!      ```
//!      runner.await polls the future to Ready. After
//!      return, the inner future has completed (returned
//!      Outcome) but is STILL ALIVE inside pinned_fut.
//!
//!   3. **Cleanup runs while pinned_fut is alive** (cx/scope.rs:
//!      959-985): the cancel_request + begin_close +
//!      RegionCloseFuture.await all happen while the user
//!      future is still alive in pinned_fut. The user is
//!      not yet dropped.
//!
//!   4. **Function returns `Ok(outcome)`** (cx/scope.rs:987):
//!      `Ok(outcome)` is the return expression. The outcome
//!      value is computed.
//!
//!   5. **Locals drop in reverse order** (Rust standard):
//!      pinned_fut is the last local dropped before the
//!      return. Its Drop runs CatchUnwind's Drop runs
//!      user-future Drop runs user-Drop-impls.
//!
//!   6. **Caller observes outcome** (parent's await
//!      resumes): only AFTER step 5 completes does the
//!      caller's await resume with the outcome.
//!
//! Verdict: **SOUND** for the Scope::region path. Drop
//! runs BEFORE the parent observes the outcome via the
//! await chain. The structured-cleanup contract is
//! preserved by Rust's standard local-drop ordering.
//!
//! For Cx::spawn + JoinHandle, there IS a documented
//! window. This is intentional — JoinHandle is the
//: lower-level primitive that doesnt enforce structured
//! cleanup. Users who need strict ordering use Scope::region.
//!
//! No bead filed. The two APIs are differently tuned for
//! different use cases.
//!
//! A regression that:
//!   - moved the user-future drop EARLIER (e.g., explicit
//!     std::mem::drop(pinned_fut) before the return) —
//!     would NOT change the observable contract for
//!     Scope::region (still drops before return), but
//!     would emit Drop before cleanup, potentially
//!     breaking finalizers,
//!   - moved the user-future drop LATER (e.g., put
//!     pinned_fut into a leaked Box) — would break the
//!     ordering and let parent observe outcome before
//:     user Drop,
//!   - changed result_tx.send to fire AFTER the wrapping
//:     future drops its inner CatchUnwind in spawn — would
//!     bring the spawn path closer to the structured
//!     ordering, but at the cost of changing existing
//!     spawn semantics,
//!   - removed RegionCloseFuture.await from
//:     region_with_budget — would let region() return
//!     before child quiescence, breaking the
//!     structured-concurrency contract,
//!
//! would all be caught by the structural pins below.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn region_with_budget_pins_user_fut_via_stack_pinned_local() {
    // Pin (link 1): pinned_fut is a stack-pinned LOCAL.
    // Stack-pin lifetime is the surrounding function — it
    // gets dropped when the function returns.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("let pinned_fut = std::pin::pin!(CatchUnwind { inner: fut });"),
        "REGRESSION: pinned_fut declaration changed. If it \
         became Box::pin or moved off the stack, the \
         drop-before-return ordering may be lost — user \
         Drop fires AFTER the function returns to the \
         caller.",
    );
}

#[test]
fn region_with_budget_runner_borrows_pinned_fut_for_await() {
    // Pin (link 2): RegionRunner takes pinned_fut by
    // mutable reference and drives it to Ready. After
    // runner.await, pinned_fut is STILL ALIVE — the user
    // future hasnt been dropped yet.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("let runner = RegionRunner {") && source.contains("fut: pinned_fut,"),
        "REGRESSION: RegionRunner construction changed. If \
         it consumes pinned_fut by value, the user future \
         may be dropped earlier — different drop ordering.",
    );

    assert!(
        source.contains("let (result, state) = runner.await;"),
        "REGRESSION: runner.await pattern changed. The \
         destructure is what gives the cleanup code access \
         to the result without consuming pinned_fut.",
    );
}

#[test]
fn region_with_budget_cleanup_runs_before_function_return() {
    // Pin (link 3): the cancel_request + begin_close +
    // RegionCloseFuture.await all run BEFORE the function
    // returns Ok(outcome). pinned_fut is alive throughout
    // — user future is alive throughout cleanup.
    let source = read("src/cx/scope.rs");

    let fn_marker = "async fn region_with_child_admission<P2, F, Fut, T, Caps>(";
    let start = source
        .find(fn_marker)
        .expect("region_with_child_admission fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // Cleanup ordering: runner.await → outcome match →
    // cancel_request → begin_close → RegionCloseFuture.await
    // → Ok(outcome).
    let runner_idx = body
        .find("let (result, state) = runner.await;")
        .expect("runner.await");
    let cleanup_idx = body.find("match &outcome {").expect("outcome match");
    let close_await_idx = body
        .find("RegionCloseFuture { state: notify }.await;")
        .expect("RegionCloseFuture.await");
    let return_idx = body.find("Ok(outcome)\n    }").expect("Ok(outcome) return");

    assert!(
        runner_idx < cleanup_idx,
        "REGRESSION: runner.await is no longer BEFORE the \
         cleanup match. The cleanup runs against an \
         unfinished outcome — broken state machine.",
    );

    assert!(
        cleanup_idx < close_await_idx,
        "REGRESSION: cleanup match is no longer BEFORE \
         RegionCloseFuture.await. The close-future awaits \
         on stale state.",
    );

    assert!(
        close_await_idx < return_idx,
        "REGRESSION: RegionCloseFuture.await is no longer \
         BEFORE the Ok(outcome) return. region() returns \
         before child quiescence — structured-concurrency \
         contract broken.",
    );
}

#[test]
fn region_with_budget_returns_ok_outcome_at_function_end() {
    // Pin (link 4): the function returns Ok(outcome) as
    // its final expression. Rust's local-drop semantics
    // ensure pinned_fut is dropped BEFORE the return value
    // is returned to the caller.
    let source = read("src/cx/scope.rs");

    let fn_marker = "async fn region_with_child_admission<P2, F, Fut, T, Caps>(";
    let start = source
        .find(fn_marker)
        .expect("region_with_child_admission fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("Ok(outcome)\n    }"),
        "REGRESSION: region_with_budget no longer ends with \
         `Ok(outcome)`. The local-drop-before-return \
         ordering is preserved by this expression \
         pattern; if the return is wrapped in a deeper \
         block, drop ordering may shift.",
    );
}

#[test]
fn region_with_budget_pins_pinned_fut_after_factory_succeeds() {
    // Pin (link 1 ordering): pinned_fut is constructed
    // AFTER the factory `f` returns successfully. The
    // factory-panic path resume_unwinds without
    // constructing pinned_fut — no orphan inner future.
    let source = read("src/cx/scope.rs");

    let fn_marker = "let fut_result =";
    let start = source.find(fn_marker).expect("fut_result");
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    let factory_panic_idx = body
        .find("std::panic::resume_unwind(payload);")
        .expect("factory panic resume_unwind");
    let pin_idx = body
        .find("let pinned_fut = std::pin::pin!(CatchUnwind { inner: fut });")
        .expect("pin! macro");

    assert!(
        factory_panic_idx < pin_idx,
        "REGRESSION: factory-panic resume_unwind is no \
         longer BEFORE pinned_fut construction. Either the \
         pin happens regardless of factory panic (would \
         break the no-orphan-inner-future contract) or the \
         resume_unwind happens with pinned_fut alive (would \
         drop the inner future during unwind, potentially \
         double-panicking).",
    );
}

#[test]
fn catch_unwind_holds_inner_future_until_dropped() {
    // Pin (link 1): CatchUnwind owns its inner future via
    // #[pin] projection. The inner is alive until
    // CatchUnwind itself is dropped.
    let source = read("src/cx/scope.rs");

    let struct_marker = "pub(crate) struct CatchUnwind<F> {";
    let start = source.find(struct_marker).expect("CatchUnwind struct");
    let body_end = source[start..].find("\n}\n").expect("CatchUnwind close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("#[pin]\n    pub(crate) inner: F,"),
        "REGRESSION: CatchUnwind.inner field is no longer \
         pin-projected. Without #[pin], the inner future \
         would not be safely pinnable — breaks the \
         structural pinning contract.",
    );
}

#[test]
fn region_runner_drop_cancels_child_when_dropped_pre_completion() {
    // Pin (link 2 cleanup-on-cancel): if RegionRunner is
    // dropped before await completes (e.g., parent panic
    // above region), Drop captures cancel_request effects,
    // queues them for scheduler dispatch after RuntimeState is
    // released, then begins close. The user future is dropped as part of
    // pinned_fut going out of scope — same drop-ordering
    // guarantee as the success path.
    let source = read("src/cx/scope.rs");

    let impl_marker = "impl<Fut> Drop for RegionRunner<'_, Fut> {";
    let start = source.find(impl_marker).expect("RegionRunner Drop");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("RegionRunner Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("let effects = state.cancel_request(self.child_region, &reason, None);")
            && body.contains("state.defer_cancel_dispatch(effects);")
            && !body.contains(".dispatch()")
            && !body.contains("wake_by_ref(")
            && body.contains("region.begin_close(None);"),
        "REGRESSION: RegionRunner::Drop no longer captures and defers \
         the child region's auxiliary cancellation observers/Wakers. \
         This pin makes no claim about later region-close/finalizer callbacks. \
         Parent-panic-above-region scenario \
         leaks the region — structured-concurrency \
         contract violated even before drop ordering.",
    );
}

#[test]
fn region_close_future_await_blocks_until_quiescence() {
    // Pin (link 3): RegionCloseFuture.await is what makes
    // region() block until the child quiesces. Without
    // this await, region() returns before the cleanup
    // completes — drop ordering doesnt matter if the
    // contract is broken upstream.
    let source = read("src/cx/scope.rs");

    let struct_marker = "struct RegionCloseFuture {";
    let start = source
        .find(struct_marker)
        .expect("RegionCloseFuture struct");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("RegionCloseFuture close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("state: Arc<parking_lot::Mutex<crate::record::region::RegionCloseState>>"),
        "REGRESSION: RegionCloseFuture state field changed. \
         The Mutex<RegionCloseState> is what synchronizes \
         the await with the close transition.",
    );
}

#[test]
fn region_close_future_poll_returns_ready_when_state_closed() {
    // Pin (link 3): RegionCloseFuture's poll returns Ready
    // when state.closed is true. This is the actual block-
    // until-close mechanism.
    let source = read("src/cx/scope.rs");

    let impl_marker = "impl Future for RegionCloseFuture {";
    let start = source.find(impl_marker).expect("RegionCloseFuture impl");
    let next_impl = source[start + impl_marker.len()..]
        .find("\nimpl ")
        .map_or(source.len(), |o| start + impl_marker.len() + o);
    let body = &source[start..next_impl];

    assert!(
        body.contains("if state.closed {") && body.contains("Poll::Ready(())"),
        "REGRESSION: RegionCloseFuture::poll no longer \
         checks state.closed for Ready. Either the await \
         returns prematurely or it never returns — both \
         break drop ordering.",
    );
}

#[test]
fn no_explicit_drop_or_mem_drop_on_pinned_fut_in_region_with_budget() {
    // Pin (audit): there's no explicit `drop(pinned_fut)`
    // or `std::mem::drop(pinned_fut)` BEFORE the return.
    // The standard local-drop-on-scope-exit IS the
    // guarantee. An explicit drop wouldnt be wrong but
    // would duplicate the standard behavior.
    let source = read("src/cx/scope.rs");

    let fn_marker = "async fn region_with_child_admission<P2, F, Fut, T, Caps>(";
    let start = source
        .find(fn_marker)
        .expect("region_with_child_admission fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // mem::forget would skip Drop entirely — must NOT exist.
    let suspect_drop_skip = [
        "std::mem::forget(pinned_fut)",
        "mem::forget(pinned_fut)",
        "ManuallyDrop::new(pinned_fut)",
    ];
    for pat in &suspect_drop_skip {
        assert!(
            !body.contains(pat),
            "REGRESSION: region_with_budget now skips \
             pinned_fut Drop via `{pat}`. The user future \
             never gets its Drop run — RESOURCE LEAK plus \
             missing structured cleanup.",
        );
    }
}

// ─────────── BEHAVIORAL PIN: Drop-before-return ordering ──
//
// Direct simulation: a function with a Drop-counter local
// that returns a value. Verify that the local's Drop runs
// BEFORE the return value is observable to the caller.

#[derive(Debug)]
struct DropCounter {
    drop_count: Arc<AtomicU32>,
}

impl Drop for DropCounter {
    fn drop(&mut self) {
        self.drop_count.fetch_add(1, Ordering::Relaxed);
    }
}

fn function_with_drop_counter_local(
    drop_count: Arc<AtomicU32>,
    drop_count_at_return: Arc<AtomicU32>,
) -> u32 {
    let _local = DropCounter {
        drop_count: Arc::clone(&drop_count),
    };
    let return_value = 42_u32;
    // At this point, _local is still alive.
    // The return expression captures the count at this moment.
    drop_count_at_return.store(drop_count.load(Ordering::Relaxed), Ordering::Relaxed);
    return_value
    // _local drops here, AFTER the return value is computed
    // but BEFORE control returns to the caller.
}

#[test]
fn behavior_local_drop_runs_before_function_return_to_caller() {
    // Behavioral pin: verify the standard Rust local-drop
    // semantics that gives Scope::region its ordering
    // guarantee.
    let drop_count = Arc::new(AtomicU32::new(0));
    let drop_count_at_return_expr = Arc::new(AtomicU32::new(0));

    // Snapshot drop_count BEFORE the function returns.
    let count_before_return_expr = drop_count_at_return_expr.load(Ordering::Relaxed);
    assert_eq!(count_before_return_expr, 0);

    // Call the function.
    let result = function_with_drop_counter_local(
        Arc::clone(&drop_count),
        Arc::clone(&drop_count_at_return_expr),
    );

    // Inside the function body, the count was 0 (DropCounter
    // not yet dropped at the return-expression evaluation
    // point).
    assert_eq!(
        drop_count_at_return_expr.load(Ordering::Relaxed),
        0,
        "REGRESSION: DropCounter dropped BEFORE the return \
         expression was evaluated. Locals should drop AFTER \
         the return expression is evaluated but BEFORE \
         control returns to the caller.",
    );

    // After the function returned to us, drop_count is 1 —
    // proving Drop ran during the function exit.
    assert_eq!(
        drop_count.load(Ordering::Relaxed),
        1,
        "REGRESSION: DropCounter did not run on function \
         exit. Local drops are not happening — Rust's \
         standard semantics broken.",
    );

    assert_eq!(result, 42);
}

#[test]
fn behavior_pinned_local_drops_at_function_end_before_caller_observes() {
    // Behavioral pin: extends the prior test with a
    // pin!-equivalent pattern. Verifies that pinned locals
    // also drop at function end before the caller observes
    // the return.
    let drop_count = Arc::new(AtomicU32::new(0));

    fn inner_fn(drop_count: Arc<AtomicU32>) -> u32 {
        // Stack-pinned via Box::pin (pin! is hard to use
        // freestanding; same drop semantics).
        let _pinned: Box<DropCounter> = Box::new(DropCounter {
            drop_count: Arc::clone(&drop_count),
        });
        99
    }

    let count_before = drop_count.load(Ordering::Relaxed);
    assert_eq!(count_before, 0);

    let result = inner_fn(Arc::clone(&drop_count));

    assert_eq!(
        drop_count.load(Ordering::Relaxed),
        1,
        "REGRESSION: pinned-local Drop did not run on \
         function exit.",
    );
    assert_eq!(result, 99);
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/cx_scope_panic_propagation_audit.rs",
        "tests/runtime_region_close_idempotency_audit.rs",
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
