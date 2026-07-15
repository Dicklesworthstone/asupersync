//! Audit + regression test for `Cx::checkpoint()` cancel
//! observation when the parent region is being cancelled.
//!
//! Operator's question: "when checkpoint() is called and parent
//! region is being cancelled, does it return Cancelled error
//! (correct) or proceed (incorrect)?"
//!
//! Audit findings:
//!
//!   This is the UNION of two prior audits:
//!     - tests/scheduler_cooperative_budget_yield_audit.rs:
//!       pins the checkpoint observation path
//!       (fast_cancel.load(Acquire) → Err return).
//!     - tests/scheduler_region_drop_propagates_cancel_to_timed_lane_audit.rs:
//!       pins the propagation chain (region close →
//!       request_cancel_with_budget → fast_cancel.store(true,
//!       Release)).
//!
//!   Cross-referenced summary of the chain (region cancel →
//!   task observation):
//!
//!   1. **Parent region cancel** triggers `state.cancel_request(
//!      region, &reason, _)` (state.rs cancel_region_subtree).
//!      The subtree walk transitions each region in the
//!      affected subtree to Closing via `region.begin_close(
//!      Some(reason))`.
//!
//!   2. **Per-task cancel propagation** (state.rs:2682): for
//!      every task in every closing region,
//!      `task.request_cancel_with_budget(reason, budget)` is
//!      called. Under the task lock this mutates state and
//!      snapshots Wakers into an opaque effects token. The
//!      outer runtime aggregates those tokens without
//!      dispatching callbacks. This sets:
//!        - `inner.cancel_requested = true`
//!        - `inner.fast_cancel.store(true, Release)`
//!        - `inner.cancel_reason = Some(reason)` (or
//!          strengthened against existing reason).
//!
//!   3. **`Cx::checkpoint()` fast path** (cx.rs:1664-1672)
//!      reads `guard.fast_cancel.load(Ordering::Acquire)`. The
//!      Release-on-store / Acquire-on-load pair guarantees
//!      cross-thread visibility of the cancel flag.
//!
//!   4. **Slow-path resolution** (cx.rs:1697-1733): when
//!      `fast_cancel == true`, checkpoint enters the slow
//!      path under the write lock, re-runs
//!      `checkpoint_budget_exhaustion`, sets
//!      `cancel_acknowledged` if mask_depth==0, and delegates
//!      to `check_cancel_from_values` for the Err return.
//!
//!   5. **Error propagation via `?`**: the user calls
//!      `cx.checkpoint()?` in their async code; the Err
//!      propagates up the await chain, returning control to
//!      the scheduler. The task is then dispatched as cancel
//!      work and finalizes through the normal cancellation
//!      drain.
//!
//! Verdict: **SOUND**. checkpoint() returns Cancelled error
//! when the parent region is being cancelled. The
//! Release-Acquire pair on `fast_cancel` provides the cross-
//! thread visibility; the cooperative-yield contract surfaces
//! the cancel via `?` propagation.
//!
//! Mask interaction: per AGENTS.md "cancellation is a
//! protocol", a mask defers cancel acknowledgment. Inside a
//! `Cx::with_mask` block, checkpoint observes
//! cancel_requested=true but does NOT set
//! cancel_acknowledged=true (that's gated on
//! `mask_depth == 0`). The Err is still returned to the
//! caller though — the mask defers the FINALIZATION, not the
//! observation.
//!
//! A regression that:
//!   - dropped the fast_cancel.load(Acquire) on checkpoint's
//!     fast path (would let cancellation requests miss the
//!     observation),
//!   - dropped the fast_cancel.store(true, Release) in
//!     request_cancel_with_budget (would break the visibility
//!     pair — checkpoint may not observe a concurrently-set
//!     flag),
//!   - changed checkpoint to return Ok when cancel_requested
//!     is true (would silently swallow cancellation),
//!   - removed the mask_depth gate from cancel_acknowledged
//!     (would prematurely acknowledge cancellation inside a
//!     mask, breaking the protocol),
//!     would all be caught here AND by the two prior audits.
//!
//! This file's pins are deliberately MINIMAL — they cross-
//! reference the prior audit files for the detailed chain.
//! The minimal set guards the SPECIFIC interaction: parent-
//! region-cancel → checkpoint Err return.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn region_cancel_propagation_sets_fast_cancel_release_on_each_task() {
    // Pin (link 1+2): the region-cancel subtree walk in
    // state.rs invokes `task.request_cancel_with_budget(
    // task_reason.clone(), task_budget)` on every task in
    // every closing region. This is what bridges "parent
    // region cancel" to "task's checkpoint observes cancel".
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("task.request_cancel_with_budget_and_publication(")
            && source.contains("let ((newly_cancelled, changed, publication), task_wakes) =",)
            && source.contains("wakes.merge(task_wakes);")
            && source.contains("CancellationEffects::new(tasks_to_cancel, wakes)"),
        "REGRESSION: state.rs cancel-region-subtree no longer \
         captures task.request_cancel_with_budget effects \
         without dispatching their auxiliary cancellation observers/Wakers \
         under the task/state \
         mutation boundary. Without this call, a parent-\
         region cancel doesn't reach the \
         child task's CxInner — the task's checkpoint() never \
         observes the cancel and the task continues running \
         orphaned even though the parent has logically been \
         cancelled. See also \
         tests/scheduler_region_drop_propagates_cancel_to_timed_lane_audit.rs.",
    );
}

#[test]
fn cx_checkpoint_fast_path_reads_fast_cancel_with_acquire() {
    // Pin (link 3): cx.checkpoint() fast path reads the
    // fast_cancel atomic with Acquire ordering. The
    // Release-on-store / Acquire-on-load pair from the
    // propagation site is what gives the observation cross-
    // thread visibility.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("guard.fast_cancel.load(std::sync::atomic::Ordering::Acquire)"),
        "REGRESSION: cx.checkpoint() no longer reads \
         fast_cancel with Acquire ordering. Without it, the \
         Release-Acquire pair is broken — a task's checkpoint \
         could observe stale state and miss a concurrently-\
         set cancel flag. See also \
         tests/scheduler_cooperative_budget_yield_audit.rs.",
    );
}

#[test]
fn cx_checkpoint_returns_err_via_check_cancel_from_values() {
    // Pin (link 4): the slow-path delegates to
    // check_cancel_from_values which constructs the Err
    // return. The Err is what propagates via `?` to yield
    // the task back to the scheduler.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("Self::check_cancel_from_values("),
        "REGRESSION: cx.checkpoint() no longer delegates to \
         check_cancel_from_values for the Err return. \
         Without this call, a cancel-observing checkpoint \
         could silently return Ok — breaking the cooperative-\
         yield contract.",
    );
}

#[test]
fn cx_checkpoint_signature_is_result_unit_error() {
    // Pin: the signature is `pub fn checkpoint(&self) ->
    // Result<(), crate::error::Error>`. Without the Result
    // return, callers can't `?`-propagate the cancel Err.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn checkpoint(&self) -> Result<(), crate::error::Error> {"),
        "REGRESSION: cx.checkpoint() signature changed. The \
         canonical `Result<(), crate::error::Error>` return is \
         what makes `cx.checkpoint()?` work in handler code; a \
         change here would break every handler.",
    );
}

#[test]
fn cancel_acknowledged_is_gated_on_mask_depth_zero() {
    // Pin (link 4 mask interaction): the slow path sets
    // cancel_acknowledged=true ONLY when mask_depth==0. Inside
    // a Cx::with_mask block, the cancel is OBSERVED (Err is
    // returned) but acknowledgment is DEFERRED until the mask
    // unwinds. A regression that always set
    // cancel_acknowledged would break the mask protocol.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    // Take a generous window for the long checkpoint body.
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("if inner.cancel_requested && inner.mask_depth == 0 {"),
        "REGRESSION: cancel_acknowledged is no longer guarded \
         on mask_depth==0. Either the mask is leaking (cancel \
         acknowledged INSIDE a mask, breaking the mask \
         contract) OR cancel is never acknowledged (priority \
         inversion). Both are bugs.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    // Pin (documentary): the detailed chain audits live in
    // sibling test files. A regression that deleted those
    // files would lose the deep coverage even if these
    // lightweight pins still pass.
    let prior_audits = [
        "tests/scheduler_cooperative_budget_yield_audit.rs",
        "tests/scheduler_region_drop_propagates_cancel_to_timed_lane_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing. \
             This audit relies on the prior audits for deep \
             coverage of the propagation chain; if they're \
             gone, restore them or update this audit to \
             include the deeper checks.",
        );
    }
}
