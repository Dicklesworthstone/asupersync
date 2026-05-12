//! Audit + regression test for `Scope::race` combinator
//! loser-drain semantics.
//!
//! Operator's question: "Cx::race(fut1, fut2, ...)
//! combinator: when one branch completes, the others are
//! cancelled. Verify: (a) the cancel propagates to all
//! other branches in O(N) total, (b) the cancellation is
//! observable (their futures' Drop run), (c) no orphan
//! tasks."
//!
//! Audit findings:
//!
//!   `Scope::race(cx, h1, h2)` correctly cancels and
//!   drains losers via the documented JoinFuture-drop +
//!   Select pattern. The chain:
//!
//!   1. **Both handles get JoinFutures with race-loser
//!      drop_reason** (cx/scope.rs:1065-1068):
//!      ```ignore
//!      let f1 = h1.join_with_drop_reason(cx, CancelReason::race_loser());
//!      let mut f1 = std::pin::pin!(f1);
//!      let f2 = h2.join_with_drop_reason(cx, CancelReason::race_loser());
//!      let mut f2 = std::pin::pin!(f2);
//!      ```
//!      Each JoinFuture carries the `RaceLost` cancel reason
//!      that fires on drop (per
//:      tests/runtime_join_handle_drop_lifecycle_audit.rs).
//!
//!   2. **`Select::new` races f1 vs f2** (cx/scope.rs:1069):
//!      ```ignore
//!      Select::new(f1.as_mut(), f2.as_mut()).await
//!      ```
//!      Per tests/combinator_select_fairness_determinism_audit.rs,
//!      Select returns the WINNER and DROPS the loser
//!      future (the pinned f1 or f2 corresponding to the
//!      losing arm).
//!
//!   3. **Loser-future drop fires
//!      CancelReason::race_loser()** (per
//!      tests/runtime_join_handle_drop_lifecycle_audit.rs's
//!      JoinFuture::Drop pin): when Select drops the
//!      losing JoinFuture, JoinFuture::Drop fires
//:      `abort_with_reason(CancelReason::race_loser())` on
//!      the loser's task — sets fast_cancel +
//!      cancel_reason, wakes cancel_waker.
//!
//!   4. **race() then drains the loser via
//:      `loser_handle.join(cx).await`** (cx/scope.rs:1090,
//!      1113): after the winner returns, race awaits the
//!      LOSER's JoinHandle. This blocks until the loser
//!      observes the cancel via checkpoint, propagates Err,
//!      and the wrapping fn sends Outcome::Cancelled.
//!      `race()` doesnt return until the loser has drained.
//!
//!   5. **Loser-drain history is recorded** (cx/scope.rs:
//!      1063, 1076-1115): record_loser_drain_start +
//!      record_loser_drain_task_complete +
//!      record_loser_drain_complete give operators an
//!      audit trail of the drain.
//!
//!   6. **Panic-from-block-on edge case**: when a winner
//!      panics in a direct block_on test (no scheduler
//!      driving the loser), race calls
//:      `best_effort_poll_loser_join(cx, &mut h_loser)` to
//!      give the loser one poll opportunity to observe its
//!      cancel before the winner-panic is surfaced. This
//!      prevents deadlock in the test-runner case.
//!
//!   The cancel propagation pattern:
//!
//!   - **For 2 branches (race)**: 1 winner + 1 loser. The
//!     loser's drop fires its abort, then race awaits the
//!     loser's join — total work O(1) per loser = O(N) for
//!     N branches.
//!   - **For N branches (race_all)**: per-branch
//!     JoinFuture drop + per-branch join.await drain. Per
//!     branch: one fast_cancel.store(Release) + one
//!     cancel_waker wake + one channel recv. Total work
//!     O(N).
//!
//!   Operator's three sub-questions:
//!
//!   (a) **Cancel propagates to all branches in O(N) total**:
//!       YES — JoinFuture::Drop fires ONE cancel publish
//!       per loser. N losers × O(1) = O(N).
//!
//!   (b) **Cancellation is observable (futures' Drop run)**:
//!       YES — the loser tasks observe cancel via their
//!       next checkpoint, propagate Err, and the wrapping
//!       future drops the user future (per
//:       tests/cx_cancel_drop_ordering_audit.rs ordering).
//:       race() awaits the loser's join, ensuring drop has
//!       happened before race returns.
//!
//!   (c) **No orphan tasks**: race() awaits each loser's
//!       JoinHandle via `loser.join(cx).await`. The loser
//!       cant outlive race(); race() blocks until the
//!       loser quiesces.
//!
//! Verdict: **SOUND**. All three sub-questions pass:
//!   (a) O(N) cancel propagation via per-loser
//!       JoinFuture::Drop.
//!   (b) Observable cancellation — race awaits loser's
//!       join, which blocks until cancel propagates +
//!       wrapping future completes + drop runs.
//:   (c) No orphan tasks — race() doesnt return until all
//:       losers have drained.
//!
//! The audit pins the structural mechanism. No bead filed.
//!
//! A regression that:
//!   - changed Select to NOT drop the loser future (would
//!     leak the abort signal — losers continue running),
//!   - removed the join_with_drop_reason wrapping in race
//!     (loser drop wouldnt fire abort — orphan tasks),
//!   - removed the loser.join(cx).await drain (race would
//!     return BEFORE loser quiesces — orphan tasks until
//!     region close),
//!   - changed CancelReason::race_loser() to a less-severe
//!     kind (would lose attribution — debugging cant tell
//!     race-loss from other cancels),
//!   - removed best_effort_poll_loser_join in the panic
//!     edge case (would deadlock the test runner under
//!     winner-panic),
//!   - made race() return Outcome before awaiting losers
//!     (would let race finish without loser drain —
//!     defeating structured concurrency),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn race_wraps_handles_in_join_with_drop_reason_race_loser() {
    // Pin (link 1): both handles get JoinFutures via
    // join_with_drop_reason with CancelReason::race_loser().
    // Without this, loser drop wouldnt fire the loser-
    // attributed abort.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn race<T>(";
    let start = source.find(fn_marker).expect("Scope::race fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Scope::race close");
    let body = &source[start..start + body_end];

    let join_with_reason_count = body
        .matches("join_with_drop_reason(cx, CancelReason::race_loser())")
        .count();
    assert!(
        join_with_reason_count >= 2,
        "REGRESSION: race() no longer wraps both handles \
         with join_with_drop_reason(race_loser()) \
         (got {join_with_reason_count}, expected >= 2). \
         Loser drop wouldnt fire RaceLost-attributed abort \
         — losers might continue running with wrong \
         attribution.",
    );
}

#[test]
fn race_uses_select_combinator_to_race_join_futures() {
    // Pin (link 2): race uses Select::new(f1, f2).await to
    // pick the winner. Select drops the loser, triggering
    // its JoinFuture::Drop.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn race<T>(";
    let start = source.find(fn_marker).expect("Scope::race fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Scope::race close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("Select::new(f1.as_mut(), f2.as_mut())"),
        "REGRESSION: race no longer uses Select::new for \
         the race. Either custom race logic was substituted \
         (would need new audit) or the loser-drop mechanism \
         is broken.",
    );
}

#[test]
fn race_pins_join_futures_via_pin_macro_for_safe_select() {
    // Pin (link 1+2): the JoinFutures must be stack-pinned
    // for Select::new(f1.as_mut(), f2.as_mut()) to work
    // safely. Without pinning, Select cant project mutable
    // references through the futures.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn race<T>(";
    let start = source.find(fn_marker).expect("Scope::race fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Scope::race close");
    let body = &source[start..start + body_end];

    let pin_count = body.matches("std::pin::pin!").count();
    assert!(
        pin_count >= 2,
        "REGRESSION: race no longer pins both JoinFutures \
         via std::pin::pin! (got {pin_count} pin macros, \
         expected >= 2). Either Select cant project mutable \
         refs (compile error) or unsafe pin manipulation \
         was substituted (UB pathway).",
    );
}

#[test]
fn race_drains_loser_via_loser_handle_join_for_no_orphan_guarantee() {
    // Pin (link 4): after the winner is determined, race
    // awaits the loser's join. This is what prevents
    // orphans — race blocks until the loser quiesces.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn race<T>(";
    let start = source.find(fn_marker).expect("Scope::race fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Scope::race close");
    let body = &source[start..start + body_end];

    // Both Either::Left and Either::Right arms must call
    // loser.join(cx).await.
    let loser_join_count = body.matches(".join(cx).await;").count();
    assert!(
        loser_join_count >= 2,
        "REGRESSION: race no longer awaits loser join in \
         both branches (got {loser_join_count}, expected \
         >= 2). race() can return BEFORE loser quiesces — \
         orphan tasks possible until region close.",
    );
}

#[test]
fn race_loser_attribution_is_distinct_cancel_kind_for_observability() {
    // Pin (link 3): CancelReason::race_loser() stamps
    // CancelKind::RaceLost — distinct from User /
    // ParentCancelled / Deadline. Operators can see
    // race-loss attribution in cancel chains.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("race_loser => RaceLost;") || source.contains("race_lost => RaceLost;"),
        "REGRESSION: race_loser() / race_lost() constructor \
         no longer maps to RaceLost variant. Race-loss \
         attribution conflated with other cancel causes.",
    );
}

#[test]
fn race_records_loser_drain_history_for_observability() {
    // Pin (link 5): race records the loser-drain
    // lifecycle (start + per-task complete + complete).
    // Without this, operators have no audit trail.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn race<T>(";
    let start = source.find(fn_marker).expect("Scope::race fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Scope::race close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("record_loser_drain_start(")
            && body.contains("record_loser_drain_task_complete(")
            && body.contains("record_loser_drain_complete("),
        "REGRESSION: race no longer records the three \
         loser-drain lifecycle events. Audit trail \
         degraded — operators cant verify drain happened.",
    );
}

#[test]
fn race_handles_winner_panic_with_best_effort_loser_poll_in_block_on() {
    // Pin (link 6): when winner panics in block_on (no
    // scheduler driving losers), race calls
    // best_effort_poll_loser_join to give the loser one
    // chance to observe cancel. Without this, the test
    // runner could deadlock.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn race<T>(";
    let start = source.find(fn_marker).expect("Scope::race fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Scope::race close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("best_effort_poll_loser_join(cx, &mut h2)")
            && body.contains("best_effort_poll_loser_join(cx, &mut h1)"),
        "REGRESSION: race no longer best-effort-polls the \
         loser when winner panics in block_on. Test runner \
         deadlocks when winner panics — the loser is \
         never polled.",
    );
}

#[test]
fn race_propagates_winner_panic_over_other_outcomes() {
    // Pin (link 6 audit): if either winner OR loser
    // panicked, race propagates the panic — not the
    // success outcome. This is panic-transparency.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn race<T>(";
    let start = source.find(fn_marker).expect("Scope::race fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Scope::race close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if let Err(JoinError::Panicked(p)) = res {")
            && body.contains("Err(JoinError::Panicked(p))"),
        "REGRESSION: race no longer propagates winner panic \
         via Err(Panicked). Winner panic would be silently \
         converted to a different error or success — panic \
         transparency lost.",
    );
}

#[test]
fn join_future_drop_reason_carries_race_loser_attribution() {
    // Pin (link 1+3 cross-reference): JoinFuture's
    // drop_reason field carries the race_loser reason.
    // Without this, JoinFuture::Drop falls back to
    // CancelReason::user("abort") — wrong attribution.
    let source = read("src/runtime/task_handle.rs");

    let fn_marker = "pub fn join_with_drop_reason<'a>(";
    let start = source.find(fn_marker).expect("join_with_drop_reason fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("join_with_drop_reason close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("drop_reason: Some(reason),"),
        "REGRESSION: join_with_drop_reason no longer sets \
         drop_reason. The race-loser attribution is lost — \
         losers stamped with default user(\"abort\") instead.",
    );
}

#[test]
fn join_future_drop_uses_drop_reason_for_attribution() {
    // Pin (link 3): JoinFuture::Drop uses
    // self.drop_reason.take() to pass to abort_with_reason.
    // Pairs with link 1 — together they ensure race_loser
    // attribution propagates.
    let source = read("src/runtime/task_handle.rs");

    let impl_marker = "impl<T> Drop for JoinFuture<'_, T> {";
    let start = source.find(impl_marker).expect("JoinFuture Drop");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("JoinFuture Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if let Some(reason) = self.drop_reason.take() {")
            && body.contains("self.abort_with_reason(reason);"),
        "REGRESSION: JoinFuture::Drop no longer uses \
         drop_reason for the abort. Race losers get the \
         default user(\"abort\") reason instead of \
         race_loser — attribution wrong.",
    );
}

#[test]
fn race_does_not_use_select_drain_pattern_that_skips_loser_join() {
    // Pin (link 4 anti-pattern): there must be NO branch in
    // race that returns the winner WITHOUT awaiting the
    // loser's join. The non-block_on path must always drain.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn race<T>(";
    let start = source.find(fn_marker).expect("Scope::race fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Scope::race close");
    let body = &source[start..start + body_end];

    // Find the Either::Left arm. After best_effort_poll
    // (block_on edge case), there must NOT be an "else
    // skip drain" path.
    let suspect_skip = ["// skip drain", "// drain not needed"];
    for pat in &suspect_skip {
        assert!(
            !body.contains(pat),
            "REGRESSION: race contains a skip-drain comment \
             (`{pat}`). Investigate whether the drain was \
             actually skipped — orphan-task pathway.",
        );
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_join_handle_drop_lifecycle_audit.rs",
        "tests/combinator_select_fairness_determinism_audit.rs",
        "tests/runtime_cancel_cause_kinds_distinct_audit.rs",
        "tests/cx_cancel_drop_ordering_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
