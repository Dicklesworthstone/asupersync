//! Audit + regression test for `Scope::join_all` vs
//! `Scope::region` independence semantics.
//!
//! Operator's question: "JoinSet has 100 spawned tasks and
//! one of them panics, do the others continue (correct:
//! independent) or all get cancelled (incorrect for
//! JoinSet vs region)? Per asupersync semantics, JoinSet
//! is independent; region cancels children."
//!
//! Audit findings:
//!
//!   asupersync does NOT have a literal `JoinSet` type.
//!   The equivalent is `Scope::join_all(cx, Vec<TaskHandle>)`
//!   which has **independent semantics** — one task's
//!   panic does NOT cancel sibling tasks. This matches
//!   the operator's "JoinSet is independent" expectation.
//!
//!   `Scope::region` (with FailFast policy) and
//!   `Scope::race` are the cancel-on-failure / cancel-on-
//!   winner alternatives. Three distinct combinator
//!   semantics:
//!
//!   1. **`Scope::join_all` (independent)** (cx/scope.rs:1426):
//!      ```ignore
//!      pub async fn join_all<T>(
//!          &self,
//!          cx: &Cx,
//!          mut handles: Vec<TaskHandle<T>>,
//!      ) -> Vec<Result<T, JoinError>> {
//!          let mut futures: Vec<_> = handles.iter_mut().map(|h| h.join(cx)).collect();
//!          let mut results = Vec::with_capacity(futures.len());
//!          for fut in &mut futures {
//!              results.push(std::pin::Pin::new(fut).await);
//!          }
//!          results
//!      }
//!      ```
//!      Sequentially awaits each handle's join; collects
//!      results into a Vec. A panic in one task surfaces
//!      as `Err(JoinError::Panicked(...))` for THAT task's
//!      slot in the Vec; the OTHER tasks continue
//!      uninterrupted.
//!
//!   2. **`Scope::race` (cancel losers)** (cx/scope.rs:1057):
//!      Picks the first to complete; cancels and drains
//!      all others (verified by
//!      tests/cx_race_combinator_loser_drain_audit.rs).
//!
//!   3. **`Scope::region` with FailFast policy**: if any
//!      child fails, sibling cancels propagate via the
//!      region close + cancel_request walk (verified by
//!      tests/runtime_region_close_timed_lane_task_cancellation_audit.rs).
//!
//!   The chain for `join_all` independence:
//!
//!   1. **Per-handle JoinFutures** (cx/scope.rs:1431):
//!      ```ignore
//!      let mut futures: Vec<_> = handles.iter_mut().map(|h| h.join(cx)).collect();
//!      ```
//!      One JoinFuture per handle. NOT a single combined
//!      future — each is independent.
//!
//!   2. **Sequential await** (cx/scope.rs:1433-1435):
//!      ```ignore
//!      for fut in &mut futures {
//!          results.push(std::pin::Pin::new(fut).await);
//!      }
//!      ```
//!      The for-loop awaits each future to completion. A
//!      panic in one task results in JoinError::Panicked
//!      for THAT slot — the next iteration polls the next
//!      future independently.
//!
//!   3. **No cross-task cancel propagation**: there is NO
//!      code path in join_all that calls
//!      `task.abort()` on siblings when one task panics.
//!      Each task's outcome is INDEPENDENT.
//!
//!   4. **TaskHandle drop-without-await is detached** (per
//!      tests/runtime_join_handle_drop_lifecycle_audit.rs):
//!      handles dropped after join_all completes leave the
//!      tasks running until completion. join_all-tasks
//!      bound to a region are still owned by that region
//!      and respect region close.
//!
//!   The chain for `region` cancel-on-failure:
//!
//!   1. **`region_with_budget`** (cx/scope.rs:881) drives
//!      the closure through RegionRunner.
//!   2. **On Outcome::Err / Outcome::Panicked** (cx/scope.rs:
//!      971): cancels the child region via
//!      `cancel_request(child_region, fail_fast_reason, None)`,
//!      then queues the returned effects so Wakers run only
//!      after the outer RuntimeState guard is released.
//!   3. The cancel propagates to all tasks in the child
//!      region (per tests/scheduler_cancel_storm_propagation_audit.rs).
//!
//! Verdict: **SOUND**. The two combinators have observably
//! different cancel semantics:
//!   - join_all: independent — one panic doesnt cancel
//!     others.
//!   - region: cancel-on-failure — one panic propagates
//!     to siblings via the region close.
//!
//! No bead filed. The distinction is structural —
//! join_all has no cancel-on-failure code path; region's
//! cancel propagation is documented and tested separately.
//!
//! A regression that:
//!   - added a cancel-on-failure path to join_all (would
//!     make it region-like, breaking the independence
//!     contract),
//!   - changed join_all to use try_join semantics
//!     (short-circuit on first error) (would change Vec
//!     return ordering and silently drop other results),
//!   - removed the for-loop sequential await (would
//!     change ordering — Vec<Result> no longer maps 1:1
//!     to handles input order),
//!   - made region's cancel propagation skip on
//!     Panicked outcome (would defeat the structured-
//!     concurrency cleanup contract for the region),
//!   - introduced a literal JoinSet type that conflates
//!     join_all and region semantics (one of them would
//!     be wrong),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn child_admission_body(source: &str) -> &str {
    let fn_marker = "async fn region_with_child_admission<P2, F, Fut, T, Caps>(";
    let start = source
        .find(fn_marker)
        .expect("region_with_child_admission fn");
    let body_end = source[start..]
        .find("\n    // =========================================================================")
        .map_or(source.len(), |offset| start + offset);
    &source[start..body_end]
}

#[test]
fn join_all_returns_vec_of_results_per_handle_for_independence() {
    // Pin (link 1): join_all returns Vec<Result<T,
    // JoinError>> — one entry per handle. The Vec preserves
    // independence; a panic in one task doesnt collapse
    // the entire return into a single error.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("pub async fn join_all<T>(")
            && source.contains("-> Vec<Result<T, JoinError>>"),
        "REGRESSION: join_all signature changed. If it now \
         returns Result<Vec<T>, JoinError> (short-circuit) \
         or Outcome<Vec<T>, ...>, the per-task independence \
         is lost — one panic would conflate the entire \
         return.",
    );
}

#[test]
fn join_all_uses_per_handle_join_future_via_iter_mut_map() {
    // Pin (link 1): join_all collects per-handle JoinFutures
    // via iter_mut().map(|h| h.join(cx)). Independent
    // futures, not a single combined Future.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn join_all<T>(";
    let start = source.find(fn_marker).expect("join_all fn");
    let body_end = source[start..].find("\n    }\n").expect("join_all close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("handles.iter_mut().map(|h| h.join(cx)).collect()"),
        "REGRESSION: join_all no longer collects per-handle \
         JoinFutures. If it uses a combined Future or \
         try_join semantics, the independence contract is \
         lost — one task's panic short-circuits.",
    );
}

#[test]
fn join_all_sequential_await_loop_preserves_per_task_results() {
    // Pin (link 2): join_all uses a for loop to await each
    // future and push to results. Each await is INDEPENDENT
    // — a panic in one doesnt skip the others.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn join_all<T>(";
    let start = source.find(fn_marker).expect("join_all fn");
    let body_end = source[start..].find("\n    }\n").expect("join_all close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("for fut in &mut futures {")
            && body.contains("results.push(std::pin::Pin::new(fut).await);"),
        "REGRESSION: join_all no longer awaits via per-future \
         for-loop. If it now uses join_all from futures-rs \
         or a similar combinator that short-circuits on \
         error, the per-task independence is lost.",
    );
}

#[test]
fn join_all_does_not_call_abort_on_sibling_handles_on_panic() {
    // Pin (link 3): join_all body has NO calls to abort() /
    // cancel() on sibling handles when one task fails.
    // Each task is independent.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn join_all<T>(";
    let start = source.find(fn_marker).expect("join_all fn");
    let body_end = source[start..].find("\n    }\n").expect("join_all close");
    let body = &source[start..start + body_end];

    let suspect_cancel_on_failure = [
        "h.abort()",
        ".abort_with_reason(",
        "for h in &handles { h.abort()",
    ];
    for pat in &suspect_cancel_on_failure {
        assert!(
            !body.contains(pat),
            "REGRESSION: join_all now calls `{pat}` — \
             cancelling siblings on failure. The \
             independence contract is broken; one task's \
             panic now cancels the others.",
        );
    }
}

#[test]
fn join_all_does_not_break_loop_on_first_error_for_full_drain() {
    // Pin (link 2): the for-loop must NOT break or return
    // on the first Err(JoinError::Panicked). Each future
    // gets awaited, even if siblings panicked.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn join_all<T>(";
    let start = source.find(fn_marker).expect("join_all fn");
    let body_end = source[start..].find("\n    }\n").expect("join_all close");
    let body = &source[start..start + body_end];

    // Look for early-break / early-return inside the loop.
    let suspect_short_circuit = [
        "if let Err(JoinError::Panicked(",
        "if result.is_err() { break;",
        "?",
    ];
    for pat in &suspect_short_circuit {
        // The `?` operator is more nuanced — there's no
        // legitimate use of ? inside join_all's body.
        if pat == &"?" {
            // Check there's no `result?` or similar
            // short-circuit pattern.
            assert!(
                !body.contains(".await?;"),
                "REGRESSION: join_all loop now uses ? on \
                 the await — short-circuits on first error. \
                 Per-task independence broken.",
            );
            continue;
        }
        assert!(
            !body.contains(pat),
            "REGRESSION: join_all loop now contains \
             `{pat}` — short-circuits on first error. \
             Per-task independence broken.",
        );
    }
}

#[test]
fn region_with_budget_cancels_on_panicked_outcome_for_failfast() {
    // Pin (link 3 contrast): region_with_budget DOES cancel
    // on Panicked outcome — this is the region/FailFast
    // semantic that distinguishes from join_all.
    let source = read("src/cx/scope.rs");
    let body = child_admission_body(&source);

    assert!(
        body.contains("Outcome::Err(_) | Outcome::Panicked(_) => {")
            && body.contains("CancelReason::fail_fast()")
            && body.contains("let effects = state.cancel_request(child_region, &reason, None);")
            && body.contains("state.defer_cancel_dispatch(effects);")
            && !body.contains(".dispatch()")
            && !body.contains("wake_by_ref("),
        "REGRESSION: region_with_budget no longer cancels \
         siblings on Err/Panicked through deferred post-lock \
         effects. The region/FailFast \
         semantic is broken — child failure no longer \
         propagates cancel to sibling tasks. The \
         distinction from join_all is lost.",
    );
}

#[test]
fn join_all_results_vec_capacity_matches_input_handles_for_one_to_one_mapping() {
    // Pin (link 1): the results Vec is initialized with
    // capacity = futures.len(). This documents the 1:1
    // mapping between input handles and output Results.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn join_all<T>(";
    let start = source.find(fn_marker).expect("join_all fn");
    let body_end = source[start..].find("\n    }\n").expect("join_all close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("Vec::with_capacity(futures.len())"),
        "REGRESSION: join_all no longer pre-allocates the \
         results Vec with the futures count. The 1:1 \
         input-to-output mapping invariant may be \
         observable to drift — minor but documents the \
         contract.",
    );
}

#[test]
fn literal_join_set_documents_region_semantics_explicitly() {
    // Pin (audit): the public JoinSet type exists now, but it must not
    // imply an independent ownership boundary. Its docs must say that
    // members run in a real region and that drop is only a cancellation
    // request, with region close as the quiescence backstop.
    let join_set_source = read("src/combinator/join_set.rs");

    assert!(
        join_set_source.contains("pub struct JoinSet<"),
        "REGRESSION: JoinSet disappeared from its documented combinator module",
    );
    assert!(
        join_set_source.contains("region's quiescence guarantee"),
        "REGRESSION: JoinSet docs no longer state that region quiescence still applies",
    );
    assert!(
        join_set_source.contains("*cancellation request*"),
        "REGRESSION: JoinSet docs no longer distinguish drop from guaranteed drain",
    );
}

#[test]
fn literal_join_set_spawns_emit_parent_set_trace_fields() {
    // Pin (audit): JoinSet members must carry enough structured trace
    // metadata to tie a spawned member back to its parent fan-out set without
    // confusing the set with an independent region boundary.
    let join_set_source = read("src/combinator/join_set.rs");

    assert!(
        join_set_source.contains("cx.trace_with_fields(")
            && join_set_source.contains("\"join_set.spawn\""),
        "REGRESSION: JoinSet no longer emits a structured spawn trace event",
    );
    for field in [
        "\"join_set_id\"",
        "\"member_index\"",
        "\"region\"",
        "\"spawn_kind\"",
        "\"active_members\"",
    ] {
        assert!(
            join_set_source.contains(field),
            "REGRESSION: JoinSet spawn trace field {field} disappeared",
        );
    }
}

#[test]
fn join_all_test_documents_in_order_result_invariant() {
    // Pin (audit hygiene): a test in scope.rs documents
    // that join_all preserves the input order in its
    // returned Vec.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("// INVARIANT: join_all preserves all task results in order"),
        "REGRESSION: the join_all order-preservation \
         invariant comment is gone. Future readers may \
         simplify to a parallel join (e.g., FuturesUnordered) \
         that returns results in completion order — silent \
         contract change for callers.",
    );
}

#[test]
fn task_handle_join_returns_per_handle_join_future_for_independence() {
    // Pin (link 1+2 supporting): TaskHandle::join returns
    // a per-handle JoinFuture<'_, T>. join_all collects
    // these into a Vec — each independent.
    let source = read("src/runtime/task_handle.rs");

    assert!(
        source.contains("pub fn join<'a>(&'a mut self, _cx: &'a Cx) -> JoinFuture<'a, T> {"),
        "REGRESSION: TaskHandle::join signature changed. \
         If it now returns a different type that combines \
         multiple handles, join_all's per-handle \
         independence is broken.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/cx_race_combinator_loser_drain_audit.rs",
        "tests/runtime_region_close_timed_lane_task_cancellation_audit.rs",
        "tests/runtime_join_handle_drop_lifecycle_audit.rs",
        "tests/scheduler_panic_in_task_isolation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
