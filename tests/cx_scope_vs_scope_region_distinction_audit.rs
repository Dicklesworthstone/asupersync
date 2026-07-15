//! Audit + regression test for `Cx::scope()` vs
//! `Scope::region()` API distinction.
//!
//! Operator's question: "are these two API surfaces really
//! distinct (different invariants) or duplicates? Verify
//! documentation matches implementation. If
//! conflated/duplicate, file bead."
//!
//! Audit findings:
//!
//!   `Cx::scope()` and `Scope::region()` are **distinct
//!   APIs with different invariants**, NOT duplicates.
//!   Documentation matches implementation. The split:
//!
//!   1. **`Cx::scope() -> Scope<'static>`** (cx/cx.rs:2972):
//!      - **Phase-0 handle accessor**. Synchronous, no
//:        async/await.
//!      - Returns a Scope BOUND TO THE CURRENT REGION.
//!      - Does NOT allocate a new region — no
//!        `state.create_child_region` call.
//!      - Inherits the current Cxs budget (`self.budget()`).
//!      - Documented purpose: "creates a scope bound to
//!        the current region. In later phases, the `scope!`
//!        macro will create child regions with proper
//!        quiescence guarantees."
//!      - Use case: spawning tasks into the current region
//!        without creating a child.
//!
//!   2. **`Scope::region(state, cx, policy, f) -> Result<...>`**
//!      (cx/scope.rs:861):
//!      - **Async region constructor**. Returns a Future.
//!      - Allocates a NEW child RegionId via
//!        `state.create_child_region(self.region, budget)`.
//!      - Drives the user's closure inside the new region
//!        via RegionRunner.
//!      - On completion, transitions the child region to
//!        Closing → Drained → Closed.
//!      - On panic-unwind drop, RegionRunner::Drop cancels
//!        the child region by queueing its auxiliary cancellation
//!        observer/Waker effects for post-lock scheduler dispatch.
//!        Other close/finalizer callbacks are outside this audit.
//!      - Use case: structured-concurrency "do this work
//!        inside a fresh region with its own quiescence
//!        boundary".
//!
//!   Different invariants:
//!
//!   - **State change**:
//!     - `Cx::scope()`: NONE. Just packages RegionId +
//!       Budget into a Scope.
//!     - `Scope::region()`: increases the regions arena
//:       length by 1.
//!
//!   - **Return type**:
//!     - `Cx::scope()`: `Scope<'static>` (synchronous).
//!     - `Scope::region()`: `Result<Outcome<T, P2::Error>,
//!       RegionCreateError>` (async — must be awaited).
//!
//!   - **Region tree**:
//!     - `Cx::scope()`: no change to the region tree.
//!     - `Scope::region()`: new child node under the
//!       parent.
//!
//!   - **Cancel propagation**:
//!     - `Cx::scope()`: tasks spawned share the parents
//!       cancel state.
//!     - `Scope::region()`: child region inherits parent's
//!       cancel state with proper isolation; dropping the
//!       region future cancels the child.
//!
//!   - **Quiescence**:
//!     - `Cx::scope()`: no separate quiescence boundary.
//!     - `Scope::region()`: child region must reach
//!       quiescence (all children + tasks + obligations
//!       complete) before the await returns Ok.
//!
//!   - **Async-vs-sync**:
//!     - `Cx::scope()`: synchronous accessor; no future to
//!       poll.
//!     - `Scope::region()`: async; the await suspends until
//!       the region quiesces.
//!
//! Verdict: **SOUND**. The two APIs have observably
//! different invariants. Cx::scope is a lightweight handle
//! accessor; Scope::region is the structured-concurrency
//! region-allocator. No conflation. Documentation matches
//! implementation (the docstring on Cx::scope explicitly
//! notes the Phase-0 handle-accessor semantics).
//!
//! No bead filed. The two APIs serve different purposes
//: with clear separation.
//!
//! A regression that:
//!   - made Cx::scope allocate a new region (would conflate
//!     with Scope::region — every Cx::scope call would
//:     consume an arena slot, defeating the lightweight-
//!     handle purpose),
//!   - made Scope::region synchronous (would lose the
//!     await-quiescence contract — apps couldnt wait for
//:     children to complete),
//!   - changed Cx::scope's return type to Result (would
//!     conflate with the fallible region-allocator),
//!   - removed Cx::scope (would lose the lightweight-handle
//!     pattern; apps would need to manually construct
//!     Scopes — verbose),
//!   - removed Scope::region (would lose the structured-
//!     concurrency primitive; apps couldnt create child
//!     regions),
//!   - documented Cx::scope as creating a new region (lying
//:     to users about Phase-0 semantics),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cx_scope_is_synchronous_returns_scope_static() {
    // Pin (link 1): Cx::scope returns Scope<'static>
    // synchronously. NOT an async fn, NOT a future. The
    // 'static lifetime is part of the Phase-0
    // handle-accessor contract.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn scope(&self) -> crate::cx::Scope<'static> {"),
        "REGRESSION: Cx::scope signature changed. If it \
         became async or Result-returning, the lightweight-\
         handle contract is broken — every existing caller \
         pays async overhead.",
    );

    // The body must construct via Scope::new, NOT via
    // create_child_region.
    let fn_marker = "pub fn scope(&self) -> crate::cx::Scope<'static> {";
    let start = source.find(fn_marker).expect("Cx::scope fn");
    let body_end = source[start..].find("\n    }\n").expect("Cx::scope close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("crate::cx::Scope::new_with_capability_budget(")
            && body.contains("self.region_id(),")
            && body.contains("self.capability_budget(),"),
        "REGRESSION: Cx::scope no longer constructs Scope::\
         new_with_capability_budget with the CURRENT region_id. \
         If it now allocates a new region, the lightweight-\
         handle purpose is broken.",
    );
}

#[test]
fn cx_scope_does_not_allocate_a_new_region() {
    // Pin (link 1 invariant): Cx::scope's body does NOT
    // call state.create_child_region. The arena is not
    // touched.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn scope(&self) -> crate::cx::Scope<'static> {";
    let start = source.find(fn_marker).expect("Cx::scope fn");
    let body_end = source[start..].find("\n    }\n").expect("Cx::scope close");
    let body = &source[start..start + body_end];

    let suspect_alloc = ["create_child_region", ".regions.insert", "Arena::insert"];
    for pat in &suspect_alloc {
        assert!(
            !body.contains(pat),
            "REGRESSION: Cx::scope now contains region-\
             allocation pattern (`{pat}`). The Phase-0 \
             handle-accessor contract is broken — every \
             Cx::scope call now consumes an arena slot, \
             conflating with Scope::region.",
        );
    }
}

#[test]
fn cx_scope_documentation_marks_phase_0_no_new_region() {
    // Pin (link 1 documentation): the docstring on
    // Cx::scope explicitly notes the Phase-0
    // handle-accessor semantics — "creates a scope bound to the current
    // region. In later phases, the `scope!` macro will
    // create child regions". Without this docstring, users
    // misread the API as creating a new region.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("In Phase 0, this creates a scope bound to the current region.")
            || source.contains("creates a scope bound to the current region"),
        "REGRESSION: Cx::scope docstring no longer documents \
         the Phase-0 contract. Users may misread the API as \
         creating a new region — the scope! macro is \
         documented as the future child-region constructor, \
         but the current Cx::scope is just the accessor.",
    );
}

#[test]
fn scope_region_is_async_returns_result_outcome() {
    // Pin (link 2): Scope::region is async and returns
    // Result<Outcome<T, P2::Error>, RegionCreateError>.
    // The async return type is what makes it the
    // structured-concurrency region constructor.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("pub async fn region<P2, F, Fut, T, Caps>("),
        "REGRESSION: Scope::region is no longer async. \
         The await-for-quiescence contract is broken — \
         apps couldnt wait for the regions children to \
         complete before proceeding.",
    );

    assert!(
        source.contains("-> Result<Outcome<T, P2::Error>, RegionCreateError>"),
        "REGRESSION: Scope::region return type changed. \
         Without Result<Outcome, RegionCreateError>, the \
         four-valued outcome (Ok/Err/Cancelled/Panicked) + \
         creation-failure split is lost.",
    );
}

#[test]
fn scope_region_with_budget_calls_create_child_region_for_arena_alloc() {
    // Pin (link 2 invariant): Scope::region (via the
    // region_with_budget -> region_with_budget_and_priority
    // -> region_with_child_admission chain) calls
    // state.create_child_region_with_capability_budget_and_priority
    // — increases the arena by 1. This is the structural
    // distinction from Cx::scope.
    let source = read("src/cx/scope.rs");

    let fn_marker = "async fn region_with_child_admission<P2, F, Fut, T, Caps>(";
    let start = source
        .find(fn_marker)
        .expect("region_with_child_admission fn");
    let window_end = (start + 12000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("state.create_child_region_with_capability_budget_and_priority(")
            && body.contains("self.region,")
            && body.contains("admission.budget,")
            && body.contains("admission.capability_budget,")
            && body.contains("admission.priority,"),
        "REGRESSION: Scope::region child-admission path no \
         longer calls create_child_region_with_capability_\
         budget_and_priority. Either the region is not \
         allocated (scope contract broken) or the allocation \
         path is silently bypassed.",
    );
}

#[test]
fn scope_region_drives_user_closure_via_region_runner_for_quiescence() {
    // Pin (link 2 invariant): Scope::region drives the
    // closure via RegionRunner — which awaits child quiescence
    // and cancels on pre-completion drop. Cx::scope has no
    // RegionRunner equivalent.
    let source = read("src/cx/scope.rs");

    let fn_marker = "async fn region_with_child_admission<P2, F, Fut, T, Caps>(";
    let start = source
        .find(fn_marker)
        .expect("region_with_child_admission fn");
    let window_end = (start + 12000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("let runner = RegionRunner {"),
        "REGRESSION: region_with_child_admission no longer \
         constructs a RegionRunner. The drop-cancels-region \
         semantic is lost — region future drops would leak \
         the region.",
    );

    assert!(
        body.contains("runner.await"),
        "REGRESSION: region_with_child_admission no longer \
         awaits the RegionRunner. The structured-concurrency \
         wait-for-children contract is broken.",
    );
}

#[test]
fn scope_region_advances_state_after_user_closure_completes() {
    // Pin (link 2 quiescence): after the user closure
    // returns, region_with_budget calls
    // advance_region_state to drive Closing → Drained →
    // Closed. Cx::scope has no such transition.
    let source = read("src/cx/scope.rs");

    let fn_marker = "async fn region_with_child_admission<P2, F, Fut, T, Caps>(";
    let start = source
        .find(fn_marker)
        .expect("region_with_child_admission fn");
    let window_end = (start + 12000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("state.advance_region_state(child_region);"),
        "REGRESSION: region_with_child_admission no longer \
         advances the region state after closure completion. \
         The region stays in transitional state — \
         close-quiescence broken.",
    );

    // The region close awaits quiescence via RegionCloseFuture.
    assert!(
        body.contains("RegionCloseFuture { state: notify }.await;"),
        "REGRESSION: region_with_child_admission no longer \
         awaits RegionCloseFuture. The await would return \
         before the region actually quiesced — visible \
         regression for callers expecting children to complete.",
    );
}

#[test]
fn scope_region_outcome_drives_post_close_action() {
    // Pin (link 2 outcome handling): the outcome match
    // (Ok/Err/Panicked/Cancelled) determines the cleanup
    // strategy — Ok → begin_close; others → cancel + close.
    // Cx::scope has no such outcome handling.
    let source = read("src/cx/scope.rs");

    let fn_marker = "async fn region_with_child_admission<P2, F, Fut, T, Caps>(";
    let start = source
        .find(fn_marker)
        .expect("region_with_child_admission fn");
    let window_end = (start + 12000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("Outcome::Ok(_) => {")
            && body.contains("Outcome::Cancelled(reason) => {")
            && body.contains("Outcome::Err(_) | Outcome::Panicked(_) => {"),
        "REGRESSION: region_with_child_admission no longer \
         dispatches on the outcome variants. The cleanup \
         strategy is conflated — error/panic paths get the \
         same treatment as Ok.",
    );
}

#[test]
fn cx_scope_documentation_does_not_falsely_claim_new_region_creation() {
    // Pin (link 1 documentation truthfulness): Cx::scope's
    // docstring must NOT claim it creates a new region.
    // That would be a documentation bug — the Phase-0
    // contract is explicit.
    let source = read("src/cx/cx.rs");

    // Locate the Cx::scope docstring.
    let fn_marker = "pub fn scope(&self) -> crate::cx::Scope<'static> {";
    let pos = source.find(fn_marker).expect("Cx::scope fn");
    let preceding = &source[pos.saturating_sub(2000)..pos];

    let suspect_lying_docs = [
        "/// Creates a new child region",
        "/// Allocates a new region",
        "/// Creates a fresh region",
    ];
    for pat in &suspect_lying_docs {
        assert!(
            !preceding.contains(pat),
            "REGRESSION: Cx::scope docstring now claims to \
             create a new region (`{pat}`) — but the \
             implementation does NOT allocate. \
             Documentation diverges from implementation; \
             user-facing contract violation.",
        );
    }
}

#[test]
fn region_runner_drop_cancels_child_only_for_scope_region_path() {
    // Pin (link 2 cleanup): RegionRunner::Drop cancels the
    // child region on pre-completion drop. This is the
    // Scope::region path. Cx::scope has no RegionRunner —
    // its Scope just packages handles, no Drop side
    // effects.
    let source = read("src/cx/scope.rs");

    let impl_marker = "impl<Fut> Drop for RegionRunner<'_, Fut> {";
    let start = source.find(impl_marker).expect("RegionRunner Drop impl");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("RegionRunner Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("let effects = state.cancel_request(self.child_region, &reason, None);")
            && body.contains("state.defer_cancel_dispatch(effects);")
            && !body.contains(".dispatch()")
            && !body.contains("wake_by_ref(")
            && body.contains("region.begin_close(None);")
            && body.contains("state.advance_region_state(self.child_region);"),
        "REGRESSION: RegionRunner::Drop no longer cleans up \
         the child region through the deferred effects queue. Dropping a region future before \
         await leaks the region.",
    );
}

#[test]
fn no_method_named_create_region_on_cx_to_avoid_naming_collision() {
    // Pin (audit hygiene): there must be NO method like
    // `Cx::create_region` or `Cx::new_region` that would
    // conflate with Scope::region. The Cx-side primitive
    // is intentionally just the handle accessor.
    let source = read("src/cx/cx.rs");

    let suspect_collisions = [
        "pub fn create_region(",
        "pub fn new_region(",
        "pub async fn create_region(",
        "pub async fn new_region(",
    ];
    for pat in &suspect_collisions {
        assert!(
            !source.contains(pat),
            "REGRESSION: Cx now has a method `{pat}` that \
             conflates with Scope::region. The Cx-vs-Scope \
             API split is broken; users may grab the wrong \
             primitive.",
        );
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/cx_with_vs_scope_distinction_audit.rs",
        "tests/cx_scope_deep_nesting_bookkeeping_audit.rs",
        "tests/cx_scope_panic_propagation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
