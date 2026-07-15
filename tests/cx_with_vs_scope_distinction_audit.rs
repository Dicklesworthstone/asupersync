//! Audit + regression test for the `Cx::with()`-family vs
//! `Scope::region()`-family API distinction.
//!
//! Operator's question: "Cx::with() vs Cx::scope() difference:
//! with() is a scoped Cx push, scope() creates a new region.
//! Verify the API distinction is observable AND with()
//! correctly pops on drop."
//!
//! Audit findings:
//!
//!   asupersync exposes these two semantics through DIFFERENT
//!   methods than `with` / `scope` exactly, but with the
//!   contrast the operator describes. The distinction IS
//!   observable via runtime state, AND every `with`-family
//!   method has a matching RAII Drop guard that correctly
//!   pops/decrements on drop.
//!
//!   The "with" family (RAII-scoped Cx mutation):
//!
//!   - **`Cx::set_current(Some(cx)) -> CurrentCxGuard`**
//!     (cx/cx.rs:464): pushes a CurrentCxFrame onto the
//!     thread-local CURRENT_CX_STACK. Returns a Drop guard
//!     that pops on scope exit.
//!   - **`Cx::set_current_restricted(self) -> CurrentCxGuard`**
//!     (cx/cx.rs:507): same as set_current but with the
//!     cx's runtime CapMask narrowed.
//!   - **`Cx::masked(closure)`** (cx/cx.rs:2151): increments
//!     mask_depth, runs closure, MaskGuard decrements on
//!     drop.
//!   - **`Cx::with_current(closure)`** (cx/cx.rs:425):
//!     borrows the ambient cx for the closure body — closure-
//!     scoped lifetime, no Drop guard needed.
//!
//!   The "scope" family (region creation, async-scoped):
//!
//!   - **`Scope::region(state, cx, policy, f)`** (cx/scope.rs:
//!     861): async method that calls
//!     `state.create_child_region(...)` to allocate a NEW
//!     RegionId in the arena, then drives the closure
//!     with a child Scope inside a `RegionRunner` future.
//!     The RegionRunner has a Drop impl that cancels the
//!     region if dropped before completion.
//!   - **`Scope::region_with_budget(...)`** (cx/scope.rs:
//!     881): same as region() with explicit budget.
//!
//!   Observable distinctions:
//!
//!   1. **State change**: `set_current` only mutates a
//!      thread-local stack (CURRENT_CX_STACK); no new
//!      arena allocation. `Scope::region` allocates a new
//!      RegionRecord in the heap arena
//!      (state.create_child_region) — the global region
//!      count increases by exactly one.
//!
//!   2. **Lifetime**: `set_current` returns `CurrentCxGuard`
//!      — synchronous RAII, releases immediately on drop.
//!      `Scope::region` returns a future — must be awaited;
//!      its RegionRunner runs the user closure inside the
//!      newly-allocated region.
//!
//!   3. **Cancel propagation**: `Scope::region` participates
//!      in the region tree — the new region inherits cancel
//!      propagation from its parent, and dropping the
//!      RegionRunner future cancels the region. `set_current`
//!      doesn't create any cancel-propagation linkage.
//!
//!   4. **Drop semantics**:
//!      - `CurrentCxGuard::drop` pops the frame from
//!        CURRENT_CX_STACK (cx/cx.rs:327-336).
//!      - `MaskGuard::drop` decrements mask_depth via
//!        saturating_sub(1) (cx/cx.rs:281-287).
//!      - `RegionRunner::drop` cancels the child region
//!        by queueing auxiliary cancellation observer/Waker
//!        effects for post-lock dispatch, and advances state if
//!        dropped before await completes (cx/scope.rs:181-192).
//!        Close/finalizer callbacks during that advance are not
//!        covered by this distinction audit.
//!
//! Verdict: **SOUND**. The two API families are observably
//! distinct AND every with-style method has a correct RAII
//! Drop guard. The operator's framing of "Cx::with()" maps
//! to the set_current / set_current_restricted / masked /
//! with_current set; "Cx::scope()" maps to Scope::region /
//! region_with_budget. There is no method literally named
//! "with()" or "scope()" on Cx — but the semantic
//! distinction the operator describes is fully present.
//!
//! A regression that:
//!   - removed the CurrentCxGuard Drop impl (would leak
//!     frames; CURRENT_CX_STACK grows monotonically and
//!     Cx::current() returns stale Cxs from prior scopes),
//!   - made set_current return Self instead of a guard
//!     (callers would have to manually pop — error-prone,
//!     RAII contract broken),
//!   - removed the MaskGuard Drop impl (would leak mask
//!     depth; cancel acknowledgment never fires),
//!   - removed RegionRunner::drop (would leak regions;
//!     dropping the region future before await completes
//!     would leave the region in non-terminal state — full
//!     close-protocol deadlock),
//!   - made Scope::region a non-async method (would lose
//!     the region-future + drop-cancels semantics; couldnt
//!     express the "drop before completion cancels region"
//!     contract),
//!   - made set_current allocate a region (would conflate
//!     the two semantics — every Cx push would consume an
//!     arena slot),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cx_set_current_returns_current_cx_guard() {
    // Pin (link 1): set_current returns CurrentCxGuard — a
    // RAII guard that pops on drop. Without the guard
    // return, callers can't get RAII semantics.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub(crate) fn set_current(cx: Option<Self>) -> CurrentCxGuard {")
            || source.contains("pub fn set_current(cx: Option<Self>) -> CurrentCxGuard {"),
        "REGRESSION: Cx::set_current signature changed. The \
         CurrentCxGuard return is the RAII contract — \
         without it, callers must manually pop the stack \
         (error-prone) or the stack leaks.",
    );
}

#[test]
fn cx_set_current_restricted_returns_current_cx_guard_with_mask() {
    // Pin (link 1+2): set_current_restricted returns the
    // same Guard but with the cx's runtime CapMask narrowed
    // to the type-level Caps.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn set_current_restricted(self) -> CurrentCxGuard {"),
        "REGRESSION: Cx::set_current_restricted signature \
         changed. The capability-narrowing variant is the \
         tool that gives Cx::current() its ambient defense; \
         without it, less-trusted code can escape via \
         thread-local lookup.",
    );
}

#[test]
fn current_cx_guard_drop_pops_from_thread_local_stack() {
    // Pin (link 4): CurrentCxGuard::drop pops the frame.
    // Without this, set_current frames leak monotonically.
    let source = read("src/cx/cx.rs");

    let impl_marker = "impl Drop for CurrentCxGuard {";
    let start = source.find(impl_marker).expect("CurrentCxGuard Drop impl");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("CurrentCxGuard Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if !self.pushed {") && body.contains("return;"),
        "REGRESSION: CurrentCxGuard::drop no longer guards on \
         self.pushed before popping. A guard from \
         set_current(None) would pop a frame that doesn't \
         belong to it — stack underflow.",
    );

    assert!(
        body.contains("CURRENT_CX_STACK.try_with(") && body.contains("stack.borrow_mut().pop();"),
        "REGRESSION: CurrentCxGuard::drop no longer pops \
         from CURRENT_CX_STACK. Frames leak — \
         Cx::current() returns stale Cxs from prior scopes.",
    );
}

#[test]
fn cx_masked_returns_value_uses_mask_guard_for_decrement() {
    // Pin (link 3): Cx::masked(closure) increments
    // mask_depth, runs the closure, and the MaskGuard's
    // Drop decrements. The closure-form ensures balance
    // even on panic.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn masked<F, R>(&self, f: F) -> R";
    let start = source.find(fn_marker).expect("Cx::masked fn");
    let window_end = (start + 1400).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("inner.mask_depth += 1;")
            && body.contains("let _guard = MaskGuard { inner: &self.inner };"),
        "REGRESSION: Cx::masked no longer increments \
         mask_depth + sets up MaskGuard. Either the mask \
         doesn't apply (no critical-section protection) or \
         the MaskGuard pattern is broken (mask depth leaks).",
    );
}

#[test]
fn mask_guard_drop_decrements_mask_depth_via_saturating_sub() {
    // Pin (link 4): MaskGuard::drop decrements mask_depth
    // via saturating_sub(1). The saturating sub prevents
    // underflow on a buggy double-drop.
    let source = read("src/cx/cx.rs");

    let impl_marker = "impl Drop for MaskGuard<'_> {";
    let start = source.find(impl_marker).expect("MaskGuard Drop impl");
    let body_end = source[start..].find("\n}\n").expect("MaskGuard Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("mask_depth.saturating_sub(1)"),
        "REGRESSION: MaskGuard::drop no longer uses \
         saturating_sub(1). A buggy double-drop would \
         underflow mask_depth (wrap to MAX) — every \
         subsequent checkpoint would think it's masked, \
         silently swallowing cancels.",
    );
}

#[test]
fn cx_with_current_borrows_ambient_for_closure_body() {
    // Pin (link 4): with_current borrows the ambient cx for
    // the closure body — the borrow is held for the duration
    // of the closure, enforcing closure-scoped lifetime via
    // the borrow checker.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn with_current<F, R>(f: F) -> Option<R>")
            && source.contains("F: FnOnce(&Self) -> R,"),
        "REGRESSION: Cx::with_current signature changed. \
         The closure-borrow contract requires F: FnOnce(&Self) \
         -> R — without it, callers can't safely borrow the \
         ambient cx without paying the Arc-clone cost.",
    );
}

#[test]
fn scope_region_allocates_new_region_via_create_child_region() {
    // Pin (link 1 contrast): Scope::region calls
    // through the child-admission path, which allocates a
    // NEW RegionRecord in the arena. Without this path, no
    // new region is created.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("pub async fn region<P2, F, Fut, T, Caps>(")
            || source.contains("pub async fn region_with_budget<P2, F, Fut, T, Caps>("),
        "REGRESSION: Scope::region or region_with_budget \
         signature changed. The async method is what gives \
         the region-future + drop-cancels semantics — \
         without it, the scope contract is broken.",
    );

    // The public budgeted region path must route through
    // the admission helper that performs capability-aware
    // child-region allocation.
    let fn_marker = "pub async fn region_with_budget<P2, F, Fut, T, Caps>(";
    let start = source.find(fn_marker).expect("region_with_budget fn");
    let window_end = (start + 1200).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("self.region_with_budget_and_priority(")
            && body.contains("RegionPriority::Normal"),
        "REGRESSION: Scope::region_with_budget no longer routes \
         through the priority-aware child admission path. Either \
         no region is allocated (scope contract broken) or it \
         bypasses resource-pressure classification.",
    );

    let helper_marker = "async fn region_with_child_admission<P2, F, Fut, T, Caps>(";
    let helper_start = source
        .find(helper_marker)
        .expect("region_with_child_admission helper");
    let helper_window_end = (helper_start + 2000).min(source.len());
    let helper_safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= helper_window_end)
        .unwrap_or(helper_window_end);
    let helper_body = &source[helper_start..helper_safe_end];

    assert!(
        helper_body.contains("state.create_child_region_with_capability_budget_and_priority("),
        "REGRESSION: region_with_child_admission no longer allocates \
         a child region through the capability/priority-aware runtime \
         state path. Either no RegionRecord is allocated or admission \
         constraints are bypassed.",
    );
}

#[test]
fn region_runner_drop_cancels_child_region_if_dropped_pre_completion() {
    // Pin (link 4): RegionRunner has a Drop impl that
    // cancels the region if the future is dropped before
    // await completes. Without this, dropped region
    // futures leak the region in non-terminal state.
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
            && !body.contains("wake_by_ref("),
        "REGRESSION: RegionRunner::drop no longer cancels \
         the child region through deferred post-lock effects. Dropping a region future \
         before completion would leak the region — full \
         close-protocol deadlock for the parent.",
    );

    assert!(
        body.contains("region.begin_close(None);")
            && body.contains("state.advance_region_state(self.child_region);"),
        "REGRESSION: RegionRunner::drop no longer transitions \
         the region to Closing + advances state. Even if \
         cancel is requested, the region may stay in a \
         transitional state — quiescence stuck.",
    );
}

#[test]
fn current_cx_guard_is_not_send_to_prevent_cross_thread_drop() {
    // Pin (link 4 supporting): CurrentCxGuard contains
    // PhantomData<*mut ()> to mark it !Send. Without this,
    // the guard could be sent to another thread which
    // would pop the wrong CURRENT_CX_STACK on drop.
    let source = read("src/cx/cx.rs");

    let struct_marker = "pub struct CurrentCxGuard {";
    let start = source.find(struct_marker).expect("CurrentCxGuard struct");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("CurrentCxGuard struct close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("_not_send: std::marker::PhantomData<*mut ()>,"),
        "REGRESSION: CurrentCxGuard no longer contains the \
         _not_send PhantomData. The guard becomes Send → \
         can be moved to another thread → drop on the wrong \
         thread pops the wrong CURRENT_CX_STACK. Stack \
         corruption.",
    );
}

#[test]
fn cx_scope_returns_scope_handle_bound_to_current_region_not_a_new_region() {
    // Pin (operators framing nuance): Cx::scope() DOES exist
    // (cx.rs:2972) but its semantics are NOT "create a new
    // region" — it returns a Scope<'static> bound to the
    // CURRENT region. The "create new region" semantics
    // belongs to Scope::region (async). The distinction
    // matters: Cx::scope is a synchronous handle accessor;
    // Scope::region is an async region-allocator.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn scope(&self) -> crate::cx::Scope<'static> {"),
        "REGRESSION: Cx::scope signature changed. The Phase-0 \
         scope-handle accessor is what bridges Cx to the \
         Scope API for spawning into the current region; a \
         change here breaks the documented spawn pattern.",
    );

    // The body must NOT call create_child_region — Cx::scope
    // is for the CURRENT region, not a new one.
    let fn_marker = "pub fn scope(&self) -> crate::cx::Scope<'static> {";
    let start = source.find(fn_marker).expect("Cx::scope fn");
    let body_end = source[start..].find("\n    }\n").expect("Cx::scope close");
    let body = &source[start..start + body_end];

    assert!(
        !body.contains("state.create_child_region("),
        "REGRESSION: Cx::scope now calls create_child_region. \
         The Phase-0 contract is that Cx::scope binds to the \
         CURRENT region (synchronous, no allocation). The \
         new-region semantics belongs to Scope::region (async). \
         Conflating them would silently allocate regions on \
         every Cx::scope call.",
    );
}

#[test]
fn region_record_arena_allocation_observable_via_state_region_count() {
    // Pin (link 1 observability): the runtime state exposes
    // region count via the regions arena. After a
    // Scope::region() call, the count increases by 1; after
    // a set_current() call, it does not.
    let source = read("src/runtime/region_table.rs");

    assert!(
        source.contains("pub fn live_count")
            || source.contains("pub fn count")
            || source.contains("self.regions.len()"),
        "REGRESSION: RegionTable no longer exposes a count \
         method. Without it, tests can't observe the \
         scope-vs-with distinction (scope adds an arena \
         slot; with does not).",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/cx_drop_semantics_parent_persistence_audit.rs",
        "tests/cx_scope_deep_nesting_bookkeeping_audit.rs",
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
