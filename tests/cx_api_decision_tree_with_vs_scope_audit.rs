//! Audit + regression test for the `Cx::*` / `Scope::*`
//! API decision tree.
//!
//! Operator's question: "Cx::with_cx() vs Cx::scope() vs
//! Scope::region() — is the API surface clear about when
//! to use each? File a bead documenting the decision tree
//! if not already documented."
//!
//! Audit findings:
//!
//!   asupersync does NOT have a literal `Cx::with_cx()`
//!   method. The operator's framing covers FIVE distinct
//!   APIs that all touch Cx/Scope, each with clear
//!   semantics. The decision tree:
//!
//!   ┌──────────────────────────────────────────────────┐
//!   │ "I want to use the AMBIENT Cx in a closure"     │
//!   │   → `Cx::with_current(|cx| { ... })`            │
//!   │     Closure-scoped borrow; zero Arc-clone fast   │
//!   │     path. (cx/cx.rs:425)                         │
//!   └──────────────────────────────────────────────────┘
//!
//!   ┌──────────────────────────────────────────────────┐
//!   │ "I want to INSTALL an ambient Cx for downstream │
//!   │  code that calls Cx::current()"                  │
//!   │   → `Cx::set_current(Some(cx))` -> CurrentCxGuard│
//!   │     RAII guard pops the frame on drop.           │
//!   │     (cx/cx.rs:464)                               │
//!   └──────────────────────────────────────────────────┘
//!
//!   ┌──────────────────────────────────────────────────┐
//!   │ "I want to DEFER cancel acknowledgment in a     │
//!   │  critical section"                               │
//!   │   → `cx.masked(|| { ... })`                      │
//!   │     Increments mask_depth; checkpoint observes   │
//!   │     cancel but defers ack until mask unwinds.    │
//!   │     (cx/cx.rs:2151)                              │
//!   └──────────────────────────────────────────────────┘
//!
//!   ┌──────────────────────────────────────────────────┐
//!   │ "I want to SPAWN tasks into the CURRENT region" │
//!   │   → `cx.scope()` returns Scope<'static>          │
//!   │     Phase-0 handle accessor; no new region       │
//!   │     allocated. Use this Scope's spawn methods.   │
//!   │     (cx/cx.rs:2972)                              │
//!   └──────────────────────────────────────────────────┘
//!
//!   ┌──────────────────────────────────────────────────┐
//!   │ "I want to CREATE a NEW child region with      │
//!   │  structured concurrency (await child quiescence)"│
//!   │   → `scope.region(state, cx, policy, f).await`   │
//!   │     Allocates new RegionId; awaits child         │
//!   │     quiescence; outcome dispatched per policy.   │
//!   │     (cx/scope.rs:861)                            │
//!   └──────────────────────────────────────────────────┘
//!
//!   The five APIs are observably distinct on multiple
//!   axes:
//!
//!   | API                  | Sync? | New region? | Drop guard? | Returns       |
//!   |----------------------|-------|-------------|-------------|---------------|
//!   | with_current(f)      | sync  | no          | closure     | Option<R>     |
//!   | set_current(Some(cx))| sync  | no          | CurrentCxGuard | Guard      |
//!   | masked(f)            | sync  | no          | MaskGuard   | R             |
//!   | cx.scope()           | sync  | no          | none (handle) | Scope<'static> |
//!   | scope.region(...)    | async | YES         | RegionRunner | Result<Outcome> |
//!
//!   Documentation status:
//!     - Cx::with_current has a 30+ line docstring
//!       (cx/cx.rs:389-424).
//!     - Cx::set_current has a multi-paragraph docstring
//!       (cx/cx.rs:454-460).
//!     - Cx::masked has a docstring describing the cancel-
//:       protocol mask (cx/cx.rs:~2117).
//!     - Cx::scope has a Phase-0 handle-accessor docstring
//!       (cx/cx.rs:2966-2970).
//!     - Scope::region has a docstring noting the await-
//:       quiescence + RegionCreateError contract (cx/scope.rs:
//!       849-860).
//!
//!   These are individually documented but lack a
//!   consolidated decision tree at a single anchor. The
//!   prior audits cover individual distinctions:
//:     - tests/cx_with_vs_scope_distinction_audit.rs
//!     - tests/cx_scope_vs_scope_region_distinction_audit.rs
//!     - tests/cx_drop_semantics_parent_persistence_audit.rs
//!
//!   This audit consolidates the five-API decision tree
//!   into one place.
//!
//! Verdict: **SOUND**. The five APIs are distinct in
//! signature and behavior. Documentation per-method is
//! adequate; consolidated decision tree is now in this
//! audit's docstring.
//!
//! No bead filed. The decision tree is documented (here +
//! per-method docstrings).
//!
//! A regression that:
//!   - removed any of the five methods (would lose a
//!     useful primitive),
//!   - changed any methods semantics to overlap with
//!     another (e.g., Cx::scope allocating a new region
//!     conflates with Scope::region),
//!   - removed the per-method docstrings (would lose user-
//!     facing documentation),
//!   - removed the prior individual-distinction audits
//!     (this consolidator would lose deep coverage),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cx_with_current_exists_and_takes_closure_returns_option() {
    // Pin (decision-tree row 1): Cx::with_current is the
    // closure-scoped ambient-borrow primitive. Returns
    // Option<R> (None if no ambient cx).
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn with_current<F, R>(f: F) -> Option<R>")
            && source.contains("F: FnOnce(&Self) -> R,"),
        "REGRESSION: Cx::with_current signature is gone or \
         changed. The closure-scoped ambient-borrow primitive \
         is broken — readers cant access Cx::current cheaply.",
    );
}

#[test]
fn cx_set_current_exists_and_returns_current_cx_guard() {
    // Pin (decision-tree row 2): Cx::set_current is the
    // RAII-guard ambient-install primitive.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub(crate) fn set_current(cx: Option<Self>) -> CurrentCxGuard {")
            || source.contains("pub fn set_current(cx: Option<Self>) -> CurrentCxGuard {"),
        "REGRESSION: Cx::set_current signature is gone or \
         changed. The RAII install primitive is broken — \
         no way to install an ambient Cx with deterministic \
         drop-pop.",
    );
}

#[test]
fn cx_masked_exists_and_takes_closure_for_cancel_defer() {
    // Pin (decision-tree row 3): Cx::masked is the
    // cancel-acknowledgment-defer primitive. Closure-scoped.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn masked<F, R>(&self, f: F) -> R")
            && source.contains("F: FnOnce() -> R,"),
        "REGRESSION: Cx::masked signature is gone or changed. \
         The cancel-defer mask primitive is broken — \
         critical sections cant defer cancel observation.",
    );
}

#[test]
fn cx_scope_exists_and_returns_scope_static_no_new_region() {
    // Pin (decision-tree row 4): Cx::scope is the Phase-0
    // handle accessor. Synchronous. Does NOT allocate a
    // new region.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn scope(&self) -> crate::cx::Scope<'static> {"),
        "REGRESSION: Cx::scope signature is gone or changed. \
         The Phase-0 handle-accessor is broken — users \
         cant get a Scope handle for spawning into the \
         current region without going through region().",
    );

    // The body must NOT call create_child_region.
    let fn_marker = "pub fn scope(&self) -> crate::cx::Scope<'static> {";
    let start = source.find(fn_marker).expect("Cx::scope fn");
    let body_end = source[start..].find("\n    }\n").expect("Cx::scope close");
    let body = &source[start..start + body_end];

    assert!(
        !body.contains("create_child_region("),
        "REGRESSION: Cx::scope now allocates a new region \
         via create_child_region. This conflates with \
         Scope::region — the Phase-0 handle-accessor \
         contract is broken.",
    );
}

#[test]
fn scope_region_exists_async_returns_result_outcome() {
    // Pin (decision-tree row 5): Scope::region is the
    // async region-allocator. Returns Result<Outcome<T,
    // P2::Error>, RegionCreateError>.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("pub async fn region<P2, F, Fut, T, Caps>(")
            && source.contains("-> Result<Outcome<T, P2::Error>, RegionCreateError>"),
        "REGRESSION: Scope::region signature is gone or \
         changed. The async region-allocator is broken — \
         users cant create child regions with structured \
         concurrency.",
    );
}

#[test]
fn cx_with_current_docstring_documents_zero_arc_clone_semantics() {
    // Pin (documentation row 1): Cx::with_current is
    // documented as the zero-Arc-clone fast path for
    // ambient reads. Without this docstring, future readers
    // may simplify to Cx::current() and lose the perf win.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("zero-Arc-clone hot path")
            || source.contains("br-asupersync-xqt7dj — zero-Arc-clone"),
        "REGRESSION: Cx::with_current docstring no longer \
         documents the zero-Arc-clone optimization. Future \
         readers may misuse Cx::current() in tight loops, \
         paying 3 atomic ops per call.",
    );
}

#[test]
fn cx_set_current_docstring_documents_raii_guard_semantics() {
    // Pin (documentation row 2): Cx::set_current is
    // documented as RAII; pops the frame on drop.
    let source = read("src/cx/cx.rs");

    let pos = source
        .find("pub(crate) fn set_current(cx: Option<Self>) -> CurrentCxGuard {")
        .or_else(|| source.find("pub fn set_current(cx: Option<Self>) -> CurrentCxGuard {"))
        .expect("set_current fn");
    let preceding = &source[pos.saturating_sub(2000)..pos];

    assert!(
        preceding.contains("Sets the current task context for the duration of the guard")
            || preceding.contains("Installs `cx` as the current ambient task context")
            || preceding.contains("public ambient-install primitive"),
        "REGRESSION: Cx::set_current docstring no longer \
         documents the RAII semantic. Users may forget \
         to retain the guard for the desired scope.",
    );
}

#[test]
fn cx_masked_docstring_documents_cancel_protocol_mask_semantics() {
    // Pin (documentation row 3): Cx::masked is documented
    // as the cancel-protocol mask that DEFERS
    // acknowledgment. Without this, users may misuse it.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn masked<F, R>(&self, f: F) -> R";
    let pos = source.find(fn_marker).expect("Cx::masked fn");
    let preceding = &source[pos.saturating_sub(3000)..pos];

    assert!(
        preceding.contains("Executes a closure with cancellation masked")
            && (preceding.contains("checkpoint() will return Ok") || preceding.contains("masked")),
        "REGRESSION: Cx::masked docstring no longer \
         documents the cancel-defer semantic. Users may \
         confuse it with abort-suppression or other \
         primitives.",
    );
}

#[test]
fn cx_scope_docstring_documents_phase_0_no_new_region() {
    // Pin (documentation row 4): Cx::scope is documented
    // as Phase-0 handle accessor. Without this, users may
    // expect new-region semantics.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("In Phase 0, this creates a scope bound to the current region.")
            || source.contains("creates a scope bound to the current region"),
        "REGRESSION: Cx::scope docstring no longer documents \
         Phase-0 handle-accessor contract. Users may misread the API as \
         creating a new region.",
    );
}

#[test]
fn scope_region_docstring_documents_await_quiescence_contract() {
    // Pin (documentation row 5): Scope::region is documented
    // as awaiting child quiescence + Result<Outcome,
    // RegionCreateError>. Without this, users dont know
    // the contract.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn region<P2, F, Fut, T, Caps>(";
    let pos = source.find(fn_marker).expect("Scope::region fn");
    let preceding = &source[pos.saturating_sub(3000)..pos];

    assert!(
        preceding.contains("RegionCreateError")
            || preceding.contains("region") && preceding.contains("close sequence")
            || preceding.contains("quiescence"),
        "REGRESSION: Scope::region docstring no longer \
         documents the contract. Users may misuse — \
         expecting sync return, not awaiting quiescence, etc.",
    );
}

#[test]
fn no_literal_with_cx_method_to_avoid_naming_collision() {
    // Pin (anti-conflation): there must be NO method named
    // `Cx::with_cx` that would collide with the existing
    // `with_current`. The current naming is intentional.
    let source = read("src/cx/cx.rs");

    let suspect_methods = [
        "pub fn with_cx<F",
        "pub fn with_cx(",
        "pub async fn with_cx(",
    ];
    for pat in &suspect_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: Cx now has a method `{pat}` — \
             potential conflation with with_current. Either \
             the API was redesigned (deserves discussion) \
             or naming drift introduces confusion.",
        );
    }
}

#[test]
fn five_apis_have_observably_different_signatures() {
    // Pin (full distinction): the five APIs have
    // different return types, sync/async-ness, and
    // closure-vs-handle patterns. This pin documents the
    // distinguishing axes.
    let cx_source = read("src/cx/cx.rs");
    let scope_source = read("src/cx/scope.rs");

    // with_current returns Option<R> — closure-scoped.
    assert!(
        cx_source.contains("pub fn with_current<F, R>(f: F) -> Option<R>"),
        "REGRESSION: with_current signature drift.",
    );

    // set_current returns CurrentCxGuard — RAII.
    assert!(
        cx_source.contains("-> CurrentCxGuard {"),
        "REGRESSION: set_current return type drift.",
    );

    // masked returns R — closure-scoped + value passthrough.
    assert!(
        cx_source.contains("pub fn masked<F, R>(&self, f: F) -> R"),
        "REGRESSION: masked signature drift.",
    );

    // scope returns Scope<'static> — handle accessor.
    assert!(
        cx_source.contains("pub fn scope(&self) -> crate::cx::Scope<'static>"),
        "REGRESSION: cx.scope signature drift.",
    );

    // Scope::region returns Result<Outcome, RegionCreateError>
    // — async region-constructor.
    assert!(
        scope_source.contains("-> Result<Outcome<T, P2::Error>, RegionCreateError>"),
        "REGRESSION: Scope::region signature drift.",
    );
}

#[test]
fn prior_individual_distinction_audits_provide_deep_coverage() {
    // Pin (cross-reference): prior audits cover the
    // pairwise distinctions. This consolidator builds on
    // them.
    let prior_audits = [
        "tests/cx_with_vs_scope_distinction_audit.rs",
        "tests/cx_scope_vs_scope_region_distinction_audit.rs",
        "tests/cx_drop_semantics_parent_persistence_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing. \
             This consolidator depends on the per-pair \
             distinction audits for deep coverage.",
        );
    }
}

#[test]
fn cross_reference_to_other_related_audits() {
    let prior_audits = [
        "tests/cx_checkpoint_cancel_fail_fast_audit.rs",
        "tests/cx_scope_panic_propagation_audit.rs",
        "tests/runtime_join_handle_drop_lifecycle_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
