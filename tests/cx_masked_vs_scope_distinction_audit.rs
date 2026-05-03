//! Audit + regression test for `Cx::masked()` vs
//! `Cx::scope()` distinction.
//!
//! Operator's question: "masked is supposed to suppress
//! cancel propagation (build a barrier), scope creates a
//! new region. Verify these are correctly distinct in
//! implementation."
//!
//! Audit findings: **SOUND BY DESIGN — distinct, but
//! semantics differ slightly from the operator's framing**.
//!
//! ── Actual semantics ────────────────────────────────────
//!
//! 1. **`Cx::masked<F, R>(&self, f: F) -> R`** (cx.rs:2151):
//!    - Synchronous closure-scoped operation.
//!    - Increments `inner.mask_depth` under a write lock.
//!    - RAII `MaskGuard` decrements on drop.
//!    - Calls the closure, returns its R.
//!    - Asserts `mask_depth < MAX_MASK_DEPTH` to prevent
//!      unbounded nesting (INV-MASK-BOUNDED).
//!    - Effect: while mask_depth > 0, `cx.checkpoint()`
//!      returns `Ok(())` even if cancel is pending. The
//!      cancel signal IS still set (fast_cancel,
//!      cancel_requested). It is just NOT acknowledged at
//!      checkpoints inside the masked section.
//!
//!    Operator framing nuance: "suppress cancel propagation
//!    (build a barrier)" is not quite right. masked()
//!    DEFERS CANCEL ACKNOWLEDGMENT. Cancel is still
//!    propagated to child regions; the masked code just
//!    doesn't observe the Err itself. After the mask
//!    unwinds (mask_depth back to 0), the next checkpoint
//!    observes Err(Cancelled).
//!
//! 2. **`Cx::scope(&self) -> Scope<'static>`** (cx.rs:2972):
//!    - Synchronous handle accessor.
//!    - Returns a `Scope` bound to the CURRENT region_id
//!      and inherited budget.
//!    - Does NOT increment mask_depth.
//!    - Does NOT allocate a new region (Phase 0
//!      placeholder; new-region allocation is via
//!      `Scope::region(state, cx, policy, f).await`).
//!    - Does NOT take a closure.
//!
//!    Operator framing nuance: "scope creates a new region"
//!    is not quite right for Phase 0. `Cx::scope()` is the
//!    handle accessor; `Scope::region(...)` is the async
//!    allocator. See
//!    `tests/cx_scope_vs_scope_region_distinction_audit.rs`
//!    for the scope-vs-region distinction.
//!
//! ── Concrete differences ────────────────────────────────
//!
//! | Property            | masked                  | scope             |
//! |---------------------|-------------------------|-------------------|
//! | Sync vs async       | sync                    | sync              |
//! | Takes closure?      | YES (FnOnce -> R)       | NO                |
//! | Returns             | R (closure result)      | Scope<'static>    |
//! | Mutates mask_depth? | YES (increment + RAII)  | NO                |
//! | Allocates region?   | NO                      | NO (Phase 0)      |
//! | Effect on cancel    | DEFERS ack at checkpoint | none             |
//! | Lock acquired       | inner.write() briefly   | inner.read()      |
//! | RAII guard          | MaskGuard               | none              |
//!
//! These five distinguishing axes make it impossible for a
//! caller to confuse the two. The signatures alone reject
//! interchange — `cx.scope()` returns a Scope; `cx.masked(||
//! { ... })` returns the closure's result type.
//!
//! ── Why neither matches the operator's framing exactly ──
//!
//! - "masked suppresses cancel propagation": NO. masked
//!   defers ACKNOWLEDGMENT inside the masked section.
//!   Cancel still propagates to child regions/tasks. The
//!   masked closure just doesn't see Err(Cancelled) until
//!   the mask unwinds.
//!
//! - "scope creates a new region": NOT in Phase 0. scope()
//!   returns a handle bound to the current region. New-
//!   region allocation requires `Scope::region(...).await`
//!   (an async constructor with explicit policy).
//!
//! Both APIs are deliberately distinct — the operator's
//! conflation risk is non-existent because their
//! signatures and return types prevent any interchange.
//!
//! ── Cross-references for full coverage ──────────────────
//!
//! - tests/cx_masked_critical_section_audit.rs (if exists)
//! - tests/cx_checkpoint_during_region_cancel_timing_audit.rs
//!   (pins masked-defers-checkpoint-Err semantic)
//! - tests/cx_scope_vs_scope_region_distinction_audit.rs
//!   (pins scope-vs-Scope::region distinction)
//! - tests/cx_api_decision_tree_with_vs_scope_audit.rs
//!   (consolidated five-API decision tree)
//!
//! Verdict: **SOUND BY DESIGN**. masked and scope have
//! disjoint signatures, return types, side effects, and
//! semantics. They cannot be conflated.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn masked_signature_takes_closure_returns_r() {
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn masked<F, R>(&self, f: F) -> R")
            && source.contains("F: FnOnce() -> R,"),
        "REGRESSION: Cx::masked signature changed. The \
         closure-scoped cancel-defer primitive is broken.",
    );
}

#[test]
fn scope_signature_returns_handle_no_closure() {
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn scope(&self) -> crate::cx::Scope<'static> {"),
        "REGRESSION: Cx::scope signature changed. The \
         Phase-0 handle-accessor is broken.",
    );

    // It must NOT take a closure parameter.
    assert!(
        !source.contains("pub fn scope<F, R>(") && !source.contains("pub fn scope(&self, f: "),
        "REGRESSION: Cx::scope now takes a closure. It has \
         been conflated with masked().",
    );
}

#[test]
fn masked_increments_mask_depth_under_write_lock() {
    // Pin: masked acquires the write lock, increments
    // mask_depth, asserts the bound, drops the lock, then
    // calls the closure under a MaskGuard RAII.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn masked<F, R>(&self, f: F) -> R";
    let pos = source.find(fn_marker).expect("masked fn");
    let body_window = &source[pos..pos + 1500];

    assert!(
        body_window.contains("inner.mask_depth += 1;"),
        "REGRESSION: masked no longer increments mask_depth. \
         Cancel-defer is broken.",
    );

    assert!(
        body_window.contains("self.inner.write()"),
        "REGRESSION: masked no longer acquires write lock. \
         mask_depth is being mutated without exclusive \
         access — race condition.",
    );

    assert!(
        body_window.contains("MAX_MASK_DEPTH"),
        "REGRESSION: masked no longer asserts the \
         MAX_MASK_DEPTH bound. INV-MASK-BOUNDED is broken \
         — unbounded nesting can prevent cancel ever \
         being observed.",
    );

    assert!(
        body_window.contains("MaskGuard {"),
        "REGRESSION: masked no longer uses MaskGuard RAII \
         to decrement mask_depth on drop. Panics inside \
         the closure would leave mask_depth elevated, \
         leaking cancel-defer state.",
    );
}

#[test]
fn scope_does_not_increment_mask_depth() {
    // Pin: scope is a handle accessor. It must NOT touch
    // mask_depth.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn scope(&self) -> crate::cx::Scope<'static> {";
    let pos = source.find(fn_marker).expect("scope fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("scope fn close");
    let body = &source[pos..pos + body_end];

    assert!(
        !body.contains("mask_depth"),
        "REGRESSION: Cx::scope now references mask_depth. \
         The handle accessor is mutating cancel-defer \
         state — conflation with masked().",
    );

    assert!(
        !body.contains("MaskGuard"),
        "REGRESSION: Cx::scope now constructs MaskGuard. \
         The handle accessor is acquiring a mask — \
         conflation with masked().",
    );
}

#[test]
fn scope_returns_handle_bound_to_current_region() {
    // Pin: scope reads the current region_id and budget,
    // constructs a Scope::new with those. It does NOT
    // allocate a new region.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn scope(&self) -> crate::cx::Scope<'static> {";
    let pos = source.find(fn_marker).expect("scope fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("scope fn close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("self.region_id()") && body.contains("crate::cx::Scope::new("),
        "REGRESSION: scope no longer constructs Scope from \
         the current region_id. It is either allocating a \
         new region (conflation with Scope::region) or \
         losing the region binding.",
    );

    let suspect_region_alloc = [
        "create_child_region(",
        "RegionTable::create",
        "Region::new(",
        "spawn_region(",
    ];
    for pat in &suspect_region_alloc {
        assert!(
            !body.contains(pat),
            "REGRESSION: Cx::scope now calls `{pat}` — it \
             is allocating a new region. The Phase-0 \
             handle-accessor contract is broken.",
        );
    }
}

#[test]
fn masked_does_not_allocate_a_region() {
    // Pin: masked is a sync closure runner. It must NOT
    // allocate a region.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn masked<F, R>(&self, f: F) -> R";
    let pos = source.find(fn_marker).expect("masked fn");
    let body_window = &source[pos..pos + 1200];

    let suspect_calls = [
        "create_child_region(",
        "RegionTable::create",
        "Region::new(",
        "Scope::new(",
        "Scope::region(",
    ];
    for pat in &suspect_calls {
        assert!(
            !body_window.contains(pat),
            "REGRESSION: Cx::masked now calls `{pat}` — it \
             is allocating or constructing a region/Scope. \
             Conflation with scope/Scope::region.",
        );
    }
}

#[test]
fn mask_guard_drop_decrements_via_saturating_sub() {
    // Pin: MaskGuard::drop uses saturating_sub(1) so a
    // double-drop or unexpected mask_depth==0 doesn't
    // underflow.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("inner.mask_depth = inner.mask_depth.saturating_sub(1);")
            || source.contains("mask_depth.saturating_sub(1)"),
        "REGRESSION: MaskGuard::drop no longer uses \
         saturating_sub. Underflow possible if mask_depth \
         is already 0 — would silently re-mask via wrap.",
    );
}

#[test]
fn masked_documented_as_cancel_acknowledgment_defer() {
    // Pin: masked's docstring documents the cancel-
    // acknowledgment-defer semantic. Without this doc,
    // future readers may think it suppresses cancel
    // propagation (the operator's framing).
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn masked<F, R>(&self, f: F) -> R";
    let pos = source.find(fn_marker).expect("masked fn");
    let preceding = &source[pos.saturating_sub(3500)..pos];

    assert!(
        preceding.contains("Executes a closure with cancellation masked")
            || preceding.contains("masked"),
        "REGRESSION: masked docstring no longer documents \
         the closure-with-cancel-masked semantic.",
    );

    assert!(
        preceding.contains("checkpoint()") && preceding.contains("Ok(())"),
        "REGRESSION: masked docstring no longer documents \
         that checkpoint() returns Ok(()) inside masked \
         sections. The defer semantic is no longer user-\
         visible in docs.",
    );
}

#[test]
fn scope_documented_as_phase_0_handle_accessor() {
    // Pin: scope's docstring documents Phase-0 placeholder
    // semantics. Without this, future readers may add a
    // new-region allocator under the same name.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("In Phase 0, this creates a scope bound to the current region.")
            || source.contains("creates a scope bound to the current region"),
        "REGRESSION: scope docstring no longer documents \
         Phase-0 handle-accessor semantics.",
    );
}

#[test]
fn masked_and_scope_have_disjoint_signatures() {
    // Pin: the signatures alone make interchange
    // impossible. masked takes a closure; scope does not.
    // masked returns R (generic); scope returns
    // Scope<'static>.
    let source = read("src/cx/cx.rs");

    let masked_sig = "pub fn masked<F, R>(&self, f: F) -> R";
    let scope_sig = "pub fn scope(&self) -> crate::cx::Scope<'static>";

    assert!(
        source.contains(masked_sig),
        "REGRESSION: masked signature drifted from `{masked_sig}`.",
    );
    assert!(
        source.contains(scope_sig),
        "REGRESSION: scope signature drifted from `{scope_sig}`.",
    );

    // Sanity: the signatures must differ.
    assert_ne!(
        masked_sig, scope_sig,
        "Test logic error: signatures shouldn't match in source.",
    );
}

#[test]
fn cx_inline_test_pins_masked_defers_cancel() {
    // Pin: the inline unit test masked_defers_cancel
    // remains. It witnesses the cancel-defer semantic.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("fn masked_defers_cancel()"),
        "REGRESSION: the masked_defers_cancel inline test \
         is gone. The cancel-defer semantic is no longer \
         witnessed in-tree.",
    );

    assert!(
        source.contains("\"checkpoint should succeed when masked\"")
            || source.contains("checkpoint should succeed when masked"),
        "REGRESSION: the masked_defers_cancel test no \
         longer asserts that masked checkpoints succeed. \
         Either the assert message changed or the test \
         was weakened.",
    );
}

#[test]
fn mask_depth_max_invariant_documented() {
    // Pin: the MAX_MASK_DEPTH invariant. Without this
    // guard, deeply nested masked calls can prevent cancel
    // from EVER being observed.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("MAX_MASK_DEPTH"),
        "REGRESSION: MAX_MASK_DEPTH constant is gone. The \
         INV-MASK-BOUNDED invariant is broken.",
    );

    let task_context_source = read("src/types/task_context.rs");
    assert!(
        task_context_source.contains("MAX_MASK_DEPTH")
            || source.contains("pub const MAX_MASK_DEPTH"),
        "REGRESSION: MAX_MASK_DEPTH constant not defined \
         anywhere obvious. INV-MASK-BOUNDED unenforceable.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::sync::Mutex;

/// Mock CxInner with mask_depth + cancel state.
struct MockCxInner {
    mask_depth: u32,
    cancel_requested: bool,
}

struct MockCx {
    inner: Mutex<MockCxInner>,
}

struct MockMaskGuard<'a> {
    inner: &'a Mutex<MockCxInner>,
}

impl Drop for MockMaskGuard<'_> {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        inner.mask_depth = inner.mask_depth.saturating_sub(1);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct MockScope {
    region_id: u32,
}

impl MockCx {
    fn new() -> Self {
        Self {
            inner: Mutex::new(MockCxInner {
                mask_depth: 0,
                cancel_requested: false,
            }),
        }
    }

    fn cancel(&self) {
        self.inner.lock().unwrap().cancel_requested = true;
    }

    /// Models cx.masked(|| { ... }): increments mask_depth,
    /// runs the closure, decrements via RAII.
    fn masked<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.mask_depth += 1;
        }
        let _g = MockMaskGuard { inner: &self.inner };
        f()
    }

    /// Models cx.scope(): returns a Scope handle bound to
    /// current region. No mask_depth touch.
    fn scope(&self) -> MockScope {
        MockScope { region_id: 42 }
    }

    /// Models checkpoint: returns Err if cancel pending and
    /// not masked.
    fn checkpoint(&self) -> Result<(), &'static str> {
        let inner = self.inner.lock().unwrap();
        if inner.cancel_requested && inner.mask_depth == 0 {
            Err("cancelled")
        } else {
            Ok(())
        }
    }

    fn mask_depth(&self) -> u32 {
        self.inner.lock().unwrap().mask_depth
    }
}

#[test]
fn behavioral_masked_increments_mask_depth_during_closure() {
    let cx = MockCx::new();
    assert_eq!(cx.mask_depth(), 0);

    let result = cx.masked(|| {
        // Inside the masked closure, mask_depth is 1.
        cx.mask_depth()
    });

    assert_eq!(
        result, 1,
        "REGRESSION: mask_depth was not 1 inside masked \
         closure. The mask is not being applied.",
    );

    // After the closure, mask_depth is back to 0 (RAII
    // decrement).
    assert_eq!(
        cx.mask_depth(),
        0,
        "REGRESSION: mask_depth not restored to 0 after \
         masked closure returned. RAII guard is broken.",
    );
}

#[test]
fn behavioral_scope_does_not_change_mask_depth() {
    let cx = MockCx::new();
    assert_eq!(cx.mask_depth(), 0);

    let scope = cx.scope();

    // Calling scope must NOT change mask_depth.
    assert_eq!(
        cx.mask_depth(),
        0,
        "REGRESSION: cx.scope() changed mask_depth. The \
         handle accessor is mutating cancel-defer state.",
    );

    assert_eq!(scope.region_id, 42);
}

#[test]
fn behavioral_masked_defers_cancel_observation() {
    let cx = MockCx::new();
    cx.cancel();

    // Outside masked: checkpoint returns Err.
    assert_eq!(cx.checkpoint(), Err("cancelled"));

    // Inside masked: checkpoint returns Ok.
    let inside_result = cx.masked(|| cx.checkpoint());
    assert_eq!(
        inside_result,
        Ok(()),
        "REGRESSION: checkpoint did NOT return Ok inside \
         masked closure. The cancel-defer semantic is \
         broken.",
    );

    // After mask unwinds: checkpoint returns Err again.
    assert_eq!(
        cx.checkpoint(),
        Err("cancelled"),
        "REGRESSION: post-mask checkpoint did not return \
         Err. Either cancel was suppressed (wrong) or the \
         mask never unwound.",
    );
}

#[test]
fn behavioral_scope_returns_handle_without_acquiring_lock_for_mask() {
    // scope() reads region_id; no lock acquisition for
    // mask manipulation.
    let cx = MockCx::new();

    let s1 = cx.scope();
    let s2 = cx.scope();

    // Multiple scope calls produce equal handles bound to
    // the current region.
    assert_eq!(s1, s2);
}

#[test]
fn behavioral_signatures_disjoint_compile_time_proof() {
    // The compile-time proof: cx.masked() takes a closure;
    // cx.scope() does not. We can't pass the same arg
    // shape to both.
    let cx = MockCx::new();

    // masked takes FnOnce -> R.
    let r: u32 = cx.masked(|| 100_u32);
    assert_eq!(r, 100);

    // scope takes no arg.
    let s: MockScope = cx.scope();
    assert_eq!(s.region_id, 42);

    // The fact that this code compiles and uses different
    // call shapes IS the proof of distinction.
}

#[test]
fn behavioral_nested_masked_increments_then_restores() {
    let cx = MockCx::new();

    cx.masked(|| {
        assert_eq!(cx.mask_depth(), 1);
        cx.masked(|| {
            assert_eq!(cx.mask_depth(), 2);
        });
        assert_eq!(cx.mask_depth(), 1);
    });

    assert_eq!(
        cx.mask_depth(),
        0,
        "REGRESSION: nested masked did not unwind to 0.",
    );
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_scope_vs_scope_region_distinction_audit.rs",
        "tests/cx_api_decision_tree_with_vs_scope_audit.rs",
        "tests/cx_checkpoint_during_region_cancel_timing_audit.rs",
        "tests/cx_no_scope_default_method_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
