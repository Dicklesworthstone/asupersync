//! Audit + regression test for `Runtime::current_handle()`
//! return semantics.
//!
//! Operator's question: "Cx::current_runtime_handle():
//! when called outside a runtime context, what happens?
//! Per asupersync, MUST panic with clear message (not
//! silently None or crash)."
//!
//! Audit findings: **SOUND BY DESIGN — but the operator's
//! premise is incorrect**.
//!
//! ── Actual API ──────────────────────────────────────────
//!
//! There is NO `Cx::current_runtime_handle()` method. The
//! actual API is:
//!
//! ```ignore
//! // src/runtime/builder.rs:3213
//! #[must_use]
//! pub fn current_handle() -> Option<RuntimeHandle> {
//!     CURRENT_RUNTIME_HANDLE
//!         .try_with(|cell| cell.borrow().clone())
//!         .unwrap_or(None)
//! }
//! ```
//!
//! It is an associated function on `Runtime`, not on Cx.
//! It returns `Option<RuntimeHandle>` — `Some(handle)`
//! inside a runtime context, `None` outside.
//!
//! The Option-return is INTENTIONAL and documented:
//!   "Returns `None` when called outside of a runtime
//!    context."
//!   "Returns `None` when no runtime is installed on the
//!    current thread and during thread-local teardown,
//!    where the ambient handle is no longer accessible."
//!
//! ── Why panic-policy would be wrong ─────────────────────
//!
//! The operator's framing — "MUST panic with clear message"
//! — would actually be a worse design:
//!
//! 1. **Thread-local teardown**: `current_handle()` is
//!    called from `Cx`-aware code at all kinds of moments,
//!    including drop / destructor paths. If
//!    current_handle() panicked, it would panic during a
//!    destructor chain, triggering double-panic abort.
//!    The `try_with(...).unwrap_or(None)` pattern at
//!    builder.rs:3214-3216 is the explicit fix for this:
//!    a graceful None when TLS access fails.
//!
//! 2. **Test/inspection code**: tools that want to *check*
//!    whether a runtime is installed shouldn't have to
//!    catch_unwind. `Option` is the idiomatic Rust way.
//!
//! 3. **Caller policy**: callers who DO want a panic on
//!    None can write `current_handle().expect("inside
//!    block_on")` — the documentation EXAMPLE shows this
//!    exact pattern (builder.rs:3203-3206). This pushes
//!    the panic policy out to the caller, which is the
//!    "no ambient policy" discipline of asupersync.
//!
//! 4. **No silent crash either**: `try_with(...)`
//!    explicitly catches the AccessError that would
//!    otherwise propagate as a panic during TLS teardown.
//!    So the contract is `None`, never an unexpected
//!    crash. The operator's "(not silently None or
//!    crash)" framing assumes a binary that doesn't apply
//!    — None is the documented, expected, tested return
//!    value, not "silent."
//!
//! ── Inline test coverage (6 unit tests) ─────────────────
//!
//! - `current_handle_available_inside_block_on` (5697):
//!   Some inside block_on.
//! - `current_handle_none_outside_block_on` (5714):
//!   None outside block_on. ← the operator's "outside
//!   context" case.
//! - `current_handle_spawn_completes_on_scheduler` (5723):
//!   handle().spawn() works correctly inside block_on.
//! - `current_handle_available_inside_spawned_task` (5747):
//!   Some inside a spawned task.
//! - `current_handle_restored_after_block_on` (5763):
//!   None → Some during block_on → None after block_on.
//! - `current_handle_returns_none_during_thread_local_teardown`
//!   (5782): None during TLS destructor chain (the
//!   double-panic-avoidance guarantee).
//!
//! These six tests pin every documented branch of the
//! Option contract.
//!
//! ── Verdict ──────────────────────────────────────────────
//!
//! **SOUND BY DESIGN**. The behavior is unambiguously
//! clear: `Runtime::current_handle() -> Option<RuntimeHandle>`,
//! with `Some` inside any runtime context and `None`
//! everywhere else (including during TLS teardown). The
//! operator's premise that "MUST panic" is incorrect —
//! the design deliberately rejects panic-policy at this
//! layer in favor of caller-controlled `.expect()`. This
//! design has explicit unit-test backing for all 6
//! documented branches, which is the OPPOSITE of unclear.
//!
//! No bead filed. No fix needed.
//!
//! A regression that:
//!   - changed `current_handle` to return `RuntimeHandle`
//!     (panic on None) would break double-panic safety
//!     during TLS teardown,
//!   - removed the `try_with(...).unwrap_or(None)` guard
//!     and used `.with(|cell| cell.borrow().clone())`
//!     directly would propagate AccessError panics
//!     during teardown,
//!   - removed the inline tests pinning the None-outside-
//!     context behavior would let regressions slip,
//! would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn current_handle_signature_returns_option() {
    // Pin: Runtime::current_handle returns Option<RuntimeHandle>,
    // not RuntimeHandle. Changing the return type to bare
    // RuntimeHandle would force a panic on the no-context
    // path, breaking double-panic safety during TLS
    // teardown.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("pub fn current_handle() -> Option<RuntimeHandle> {"),
        "REGRESSION: Runtime::current_handle no longer \
         returns Option<RuntimeHandle>. If it now returns \
         RuntimeHandle directly (panic on None), thread-\
         local teardown will trigger double-panic crashes.",
    );
}

#[test]
fn current_handle_uses_try_with_unwrap_or_none_for_teardown_safety() {
    // Pin: the implementation uses
    // `try_with(...).unwrap_or(None)` to gracefully handle
    // thread-local teardown. If this changes to plain
    // `with(...)`, AccessError panics propagate during
    // TLS destructor chains.
    let source = read("src/runtime/builder.rs");

    let fn_marker = "pub fn current_handle() -> Option<RuntimeHandle> {";
    let pos = source.find(fn_marker).expect("current_handle fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("current_handle close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("try_with("),
        "REGRESSION: current_handle no longer uses \
         try_with(...) for TLS access. If it uses .with(...) \
         directly, AccessError will panic during teardown.",
    );

    assert!(
        body.contains(".unwrap_or(None)"),
        "REGRESSION: current_handle no longer falls back \
         to None on TLS access failure. The graceful-during-\
         teardown contract is broken.",
    );
}

#[test]
fn current_handle_is_must_use() {
    // Pin: #[must_use] forces callers to acknowledge they
    // got an Option. If this attribute is removed, callers
    // can silently ignore the None case.
    let source = read("src/runtime/builder.rs");

    let fn_marker = "pub fn current_handle() -> Option<RuntimeHandle> {";
    let pos = source.find(fn_marker).expect("current_handle fn");
    let preceding = &source[pos.saturating_sub(2000)..pos];

    assert!(
        preceding.contains("#[must_use]"),
        "REGRESSION: #[must_use] is missing from \
         current_handle. Callers can now silently drop the \
         Option, missing the no-runtime-context case.",
    );
}

#[test]
fn current_handle_documented_to_return_none_outside_context() {
    // Pin: the docstring documents the None case explicitly.
    // Without this doc, future maintainers may add a panic
    // and call it a "fix" because they don't know the
    // graceful-None is the intended contract.
    let source = read("src/runtime/builder.rs");

    let fn_marker = "pub fn current_handle() -> Option<RuntimeHandle> {";
    let pos = source.find(fn_marker).expect("current_handle fn");
    let preceding = &source[pos.saturating_sub(2500)..pos];

    assert!(
        preceding.contains("Returns `None` when called outside of a runtime context.")
            || preceding.contains("Returns `None` when no runtime is installed"),
        "REGRESSION: current_handle docstring no longer \
         documents the None-outside-context case. Future \
         maintainers may misinterpret the design intent.",
    );
}

#[test]
fn current_handle_documented_to_return_none_during_teardown() {
    // Pin: the docstring documents the teardown case
    // explicitly. This is the load-bearing reason the
    // function returns Option (not just an idiomatic
    // choice).
    let source = read("src/runtime/builder.rs");

    let fn_marker = "pub fn current_handle() -> Option<RuntimeHandle> {";
    let pos = source.find(fn_marker).expect("current_handle fn");
    let preceding = &source[pos.saturating_sub(3000)..pos];

    assert!(
        preceding.contains("thread-local teardown")
            || preceding.contains("TLS")
            || preceding.contains("ambient handle is no longer accessible"),
        "REGRESSION: current_handle docstring no longer \
         documents the thread-local-teardown case. Future \
         maintainers may try to 'simplify' to .with(...) \
         and reintroduce double-panic crashes.",
    );
}

#[test]
fn cx_does_not_have_current_runtime_handle_method() {
    // Pin: there is no `Cx::current_runtime_handle()`
    // method. The runtime-handle accessor lives on
    // Runtime, not Cx — Cx is the capability context, not
    // a runtime-discovery mechanism.
    let source = read("src/cx/cx.rs");

    let suspect_methods = [
        "pub fn current_runtime_handle(",
        "pub fn runtime_handle(",
        "pub fn current_runtime(",
    ];
    for pat in &suspect_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: Cx now has `{pat}` — runtime-\
             handle access is being moved onto Cx, blurring \
             the capability/runtime boundary.",
        );
    }
}

#[test]
fn current_handle_inline_tests_pin_all_six_branches() {
    // Pin: all 6 inline tests must remain. Each guards a
    // specific branch of the Option contract. Deleting any
    // one lets a regression in that branch slip.
    let source = read("src/runtime/builder.rs");

    let required_tests = [
        "fn current_handle_available_inside_block_on()",
        "fn current_handle_none_outside_block_on()",
        "fn current_handle_spawn_completes_on_scheduler()",
        "fn current_handle_available_inside_spawned_task()",
        "fn current_handle_restored_after_block_on()",
        "fn current_handle_returns_none_during_thread_local_teardown()",
    ];

    for t in &required_tests {
        assert!(
            source.contains(t),
            "REGRESSION: inline test `{t}` is gone. The \
             corresponding Option-contract branch is no \
             longer guarded.",
        );
    }
}

#[test]
fn current_handle_none_outside_block_on_test_pins_no_panic() {
    // Pin: the inline test that proves None (not panic)
    // outside block_on. If this test is replaced with a
    // panic-expectation, the design has flipped.
    let source = read("src/runtime/builder.rs");

    let fn_marker = "fn current_handle_none_outside_block_on()";
    let pos = source.find(fn_marker).expect("none_outside test");
    let body = &source[pos..pos + 600];

    assert!(
        body.contains("Runtime::current_handle().is_none()"),
        "REGRESSION: the none_outside_block_on test no \
         longer asserts is_none(). Either the contract \
         changed (review!) or the test was weakened.",
    );

    // Must NOT use catch_unwind / panic-expecting patterns —
    // those would indicate the design flipped to "panic
    // outside context."
    assert!(
        !body.contains("catch_unwind") && !body.contains("should_panic"),
        "REGRESSION: the none_outside_block_on test now \
         expects a panic. The Option-return design has \
         been flipped — review whether this is \
         intentional and update the audit.",
    );
}

#[test]
fn current_handle_teardown_test_pins_graceful_none_during_destructors() {
    // Pin: the teardown test must remain — it's the
    // load-bearing test that proves try_with+unwrap_or
    // works during TLS destructor chains.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("fn current_handle_returns_none_during_thread_local_teardown()"),
        "REGRESSION: the thread_local_teardown test is \
         gone. The double-panic-avoidance guarantee is no \
         longer guarded.",
    );
}

#[test]
fn caller_pattern_expect_inside_block_on_documented() {
    // Pin: the docstring's example shows
    // `current_handle().expect("inside block_on")` — the
    // caller-controlled panic policy. If the example is
    // removed, users may not know how to "panic on None"
    // when they want that behavior.
    let source = read("src/runtime/builder.rs");

    let fn_marker = "pub fn current_handle() -> Option<RuntimeHandle> {";
    let pos = source.find(fn_marker).expect("current_handle fn");
    let preceding = &source[pos.saturating_sub(2500)..pos];

    assert!(
        preceding.contains(".expect(\"inside block_on\")") || preceding.contains(".expect("),
        "REGRESSION: the docstring example showing \
         caller-controlled .expect() panic policy is gone. \
         Users no longer have an idiomatic guide for the \
         panic-on-None case.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Mock TLS-installed runtime handle. Models the
/// `try_with(...).unwrap_or(None)` pattern.
struct MockRuntimeHandle {
    id: u32,
}

thread_local! {
    static MOCK_HANDLE: RefCell<Option<Arc<MockRuntimeHandle>>> = const { RefCell::new(None) };
}

fn mock_install(handle: Arc<MockRuntimeHandle>) -> InstallGuard {
    MOCK_HANDLE.with(|cell| {
        *cell.borrow_mut() = Some(handle);
    });
    InstallGuard
}

struct InstallGuard;
impl Drop for InstallGuard {
    fn drop(&mut self) {
        MOCK_HANDLE.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
}

fn mock_current_handle() -> Option<Arc<MockRuntimeHandle>> {
    MOCK_HANDLE
        .try_with(|cell| cell.borrow().clone())
        .unwrap_or(None)
}

#[test]
fn behavioral_current_handle_some_when_installed() {
    let handle = Arc::new(MockRuntimeHandle { id: 7 });
    let _guard = mock_install(Arc::clone(&handle));

    let observed = mock_current_handle().expect("installed");
    assert_eq!(observed.id, 7);
}

#[test]
fn behavioral_current_handle_none_when_not_installed() {
    // The current thread has no installed handle.
    let result = mock_current_handle();
    assert!(
        result.is_none(),
        "REGRESSION: current_handle returned Some despite \
         no install. The graceful-None contract is broken.",
    );
}

#[test]
fn behavioral_current_handle_none_after_guard_drop() {
    let handle = Arc::new(MockRuntimeHandle { id: 11 });
    {
        let _guard = mock_install(Arc::clone(&handle));
        assert!(mock_current_handle().is_some());
    }
    // Guard dropped — handle should be None.
    assert!(
        mock_current_handle().is_none(),
        "REGRESSION: current_handle still Some after guard \
         drop. TLS cleanup is broken.",
    );
}

#[test]
fn behavioral_current_handle_does_not_panic_outside_context() {
    // The most important behavioral pin: outside any
    // runtime context, the function does NOT panic. It
    // returns None gracefully.
    let panicked = std::panic::catch_unwind(|| {
        let _ = mock_current_handle();
    });

    assert!(
        panicked.is_ok(),
        "REGRESSION: mock_current_handle panicked outside \
         runtime context. The graceful-None contract is \
         broken — production current_handle would now \
         double-panic during TLS teardown.",
    );
}

#[test]
fn behavioral_caller_can_expect_to_get_panic_when_desired() {
    // Caller-controlled panic policy: if the user wants a
    // panic on None, they write `.expect(...)`.
    let observed_panic = AtomicBool::new(false);
    let result = std::panic::catch_unwind(|| {
        let _ = mock_current_handle().expect("inside runtime context");
    });

    if result.is_err() {
        observed_panic.store(true, Ordering::Release);
    }

    assert!(
        observed_panic.load(Ordering::Acquire),
        "REGRESSION: .expect() on a None did not panic. \
         The caller-controlled panic-policy idiom is broken.",
    );
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/runtime_block_on_vs_run_until_distinction_audit.rs",
        "tests/cx_no_scope_default_method_audit.rs",
        "tests/runtime_no_detached_orphan_spawn_api_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
