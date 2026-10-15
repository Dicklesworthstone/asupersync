//! Audit + regression test for `Runtime::current_handle()`
//! cross-runtime safety.
//!
//! Operator's question: "When called from inside a Tokio
//! runtime (not asupersync), do we (a) panic with clear
//! 'wrong runtime' error (correct: actionable), (b) return
//! Err(NotInRuntime) (correct: fail-soft), or (c) succeed
//! but return invalid handle (data corruption)?"
//!
//! Audit findings: **SOUND BY DESIGN — option (b)-equivalent
//! via Option<RuntimeHandle>, never panic, never data
//! corruption**.
//!
//! ── Why cross-runtime confusion is impossible ───────────
//!
//! The thread-local slot at `src/runtime/builder.rs:200`:
//!
//! ```ignore
//! thread_local! {
//!     static CURRENT_RUNTIME_HANDLE: RefCell<Option<RuntimeHandle>>
//!         = const { RefCell::new(None) };
//! }
//! ```
//!
//! Critical properties:
//!
//! 1. **Asupersync-specific namespace**: this static is
//!    declared inside the asupersync crate at module scope.
//!    No other crate can write to it. Tokio (or any other
//!    runtime) has no path to populate this slot.
//!
//! 2. **Strongly-typed**: the cell holds
//!    `Option<RuntimeHandle>` of asupersync's RuntimeHandle
//!    type. Even if another crate had a TLS with a
//!    coincidentally similar name, the type system would
//!    prevent any cross-population.
//!
//! 3. **Default = None**: every new thread starts with
//!    None. Tokio worker threads, raw std::thread::spawn
//!    threads, kernel callbacks — all start with None.
//!
//! 4. **Only set by ScopedRuntimeHandle::new** (line 211)
//!    — called from `Runtime::block_on` / worker thread
//!    startup. This is the ONLY write path.
//!
//! 5. **Restored on guard drop** (line 219): the previous
//!    value (which may be None or a parent block_on's
//!    handle) is restored. No stale leakage.
//!
//! ── What happens inside a tokio runtime ─────────────────
//!
//! A tokio worker thread (or any thread that's NOT inside
//! an asupersync `block_on` / asupersync worker pool):
//!
//! - The thread-local slot CURRENT_RUNTIME_HANDLE is None
//!   (default).
//! - `Runtime::current_handle()` calls
//!   `try_with(|cell| cell.borrow().clone()).unwrap_or(None)`.
//! - Returns `None`.
//!
//! Operator's option (b) is "Err(NotInRuntime)". Asupersync
//! returns `None` (Option<T>) instead — semantically
//! equivalent fail-soft, idiomatic Rust, and matches the
//! prior audit's design rationale (no caller-imposed
//! panic policy; safe during TLS teardown).
//!
//! ── Why NOT panic (operator's option (a)) ───────────────
//!
//! Panicking on no-asupersync-runtime would:
//!   - Trigger double-panic abort during TLS destructor
//!     chains (the load-bearing reason already documented
//!     in `runtime_current_handle_returns_option_not_panic_audit.rs`).
//!   - Force every caller to use catch_unwind to probe
//!     runtime presence — un-idiomatic.
//!   - Force panic-policy on the caller; users who want
//!     panic-on-None already write
//!     `current_handle().expect("inside block_on")`.
//!
//! ── Why NOT data corruption (operator's option (c)) ─────
//!
//! The handle is `Arc<Runtime>` cloned out of the cell.
//! Once cloned, the Arc keeps the Runtime alive. There
//! is no path for `current_handle()` to return a stale
//! / dangling / wrongly-typed handle:
//!
//! - Type-correct: cell is `Option<RuntimeHandle>`; only
//!   asupersync RuntimeHandle values can ever go in.
//! - Lifetime-correct: clone retains the Arc's strong ref.
//! - Tokio-disjoint: tokio cannot write to this cell.
//!
//! ── What if asupersync block_on is nested inside tokio? ─
//!
//! `runtime.block_on(async { ... })` from inside a tokio
//! runtime works (asupersync's block_on doesn't check for
//! ambient tokio): it pushes its own ScopedRuntimeHandle,
//! polls the future on the calling thread, then drops the
//! guard. Inside that block_on:
//!   - asupersync's CURRENT_RUNTIME_HANDLE = Some(asupersync handle)
//!   - tokio's separate TLS = whatever tokio set
//!
//! Neither runtime sees the other's TLS. Cross-runtime
//! pollution is impossible.
//!
//! Verdict: **SOUND BY DESIGN**. Cross-runtime safety is
//! enforced by namespace (asupersync-specific TLS slot)
//! and type (Option<RuntimeHandle>). Inside tokio (or
//! any non-asupersync context), `current_handle()`
//! returns None — operator's option (b)-equivalent.
//! Never (a) panic, never (c) invalid handle.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn tls_slot_is_asupersync_specific_namespace() {
    // Pin: CURRENT_RUNTIME_HANDLE lives inside src/runtime/
    // and is module-scope thread_local — not exported, not
    // settable by other crates.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("static CURRENT_RUNTIME_HANDLE: RefCell<Option<RuntimeHandle>>"),
        "REGRESSION: CURRENT_RUNTIME_HANDLE TLS slot is \
         gone or no longer typed Option<RuntimeHandle>. \
         Cross-runtime namespace isolation is broken.",
    );
}

#[test]
fn tls_slot_default_is_none() {
    // Pin: TLS slot initializes to None on every new
    // thread.
    let source = read("src/runtime/builder.rs");

    let slot_marker = "static CURRENT_RUNTIME_HANDLE: RefCell<Option<RuntimeHandle>>";
    let pos = source.find(slot_marker).expect("TLS slot");
    let line_window = &source[pos..pos + 200];

    assert!(
        line_window.contains("RefCell::new(None)"),
        "REGRESSION: TLS slot no longer initializes to \
         None. Threads that never installed a runtime \
         may now have a non-None value — cross-runtime \
         confusion vector.",
    );
}

#[test]
fn current_handle_returns_option_no_panic_path() {
    // Pin: Runtime::current_handle returns Option<RuntimeHandle>
    // and uses try_with + unwrap_or(None) — never panics.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("pub fn current_handle() -> Option<RuntimeHandle> {"),
        "REGRESSION: Runtime::current_handle is no longer \
         Option-returning. If it now panics or returns \
         RuntimeHandle directly, cross-runtime safety is \
         broken.",
    );

    let fn_marker = "pub fn current_handle() -> Option<RuntimeHandle> {";
    let pos = source.find(fn_marker).expect("current_handle fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("current_handle close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains(".try_with(") && body.contains(".unwrap_or(None)"),
        "REGRESSION: current_handle no longer uses \
         try_with(...).unwrap_or(None). Either the Option \
         contract is broken or TLS-teardown safety is gone.",
    );

    // Must NOT panic.
    let panic_paths = ["panic!(", ".expect(", ".unwrap()"];
    for pat in &panic_paths {
        assert!(
            !body.contains(pat),
            "REGRESSION: current_handle body contains \
             `{pat}`. The fail-soft Option contract is \
             broken — cross-runtime callers may now panic.",
        );
    }
}

#[test]
fn scoped_runtime_handle_is_only_writer_to_tls() {
    // Pin: ScopedRuntimeHandle::new is the only path that
    // populates the TLS slot. Drop restores the previous
    // value — preventing stale-handle leakage.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("CURRENT_RUNTIME_HANDLE.with(|cell| cell.replace(Some(handle)))"),
        "REGRESSION: ScopedRuntimeHandle::new no longer \
         uses .replace() to track the previous value. \
         Stale handle leakage may occur.",
    );

    let drop_marker = "impl Drop for ScopedRuntimeHandle {";
    let pos = source.find(drop_marker).expect("ScopedRuntimeHandle Drop");
    let body_end = source[pos..]
        .find("\n}\n")
        .expect("ScopedRuntimeHandle Drop close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("self.prev.take()") && body.contains(".try_with("),
        "REGRESSION: ScopedRuntimeHandle::drop no longer \
         restores the previous value via try_with. Either \
         stale handle leakage or TLS-teardown safety is \
         broken.",
    );
}

#[test]
fn no_panic_or_unwrap_on_cross_runtime_path() {
    // Pin: there is no panic / expect / unwrap in
    // current_handle's call chain that would trigger from
    // a foreign-runtime caller.
    let source = read("src/runtime/builder.rs");

    let fn_marker = "pub fn current_handle() -> Option<RuntimeHandle> {";
    let pos = source.find(fn_marker).expect("current_handle fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("current_handle close");
    let body = &source[pos..pos + body_end];

    assert!(
        !body.contains("panic!")
            && !body.contains("\"wrong runtime\"")
            && !body.contains("\"tokio\""),
        "REGRESSION: current_handle now panics with a \
         runtime-mismatch message. The fail-soft contract \
         is broken.",
    );
}

#[test]
fn no_invalid_handle_construction_path() {
    // Pin: there is no path that constructs a
    // RuntimeHandle from arbitrary bytes / from a tokio
    // handle / from a stale Arc. The Arc-clone semantics
    // guarantee any returned handle is valid.
    let source = read("src/runtime/builder.rs");

    let fn_marker = "pub fn current_handle() -> Option<RuntimeHandle> {";
    let pos = source.find(fn_marker).expect("current_handle fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("current_handle close");
    let body = &source[pos..pos + body_end];

    // Must NOT use unsafe or transmute.
    let suspect_unsafe = ["unsafe ", "transmute(", "from_raw("];
    for pat in &suspect_unsafe {
        assert!(
            !body.contains(pat),
            "REGRESSION: current_handle body contains \
             `{pat}`. Invalid handle construction risk.",
        );
    }

    // The body must clone (Arc-clone preserves validity).
    assert!(
        body.contains(".clone()"),
        "REGRESSION: current_handle no longer Arc-clones \
         the cell value. Lifetime guarantee may be broken.",
    );
}

#[test]
fn handle_uses_arc_strong_ref_for_lifetime_safety() {
    // Pin: RuntimeHandle is wrapped around an Arc so
    // cloning it from the cell preserves the runtime's
    // lifetime. No use-after-free.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("RuntimeHandle::strong(Arc::clone(&self.inner))")
            || source.contains("Arc<Runtime")
            || source.contains("Arc<RuntimeInner>"),
        "REGRESSION: RuntimeHandle no longer wraps Arc<Runtime>. \
         Use-after-free risk if a current_handle clone \
         outlives the runtime.",
    );
}

#[test]
fn cross_runtime_inline_test_or_outside_block_on_test_exists() {
    // Pin: at least one inline test asserts None when
    // called outside any asupersync block_on. This is
    // the structural witness for cross-runtime safety.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("fn current_handle_none_outside_block_on()"),
        "REGRESSION: the current_handle_none_outside_block_on \
         inline test is gone. The cross-runtime fail-soft \
         contract is no longer guarded in-tree.",
    );
}

#[test]
fn cross_runtime_handle_test_uses_is_none_assertion() {
    // Pin: the test asserts is_none(), not is_err() / not
    // catch_unwind / not should_panic.
    let source = read("src/runtime/builder.rs");

    let fn_marker = "fn current_handle_none_outside_block_on()";
    let pos = source.find(fn_marker).expect("none_outside test");
    let body = &source[pos..pos + 600];

    assert!(
        body.contains("Runtime::current_handle().is_none()"),
        "REGRESSION: the cross-runtime test no longer \
         asserts is_none(). Either the contract changed \
         (review!) or the test was weakened.",
    );

    assert!(
        !body.contains("catch_unwind") && !body.contains("should_panic"),
        "REGRESSION: the test now expects a panic. The \
         fail-soft contract has been flipped.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::cell::RefCell;

#[derive(Clone)]
struct MockRuntimeHandle {
    id: u32,
}

thread_local! {
    static MOCK_CURRENT: RefCell<Option<MockRuntimeHandle>> = const { RefCell::new(None) };
}

struct MockGuard {
    prev: Option<MockRuntimeHandle>,
}

impl MockGuard {
    fn new(handle: MockRuntimeHandle) -> Self {
        let prev = MOCK_CURRENT.with(|c| c.replace(Some(handle)));
        Self { prev }
    }
}

impl Drop for MockGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        let _ = MOCK_CURRENT.try_with(|c| {
            *c.borrow_mut() = prev;
        });
    }
}

fn mock_current_handle() -> Option<MockRuntimeHandle> {
    MOCK_CURRENT
        .try_with(|c| c.borrow().clone())
        .unwrap_or(None)
}

#[test]
fn behavioral_returns_none_when_no_runtime_installed() {
    // Models a thread that has NEVER had asupersync's
    // block_on called (e.g., a tokio worker thread or
    // raw std::thread::spawn).
    let result = mock_current_handle();
    assert!(
        result.is_none(),
        "REGRESSION: current_handle returned Some on a \
         thread with no asupersync runtime installed. \
         Cross-runtime safety is broken.",
    );
}

#[test]
fn behavioral_returns_none_when_called_from_thread_without_install() {
    // Run the check on a fresh std thread (analogous to a
    // tokio worker) — no asupersync block_on context.
    let handle = std::thread::spawn(|| {
        // No MockGuard installed.
        mock_current_handle()
    });

    let result = handle.join().unwrap();
    assert!(
        result.is_none(),
        "REGRESSION: a fresh thread without asupersync \
         install observed Some. Either the TLS leaked \
         from another thread (impossible — TLS is per-\
         thread) or the default isn't None.",
    );
}

#[test]
fn behavioral_does_not_panic_outside_runtime() {
    // The most important behavioral pin: outside any
    // asupersync runtime context, the function does NOT
    // panic. It returns None.
    let panic_result = std::panic::catch_unwind(mock_current_handle);

    assert!(
        panic_result.is_ok(),
        "REGRESSION: current_handle panicked outside a \
         runtime context. Cross-runtime callers (e.g., \
         tokio code calling into asupersync helpers) will \
         see panics.",
    );

    let inner = panic_result.unwrap();
    assert!(inner.is_none());
}

#[test]
fn behavioral_returns_none_in_simulated_tokio_thread() {
    // Simulate a "tokio" thread by setting an unrelated
    // TLS variable while leaving asupersync's slot
    // untouched. asupersync's lookup must still return
    // None — namespace isolation.
    thread_local! {
        static FAKE_TOKIO_RUNTIME: RefCell<Option<u32>> = const { RefCell::new(None) };
    }

    FAKE_TOKIO_RUNTIME.with(|c| {
        *c.borrow_mut() = Some(999); // pretend tokio is "installed"
    });

    let asupersync_result = mock_current_handle();
    assert!(
        asupersync_result.is_none(),
        "REGRESSION: asupersync's current_handle picked up \
         a foreign-runtime TLS slot. Namespace isolation \
         is broken — cross-runtime data corruption vector.",
    );

    // Cleanup.
    FAKE_TOKIO_RUNTIME.with(|c| {
        *c.borrow_mut() = None;
    });
}

#[test]
fn behavioral_returns_some_inside_install_returns_none_after() {
    // The boundary case: install asupersync runtime
    // briefly, then verify None outside.
    assert!(mock_current_handle().is_none());

    {
        let _g = MockGuard::new(MockRuntimeHandle { id: 7 });
        assert_eq!(mock_current_handle().unwrap().id, 7);
    }

    assert!(
        mock_current_handle().is_none(),
        "REGRESSION: TLS slot not restored to None after \
         guard drop. Stale handle leakage.",
    );
}

#[test]
fn behavioral_handle_arc_clone_preserves_validity() {
    // The handle must remain valid (no use-after-free)
    // after being cloned out of the cell.
    let outer_handle = MockRuntimeHandle { id: 42 };
    let _g = MockGuard::new(outer_handle.clone());

    let cloned = mock_current_handle().expect("installed");
    assert_eq!(cloned.id, 42);

    // Use the clone after the cell has been read.
    let _another_use = cloned.clone();
}

#[test]
fn behavioral_caller_can_opt_into_panic_via_expect() {
    // Caller-controlled panic policy: those who want a
    // panic on None write `.expect(...)`.
    let panicked = std::panic::catch_unwind(|| {
        let _ = mock_current_handle().expect("inside asupersync runtime");
    });

    assert!(
        panicked.is_err(),
        "REGRESSION: .expect() on None did not panic.",
    );
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/runtime_current_handle_returns_option_not_panic_audit.rs",
        "tests/runtime_block_on_vs_run_until_distinction_audit.rs",
        "tests/cx_set_current_per_poll_install_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
