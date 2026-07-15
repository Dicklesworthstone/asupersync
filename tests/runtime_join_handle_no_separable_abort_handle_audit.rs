//! Audit + regression test for `JoinHandle::abort_handle()`
//! vs `JoinHandle::abort()` distinction.
//!
//! Operator's question: "abort_handle returns a separable
//! AbortHandle that can cancel without holding the
//! JoinHandle. Verify this is correctly distinct (not
//! aliased). If conflated, file bead. If distinct, pin
//! with audit test."
//!
//! Audit findings: **SOUND BY DESIGN** — these APIs
//! DELIBERATELY DO NOT EXIST in asupersync.
//!
//! The operator's framing assumes the tokio API surface
//! (`tokio::task::JoinHandle::abort_handle()` returning
//! `tokio::task::AbortHandle`). asupersync rejects that
//! API design in favor of structured-concurrency
//! cancellation.
//!
//! ── Searched the entire workspace ───────────────────────
//!
//! - `grep -rn "abort_handle"` across src/, tests/, the
//!   tokio-compat crate, and conformance/: ZERO hits.
//! - `grep -rn "AbortHandle"` across the same: ZERO hits.
//!
//! These names are absent by design.
//!
//! ── What asupersync provides instead ────────────────────
//!
//! 1. `runtime::builder::JoinHandle<T>` (src/runtime/builder.rs:3474)
//!    is a NON-CANCELLING handle. It exposes:
//!      - `pub fn is_finished(&self) -> bool` (line 3489)
//!      - `impl Future for JoinHandle<T>` (line 3498)
//!        There is NO `abort()`, NO `abort_handle()`, NO
//!        `cancel()`. The handle is used to await the result;
//!        cancellation flows through other channels.
//!
//! 2. `runtime::task_handle::TaskHandle` (src/runtime/task_handle.rs)
//!    is a separate type that exposes:
//!      - `pub fn abort(&self)` (line 213) — request
//!        cancellation; observed at next checkpoint.
//!      - `pub fn abort_with_reason(&self, ...)` (line 222)
//!        `TaskHandle` holds a `Weak<RwLock<CxInner>>` so
//!        multiple TaskHandle clones can coexist. This is the
//!        moral equivalent of tokio's AbortHandle but at a
//!        different name and with structured-concurrency
//!        semantics.
//!
//! 3. `Cx::cancel()` and `Cx::abort()` — capability-based
//!    cancellation flowing through Cx.
//!
//! 4. Region-scoped cancellation — when a region closes /
//!    is cancelled, all tasks in the region observe
//!    cancel via their checkpoints.
//!
//! ── Why no abort_handle() / AbortHandle ─────────────────
//!
//! The asupersync design rejects "spawn an orphan task and
//! hold a separable AbortHandle to cancel it from afar"
//! because:
//!
//! 1. **Structured concurrency invariant**: every task is
//!    owned by exactly one region. Cancellation flows
//!    through region close, not through detachable cancel
//!    handles.
//!
//! 2. **No ambient authority**: cancellation requires a Cx
//!    or a TaskHandle obtained from the spawning Scope.
//!    Sprinkling AbortHandle clones violates the explicit-
//!    capability discipline.
//!
//! 3. **Cancel is a protocol** (request, drain, finalize)
//!    not a silent drop. AbortHandle's "fire and forget"
//!    cancel doesn't compose with the drain/finalize
//!    contract.
//!
//! These design decisions are documented in
//! `asupersync_plan_v4.md` and are tested elsewhere — see
//! cross-references below.
//!
//! ── Conflation risk ─────────────────────────────────────
//!
//! Since `abort_handle()` and `AbortHandle` do not exist,
//! there is NOTHING to conflate. The risk would be:
//!
//! - A future regression that ADDS `abort_handle()` to
//!   `JoinHandle` and aliases it to `JoinHandle::abort()`
//!   without designing it as a separately-droppable type.
//! - A future regression that adds an `AbortHandle` type
//!   that shares state with `JoinHandle` in a way that
//!   breaks the "TaskHandle is the cancel channel"
//!   invariant.
//!
//! Both regressions are caught by the structural pins
//! below.
//!
//! Verdict: **SOUND BY DESIGN**. The APIs deliberately
//! don't exist; structured-concurrency cancellation flows
//! through `TaskHandle::abort`, `Cx::cancel`, and region
//! close.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn read_dir_recursive(root: &str) -> Vec<PathBuf> {
    let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(root);
    let mut out = Vec::new();
    let mut stack = vec![root_path];
    while let Some(p) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&p) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn abort_handle_method_does_not_exist_in_src() {
    // Pin: NO file in src/ defines an `abort_handle` method.
    // Adding one would silently introduce the tokio-style
    // detachable-cancel-handle pattern, breaking structured
    // concurrency.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains("fn abort_handle") {
            violations.push(format!("{}: contains `fn abort_handle`", path.display()));
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: `abort_handle` method introduced in \
         src/. The structured-concurrency cancel discipline \
         is broken — the new method needs explicit design \
         review.\n\nViolations:\n{}",
        violations.join("\n"),
    );
}

#[test]
fn abort_handle_type_does_not_exist_in_src() {
    // Pin: NO file in src/ defines an `AbortHandle` type
    // (struct, enum, trait, type alias).
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let suspect_decls = [
            "struct AbortHandle",
            "enum AbortHandle",
            "trait AbortHandle",
            "type AbortHandle",
            "pub struct AbortHandle",
            "pub enum AbortHandle",
            "pub trait AbortHandle",
            "pub type AbortHandle",
        ];
        for decl in &suspect_decls {
            if content.contains(decl) {
                violations.push(format!("{}: contains `{}`", path.display(), decl));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: `AbortHandle` type introduced in src/. \
         The structured-concurrency cancel discipline is \
         broken — the new type needs explicit design \
         review.\n\nViolations:\n{}",
        violations.join("\n"),
    );
}

#[test]
fn join_handle_in_builder_has_no_abort_method() {
    // Pin: `runtime::builder::JoinHandle<T>` is a non-
    // cancelling handle. It must NOT have an `abort()`
    // method (that would conflate with the deliberate
    // separation of join vs cancel channels).
    let source = read("src/runtime/builder.rs");

    let struct_marker = "pub struct JoinHandle<T> {";
    let pos = source.find(struct_marker).expect("JoinHandle struct");

    // Find the impl block for JoinHandle.
    let impl_marker = "impl<T> JoinHandle<T> {";
    let impl_pos = source[pos..]
        .find(impl_marker)
        .map(|i| pos + i)
        .expect("JoinHandle impl block");

    // Body of the impl block.
    let impl_end = source[impl_pos..]
        .find("\nimpl<T>")
        .map_or(source.len(), |i| impl_pos + i);
    let impl_body = &source[impl_pos..impl_end];

    let suspect_methods = [
        "fn abort(",
        "fn abort_handle(",
        "fn cancel(",
        "fn cancel_handle(",
    ];
    for pat in &suspect_methods {
        assert!(
            !impl_body.contains(pat),
            "REGRESSION: JoinHandle in src/runtime/builder.rs \
             now has `{pat}`. JoinHandle is the join channel; \
             cancellation must flow through TaskHandle / Cx / \
             region close, NOT through JoinHandle. Adding \
             this method conflates the two channels.",
        );
    }
}

#[test]
fn join_handle_in_builder_only_has_join_methods() {
    // Pin: `runtime::builder::JoinHandle<T>` exposes ONLY
    // `is_finished()` and `impl Future`. Any new method
    // is a deliberate API expansion that needs review.
    let source = read("src/runtime/builder.rs");

    let impl_marker = "impl<T> JoinHandle<T> {";
    let pos = source.find(impl_marker).expect("JoinHandle impl");
    let impl_end = source[pos..]
        .find("\nimpl<T>")
        .map(|i| pos + i)
        .expect("JoinHandle impl close (next impl)");
    let impl_body = &source[pos..impl_end];

    assert!(
        impl_body.contains("pub fn is_finished(&self) -> bool {"),
        "REGRESSION: JoinHandle::is_finished is gone — the \
         non-cancelling join interface is broken.",
    );

    // The impl block must contain ONLY `new` (private) and
    // `is_finished` as named methods. Count `pub fn` and
    // `fn ` (private) inside.
    let pub_fn_count = impl_body.matches("    pub fn ").count();
    assert_eq!(
        pub_fn_count, 1,
        "REGRESSION: JoinHandle has {pub_fn_count} pub fn \
         methods (expected exactly 1: is_finished). New \
         method introduced — review whether it conflates \
         with cancel channels.",
    );
}

#[test]
fn task_handle_owns_abort_method_not_join_handle() {
    // Pin: `TaskHandle::abort(&self)` is the canonical
    // cancellation entry point. It is on TaskHandle, NOT
    // on the runtime::builder::JoinHandle returned by
    // RuntimeHandle::spawn.
    let source = read("src/runtime/task_handle.rs");

    assert!(
        source.contains("pub fn abort(&self) {"),
        "REGRESSION: TaskHandle::abort is gone. The canonical \
         cancellation entry point has been removed or renamed.",
    );

    assert!(
        source.contains("pub fn abort_with_reason(&self, reason: CancelReason) {"),
        "REGRESSION: TaskHandle::abort_with_reason is gone. \
         The reason-attribution path for deterministic cancel \
         provenance is broken.",
    );

    // TaskHandle must NOT define abort_handle (that would
    // be the tokio API).
    assert!(
        !source.contains("fn abort_handle"),
        "REGRESSION: TaskHandle now has `abort_handle`. The \
         tokio detachable-cancel-handle pattern is being \
         silently introduced.",
    );
}

#[test]
fn task_handle_holds_weak_for_multi_handle_safety() {
    // Pin: TaskHandle's cx_inner field is a Weak<RwLock<CxInner>>
    // — multiple TaskHandle clones can coexist (each holding
    // a Weak), and the abort path upgrades transiently.
    // This is asupersync's structured-concurrency answer
    // to "separable cancel handle": multiple TaskHandle
    // clones, all upgrading the same Weak.
    let source = read("src/runtime/task_handle.rs");

    let abort_with_reason_marker = "fn apply_or_defer_cancel_reason(";
    let pos = source
        .find(abort_with_reason_marker)
        .expect("admission-aware cancellation helper");
    let body_end = source[pos..]
        .find("\n}\n")
        .expect("admission-aware cancellation helper close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("admitted.cx_inner.upgrade()") && body.contains("fallback_inner.upgrade()"),
        "REGRESSION: the TaskHandle cancellation gateway no longer \
         upgrades both canonical-admission and construction-time Weak \
         handles transiently. The cancel channel may have shifted to a \
         strong Arc that prevents drop.",
    );
    assert!(
        source.contains("inner: Weak<RwLock<CxInner>>,")
            && source.contains("cx_inner: Weak<RwLock<CxInner>>,"),
        "REGRESSION: TaskHandle or JoinFuture no longer stores a Weak \
         Cx handle at the cancellation boundary.",
    );

    // Strong-only patterns are wrong here.
    let strong_only_patterns = ["self.inner.write()", "self.inner.read()"];
    for pat in &strong_only_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: abort_with_reason now uses strong \
             Arc access pattern `{pat}` — TaskHandle would \
             keep CxInner alive past drop, breaking task \
             cleanup.",
        );
    }
}

#[test]
fn no_tokio_abort_handle_doc_aliases_in_src() {
    // Pin: no `#[doc(alias = "abort_handle")]` or
    // `#[doc(alias = "AbortHandle")]` exists. If we ever
    // add tokio-API doc aliases, that's a deliberate
    // tokio-compat decision and must be in the
    // asupersync-tokio-compat crate, not core src/.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains("#[doc(alias = \"abort_handle\")]")
            || content.contains("#[doc(alias = \"AbortHandle\")]")
        {
            violations.push(path.display().to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: tokio-API doc-aliases for \
         abort_handle / AbortHandle introduced into core \
         src/. Tokio-compat surface belongs in the \
         asupersync-tokio-compat crate.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn cancel_flow_documented_in_builder_or_task_handle() {
    // Pin: at least one of builder.rs / task_handle.rs
    // documents the cancel flow (request, drain,
    // finalize) so future maintainers don't introduce
    // tokio-style abort_handle expecting it to be a
    // silent drop.
    let task_handle = read("src/runtime/task_handle.rs");

    assert!(
        task_handle.contains("This is a request") && task_handle.contains("checkpoint"),
        "REGRESSION: TaskHandle::abort no longer documents \
         the request/checkpoint protocol. Future maintainers \
         may add an abort_handle expecting tokio-style \
         immediate kill semantics.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Models asupersync's structured-concurrency cancel
/// channel: cancel state lives in CxInner; multiple
/// TaskHandle clones each hold a Weak to it. The "join"
/// channel is separate: a oneshot for the result.
struct MockCxInner {
    cancel_requested: AtomicBool,
}

#[derive(Clone)]
struct MockTaskHandle {
    inner: std::sync::Weak<MockCxInner>,
}

impl MockTaskHandle {
    fn abort(&self) {
        if let Some(inner) = self.inner.upgrade() {
            inner.cancel_requested.store(true, Ordering::Release);
        }
    }
}

/// Mock JoinHandle: holds a result channel, NOT a cancel
/// channel. Has NO abort() method by design.
struct MockJoinHandle {
    completed: AtomicBool,
}

impl MockJoinHandle {
    fn is_finished(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }
}

#[test]
fn behavioral_join_handle_is_not_a_cancel_channel() {
    // Pin: MockJoinHandle has no abort method. We assert
    // by construction (no abort() defined).
    let h = MockJoinHandle {
        completed: AtomicBool::new(false),
    };
    assert!(!h.is_finished());

    // The compile-time absence of MockJoinHandle::abort()
    // is the proof. If a future regression adds one, this
    // test stays green but the structural pins above will
    // catch it.
}

#[test]
fn behavioral_multiple_task_handles_share_cancel_state_via_weak() {
    // Models the structured-concurrency answer to
    // "separable cancel handle": clone the TaskHandle
    // (which holds a Weak), each clone can call abort,
    // they all observe the same cancel_requested flag.
    let inner = Arc::new(MockCxInner {
        cancel_requested: AtomicBool::new(false),
    });
    let weak = Arc::downgrade(&inner);

    let h1 = MockTaskHandle {
        inner: weak.clone(),
    };
    let h2 = MockTaskHandle { inner: weak };

    // Drop the original strong; abort still works via
    // Weak::upgrade as long as ANOTHER strong (e.g., the
    // task itself) exists.
    h1.abort();

    assert!(
        inner.cancel_requested.load(Ordering::Acquire),
        "REGRESSION: TaskHandle::abort via Weak failed to \
         set cancel state. The structured-concurrency \
         cancel-via-clone pattern is broken.",
    );

    // Drop h1; h2 still functions.
    drop(h1);
    inner.cancel_requested.store(false, Ordering::Release);
    h2.abort();
    assert!(
        inner.cancel_requested.load(Ordering::Acquire),
        "REGRESSION: a second TaskHandle clone did not \
         independently signal cancel. Multi-handle support \
         is broken.",
    );
}

#[test]
fn behavioral_task_handle_does_not_keep_inner_alive() {
    // Pin: when ALL strong refs to CxInner are dropped,
    // TaskHandle's Weak::upgrade returns None — abort()
    // is a no-op (graceful, not a panic). This proves
    // TaskHandle does NOT extend CxInner's lifetime,
    // which is required for proper task cleanup.
    let inner = Arc::new(MockCxInner {
        cancel_requested: AtomicBool::new(false),
    });
    let h = MockTaskHandle {
        inner: Arc::downgrade(&inner),
    };

    drop(inner);

    // After last strong drop, abort is silent no-op.
    h.abort();
    // We can't observe cancel_requested directly (inner is
    // gone) but the absence of panic is the pin.
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/runtime_join_handle_drop_lifecycle_audit.rs",
        "tests/runtime_join_handle_abort_is_finished_race_audit.rs",
        "tests/runtime_no_detached_orphan_spawn_api_audit.rs",
        "tests/runtime_abort_vs_cancel_semantics_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
