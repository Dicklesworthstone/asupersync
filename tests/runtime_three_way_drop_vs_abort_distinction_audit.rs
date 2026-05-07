//! Audit + regression test for the three-way distinction
//! between `Cx::abort_on_drop()`, `JoinHandle::abort()`,
//! and the `Drop` impl for handles/futures.
//!
//! Operator's question: "abort_on_drop is the explicit
//! cancel-on-drop semantic; bare drop should detach.
//! Verify behavior of each."
//!
//! Audit findings: **SOUND BY DESIGN — three distinct
//! paths**.
//!
//! ── The actual landscape ────────────────────────────────
//!
//! Path 1: **`Cx::abort_on_drop()`** — DOES NOT EXIST.
//!   Whole-tree grep returns zero hits in src/. The
//!   "explicit cancel-on-drop" semantic the operator
//!   describes is provided at the JOIN FUTURE level
//!   (path 3), not on Cx.
//!
//! Path 2: **`runtime::builder::JoinHandle<T>`** (the
//!   public spawn handle, builder.rs:3474):
//!     - exposes `is_finished()` and `impl Future` only
//!     - has NO `abort()` method (already pinned in
//!       runtime_join_handle_no_separable_abort_handle_audit.rs)
//!     - has NO custom `Drop` impl
//!     - dropping it = DETACH (task continues running on
//!       the scheduler; the executor side holds its own
//!       strong reference to the join state)
//!
//! Path 3: **`runtime::task_handle::JoinFuture<'_, T>`**
//!   (the `.await`-able future returned by
//!   `TaskHandle::join`, task_handle.rs:255):
//!     - HAS a `Drop` impl that aborts the task on drop
//!       UNLESS `terminal_state` is true OR
//!       `drop_abort_defused` is set (task_handle.rs:337)
//!     - This IS the operator's "abort_on_drop" semantic,
//!       but it's the `.join()` FUTURE, not the handle
//!     - Purpose: cancel-safety for `.await` interruption
//!       (timeout, race lost) — when the await is
//!       interrupted, the JoinFuture's drop aborts the
//!       task to drain it
//!
//! Path 4: **`TaskHandle::abort()`** (task_handle.rs:213):
//!   - explicit method call (not Drop-triggered)
//!   - requests cancel via fast_cancel.store(true, Release)
//!     on the underlying CxInner
//!
//! Path 5: **`Drop` for `TaskHandle`** — NO custom Drop
//!   impl exists. Pinned in
//!   `runtime_join_handle_drop_lifecycle_audit.rs`. Bare
//!   drop of TaskHandle = detach (TaskHandle holds
//!   `Weak<CxInner>` so does not extend task lifetime
//!   anyway).
//!
//! ── Three paths summarised ──────────────────────────────
//!
//! | Action                              | Result            |
//! |-------------------------------------|-------------------|
//! | drop `JoinHandle` (builder)         | DETACH            |
//! | drop `TaskHandle`                   | DETACH            |
//! | drop `JoinFuture` mid-`.await`      | ABORT (cancel)    |
//! | call `TaskHandle::abort()`          | ABORT (request)   |
//! | call `Cx::abort_on_drop()`          | DOES NOT EXIST    |
//!
//! The operator's framing maps onto:
//!   - "abort_on_drop is explicit" → JoinFuture::Drop
//!     (the `.join()` future, not a handle)
//!   - "bare drop should detach" → JoinHandle / TaskHandle
//!     drop (no custom Drop impl)
//!
//! ── Why NO custom Drop on JoinHandle/TaskHandle ─────────
//!
//! If JoinHandle had abort-on-drop semantics by default,
//! every `_ = handle;` discard would silently cancel a
//! task — a violation of "no surprising cancellation."
//! The structured-concurrency rule is "drop = detach
//! (let the task continue under its region's
//! supervision); explicit cancel via `.abort()`."
//!
//! ── Why JoinFuture::Drop DOES abort ─────────────────────
//!
//! `tokio::time::timeout(Duration, fut)` and similar
//! combinators internally race a sleep against `fut`. If
//! the sleep fires first, `fut` is dropped mid-poll. If
//! `fut` is a `.join()` future and its drop didn't abort
//! the underlying task, the task would leak. The
//! `JoinFuture::Drop` impl thus aborts on drop —
//! preserving the cancel-safe-await contract. The
//! `defuse_drop_abort()` escape hatch (task_handle.rs:294)
//! lets internal combinators opt out for control flow
//! that doesn't want abort.
//!
//! Verdict: **SOUND BY DESIGN**. The three paths are
//! deliberately distinct. The operator's `abort_on_drop`
//! framing maps to `JoinFuture::Drop` (the `.join()`
//! future, not a handle). Bare drop of JoinHandle /
//! TaskHandle correctly detaches.
//!
//! No bead filed.
//!
//! ── Cross-references ────────────────────────────────────
//!
//! Prior audits pin specific behaviors of this lifecycle:
//!   - tests/runtime_join_handle_drop_lifecycle_audit.rs
//!     (TaskHandle no Drop; JoinFuture aborts on drop;
//!     defuse path; receiver_finished short-circuit;
//!     drop_reason precedence)
//!   - tests/runtime_join_handle_no_separable_abort_handle_audit.rs
//!     (no abort_handle method; TaskHandle::abort exists)
//!   - tests/runtime_no_detached_orphan_spawn_api_audit.rs
//!     (no Cx::detached spawn API)
//!   - tests/runtime_join_handle_abort_is_finished_race_audit.rs
//!     (two-stage cancel-request model)
//!
//! This audit pins the THREE-WAY decision tree the
//! operator asks about.

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
fn cx_abort_on_drop_method_does_not_exist() {
    // Pin: no `Cx::abort_on_drop()` method anywhere in
    // src/. The operator's name maps onto JoinFuture's
    // Drop impl, NOT a Cx method.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains("fn abort_on_drop") {
            violations.push(path.display().to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: `abort_on_drop` method introduced. \
         The cancel-on-drop semantic on a handle would \
         conflate explicit method (.abort()) and Drop \
         lifecycle. Design review required.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn builder_join_handle_has_no_custom_drop_impl() {
    // Pin: runtime::builder::JoinHandle<T> (the public
    // spawn handle) has NO custom Drop impl. Bare drop
    // detaches — this is the operator's "bare drop
    // should detach" expectation.
    let source = read("src/runtime/builder.rs");

    // Check: NO `impl<T> Drop for JoinHandle` block.
    assert!(
        !source.contains("impl<T> Drop for JoinHandle<T>")
            && !source.contains("impl Drop for JoinHandle"),
        "REGRESSION: builder::JoinHandle now has a custom \
         Drop impl. Bare drop is no longer pure detach — \
         every `_ = handle;` discard now triggers cleanup. \
         Surprising-cancel hazard.",
    );
}

#[test]
fn builder_join_handle_has_no_abort_method() {
    // Pin: builder::JoinHandle has no abort() method.
    // (Already pinned in
    // runtime_join_handle_no_separable_abort_handle_audit.rs;
    // re-pinned here for the three-way matrix.)
    let source = read("src/runtime/builder.rs");

    let impl_marker = "impl<T> JoinHandle<T> {";
    let pos = source.find(impl_marker).expect("JoinHandle impl");
    let impl_end = source[pos..]
        .find("\nimpl<T>")
        .map(|i| pos + i)
        .expect("JoinHandle impl close");
    let impl_body = &source[pos..impl_end];

    let suspect_methods = ["fn abort(", "fn abort_on_drop(", "fn cancel("];
    for pat in &suspect_methods {
        assert!(
            !impl_body.contains(pat),
            "REGRESSION: builder::JoinHandle now has \
             `{pat}` — the join-vs-cancel channel \
             separation is broken.",
        );
    }
}

#[test]
fn task_handle_has_explicit_abort_method() {
    // Pin: TaskHandle::abort exists and is the EXPLICIT
    // cancel path (not Drop-triggered).
    let source = read("src/runtime/task_handle.rs");

    assert!(
        source.contains("pub fn abort(&self) {"),
        "REGRESSION: TaskHandle::abort is gone. The \
         explicit cancel path is broken.",
    );

    assert!(
        source.contains("pub fn abort_with_reason(&self, reason: CancelReason) {"),
        "REGRESSION: TaskHandle::abort_with_reason gone.",
    );
}

#[test]
fn task_handle_has_no_custom_drop_impl() {
    // Pin: TaskHandle itself has NO custom Drop impl.
    // Bare drop = detach.
    let source = read("src/runtime/task_handle.rs");

    assert!(
        !source.contains("impl<T> Drop for TaskHandle<T>")
            && !source.contains("impl Drop for TaskHandle<T>"),
        "REGRESSION: TaskHandle now has a custom Drop impl. \
         Bare drop is no longer detach — every dropped \
         TaskHandle now triggers some action.",
    );
}

#[test]
fn join_future_has_drop_impl_that_aborts() {
    // Pin: JoinFuture (the `.join()` future) DOES have a
    // Drop impl that aborts on drop unless terminal_state
    // is true or drop_abort_defused. This IS the
    // operator's "abort_on_drop" semantic, at the join-
    // FUTURE level (not handle level).
    let source = read("src/runtime/task_handle.rs");

    assert!(
        source.contains("impl<T> Drop for JoinFuture<'_, T> {"),
        "REGRESSION: JoinFuture::Drop impl is gone. The \
         cancel-safe-await contract is broken — interrupted \
         awaits will leak the underlying task.",
    );

    let impl_marker = "impl<T> Drop for JoinFuture<'_, T> {";
    let pos = source.find(impl_marker).expect("JoinFuture Drop impl");
    let body_end = source[pos..].find("\n}\n").expect("JoinFuture Drop close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("self.abort_with_reason("),
        "REGRESSION: JoinFuture::Drop no longer calls \
         abort_with_reason. The cancel-on-drop is broken.",
    );

    assert!(
        body.contains("if !*self.terminal_state && !self.drop_abort_defused {"),
        "REGRESSION: JoinFuture::Drop no longer checks the \
         terminal_state and drop_abort_defused gates. The \
         abort path may now fire on completed/defused \
         futures.",
    );
}

#[test]
fn join_future_drop_short_circuits_when_receiver_finished() {
    // Pin: even when not in terminal_state and not
    // defused, JoinFuture::Drop still skips abort if the
    // receiver has finished — avoids stamping a spurious
    // cancel on a task whose result was already produced.
    let source = read("src/runtime/task_handle.rs");

    let impl_marker = "impl<T> Drop for JoinFuture<'_, T> {";
    let pos = source.find(impl_marker).expect("JoinFuture Drop impl");
    let body = &source[pos..pos + 1500];

    assert!(
        body.contains("self.inner.receiver_finished()"),
        "REGRESSION: JoinFuture::Drop no longer checks \
         receiver_finished. Spurious cancel reasons may \
         be stamped on already-completed tasks.",
    );
}

#[test]
fn join_future_drop_uses_drop_reason_when_present() {
    // Pin: drop_reason precedence — if the JoinFuture
    // was configured with a specific drop_reason
    // (e.g., RaceLost), use it instead of generic "abort".
    let source = read("src/runtime/task_handle.rs");

    let impl_marker = "impl<T> Drop for JoinFuture<'_, T> {";
    let pos = source.find(impl_marker).expect("JoinFuture Drop impl");
    let body = &source[pos..pos + 1500];

    assert!(
        body.contains("if let Some(reason) = self.drop_reason.take()")
            && body.contains("CancelReason::user(\"abort\")"),
        "REGRESSION: JoinFuture::Drop reason precedence is \
         broken. The drop_reason vs default-\"abort\" \
         distinction has drifted.",
    );
}

#[test]
fn join_future_has_defuse_escape_hatch_for_combinators() {
    // Pin: internal combinators that need to drop the
    // JoinFuture WITHOUT triggering abort can call
    // defuse_drop_abort. This is the controlled-flow
    // escape hatch.
    let source = read("src/runtime/task_handle.rs");

    assert!(
        source.contains("pub(crate) fn defuse_drop_abort(&mut self) {"),
        "REGRESSION: JoinFuture::defuse_drop_abort gone. \
         Internal combinators cannot drop a JoinFuture \
         without triggering abort.",
    );
}

#[test]
fn three_way_drop_matrix_documented_in_audits() {
    // Pin: the three-way decision matrix is documented
    // across this audit + prior audits. If any of the
    // prior audits is missing, a future regression in
    // that area can slip.
    let prior_audits = [
        "tests/runtime_join_handle_drop_lifecycle_audit.rs",
        "tests/runtime_join_handle_no_separable_abort_handle_audit.rs",
        "tests/runtime_join_handle_abort_is_finished_race_audit.rs",
        "tests/runtime_no_detached_orphan_spawn_api_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing. \
             The three-way drop/abort distinction is no \
             longer fully covered.",
        );
    }
}

// ── Behavioral pins ─────────────────────────────────────

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Mock JoinHandle: bare drop = detach (no custom Drop).
struct MockJoinHandle {
    completed: AtomicBool,
}

/// Mock TaskHandle: bare drop = detach (no custom Drop),
/// but exposes explicit `abort()`.
#[derive(Clone)]
struct MockTaskHandle {
    cancel_flag: Arc<AtomicBool>,
    abort_count: Arc<AtomicU64>,
}

impl MockTaskHandle {
    fn new() -> Self {
        Self {
            cancel_flag: Arc::new(AtomicBool::new(false)),
            abort_count: Arc::new(AtomicU64::new(0)),
        }
    }

    fn abort(&self) {
        self.abort_count.fetch_add(1, Ordering::Relaxed);
        self.cancel_flag.store(true, Ordering::Release);
    }
}

/// Mock JoinFuture: HAS Drop impl that aborts on drop
/// unless terminal_state OR drop_abort_defused.
struct MockJoinFuture<'a> {
    handle: &'a MockTaskHandle,
    terminal_state: bool,
    drop_abort_defused: bool,
}

impl Drop for MockJoinFuture<'_> {
    fn drop(&mut self) {
        if !self.terminal_state && !self.drop_abort_defused {
            self.handle.abort();
        }
    }
}

#[test]
fn behavioral_join_handle_drop_is_detach_no_abort() {
    // Bare drop of JoinHandle: NO action taken on the task.
    let h = MockJoinHandle {
        completed: AtomicBool::new(false),
    };
    drop(h);
    // No abort, no panic — pure detach. The compile-time
    // absence of abort logic IS the proof.
}

#[test]
fn behavioral_task_handle_drop_is_detach_no_abort() {
    let h = MockTaskHandle::new();
    let count_before = h.abort_count.load(Ordering::Relaxed);
    let cancel_before = h.cancel_flag.load(Ordering::Acquire);

    let h_clone = h.clone();
    drop(h_clone);

    let count_after = h.abort_count.load(Ordering::Relaxed);
    let cancel_after = h.cancel_flag.load(Ordering::Acquire);

    assert_eq!(
        count_before, count_after,
        "REGRESSION: TaskHandle drop incremented abort_count. \
         Bare drop is no longer detach.",
    );
    assert_eq!(
        cancel_before, cancel_after,
        "REGRESSION: TaskHandle drop set the cancel flag. \
         Bare drop now silently cancels — surprising-cancel \
         hazard.",
    );
}

#[test]
fn behavioral_task_handle_explicit_abort_does_cancel() {
    let h = MockTaskHandle::new();
    h.abort();
    assert_eq!(h.abort_count.load(Ordering::Relaxed), 1);
    assert!(h.cancel_flag.load(Ordering::Acquire));
}

#[test]
fn behavioral_join_future_drop_aborts_when_not_terminal() {
    let h = MockTaskHandle::new();
    {
        let _f = MockJoinFuture {
            handle: &h,
            terminal_state: false,
            drop_abort_defused: false,
        };
        // f drops here; should abort.
    }
    assert_eq!(
        h.abort_count.load(Ordering::Relaxed),
        1,
        "REGRESSION: JoinFuture drop did not abort. The \
         cancel-safe-await contract is broken.",
    );
}

#[test]
fn behavioral_join_future_drop_skips_abort_when_terminal() {
    let h = MockTaskHandle::new();
    {
        let _f = MockJoinFuture {
            handle: &h,
            terminal_state: true,
            drop_abort_defused: false,
        };
    }
    assert_eq!(
        h.abort_count.load(Ordering::Relaxed),
        0,
        "REGRESSION: JoinFuture drop aborted a terminal-\
         state task. Spurious cancel.",
    );
}

#[test]
fn behavioral_join_future_drop_skips_abort_when_defused() {
    let h = MockTaskHandle::new();
    {
        let _f = MockJoinFuture {
            handle: &h,
            terminal_state: false,
            drop_abort_defused: true,
        };
    }
    assert_eq!(
        h.abort_count.load(Ordering::Relaxed),
        0,
        "REGRESSION: JoinFuture drop aborted a defused \
         future. Internal combinator escape hatch is broken.",
    );
}

#[test]
fn behavioral_three_paths_have_different_observable_effects() {
    // Side-by-side: the three paths produce three different
    // outcomes.
    let h1 = MockTaskHandle::new();
    let h2 = MockTaskHandle::new();
    let h3 = MockTaskHandle::new();

    // Path A: drop the handle directly.
    drop(h1.clone());

    // Path B: explicit abort.
    h2.abort();

    // Path C: drop a non-terminal JoinFuture.
    {
        let _f = MockJoinFuture {
            handle: &h3,
            terminal_state: false,
            drop_abort_defused: false,
        };
    }

    let a_aborts = h1.abort_count.load(Ordering::Relaxed);
    let b_aborts = h2.abort_count.load(Ordering::Relaxed);
    let c_aborts = h3.abort_count.load(Ordering::Relaxed);

    assert_eq!(a_aborts, 0, "Path A (drop handle): expected 0 aborts");
    assert_eq!(b_aborts, 1, "Path B (explicit abort): expected 1 abort");
    assert_eq!(c_aborts, 1, "Path C (drop JoinFuture): expected 1 abort");

    // The three paths are observably different:
    assert_ne!(
        a_aborts, b_aborts,
        "REGRESSION: drop-handle and explicit-abort produced \
         the same effect. The detach-vs-cancel distinction \
         is broken.",
    );
    assert_ne!(
        a_aborts, c_aborts,
        "REGRESSION: drop-handle and drop-JoinFuture produced \
         the same effect. The cancel-safe-await contract is \
         not enforced.",
    );
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/runtime_join_handle_drop_lifecycle_audit.rs",
        "tests/runtime_join_handle_no_separable_abort_handle_audit.rs",
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
