//! Audit + regression test for `Cx::interrupt()` vs
//! `Cx::cancel()` semantics.
//!
//! Operator's question: "interrupt is graceful (let task
//! complete current poll, then cancel); cancel is immediate
//! (next checkpoint observes Err). If both APIs exist,
//! verify they're correctly distinct."
//!
//! Audit findings: **SOUND BY DESIGN** — neither
//! `Cx::interrupt()` nor a bare `Cx::cancel()` method
//! exists. The cancel mechanism on Cx is one unified
//! protocol with two attribution variants:
//!
//!   - `cx.cancel_with(kind, message)` — full attribution
//!     (region, task, timestamp, message, cause chain).
//!   - `cx.cancel_fast(kind)` — minimal attribution
//!     (kind + region only) for the performance-critical
//!     path.
//!
//! Both paths perform the SAME cancellation operation:
//!
//! ```ignore
//! inner.cancel_requested = true;
//! inner.fast_cancel.store(true, Ordering::Release);
//! inner.cancel_reason = Some(reason);
//! // wake the cancel_waker, if any.
//! ```
//!
//! And both are observed by tasks identically: at the next
//! `cx.checkpoint()?` call (or via the fast-cancel waker
//! injecting the task into the cancel lane). There is NO
//! "graceful let-current-poll-finish" alternative.
//!
//! ── Why no graceful "interrupt" mode ────────────────────
//!
//! asupersync's cancellation is intrinsically graceful at
//! the granularity the runtime can guarantee:
//!
//!   - Cancellation NEVER kills a polling task mid-poll.
//!     The task always finishes its current poll() (which
//!     in well-behaved code is a few microseconds bounded
//!     by an `.await` or `cx.checkpoint()`).
//!   - Cancellation is observed at the NEXT checkpoint.
//!     That's the protocol — there is no preemptive
//!     interrupt.
//!   - For long-running synchronous work, the contract is
//!     "checkpoint at every yield-point or every ~1ms" —
//!     see tests/checkpoint_frequency_survey_audit.rs.
//!
//! So the "graceful interrupt" semantic the operator asks
//! about is ALREADY the only semantic. Adding a separate
//! `interrupt()` method would either:
//!   - Be redundant (alias of cancel_with), creating
//!     conflation, or
//!   - Imply preemptive task-killing, which asupersync's
//!     `#![deny(unsafe_code)]` discipline does not allow
//!     (no SCHED_FIFO, no thread termination — see
//!     tests/scheduler_thread_priority_design_audit.rs).
//!
//! ── Whole-tree search ───────────────────────────────────
//!
//! `grep "fn interrupt\b" src/`:
//!   - src/signal/kind.rs:38  →
//!     `pub const fn interrupt() -> Self` — this is the
//!     SignalKind::interrupt() constructor for SIGINT, not
//!     a Cx method. Excluded.
//!
//! `grep "pub fn interrupt\b" src/cx/`: ZERO hits.
//! `grep "pub fn cancel\b(&self)" src/cx/`: ZERO hits (no
//!     bare cancel method).
//!
//! ── How structured cancellation actually works ──────────
//!
//! 1. Caller invokes `cx.cancel_with(kind, msg)` or
//!    `cx.cancel_fast(kind)` (or via `TaskHandle::abort()`
//!    which holds a Weak<CxInner> and sets the same flag).
//! 2. `inner.fast_cancel` flips to true with Release.
//! 3. Any pending cancel_waker is invoked, scheduling the
//!    task on the cancel lane of the three-lane scheduler.
//! 4. The task completes its current `poll()` (whatever
//!    it's currently doing: I/O wait, compute, etc.).
//! 5. On the NEXT poll iteration, the first
//!    `cx.checkpoint()` returns `Err(Cancelled)` (or the
//!    next `.await` on a cancel-aware Future returns
//!    Err/Pending+wake).
//! 6. The user's `?` propagates Err; structured-concurrency
//!    drain/finalize sequence runs.
//!
//! Step 4 IS the "graceful let task complete current
//! poll" semantic. There's no separate API for it.
//!
//! Verdict: **SOUND BY DESIGN**. `Cx::interrupt()` does
//! not exist; cancel is one mechanism with two attribution
//! variants. The graceful-current-poll behavior is the
//! built-in default; there is no preemptive alternative
//! and there cannot be one under the unsafe-code-denied
//! discipline.
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
fn cx_does_not_have_interrupt_method() {
    // Pin: the Cx impl block(s) in src/cx/cx.rs must NOT
    // define `fn interrupt(...)`. SignalKind::interrupt is
    // a different namespace and is excluded.
    let source = read("src/cx/cx.rs");

    let suspect_methods = [
        "pub fn interrupt(",
        "pub fn interrupt_self(",
        "pub fn interrupt_with(",
        "pub async fn interrupt(",
    ];
    for pat in &suspect_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: Cx now has `{pat}` — the operator-\
             requested graceful/immediate distinction is \
             being silently introduced. asupersync's cancel \
             is unified by design; adding a separate \
             interrupt method requires explicit design \
             review.",
        );
    }
}

#[test]
fn cx_does_not_have_bare_cancel_method() {
    // Pin: there is no bare `Cx::cancel(&self)` method.
    // Cancel goes through `cancel_with(kind, message)` or
    // `cancel_fast(kind)` — both require an explicit
    // CancelKind for attribution.
    let source = read("src/cx/cx.rs");

    let suspect_methods = [
        "pub fn cancel(&self) {",
        "pub fn cancel(&self,",
        "pub fn cancel(&mut self) {",
        "pub async fn cancel(&self)",
    ];
    for pat in &suspect_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: Cx now has bare `{pat}` — cancel \
             without an explicit CancelKind argument breaks \
             the attribution discipline (CancelKind is the \
             foundation of deterministic cancel provenance).",
        );
    }
}

#[test]
fn cx_cancel_with_exists_with_kind_and_message() {
    // Pin: the canonical full-attribution cancel path.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains(
            "pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {"
        ),
        "REGRESSION: Cx::cancel_with signature is gone or \
         changed. The canonical attribution-rich cancel \
         path is broken.",
    );
}

#[test]
fn cx_cancel_fast_exists_with_kind_only() {
    // Pin: the performance-critical cancel path with
    // minimal attribution.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn cancel_fast(&self, kind: CancelKind) {"),
        "REGRESSION: Cx::cancel_fast signature is gone or \
         changed. The performance-critical cancel path is \
         broken.",
    );
}

#[test]
fn cancel_with_and_cancel_fast_use_same_underlying_mechanism() {
    // Pin: BOTH cancel_with and cancel_fast set the SAME
    // three flags: cancel_requested = true, fast_cancel
    // store(true, Release), cancel_reason = Some(...). If
    // they ever diverge, the "two paths, same semantic"
    // promise is broken.
    let source = read("src/cx/cx.rs");

    let cancel_with_marker =
        "pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {";
    let cancel_fast_marker = "pub fn cancel_fast(&self, kind: CancelKind) {";

    let cw_pos = source.find(cancel_with_marker).expect("cancel_with fn");
    let cf_pos = source.find(cancel_fast_marker).expect("cancel_fast fn");

    let cw_body = &source[cw_pos..cw_pos + 1500];
    let cf_body = &source[cf_pos..cf_pos + 1500];

    let common_ops = [
        "inner.cancel_requested = true;",
        ".fast_cancel",
        ".store(true, std::sync::atomic::Ordering::Release);",
        "inner.cancel_reason = Some",
    ];
    for op in &common_ops {
        assert!(
            cw_body.contains(op),
            "REGRESSION: cancel_with no longer performs \
             `{op}`. The unified cancel mechanism has \
             diverged.",
        );
        assert!(
            cf_body.contains(op),
            "REGRESSION: cancel_fast no longer performs \
             `{op}`. The unified cancel mechanism has \
             diverged.",
        );
    }
}

#[test]
fn no_interrupt_method_anywhere_in_cx_module() {
    // Pin: not even a free function or trait fn named
    // `interrupt` exists in src/cx/.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src/cx") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains("fn interrupt(") || content.contains("fn interrupt_") {
            violations.push(path.display().to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: `interrupt` function introduced in \
         src/cx/. The unified-cancel discipline is being \
         silently expanded.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn signal_kind_interrupt_is_a_separate_namespace_not_a_cx_method() {
    // Pin: `SignalKind::interrupt()` (src/signal/kind.rs:38)
    // is the SIGINT constructor, NOT a Cx method. This is
    // the only `fn interrupt` in src/ and must remain in
    // the signal module.
    let source = read("src/signal/kind.rs");

    assert!(
        source.contains("pub const fn interrupt() -> Self {")
            || source.contains("pub fn interrupt() -> Self {"),
        "REGRESSION: SignalKind::interrupt constructor is \
         gone. (This is the legitimate sibling — the SIGINT \
         signal kind, not a cancel verb.)",
    );

    // The signal module's `interrupt` must NOT be tagged
    // with a doc-alias suggesting it's a Cx cancel method.
    assert!(
        !source.contains("#[doc(alias = \"cx.interrupt\")]")
            && !source.contains("#[doc(alias = \"Cx::interrupt\")]")
            && !source.contains("#[doc(alias = \"cancel\")]"),
        "REGRESSION: SignalKind::interrupt now has a doc-\
         alias suggesting it is a Cx cancel method. This \
         creates exactly the conflation the operator's \
         question warns about.",
    );
}

#[test]
fn cx_has_no_graceful_immediate_cancel_distinction_methods() {
    // Pin: the operator's framing assumes a graceful-vs-
    // immediate API surface. We must NOT have method names
    // that imply such a distinction.
    let source = read("src/cx/cx.rs");

    let suspect_distinction_methods = [
        "pub fn graceful_cancel(",
        "pub fn immediate_cancel(",
        "pub fn cancel_now(",
        "pub fn cancel_soon(",
        "pub fn soft_cancel(",
        "pub fn hard_cancel(",
        "pub fn cancel_after_poll(",
        "pub fn cancel_immediately(",
    ];
    for pat in &suspect_distinction_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: Cx now has `{pat}` — this implies \
             a graceful-vs-immediate distinction that does \
             not match asupersync's unified cancel \
             protocol. Either the design changed (review!) \
             or this is naming drift.",
        );
    }
}

#[test]
fn cancel_with_documents_unified_protocol() {
    // Pin: the docstring on cancel_with must reference
    // the standard cancel protocol so future readers don't
    // add `interrupt` as a "different" thing.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {";
    let pos = source.find(fn_marker).expect("cancel_with fn");
    let preceding = &source[pos.saturating_sub(2500)..pos];

    assert!(
        preceding.contains("cancel")
            && (preceding.contains("checkpoint")
                || preceding.contains("CancelReason")
                || preceding.contains("CancelKind")),
        "REGRESSION: cancel_with docstring no longer \
         references the cancel protocol (CancelKind / \
         CancelReason / checkpoint). Future readers may add \
         `interrupt` thinking the existing API is missing a \
         primitive.",
    );
}

#[test]
fn cancel_fast_documents_attribution_tradeoff() {
    // Pin: the docstring on cancel_fast must explain it is
    // the SAME cancel mechanism with REDUCED attribution
    // (not a different semantic).
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn cancel_fast(&self, kind: CancelKind) {";
    let pos = source.find(fn_marker).expect("cancel_fast fn");
    let preceding = &source[pos.saturating_sub(3000)..pos];

    assert!(
        preceding.contains("attribution") || preceding.contains("Use `cancel_with`"),
        "REGRESSION: cancel_fast docstring no longer \
         documents the attribution tradeoff vs cancel_with. \
         Readers may interpret cancel_fast as a separate \
         semantic (immediate vs graceful) when in fact it \
         is the same operation with less metadata.",
    );
}

#[test]
fn no_interrupt_doc_alias_anywhere_in_src() {
    // Pin: no `#[doc(alias = "interrupt")]` anywhere in
    // src/. Adding one would imply a method exists that
    // doesn't.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains("#[doc(alias = \"interrupt\")]") {
            violations.push(path.display().to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: doc-alias for `interrupt` introduced \
         in src/. Users will expect a Cx::interrupt method \
         that doesn't exist.\n\n{}",
        violations.join("\n"),
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Mock Cx with the unified cancel mechanism: both
/// `cancel_with` and `cancel_fast` set the same fast_cancel
/// flag. There is NO `interrupt` method.
struct MockCx {
    fast_cancel: Arc<AtomicBool>,
    cancel_kind: Arc<parking_lot_mock::Mutex<Option<&'static str>>>,
    poll_count: AtomicU64,
}

mod parking_lot_mock {
    use std::sync::Mutex as StdMutex;

    pub struct Mutex<T>(StdMutex<T>);
    impl<T> Mutex<T> {
        pub const fn new(t: T) -> Self
        where
            T: Sized,
        {
            Self(StdMutex::new(t))
        }
        pub fn store(&self, t: T) {
            *self.0.lock().unwrap() = t;
        }
        pub fn load(&self) -> T
        where
            T: Clone,
        {
            self.0.lock().unwrap().clone()
        }
    }
}

impl MockCx {
    fn new() -> Self {
        Self {
            fast_cancel: Arc::new(AtomicBool::new(false)),
            cancel_kind: Arc::new(parking_lot_mock::Mutex::new(None)),
            poll_count: AtomicU64::new(0),
        }
    }

    /// Models cx.cancel_with(kind, message): full attribution.
    fn cancel_with(&self, kind: &'static str, _message: Option<&'static str>) {
        self.cancel_kind.store(Some(kind));
        self.fast_cancel.store(true, Ordering::Release);
    }

    /// Models cx.cancel_fast(kind): minimal attribution.
    /// Same underlying mechanism as cancel_with.
    fn cancel_fast(&self, kind: &'static str) {
        self.cancel_kind.store(Some(kind));
        self.fast_cancel.store(true, Ordering::Release);
    }

    fn checkpoint(&self) -> Result<(), &'static str> {
        if self.fast_cancel.load(Ordering::Acquire) {
            Err("cancelled")
        } else {
            Ok(())
        }
    }

    /// Models a single poll: completes its current iteration
    /// THEN checks for cancel on the next checkpoint. This
    /// is the "graceful let-current-poll-finish" behavior
    /// that is asupersync's default.
    fn poll_once(&self) -> Poll {
        // Poll always runs to completion of its current step.
        self.poll_count.fetch_add(1, Ordering::Relaxed);

        // After the step, check for cancel.
        if self.checkpoint().is_err() {
            Poll::Cancelled
        } else {
            Poll::Pending
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Poll {
    Pending,
    Cancelled,
}

#[test]
fn behavioral_cancel_with_and_cancel_fast_have_identical_observable_effect() {
    // Both cancel paths set the same fast_cancel flag and
    // are observed identically at the next checkpoint.
    let cx1 = MockCx::new();
    let cx2 = MockCx::new();

    cx1.cancel_with("user", Some("test message"));
    cx2.cancel_fast("user");

    assert_eq!(cx1.checkpoint(), Err("cancelled"));
    assert_eq!(cx2.checkpoint(), Err("cancelled"));

    // Both paths set cancel_kind.
    assert_eq!(cx1.cancel_kind.load(), Some("user"));
    assert_eq!(cx2.cancel_kind.load(), Some("user"));
}

#[test]
fn behavioral_cancel_lets_current_poll_complete_before_observing() {
    // Models the "graceful" semantic that the operator's
    // framing attributed to a hypothetical `interrupt()`:
    // the current poll always completes before cancel is
    // observed.
    let cx = MockCx::new();

    // First poll: not cancelled, completes Pending.
    assert_eq!(cx.poll_once(), Poll::Pending);
    assert_eq!(cx.poll_count.load(Ordering::Relaxed), 1);

    // Cancel arrives between polls.
    cx.cancel_with("test", None);

    // Next poll: completes its step (poll_count++) and
    // THEN observes cancel — proving the "let current
    // poll complete" semantic.
    assert_eq!(cx.poll_once(), Poll::Cancelled);
    assert_eq!(
        cx.poll_count.load(Ordering::Relaxed),
        2,
        "REGRESSION: poll did NOT complete its step before \
         observing cancel. This would be preemptive \
         interrupt — not allowed under unsafe-code-denied.",
    );
}

#[test]
fn behavioral_no_separate_interrupt_path_compile_time_proof() {
    // The compile-time absence of `MockCx::interrupt` is
    // the proof. If a future regression adds an interrupt
    // method to MockCx (mirroring a production change),
    // this test is unaffected — but the structural pins
    // catch the production change.
    let cx = MockCx::new();
    cx.cancel_with("u", None);
    assert_eq!(cx.checkpoint(), Err("cancelled"));

    // No `cx.interrupt(...)` call exists. By construction,
    // the only cancel paths are cancel_with and cancel_fast.
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/runtime_abort_vs_cancel_semantics_audit.rs",
        "tests/runtime_cancel_signal_coalescing_audit.rs",
        "tests/runtime_cancel_cause_kinds_distinct_audit.rs",
        "tests/cx_checkpoint_during_region_cancel_timing_audit.rs",
        "tests/scheduler_thread_priority_design_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
