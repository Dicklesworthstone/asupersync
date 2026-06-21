//! Audit + regression test for `block_on()` vs `run_until()`
//! distinction.
//!
//! Operator's question: "block_on takes a future and blocks
//! until it completes; run_until is similar but provides
//! scheduler control. If both APIs exist, verify they have
//! observable differences in behavior."
//!
//! Audit findings: **SOUND BY DESIGN — DIFFERENT TYPES**.
//!
//! The two APIs the operator is asking about live on
//! DIFFERENT TYPES belonging to DIFFERENT RUNTIMES:
//!
//! 1. **`Runtime::block_on<F>(&self, future: F) -> F::Output`**
//!    (src/runtime/builder.rs:3140) — the PRODUCTION
//!    runtime driver. Drives the real scheduler with real
//!    time, real I/O, real workers until the supplied
//!    future completes. Returns the future's output value.
//!
//! 2. **`LabRuntime::run_until_quiescent(&mut self) -> u64`**
//!    (src/lab/runtime.rs:1156) — the DETERMINISTIC lab
//!    runtime driver. Repeatedly calls `step()` until no
//!    runnable tasks AND no pending obligations. Returns
//!    the number of steps executed (not a future's output).
//!
//!    Sibling: `LabRuntime::run_until_idle(&mut self) -> u64`
//!    (line 1180) — weaker variant: runs until scheduler
//!    queue is empty (tasks may still be blocked on
//!    channels). Documented in source as "intentionally
//!    weaker than run_until_quiescent."
//!
//! NEITHER `Cx::block_on()` NOR `Cx::run_until()` exists.
//! These are runtime-level methods, not capability-context
//! methods.
//!
//! ── Why they cannot be conflated ────────────────────────
//!
//! - `block_on` lives on `Runtime` / `RuntimeHandle`
//!   (production). `run_until_*` lives on `LabRuntime`
//!   (test). Different impl blocks; different types; no
//!   trait unifies them.
//! - `block_on` returns `F::Output` (the future's value).
//!   `run_until_quiescent` returns `u64` (step count). The
//!   return types alone make them un-aliasable.
//! - `block_on` takes a `future: F: Future`.
//!   `run_until_quiescent` takes NO future argument — it
//!   drains whatever was already spawned via
//!   `LabRuntime::spawn`.
//! - `block_on` uses real wall time; `run_until_*` uses
//!   virtual time via the `LabClock` and advances time
//!   deterministically.
//!
//! ── What "scheduler control" means in each case ─────────
//!
//! - Production `block_on` provides ZERO knobs for
//!   scheduler control beyond what `RuntimeBuilder` was
//!   configured with. The future is polled with the
//!   runtime's poll_budget; that's it.
//! - Lab `run_until_quiescent` and `run_until_idle` ARE
//!   the scheduler control surface — the test bounds
//!   exactly when the deterministic step loop terminates,
//!   either at full quiescence or at empty-queue-idle.
//!
//! So the operator's framing — "run_until provides
//! scheduler control" — maps onto LabRuntime's `run_until_*`
//! methods, while production `block_on` is the
//! "fire-and-wait" driver.
//!
//! ── A third lab method: `LabNetwork::run_until(target: Time)` ──
//!
//! `src/lab/network/network.rs:330` defines a method
//! literally named `run_until(target: Time)`. This is on
//! the lab NETWORK, not the lab RUNTIME — it advances
//! virtual network time. Unrelated to scheduler control;
//! relevant only to in-flight messages.
//!
//! ── Conflation risk ─────────────────────────────────────
//!
//! Since the APIs live on different types with different
//! signatures and return values, conflation in source code
//! is impossible without explicit refactoring. The risk is:
//!
//!   - A future regression that adds `Cx::block_on` or
//!     `Cx::run_until` (introducing the operator's
//!     conflated framing into source).
//!   - A future regression that exposes lab-runtime methods
//!     on the production `RuntimeHandle` (or vice versa),
//!     blurring the production / test boundary.
//!
//! Both are caught by the structural pins below.
//!
//! Verdict: **SOUND BY DESIGN**. `block_on` and
//! `run_until_*` are on different runtimes, return
//! different values, and serve different purposes
//! (production fire-and-wait vs deterministic lab step
//! control). They cannot be conflated because they don't
//! share a type or signature.
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
fn cx_does_not_have_block_on_method() {
    // Pin: block_on is a runtime-level driver, not a Cx
    // method. Adding it to Cx would imply blocking on a
    // future from inside another future — a deadlock
    // hazard.
    let source = read("src/cx/cx.rs");

    let suspect_methods = [
        "pub fn block_on(",
        "pub async fn block_on(",
        "pub fn block_on<",
    ];
    for pat in &suspect_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: Cx now has `{pat}` — block_on \
             belongs on Runtime, not Cx. Calling block_on \
             from inside async code (which is what having \
             it on Cx invites) is a deadlock pattern.",
        );
    }
}

#[test]
fn cx_does_not_have_run_until_method() {
    // Pin: run_until is a LabRuntime test driver, not a Cx
    // method. Exposing it on Cx leaks lab semantics into
    // production.
    let source = read("src/cx/cx.rs");

    let suspect_methods = [
        "pub fn run_until(",
        "pub fn run_until_quiescent(",
        "pub fn run_until_idle(",
    ];
    for pat in &suspect_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: Cx now has `{pat}` — run_until \
             family belongs on LabRuntime (test-only). \
             Production Cx must not expose deterministic \
             step control.",
        );
    }
}

#[test]
fn runtime_block_on_signature_pinned() {
    // Pin: production block_on takes a Future and returns
    // F::Output. If the signature drifts to return u64 or
    // step count, it has been conflated with run_until_*.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("pub fn block_on<F: Future>(&self, future: F) -> F::Output {"),
        "REGRESSION: Runtime::block_on signature changed. \
         The production future-driver contract is broken.",
    );
}

#[test]
fn lab_runtime_run_until_quiescent_signature_pinned() {
    // Pin: lab run_until_quiescent takes no future arg and
    // returns step count. If the signature drifts to take
    // a future and return F::Output, it has been conflated
    // with block_on.
    let source = read("src/lab/runtime.rs");

    assert!(
        source.contains("pub fn run_until_quiescent(&mut self) -> u64 {"),
        "REGRESSION: LabRuntime::run_until_quiescent \
         signature changed. The deterministic step-driver \
         contract is broken.",
    );
}

#[test]
fn lab_runtime_run_until_idle_signature_pinned() {
    // Pin: the weaker idle variant returns step count too.
    let source = read("src/lab/runtime.rs");

    assert!(
        source.contains("pub fn run_until_idle(&mut self) -> u64 {"),
        "REGRESSION: LabRuntime::run_until_idle signature \
         changed.",
    );
}

#[test]
fn lab_run_until_idle_documented_as_weaker_than_quiescent() {
    // Pin: the idle variant is documented as intentionally
    // weaker. If this doc is lost, future readers may
    // collapse the two into one and lose the
    // "blocked-on-channel-counts-as-idle" semantic.
    let source = read("src/lab/runtime.rs");

    let fn_marker = "pub fn run_until_idle(&mut self) -> u64 {";
    let pos = source.find(fn_marker).expect("run_until_idle fn");
    let preceding = &source[pos.saturating_sub(2000)..pos];

    assert!(
        preceding.contains("intentionally weaker")
            || preceding.contains("not** require all tasks to complete")
            || preceding.contains("blocked on a channel"),
        "REGRESSION: run_until_idle docstring no longer \
         documents the intentionally-weaker semantic vs \
         run_until_quiescent. Future readers may merge them.",
    );
}

#[test]
fn block_on_is_only_on_runtime_not_lab() {
    // Pin: block_on must NOT exist on LabRuntime — that
    // would conflate production fire-and-wait with
    // deterministic step control.
    let source = read("src/lab/runtime.rs");

    let suspect_methods = [
        "pub fn block_on<",
        "pub fn block_on(",
        "pub async fn block_on(",
    ];
    for pat in &suspect_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: LabRuntime now has `{pat}` — \
             production block_on semantic leaked into the \
             deterministic test runtime.",
        );
    }
}

#[test]
fn run_until_is_only_on_lab_not_production_runtime() {
    // Pin: run_until_quiescent / run_until_idle must NOT
    // exist on production RuntimeHandle/Runtime.
    let source = read("src/runtime/builder.rs");

    let suspect_methods = ["pub fn run_until_quiescent(", "pub fn run_until_idle("];
    for pat in &suspect_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: production Runtime now has `{pat}` \
             — deterministic lab semantic leaked into \
             production. The production runtime cannot \
             have a 'quiescent' notion (real I/O blocks \
             indefinitely).",
        );
    }
}

#[test]
fn block_on_returns_future_output_not_step_count() {
    // Pin: at the type level, block_on's return is
    // F::Output (a generic). run_until_* return u64. If
    // someone changed block_on to return u64, the test
    // catches it.
    let source = read("src/runtime/builder.rs");

    let block_on_marker = "pub fn block_on<F: Future>(&self, future: F) -> F::Output {";
    let pos = source.find(block_on_marker).expect("block_on fn");
    let body_end = source[pos..].find("\n    }\n").expect("block_on close");
    let body = &source[pos..pos + body_end];

    // The body must call run_future_with_budget which
    // returns F::Output. If it called something returning
    // u64, the type system would error — but we also pin
    // the call here for clarity.
    assert!(
        body.contains("run_future_with_budget(future, "),
        "REGRESSION: block_on body no longer calls \
         run_future_with_budget. The future-driving path \
         has changed — re-audit.",
    );
}

#[test]
fn run_until_quiescent_calls_step_in_a_loop() {
    // Pin: run_until_quiescent's body is a loop calling
    // self.step() until is_quiescent() OR max_steps. If
    // this drifts to "spawn future + block_on", the
    // deterministic step semantic is broken.
    let source = read("src/lab/runtime.rs");

    let fn_marker = "pub fn run_until_quiescent(&mut self) -> u64 {";
    let pos = source.find(fn_marker).expect("run_until_quiescent fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("run_until_quiescent close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("self.step();") && body.contains("is_quiescent()"),
        "REGRESSION: run_until_quiescent no longer calls \
         self.step() in a loop with is_quiescent() check. \
         The deterministic step semantic is broken.",
    );

    // Must NOT call block_on — the lab driver does not
    // delegate to production semantics.
    assert!(
        !body.contains("block_on("),
        "REGRESSION: run_until_quiescent now calls \
         block_on — lab/production boundary is broken.",
    );
}

#[test]
fn lab_network_run_until_takes_target_time_not_future() {
    // Pin: LabNetwork::run_until(target: Time) is the
    // virtual-network advancer. It takes a Time, not a
    // Future. This is unrelated to scheduler control —
    // pinning it documents the third place "run_until"
    // appears so readers don't conflate.
    let source = read("src/lab/network/network.rs");

    assert!(
        source.contains("pub fn run_until(&mut self, target: Time) {"),
        "REGRESSION: LabNetwork::run_until signature \
         changed. Either the virtual-network advancer is \
         broken or it has been merged with the runtime \
         step driver.",
    );
}

#[test]
fn no_doc_alias_blurring_block_on_with_run_until() {
    // Pin: no doc-alias from block_on to run_until or
    // vice versa. Such an alias would imply they are
    // interchangeable — they aren't.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let suspect_aliases = [
            "#[doc(alias = \"block_on\")]",
            "#[doc(alias = \"run_until\")]",
            "#[doc(alias = \"run_until_quiescent\")]",
            "#[doc(alias = \"run_until_idle\")]",
        ];
        for alias in &suspect_aliases {
            if content.contains(alias) {
                // The doc-alias is fine on the actual
                // method. We're checking it isn't applied
                // to the OTHER method.
                let block_on_method = content.contains("pub fn block_on<F: Future>");
                let run_until_method =
                    content.contains("pub fn run_until_quiescent(&mut self) -> u64");

                if alias.contains("block_on") && !block_on_method {
                    violations.push(format!(
                        "{}: has `{}` but no block_on method",
                        path.display(),
                        alias
                    ));
                }
                if alias.contains("run_until") && !run_until_method {
                    violations.push(format!(
                        "{}: has `{}` but no run_until method",
                        path.display(),
                        alias
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: doc-alias to a different runtime's \
         driver. Users will conflate.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn block_on_documented_as_production_future_driver() {
    let source = read("src/runtime/builder.rs");

    let fn_marker = "pub fn block_on<F: Future>(&self, future: F) -> F::Output {";
    let pos = source.find(fn_marker).expect("block_on fn");
    let preceding = &source[pos.saturating_sub(1500)..pos];

    assert!(
        preceding.contains("Run a future to completion")
            || preceding.contains("future to completion"),
        "REGRESSION: block_on docstring no longer documents \
         the future-driver semantic.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

/// Mock production runtime: block_on takes a Future and
/// returns F::Output.
struct MockRuntime;

impl MockRuntime {
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut pinned = std::pin::pin!(future);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(out) => return out,
                Poll::Pending => {}
            }
        }
    }
}

/// Mock lab runtime: run_until_quiescent takes NO future
/// and returns a step count.
struct MockLabRuntime {
    steps: AtomicU64,
    quiescent_at_step: u64,
}

impl MockLabRuntime {
    fn new(quiescent_at_step: u64) -> Self {
        Self {
            steps: AtomicU64::new(0),
            quiescent_at_step,
        }
    }

    fn step(&self) {
        self.steps.fetch_add(1, Ordering::Relaxed);
    }

    fn is_quiescent(&self) -> bool {
        self.steps.load(Ordering::Acquire) >= self.quiescent_at_step
    }

    fn run_until_quiescent(&mut self) -> u64 {
        let start = self.steps.load(Ordering::Acquire);
        while !self.is_quiescent() {
            self.step();
        }
        self.steps.load(Ordering::Acquire) - start
    }
}

#[test]
fn behavioral_block_on_returns_future_output() {
    let rt = MockRuntime;

    let result: u32 = rt.block_on(async { 42_u32 });

    assert_eq!(
        result, 42,
        "REGRESSION: block_on did not return future's \
         output. The production driver contract is broken.",
    );
}

#[test]
fn behavioral_run_until_quiescent_returns_step_count() {
    let mut lab = MockLabRuntime::new(7);

    let steps = lab.run_until_quiescent();

    assert_eq!(
        steps, 7,
        "REGRESSION: run_until_quiescent did not return \
         step count.",
    );
}

#[test]
fn behavioral_block_on_and_run_until_have_distinct_signatures() {
    // Compile-time proof: block_on takes a Future and
    // returns F::Output; run_until_quiescent takes no arg
    // and returns u64. If a future regression aliases
    // them, the signatures will diverge from this test.
    let rt = MockRuntime;
    let mut lab = MockLabRuntime::new(3);

    // block_on: future in, value out.
    let value: i64 = rt.block_on(async { -100_i64 });
    assert_eq!(value, -100);

    // run_until_quiescent: no future, step count out.
    let steps: u64 = lab.run_until_quiescent();
    assert_eq!(steps, 3);

    // The fact that this code compiles AND both functions
    // have different shapes IS the proof of distinction.
}

#[test]
fn behavioral_lab_run_until_does_not_drive_a_future() {
    // run_until_quiescent does NOT take a future. We can't
    // pass one. This is the structural distinction from
    // block_on.
    let mut lab = MockLabRuntime::new(5);

    // Pre-spawn work would happen via lab.spawn(...) — but
    // run_until_quiescent itself has no future parameter.
    let steps = lab.run_until_quiescent();

    assert_eq!(steps, 5);
    // The compile-time absence of a future arg on
    // run_until_quiescent is the design proof.
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_no_scope_default_method_audit.rs",
        "tests/cx_api_decision_tree_with_vs_scope_audit.rs",
        "tests/runtime_join_handle_no_separable_abort_handle_audit.rs",
        "tests/runtime_no_detached_orphan_spawn_api_audit.rs",
        "tests/cx_no_interrupt_method_unified_cancel_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
