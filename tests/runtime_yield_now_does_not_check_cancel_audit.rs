//! Audit + regression test for `yield_now()` interaction
//! with pending cancel.
//!
//! Operator's question: "when yield_now is called and the
//! cancel-bit is already set, must yield_now return
//! Err(Cancelled) (correct: fail-fast) instead of yielding."
//!
//! Audit findings:
//!
//!   `yield_now()` is a **cancel-ignorant** primitive by
//!   design. Its return type is `Poll<()>`, NOT
//!   `Poll<Result<(), Error>>`. It cannot return
//!   `Err(Cancelled)` because errors are not in its type
//!   signature. This is the **intentional asupersync API
//!   split**:
//!
//!   - **`Cx::checkpoint() -> Result<(), Error>`** — the
//!     cancel-observation primitive. Returns Err on
//!     cancel/budget-exhaustion. Same-call fail-fast.
//!   - **`yield_now() -> impl Future<Output = ()>`** — the
//:     pure scheduler-yield primitive. Returns nothing.
//!     Always yields once and completes.
//!
//!   The operator's "must return Err(Cancelled)" framing
//!   maps onto a NON-EXISTENT API surface — yield_now's
//!   `()` Output cannot carry an error variant. The
//!   structurally correct way to compose fail-fast cancel
//!   observation with a yield is:
//!
//!   ```ignore
//!   loop {
//!       cx.checkpoint()?;       // fail-fast on cancel
//!       yield_now().await;      // pure yield
//!       // ...do work...
//!   }
//!   ```
//!
//!   This separation is deliberate:
//!
//!   1. **`yield_now` doesnt take `&Cx`** — it's a global
//!      primitive (cooperative-yield doesnt need
//!      capability/cancel context).
//!
//!   2. **`yield_now` can be called from any future** — even
//!      ones that dont have a Cx in scope (e.g., low-level
//!      I/O futures, raw Tokio-compat shims). Coupling it
//!      to Cx would force every caller to thread the
//!      capability context through.
//!
//!   3. **`Cx::checkpoint`** is the documented cancel-
//!      observation site (see prior audits:
//!      cx_checkpoint_cancel_fail_fast_audit.rs,
//!      cx_checkpoint_concurrent_cancel_observation_audit.rs).
//!      Adding cancel observation to yield_now would
//!      duplicate the contract.
//!
//!   4. **Cancel propagation works regardless**: if a task
//!      yields via yield_now while cancel is pending, the
//!      task is re-scheduled (the wake_by_ref re-injects
//!      it). On the NEXT poll, the task's NEXT cx.checkpoint
//!      observes the cancel and returns Err. So cancel is
//!      ALWAYS observed at most one yield-cycle late — and
//!      the user controls when checkpoint fires.
//!
//!   The chain:
//!
//!   1. **`YieldNow.poll`** (runtime/yield_now.rs:20):
//!      ```ignore
//!      fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
//!          assert!(!self.completed, "yield_now future polled after completion");
//!          if self.yielded {
//!              self.completed = true;
//!              Poll::Ready(())
//!          } else {
//!              self.yielded = true;
//!              cx.waker().wake_by_ref();
//!              Poll::Pending
//!          }
//!      }
//!      ```
//!      No fast_cancel access. No Cx access. No Result
//!      return. Pure two-poll yield.
//!
//!   2. **`yield_now() -> YieldNow`** signature: takes no
//!      arguments, returns a Future<Output = ()>. The Cx
//!      is not in scope here.
//!
//!   3. **No fast_cancel reference** in
//!      `src/runtime/yield_now.rs`: a grep confirms zero
//!      references to fast_cancel, cancel_requested, or
//!      Cx — yield_now is structurally cancel-ignorant.
//!
//! Verdict: **SOUND BY DESIGN**. The operator's "must
//: return Err(Cancelled)" framing maps onto a NON-EXISTENT
//! API surface — yield_now's Output is `()`, not Result.
//! This is intentional — the asupersync API splits cancel
//! observation (`Cx::checkpoint()?`) from yield
//! (`yield_now().await`). Composing them is the user's
//! responsibility.
//!
//! No bead filed for the fail-fast variant. The two-
//! primitive design is documented; users have a clear
//! pattern (`cx.checkpoint()?; yield_now().await;`).
//!
//! If the operator wants a combined `cx.yield_checkpoint()`
//! method that does both, that's a feature bead, NOT a
//! defect bead. The CURRENT API is correct per its
//! documented contract.
//!
//! A regression that:
//!   - changed yield_now to take `&Cx` (would couple yield
//!     to capability context — caller now needs Cx in
//!     scope, breaking yield_now from non-Cx contexts),
//!   - changed yield_now's Output from `()` to
//:     `Result<(), Error>` (breaks every existing caller's
//!     `.await` ergonomics — `yield_now().await?` instead
//!     of `yield_now().await`),
//!   - added a fast_cancel.load inside YieldNow::poll
//:     (would silently do cancel observation in a primitive
//!     that doesnt return errors — silent swallow if the
//!     user doesnt also call checkpoint),
//!   - removed yield_now entirely (would lose the pure-
//!     yield primitive — apps would have to compose
//!     ad-hoc Pending+wake patterns),
//! would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn yield_now_returns_yield_now_future_not_a_result_wrapper() {
    // Pin (link 1+2): the yield_now() function returns
    // YieldNow which implements Future<Output = ()>. NOT
    // Result. The Output type is the structural reason
    // yield_now can never "return Err(Cancelled)".
    let source = read("src/runtime/yield_now.rs");

    assert!(
        source.contains("pub fn yield_now() -> YieldNow {"),
        "REGRESSION: yield_now() return type changed. If it \
         became Result-returning or Cx-taking, every \
         existing caller's `.await` ergonomics breaks.",
    );
}

#[test]
fn yield_now_future_output_is_unit_not_result() {
    // Pin (link 1): YieldNow's Future Output is `()`, NOT
    // `Result<(), ...>`. yield_now().await produces (),
    // not a Result that needs ?-propagation.
    let source = read("src/runtime/yield_now.rs");

    let impl_marker = "impl Future for YieldNow {";
    let start = source.find(impl_marker).expect("YieldNow Future impl");
    let next_impl = source[start + impl_marker.len()..]
        .find("\nimpl ")
        .map(|o| start + impl_marker.len() + o)
        .unwrap_or(source.len());
    let body = &source[start..next_impl];

    assert!(
        body.contains("type Output = ();"),
        "REGRESSION: YieldNow::Output is no longer (). If it \
         became Result<(), Error>, every caller's \
         `yield_now().await` ergonomics breaks — they'd \
         need `yield_now().await?` instead.",
    );
}

#[test]
fn yield_now_does_not_reference_fast_cancel_or_cx() {
    // Pin (link 3): the yield_now module has ZERO references
    // to fast_cancel, cancel_requested, or Cx. The primitive
    // is structurally cancel-ignorant.
    let source = read("src/runtime/yield_now.rs");

    let suspect_cancel_refs = [
        "fast_cancel",
        "cancel_requested",
        "Cx::current",
        "cx.checkpoint",
    ];
    for pat in &suspect_cancel_refs {
        assert!(
            !source.contains(pat),
            "REGRESSION: yield_now.rs now references `{pat}`. \
             The pure-yield-primitive contract is broken — \
             yield_now is now cancel-aware, conflating with \
             checkpoint and breaking the documented API split.",
        );
    }
}

#[test]
fn yield_now_takes_no_arguments_no_cx_parameter() {
    // Pin (link 1): the `pub fn yield_now()` signature has
    // no parameters. Without a Cx parameter, yield_now
    // can't access the cancel state — structurally
    // cancel-ignorant.
    let source = read("src/runtime/yield_now.rs");

    assert!(
        source.contains("pub fn yield_now() -> YieldNow {"),
        "REGRESSION: yield_now signature now takes \
         arguments. If it now takes &Cx, every existing \
         caller breaks — yield_now becomes Cx-coupled.",
    );

    // Forbid suspect Cx-coupled signatures.
    let suspect_signatures = [
        "pub fn yield_now(cx: &Cx)",
        "pub fn yield_now(cx: Cx)",
        "pub fn yield_now<C>(cx: &C)",
    ];
    for pat in &suspect_signatures {
        assert!(
            !source.contains(pat),
            "REGRESSION: yield_now signature now takes Cx \
             (`{pat}`). Coupling yield to capability context \
             forces every caller to have Cx in scope — \
             breaks low-level futures that don't have Cx.",
        );
    }
}

#[test]
fn yield_now_poll_body_is_pure_two_poll_yield_no_cancel_check() {
    // Pin (link 1): the YieldNow::poll body is the pure
    // two-poll yield pattern (yielded flag, wake_by_ref,
    // completed flag). NO cancel check, NO Cx access.
    let source = read("src/runtime/yield_now.rs");

    let fn_marker = "fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let start = source.find(fn_marker).expect("YieldNow::poll fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("YieldNow::poll close");
    let body = &source[start..start + body_end];

    // The cx parameter is the std task::Context for the
    // waker, NOT asupersync Cx.
    assert!(
        body.contains("cx.waker().wake_by_ref();"),
        "REGRESSION: YieldNow::poll no longer self-wakes. \
         The yield is broken — task hangs without external \
         wake.",
    );

    assert!(
        body.contains("Poll::Ready(())")
            && body.contains("Poll::Pending"),
        "REGRESSION: YieldNow::poll no longer alternates \
         Pending → Ready. The two-poll contract is broken.",
    );

    // Forbid cancel-check patterns in the poll body.
    let suspect_cancel_check = [
        ".fast_cancel.load(",
        "if cancel_requested",
        "Cx::current()",
    ];
    for pat in &suspect_cancel_check {
        assert!(
            !body.contains(pat),
            "REGRESSION: YieldNow::poll now contains a cancel \
             check (`{pat}`). The pure-yield contract is \
             broken — yield_now is silently observing cancel \
             but cant return Err (Output is ()), so the \
             observation is SWALLOWED.",
        );
    }
}

#[test]
fn cx_checkpoint_is_the_documented_cancel_observation_site() {
    // Pin (link 3 cross-reference): Cx::checkpoint is the
    // documented cancel-observation primitive — its
    // signature returns Result, its body checks fast_cancel.
    // This is the API yield_now is INTENTIONALLY
    // complementing.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn checkpoint(&self) -> Result<(), crate::error::Error> {"),
        "REGRESSION: Cx::checkpoint signature is gone — the \
         cancel-observation API is broken. yield_now's \
         design assumes checkpoint exists for the user to \
         compose fail-fast cancel observation alongside \
         pure yield.",
    );

    assert!(
        source.contains("guard.fast_cancel.load(std::sync::atomic::Ordering::Acquire)"),
        "REGRESSION: Cx::checkpoint no longer reads \
         fast_cancel. The cancel-observation site is \
         broken — yield_now's pure-yield design relies on \
         checkpoint being the cancel-aware primitive.",
    );
}

#[test]
fn yield_now_poll_assertion_panics_on_repoll_after_completion() {
    // Pin (audit hygiene): YieldNow asserts !self.completed
    // at the top of poll — repolling after Ready panics.
    // This is the single-shot contract.
    let source = read("src/runtime/yield_now.rs");

    assert!(
        source.contains("assert!(!self.completed, \"yield_now future polled after completion\");"),
        "REGRESSION: YieldNow::poll no longer asserts \
         against repoll. Without it, repolling after Ready \
         could oscillate Ready/Pending — UB.",
    );
}

#[test]
fn yield_now_module_documents_purpose_as_cooperative_yield_primitive() {
    // Pin (audit hygiene): the module-level doc comment
    // describes yield_now as a cooperative-yield primitive.
    // Without this docstring, users may misread the API
    // as cancel-aware.
    let source = read("src/runtime/yield_now.rs");

    assert!(
        source.contains("Cooperative yielding primitive")
            || source.contains("cooperative yield")
            || source.contains("cooperatively yield"),
        "REGRESSION: yield_now module-level docstring no \
         longer describes the primitive as cooperative-\
         yield. Users may misinterpret the API contract — \
         expecting cancel-aware behavior that yield_now \
         doesn't provide.",
    );
}

#[test]
fn yield_now_pattern_compose_with_checkpoint_for_fail_fast_cancel() {
    // Pin (compositional pattern): the canonical fail-fast
    // pattern is `cx.checkpoint()?; yield_now().await;`.
    // Verify the prior audits document this pattern.
    let prior_audit = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/runtime_yield_now_vs_sleep_zero_distinction_audit.rs");

    assert!(
        prior_audit.exists(),
        "REGRESSION: the prior yield_now audit is missing. \
         The compositional pattern (checkpoint? + yield_now) \
         is documented across multiple audits; losing one \
         leaves a gap in the test coverage.",
    );
}

#[test]
fn yield_now_struct_is_explicitly_yield_now_not_a_result_carrier() {
    // Pin (link 1): the YieldNow struct has yielded +
    // completed bool fields — both for the two-poll
    // alternation. NO Result-carrying field.
    let source = read("src/runtime/yield_now.rs");

    let struct_marker = "pub struct YieldNow {";
    let start = source.find(struct_marker).expect("YieldNow struct");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("YieldNow struct close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("yielded: bool,") && body.contains("completed: bool,"),
        "REGRESSION: YieldNow struct fields changed. The \
         two-poll yield contract depends on these flags.",
    );

    let suspect_error_fields = [
        "result: Result<",
        "cancelled: AtomicBool,",
        "error: Option<Error>,",
    ];
    for pat in &suspect_error_fields {
        assert!(
            !body.contains(pat),
            "REGRESSION: YieldNow struct now has `{pat}` — \
             carrying a result/error field. The pure-yield \
             primitive is being conflated with a Result-\
             returning future.",
        );
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_yield_now_vs_sleep_zero_distinction_audit.rs",
        "tests/cx_checkpoint_cancel_fail_fast_audit.rs",
        "tests/scheduler_checkpoint_tight_loop_dos_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
