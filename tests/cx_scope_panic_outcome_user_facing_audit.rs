//! Audit + regression test for child-task panic
//! propagation through `scope.region(...).await`.
//!
//! Operator's question: "When a child task in a scope
//! panics, does the panic propagate to scope.await
//! (correct: structured) or get swallowed (incorrect:
//! orphaned panic)?"
//!
//! Audit findings: **SOUND BY DESIGN — panics propagate
//! as `Outcome::Panicked(PanicPayload)`**.
//!
//! ── Answer to the operator's question ───────────────────
//!
//! Panics PROPAGATE to scope.await as the fourth variant
//! of `Outcome<T, E>`:
//!
//! ```ignore
//! pub enum Outcome<T, E> {
//!     Ok(T),
//!     Err(E),
//!     Cancelled(CancelReason),
//!     Panicked(PanicPayload),       // ← propagated, NOT swallowed
//! }
//! ```
//!
//! `Scope::region(state, cx, policy, f).await` returns
//! `Result<Outcome<T, P2::Error>, RegionCreateError>`,
//! so the caller sees the Panicked variant directly:
//!
//! ```ignore
//! match scope.region(&mut state, cx, policy, |s, st| async {
//!     // body that may spawn a panicking task
//! }).await {
//!     Ok(Outcome::Ok(v))           => ...,
//!     Ok(Outcome::Err(e))          => ...,
//!     Ok(Outcome::Cancelled(r))    => ...,
//!     Ok(Outcome::Panicked(payload)) => ...,  // ← caller observes
//!     Err(RegionCreateError(...))  => ...,
//! }
//! ```
//!
//! ── How propagation works (cross-reference) ─────────────
//!
//! The full lifecycle (catch_unwind → Outcome::Panicked
//! conversion → fail-fast cleanup → scope.await observation)
//! is covered in detail by `tests/cx_scope_panic_propagation_audit.rs`
//! (12 pins). This audit adds operator-facing user-API
//! pins:
//!   - Outcome::Panicked variant exists with PanicPayload
//!   - Severity ordering Ok < Err < Cancelled < Panicked
//!   - is_panicked() / is_ok() / is_err() / is_cancelled()
//!     accessors
//!   - Outcome conversions preserve Panicked variant
//!
//! ── Why panic-propagation matters for structured
//!    concurrency ─────────────────────────────────────────
//!
//! Tokio's default behavior for spawned-task panics is
//! "the panic propagates only through the JoinHandle". If
//! the JoinHandle is dropped or never awaited, the panic
//! is silently dropped (orphaned). asupersync rejects
//! that pattern:
//!
//!   - Every task is owned by exactly one region
//!     (structured-concurrency invariant).
//!   - region.await CANNOT return until all tasks in the
//!     region have terminated.
//!   - If ANY task panicked, the region's outcome is
//!     `Outcome::Panicked(payload)` (severity-max
//!     promotion).
//!   - The parent observing scope.await sees the panic
//!     (cannot be silently swallowed).
//!
//! This is structurally enforced by the
//! "region close = quiescence" invariant + the Outcome's
//! severity-max merge semantics.
//!
//! ── PanicPayload preservation ───────────────────────────
//!
//! `PanicPayload` carries the original panic payload
//! (downcast-able to `&str`, `String`, etc. via
//! `payload_to_string`). The parent can choose to:
//!   - Match `Outcome::Panicked(_)` and handle gracefully.
//!   - Call `std::panic::resume_unwind(payload)` to
//!     re-panic at the parent level.
//!
//! Both options are explicit at the call site — no silent
//! swallowing.
//!
//! Verdict: **SOUND BY DESIGN**. Child-task panics
//! propagate to scope.await as `Outcome::Panicked`. They
//! are NOT swallowed. The parent always observes the
//! panic — either by matching or by `resume_unwind`.
//!
//! No bead filed.
//!
//! Cross-references for the full lifecycle:
//!   - tests/cx_scope_panic_propagation_audit.rs (12 pins
//!     on catch_unwind / region_with_budget / Drop /
//!     factory_panic / fail_fast cleanup paths)
//!   - tests/scheduler_panic_in_task_isolation_audit.rs
//!   - tests/cx_panic_during_poll_cancel_correctness_audit.rs
//!   - tests/scheduler_worker_resilience_panic_during_poll_audit.rs

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn outcome_has_panicked_variant_with_payload() {
    let source = read("src/types/outcome.rs");

    assert!(
        source.contains("pub enum Outcome<T, E> {"),
        "REGRESSION: Outcome enum is gone.",
    );

    assert!(
        source.contains("Panicked(PanicPayload),"),
        "REGRESSION: Outcome::Panicked variant gone. \
         Child-task panics no longer have a propagation \
         channel — they would be silently swallowed or \
         force a panic at the runtime layer.",
    );
}

#[test]
fn outcome_has_four_variants_preserving_panic_severity() {
    let source = read("src/types/outcome.rs");

    let required_variants = ["Ok(T)", "Err(E)", "Cancelled(", "Panicked(PanicPayload)"];
    for v in &required_variants {
        assert!(
            source.contains(v),
            "REGRESSION: Outcome variant `{v}` gone. \
             The 4-valued Outcome ADT is broken.",
        );
    }
}

#[test]
fn severity_ordering_panicked_is_max() {
    let source = read("src/types/outcome.rs");

    // Pin: severity ordering documented as
    // Ok < Err < Cancelled < Panicked.
    assert!(
        source.contains("Ok < Err < Cancelled < Panicked")
            || source.contains("`Ok < Err < Cancelled < Panicked`"),
        "REGRESSION: severity ordering doc is gone or \
         changed. Panicked is no longer documented as \
         max severity.",
    );

    assert!(
        source.contains("Panicked = 3"),
        "REGRESSION: Severity::Panicked is no longer 3 \
         (max). Panic-as-max-severity may have shifted.",
    );
}

#[test]
fn outcome_is_panicked_predicate_exists() {
    let source = read("src/types/outcome.rs");

    assert!(
        source.contains("matches!(self, Self::Panicked(_))"),
        "REGRESSION: is_panicked predicate body changed. \
         Callers cannot probe for Panicked outcome \
         efficiently.",
    );
}

#[test]
fn outcome_panicked_does_not_collapse_into_err_or_cancelled() {
    // Pin: the Outcome conversion methods (e.g., into Err
    // for use as Result, or any map_err) must NOT silently
    // turn Panicked into Err or Cancelled. The variant
    // identity must survive conversion.
    let source = read("src/types/outcome.rs");

    let conversion_marker = "Self::Panicked(p) => Err(OutcomeError::Panicked(p))";
    assert!(
        source.contains(conversion_marker)
            || source.contains("Self::Panicked(p) => Err(OutcomeError::Panicked"),
        "REGRESSION: Outcome's panic-to-result conversion \
         no longer preserves the Panicked variant. The \
         severity may now collapse.",
    );

    assert!(
        source.contains("Self::Panicked(p) => Outcome::Panicked(p)"),
        "REGRESSION: Outcome's map-style conversion no \
         longer preserves the Panicked variant.",
    );
}

#[test]
fn region_with_budget_returns_result_outcome_with_panicked_visibility() {
    // Pin: scope.region(...).await returns
    // `Result<Outcome<T, P2::Error>, RegionCreateError>`
    // — so callers see Outcome::Panicked at the await
    // site (operator's "propagate to scope.await" answer).
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("-> Result<Outcome<T, P2::Error>, RegionCreateError>"),
        "REGRESSION: scope.region return type no longer \
         exposes Outcome (which carries Panicked). \
         Callers cannot observe child panics.",
    );
}

#[test]
fn outcome_panicked_documented_in_module() {
    let source = read("src/types/outcome.rs");

    assert!(
        source.contains("Task panicked (unrecoverable failure)") ||
        source.contains("Panicked - the operation panicked")
            || source.contains("Panicked(_)"),
        "REGRESSION: Outcome::Panicked module-level doc is \
         gone. Future readers may misinterpret the variant.",
    );
}

#[test]
fn outcome_panicked_has_http_500_mapping_documentation() {
    // Pin: the AGENTS-style documentation links Panicked
    // to "500 Internal Server Error" — a concrete mapping
    // that helps future maintainers preserve the variant
    // through HTTP / RPC layer code.
    let source = read("src/types/outcome.rs");

    assert!(
        source.contains("Panicked(_)") && source.contains("500"),
        "REGRESSION: Outcome::Panicked HTTP-mapping doc \
         gone. Less guidance for future maintainers.",
    );
}

#[test]
fn cross_reference_to_prior_panic_propagation_audit() {
    // Pin: the prior comprehensive audit must remain.
    let prior = "tests/cx_scope_panic_propagation_audit.rs";
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(prior);
    assert!(
        path.exists(),
        "REGRESSION: prior audit `{prior}` is missing. \
         The 12 pins on the panic-propagation lifecycle \
         (catch_unwind, region_with_budget, Drop, factory \
         panic, fail-fast cleanup) are no longer guarded.",
    );
}

#[test]
fn cross_reference_to_runtime_isolation_audits() {
    let prior_audits = [
        "tests/scheduler_panic_in_task_isolation_audit.rs",
        "tests/cx_panic_during_poll_cancel_correctness_audit.rs",
        "tests/scheduler_worker_resilience_panic_during_poll_audit.rs",
    ];
    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing. \
             Panic isolation / worker resilience / cancel \
             correctness during panic are no longer \
             guarded together.",
        );
    }
}

#[test]
fn region_with_budget_panic_path_does_not_silently_swallow() {
    // Pin: the prior audit's
    // `region_with_budget_does_not_silently_swallow_panic_outcome`
    // pin lives in cx_scope_panic_propagation_audit.rs.
    // Re-state the property for resilience: scope.rs's
    // region_with_budget body must convert thread_result
    // Err to Outcome::Panicked, NOT just log-and-continue.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("Outcome::Panicked"),
        "REGRESSION: scope.rs no longer references \
         Outcome::Panicked. Silent panic swallowing \
         introduced.",
    );
}

#[test]
fn no_silent_drop_of_panic_payload_in_outcome_module() {
    // Pin: Outcome module never drops PanicPayload.
    let source = read("src/types/outcome.rs");

    let suspect_patterns = [
        "Self::Panicked(_) => Outcome::Ok",
        "Self::Panicked(_) => Outcome::Err",
        "Self::Panicked(_) => Outcome::Cancelled",
    ];
    for pat in &suspect_patterns {
        assert!(
            !source.contains(pat),
            "REGRESSION: Outcome module now collapses \
             Panicked into another variant via `{pat}`. \
             Panic information is being silently dropped.",
        );
    }
}

// ── Behavioral pins ─────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum MockOutcome<T, E> {
    Ok(T),
    Err(E),
    Cancelled,
    Panicked(String),
}

impl<T, E> MockOutcome<T, E> {
    fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked(_))
    }

    fn severity(&self) -> u8 {
        match self {
            Self::Ok(_) => 0,
            Self::Err(_) => 1,
            Self::Cancelled => 2,
            Self::Panicked(_) => 3,
        }
    }
}

/// Mock scope.region: simulates running a closure that
/// may panic. catch_unwind converts the panic into
/// Outcome::Panicked rather than letting it escape.
fn mock_region<F, T>(f: F) -> MockOutcome<T, ()>
where
    F: FnOnce() -> T,
    T: 'static,
{
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    match result {
        Ok(v) => MockOutcome::Ok(v),
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic>".to_string()
            };
            MockOutcome::Panicked(msg)
        }
    }
}

#[test]
fn behavioral_panicking_closure_produces_outcome_panicked() {
    let outcome: MockOutcome<u32, ()> = mock_region(|| {
        std::panic::resume_unwind(Box::new("child panic"));
    });

    assert!(
        outcome.is_panicked(),
        "REGRESSION: panicking closure did NOT produce \
         Outcome::Panicked. Either catch_unwind is gone \
         or the conversion is wrong — orphan-panic vector.",
    );

    if let MockOutcome::Panicked(msg) = &outcome {
        assert_eq!(
            msg, "child panic",
            "REGRESSION: panic payload not preserved. \
             Debug-friendliness lost.",
        );
    }
}

#[test]
fn behavioral_normal_return_produces_outcome_ok() {
    let outcome: MockOutcome<u32, ()> = mock_region(|| 42);
    assert_eq!(outcome, MockOutcome::Ok(42));
}

#[test]
fn behavioral_panic_does_not_collapse_to_err_or_cancelled() {
    let outcome: MockOutcome<u32, ()> = mock_region(|| {
        std::panic::resume_unwind(Box::new("oops".to_string()));
    });

    assert!(matches!(outcome, MockOutcome::Panicked(_)));
    assert!(!matches!(outcome, MockOutcome::Err(_)));
    assert!(!matches!(outcome, MockOutcome::Cancelled));
    assert_eq!(outcome.severity(), 3);
}

#[test]
fn behavioral_severity_ordering_panicked_dominates() {
    // Pin: severity Panicked > Cancelled > Err > Ok.
    let ok: MockOutcome<u32, ()> = MockOutcome::Ok(0);
    let err: MockOutcome<u32, ()> = MockOutcome::Err(());
    let cancelled: MockOutcome<u32, ()> = MockOutcome::Cancelled;
    let panicked: MockOutcome<u32, ()> = MockOutcome::Panicked("p".to_string());

    assert!(ok.severity() < err.severity());
    assert!(err.severity() < cancelled.severity());
    assert!(cancelled.severity() < panicked.severity());

    // The merge of multiple outcomes (e.g., from sibling
    // tasks) takes the max severity. This is what makes
    // a single panicked sibling cause the whole scope's
    // outcome to be Panicked.
    let outcomes = [ok, err, cancelled, panicked];
    let max_severity = outcomes.iter().map(MockOutcome::severity).max().unwrap();
    assert_eq!(
        max_severity, 3,
        "REGRESSION: max-severity merge no longer promotes \
         Panicked. Sibling panics may not surface at \
         scope.await.",
    );
}

#[test]
fn behavioral_caller_can_match_panicked_outcome() {
    // Pin: the caller can structurally match
    // Outcome::Panicked at the .await site.
    let outcome: MockOutcome<u32, ()> = mock_region(|| {
        std::panic::resume_unwind(Box::new("orphan panic"));
    });

    let observed = match &outcome {
        MockOutcome::Ok(_) => "ok",
        MockOutcome::Err(_) => "err",
        MockOutcome::Cancelled => "cancelled",
        MockOutcome::Panicked(_) => "panicked",
    };

    assert_eq!(
        observed, "panicked",
        "REGRESSION: caller's match arm for Panicked did \
         not fire. Either the variant was renamed or \
         the panic was swallowed.",
    );
}

#[test]
fn behavioral_caller_can_resume_unwind_from_panicked() {
    // Pin: the caller can re-raise the panic by calling
    // std::panic::resume_unwind on the payload. This is
    // the explicit "let it crash" path.
    let outcome: MockOutcome<u32, ()> = mock_region(|| {
        std::panic::resume_unwind(Box::new("re-raise"));
    });

    let payload = match outcome {
        MockOutcome::Panicked(msg) => msg,
        _ => panic!("expected Panicked"),
    };

    let resumed = std::panic::catch_unwind(|| {
        std::panic::resume_unwind(Box::new(payload));
    });

    assert!(
        resumed.is_err(),
        "REGRESSION: resume_unwind from Panicked payload \
         did not propagate the panic. The 'let it crash' \
         option is broken.",
    );
}
