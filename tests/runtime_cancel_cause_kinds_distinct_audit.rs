//! Audit + regression test for distinguishability of cancel
//! causes — Deadline vs User vs ParentCancelled.
//!
//! Operator's question: "when a task is cancelled due to
//! deadline expiry vs explicit Cx::cancel() vs region drop,
//! are the three reasons distinguishable in the cancel-cause
//! chain?"
//!
//! Audit findings:
//!
//!   asupersync's `CancelKind` enum has **11 distinct
//!   variants** (types/cancel.rs:264). The operator's three
//!   scenarios map to three SEPARATE variants:
//!
//!   - **Deadline expiry** → `CancelKind::Deadline`
//!     (stamped by `checkpoint_budget_exhaustion` at
//!     cx/cx.rs:1962-1966 when `budget.is_past_deadline(now)`).
//!     The `Timeout` variant is also reserved for
//!     combinator-level timeouts (different code path).
//!
//!   - **Explicit `Cx::cancel()`** → `CancelKind::User`
//!     (created via `CancelReason::user(message)` at
//!     types/cancel.rs:612). User-initiated cancellation
//!     always carries this kind.
//!
//!   - **Region drop / parent close** →
//!     `CancelKind::ParentCancelled` (created via
//!     `CancelReason::parent_cancelled()` at
//!     types/cancel.rs:649). Used by
//!     `cancel_request`'s subtree walk for descendant
//!     regions (state.rs:2588).
//!
//!   The full enum (`CancelKind`):
//!     User, Timeout, Deadline, PollQuota, CostBudget,
//!     FailFast, RaceLost, ParentCancelled,
//!     ResourceUnavailable, Shutdown, LinkedExit.
//!
//!   These 11 variants give 11-way distinguishability for
//!   debugging — supervisors / audit logs / tracing can
//!   route on the kind without parsing strings.
//!
//!   Distinguishability propagates through the cause chain:
//!
//!   1. **`CancelReason.kind: CancelKind`** is the variant
//!      field on each chain link.
//!   2. **`CancelReason.cause: Option<Box<Self>>`** is the
//!      chain pointer to the next-deeper cause.
//!   3. **`root_cause()`** (cancel.rs:842) walks to the
//!      deepest cause — preserves the original kind.
//!   4. **`any_cause_is(kind)`** (cancel.rs:859) tests
//!      whether any chain link matches a kind — useful for
//!      "was this cancel triggered by a deadline anywhere?"
//!   5. **`caused_by(other)`** (cancel.rs:867) tests
//!      transitive causation by full reason match.
//!   6. **`is_budget_exhaustion()`** (cancel.rs:929) tests
//!      whether the kind is one of Deadline/PollQuota/
//!      CostBudget — a useful coarse-grained classification.
//!   7. **`is_timeout_related()`** (cancel.rs:937) tests
//!      whether the kind is Timeout or Deadline — bridges
//!      combinator-timeout and budget-deadline.
//!
//!   The cleanup-budget calibration also varies by kind
//!   (cancel.rs:1029-1042):
//!     - User: poll_quota=1000, priority=200
//!     - Timeout/Deadline: shorter cleanup
//!     - PollQuota/CostBudget: even shorter
//!     - FailFast/RaceLost/ParentCancelled/ResourceUnavailable
//!       /LinkedExit: poll_quota=200, priority=220
//!     - Shutdown: poll_quota=50, priority=255 (highest)
//!   So the kind drives observable behavior beyond just
//!   debugging — cleanup latency depends on it.
//!
//! Verdict: **SOUND**. The three operator-named scenarios
//! produce three DISTINCT CancelKind variants
//! (Deadline, User, ParentCancelled) that propagate
//! end-to-end through the cause chain. Plus 8 more
//! variants for the other documented causes. No conflation.
//!
//! No bead filed. The 11-way distinction is intentional
//! and well-tested.
//!
//! A regression that:
//!   - merged Deadline / PollQuota / CostBudget into a
//!     single `BudgetExhausted` variant (would lose the
//:     fine-grained which-budget signal),
//!   - merged User / Timeout into a single `External`
//!     variant (would conflate user-initiated with
//!     combinator-timeout — different debugging paths),
//!   - merged ParentCancelled / FailFast / RaceLost into
//:     a single `Cascaded` variant (would lose the
//!     why-was-the-parent-cancelled distinction),
//!   - changed checkpoint_budget_exhaustion to stamp
//!     a generic kind instead of Deadline/PollQuota/
//!     CostBudget per branch (cause-chain debugging
//!     loses the exhaustion-axis),
//!   - changed cancel_request to use User instead of
//!     ParentCancelled for descendants (would conflate
//!     user-initiated cancels with cascade-from-parent),
//!   - changed user() / parent_cancelled() / deadline()
//:     constructors to share a single CancelKind (would
//!     erase the 11-way distinction at the constructor
//!     boundary),
//! would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cancel_kind_enum_has_eleven_distinct_variants() {
    // Pin (link 1): CancelKind has 11 distinct variants.
    // Each variant represents a different cancellation
    // scenario; merging them would lose debugging
    // observability.
    let source = read("src/types/cancel.rs");

    let enum_marker = "pub enum CancelKind {";
    let start = source.find(enum_marker).expect("CancelKind enum");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("CancelKind enum close");
    let body = &source[start..start + body_end];

    let required_variants = [
        "User,",
        "Timeout,",
        "Deadline,",
        "PollQuota,",
        "CostBudget,",
        "FailFast,",
        "RaceLost,",
        "ParentCancelled,",
        "ResourceUnavailable,",
        "Shutdown,",
        "LinkedExit,",
    ];
    for variant in &required_variants {
        assert!(
            body.contains(variant),
            "REGRESSION: CancelKind variant `{variant}` is \
             gone. The operator's debugging contract requires \
             distinct variants for distinct causes; merging \
             would conflate scenarios.",
        );
    }
}

#[test]
fn cancel_kind_user_distinct_from_deadline_distinct_from_parent_cancelled() {
    // Pin (operator's three scenarios): the three named
    // scenarios produce three DIFFERENT enum variants. The
    // PartialEq impl on CancelKind makes them distinguishable
    // via direct equality.
    let source = read("src/types/cancel.rs");

    // The enum derives PartialEq + Eq so variants are
    // distinguishable.
    let enum_decl_idx = source
        .find("pub enum CancelKind {")
        .expect("CancelKind enum");
    let preceding_attrs = &source[enum_decl_idx.saturating_sub(200)..enum_decl_idx];

    assert!(
        preceding_attrs.contains("PartialEq")
            && preceding_attrs.contains("Eq"),
        "REGRESSION: CancelKind no longer derives PartialEq + \
         Eq. Variants can't be compared via == — debugging \
         consumers must downcast or pattern-match for any \
         comparison, breaking the simple `if kind == \
         CancelKind::User` ergonomic.",
    );

    // The three target variants must exist in the enum.
    assert!(
        source.contains("User,") && source.contains("Deadline,")
            && source.contains("ParentCancelled,"),
        "REGRESSION: one of User / Deadline / ParentCancelled \
         missing from CancelKind. The operator's three \
         scenarios lose distinguishability.",
    );
}

#[test]
fn cancel_reason_user_constructor_stamps_user_kind() {
    // Pin (operator scenario 2): explicit Cx::cancel() goes
    // through CancelReason::user(message) which stamps
    // CancelKind::User.
    let source = read("src/types/cancel.rs");

    let fn_marker = "pub fn user(message: &'static str) -> Self {";
    let start = source.find(fn_marker).expect("user fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("user close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("kind: CancelKind::User,"),
        "REGRESSION: CancelReason::user no longer stamps \
         CancelKind::User. Explicit user-initiated cancels \
         lose their distinguishing kind — debugging can no \
         longer tell user-cancel from other causes.",
    );

    assert!(
        body.contains("message: Some(message.to_string()),"),
        "REGRESSION: CancelReason::user no longer carries \
         the user-provided message. The 'why did the user \
         cancel?' information is lost.",
    );
}

#[test]
fn cancel_reason_macro_constructors_include_deadline_and_parent_cancelled() {
    // Pin (operator scenarios 1+3): the cancel_reason_constructors
    // macro generates `deadline() -> Deadline` and
    // `parent_cancelled() -> ParentCancelled` constructors.
    // Without these, the three operator scenarios lose
    // their constructor entry points.
    let source = read("src/types/cancel.rs");

    let macro_marker = "cancel_reason_constructors! {";
    let start = source.find(macro_marker).expect("constructors macro");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("constructors macro close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("deadline => Deadline;"),
        "REGRESSION: deadline() constructor is gone. \
         Code paths that detect deadline-budget exhaustion \
         lose their canonical constructor — may use \
         Timeout or some other variant, conflating scenarios.",
    );

    assert!(
        body.contains("parent_cancelled => ParentCancelled;"),
        "REGRESSION: parent_cancelled() constructor is gone. \
         The cancel_request subtree walk loses its \
         canonical constructor — may stamp User or another \
         variant, conflating with user-initiated cancels.",
    );

    // Other budget-exhaustion constructors must also exist.
    assert!(
        body.contains("poll_quota => PollQuota;")
            && body.contains("cost_budget => CostBudget;")
            && body.contains("timeout => Timeout;"),
        "REGRESSION: one of poll_quota / cost_budget / \
         timeout constructors is gone. Budget-axis \
         distinguishability is degraded.",
    );

    // The shutdown / fail_fast / race_loser / linked_exit /
    // resource_unavailable constructors round out the 11-way
    // set.
    assert!(
        body.contains("shutdown => Shutdown;")
            && body.contains("fail_fast => FailFast;")
            && body.contains("race_loser => RaceLost;")
            && body.contains("linked_exit => LinkedExit;")
            && body.contains("resource_unavailable => ResourceUnavailable;"),
        "REGRESSION: one of the 8 secondary constructors is \
         gone. Debugging observability is degraded.",
    );
}

#[test]
fn checkpoint_budget_exhaustion_stamps_deadline_kind_for_past_deadline() {
    // Pin (operator scenario 1): when a task hits its
    // deadline, checkpoint_budget_exhaustion stamps
    // CancelKind::Deadline (NOT Timeout, NOT a generic
    // BudgetExhausted). This is what makes
    // deadline-vs-poll-quota-vs-cost-budget distinguishable.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn checkpoint_budget_exhaustion(";
    let start = source.find(fn_marker).expect("checkpoint_budget_exhaustion fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("checkpoint_budget_exhaustion close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("CancelKind::Deadline"),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         stamps CancelKind::Deadline. Deadline-induced \
         cancels lose their distinguishing kind — \
         indistinguishable from PollQuota / CostBudget.",
    );

    assert!(
        body.contains("CancelKind::PollQuota"),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         stamps CancelKind::PollQuota for poll exhaustion.",
    );

    assert!(
        body.contains("CancelKind::CostBudget"),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         stamps CancelKind::CostBudget for cost exhaustion.",
    );
}

#[test]
fn cancel_request_subtree_walk_stamps_parent_cancelled_for_descendants() {
    // Pin (operator scenario 3): the subtree walk in
    // state.rs cancel_request stamps
    // CancelReason::parent_cancelled() for descendants —
    // distinguishing them from user-initiated cancels at
    // the root.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("CancelReason::parent_cancelled()"),
        "REGRESSION: cancel_request no longer stamps \
         parent_cancelled() on descendants. The cascade-\
         from-parent kind is lost — descendants look like \
         direct user-initiated cancels.",
    );
}

#[test]
fn cancel_reason_chain_preserves_kind_via_box_self_pointer() {
    // Pin (chain preservation): the cause: Option<Box<Self>>
    // chain pointer preserves each link's kind. Without it,
    // multi-level cascades lose attribution.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub cause: Option<Box<Self>>,"),
        "REGRESSION: CancelReason.cause field is gone. The \
         cause chain can't preserve per-link kinds — \
         cascading cancellations lose attribution at every \
         level.",
    );
}

#[test]
fn cancel_reason_root_cause_walks_chain_preserving_original_kind() {
    // Pin (chain helper): root_cause walks the cause chain
    // to the deepest level. The deepest level is the
    // ORIGINAL trigger — its kind is what supervisors /
    // audit consumers want to see.
    let source = read("src/types/cancel.rs");

    let fn_marker = "pub fn root_cause(&self) -> &Self {";
    let start = source.find(fn_marker).expect("root_cause fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("root_cause close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("while let Some(ref cause) = current.cause {"),
        "REGRESSION: root_cause no longer walks the cause \
         chain. The deepest-original-kind information is \
         lost — supervisors see only the immediate cause, \
         not the underlying trigger.",
    );
}

#[test]
fn cancel_reason_any_cause_is_predicate_for_kind_membership_check() {
    // Pin (chain helper): any_cause_is(kind) tests whether
    // any chain link matches a given kind. Useful for
    // queries like "was this cancel triggered by a deadline
    // anywhere in the chain?"
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub fn any_cause_is(&self, kind: CancelKind) -> bool {"),
        "REGRESSION: any_cause_is helper is gone. \
         Consumers can't easily query 'was this triggered \
         by Deadline at any depth?' — must walk the chain \
         manually.",
    );
}

#[test]
fn cancel_reason_classification_helpers_preserve_axis_distinguishability() {
    // Pin (audit hygiene): is_budget_exhaustion and
    // is_timeout_related help group related kinds without
    // erasing the underlying distinction. They classify
    // (Deadline/PollQuota/CostBudget) as budget-exhaustion
    // but the underlying kind is still queryable.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("CancelKind::Deadline | CancelKind::PollQuota | CancelKind::CostBudget"),
        "REGRESSION: is_budget_exhaustion no longer matches \
         all three budget-axis kinds. The classification \
         helper drifts from the enum — consumers may miss \
         a budget-exhaustion event.",
    );

    assert!(
        source.contains("CancelKind::Timeout | CancelKind::Deadline"),
        "REGRESSION: is_timeout_related no longer bridges \
         Timeout (combinator) and Deadline (budget). \
         Consumers can't easily query 'time-related' \
         cancels.",
    );
}

#[test]
fn cleanup_budget_varies_by_cancel_kind_for_calibrated_drain() {
    // Pin (audit hygiene): cleanup_budget returns a
    // priority + poll_quota that varies by kind. This is
    // observable behavior beyond just debugging — kind
    // drives cleanup latency.
    let source = read("src/types/cancel.rs");

    // The match arm by kind must still classify into bands.
    assert!(
        source.contains("CancelKind::User =>")
            && source.contains("CancelKind::Shutdown =>"),
        "REGRESSION: cleanup_budget no longer dispatches by \
         kind. Cleanup priority/quota becomes uniform — \
         user-cancel and shutdown have the same bound, \
         losing the prioritization that lets shutdown \
         preempt user-cancel cleanup.",
    );

    // Shutdown gets the highest priority (255).
    assert!(
        source.contains("CancelKind::Shutdown => Budget::new().with_poll_quota(50).with_priority(255)"),
        "REGRESSION: Shutdown cleanup_budget no longer has \
         priority=255. Shutdown loses its scheduler-priority \
         override — runtime teardown becomes preemptible by \
         user cleanup.",
    );
}

#[test]
fn cancel_kind_derives_for_audit_logging_tracing() {
    // Pin (audit hygiene): CancelKind derives Debug, Clone,
    // Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize,
    // Deserialize. The derives are what let the kind be
    // logged, hashed, sorted, and serialized — full
    // audit-trail observability.
    let source = read("src/types/cancel.rs");

    let enum_decl_idx = source
        .find("pub enum CancelKind {")
        .expect("CancelKind enum");
    let preceding = &source[enum_decl_idx.saturating_sub(300)..enum_decl_idx];

    let required_derives = [
        "Debug",
        "Clone",
        "Copy",
        "PartialEq",
        "Eq",
        "Hash",
        "Serialize",
        "Deserialize",
    ];
    for derive in &required_derives {
        assert!(
            preceding.contains(derive),
            "REGRESSION: CancelKind no longer derives \
             {derive}. Audit logging / trace serialization / \
             hash-based deduplication may break.",
        );
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_cancel_cause_chain_depth_audit.rs",
        "tests/cx_checkpoint_budget_exhausted_yield_audit.rs",
        "tests/runtime_region_close_idempotency_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
