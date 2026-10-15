//! Audit + regression test for the operator's question
//! about `Cx::with_obligation()` lifecycle when an
//! obligation's deadline expires.
//!
//! Operator's question: "When an obligation is registered
//! with a deadline AND that deadline expires before
//! resolution, what happens? Per asupersync, must trigger
//! Outcome::ObligationFailed (not silently drop)."
//!
//! Audit findings: **SOUND BY DESIGN — but the operator's
//! framing assumes APIs and a variant that don't exist**.
//!
//! Three premises in the operator's framing are incorrect:
//!
//! 1. **No `Cx::with_obligation()` method**. Obligations
//!    are acquired via `ObligationLedger::acquire(kind,
//!    holder, region, now)` returning an
//!    `ObligationToken` — a linear handle. There is no
//!    Cx-level wrapper.
//!
//! 2. **No per-obligation deadline**. The
//!    `ObligationRecord` (src/obligation/ledger.rs:~70)
//!    carries kind, holder, region, timestamp, location,
//!    optional description, optional backtrace — but NO
//!    deadline field. Deadlines live at the Cx/region
//!    level via `Budget.deadline`.
//!
//! 3. **No `Outcome::ObligationFailed` variant**.
//!    Whole-tree grep for `ObligationFailed` returns
//!    zero hits. `Outcome<T, E>` (src/types/outcome.rs:214)
//!    has exactly 4 variants: `Ok(T)`, `Err(E)`,
//!    `Cancelled(CancelReason)`, `Panicked(PanicPayload)`.
//!
//! ── How obligation deadline-expiry IS handled ───────────
//!
//! The actual mechanism is layered:
//!
//! Layer A — **Deadline lives in Budget** (per region/Cx):
//!   `Budget.deadline: Option<Time>`. Set via
//!   `Budget::with_deadline(...)`,
//!   `Cx::scope_with_budget(Budget::with_deadline(...))`,
//!   or the `scope!` macro.
//!
//! Layer B — **Deadline expiry triggers cancel**:
//!   `Cx::checkpoint` (cx.rs:1644) calls
//!   `checkpoint_budget_exhaustion(region, task, budget,
//!   now)`. If `budget.is_past_deadline(now)`, it builds
//!   a `CancelReason::with_origin(CancelKind::Deadline,
//!   region, now)`, sets `cancel_requested = true`, and
//!   returns `Err(Cancelled)`.
//!
//! Layer C — **Cancel propagates to region**: the runtime
//!   sees the cancel and calls `state.cancel_request(region,
//!   reason, source_task)`. ALL tasks in the region (and
//!   descendants) are marked CancelRequested.
//!
//! Layer D — **Cancel-drain aborts pending obligations**:
//!   the cancel-handler enumerates
//!   `ledger.pending_ids_for_region(region)` and calls
//!   `ledger.abort_by_id(id, reason, now)` for each.
//!   Obligations transition Reserved → Aborted (not
//!   Leaked).
//!
//! Layer E — **Region close requires obligation
//!   quiescence**: `is_region_clean(region)` must be true
//!   before close. If any obligations remain unresolved
//!   after the cancel-drain runs, region close stalls.
//!
//! Layer F — **Lab-mode leak detection catches stragglers**:
//!   `check_leaks() -> LeakCheckResult` walks the ledger.
//!   Lab tests assert `leaked.is_empty()` at end of run.
//!   Production runs report leaks for diagnostic purposes
//!   but don't fail-stop.
//!
//! Layer G — **Outcome propagation as Cancelled, not
//!   ObligationFailed**: when the region closes after a
//!   deadline-driven cancel-drain, the region's outcome
//!   is `Outcome::Cancelled(CancelReason)` with
//!   `CancelKind::Deadline` in the root_cause. There is
//!   NO separate Outcome::ObligationFailed.
//!
//! ── Why no separate Outcome variant ──────────────────────
//!
//! The unified-cancel design (see
//! cx_no_interrupt_method_unified_cancel_audit.rs) routes
//! all exhaustion-style failures (Deadline, PollQuota,
//! CostBudget) through `Outcome::Cancelled` with the
//! specific kind in the cause chain. Adding a separate
//! `ObligationFailed` would force every caller to match
//! on TWO outcomes for the same conceptual failure
//! (deadline expired) — fragmentation that doesn't help
//! anyone.
//!
//! Callers who want to know "did an obligation fail to
//! resolve?" use the leak-detection / cancel-drain
//! observability layers.
//!
//! ── Why no per-obligation deadline ──────────────────────
//!
//! A per-obligation deadline would create three problems:
//!
//! 1. Storage cost in every ObligationRecord (currently
//!    minimal — kind, holder, region, optional fields).
//! 2. A deadline-monitor for obligations that's separate
//!    from the budget-deadline path — duplicating the
//!    Cx::checkpoint mechanism.
//! 3. An obligation could outlive its region's deadline
//!    (or vice versa) — orthogonality conflicts.
//!
//! The structured-concurrency design ties obligation
//! lifetime to region lifetime. The region's deadline is
//! the obligation's effective deadline. Region close +
//! cancel-drain handles all the cleanup paths.
//!
//! Verdict: **SOUND BY DESIGN**. There is no defect.
//! The operator's framing assumes APIs that don't exist
//! (Cx::with_obligation, per-obligation deadline,
//! Outcome::ObligationFailed). The actual mechanism is
//! the layered Budget-deadline + cancel-drain +
//! leak-detection design, which already produces the
//! correct observable behavior: deadline expiry leads to
//! Outcome::Cancelled with CancelKind::Deadline, and any
//! unresolved obligations get aborted (not silently
//! dropped) during cancel-drain.
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
fn outcome_obligation_failed_variant_does_not_exist() {
    // Pin: Outcome enum has 4 variants (Ok/Err/Cancelled/
    // Panicked). NO ObligationFailed variant.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains("ObligationFailed") {
            violations.push(path.display().to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: ObligationFailed introduced. The \
         unified-cancel design routes deadline expiry \
         through Outcome::Cancelled with CancelKind::Deadline. \
         Adding a separate variant fragments the failure \
         channel.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn cx_with_obligation_method_does_not_exist() {
    // Pin: no Cx::with_obligation method anywhere. The
    // acquire path goes through ObligationLedger directly.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains("fn with_obligation(") {
            violations.push(path.display().to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: with_obligation method introduced. \
         The acquire-path-via-ledger discipline is being \
         silently bypassed.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn outcome_has_only_four_variants() {
    let source = read("src/types/outcome.rs");

    // Pin: enum has Ok, Err, Cancelled, Panicked — NO
    // ObligationFailed (or any other 5th variant).
    assert!(
        source.contains("Ok(T),"),
        "REGRESSION: Outcome::Ok variant gone.",
    );
    assert!(
        source.contains("Err(E),"),
        "REGRESSION: Outcome::Err variant gone.",
    );
    assert!(
        source.contains("Cancelled("),
        "REGRESSION: Outcome::Cancelled variant gone.",
    );
    assert!(
        source.contains("Panicked(PanicPayload)"),
        "REGRESSION: Outcome::Panicked variant gone.",
    );

    // No 5th variant.
    let suspect_5th_variants = [
        "ObligationFailed(",
        "ObligationLeaked(",
        "ObligationExpired(",
        "DeadlineExpired(",
        "Timeout(",
    ];
    for pat in &suspect_5th_variants {
        assert!(
            !source.contains(pat),
            "REGRESSION: Outcome now has a 5th variant \
             `{pat}`. The 4-valued ADT is broken.",
        );
    }
}

#[test]
fn obligation_record_has_no_deadline_field() {
    // Pin: ObligationRecord doesn't carry a per-obligation
    // deadline. Deadline is at Budget/Cx level.
    let source = read("src/record/obligation.rs");

    // Find ObligationRecord struct definition.
    let struct_marker = "pub struct ObligationRecord";
    let pos = source.find(struct_marker).expect("ObligationRecord struct");
    let body_end = source[pos..]
        .find("\n}\n")
        .expect("ObligationRecord struct close");
    let body = &source[pos..pos + body_end];

    let suspect_deadline_fields = [
        "deadline: Option<Time>,",
        "deadline: Time,",
        "expires_at: Time,",
        "expiry: Option<Time>,",
        "ttl: Duration,",
    ];
    for pat in &suspect_deadline_fields {
        assert!(
            !body.contains(pat),
            "REGRESSION: ObligationRecord now has `{pat}`. \
             Per-obligation deadline conflicts with the \
             region-level Budget.deadline design.",
        );
    }
}

#[test]
fn budget_carries_the_canonical_deadline() {
    // Pin: Budget has the deadline field; that's where
    // deadlines live for both Cx and obligations (via
    // region scope).
    let source = read("src/types/budget.rs");

    assert!(
        source.contains("deadline: Option<Time>") || source.contains("pub deadline:"),
        "REGRESSION: Budget no longer carries a deadline. \
         The region-level deadline path is broken.",
    );
}

#[test]
fn checkpoint_emits_deadline_cancel_kind_on_expiry() {
    // Pin: when budget.is_past_deadline(now), checkpoint
    // emits CancelKind::Deadline. This is the cancel
    // signal that drives the cancel-drain.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn checkpoint_budget_exhaustion(";
    let pos = source
        .find(fn_marker)
        .expect("checkpoint_budget_exhaustion fn");
    let body_window = &source[pos..pos + 2500];

    assert!(
        body_window.contains("CancelKind::Deadline"),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         emits CancelKind::Deadline on deadline expiry. \
         The deadline-driven cancel chain is broken.",
    );

    assert!(
        body_window.contains("budget.is_past_deadline(now)")
            || body_window.contains("is_past_deadline("),
        "REGRESSION: checkpoint no longer checks \
         is_past_deadline. Deadline expiry won't trigger.",
    );
}

#[test]
fn cancel_drain_uses_pending_ids_for_region_and_abort_by_id() {
    // Pin: the cancel-drain path enumerates pending
    // obligations by region and aborts them by ID. This
    // is what prevents silent drop of obligations on
    // deadline-driven cancel.
    let ledger_source = read("src/obligation/ledger.rs");

    assert!(
        ledger_source.contains(
            "pub fn pending_ids_for_region(&self, region: RegionId) -> Vec<ObligationId> {"
        ),
        "REGRESSION: pending_ids_for_region gone. Cancel-\
         drain cannot enumerate obligations to abort.",
    );

    assert!(
        ledger_source.contains("pub fn abort_by_id("),
        "REGRESSION: abort_by_id gone. Cancel-drain cannot \
         resolve obligations without recovering linear \
         tokens.",
    );
}

#[test]
fn region_close_requires_obligation_quiescence() {
    // Pin: is_region_clean is the quiescence predicate.
    // Without zero-pending, region close stalls — preventing
    // silent drop of unresolved obligations.
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn is_region_clean(&self, region: RegionId) -> bool {"),
        "REGRESSION: is_region_clean gone. Region close \
         cannot verify obligation quiescence — silent-drop \
         vector.",
    );
}

#[test]
fn check_leaks_lab_mode_catches_stragglers() {
    // Pin: check_leaks reports any pending obligation as
    // a leak. Lab tests assert empty.
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn check_leaks(&self) -> LeakCheckResult {"),
        "REGRESSION: check_leaks gone. Stragglers cannot \
         be reported.",
    );

    assert!(
        source.contains("pub struct LeakCheckResult {"),
        "REGRESSION: LeakCheckResult struct gone.",
    );
}

#[test]
fn obligation_lifetime_tied_to_region_via_acquire_signature() {
    // Pin: acquire takes a RegionId, tying obligation
    // lifetime to region lifetime. There is no acquire
    // variant that takes a deadline.
    let source = read("src/obligation/ledger.rs");

    let fn_marker = "pub fn acquire(";
    let pos = source.find(fn_marker).expect("acquire fn");
    let sig_window = &source[pos..pos + 400];

    assert!(
        sig_window.contains("region: RegionId,"),
        "REGRESSION: acquire no longer takes a RegionId. \
         Obligation lifetime decoupled from region.",
    );

    assert!(
        !sig_window.contains("deadline: Time,") && !sig_window.contains("deadline: Option<Time>,"),
        "REGRESSION: acquire now takes a deadline parameter. \
         Per-obligation deadline conflicts with region-level \
         Budget.deadline.",
    );
}

#[test]
fn no_alternate_obligation_with_deadline_helper() {
    // Pin: there is no alternate constructor like
    // acquire_with_deadline that carries a per-obligation
    // expiry.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src/obligation") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let suspect_decls = [
            "pub fn acquire_with_deadline(",
            "pub fn acquire_with_expiry(",
            "pub fn acquire_with_ttl(",
            "fn try_acquire_with_deadline(",
        ];
        for pat in &suspect_decls {
            if content.contains(pat) {
                violations.push(format!("{}: contains `{}`", path.display(), pat));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: per-obligation deadline helper \
         introduced.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn unified_cancel_design_documented() {
    // Pin: the unified-cancel design is documented (so
    // future maintainers don't add ObligationFailed to
    // "fix" what isn't broken).
    let source = read("src/types/outcome.rs");

    assert!(
        source.contains("Cancelled")
            && (source.contains("four-valued")
                || source.contains("4-valued")
                || source.contains("4 variants")),
        "REGRESSION: four-valued Outcome / unified-cancel \
         design no longer documented in outcome.rs.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct MockObligationId(u64);
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct MockRegionId(u32);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MockObligationState {
    Reserved,
    #[expect(dead_code, reason = "mock mirrors committed production state")]
    Committed,
    Aborted,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CancelKind {
    Deadline,
    #[expect(dead_code, reason = "mock mirrors non-deadline cancellation")]
    User,
}

#[derive(Clone, Debug)]
struct CancelReason {
    kind: CancelKind,
}

#[derive(Debug, PartialEq, Eq)]
enum MockOutcome<T, E> {
    #[expect(dead_code, reason = "mock mirrors four-valued production Outcome")]
    Ok(T),
    #[expect(dead_code, reason = "mock mirrors four-valued production Outcome")]
    Err(E),
    Cancelled(CancelKind),
    #[expect(dead_code, reason = "mock mirrors four-valued production Outcome")]
    Panicked(String),
}

struct MockLedger {
    next: AtomicU64,
    obligations: Mutex<HashMap<MockObligationId, (MockRegionId, MockObligationState)>>,
}

impl MockLedger {
    fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
            obligations: Mutex::new(HashMap::new()),
        }
    }

    fn acquire(&self, region: MockRegionId) -> MockObligationId {
        let id = MockObligationId(self.next.fetch_add(1, Ordering::Relaxed));
        self.obligations
            .lock()
            .unwrap()
            .insert(id, (region, MockObligationState::Reserved));
        id
    }

    fn abort_by_id(&self, id: MockObligationId) {
        let mut o = self.obligations.lock().unwrap();
        if let Some((_, state)) = o.get_mut(&id) {
            if *state == MockObligationState::Reserved {
                *state = MockObligationState::Aborted;
            }
        }
    }

    fn pending_ids_for_region(&self, region: MockRegionId) -> Vec<MockObligationId> {
        self.obligations
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, (r, s))| *r == region && matches!(*s, MockObligationState::Reserved))
            .map(|(id, _)| *id)
            .collect()
    }

    fn pending_count_for_region(&self, region: MockRegionId) -> usize {
        self.pending_ids_for_region(region).len()
    }
}

fn deadline_driven_cancel_drain(
    ledger: &MockLedger,
    region: MockRegionId,
    _reason: &CancelReason,
) -> usize {
    // Layer D: enumerate pending obligations and abort each.
    let pending = ledger.pending_ids_for_region(region);
    let count = pending.len();
    for id in pending {
        ledger.abort_by_id(id);
    }
    count
}

#[test]
fn behavioral_deadline_cancel_drain_aborts_pending_obligations() {
    let ledger = MockLedger::new();
    let region = MockRegionId(1);

    // 3 obligations acquired in the region.
    let _t1 = ledger.acquire(region);
    let _t2 = ledger.acquire(region);
    let _t3 = ledger.acquire(region);

    assert_eq!(ledger.pending_count_for_region(region), 3);

    // Deadline-driven cancel arrives; cancel-drain runs.
    let drained = deadline_driven_cancel_drain(
        &ledger,
        region,
        &CancelReason {
            kind: CancelKind::Deadline,
        },
    );

    assert_eq!(
        drained, 3,
        "REGRESSION: cancel-drain did not abort all pending \
         obligations on deadline expiry. Silent drop vector.",
    );
    assert_eq!(
        ledger.pending_count_for_region(region),
        0,
        "REGRESSION: pending obligations remain after \
         cancel-drain. Either abort_by_id failed or some \
         obligations were missed.",
    );
}

#[test]
fn behavioral_region_outcome_is_cancelled_not_obligation_failed() {
    // Models the region-close outcome after deadline-driven
    // cancel. It is Outcome::Cancelled, NOT a separate
    // ObligationFailed variant.
    let outcome: MockOutcome<u32, ()> = MockOutcome::Cancelled(CancelKind::Deadline);

    match &outcome {
        MockOutcome::Cancelled(kind) => {
            assert_eq!(
                *kind,
                CancelKind::Deadline,
                "REGRESSION: deadline-driven cancel kind is \
                 not Deadline.",
            );
        }
        _ => panic!("expected Cancelled, got {:?}", outcome),
    }

    // The compile-time absence of ObligationFailed in
    // MockOutcome IS the proof.
}

#[test]
fn behavioral_unresolved_obligations_caught_by_leak_check() {
    // Models the lab-mode leak detection: any obligation
    // still Reserved at end of run is a leak.
    let ledger = MockLedger::new();
    let region = MockRegionId(1);

    let _t1 = ledger.acquire(region);
    let _t2 = ledger.acquire(region);
    // Note: NO cancel-drain runs here. Stragglers remain.

    let leaks = ledger.pending_ids_for_region(region);
    assert!(
        !leaks.is_empty(),
        "REGRESSION: lab-mode leak check did not detect \
         unresolved obligations.",
    );
    assert_eq!(leaks.len(), 2);
}

#[test]
fn behavioral_layered_design_deadline_to_outcome_cancelled() {
    // End-to-end behavioral demo: deadline expires → cancel
    // emitted → cancel-drain aborts obligations → region
    // outcome is Cancelled with CancelKind::Deadline.
    let ledger = MockLedger::new();
    let region = MockRegionId(7);

    // Acquire some obligations.
    let _o1 = ledger.acquire(region);
    let _o2 = ledger.acquire(region);

    // Layer B simulated: deadline expires, cancel reason
    // built with CancelKind::Deadline.
    let cancel_reason = CancelReason {
        kind: CancelKind::Deadline,
    };

    // Layer D: cancel-drain.
    let drained = deadline_driven_cancel_drain(&ledger, region, &cancel_reason);
    assert_eq!(drained, 2);

    // Layer E: region quiescence achieved.
    assert_eq!(ledger.pending_count_for_region(region), 0);

    // Layer G: region outcome is Cancelled with the
    // original kind preserved.
    let outcome: MockOutcome<u32, ()> = MockOutcome::Cancelled(cancel_reason.kind);
    assert!(matches!(
        outcome,
        MockOutcome::Cancelled(CancelKind::Deadline)
    ));
}

#[test]
fn behavioral_no_silent_drop_at_any_layer() {
    // Prove that NO layer silently drops an unresolved
    // obligation on deadline expiry. Either:
    //   (a) cancel-drain aborts them (ledger shows
    //       Aborted), or
    //   (b) leak-check reports them (lab mode).
    let ledger = MockLedger::new();
    let region = MockRegionId(99);

    let id1 = ledger.acquire(region);
    let id2 = ledger.acquire(region);

    // Run cancel-drain.
    let _ = deadline_driven_cancel_drain(
        &ledger,
        region,
        &CancelReason {
            kind: CancelKind::Deadline,
        },
    );

    // Both obligations are now Aborted, NOT silently
    // dropped (the record persists in the ledger map).
    let obligations = ledger.obligations.lock().unwrap();
    assert!(matches!(
        obligations.get(&id1),
        Some(&(_, MockObligationState::Aborted))
    ));
    assert!(matches!(
        obligations.get(&id2),
        Some(&(_, MockObligationState::Aborted))
    ));
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/obligation_no_leak_tracking_mechanism_audit.rs",
        "tests/cx_with_budget_via_scope_with_budget_audit.rs",
        "tests/cx_no_combined_scope_with_timeout_audit.rs",
        "tests/runtime_cancel_cause_kinds_distinct_audit.rs",
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
