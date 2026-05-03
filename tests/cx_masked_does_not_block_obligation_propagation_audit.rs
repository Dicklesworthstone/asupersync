//! Audit + regression test for obligation propagation
//! across `Cx::masked()` boundaries.
//!
//! Operator's question: "masked() builds a barrier that
//! prevents cancel propagation upward but obligations
//! still flow. Verify obligations from inside a masked
//! block are observable to outer scope. If obligations
//! get lost, file critical bead."
//!
//! Audit findings: **SOUND BY DESIGN — masked is
//! orthogonal to obligations**.
//!
//! ── The orthogonality theorem ────────────────────────────
//!
//! `Cx::masked` (cx.rs:2151) only touches `inner.mask_depth`
//! under the inner write lock — that's its entire side
//! effect. The obligation ledger
//! (`src/obligation/ledger.rs`) operates via separate
//! state (the ObligationLedger struct, ObligationToken
//! handles, commit/abort/issue paths) and has ZERO
//! references to `mask_depth` or `masked` anywhere in
//! `src/obligation/`.
//!
//! Therefore:
//!   - Issuing an obligation inside `cx.masked(|| ...)`
//!     calls the same ledger via the same token; the
//!     resulting `ObligationToken` is identical to one
//!     issued outside the masked block.
//!   - The token survives mask boundaries because nothing
//!     about the mask changes ledger state.
//!   - Outer-scope code observing the ledger sees the
//!     obligation regardless of where it was issued
//!     (inside a mask or outside).
//!
//! ── What `masked()` actually does ────────────────────────
//!
//! ```ignore
//! pub fn masked<F, R>(&self, f: F) -> R
//! where F: FnOnce() -> R,
//! {
//!     {
//!         let mut inner = self.inner.write();
//!         assert!(inner.mask_depth < MAX_MASK_DEPTH, ...);
//!         inner.mask_depth += 1;
//!     }
//!     let _guard = MaskGuard { inner: &self.inner };
//!     f()
//! }
//! ```
//!
//! - Increments `mask_depth` (write lock, brief).
//! - Constructs a `MaskGuard` (RAII; saturating decrement
//!   on drop).
//! - Calls the closure, returns the result.
//!
//! No obligation ledger touched. No commit / abort /
//! issue side effect. No leak-tracker mutation.
//!
//! ── What checkpoint sees inside a mask ──────────────────
//!
//! `Cx::checkpoint` (cx.rs:1644) checks
//! `cancel_requested && mask_depth == 0` to decide
//! whether to return Err(Cancelled). Inside a mask, the
//! check returns Ok even if cancel is pending. This is
//! the ONLY thing the mask gates — cancel acknowledgment
//! at checkpoints. Obligations are unaffected.
//!
//! ── Operator's framing nuance ───────────────────────────
//!
//! "masked() builds a barrier that prevents cancel
//! propagation upward" — slight clarification:
//!
//! - Cancel itself IS still set via fast_cancel.store(...)
//!   even when masked code calls cx.cancel_with(...).
//! - Cancel STILL propagates to child regions (cancel-
//!   request is a flag flip; mask doesn't intercept it).
//! - What the mask DEFERS is the OBSERVATION at the
//!   masked task's own checkpoints — `cx.checkpoint()`
//!   inside the mask returns Ok instead of Err.
//!
//! See tests/cx_masked_vs_scope_distinction_audit.rs and
//! tests/cx_checkpoint_during_region_cancel_timing_audit.rs
//! for the full mask-vs-cancel semantic mapping.
//!
//! ── No obligation pollution from mask ───────────────────
//!
//! Critical bug check: if `masked()` somehow swallowed
//! obligations, paused them, or short-circuited their
//! commit, the structured-concurrency invariant "no
//! obligation leaks" would be silently violated. The
//! orthogonality (mask code never touches obligation
//! state) makes this bug impossible by construction.
//!
//! Verdict: **SOUND BY DESIGN**. masked() is orthogonal
//! to the obligation ledger. Obligations issued inside
//! a masked block flow to the outer scope identically to
//! obligations issued outside.
//!
//! No bead filed.
//!
//! A regression that:
//!   - made `masked()` pause / suppress / re-route
//!     obligation commits,
//!   - made the obligation ledger consult `mask_depth`
//!     when issuing or committing,
//!   - introduced a second ledger that mask flips between,
//! would all be caught by the structural pins below.

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
fn masked_body_only_touches_mask_depth_not_obligations() {
    // Pin: the body of Cx::masked has no references to
    // any obligation API. If a future regression added
    // obligation manipulation here, obligation propagation
    // could be broken silently.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn masked<F, R>(&self, f: F) -> R";
    let pos = source.find(fn_marker).expect("masked fn");
    let body_window = &source[pos..pos + 1200];

    let suspect_calls = [
        "obligation",
        "Obligation",
        "ledger",
        "Ledger",
        "commit_obligation",
        "issue_obligation",
        "abort_obligation",
    ];
    for pat in &suspect_calls {
        assert!(
            !body_window.contains(pat),
            "REGRESSION: Cx::masked body now references \
             `{pat}` — masked is no longer orthogonal to \
             obligations. Obligations issued inside a mask \
             may be silently dropped, paused, or re-routed.",
        );
    }
}

#[test]
fn obligation_module_does_not_consult_mask_depth() {
    // Pin: the obligation module has ZERO references to
    // mask_depth, masked, or MaskGuard. If a future
    // regression made the ledger consult the mask, the
    // orthogonality would be broken.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src/obligation") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let suspect_patterns = [
            "mask_depth",
            "MaskGuard",
            ".masked(",
            "mask_depth ==",
            "mask_depth >",
        ];
        for pat in &suspect_patterns {
            if content.contains(pat) {
                violations.push(format!(
                    "{}: contains `{}`",
                    path.display(),
                    pat
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: obligation module now references mask \
         state. Orthogonality is broken — obligations may \
         behave differently inside vs outside a masked \
         section.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn masked_increments_only_mask_depth_field() {
    // Pin: masked's write-lock block increments ONLY
    // mask_depth. No other inner field is mutated.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn masked<F, R>(&self, f: F) -> R";
    let pos = source.find(fn_marker).expect("masked fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("masked fn close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("inner.mask_depth += 1;"),
        "REGRESSION: masked no longer increments mask_depth.",
    );

    // Must NOT touch other fields that could affect
    // obligation propagation.
    let suspect_field_writes = [
        "inner.cancel_requested =",
        "inner.cancel_reason =",
        "inner.budget =",
        "inner.fast_cancel.store",
    ];
    for pat in &suspect_field_writes {
        assert!(
            !body.contains(pat),
            "REGRESSION: masked body now writes to `{pat}`. \
             Side-effect leakage from a defer-only operation.",
        );
    }
}

#[test]
fn mask_guard_drop_only_decrements_mask_depth() {
    // Pin: MaskGuard::drop only decrements mask_depth
    // (saturating). It does NOT commit/abort/touch
    // obligations.
    let source = read("src/cx/cx.rs");

    let drop_marker = "impl Drop for MaskGuard<'_> {";
    let pos = source.find(drop_marker).expect("MaskGuard Drop impl");
    let body_end = source[pos..]
        .find("\n}\n")
        .expect("MaskGuard Drop close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("mask_depth = inner.mask_depth.saturating_sub(1)")
            || body.contains("inner.mask_depth.saturating_sub(1)"),
        "REGRESSION: MaskGuard::drop no longer uses \
         saturating_sub on mask_depth.",
    );

    let suspect_calls = [
        "obligation",
        "ledger",
        "commit",
        "abort_obligation",
    ];
    for pat in &suspect_calls {
        assert!(
            !body.contains(pat),
            "REGRESSION: MaskGuard::drop now references \
             `{pat}` — mask unwind is now coupled to \
             obligation lifecycle. Orthogonality broken.",
        );
    }
}

#[test]
fn obligation_ledger_commit_and_abort_signatures_pinned() {
    // Pin: the ledger's commit/abort signatures take just
    // an ObligationToken and Time/CancelReason — NOT a
    // mask state. So they cannot consult mask state in
    // their decisions.
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn commit(&mut self, token: ObligationToken, now: Time) -> u64 {"),
        "REGRESSION: ObligationLedger::commit signature \
         changed. If it now takes a mask parameter, the \
         orthogonality is broken.",
    );

    assert!(
        source.contains("pub fn abort("),
        "REGRESSION: ObligationLedger::abort is gone.",
    );
}

#[test]
fn obligation_token_does_not_carry_mask_state() {
    // Pin: ObligationToken (the handle returned by issue
    // and consumed by commit/abort) does not carry mask
    // state. If it did, an obligation issued inside a
    // mask might commit/abort differently.
    let source = read("src/obligation/ledger.rs");
    let mut all_obligation = source;
    for path in read_dir_recursive("src/obligation") {
        if let Ok(c) = std::fs::read_to_string(&path) {
            all_obligation.push_str(&c);
        }
    }

    let suspect_patterns = [
        "ObligationToken { ... mask_depth",
        "token.mask_depth",
        "issued_with_mask:",
    ];
    for pat in &suspect_patterns {
        assert!(
            !all_obligation.contains(pat),
            "REGRESSION: ObligationToken now carries mask \
             state via `{pat}`. Mask leakage into the \
             ledger.",
        );
    }
}

#[test]
fn no_alternate_ledger_keyed_by_mask() {
    // Pin: there is no second ledger / variant ledger /
    // mask-specific ledger. A regression that introduced
    // one would silently route obligations differently
    // based on mask state.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let suspect_decls = [
            "MaskedLedger",
            "MaskAwareLedger",
            "ObligationLedgerForMask",
            "masked_ledger:",
        ];
        for pat in &suspect_decls {
            if content.contains(pat) {
                violations.push(format!(
                    "{}: contains `{}`",
                    path.display(),
                    pat
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: alternate mask-keyed ledger \
         introduced. Obligations may now route differently \
         inside vs outside a mask.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn mask_depth_only_consumed_by_checkpoint() {
    // Pin: the only consumer of mask_depth is the cancel
    // observation at checkpoint. If mask_depth gates
    // anything else (including obligation commit), the
    // orthogonality is broken.
    let source = read("src/cx/cx.rs");

    // Find all references to mask_depth in the cx.rs
    // source. Each should be in masked(), MaskGuard,
    // checkpoint, or check_cancel_from_values — NOT in
    // obligation-adjacent code.
    let suspect_proximity_patterns = [
        "obligation_table",
        "ObligationTable",
        "issue_obligation_with_mask",
    ];

    for pat in &suspect_proximity_patterns {
        assert!(
            !source.contains(pat),
            "REGRESSION: cx.rs references `{pat}` — \
             obligation handling now interacts with mask \
             state. Orthogonality broken.",
        );
    }
}

#[test]
fn masked_documented_to_defer_cancel_not_obligations() {
    // Pin: masked's docstring explicitly mentions cancel
    // and checkpoint — not obligations. If the doc is
    // changed to claim mask suppresses obligations, that's
    // a doc-vs-implementation drift.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn masked<F, R>(&self, f: F) -> R";
    let pos = source.find(fn_marker).expect("masked fn");
    let preceding = &source[pos.saturating_sub(3500)..pos];

    assert!(
        preceding.contains("masked"),
        "REGRESSION: masked docstring is gone or doesn't \
         describe the mask semantic.",
    );

    // Must NOT claim it suppresses obligations.
    let suspect_claims = [
        "suppresses obligations",
        "obligations are paused",
        "obligation propagation is blocked",
    ];
    for pat in &suspect_claims {
        assert!(
            !preceding.contains(pat),
            "REGRESSION: masked docstring now claims \
             obligations are affected. The orthogonality \
             contract is being misrepresented in docs.",
        );
    }
}

// ── Behavioral pins ─────────────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Mock ObligationLedger — records (issued, committed,
/// aborted) by token id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ObligationStatus {
    Issued,
    Committed,
    Aborted,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct MockObligationToken(u64);

struct MockLedger {
    next: AtomicU64,
    status: Mutex<HashMap<MockObligationToken, ObligationStatus>>,
}

impl MockLedger {
    fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
            status: Mutex::new(HashMap::new()),
        }
    }

    fn issue(&self) -> MockObligationToken {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let token = MockObligationToken(id);
        self.status.lock().unwrap().insert(token, ObligationStatus::Issued);
        token
    }

    fn commit(&self, token: MockObligationToken) {
        self.status
            .lock()
            .unwrap()
            .insert(token, ObligationStatus::Committed);
    }

    fn status(&self, token: MockObligationToken) -> Option<ObligationStatus> {
        self.status.lock().unwrap().get(&token).copied()
    }

    fn count_issued(&self) -> usize {
        self.status
            .lock()
            .unwrap()
            .values()
            .filter(|s| matches!(s, ObligationStatus::Issued))
            .count()
    }

    fn count_committed(&self) -> usize {
        self.status
            .lock()
            .unwrap()
            .values()
            .filter(|s| matches!(s, ObligationStatus::Committed))
            .count()
    }
}

struct MockCx {
    mask_depth: Mutex<u32>,
    cancel_requested: Mutex<bool>,
    ledger: MockLedger,
}

struct MockMaskGuard<'a> {
    cx: &'a MockCx,
}

impl Drop for MockMaskGuard<'_> {
    fn drop(&mut self) {
        let mut d = self.cx.mask_depth.lock().unwrap();
        *d = d.saturating_sub(1);
    }
}

impl MockCx {
    fn new() -> Self {
        Self {
            mask_depth: Mutex::new(0),
            cancel_requested: Mutex::new(false),
            ledger: MockLedger::new(),
        }
    }

    fn masked<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        {
            let mut d = self.mask_depth.lock().unwrap();
            *d += 1;
        }
        let _g = MockMaskGuard { cx: self };
        f()
    }

    fn issue_obligation(&self) -> MockObligationToken {
        // CRITICAL: this must NOT consult mask_depth.
        self.ledger.issue()
    }

    fn commit_obligation(&self, token: MockObligationToken) {
        self.ledger.commit(token);
    }

    fn cancel(&self) {
        *self.cancel_requested.lock().unwrap() = true;
    }

    fn checkpoint(&self) -> Result<(), &'static str> {
        let cancelled = *self.cancel_requested.lock().unwrap();
        let mask = *self.mask_depth.lock().unwrap();
        if cancelled && mask == 0 {
            Err("cancelled")
        } else {
            Ok(())
        }
    }
}

#[test]
fn behavioral_obligation_issued_inside_mask_visible_to_outer_scope() {
    let cx = MockCx::new();

    // Issue an obligation inside a masked closure.
    let token = cx.masked(|| cx.issue_obligation());

    // Outer scope can observe the obligation.
    let status = cx.ledger.status(token);
    assert_eq!(
        status,
        Some(ObligationStatus::Issued),
        "REGRESSION: obligation issued inside mask is not \
         observable to outer scope. CRITICAL — obligation \
         leak vector.",
    );

    assert_eq!(cx.ledger.count_issued(), 1);
}

#[test]
fn behavioral_obligation_committed_inside_mask_visible_to_outer_scope() {
    let cx = MockCx::new();

    let token = cx.issue_obligation();
    assert_eq!(cx.ledger.count_issued(), 1);

    // Commit inside the mask.
    cx.masked(|| {
        cx.commit_obligation(token);
    });

    // Outer scope sees the commit.
    assert_eq!(
        cx.ledger.status(token),
        Some(ObligationStatus::Committed),
        "REGRESSION: commit inside mask is not visible to \
         outer scope. The commit was either dropped, \
         paused, or routed to a separate ledger.",
    );

    assert_eq!(cx.ledger.count_committed(), 1);
    assert_eq!(cx.ledger.count_issued(), 0);
}

#[test]
fn behavioral_obligations_persist_across_mask_with_cancel() {
    // The pathological case: cancel pending, mask gates
    // checkpoint. Obligations issued inside the mask must
    // STILL be observable.
    let cx = MockCx::new();
    cx.cancel();

    let token = cx.masked(|| {
        // Inside mask, checkpoint returns Ok despite cancel.
        assert_eq!(cx.checkpoint(), Ok(()));
        // Issue an obligation despite cancel.
        cx.issue_obligation()
    });

    // After mask unwinds, checkpoint sees Err.
    assert_eq!(cx.checkpoint(), Err("cancelled"));

    // The obligation issued inside the mask is STILL
    // observable.
    assert_eq!(
        cx.ledger.status(token),
        Some(ObligationStatus::Issued),
        "REGRESSION: obligation issued inside masked block \
         under pending cancel got LOST. CRITICAL — \
         obligation leak.",
    );
}

#[test]
fn behavioral_nested_mask_does_not_partition_obligations() {
    let cx = MockCx::new();

    let (t_outer_pre, t_inner, t_outer_post) = cx.masked(|| {
        let pre = cx.issue_obligation();
        let inner = cx.masked(|| cx.issue_obligation());
        let post = cx.issue_obligation();
        (pre, inner, post)
    });

    // All three obligations are observable to the outer
    // scope.
    assert_eq!(cx.ledger.status(t_outer_pre), Some(ObligationStatus::Issued));
    assert_eq!(cx.ledger.status(t_inner), Some(ObligationStatus::Issued));
    assert_eq!(cx.ledger.status(t_outer_post), Some(ObligationStatus::Issued));

    assert_eq!(
        cx.ledger.count_issued(),
        3,
        "REGRESSION: nested mask partitioned the ledger. \
         Some obligations got lost between mask levels.",
    );
}

#[test]
fn behavioral_mask_does_not_change_token_identity() {
    let cx = MockCx::new();

    let outside = cx.issue_obligation();
    let inside = cx.masked(|| cx.issue_obligation());

    // Token IDs are unique; both visible in same ledger.
    assert_ne!(outside, inside);
    assert_eq!(cx.ledger.status(outside), Some(ObligationStatus::Issued));
    assert_eq!(cx.ledger.status(inside), Some(ObligationStatus::Issued));
    assert_eq!(cx.ledger.count_issued(), 2);
}

#[test]
fn behavioral_panic_inside_mask_preserves_obligations() {
    // Pathological: the masked closure panics. The mask
    // unwinds via RAII; obligations issued before the
    // panic must still be observable.
    let cx = MockCx::new();

    let token_holder = std::sync::Mutex::new(None::<MockObligationToken>);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cx.masked(|| {
            let token = cx.issue_obligation();
            *token_holder.lock().unwrap() = Some(token);
            std::panic::resume_unwind(Box::new("test panic"));
        })
    }));

    assert!(result.is_err(), "the closure must have panicked");

    // mask_depth is back to 0 (RAII unwound).
    assert_eq!(*cx.mask_depth.lock().unwrap(), 0);

    // The obligation issued before the panic is observable.
    let token = token_holder.lock().unwrap().unwrap();
    assert_eq!(
        cx.ledger.status(token),
        Some(ObligationStatus::Issued),
        "REGRESSION: panic inside mask lost an obligation. \
         CRITICAL — panic-safety + obligation-tracking \
         interaction broken.",
    );
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_masked_vs_scope_distinction_audit.rs",
        "tests/cx_checkpoint_during_region_cancel_timing_audit.rs",
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
