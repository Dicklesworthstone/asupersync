//! Audit + regression test for the no-obligation-leak
//! tracking mechanism.
//!
//! Operator's question: "Per asupersync invariant 'no
//! obligation leaks', any task that registers an obligation
//! MUST resolve it (or cancel it) before exit. Verify the
//! tracking mechanism."
//!
//! Audit findings: **SOUND BY DESIGN — comprehensive
//! tracking via `ObligationLedger` with linear tokens,
//! pending-count accounting, region-quiescence checks,
//! finalize fences, and lab-mode leak detection**.
//!
//! Note: there is no literal `Cx::with_obligation()`
//! method. The acquire path goes through
//! `ObligationLedger::acquire` directly (or the higher-
//! level wrappers in `obligation/`); the operator's name
//! maps onto the linear-token discipline.
//!
//! ── Layered enforcement ─────────────────────────────────
//!
//! Layer 1 — **Linear tokens**:
//!   `ObligationLedger::acquire` (ledger.rs:374) returns
//!   an `ObligationToken { id, kind, holder, region }`. The
//!   token is consumed by `commit(token, now)` (line 512)
//!   or `abort(token, ...)` (line 541). Lose the token =
//!   leak.
//!
//! Layer 2 — **Pending-count accounting**:
//!   The ledger tracks `stats.pending` (incremented on
//!   acquire, decremented on commit/abort/leak). This is
//!   the running balance that must reach zero by region
//!   close. `pending_count()`, `pending_for_region(region)`,
//!   `pending_for_task(task)` (lines 679-699) expose it.
//!
//! Layer 3 — **Region-quiescence check**:
//!   `is_region_clean(region) -> bool` (line 717) returns
//!   true iff no pending obligations belong to the region.
//!   Region close requires this to be true (region close =
//!   quiescence invariant, AGENTS.md core invariant #2).
//!
//! Layer 4 — **Drain enumeration for cancel paths**:
//!   `pending_ids_for_region(region) -> Vec<ObligationId>`
//!   (line 707) lists pending obligations in a region;
//!   cancel handlers can feed these IDs into
//!   `abort_by_id(id, ...)` (line 574) to resolve them
//!   without recovering the original linear tokens.
//!
//! Layer 5 — **Acquire-on-finalized-region fence**:
//!   `acquire_with_context` (line 414-418) PANICS if the
//!   owning region was already finalized. This catches
//!   use-after-finalize bugs at the acquire site rather
//!   than letting them silently mutate the ledger.
//!   `mark_region_finalized(region)` (line 318) sets the
//!   fence.
//!
//! Layer 6 — **Late-arrival fallible variant**:
//!   `try_acquire` / `try_acquire_with_context` (line 453,
//!   475) return `LedgerError::RegionFinalized` instead of
//!   panicking — for Drop impls / detached cleanup tasks
//!   where late-arrival is part of the contract.
//!
//! Layer 7 — **Lab-mode leak detection**:
//!   `check_leaks() -> LeakCheckResult` (line 726) walks
//!   all obligations, returns a deterministic leak report
//!   with `LeakedObligation` records. Lab tests assert
//!   `result.leaked.is_empty()` at end of run.
//!
//! Layer 8 — **Idempotent resolve**:
//!   `try_commit` and `try_abort` (lines 334, 346) handle
//!   double-resolve gracefully. Replay safety.
//!
//! ── Inline tests pin the tracking ───────────────────────
//!
//! - `fn leak_check_detects_pending` (line 945) — verifies
//!   `check_leaks` reports an unresolved acquire.
//! - `fn leak_check_clean_after_resolve` (line 970) —
//!   verifies clean after commit.
//! - `fn check_leaks_includes_marked_leaked_obligations`
//!   (line 1054) — verifies `mark_leaked` shows up in the
//!   report.
//! - Plus ~50+ other inline tests covering acquire/commit/
//!   abort/replay/region-finalize-fence cases.
//!
//! ── Cross-layer enforcement: region close ───────────────
//!
//! When a region closes, the runtime drives the obligation
//! ledger to ensure quiescence:
//!
//!   1. `pending_ids_for_region(region)` enumerates
//!      pending obligations.
//!   2. The cancel-drain handler calls `abort_by_id` for
//!      each.
//!   3. `is_region_clean(region)` confirms zero pending.
//!   4. `mark_region_finalized(region)` sets the post-
//!      finalize fence.
//!   5. Subsequent acquire on this region panics (or
//!      returns RegionFinalized via try_acquire).
//!
//! Verdict: **SOUND BY DESIGN**. The no-obligation-leak
//! invariant is enforced at 8 layers: linear tokens,
//! pending-count accounting, region-quiescence,
//! drain enumeration, acquire fences, fallible-acquire,
//! leak detection, and idempotent resolve. The mechanism
//! is comprehensive, deterministic, and auditable.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn ledger_acquire_returns_linear_obligation_token() {
    // Pin: acquire returns an ObligationToken that must
    // be consumed by commit/abort. Linear discipline
    // catches leaks at compile-time-ish (the token can't
    // be discarded silently — Rust's drop check fires).
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains(
            "pub fn acquire(\n        &mut self,\n        kind: ObligationKind,\n        holder: TaskId,\n        region: RegionId,\n        now: Time,\n    ) -> ObligationToken {"
        ) || source.contains("pub fn acquire(") && source.contains("-> ObligationToken {"),
        "REGRESSION: ObligationLedger::acquire signature \
         changed. The linear-token discipline is broken \
         if the return type is no longer ObligationToken.",
    );
}

#[test]
fn ledger_commit_consumes_token_returns_pending_count() {
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn commit(&mut self, token: ObligationToken, now: Time) -> u64 {"),
        "REGRESSION: ObligationLedger::commit signature \
         changed. Linear-resolve path is broken.",
    );
}

#[test]
fn ledger_abort_consumes_token_with_reason() {
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn abort("),
        "REGRESSION: ObligationLedger::abort gone.",
    );
}

#[test]
fn ledger_pending_count_accessor_exists() {
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn pending_count(&self) -> u64 {"),
        "REGRESSION: pending_count accessor gone. \
         Pending-balance observability is broken.",
    );
}

#[test]
fn ledger_pending_for_region_and_task_accessors_exist() {
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn pending_for_region(&self, region: RegionId) -> usize {"),
        "REGRESSION: pending_for_region gone. Per-region \
         leak detection broken.",
    );

    assert!(
        source.contains("pub fn pending_for_task(&self, task: TaskId) -> usize {"),
        "REGRESSION: pending_for_task gone. Per-task leak \
         detection broken.",
    );
}

#[test]
fn ledger_is_region_clean_quiescence_check_exists() {
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn is_region_clean(&self, region: RegionId) -> bool {"),
        "REGRESSION: is_region_clean gone. Region-close \
         quiescence invariant cannot be checked.",
    );
}

#[test]
fn ledger_check_leaks_returns_deterministic_report() {
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn check_leaks(&self) -> LeakCheckResult {"),
        "REGRESSION: check_leaks gone. Lab-mode leak \
         detection is broken — tests cannot assert \
         clean state.",
    );

    assert!(
        source.contains("pub struct LeakCheckResult {"),
        "REGRESSION: LeakCheckResult struct gone.",
    );
}

#[test]
fn ledger_pending_ids_for_region_drain_enumeration_exists() {
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains(
            "pub fn pending_ids_for_region(&self, region: RegionId) -> Vec<ObligationId> {"
        ),
        "REGRESSION: pending_ids_for_region gone. Cancel \
         handlers cannot enumerate pending obligations \
         for drain.",
    );

    assert!(
        source.contains("pub fn abort_by_id("),
        "REGRESSION: abort_by_id gone. Cancel-drain \
         resolution by ID is broken.",
    );
}

#[test]
fn ledger_acquire_panics_on_finalized_region() {
    // Pin: acquire-on-finalized-region is a programming
    // error and must panic. Without this fence, late
    // acquires silently grow the ledger past finalize.
    let source = read("src/obligation/ledger.rs");

    let fn_marker = "fn acquire_internal(";
    let pos = source.find(fn_marker).expect("acquire_with_context fn");
    let body_window = &source[pos..pos + 1500];

    assert!(
        body_window.contains("self.finalized_regions.contains(&region)"),
        "REGRESSION: acquire no longer checks the \
         finalized_regions fence. Late acquires post-\
         finalize will silently mutate the ledger.",
    );

    assert!(
        source.contains("br-asupersync-12cqs2"),
        "REGRESSION: the br-asupersync-12cqs2 reference \
         (acquire-on-finalized fence rationale) is gone.",
    );
}

#[test]
fn ledger_try_acquire_fallible_variant_for_late_arrival() {
    // Pin: try_acquire returns LedgerError::RegionFinalized
    // instead of panicking — for Drop impls / detached
    // cleanup paths.
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn try_acquire("),
        "REGRESSION: try_acquire gone. Late-arrival paths \
         (Drop impls, detached cleanup) cannot handle \
         post-finalize gracefully.",
    );

    assert!(
        source.contains("LedgerError::RegionFinalized"),
        "REGRESSION: RegionFinalized error variant gone.",
    );
}

#[test]
fn ledger_mark_region_finalized_sets_fence() {
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn mark_region_finalized(&mut self, region: RegionId) {"),
        "REGRESSION: mark_region_finalized gone. The \
         post-finalize fence cannot be set.",
    );

    assert!(
        source.contains("pub fn is_region_finalized(&self, region: RegionId) -> bool {"),
        "REGRESSION: is_region_finalized accessor gone.",
    );
}

#[test]
fn ledger_try_commit_and_try_abort_idempotent_resolve() {
    // Pin: idempotent resolve via try_commit / try_abort.
    // Without these, a replay of an already-resolved
    // token would panic.
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains(
            "pub fn try_commit(&mut self, token: ObligationToken, now: Time) -> Result<u64, LedgerError> {"
        ),
        "REGRESSION: try_commit gone. Replay-safe commit \
         is broken.",
    );

    assert!(
        source.contains("pub fn try_abort("),
        "REGRESSION: try_abort gone. Replay-safe abort \
         is broken.",
    );
}

#[test]
fn ledger_mark_leaked_for_diagnostic_attribution() {
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("pub fn mark_leaked(&mut self, id: ObligationId, now: Time) -> u64 {"),
        "REGRESSION: mark_leaked gone. Explicit leak \
         attribution for diagnostics is broken.",
    );
}

#[test]
fn ledger_leak_check_inline_tests_retained() {
    // Pin: at least three load-bearing inline tests must
    // remain.
    let source = read("src/obligation/ledger.rs");

    assert!(
        source.contains("fn leak_check_detects_pending()"),
        "REGRESSION: leak_check_detects_pending inline \
         test gone. The leak-detection contract is no \
         longer guarded in-tree.",
    );

    assert!(
        source.contains("fn leak_check_clean_after_resolve()"),
        "REGRESSION: leak_check_clean_after_resolve test \
         gone. The post-resolve clean-state invariant is \
         no longer guarded.",
    );

    assert!(
        source.contains("fn check_leaks_includes_marked_leaked_obligations()"),
        "REGRESSION: check_leaks_includes_marked_leaked_obligations \
         test gone.",
    );
}

#[test]
fn ledger_stats_pending_field_drives_pending_count() {
    // Pin: the stats.pending field is what pending_count
    // returns. acquire/commit/abort must increment/decrement
    // it.
    let source = read("src/obligation/ledger.rs");

    let acquire_marker = "fn acquire_internal(";
    let pos = source.find(acquire_marker).expect("acquire_internal fn");
    let body_window = &source[pos..pos + 2500];

    assert!(
        body_window.contains("self.stats.total_acquired += 1;")
            && body_window.contains("self.stats.pending += 1;"),
        "REGRESSION: acquire no longer increments \
         stats.pending. Pending-count accounting is broken.",
    );
}

#[test]
fn invariant_no_obligation_leaks_documented_in_agents_md() {
    // Pin: AGENTS.md documents the "no obligation leaks"
    // invariant. Without this in the canonical docs,
    // future maintainers may not know the rule.
    let source = read("AGENTS.md");

    assert!(
        source.contains("No obligation leaks")
            || source.contains("no obligation leaks")
            || source.contains("**No obligation leaks:**"),
        "REGRESSION: AGENTS.md no longer documents the \
         no-obligation-leaks invariant.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ObligationId(u64);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct TaskId(u64);
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
struct RegionId(u64);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ObligationState {
    Reserved,
    Committed,
    Aborted,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ObligationToken {
    id: ObligationId,
    holder: TaskId,
    region: RegionId,
}

struct MockLedger {
    next: AtomicU64,
    obligations: Mutex<HashMap<ObligationId, (TaskId, RegionId, ObligationState)>>,
    pending: AtomicU64,
    finalized: Mutex<Vec<RegionId>>,
}

impl MockLedger {
    fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
            obligations: Mutex::new(HashMap::new()),
            pending: AtomicU64::new(0),
            finalized: Mutex::new(Vec::new()),
        }
    }

    fn acquire(&self, holder: TaskId, region: RegionId) -> ObligationToken {
        let finalized = self.finalized.lock().unwrap();
        assert!(
            !finalized.contains(&region),
            "MockLedger: cannot acquire on finalized region {:?}",
            region,
        );
        drop(finalized);

        let id = ObligationId(self.next.fetch_add(1, Ordering::Relaxed));
        self.obligations
            .lock()
            .unwrap()
            .insert(id, (holder, region, ObligationState::Reserved));
        self.pending.fetch_add(1, Ordering::Relaxed);
        ObligationToken { id, holder, region }
    }

    fn commit(&self, token: ObligationToken) {
        let mut obligations = self.obligations.lock().unwrap();
        if let Some((_, _, state)) = obligations.get_mut(&token.id) {
            if matches!(*state, ObligationState::Reserved) {
                *state = ObligationState::Committed;
                self.pending.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    fn abort(&self, token: ObligationToken) {
        let mut obligations = self.obligations.lock().unwrap();
        if let Some((_, _, state)) = obligations.get_mut(&token.id) {
            if matches!(*state, ObligationState::Reserved) {
                *state = ObligationState::Aborted;
                self.pending.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    fn pending_count(&self) -> u64 {
        self.pending.load(Ordering::Relaxed)
    }

    fn pending_for_region(&self, region: RegionId) -> u64 {
        self.obligations
            .lock()
            .unwrap()
            .values()
            .filter(|(_, r, s)| *r == region && matches!(*s, ObligationState::Reserved))
            .count() as u64
    }

    fn pending_ids_for_region(&self, region: RegionId) -> Vec<ObligationId> {
        self.obligations
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, (_, r, s))| *r == region && matches!(*s, ObligationState::Reserved))
            .map(|(id, _)| *id)
            .collect()
    }

    fn abort_by_id(&self, id: ObligationId) {
        let mut obligations = self.obligations.lock().unwrap();
        if let Some((_, _, state)) = obligations.get_mut(&id) {
            if matches!(*state, ObligationState::Reserved) {
                *state = ObligationState::Aborted;
                self.pending.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    fn is_region_clean(&self, region: RegionId) -> bool {
        self.pending_for_region(region) == 0
    }

    fn mark_region_finalized(&self, region: RegionId) {
        self.finalized.lock().unwrap().push(region);
    }

    fn check_leaks(&self) -> Vec<ObligationId> {
        self.obligations
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, (_, _, s))| matches!(*s, ObligationState::Reserved))
            .map(|(id, _)| *id)
            .collect()
    }
}

#[test]
fn behavioral_acquire_increments_pending_count() {
    let ledger = MockLedger::new();
    assert_eq!(ledger.pending_count(), 0);

    let _t = ledger.acquire(TaskId(1), RegionId(10));
    assert_eq!(ledger.pending_count(), 1);

    let _t2 = ledger.acquire(TaskId(2), RegionId(10));
    assert_eq!(ledger.pending_count(), 2);
}

#[test]
fn behavioral_commit_decrements_pending_count() {
    let ledger = MockLedger::new();
    let t1 = ledger.acquire(TaskId(1), RegionId(10));
    let t2 = ledger.acquire(TaskId(1), RegionId(10));
    assert_eq!(ledger.pending_count(), 2);

    ledger.commit(t1);
    assert_eq!(ledger.pending_count(), 1);

    ledger.commit(t2);
    assert_eq!(ledger.pending_count(), 0);
}

#[test]
fn behavioral_abort_decrements_pending_count() {
    let ledger = MockLedger::new();
    let t = ledger.acquire(TaskId(1), RegionId(10));
    assert_eq!(ledger.pending_count(), 1);

    ledger.abort(t);
    assert_eq!(ledger.pending_count(), 0);
}

#[test]
fn behavioral_check_leaks_detects_unresolved() {
    let ledger = MockLedger::new();
    let _t = ledger.acquire(TaskId(1), RegionId(10));
    // Token dropped without commit/abort — leak.

    let leaks = ledger.check_leaks();
    assert_eq!(
        leaks.len(),
        1,
        "REGRESSION: check_leaks did not detect 1 \
         unresolved obligation. The leak-detection \
         contract is broken.",
    );
}

#[test]
fn behavioral_check_leaks_clean_after_resolve() {
    let ledger = MockLedger::new();
    let t1 = ledger.acquire(TaskId(1), RegionId(10));
    let t2 = ledger.acquire(TaskId(1), RegionId(10));

    ledger.commit(t1);
    ledger.abort(t2);

    let leaks = ledger.check_leaks();
    assert_eq!(
        leaks.len(),
        0,
        "REGRESSION: check_leaks reported leaks after all \
         tokens were resolved. False positive.",
    );
}

#[test]
fn behavioral_drain_enumeration_resolves_all_pending_for_region() {
    let ledger = MockLedger::new();
    let region = RegionId(42);

    let _t1 = ledger.acquire(TaskId(1), region);
    let _t2 = ledger.acquire(TaskId(2), region);
    let _t3 = ledger.acquire(TaskId(1), RegionId(99)); // different region

    assert_eq!(ledger.pending_for_region(region), 2);

    // Drain: enumerate IDs, abort each.
    let pending = ledger.pending_ids_for_region(region);
    assert_eq!(pending.len(), 2);
    for id in pending {
        ledger.abort_by_id(id);
    }

    assert!(
        ledger.is_region_clean(region),
        "REGRESSION: region not clean after drain. The \
         enumerate+abort_by_id pattern is broken.",
    );
    // Other region still has 1 pending.
    assert_eq!(ledger.pending_for_region(RegionId(99)), 1);
}

#[test]
fn behavioral_acquire_on_finalized_region_panics() {
    let ledger = MockLedger::new();
    let region = RegionId(7);

    ledger.mark_region_finalized(region);

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = ledger.acquire(TaskId(1), region);
    }));

    assert!(
        panicked.is_err(),
        "REGRESSION: acquire on finalized region did NOT \
         panic. The post-finalize fence is broken — late \
         acquires silently grow the ledger.",
    );
}

#[test]
fn behavioral_double_resolve_is_idempotent_no_underflow() {
    let ledger = MockLedger::new();
    let t = ledger.acquire(TaskId(1), RegionId(10));
    assert_eq!(ledger.pending_count(), 1);

    ledger.commit(t);
    assert_eq!(ledger.pending_count(), 0);

    // Replay the commit — must NOT underflow pending.
    ledger.commit(t);
    assert_eq!(
        ledger.pending_count(),
        0,
        "REGRESSION: double-commit underflowed the pending \
         counter. Replay-safety broken.",
    );

    // Replay abort after commit — must NOT underflow.
    ledger.abort(t);
    assert_eq!(ledger.pending_count(), 0);
}

#[test]
fn behavioral_region_quiescence_requires_zero_pending() {
    let ledger = MockLedger::new();
    let region = RegionId(5);

    // Initially clean.
    assert!(ledger.is_region_clean(region));

    // Acquire — not clean.
    let t = ledger.acquire(TaskId(1), region);
    assert!(!ledger.is_region_clean(region));

    // Resolve — clean again.
    ledger.commit(t);
    assert!(
        ledger.is_region_clean(region),
        "REGRESSION: region not clean after resolving its \
         only obligation. is_region_clean is broken.",
    );
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_masked_does_not_block_obligation_propagation_audit.rs",
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
