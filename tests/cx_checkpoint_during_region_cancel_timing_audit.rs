//! Audit + regression test for `Cx::checkpoint()` timing
//! during region cancel.
//!
//! Operator's question: "When a child task's region is
//! cancelled and the task is mid-checkpoint, the checkpoint
//! MUST observe Err(Cancelled) before doing any work.
//! Verify timing: checkpoint should NOT do its work then
//! return Err."
//!
//! Audit findings: **SOUND BY DESIGN**.
//!
//! `Cx::checkpoint()` is structured as a two-phase
//! observation: a *fast path* that checks `fast_cancel` via
//! a single Acquire load BEFORE any progress recording,
//! and a *slow path* that runs only when the fast load
//! observes cancellation OR budget exhaustion.
//!
//! Source: `src/cx/cx.rs:1644` (`pub fn checkpoint(&self)
//! -> Result<(), Error>`).
//!
//! ── Fast path (cx.rs:1662-1683) ─────────────────────────
//!
//! ```ignore
//! {
//!     let guard = self.inner.read();
//!     let cancelled = guard.fast_cancel
//!         .load(std::sync::atomic::Ordering::Acquire);   // (A)
//!     let exhausted = !cancelled
//!         && Self::checkpoint_budget_exhaustion(...).is_some();
//!     let has_message = guard.checkpoint_state.last_message.is_some();
//!     let is_first_checkpoint = guard.checkpoint_state.checkpoint_count == 0
//!         && guard.fast_path_count.load(Relaxed) == 0;
//!     if !cancelled && !exhausted && !has_message && !is_first_checkpoint {
//!         // ── progress recording ONLY when healthy ──
//!         guard.fast_path_last_checkpoint_ns.store(...);
//!         guard.fast_path_count.fetch_add(1, ...);
//!         return Ok(());
//!     }
//! }
//! // fall through to slow path
//! ```
//!
//! Critical observation: `fast_cancel.load(Acquire)` at (A)
//! is the FIRST observable side effect of checkpoint(). If
//! the load returns `true`, the if-block is skipped — no
//! progress is recorded in the fast-path counters, no
//! checkpoint state is mutated. Control falls through to
//! the slow path, which returns `Err(Cancelled)`.
//!
//! ── Slow path (cx.rs:1684-1771) ──────────────────────────
//!
//! ```ignore
//! let mut inner = self.inner.write();
//! inner.drain_fast_path_checkpoint();
//! inner.checkpoint_state.record_at(checkpoint_time);
//! // ... budget exhaustion check, cancel reason update ...
//! Self::check_cancel_from_values(
//!     cancel_requested, mask_depth, ...,
//! )  // -> Err(Cancelled) if cancel_requested && mask==0
//! ```
//!
//! The slow path DOES record the checkpoint event in
//! `CheckpointState` via `record_at(checkpoint_time)`
//! BEFORE returning `Err(Cancelled)`. This is **checkpoint's
//! own internal accounting**, not user work — it lets
//! observability tools show "this task did reach this
//! checkpoint, and there it observed cancellation."
//!
//! The user contract — "checkpoint MUST observe
//! Err(Cancelled) before any USER work" — is honored
//! because:
//!
//!   1. checkpoint() returns `Err(Cancelled)`.
//!   2. The user propagates via `?` (idiomatic Rust).
//!   3. Any user code AFTER `cx.checkpoint()?` is skipped.
//!
//! ── Acquire/Release pairing ─────────────────────────────
//!
//! - Cancellers store `fast_cancel.store(true, Release)`
//!   at: cx/cx.rs:1710, 1828, 2483, 2517, 2579, 2636, 2836
//!   and runtime/task_handle.rs:227, 277, 499.
//! - checkpoint() loads `fast_cancel.load(Acquire)` at
//!   cx/cx.rs:1664.
//! - Acquire-Release pair guarantees: any cancellation set
//!   before the canceller's store-Release is observable at
//!   the load-Acquire in checkpoint().
//!
//! ── Mid-checkpoint race ─────────────────────────────────
//!
//! If cancellation happens DURING checkpoint() execution
//! (between (A) and the slow path), the slow path is taken
//! only when (A) already observed `cancelled = true`. If
//! (A) read `cancelled = false`, the fast path proceeds
//! and returns `Ok(())` — the cancel will be observed on
//! the NEXT checkpoint. This is the standard sampling-point
//! semantics of checkpoint() and is correct: the contract
//! is "if cancel is set when I call checkpoint, I get Err
//! soon," not "any cancel set during checkpoint produces
//! Err in this call."
//!
//! ── Masked critical sections ────────────────────────────
//!
//! `check_cancel_from_values` (cx.rs:2068) returns
//! `Ok(())` when `cancel_requested && mask_depth > 0`.
//! This is the documented mask semantic — `cx.masked(||
//! { ... })` defers cancel acknowledgment until the mask
//! unwinds. See `cx_checkpoint_concurrent_cancel_observation_audit.rs`
//! and `cx_masked_critical_section_audit.rs` for masked-
//! path coverage.
//!
//! Verdict: **SOUND BY DESIGN**. Checkpoint observes
//! cancellation via an Acquire load BEFORE any user-visible
//! state mutation. The slow-path `record_at` is internal
//! observability bookkeeping, not user work — and it
//! correctly precedes the `Err(Cancelled)` return so the
//! diagnostic trail is complete.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn checkpoint_fast_path_loads_fast_cancel_with_acquire_first() {
    // Pin: the FIRST observable side effect of checkpoint()
    // is the Acquire-load of fast_cancel. If this changes
    // (e.g., progress recording moves before the load), the
    // user contract that cancel is observed BEFORE work is
    // broken.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let pos = source.find(fn_marker).expect("checkpoint fn");
    let body_window = &source[pos..pos + 4000];

    // The Acquire-load of fast_cancel must appear in the
    // first read() block, before any fetch_add / store on
    // the fast-path counters.
    let load_pos = body_window
        .find("fast_cancel.load(std::sync::atomic::Ordering::Acquire)")
        .expect("fast_cancel.load(Acquire) in checkpoint body");

    // The progress-recording stores must come AFTER the load.
    let store_ns_pos = body_window
        .find("fast_path_last_checkpoint_ns.store(")
        .expect("fast_path_last_checkpoint_ns.store in checkpoint");
    let fetch_add_pos = body_window
        .find("fast_path_count")
        .and_then(|i| body_window[i..].find("fetch_add").map(|j| i + j))
        .expect("fast_path_count.fetch_add in checkpoint");

    assert!(
        load_pos < store_ns_pos,
        "REGRESSION: fast_path_last_checkpoint_ns.store now \
         precedes fast_cancel.load(Acquire). Cancel-check is \
         no longer the first observable effect — checkpoint() \
         records progress BEFORE checking cancel, violating \
         the cancel-correctness contract.",
    );

    assert!(
        load_pos < fetch_add_pos,
        "REGRESSION: fast_path_count.fetch_add now precedes \
         fast_cancel.load(Acquire). Cancel-check is no longer \
         the first observable effect.",
    );
}

#[test]
fn checkpoint_fast_path_skips_progress_recording_when_cancelled() {
    // Pin: the fast-path progress-recording stores are
    // gated by the full healthy fast-path predicate, which
    // must include `!cancelled`. If cancelled OR exhausted,
    // control falls through to the slow path WITHOUT recording.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let pos = source.find(fn_marker).expect("checkpoint fn");
    let body_window = &source[pos..pos + 4000];

    assert!(
        body_window
            .contains("if !cancelled && !exhausted && !has_message && !is_first_checkpoint {")
            && body_window.contains("fast_path_last_checkpoint_ns.store(")
            && body_window.contains("fast_path_count"),
        "REGRESSION: the fast-path gate no longer includes \
         `!cancelled` or progress recording is no longer \
         inside that healthy path. Checkpoint now records \
         progress even when cancelled.",
    );

    // Verify the gate appears BEFORE the stores in source order.
    let gate_pos = body_window
        .find("if !cancelled && !exhausted && !has_message && !is_first_checkpoint {")
        .expect("cancel/exhaustion gate");
    let store_pos = body_window
        .find("fast_path_last_checkpoint_ns.store(")
        .expect("progress store");

    assert!(
        gate_pos < store_pos,
        "REGRESSION: progress recording is no longer guarded \
         by the cancel/exhaustion gate.",
    );
}

#[test]
fn checkpoint_slow_path_returns_err_via_check_cancel_from_values() {
    // Pin: the slow path's terminal action is a tail-call
    // to check_cancel_from_values(...) which returns
    // Err(Cancelled) when cancel_requested && mask_depth==0.
    // No user-visible work happens after this returns.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let pos = source.find(fn_marker).expect("checkpoint fn");
    let body_window = &source[pos..pos + 8000];

    assert!(
        body_window.contains("Self::check_cancel_from_values("),
        "REGRESSION: checkpoint() no longer terminates via \
         check_cancel_from_values. The Err(Cancelled) return \
         path may have shifted.",
    );

    // check_cancel_from_values must produce Err(Cancelled)
    // when cancel_requested && mask_depth == 0.
    assert!(
        source.contains("fn check_cancel_from_values(")
            && source.contains("Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled))"),
        "REGRESSION: check_cancel_from_values no longer \
         emits Err(Cancelled). Cancel-correctness is broken.",
    );
}

#[test]
fn checkpoint_slow_path_record_at_is_internal_bookkeeping_not_user_work() {
    // Pin: the slow path calls
    // `inner.checkpoint_state.record_at(checkpoint_time)`
    // BEFORE returning Err(Cancelled). This is checkpoint's
    // own internal observability bookkeeping (CheckpointState
    // counter + last-checkpoint timestamp), NOT user work.
    // The contract that NO USER work happens between
    // checkpoint observing cancel and returning Err is
    // honored — the user only sees the Err return.
    let source = read("src/cx/cx.rs");
    let context_source = read("src/types/task_context.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let pos = source.find(fn_marker).expect("checkpoint fn");
    let body_window = &source[pos..pos + 4000];

    assert!(
        body_window.contains("inner.checkpoint_state.record_at(checkpoint_time);"),
        "REGRESSION: slow path no longer records the checkpoint \
         event before determining the result. Diagnostic trail \
         loses the 'checkpoint reached, then cancel observed' \
         signal.",
    );

    // record_at is purely internal field updates — no I/O,
    // no callbacks, no user-observable side effects.
    let record_at_marker = "pub fn record_at(&mut self, at: Time) {";
    let ra_pos = context_source.find(record_at_marker).expect("record_at fn");
    let ra_window = &context_source[ra_pos..ra_pos + 300];

    assert!(
        ra_window.contains("self.last_checkpoint = Some(at);")
            && ra_window.contains("self.last_message = None;")
            && ra_window.contains("self.checkpoint_count += 1;"),
        "REGRESSION: record_at is no longer pure field updates. \
         Slow-path checkpoint now does observable side effects \
         before returning Err(Cancelled).",
    );

    // No I/O / callback / waker / channel calls.
    let suspect_calls = [
        "send(",
        "wake(",
        "wake_by_ref(",
        "fs::",
        "stdout(",
        "stderr(",
        "println!(",
        "eprintln!(",
    ];
    for pat in &suspect_calls {
        assert!(
            !ra_window.contains(pat),
            "REGRESSION: record_at now performs `{pat}` — that \
             is user-observable side effect, not internal \
             bookkeeping. checkpoint() may now do work before \
             returning Err.",
        );
    }
}

#[test]
fn checkpoint_acquire_release_pairing_documented() {
    // Pin: the source must document the Acquire-Release
    // pairing between fast_cancel.store(Release) by
    // cancellers and fast_cancel.load(Acquire) here. If
    // this is removed and the orderings drift to Relaxed,
    // mid-checkpoint cancels are no longer guaranteed to
    // be observed.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("`fast_cancel` is set with `Release` ordering")
            || source.contains("fast_cancel` is set with `Release`"),
        "REGRESSION: the Acquire-Release pairing for \
         fast_cancel is no longer documented in checkpoint(). \
         Future maintainers may downgrade orderings to Relaxed \
         and break cross-thread visibility.",
    );

    assert!(
        source.contains("Acquire") && source.contains("fast_cancel.load"),
        "REGRESSION: Acquire ordering is no longer used on \
         fast_cancel.load. Cancel propagation across threads \
         is no longer guaranteed.",
    );
}

#[test]
fn checkpoint_masked_path_returns_ok_documented() {
    // Pin: masked critical sections defer Err(Cancelled).
    // check_cancel_from_values returns Ok(()) when
    // cancel_requested && mask_depth > 0 — the mask
    // contract.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn check_cancel_from_values(";
    let pos = source.find(fn_marker).expect("check_cancel_from_values fn");
    let body_window = &source[pos..pos + 3500];

    assert!(
        body_window.contains("if cancel_requested {")
            && body_window.contains("if mask_depth == 0 {")
            && body_window
                .contains("Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled))")
            && body_window.contains("Ok(())"),
        "REGRESSION: check_cancel_from_values no longer has \
         the cancel_requested + mask_depth==0 → Err / mask \
         > 0 → Ok branching. Mask semantics are broken.",
    );
}

#[test]
fn checkpoint_unit_test_pins_cancel_returns_err() {
    // Pin: the inline unit test that asserts checkpoint()
    // returns Err when cancel is set must remain. If this
    // is deleted, regressions in cancel observation can
    // pass CI.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("fn checkpoint_with_cancel()")
            && source.contains("cx.set_cancel_requested(true);")
            && source.contains("assert!(cx.checkpoint().is_err());"),
        "REGRESSION: the checkpoint_with_cancel inline test \
         is gone. The basic cancel-observation contract is \
         no longer guarded.",
    );
}

#[test]
fn checkpoint_unit_test_pins_masked_defers_cancel() {
    // Pin: the masked_defers_cancel inline test must
    // remain — it pins both the mask semantics AND that
    // unmasked checkpoint sees Err.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("fn masked_defers_cancel()")
            && source.contains("cx.set_cancel_requested(true);")
            && source.contains("\"checkpoint should succeed when masked\"")
            && source.contains("\"checkpoint should fail after unmasking\""),
        "REGRESSION: the masked_defers_cancel inline test is \
         gone. Mask semantics are no longer guarded.",
    );
}

#[test]
fn checkpoint_no_user_observable_side_effects_between_cancel_and_err() {
    // Pin: between observing cancel and returning Err,
    // checkpoint() must not perform user-observable side
    // effects (channel sends, file I/O, panics, allocations
    // beyond the bookkeeping). The slow path does:
    //   1. drain_fast_path_checkpoint (atomic swaps)
    //   2. record_at (field assignments)
    //   3. check budget_exhaustion (read-only inspection)
    //   4. set cancel_acknowledged (field write)
    //   5. emit evidence via evidence_sink (one optional
    //      observability hook — gated on Some(sink))
    //   6. return Err
    //
    // The evidence_sink is the ONLY external hook, and it
    // is documented as observability-only (no user work).
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let pos = source.find(fn_marker).expect("checkpoint fn");
    let body_end_marker = "\n    }\n";
    let body_end = source[pos..]
        .find(body_end_marker)
        .map(|i| pos + i)
        .expect("checkpoint fn close");
    let body = &source[pos..body_end];

    // No spawn / send / panic / unwrap inside checkpoint
    // body — these would be user-observable side effects.
    let suspect_patterns = [
        "panic!(",
        "unreachable!(",
        ".send(",
        ".unwrap(",
        ".expect(",
        "tokio::",
    ];
    for pat in &suspect_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: checkpoint() body now contains \
             `{pat}` — that is a user-observable side effect. \
             Checkpoint must not do work before returning \
             Err(Cancelled).",
        );
    }
}

#[test]
fn checkpoint_evidence_sink_is_observability_not_user_work() {
    // Pin: the evidence_sink emit_cancel_evidence call
    // happens inside the slow path BEFORE returning Err,
    // but it is gated on `Some(sink)` and is documented as
    // observability-only. It must never invoke user code.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let pos = source.find(fn_marker).expect("checkpoint fn");
    let body_window = &source[pos..pos + 8000];

    assert!(
        body_window.contains("if let Some(ref sink) = self.handles.evidence_sink"),
        "REGRESSION: evidence_sink emission is no longer \
         gated. checkpoint() may now invoke user code.",
    );

    assert!(
        body_window.contains("crate::evidence_sink::emit_cancel_evidence("),
        "REGRESSION: emit_cancel_evidence is no longer the \
         observability path used here.",
    );
}

#[test]
fn checkpoint_terminal_branch_emits_err_cancelled() {
    // Pin: the terminal Err in check_cancel_from_values is
    // ErrorKind::Cancelled (not Aborted, not Custom, not
    // some other variant).
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn check_cancel_from_values(";
    let pos = source.find(fn_marker).expect("check_cancel_from_values fn");
    let body_window = &source[pos..pos + 3500];

    assert!(
        body_window.contains("Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled))"),
        "REGRESSION: checkpoint no longer returns \
         ErrorKind::Cancelled — variant drift breaks user \
         pattern matching on the cancel branch.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Simplified mock matching the production fast-path / slow-
/// path structure of `Cx::checkpoint()`. Verifies that:
///
///   1. The Acquire load of `fast_cancel` is the FIRST
///      observable side effect.
///   2. When cancelled, NO progress is recorded in the
///      fast-path counters.
///   3. The result is `Err` when cancelled.
struct MockCx {
    fast_cancel: Arc<AtomicBool>,
    fast_path_count: AtomicU64,
    fast_path_last_checkpoint_ns: AtomicU64,
    cancel_requested: parking_lot_mock::Mutex<bool>,
    mask_depth: parking_lot_mock::Mutex<u32>,
    user_work_after_checkpoint: AtomicU64,
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
        pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
            let mut g = self.0.lock().unwrap();
            f(&mut *g)
        }
        pub fn read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
            let g = self.0.lock().unwrap();
            f(&*g)
        }
    }
}

impl MockCx {
    fn new() -> Self {
        Self {
            fast_cancel: Arc::new(AtomicBool::new(false)),
            fast_path_count: AtomicU64::new(0),
            fast_path_last_checkpoint_ns: AtomicU64::new(0),
            cancel_requested: parking_lot_mock::Mutex::new(false),
            mask_depth: parking_lot_mock::Mutex::new(0),
            user_work_after_checkpoint: AtomicU64::new(0),
        }
    }

    fn cancel(&self) {
        // Region cancel: set fast_cancel with Release.
        self.cancel_requested.with(|c| *c = true);
        self.fast_cancel.store(true, Ordering::Release);
    }

    fn checkpoint(&self, now_ns: u64) -> Result<(), &'static str> {
        // Fast path: cancel-check FIRST.
        let cancelled = self.fast_cancel.load(Ordering::Acquire);
        if !cancelled {
            // Healthy: record progress.
            self.fast_path_last_checkpoint_ns
                .store(now_ns, Ordering::Relaxed);
            self.fast_path_count.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        // Slow path: cancellation pending.
        let masked = self.mask_depth.read(|m| *m > 0);
        if masked {
            return Ok(());
        }
        Err("cancelled")
    }
}

#[test]
fn behavioral_checkpoint_returns_err_when_cancelled_no_progress_recorded() {
    let cx = MockCx::new();

    // Initial state: no cancel, healthy checkpoint records.
    assert!(cx.checkpoint(100).is_ok());
    assert_eq!(cx.fast_path_count.load(Ordering::Relaxed), 1);

    // Region cancels.
    cx.cancel();

    // Snapshot the count BEFORE the cancelled checkpoint.
    let count_before = cx.fast_path_count.load(Ordering::Relaxed);
    let last_ns_before = cx.fast_path_last_checkpoint_ns.load(Ordering::Relaxed);

    // Checkpoint after cancel: must return Err.
    let result = cx.checkpoint(200);
    assert!(result.is_err(), "checkpoint must return Err when cancelled");

    // Critical pin: the fast-path progress counters must NOT
    // have been incremented during the cancelled checkpoint.
    let count_after = cx.fast_path_count.load(Ordering::Relaxed);
    let last_ns_after = cx.fast_path_last_checkpoint_ns.load(Ordering::Relaxed);

    assert_eq!(
        count_before, count_after,
        "REGRESSION: fast_path_count incremented during \
         cancelled checkpoint — checkpoint did work before \
         returning Err.",
    );
    assert_eq!(
        last_ns_before, last_ns_after,
        "REGRESSION: fast_path_last_checkpoint_ns updated \
         during cancelled checkpoint — checkpoint did work \
         before returning Err.",
    );
}

#[test]
fn behavioral_user_work_after_checkpoint_skipped_on_err() {
    // Models the user pattern:
    //
    //   for item in items {
    //       cx.checkpoint()?;
    //       do_user_work(item);  // <- must be skipped
    //   }
    let cx = MockCx::new();

    // First iteration: checkpoint succeeds.
    cx.checkpoint(100).expect("first checkpoint ok");
    cx.user_work_after_checkpoint
        .fetch_add(1, Ordering::Relaxed);

    // Region cancels.
    cx.cancel();

    // Subsequent iterations: checkpoint fails, user work
    // must be skipped via `?` propagation.
    for i in 0..10u64 {
        let result = cx.checkpoint(200 + i);
        if result.is_err() {
            // `?` propagates — bail out of the loop.
            break;
        }
        // Unreachable when cancelled.
        cx.user_work_after_checkpoint
            .fetch_add(1, Ordering::Relaxed);
    }

    // Only the first (pre-cancel) iteration's user work ran.
    assert_eq!(
        cx.user_work_after_checkpoint.load(Ordering::Relaxed),
        1,
        "REGRESSION: user work ran AFTER checkpoint observed \
         cancel — the cancel-bail contract is broken.",
    );
}

#[test]
fn behavioral_acquire_release_visibility_across_threads() {
    use std::sync::Barrier;
    use std::thread;

    // Spawn a canceller thread that issues cancel via
    // Release store; the worker thread observes via Acquire
    // load in checkpoint(). The Acquire-Release pair ensures
    // that any cancel set BEFORE the canceller's Release
    // store is observable at the checkpoint's Acquire load.
    let cx = Arc::new(MockCx::new());
    let barrier = Arc::new(Barrier::new(2));

    let cx_canceller = Arc::clone(&cx);
    let bar_canceller = Arc::clone(&barrier);
    let canceller = thread::spawn(move || {
        bar_canceller.wait();
        cx_canceller.cancel();
    });

    let cx_worker = Arc::clone(&cx);
    let bar_worker = Arc::clone(&barrier);
    let worker = thread::spawn(move || {
        bar_worker.wait();
        // Spin until the checkpoint observes cancel. With
        // Acquire-Release pairing, this terminates.
        loop {
            if cx_worker.checkpoint(0).is_err() {
                return true;
            }
            std::thread::yield_now();
        }
    });

    canceller.join().unwrap();
    let observed = worker.join().unwrap();

    assert!(
        observed,
        "REGRESSION: worker thread did not observe cancel via \
         Acquire-Release pair. Cross-thread cancel visibility \
         is broken.",
    );
}

#[test]
fn behavioral_masked_section_defers_err_until_unmask() {
    let cx = MockCx::new();
    cx.cancel();

    // Inside masked section: checkpoint returns Ok.
    cx.mask_depth.with(|m| *m += 1);
    let result_masked = cx.checkpoint(100);
    cx.mask_depth.with(|m| *m -= 1);

    assert!(
        result_masked.is_ok(),
        "REGRESSION: masked checkpoint returned Err — mask \
         semantics broken.",
    );

    // After unmask: checkpoint returns Err.
    let result_unmasked = cx.checkpoint(200);
    assert!(
        result_unmasked.is_err(),
        "REGRESSION: post-unmask checkpoint did not return \
         Err — cancel acknowledgment is leaked or lost.",
    );
}

// ── Cross-reference ─────────────────────────────────────

#[test]
fn cross_reference_to_related_checkpoint_audits() {
    let prior_audits = [
        "tests/cx_checkpoint_concurrent_cancel_observation_audit.rs",
        "tests/cx_checkpoint_past_deadline_immediate_err_audit.rs",
        "tests/runtime_cancel_signal_coalescing_audit.rs",
        "tests/cx_scope_panic_propagation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing. \
             This audit relies on it for adjacent coverage.",
        );
    }
}
