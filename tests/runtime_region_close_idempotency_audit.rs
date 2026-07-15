//! Audit + regression test for region.close() idempotency.
//!
//! Operator's question: "when region.close() is called
//! multiple times on the same region, do they all observe
//! the same outcome (correct: idempotent) or does each
//! subsequent call cause unexpected behavior?"
//!
//! Audit findings:
//!
//!   `RegionRecord::begin_close()` is **fully idempotent**
//!   via an atomic compare-and-swap on the region's state
//!   field. Multiple calls converge on the same observable
//!   state — the first call transitions Open → Closing,
//!   subsequent calls observe Closing (or later) and
//!   return false. The cancel_reason is STRENGTHENED (via
//!   `CancelReason::strengthen`), not overwritten, so
//!   parallel-call attribution is preserved.
//!
//!   Chain:
//!
//!   1. **Atomic state transition** (record/region.rs:305):
//!      ```ignore
//!      pub fn transition(&self, from: RegionState, to: RegionState) -> bool {
//!          self.inner
//!              .compare_exchange(
//!                  from.as_u8(),
//!                  to.as_u8(),
//!                  Ordering::AcqRel,
//!                  Ordering::Acquire,
//!              )
//!              .is_ok()
//!      }
//!      ```
//!      The CAS is what makes the transition atomic — only
//!      ONE caller across all threads can flip Open →
//!      Closing. Returns `true` on success, `false` on
//!      failure (the from-state didn't match).
//!
//!   2. **`begin_close` returns the transition outcome**
//!      (region.rs:894):
//!      ```ignore
//!      fn begin_close_transition(&self, reason: Option<CancelReason>) -> bool {
//!          let mut inner = self.inner.write();
//!          if self.state.load() == RegionState::Closed {
//!              return false;
//!          }
//!          if let Some(reason) = reason {
//!              if let Some(existing) = &mut inner.cancel_reason {
//!                  existing.strengthen(&reason);
//!              } else {
//!                  inner.cancel_reason = Some(reason);
//!              }
//!          }
//!          let transitioned = self.state.transition(
//!              RegionState::Open, RegionState::Closing);
//!          drop(inner);
//!          transitioned
//!      }
//!      pub fn begin_close(&self, reason: Option<CancelReason>) -> bool {
//!          let transitioned = self.begin_close_transition(reason);
//!          if transitioned {
//!              self.trace_state_change(RegionState::Closing);
//!          }
//!          transitioned
//!      }
//!      ```
//!      Three idempotent properties matter here:
//!      closed-state early return, where an already Closed
//!      region returns false without side effects; reason
//!      strengthening, where `existing.strengthen(&reason)`
//!      preserves the higher-severity reason across multiple
//!      calls; and CAS-only transition, where the Open →
//!      Closing flip is atomic and later calls observe the
//!      new state without repeating the transition.
//!
//!   3. **Trace event emitted only on the winning transition**
//!      (region.rs:912-914): `trace_state_change` fires
//!      ONLY when the CAS succeeded. Subsequent calls
//!      don't emit duplicate trace events — debugging
//!      output reflects the actual state-machine
//!      transitions, not the call count.
//!
//!   4. **`strengthen_cancel_reason` is the no-CAS sibling**
//!      (region.rs:486): used by cancel_request when
//!      begin_close returns false (region already in
//!      non-Open state). It updates the reason via
//!      `existing.strengthen(&reason)` without attempting
//!      a state transition. Pairs with begin_close to
//!      handle the "already-closing, but a stronger reason
//!      arrived" case.
//!
//!   5. **`cancel_request` first pass uses the strengthening
//!      branch** (state.rs:2650-2652):
//!      ```ignore
//!      if region.begin_close_without_subscriber(Some(region_reason.clone())) {
//!          // ... emit RegionCloseBegin trace
//!      } else if region.state() != RegionState::Closed {
//!          region.strengthen_cancel_reason(region_reason);
//!      }
//!      ```
//!      The else-branch handles repeated cancel_request
//!      calls with different reasons — the cancel_reason is
//!      strengthened even when no state transition fires.
//!
//!   6. **Subsequent transitions are also CAS-protected**:
//!      `begin_drain` (Closing → Draining), `begin_finalize`
//!      (Closing/Draining → Finalizing), `complete_close`
//!      (Finalizing → Closed) — all use the same atomic
//!      transition primitive. Each transition is single-
//!      shot; subsequent calls observe the new state and
//!      return false.
//!
//!   7. **`complete_close` enforces structural quiescence**
//!      (region.rs:952-964): the final transition only
//!      fires when children/tasks/pending_obligations/
//!      finalizers are all empty. Idempotency is preserved
//!      via the same CAS — multiple calls during a
//!      pre-quiescent state all return false.
//!
//! Verdict: **SOUND**. region.close() is fully idempotent
//! by construction. The atomic CAS on RegionState (with
//! AcqRel ordering) gives single-winner semantics across
//! threads. The cancel_reason strengthening preserves
//! attribution under parallel calls with different reasons.
//! Trace events fire only on the winning transition —
//! debugging output is clean.
//!
//! A regression that:
//!   - replaced the atomic CAS in transition() with a
//!     read-then-store pattern (would race; multiple
//!     callers could each "succeed" and emit duplicate
//!     trace events, mutate state non-deterministically),
//!   - changed begin_close to OVERWRITE cancel_reason
//!     instead of strengthen (would lose attribution
//!     when a stronger reason arrives second),
//!   - removed the closed-state early-return (would let
//!     a Closed → Closing transition attempt fire the
//!     trace event again — duplicate observability),
//!   - used Relaxed ordering on the CAS instead of AcqRel
//!     (could observe stale state; cross-thread
//!     transitions might double-fire),
//!   - removed the strengthen_cancel_reason branch from
//!     cancel_request (would silently drop reason
//!     strengthening when the region is already closing),
//!   - removed the structural-quiescence check in
//!     complete_close (would close a region with live
//!     tasks/children — UB),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn region_state_transition_uses_atomic_compare_exchange_with_acqrel() {
    // Pin (link 1): RegionState::transition uses
    // compare_exchange with AcqRel ordering. The atomic CAS
    // is what makes the transition single-winner across
    // threads.
    let source = read("src/record/region.rs");

    let fn_marker = "pub fn transition(&self, from: RegionState, to: RegionState) -> bool {";
    let start = source.find(fn_marker).expect("transition fn");
    let body_end = source[start..].find("\n    }\n").expect("transition close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("compare_exchange("),
        "REGRESSION: transition() no longer uses \
         compare_exchange. Without the atomic CAS, \
         concurrent close() calls race — multiple callers \
         could each succeed and emit duplicate trace events.",
    );

    assert!(
        body.contains("Ordering::AcqRel,"),
        "REGRESSION: transition() no longer uses AcqRel \
         ordering on the CAS. Weaker ordering could let a \
         concurrent thread observe stale state — cross-\
         thread transitions might double-fire.",
    );

    // The .is_ok() return distinguishes successful CAS from
    // failed CAS.
    assert!(
        body.contains(".is_ok()"),
        "REGRESSION: transition() no longer returns the CAS \
         result via .is_ok(). Callers can't distinguish \
         winning from losing the race.",
    );
}

#[test]
fn begin_close_returns_false_when_already_closed() {
    // Pin (link 2a): begin_close returns false (early) when
    // the region is already Closed. Without this, attempting
    // to close a Closed region would fire the trace event
    // again or attempt a no-op CAS.
    let source = read("src/record/region.rs");

    let fn_marker = "fn begin_close_transition(&self, reason: Option<CancelReason>) -> bool {";
    let start = source.find(fn_marker).expect("begin_close transition fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("begin_close transition close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if self.state.load() == RegionState::Closed {")
            && body.contains("return false;"),
        "REGRESSION: begin_close no longer early-returns on \
         Closed state. Repeated close() calls on a closed \
         region may emit duplicate trace events or attempt \
         a transition that's structurally impossible.",
    );
}

#[test]
fn begin_close_strengthens_existing_cancel_reason_not_overwrites() {
    // Pin (link 2b): begin_close strengthens the existing
    // cancel_reason via existing.strengthen(&reason) when a
    // prior reason exists. Without this, the second call's
    // reason would overwrite the first — losing attribution.
    let source = read("src/record/region.rs");

    let fn_marker = "fn begin_close_transition(&self, reason: Option<CancelReason>) -> bool {";
    let start = source.find(fn_marker).expect("begin_close transition fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("begin_close transition close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if let Some(existing) = &mut inner.cancel_reason {")
            && body.contains("existing.strengthen(&reason);"),
        "REGRESSION: begin_close no longer strengthens an \
         existing cancel_reason. Multiple close() calls \
         with different reasons lose attribution — the \
         second call's reason silently overwrites the first.",
    );

    // The Else arm sets a new reason when none exists.
    assert!(
        body.contains("inner.cancel_reason = Some(reason);"),
        "REGRESSION: begin_close no longer sets cancel_reason \
         when none exists. The first close() call's reason \
         is silently dropped.",
    );
}

#[test]
fn begin_close_uses_atomic_transition_for_open_to_closing_flip() {
    // Pin (link 2c): the Open → Closing transition uses the
    // atomic transition() method. The CAS is what makes
    // begin_close single-winner.
    let source = read("src/record/region.rs");

    let fn_marker = "fn begin_close_transition(&self, reason: Option<CancelReason>) -> bool {";
    let start = source.find(fn_marker).expect("begin_close transition fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("begin_close transition close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self\n            .state\n            .transition(RegionState::Open, RegionState::Closing)")
            || body.contains(".transition(RegionState::Open, RegionState::Closing)"),
        "REGRESSION: begin_close no longer uses transition() \
         for the Open → Closing flip. Without the atomic \
         CAS, concurrent calls all 'succeed' — multiple \
         RegionCloseBegin trace events fire.",
    );
}

#[test]
fn begin_close_emits_trace_only_on_winning_transition() {
    // Pin (link 3): trace_state_change fires ONLY when
    // transitioned == true (the CAS succeeded). Subsequent
    // losing calls don't emit trace events — debugging
    // output is clean.
    let source = read("src/record/region.rs");

    let fn_marker = "pub fn begin_close(&self, reason: Option<CancelReason>) -> bool {";
    let start = source.find(fn_marker).expect("begin_close fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("begin_close close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if transitioned {")
            && body.contains("self.trace_state_change(RegionState::Closing);"),
        "REGRESSION: begin_close no longer gates the trace \
         event on transitioned. Either the trace fires on \
         every call (duplicate trace events under concurrent \
         close) or it never fires (lost observability).",
    );
}

#[test]
fn runtime_cancel_close_transition_does_not_enter_tracing_subscriber() {
    // RuntimeState::cancel_request commonly executes beneath the scheduler's
    // outer state lock. Its RegionRecord transition must therefore share the
    // same CAS/reason mutation as public begin_close without invoking the
    // tracing subscriber. RuntimeState records RegionCloseBegin in its
    // callback-free TraceBuffer instead.
    let region_source = read("src/record/region.rs");
    let marker = "pub(crate) fn begin_close_without_subscriber(";
    let start = region_source
        .find(marker)
        .expect("subscriber-free begin_close variant");
    let body_end = region_source[start..]
        .find("\n    }\n")
        .expect("subscriber-free begin_close close");
    let body = &region_source[start..start + body_end];

    assert!(
        body.contains("self.begin_close_transition(reason)")
            && !body.contains("trace_state_change(")
            && !body.contains("debug!("),
        "REGRESSION: RuntimeState's close transition can invoke the tracing \
         subscriber beneath the outer state lock.",
    );

    let state_source = read("src/runtime/state.rs");
    assert!(
        state_source
            .contains("if region.begin_close_without_subscriber(Some(region_reason.clone())) {")
            && state_source.contains("TraceEventKind::RegionCloseBegin"),
        "REGRESSION: cancel_request no longer couples its subscriber-free \
         RegionRecord transition to the internal RegionCloseBegin trace event.",
    );
}

#[test]
fn strengthen_cancel_reason_provides_no_cas_sibling_for_already_closing_regions() {
    // Pin (link 4): strengthen_cancel_reason updates the
    // reason without attempting a state transition. Pairs
    // with begin_close — when begin_close returns false
    // (already closing), strengthen_cancel_reason still
    // updates attribution.
    let source = read("src/record/region.rs");

    let fn_marker = "pub fn strengthen_cancel_reason(&self, reason: CancelReason) {";
    let start = source.find(fn_marker).expect("strengthen_cancel_reason fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("strengthen_cancel_reason close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("existing.strengthen(&reason);"),
        "REGRESSION: strengthen_cancel_reason no longer \
         calls existing.strengthen. Repeated cancel_request \
         calls on a Closing region lose reason \
         strengthening — attribution drifts.",
    );

    // Forbid a CAS attempt — strengthen_cancel_reason MUST
    // NOT try to flip the state.
    assert!(
        !body.contains(".transition("),
        "REGRESSION: strengthen_cancel_reason now attempts a \
         state transition. The split between begin_close \
         (CAS + reason) and strengthen_cancel_reason \
         (reason-only) is intentional — conflating them \
         could double-fire trace events.",
    );
}

#[test]
fn cancel_request_falls_back_to_strengthen_when_begin_close_returns_false() {
    // Pin (link 5): cancel_request's first pass uses
    // begin_close OR strengthen_cancel_reason depending on
    // the begin_close return value. This is what makes
    // repeated cancel_request calls converge on the
    // strongest reason.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("if region.begin_close_without_subscriber(Some(region_reason.clone())) {")
            && source.contains(
                "} else if region.state() != crate::record::region::RegionState::Closed {"
            )
            && source.contains("region.strengthen_cancel_reason(region_reason);"),
        "REGRESSION: cancel_request first pass no longer \
         falls back to strengthen_cancel_reason when \
         the callback-free close transition returns false. Repeated cancels with \
         different reasons silently drop the second reason \
         when the region is already closing.",
    );
}

#[test]
fn complete_close_enforces_structural_quiescence_before_final_transition() {
    // Pin (link 7): complete_close (Finalizing → Closed)
    // checks children/tasks/pending_obligations/finalizers
    // are all empty. Without this, a region could be marked
    // Closed while live work is still in flight — UB.
    let source = read("src/record/region.rs");

    let fn_marker = "pub fn complete_close(&self) -> bool {";
    let start = source.find(fn_marker).expect("complete_close fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("complete_close close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("inner.children.is_empty()")
            && body.contains("inner.tasks.is_empty()")
            && body.contains("inner.pending_obligations == 0")
            && body.contains("inner.finalizers.is_empty()"),
        "REGRESSION: complete_close no longer enforces \
         structural quiescence (children/tasks/obligations/\
         finalizers all empty). A region could be Closed \
         while live work persists — UB pathway.",
    );

    // The transition is also CAS-protected.
    assert!(
        body.contains(".transition(RegionState::Finalizing, RegionState::Closed)"),
        "REGRESSION: complete_close no longer uses atomic \
         transition for the Finalizing → Closed flip. \
         Repeated complete_close calls would race.",
    );
}

#[test]
fn intermediate_state_transitions_use_atomic_cas() {
    // Pin (link 6): begin_drain (Closing → Draining) and
    // begin_finalize (Closing/Draining → Finalizing) also
    // use atomic transitions. Each is single-shot.
    let source = read("src/record/region.rs");

    assert!(
        source.contains(".transition(RegionState::Closing, RegionState::Draining)"),
        "REGRESSION: begin_drain no longer uses the atomic \
         transition for Closing → Draining. Repeated calls \
         would race.",
    );

    assert!(
        source.contains(".transition(RegionState::Closing, RegionState::Finalizing)")
            || source.contains(".transition(RegionState::Draining, RegionState::Finalizing)"),
        "REGRESSION: begin_finalize no longer uses atomic \
         transition. Repeated calls would race.",
    );
}

// ─────────── BEHAVIORAL PIN: concurrent close idempotency ──
//
// Direct simulation: build a MockRegion with state=Open,
// have N threads all call begin_close concurrently, verify
// EXACTLY ONE returns true (the winner). All others return
// false. Final state is Closing.

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
enum MockRegionState {
    Open = 0,
    Closing = 1,
    Closed = 2,
}

impl MockRegionState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Open,
            1 => Self::Closing,
            _ => Self::Closed,
        }
    }
}

struct MockRegion {
    state: AtomicU8,
}

impl MockRegion {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(MockRegionState::Open as u8),
        }
    }

    fn state(&self) -> MockRegionState {
        MockRegionState::from_u8(self.state.load(Ordering::Acquire))
    }

    fn begin_close(&self) -> bool {
        if self.state() == MockRegionState::Closed {
            return false;
        }
        self.state
            .compare_exchange(
                MockRegionState::Open as u8,
                MockRegionState::Closing as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

#[test]
fn concurrent_begin_close_calls_have_exactly_one_winner() {
    // Behavioral pin: 16 threads all call begin_close on
    // the same region. EXACTLY ONE returns true; all
    // others return false. Final state is Closing.
    let region = Arc::new(MockRegion::new());
    let barrier = Arc::new(Barrier::new(16));
    let winners = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let mut handles = Vec::new();
    for _ in 0..16 {
        let region = Arc::clone(&region);
        let barrier = Arc::clone(&barrier);
        let winners = Arc::clone(&winners);
        handles.push(thread::spawn(move || {
            barrier.wait();
            if region.begin_close() {
                winners.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }

    let winner_count = winners.load(Ordering::Relaxed);
    assert_eq!(
        winner_count, 1,
        "REGRESSION: concurrent begin_close had {winner_count} \
         winners (expected exactly 1). The atomic CAS is not \
         giving single-winner semantics — multiple threads \
         each 'succeed' and the trace event would fire \
         multiple times.",
    );

    assert_eq!(
        region.state(),
        MockRegionState::Closing,
        "REGRESSION: final state after concurrent close is \
         not Closing. Either the CAS is broken or the \
         transition was overwritten by a subsequent call.",
    );
}

#[test]
fn sequential_begin_close_calls_are_idempotent() {
    // Behavioral pin: sequential calls to begin_close on
    // the same region — first returns true, all subsequent
    // return false. State stays Closing throughout (no
    // re-transition).
    let region = MockRegion::new();

    let first = region.begin_close();
    assert!(first, "first call should win the transition");
    assert_eq!(region.state(), MockRegionState::Closing);

    for i in 1..100 {
        let result = region.begin_close();
        assert!(
            !result,
            "REGRESSION: subsequent begin_close call #{i} \
             returned true. Idempotency is broken — state \
             may oscillate.",
        );
        assert_eq!(
            region.state(),
            MockRegionState::Closing,
            "REGRESSION: state changed across sequential \
             begin_close calls. Should remain Closing after \
             the first winning call.",
        );
    }
}

#[test]
fn begin_close_on_closed_region_returns_false_no_transition() {
    // Behavioral pin: begin_close on a region in the Closed
    // state returns false without attempting any transition.
    // This is the closed-state early-return guard.
    let region = MockRegion::new();
    region
        .state
        .store(MockRegionState::Closed as u8, Ordering::Release);

    let result = region.begin_close();
    assert!(
        !result,
        "REGRESSION: begin_close on Closed region returned \
         true. The closed-state early-return guard is \
         broken — closed regions could be re-transitioned, \
         producing inconsistent state.",
    );

    assert_eq!(
        region.state(),
        MockRegionState::Closed,
        "REGRESSION: begin_close on Closed region mutated \
         the state. The early-return guard must be a true \
         no-op.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_region_close_timed_lane_task_cancellation_audit.rs",
        "tests/runtime_cancel_cause_chain_depth_audit.rs",
        "tests/scheduler_cancel_storm_propagation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
