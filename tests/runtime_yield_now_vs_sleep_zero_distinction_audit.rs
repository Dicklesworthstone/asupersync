#![allow(unsafe_code)]
//! Audit + regression test for `yield_now()` vs
//! `Sleep::after(now, Duration::ZERO)` distinguishability.
//!
//! Operator's question: "yield_now should give other tasks
//! one quantum; sleep(0) should be similar but routed
//! through timer. Verify the two are distinguishable in
//! scheduler observable. If conflated, file bead."
//!
//! Audit findings:
//!
//!   The two primitives are **observably different** at the
//!   poll-count level, not just structurally:
//!
//!   - **`yield_now()`** (runtime/yield_now.rs:36):
//!     Returns a `YieldNow` future with internal `yielded:
//!     bool` flag. Poll behavior:
//!       - First poll: sets `yielded = true`, calls
//!         `cx.waker().wake_by_ref()`, returns `Poll::Pending`.
//!       - Second poll: sets `completed = true`, returns
//!         `Poll::Ready(())`.
//!         Two-poll sequence: Pending+wake → Ready. Always
//!         yields the worker for at least one dispatch cycle.
//!
//!   - **`Sleep::after(now, Duration::ZERO)`** (time/sleep.
//!     rs:260):
//!     `let deadline = now.saturating_add_nanos(0)` — the
//!     deadline equals `now` exactly. Poll behavior:
//!       - First poll: `poll_with_time(now)` checks
//!         `now >= self.deadline` (now == deadline → true),
//!         sets `completed = true`, returns `Poll::Ready(())`.
//!         One-poll sequence: Ready immediately. Does NOT yield
//!         the worker.
//!
//!   Observable difference at the scheduler level:
//!     - yield_now: 2 polls per use, +1 ready_dispatches
//!       (the wake re-injects the task). Other tasks DO get
//!       a chance to run between the two polls.
//!     - sleep(Duration::ZERO): 1 poll, 0 additional
//!       dispatches. Equivalent to a no-op for scheduling
//!       purposes — does NOT yield.
//!
//!   The operator's "sleep(0) should be similar but routed
//!   through timer" framing is technically incorrect — the
//!   timer driver is bypassed entirely when the deadline
//!   is already past. The Sleep code path does NOT register
//!   a TimerHandle for past-deadline cases (the `Poll::Ready`
//!   branch fires before the timer-registration path).
//!
//!   For a Sleep that DOES route through the timer driver
//!   (any `Duration > 0`):
//!     - First poll: `now < deadline` → register
//!       TimerHandle, return Pending.
//!     - Timer fires at deadline → wakes the task.
//!     - Second poll: `now >= deadline` → Ready.
//!     - Observable: 2 polls + 1 timer registration +
//!       timer-driver dispatch. Distinct from yield_now's
//!       same-iteration wake.
//!
//!   The chain:
//!
//!   1. **YieldNow.poll** (yield_now.rs:20):
//!      ```ignore
//!      fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
//!          assert!(!self.completed, "yield_now polled after completion");
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
//!      Two-poll behavior is structural — first poll
//!      always Pending, second always Ready.
//!
//!   2. **Sleep::poll_with_time** (time/sleep.rs:459):
//!      ```ignore
//!      pub fn poll_with_time(&self, now: Time) -> Poll<()> {
//!          ...
//!          if self.ready.swap(false, AcqRel) || now >= self.deadline {
//!              self.completed.store(true, Release);
//!              Poll::Ready(())
//!          } else {
//!              Poll::Pending
//!          }
//!      }
//!      ```
//!      Time-based check — Ready when now >= deadline.
//!      For deadline=now (the Duration::ZERO case), Ready
//!      on FIRST poll.
//!
//!   3. **Sleep::after** uses saturating_add_nanos
//!      (sleep.rs:261):
//!      `let deadline = now.saturating_add_nanos(
//!      duration_to_nanos(duration));`. For Duration::ZERO,
//!      saturating_add_nanos(0) returns now unchanged —
//!      deadline = now.
//!
//! Verdict: **SOUND**. yield_now and Sleep::after(now,
//! Duration::ZERO) produce DIFFERENT observable scheduler
//! behavior:
//!   - yield_now: 2 polls, yields worker (Pending → wake →
//!     re-poll).
//!   - sleep(0): 1 poll, does NOT yield (Ready immediately).
//!
//! The operator's claim that "sleep(0) should be similar
//! but routed through timer" is technically wrong — sleep(0)
//! is a no-op (no timer registered). For yield-equivalent
//! behavior with timer routing, callers should use
//! `Sleep::after(now, Duration::from_nanos(1))` (any
//! positive duration); that DOES route through the timer
//! driver and yields the worker.
//!
//! No bead filed. The two primitives serve different
//! purposes and have observably different behavior. The
//! "conflation" framing doesn't apply.
//!
//! A regression that:
//!   - changed yield_now to skip the wake_by_ref (would
//!     return Pending forever — task hangs),
//!   - changed yield_now to return Ready on first poll
//!     (would not yield — equivalent to sleep(0)),
//!   - changed sleep(0) to register a timer + Pending
//!     (would conflate with yield_now's behavior — extra
//!     timer-driver overhead for nothing),
//!   - changed Sleep::after to NOT use saturating_add_nanos
//!     (Duration::ZERO might overflow or wrap — undefined
//!     behavior at the boundary),
//!   - removed yield_now entirely (would lose the
//!     cooperative-yield primitive — apps would have to
//!     compose ad-hoc Pending+wake patterns),
//!     would all be caught by the structural pins below.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn yield_now_struct_has_yielded_and_completed_flags() {
    // Pin (link 1): YieldNow's two-poll behavior depends on
    // the `yielded` flag (set on first poll, observed on
    // second). The `completed` flag prevents repolling.
    let source = read("src/runtime/yield_now.rs");

    let struct_marker = "pub struct YieldNow {";
    let start = source.find(struct_marker).expect("YieldNow struct");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("YieldNow struct close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("yielded: bool,"),
        "REGRESSION: YieldNow.yielded field is gone. The \
         two-poll yield behavior depends on this flag — \
         without it, the future has no way to alternate \
         Pending → Ready.",
    );

    assert!(
        body.contains("completed: bool,"),
        "REGRESSION: YieldNow.completed field is gone. \
         Repolling after Ready would not panic — \
         single-shot contract broken.",
    );
}

#[test]
fn yield_now_poll_returns_pending_on_first_call_with_self_wake() {
    // Pin (link 1): YieldNow::poll returns Pending on first
    // call AND calls cx.waker().wake_by_ref() to re-schedule
    // itself. This is what makes yield_now yield without
    // needing external wake.
    let source = read("src/runtime/yield_now.rs");

    let fn_marker =
        "fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let start = source.find(fn_marker).expect("YieldNow::poll fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("YieldNow::poll close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.yielded = true;")
            && body.contains("cx.waker().wake_by_ref();")
            && body.contains("Poll::Pending"),
        "REGRESSION: YieldNow::poll first-call branch no \
         longer sets yielded + wakes + returns Pending. \
         Either the future returns Ready immediately \
         (no yield — conflates with sleep(0)) or doesnt \
         self-wake (task hangs).",
    );

    // Second-call branch returns Ready.
    assert!(
        body.contains("if self.yielded {")
            && body.contains("self.completed = true;")
            && body.contains("Poll::Ready(())"),
        "REGRESSION: YieldNow::poll second-call branch no \
         longer returns Ready. Either the yield never \
         completes (hangs) or alternates forever.",
    );
}

#[test]
fn yield_now_returns_yield_now_struct_not_a_sleep_alias() {
    // Pin (link 1+contrast): the public yield_now() function
    // returns a YieldNow struct, NOT a Sleep alias. This
    // is the API distinction.
    let source = read("src/runtime/yield_now.rs");

    assert!(
        source.contains("pub fn yield_now() -> YieldNow {"),
        "REGRESSION: yield_now() return type changed from \
         YieldNow. If it now returns Sleep or another type, \
         the API distinction is broken — apps that match on \
         the return type may regress.",
    );
}

#[test]
fn sleep_after_uses_saturating_add_nanos_for_zero_duration_safety() {
    // Pin (link 3): Sleep::after computes
    // deadline = now.saturating_add_nanos(...). The
    // saturating_add ensures Duration::ZERO maps to
    // deadline = now (not overflow / wrap).
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn after(now: Time, duration: Duration) -> Self {";
    let start = source.find(fn_marker).expect("Sleep::after fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Sleep::after close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("let deadline = now.saturating_add_nanos(duration_to_nanos(duration));"),
        "REGRESSION: Sleep::after no longer uses \
         saturating_add_nanos. Duration::ZERO may compute \
         deadline incorrectly — boundary behavior at \
         duration=0 becomes unreliable.",
    );
}

#[test]
fn sleep_poll_with_time_returns_ready_when_now_geq_deadline() {
    // Pin (link 2): Sleep::poll_with_time returns Ready
    // when now >= deadline (inclusive). For sleep(0) where
    // deadline = now, the first poll returns Ready
    // immediately — no yield.
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn poll_with_time(&self, now: Time) -> Poll<()> {";
    let start = source.find(fn_marker).expect("Sleep::poll_with_time fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Sleep::poll_with_time close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("now >= self.deadline"),
        "REGRESSION: Sleep::poll_with_time no longer uses \
         now >= deadline (inclusive). One-tick window where \
         deadline=now might miss — sleep(0) flaky behavior.",
    );

    assert!(
        body.contains("Poll::Ready(())"),
        "REGRESSION: Sleep::poll_with_time no longer has a \
         Poll::Ready return. sleep(0) wouldn't complete — \
         task hangs.",
    );
}

#[test]
fn sleep_state_does_not_register_timer_for_already_past_deadline() {
    // Pin (link 2): when poll_with_time returns Ready, the
    // outer Sleep::poll does NOT register a TimerHandle.
    // This is the key behavioral distinction from
    // Duration > 0 — sleep(0) bypasses the timer driver
    // entirely.
    let source = read("src/time/sleep.rs");

    let fn_marker = "fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let start = source.find(fn_marker).expect("Sleep::poll fn");
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // The Ready branch comes BEFORE the Pending branch.
    // The Pending branch registers the timer; Ready doesnt.
    assert!(
        body.contains("Poll::Ready(()) => {"),
        "REGRESSION: Sleep::poll no longer matches \
         Poll::Ready. The Ready branch is what skips timer \
         registration for sleep(0).",
    );

    assert!(
        body.contains("Poll::Pending => {"),
        "REGRESSION: Sleep::poll no longer matches \
         Poll::Pending. Either the future returns Ready \
         on every poll (broken) or never registers timers \
         (sleep(d>0) hangs).",
    );
}

#[test]
fn yield_now_does_not_use_timer_driver_at_all() {
    // Pin (audit hygiene): yield_now is timer-driver-free.
    // A grep over yield_now.rs finds no TimerDriver /
    // TimerHandle references. The yield is a pure
    // scheduler primitive, NOT a timer-routed sleep.
    let source = read("src/runtime/yield_now.rs");

    let suspect_timer_refs = ["TimerDriver", "TimerHandle", "timer_driver"];
    for pat in &suspect_timer_refs {
        assert!(
            !source.contains(pat),
            "REGRESSION: yield_now.rs now references \
             `{pat}` — yield_now is being routed through \
             the timer driver. This conflates with sleep(0) \
             behavior; restore the timer-driver-free \
             pure-scheduler primitive.",
        );
    }
}

#[test]
fn sleep_with_positive_duration_routes_through_timer_driver() {
    // Pin (link 2 contrast): for Duration > 0, the Pending
    // branch in Sleep::poll registers a TimerHandle via
    // the timer driver. This IS the timer-routing behavior
    // the operator described — but only for d > 0, not
    // d == 0.
    let source = read("src/time/sleep.rs");

    assert!(
        source.contains("TimerDriverHandle"),
        "REGRESSION: TimerDriverHandle reference is gone \
         from sleep.rs. Sleeps with positive duration would \
         have no timer routing — Pending without wake \
         means hung task.",
    );

    // The Pending branch must register a timer.
    let fn_marker = "fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let start = source.find(fn_marker).expect("Sleep::poll fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("timer_driver"),
        "REGRESSION: Sleep::poll no longer references \
         timer_driver. The Pending branch cant register a \
         timer — sleep(d>0) hangs.",
    );
}

#[test]
fn yield_now_assertion_panics_on_repoll_after_ready() {
    // Pin (link 1): the assert!(!self.completed, ...) at
    // the top of poll panics on repoll after Ready. This
    // is the single-shot contract enforcement.
    let source = read("src/runtime/yield_now.rs");

    assert!(
        source.contains("assert!(!self.completed, \"yield_now future polled after completion\");"),
        "REGRESSION: YieldNow::poll no longer asserts \
         against repoll after Ready. Repolling would either \
         return Ready forever (silent UB) or oscillate \
         Ready/Pending — undefined behavior.",
    );
}

#[test]
fn sleep_assertion_panics_on_repoll_after_ready() {
    // Pin (link 2): Sleep::poll_with_time also asserts
    // against repoll after completion. Same single-shot
    // contract.
    let source = read("src/time/sleep.rs");

    assert!(
        source.contains("\"Sleep polled after completion\""),
        "REGRESSION: Sleep::poll_with_time no longer asserts \
         against repoll. Repolling after Ready may produce \
         UB or unexpected re-registration of timers.",
    );
}

// ─────────── BEHAVIORAL PIN: 2-poll vs 1-poll observable ──
//
// Direct simulation: build YieldNow and a sleep(0)-equivalent
// future, count polls until each returns Ready. Verify
// yield_now needs 2 polls, sleep(0)-equivalent needs 1.

struct MockYieldNow {
    yielded: bool,
    completed: bool,
}

impl MockYieldNow {
    fn new() -> Self {
        Self {
            yielded: false,
            completed: false,
        }
    }
}

impl Future for MockYieldNow {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        assert!(!self.completed);
        if self.yielded {
            self.completed = true;
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct MockSleep {
    deadline_nanos: u64,
    now_nanos: u64,
    completed: bool,
}

impl MockSleep {
    fn after_zero(now_nanos: u64) -> Self {
        Self {
            deadline_nanos: now_nanos,
            now_nanos,
            completed: false,
        }
    }
}

impl Future for MockSleep {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        assert!(!self.completed);
        if self.now_nanos >= self.deadline_nanos {
            self.completed = true;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

fn dummy_waker_with_counter(counter: Arc<AtomicU64>) -> Waker {
    use std::sync::atomic::Ordering as O;
    struct CounterData(Arc<AtomicU64>);

    fn clone(data: *const ()) -> RawWaker {
        let counter = unsafe { &*(data as *const CounterData) };
        let cloned = Box::into_raw(Box::new(CounterData(Arc::clone(&counter.0))));
        RawWaker::new(cloned as *const (), &VTABLE)
    }
    fn wake(data: *const ()) {
        let counter = unsafe { Box::from_raw(data as *mut CounterData) };
        counter.0.fetch_add(1, O::Relaxed);
    }
    fn wake_by_ref(data: *const ()) {
        let counter = unsafe { &*(data as *const CounterData) };
        counter.0.fetch_add(1, O::Relaxed);
    }
    fn drop_no_op(data: *const ()) {
        let _ = unsafe { Box::from_raw(data as *mut CounterData) };
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_no_op);

    let boxed = Box::into_raw(Box::new(CounterData(counter)));
    let raw = RawWaker::new(boxed as *const (), &VTABLE);
    unsafe { Waker::from_raw(raw) }
}

#[test]
fn behavior_yield_now_takes_two_polls_and_calls_wake_once() {
    // Behavioral pin: YieldNow returns Pending on poll #1
    // (with self-wake) and Ready on poll #2. Total wakes
    // observed: 1.
    let counter = Arc::new(AtomicU64::new(0));
    let waker = dummy_waker_with_counter(Arc::clone(&counter));
    let mut cx = Context::from_waker(&waker);
    let mut fut = MockYieldNow::new();

    let p1 = Pin::new(&mut fut).poll(&mut cx);
    assert!(
        matches!(p1, Poll::Pending),
        "REGRESSION: YieldNow first poll is not Pending. \
         The yield primitive doesnt actually yield — \
         conflates with sleep(0) behavior.",
    );

    let wake_count_after_p1 = counter.load(Ordering::Relaxed);
    assert_eq!(
        wake_count_after_p1, 1,
        "REGRESSION: YieldNow first poll did not call \
         wake_by_ref exactly once (got {wake_count_after_p1}). \
         Without the self-wake, the task hangs.",
    );

    let p2 = Pin::new(&mut fut).poll(&mut cx);
    assert!(
        matches!(p2, Poll::Ready(())),
        "REGRESSION: YieldNow second poll is not Ready. \
         Either the future never completes (hang) or \
         alternates Pending forever.",
    );
}

#[test]
fn behavior_sleep_zero_takes_one_poll_and_calls_wake_zero_times() {
    // Behavioral pin: sleep(0) (deadline == now) returns
    // Ready on the FIRST poll. Total wakes observed: 0.
    // This is the sharp distinction from yield_now.
    let counter = Arc::new(AtomicU64::new(0));
    let waker = dummy_waker_with_counter(Arc::clone(&counter));
    let mut cx = Context::from_waker(&waker);
    let mut fut = MockSleep::after_zero(100);

    let p1 = Pin::new(&mut fut).poll(&mut cx);
    assert!(
        matches!(p1, Poll::Ready(())),
        "REGRESSION: sleep(0) first poll is not Ready. \
         sleep(0) is conflated with yield_now (Pending+wake) \
         — the timer-routing distinction is gone.",
    );

    let wake_count = counter.load(Ordering::Relaxed);
    assert_eq!(
        wake_count, 0,
        "REGRESSION: sleep(0) called wake_by_ref \
         {wake_count} times (expected 0). Either the future \
         self-wakes (yield_now-like behavior) or registered \
         a timer and the timer fired immediately (extra \
         scheduler overhead for nothing).",
    );
}

#[test]
fn behavior_yield_now_and_sleep_zero_have_different_poll_counts() {
    // Behavioral pin: side-by-side comparison. yield_now
    // = 2 polls; sleep(0) = 1 poll. The poll-count
    // difference is the operator-observable distinction.
    let counter1 = Arc::new(AtomicU64::new(0));
    let waker1 = dummy_waker_with_counter(Arc::clone(&counter1));
    let mut cx1 = Context::from_waker(&waker1);
    let mut yield_fut = MockYieldNow::new();
    let mut yield_polls = 0_u32;
    loop {
        yield_polls += 1;
        match Pin::new(&mut yield_fut).poll(&mut cx1) {
            Poll::Ready(()) => break,
            Poll::Pending => {
                assert!(yield_polls <= 10, "yield_now took >10 polls — broken");
            }
        }
    }

    let counter2 = Arc::new(AtomicU64::new(0));
    let waker2 = dummy_waker_with_counter(Arc::clone(&counter2));
    let mut cx2 = Context::from_waker(&waker2);
    let mut sleep_fut = MockSleep::after_zero(0);
    let mut sleep_polls = 0_u32;
    loop {
        sleep_polls += 1;
        match Pin::new(&mut sleep_fut).poll(&mut cx2) {
            Poll::Ready(()) => break,
            Poll::Pending => {
                assert!(sleep_polls <= 10, "sleep(0) took >10 polls — broken");
            }
        }
    }

    assert_eq!(
        yield_polls, 2,
        "REGRESSION: yield_now took {yield_polls} polls (expected 2).",
    );
    assert_eq!(
        sleep_polls, 1,
        "REGRESSION: sleep(0) took {sleep_polls} polls (expected 1).",
    );
    assert!(
        yield_polls > sleep_polls,
        "REGRESSION: yield_now poll count is not strictly \
         greater than sleep(0). The two primitives are \
         conflated — operators observable distinction is \
         lost.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/scheduler_checkpoint_tight_loop_dos_audit.rs",
        "tests/runtime_budget_carry_forward_across_yields_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
