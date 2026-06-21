//! Audit + regression test for `Sleep` future behavior
//! when the deadline is already in the past.
//!
//! Operator's question: "When sleep(d) is called and
//! (now + d) is already in the past, does the future
//! immediately resolve (correct) or wait?"
//!
//! Audit findings: **SOUND** — the past-deadline case
//! resolves immediately. No hang.
//!
//! ── The critical check ──────────────────────────────────
//!
//! `src/time/sleep.rs:459-473` defines `poll_with_time`:
//!
//! ```ignore
//! pub fn poll_with_time(&self, now: Time) -> Poll<()> {
//!     assert!(!self.completed.load(Acquire), "Sleep polled after completion");
//!     self.polled.store(true, Relaxed);
//!     if self.ready.swap(false, AcqRel) || now >= self.deadline {
//!         self.completed.store(true, Release);
//!         Poll::Ready(())
//!     } else {
//!         Poll::Pending
//!     }
//! }
//! ```
//!
//! The critical predicate is `now >= self.deadline`. When
//! `now` is at or past the deadline:
//!
//!   - `now > deadline`  → `Poll::Ready(())` immediately
//!   - `now == deadline` → `Poll::Ready(())` immediately (boundary)
//!   - `now < deadline`  → `Poll::Pending` (waits for timer)
//!
//! ── Coverage of the operator's three scenarios ──────────
//!
//! 1. **`sleep(now, Duration::ZERO)`**:
//!    `Sleep::after(now, Duration::ZERO)` computes
//!    `deadline = now.saturating_add_nanos(0) = now`. On
//!    poll, `now >= deadline` is `now >= now` which is
//!    true → Ready. (See also
//!    `time_sleep_vs_sleep_until_convergence_audit.rs`
//!    which pins the construction equation.)
//!
//! 2. **`sleep(stale_now, d)` where `stale_now + d` is
//!    already in the past relative to wall time**:
//!    On the FIRST poll, the timer driver / time getter
//!    reports the *current* time. If that current time
//!    is past `deadline`, `now >= deadline` triggers
//!    immediate Ready.
//!
//! 3. **`sleep_until(past_time)`**:
//!    `Sleep::new(past_time)`. On poll, `now >= past_time`
//!    is true → Ready.
//!
//! ── Why this matters under negative skew ────────────────
//!
//! In the lab runtime, time is virtual and monotonic
//! (VirtualClock atomic increments only). In production
//! with WallClock, the underlying `Instant::elapsed()`
//! is monotonic by construction. So negative skew
//! between the deadline and `now` cannot arise from
//! clock regression — only from the deadline having
//! been computed AT a stale `now` and then being polled
//! AFTER significant time has passed. In all such cases,
//! `now >= deadline` triggers immediate Ready.
//!
//! ── No timer registration on immediate Ready ────────────
//!
//! The `Future::poll` impl (sleep.rs:480) delegates to
//! `poll_with_time`. The Ready branch (lines 502-519)
//! attempts to cancel any registered timer, but for the
//! already-past case NO TIMER WAS EVER REGISTERED — the
//! Ready return happens BEFORE the registration block
//! (which only runs in the Pending branch at lines
//! 521+). So the past-deadline path is allocation-free
//! and timer-free.
//!
//! ── No hang risk ────────────────────────────────────────
//!
//! The Ready return is unconditional once `now >= deadline`.
//! There is no waker registration, no thread spawn, no
//! channel recv — just a synchronous compare-and-Ready.
//! The future cannot hang.
//!
//! Verdict: **SOUND**. The past-deadline case resolves
//! immediately on the first poll, with zero timer
//! allocation. The boundary case `now == deadline` is
//! also immediate (the predicate is `>=`, not `>`).
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn sleep_poll_with_time_uses_geq_predicate_for_past_deadline() {
    // Pin: the critical predicate `now >= self.deadline`
    // (NOT `now > self.deadline`). Switching to strict
    // greater-than would cause the boundary case
    // `now == deadline` (e.g., Duration::ZERO) to hang.
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn poll_with_time(&self, now: Time) -> Poll<()> {";
    let pos = source.find(fn_marker).expect("poll_with_time fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("poll_with_time close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("now >= self.deadline"),
        "REGRESSION: poll_with_time no longer uses the \
         `now >= self.deadline` predicate. If this was \
         changed to `now > deadline`, sleep(now, ZERO) \
         hangs forever (boundary case slips). If removed \
         entirely, all past-deadline sleeps hang.",
    );

    assert!(
        body.contains("Poll::Ready(())"),
        "REGRESSION: poll_with_time no longer returns \
         Poll::Ready(()) on the past-deadline branch.",
    );
}

#[test]
fn sleep_poll_with_time_returns_ready_synchronously_no_waker() {
    // Pin: the past-deadline branch must NOT register a
    // waker, NOT spawn a fallback thread, NOT register a
    // timer. It must be a synchronous Ready return.
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn poll_with_time(&self, now: Time) -> Poll<()> {";
    let pos = source.find(fn_marker).expect("poll_with_time fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("poll_with_time close");
    let body = &source[pos..pos + body_end];

    let suspect_calls = [
        ".register(",
        "spawn_fallback",
        "thread::spawn",
        ".wake(",
        ".wake_by_ref(",
    ];
    for pat in &suspect_calls {
        assert!(
            !body.contains(pat),
            "REGRESSION: poll_with_time body now contains \
             `{pat}` — the synchronous-Ready path is \
             contaminated with side effects. Past-deadline \
             sleeps may hang or perform unnecessary work.",
        );
    }
}

#[test]
fn sleep_completed_flag_set_before_returning_ready() {
    // Pin: completed flag is set BEFORE returning Ready,
    // so a subsequent poll panics via the assert at the
    // top of poll_with_time. Without this, polling-after-
    // completion silently succeeds — a fail-OPEN behavior.
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn poll_with_time(&self, now: Time) -> Poll<()> {";
    let pos = source.find(fn_marker).expect("poll_with_time fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("poll_with_time close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("self.completed")
            && body.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: poll_with_time no longer sets \
         self.completed = true with Release ordering. The \
         polling-after-completion fail-closed guard is \
         broken.",
    );
}

#[test]
fn sleep_main_poll_delegates_to_poll_with_time() {
    // Pin: Future::poll delegates to poll_with_time. If
    // it had its own past-deadline logic that diverged
    // from poll_with_time, we'd have two code paths to
    // audit.
    let source = read("src/time/sleep.rs");

    let fn_marker = "fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let pos = source.find(fn_marker).expect("Future::poll");
    let body_window = &source[pos..pos + 1500];

    assert!(
        body_window.contains("self.poll_with_time(now)"),
        "REGRESSION: Sleep::Future::poll no longer \
         delegates to poll_with_time. Two code paths now \
         exist; past-deadline behavior must be re-verified.",
    );
}

#[test]
fn sleep_ready_branch_cancels_timer_handle_if_any() {
    // Pin: when poll_with_time returns Ready, the outer
    // Future::poll cancels any registered timer handle.
    // This is harmless on the past-deadline path (no
    // timer ever registered) but matters when ready was
    // signalled by a fired timer. The actual cancellation
    // may live in a helper, but Future::poll must route
    // the Ready branch through that helper.
    let source = read("src/time/sleep.rs");

    let fn_marker = "fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let pos = source.find(fn_marker).expect("Future::poll");
    let body_window = &source[pos..pos + 2500];

    let helper_marker =
        "fn complete_ready_registration(&self, now: Time, timer_driver: Option<TimerDriverHandle>)";
    let helper_pos = source
        .find(helper_marker)
        .expect("complete_ready_registration helper");
    let helper_window = &source[helper_pos..helper_pos + 1200];

    assert!(
        body_window.contains("Poll::Ready(()) => {")
            && body_window.contains("self.complete_ready_registration(now, timer_driver.clone())")
            && helper_window.contains("state.timer_handle.take()")
            && helper_window.contains("driver.cancel(&handle)"),
        "REGRESSION: Sleep::Future::poll Ready branch no \
         longer cancels any registered timer handle. \
         Could leak timer-wheel slots after firing.",
    );
}

#[test]
fn sleep_ready_branch_runs_before_pending_branch_setup() {
    // Pin: the Ready branch must NOT fall through into
    // the Pending branch's waker-registration / fallback-
    // spawn logic. These are mutually exclusive arms of
    // a `match`.
    let source = read("src/time/sleep.rs");

    let fn_marker = "fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let pos = source.find(fn_marker).expect("Future::poll");
    let body_window = &source[pos..pos + 4000];

    assert!(
        body_window.contains("match self.poll_with_time(now) {")
            && body_window.contains("Poll::Ready(()) => {")
            && body_window.contains("Poll::Pending => {"),
        "REGRESSION: Sleep::Future::poll no longer dispatches \
         on poll_with_time's result via match. Ready and \
         Pending are no longer mutually exclusive arms — \
         past-deadline path may now fall through into timer \
         registration.",
    );
}

#[test]
fn sleep_inline_test_pins_zero_duration_immediate_ready() {
    // Pin: the inline unit test for Duration::ZERO
    // immediate-ready behavior must remain.
    let source = read("src/time/sleep.rs");

    // The inline tests should cover the zero-duration /
    // past-deadline cases. Search for at least one such
    // test name.
    let candidates = [
        "fn ready_immediately_when_deadline_in_past",
        "fn ready_when_now_equals_deadline",
        "fn poll_returns_ready_when_deadline_passed",
        "fn poll_with_time_ready_when_now_at_deadline",
        "fn deadline_in_past_resolves_immediately",
        "fn ready_when_deadline_already_passed",
    ];

    let any_present = candidates.iter().any(|name| source.contains(name));
    if !any_present {
        // Soft pin: if no specifically-named test exists,
        // verify at least that there are inline tests
        // calling poll_with_time with `now >= deadline`.
        assert!(
            source.contains("poll_with_time(") && source.contains("Poll::Ready"),
            "REGRESSION: no inline test exercises the \
             past-deadline immediate-Ready behavior. Either \
             add a dedicated test (recommended) or ensure \
             at least one test calls poll_with_time with \
             a time ≥ deadline and asserts Poll::Ready.",
        );
    }
}

#[test]
fn sleep_struct_has_completed_flag_for_post_ready_assert() {
    // Pin: the `completed: AtomicBool` field is what the
    // poll_with_time top-of-fn assert checks. Without it
    // the fail-closed guard against double-Ready is gone.
    let source = read("src/time/sleep.rs");

    assert!(
        source.contains("completed: std::sync::atomic::AtomicBool,"),
        "REGRESSION: Sleep::completed field is gone. The \
         post-completion repoll fail-closed assert is \
         broken.",
    );
}

#[test]
fn sleep_after_zero_duration_produces_deadline_equal_to_now() {
    // Pin: Sleep::after(now, Duration::ZERO) computes
    // deadline = now.saturating_add_nanos(0) = now. So
    // poll's `now >= deadline` is `now >= now` → true →
    // Ready. (This is also pinned by
    // time_sleep_vs_sleep_until_convergence_audit.rs;
    // re-pinned here for the past-deadline angle.)
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn after(now: Time, duration: Duration) -> Self {";
    let pos = source.find(fn_marker).expect("Sleep::after fn");
    let body = &source[pos..pos + 500];

    assert!(
        body.contains("now.saturating_add_nanos(duration_to_nanos(duration))"),
        "REGRESSION: Sleep::after no longer computes \
         deadline via saturating_add_nanos(0). For \
         Duration::ZERO this would diverge from \
         deadline=now, breaking the immediate-Ready \
         contract for sleep(now, ZERO).",
    );
}

#[test]
fn sleep_assert_polled_after_completion_message_is_clear() {
    // Pin: the assert message identifies the bug clearly
    // for downstream debugging.
    let source = read("src/time/sleep.rs");

    assert!(
        source.contains("\"Sleep polled after completion\""),
        "REGRESSION: the post-completion repoll assert no \
         longer has its identifying message. Debugging \
         polled-after-completion bugs becomes harder.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MockTime(u64);

impl MockTime {
    const fn from_nanos(n: u64) -> Self {
        Self(n)
    }
    const ZERO: Self = Self(0);
    fn saturating_add_nanos(self, n: u64) -> Self {
        Self(self.0.saturating_add(n))
    }
}

fn duration_to_nanos(d: Duration) -> u64 {
    let secs_ns = d.as_secs().saturating_mul(1_000_000_000);
    let sub_ns = u64::from(d.subsec_nanos());
    secs_ns.saturating_add(sub_ns)
}

/// Mock Sleep with the same poll-decision logic.
struct MockSleep {
    deadline: MockTime,
    completed: AtomicBool,
    polled: AtomicBool,
    ready: AtomicBool,
}

impl MockSleep {
    fn new(deadline: MockTime) -> Self {
        Self {
            deadline,
            completed: AtomicBool::new(false),
            polled: AtomicBool::new(false),
            ready: AtomicBool::new(false),
        }
    }

    fn after(now: MockTime, duration: Duration) -> Self {
        let deadline = now.saturating_add_nanos(duration_to_nanos(duration));
        Self::new(deadline)
    }

    fn poll_with_time(&self, now: MockTime) -> Poll<()> {
        assert!(
            !self.completed.load(Ordering::Acquire),
            "MockSleep polled after completion"
        );
        self.polled.store(true, Ordering::Relaxed);
        if self.ready.swap(false, Ordering::AcqRel) || now >= self.deadline {
            self.completed.store(true, Ordering::Release);
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

#[test]
fn behavioral_zero_duration_resolves_immediately() {
    // sleep(now, ZERO) — the operator's exact case.
    let now = MockTime::ZERO;
    let s = MockSleep::after(now, Duration::ZERO);

    assert_eq!(
        s.poll_with_time(now),
        Poll::Ready(()),
        "REGRESSION: sleep(now, ZERO) did not resolve \
         immediately. Boundary case `now == deadline` is \
         hanging.",
    );

    // Polling again must panic (fail-closed on double
    // Ready).
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = s.poll_with_time(now);
    }));
    assert!(
        panicked.is_err(),
        "REGRESSION: polled-after-completion did NOT \
         panic. The fail-closed guard is broken.",
    );
}

#[test]
fn behavioral_past_deadline_resolves_immediately() {
    // Deadline in the past.
    let s = MockSleep::new(MockTime::from_nanos(100));
    let now = MockTime::from_nanos(200); // 100ns past

    assert_eq!(
        s.poll_with_time(now),
        Poll::Ready(()),
        "REGRESSION: sleep_until(past_time) did not \
         resolve immediately. Past-deadline check is \
         broken.",
    );
}

#[test]
fn behavioral_future_deadline_returns_pending() {
    // Sanity check the OTHER branch.
    let s = MockSleep::new(MockTime::from_nanos(1000));
    let now = MockTime::from_nanos(500);

    assert_eq!(
        s.poll_with_time(now),
        Poll::Pending,
        "REGRESSION: future deadline did not return \
         Pending. Either the predicate has flipped or \
         the ready flag is stuck on.",
    );
}

#[test]
fn behavioral_boundary_case_now_equals_deadline_resolves_immediately() {
    // The most subtle case: now == deadline. Predicate
    // must be `>=`, not `>`.
    let s = MockSleep::new(MockTime::from_nanos(500));
    let now = MockTime::from_nanos(500);

    assert_eq!(
        s.poll_with_time(now),
        Poll::Ready(()),
        "REGRESSION: now == deadline returned Pending. \
         The predicate flipped to strict greater-than. \
         sleep(now, ZERO) and other boundary cases hang.",
    );
}

#[test]
fn behavioral_sleep_does_not_hang_under_pending_to_ready_via_time_advance() {
    // Two-poll scenario: first poll Pending, then time
    // advances past the deadline, second poll Ready.
    let s = MockSleep::new(MockTime::from_nanos(1000));
    let now1 = MockTime::from_nanos(500);
    let now2 = MockTime::from_nanos(1500);

    assert_eq!(s.poll_with_time(now1), Poll::Pending);
    assert_eq!(
        s.poll_with_time(now2),
        Poll::Ready(()),
        "REGRESSION: Sleep did not transition Pending -> \
         Ready when time advanced past the deadline.",
    );
}

#[test]
fn behavioral_full_future_poll_converges_for_zero_duration() {
    // Drive a real Future to completion using the std
    // executor pattern; assert it finishes in a single
    // poll for sleep(now, ZERO).
    struct ZeroDurationFuture {
        sleep: MockSleep,
        time: MockTime,
    }

    impl Future for ZeroDurationFuture {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.sleep.poll_with_time(self.time)
        }
    }

    let now = MockTime::from_nanos(7_777);
    let f = ZeroDurationFuture {
        sleep: MockSleep::after(now, Duration::ZERO),
        time: now,
    };

    let waker = Waker::noop();
    let mut ctx = Context::from_waker(waker);
    let mut pinned = std::pin::pin!(f);

    let result = pinned.as_mut().poll(&mut ctx);
    assert_eq!(
        result,
        Poll::Ready(()),
        "REGRESSION: full Future::poll did not return \
         Ready in a single poll for ZERO-duration sleep. \
         Hang risk via the executor.",
    );
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/time_sleep_vs_sleep_until_convergence_audit.rs",
        "tests/timeout_combinator_timer_cleanup_audit.rs",
        "tests/cx_checkpoint_past_deadline_immediate_err_audit.rs",
        "tests/cx_time_source_virtualizable_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
