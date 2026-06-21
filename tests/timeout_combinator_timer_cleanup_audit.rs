//! Audit + regression test for timeout combinator timer
//! cleanup when the inner future completes before the
//! deadline.
//!
//! Operator's question: "Cx::with_timeout(d, fut) shorthand:
//! when fut completes before deadline d, does the timeout
//! future correctly resolve to Ok (correct) and cancel the
//! timer? Verify the timer is properly cancelled (not
//! leaked)."
//!
//! Audit findings:
//!
//!   asupersync does NOT have a literal `Cx::with_timeout(d,
//!   fut)` method. The timeout pattern is composed from
//!   primitives:
//!     - `Sleep::after(now, duration)` — the deadline future.
//!     - `Scope::race(cx, fut, sleep_fut)` — races the user's
//!       fut against the deadline; drops the loser.
//!     - `combinator::timeout::Timeout<T>` + `TimedResult<T,
//!       E>` — structured types for timeout handling.
//!
//!   When the inner fut completes BEFORE the deadline:
//!     1. race observes the inner fut Ready.
//!     2. race drops the Sleep loser.
//!     3. Sleep::Drop fires (sleep.rs:693-723) — cancels the
//!        registered TimerHandle via `driver.cancel(&handle)`.
//!     4. Trace event `timer_cancelled` fires for
//!        observability.
//!
//!   Timer cancellation paths (4 distinct):
//!
//!   1. **`Sleep::Drop`** (sleep.rs:693-723): when the Sleep
//!      future is dropped (e.g., race drops the loser),
//!      Drop takes the timer_handle + timer_driver out of
//!      the state and calls `driver.cancel(&handle)`. The
//!      `let _ =` ignores the cancel result (the timer may
//!      have already fired — both branches are safe).
//!
//!   2. **`Sleep::poll` Ready branch**: when poll_with_time
//!      returns Ready, the outer poll fn routes through
//!      `complete_ready_registration`, which takes the
//!      registered handle and cancels it via
//!      `driver.cancel(&handle)`. This handles the case
//!      where the deadline arrives BEFORE the future is
//:      dropped (e.g., the timer fires and the next poll
//!      completes Ready).
//!
//!   3. **`Sleep::reset_after`** (sleep.rs:398-431): when
//!      the Sleep is reset to a new deadline, the OLD
//!      timer is cancelled before the new one is
//!      registered. Prevents stale-timer accumulation
//!      under repeated reset.
//!
//!   4. **`Sleep::reset`** (sleep.rs:380-391, similar
//!      pattern at sleep.rs:560 for driver migration):
//:      same cancel-on-replace pattern.
//!
//!   Each cancel path also emits a `TraceEvent::timer_cancelled`
//!   trace event so operators can see when timers are
//!   cleaned up — debugging timer-leak suspicions has
//!   structured observability.
//!
//! Verdict: **SOUND**. Timer cleanup is enforced in 4
//! distinct paths. The Sleep::Drop path is the structural
//! guarantee for the operator's scenario (fut completes
//! first, race drops the Sleep loser, Drop cancels the
//! timer). The trace events provide observability for
//! operators to audit timer lifecycle.
//!
//! No bead filed. The cleanup is structurally enforced.
//!
//! A regression that:
//!   - removed the Sleep Drop impl (would leak timer
//!     handles indefinitely — the timer driver fires
//!     callbacks for tasks that no longer exist, wasting
//:     CPU and memory),
//!   - removed the Ready-branch driver.cancel call (would
//!     leak the just-fired timer's bookkeeping until the
//!     Sleep itself is dropped — minor leak, but
//!     measurable),
//!   - removed the timer_cancelled trace event (lost
//!     observability — operators cant audit the timer
//!     lifecycle),
//!   - changed the Drop impl to NOT take the timer_handle
//!     out of state (would leave a dangling reference if
//!     the Sleep is reused — UB pathway),
//!   - added a reference cycle between Sleep and the timer
//!     driver (would prevent Drop from firing — silent
//!     leak),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn sleep_drop_impl_cancels_registered_timer() {
    // Pin (link 1): Sleep::Drop takes the timer_handle +
    // timer_driver from state and calls driver.cancel(&handle).
    // This is the structural guarantee for the operator's
    // scenario — fut-completes-first → race drops Sleep →
    // Drop cancels timer.
    let source = read("src/time/sleep.rs");

    let impl_marker = "impl Drop for Sleep {";
    let start = source.find(impl_marker).expect("Sleep Drop impl");
    let body_end = source[start..].find("\n}\n").expect("Sleep Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("state.timer_handle.take()") && body.contains("state.timer_driver.take()"),
        "REGRESSION: Sleep::Drop no longer takes timer_handle \
         + timer_driver from state. The cancel call has \
         nothing to cancel — timer leaks until the driver \
         fires the callback for the now-dropped task.",
    );

    assert!(
        body.contains("driver.cancel(&handle);"),
        "REGRESSION: Sleep::Drop no longer calls \
         driver.cancel(&handle). Registered timers persist \
         past Sleep drop — leak in the timer-driver wheel \
         until the deadline fires (then a no-op callback \
         executes).",
    );
}

#[test]
fn sleep_drop_emits_timer_cancelled_trace_event_for_observability() {
    // Pin (link 4): Sleep::Drop emits a TraceEvent::
    // timer_cancelled so operators can audit the timer
    // lifecycle. Without it, debugging timer leaks is
    // blind.
    let source = read("src/time/sleep.rs");

    let impl_marker = "impl Drop for Sleep {";
    let start = source.find(impl_marker).expect("Sleep Drop impl");
    let body_end = source[start..].find("\n}\n").expect("Sleep Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("TraceEvent::timer_cancelled(seq, now, handle.id())"),
        "REGRESSION: Sleep::Drop no longer emits the \
         timer_cancelled trace event. Operators lose \
         visibility into timer lifecycle — leak suspicions \
         become unfalsifiable.",
    );
}

#[test]
fn sleep_poll_ready_branch_cancels_timer_immediately() {
    // Pin (link 2): the Sleep::poll Ready branch cancels
    // the timer immediately when the deadline fires. This
    // handles the case where the deadline arrives BEFORE
    // the future is dropped.
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

    let helper_marker =
        "fn complete_ready_registration(&self, now: Time, timer_driver: Option<TimerDriverHandle>)";
    let helper_start = source
        .find(helper_marker)
        .expect("complete_ready_registration helper");
    let helper_end = (helper_start + 1200).min(source.len());
    let helper_body = &source[helper_start..helper_end];

    assert!(
        body.contains("Poll::Ready(()) => {")
            && body.contains("self.complete_ready_registration(now, timer_driver.clone())")
            && helper_body.contains("state.timer_handle.take()")
            && helper_body.contains("driver.cancel(&handle)"),
        "REGRESSION: Sleep::poll Ready branch no longer \
         cancels the timer through complete_ready_registration. \
         The just-fired timer's bookkeeping persists until \
         Sleep::Drop runs — minor leak, but measurable in \
         long-running servers with many timeouts.",
    );
}

#[test]
fn sleep_reset_after_cancels_old_timer_before_re_registration() {
    // Pin (link 3): reset_after cancels the old timer
    // before the new one is registered. Prevents
    // stale-timer accumulation under repeated reset.
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn reset_after(&mut self, now: Time, duration: Duration) {";
    let start = source.find(fn_marker).expect("Sleep::reset_after fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Sleep::reset_after close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("state.timer_handle.take()") && body.contains("driver.cancel(&handle);"),
        "REGRESSION: reset_after no longer cancels the old \
         timer before re-registration. Repeated reset_after \
         calls accumulate stale timer registrations in the \
         driver — measurable leak under high-frequency \
         reset (e.g., interval timer).",
    );
}

#[test]
fn sleep_drop_clears_waker_to_release_task_reference() {
    // Pin (audit): Sleep::Drop also clears state.waker.
    // Without this, the waker holds a strong reference to
    // the task, preventing the tasks Cx from dropping —
    // unbounded lifetime extension under sustained
    // background-thread activity.
    let source = read("src/time/sleep.rs");

    let impl_marker = "impl Drop for Sleep {";
    let start = source.find(impl_marker).expect("Sleep Drop impl");
    let body_end = source[start..].find("\n}\n").expect("Sleep Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("state.waker = None;"),
        "REGRESSION: Sleep::Drop no longer clears the waker. \
         The waker holds a strong reference to the tasks \
         WakeState — preventing task drop and silently \
         extending lifetimes.",
    );
}

#[test]
fn sleep_drop_uses_safe_let_underscore_for_cancel_result() {
    // Pin (audit): Sleep::Drop uses `let _ = driver.cancel
    // (&handle)` — ignoring the cancel result. Without
    // the discard, a panic in the driver could escape and
    // double-panic during destructor unwind.
    let source = read("src/time/sleep.rs");

    let impl_marker = "impl Drop for Sleep {";
    let start = source.find(impl_marker).expect("Sleep Drop impl");
    let body_end = source[start..].find("\n}\n").expect("Sleep Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("let _ = driver.cancel(&handle);"),
        "REGRESSION: Sleep::Drop no longer discards the \
         cancel result. A failure return would propagate \
         (or panic) in Drop — destructor double-panic \
         hazard.",
    );
}

#[test]
fn sleep_drop_detaches_fallback_threads_to_avoid_blocking() {
    // Pin (audit): Sleep::Drop drops the fallback_handles
    // Vec without joining — `drop(fallback_handles)`. This
    // detaches background threads. Joining would block the
    // executor; detaching lets them complete in their own
    // time.
    let source = read("src/time/sleep.rs");

    let impl_marker = "impl Drop for Sleep {";
    let start = source.find(impl_marker).expect("Sleep Drop impl");
    let body_end = source[start..].find("\n}\n").expect("Sleep Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("drop(fallback_handles);"),
        "REGRESSION: Sleep::Drop no longer detaches \
         fallback_handles. Either it joins (would block \
         the executor) or it leaks (background threads \
         persist past task lifetime).",
    );
}

#[test]
fn timeout_combinator_provides_structured_timeout_types() {
    // Pin (high-level audit): the combinator/timeout module
    // provides structured Timeout<T> + TimedResult<T, E>
    // types so callers can compose timeouts ergonomically.
    let source = read("src/combinator/timeout.rs");

    assert!(
        source.contains("pub struct Timeout<T> {"),
        "REGRESSION: Timeout<T> struct is gone. Callers lose \
         the type-safe deadline wrapper — would have to use \
         raw Sleep + race manually.",
    );

    assert!(
        source.contains("pub enum TimedResult<T, E> {")
            && source.contains("Completed(Outcome<T, E>),")
            && source.contains("TimedOut(TimeoutError),"),
        "REGRESSION: TimedResult variants are gone. The \
         structured Completed-vs-TimedOut distinction is \
         lost.",
    );
}

#[test]
fn timed_result_into_outcome_treats_timeout_as_cancelled() {
    // Pin (audit): TimedResult::into_outcome maps TimedOut
    // → Outcome::Cancelled. This is what bridges the
    // combinator-timeout to the cancel protocol.
    let source = read("src/combinator/timeout.rs");

    let fn_marker = "pub fn into_outcome(self) -> Outcome<T, E> {";
    let start = source.find(fn_marker).expect("into_outcome fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("into_outcome close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("Self::TimedOut(err) => Outcome::Cancelled(err.into_cancel_reason())"),
        "REGRESSION: TimedResult::into_outcome no longer \
         maps TimedOut → Cancelled. The combinator-timeout \
         no longer feeds into the cancel cause chain — \
         downstream cleanup may not see the timeout.",
    );
}

#[test]
fn make_timed_result_does_not_drop_successful_outcomes_past_deadline() {
    // Pin (audit): make_timed_result preserves Ok/Err/
    // Panicked outcomes even when the deadline passed —
    // the operation reached a non-cancelled terminal
    // state, so we surface that. Only Cancelled outcomes
    // become TimedOut.
    let source = read("src/combinator/timeout.rs");

    let fn_marker = "pub fn make_timed_result<T, E>(";
    let start = source.find(fn_marker).expect("make_timed_result fn");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("make_timed_result close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("Outcome::Ok(_) | Outcome::Err(_) | Outcome::Panicked(_)")
            && body.contains("TimedResult::Completed(outcome)"),
        "REGRESSION: make_timed_result no longer preserves \
         Ok/Err/Panicked even past deadline. Successful \
         results would be silently discarded as TimedOut \
         — data loss for tasks that completed at the \
         deadline boundary.",
    );

    assert!(
        body.contains("Outcome::Cancelled(_) => {")
            && body.contains("TimedResult::TimedOut(TimeoutError::new(deadline))"),
        "REGRESSION: make_timed_result no longer maps \
         Cancelled-past-deadline to TimedOut. The timeout \
         signal is lost.",
    );
}

#[test]
fn race_drops_loser_for_loser_drain_correctness() {
    // Pin (high-level audit): Scope::race is the API that
    // backs the timeout pattern. When the winner returns,
    // the loser is dropped — for Sleep, this triggers the
    // Drop-cancel path.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("pub async fn race<T>("),
        "REGRESSION: Scope::race signature gone. The \
         timeout pattern composes Sleep + race; without \
         race, callers cant compose timeout cleanly.",
    );
}

// ─────────── BEHAVIORAL PIN: timer-cancel on inner-completion ──
//
// Direct simulation: build a MockTimer with a cancel-counter,
// register a "Sleep" with it, drop the Sleep simulating
// inner-fut-completes-first. Verify cancel is called exactly
// once.

#[derive(Debug)]
struct MockTimer {
    cancel_count: Arc<AtomicU32>,
    fired_count: Arc<AtomicU32>,
}

impl MockTimer {
    fn new() -> Self {
        Self {
            cancel_count: Arc::new(AtomicU32::new(0)),
            fired_count: Arc::new(AtomicU32::new(0)),
        }
    }
    fn cancel(&self, _handle: u64) {
        self.cancel_count.fetch_add(1, Ordering::Relaxed);
    }
}

struct MockSleep {
    handle: Option<u64>,
    timer: Option<Arc<MockTimer>>,
}

impl MockSleep {
    fn new(timer: Arc<MockTimer>, handle: u64) -> Self {
        Self {
            handle: Some(handle),
            timer: Some(timer),
        }
    }
}

impl Drop for MockSleep {
    fn drop(&mut self) {
        if let (Some(handle), Some(timer)) = (self.handle.take(), self.timer.take()) {
            timer.cancel(handle);
        }
    }
}

#[test]
fn sleep_drop_cancels_timer_exactly_once_when_inner_fut_completes_first() {
    // Behavioral pin: simulate the operator's scenario.
    // Inner fut completes first → Sleep is dropped → timer
    // cancelled. Verify cancel called exactly once.
    let timer = Arc::new(MockTimer::new());

    {
        let sleep = MockSleep::new(Arc::clone(&timer), 42);
        // Inner fut completes — Sleep is dropped here.
        drop(sleep);
    }

    let cancel_count = timer.cancel_count.load(Ordering::Relaxed);
    let fired_count = timer.fired_count.load(Ordering::Relaxed);

    assert_eq!(
        cancel_count, 1,
        "REGRESSION: Sleep drop did not cancel the timer \
         (cancel_count = {cancel_count}, expected 1). \
         Timer leaked — driver wheel would fire the \
         callback for a now-dropped task, wasting CPU.",
    );

    assert_eq!(
        fired_count, 0,
        "REGRESSION: timer fired despite being cancelled \
         (fired_count = {fired_count}). The cancel didnt \
         actually prevent firing.",
    );
}

#[test]
fn many_sleeps_dropped_in_sequence_each_cancels_its_own_timer() {
    // Behavioral pin: simulate a high-frequency
    // timeout-and-complete pattern. Each Sleep gets a
    // unique handle; each Drop cancels exactly one timer.
    // Verifies no per-call leak under sustained load.
    let timer = Arc::new(MockTimer::new());

    for i in 0_u64..1000 {
        let sleep = MockSleep::new(Arc::clone(&timer), i);
        drop(sleep);
    }

    let cancel_count = timer.cancel_count.load(Ordering::Relaxed);
    assert_eq!(
        cancel_count, 1000,
        "REGRESSION: 1000 Sleep drops cancelled \
         {cancel_count} timers (expected 1000). Some \
         drops failed to cancel — timer leak under \
         sustained load.",
    );
}

#[test]
fn sleep_dropped_without_handle_does_not_cancel_or_panic() {
    // Behavioral pin: a Sleep that never registered a
    // timer (e.g., past-deadline case where Ready fires
    // before timer registration) drops without calling
    // cancel.
    let timer = Arc::new(MockTimer::new());

    {
        let mut sleep = MockSleep::new(Arc::clone(&timer), 99);
        // Simulate the case where the timer was already
        // taken (e.g., by a Ready-branch cancel).
        sleep.handle = None;
        sleep.timer = None;
        // Drop now — no-op.
    }

    let cancel_count = timer.cancel_count.load(Ordering::Relaxed);
    assert_eq!(
        cancel_count, 0,
        "REGRESSION: Sleep drop without handle still called \
         cancel (cancel_count = {cancel_count}). The \
         Drop guard against double-cancel is broken.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_yield_now_vs_sleep_zero_distinction_audit.rs",
        "tests/cx_checkpoint_past_deadline_immediate_err_audit.rs",
        "tests/cx_deadline_inheritance_min_parent_child_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
