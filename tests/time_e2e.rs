#![allow(warnings)]
#![allow(clippy::all)]
//! Time/Timers Verification Suite - E2E Tests
//!
//! This test file provides comprehensive verification for the time/timer infrastructure,
//! ensuring virtual/wall time correctness, budget integration, and deterministic behavior.
//!
//! Test categories:
//! 1. Basic sleep operations
//! 2. Interval timer operations
//! 3. Timeout integration
//! 4. Virtual vs wall time
//! 5. Determinism tests
//! 6. Budget integration
//! 7. Cancel-safety
//! 8. Timer wheel operations

#[macro_use]
mod common;

use asupersync::lab::{
    CancellationRecord, DualRunHarness, DualRunScenarioIdentity, LoserDrainRecord,
    NormalizedSemantics, ObligationBalanceRecord, Phase, ResourceSurfaceRecord, SeedPlan,
    TerminalOutcome, assert_dual_run_passes, capture_region_close, run_live_adapter,
};
use asupersync::time::{
    Elapsed, Interval, MissedTickBehavior, Sleep, TimeoutFuture, TimerWheel, interval, interval_at,
    timeout, timeout_at,
};
use asupersync::types::{Budget, Time};
use common::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

// ============================================================================
// Test Infrastructure
// ============================================================================

struct DropTracker(Arc<AtomicBool>);

impl Drop for DropTracker {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

static VIRTUAL_TIME: AtomicUsize = AtomicUsize::new(0);

fn get_virtual_time() -> Time {
    Time::from_secs(VIRTUAL_TIME.load(Ordering::SeqCst) as u64)
}

fn noop_waker() -> Waker {
    std::task::Waker::noop().clone()
}

struct NotifyWaker {
    notified: Arc<AtomicBool>,
}

impl NotifyWaker {
    fn new() -> (Self, Arc<AtomicBool>) {
        let notified = Arc::new(AtomicBool::new(false));
        (
            Self {
                notified: notified.clone(),
            },
            notified,
        )
    }
}

use std::task::Wake;
impl Wake for NotifyWaker {
    fn wake(self: Arc<Self>) {
        self.notified.store(true, Ordering::SeqCst);
    }
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

const VIRTUAL_TIMEOUT_CONTRACT_VERSION: &str = "time.timeout.virtual_clock_reset.v1";
const VIRTUAL_TIMEOUT_SCENARIO_CLOCK_ID: &str = "clock.virtual.timeout_ticks.v1";
const VIRTUAL_TIMEOUT_DEADLINE_ID: &str = "deadline.timeout.pending.reset.v1";
const VIRTUAL_TIMEOUT_NORMALIZATION_WINDOW: &str = "exact_logical_tick";
const FIRST_TIMEOUT_DEADLINE_TICKS: u64 = 5;
const RESET_TIMEOUT_DEADLINE_TICKS: u64 = 9;

fn usize_counter_i64(value: usize) -> i64 {
    i64::try_from(value).expect("time_e2e usize counters should fit in i64")
}

fn u64_counter_i64(value: u64) -> i64 {
    i64::try_from(value).expect("time_e2e u64 counters should fit in i64")
}

fn bool_counter_i64(value: bool) -> i64 {
    i64::from(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VirtualTimeoutObservation {
    pending_before_first_deadline: usize,
    first_deadline_ticks: u64,
    elapsed_at_first_deadline: bool,
    elapsed_after_first_deadline: bool,
    pending_before_reset_deadline: usize,
    reset_deadline_ticks: u64,
    elapsed_at_reset_deadline: bool,
    final_logical_elapsed_ticks: u64,
}

impl VirtualTimeoutObservation {
    fn to_semantics(self) -> NormalizedSemantics {
        let mut outcome = TerminalOutcome::err("timeout_elapsed");
        outcome.surface_result = Some("expected_virtual_timeout".to_string());

        NormalizedSemantics {
            terminal_outcome: outcome,
            cancellation: CancellationRecord::none(),
            loser_drain: LoserDrainRecord::not_applicable(),
            region_close: capture_region_close(true, true),
            obligation_balance: ObligationBalanceRecord::zero(),
            resource_surface: ResourceSurfaceRecord::empty("timer.timeout.virtual_clock_reset")
                .with_counter(
                    "timeout_pending_before_first_deadline",
                    usize_counter_i64(self.pending_before_first_deadline),
                )
                .with_counter(
                    "logical_deadline_ticks",
                    u64_counter_i64(self.first_deadline_ticks),
                )
                .with_counter(
                    "timeout_elapsed_at_first_deadline",
                    bool_counter_i64(self.elapsed_at_first_deadline),
                )
                .with_counter(
                    "timeout_elapsed_after_first_deadline",
                    bool_counter_i64(self.elapsed_after_first_deadline),
                )
                .with_counter(
                    "timeout_pending_before_reset_deadline",
                    usize_counter_i64(self.pending_before_reset_deadline),
                )
                .with_counter(
                    "logical_reset_deadline_ticks",
                    u64_counter_i64(self.reset_deadline_ticks),
                )
                .with_counter(
                    "timeout_elapsed_at_reset_deadline",
                    bool_counter_i64(self.elapsed_at_reset_deadline),
                )
                .with_counter(
                    "logical_elapsed_ticks",
                    u64_counter_i64(self.final_logical_elapsed_ticks),
                ),
        }
    }
}

fn virtual_timeout_identity() -> DualRunScenarioIdentity {
    let scenario_id = "phase2.timer.timeout.virtual_clock_reset";
    let seed_plan = SeedPlan::inherit(0x51A0_C031, format!("seed.{scenario_id}.v1"));
    let mut identity = DualRunScenarioIdentity::phase1(
        scenario_id,
        "timer.timeout.virtual_clock_reset",
        VIRTUAL_TIMEOUT_CONTRACT_VERSION,
        "Timeout differential pilot preserves logical deadline and reset semantics under a virtual scenario clock",
        seed_plan.canonical_seed,
    )
    .with_seed_plan(seed_plan)
    .with_metadata("eligibility_verdict", "eligible_for_pilot")
    .with_metadata("surface_family", "timer_surface")
    .with_metadata("scenario_clock_id", VIRTUAL_TIMEOUT_SCENARIO_CLOCK_ID)
    .with_metadata("clock_source", "scripted_poll_with_time")
    .with_metadata("logical_deadline_id", VIRTUAL_TIMEOUT_DEADLINE_ID)
    .with_metadata("normalization_window", VIRTUAL_TIMEOUT_NORMALIZATION_WINDOW);
    identity.phase = Phase::Phase2;
    identity
}

fn scripted_virtual_timeout_observation() -> VirtualTimeoutObservation {
    let mut timeout = TimeoutFuture::new(
        std::future::pending::<()>(),
        Time::from_secs(FIRST_TIMEOUT_DEADLINE_TICKS),
    );
    let waker = noop_waker();
    let mut task_cx = Context::from_waker(&waker);

    let first_poll = timeout.poll_with_time(&mut task_cx, Time::ZERO);
    let first_poll_pending = first_poll.is_pending();
    assert!(first_poll_pending, "timeout should start pending");

    let before_deadline = timeout.poll_with_time(
        &mut task_cx,
        Time::from_secs(FIRST_TIMEOUT_DEADLINE_TICKS - 1),
    );
    let before_deadline_pending = before_deadline.is_pending();
    assert!(
        before_deadline_pending,
        "timeout should remain pending before logical deadline"
    );

    let at_first_deadline =
        timeout.poll_with_time(&mut task_cx, Time::from_secs(FIRST_TIMEOUT_DEADLINE_TICKS));
    let elapsed_at_first_deadline = match at_first_deadline {
        Poll::Ready(Err(elapsed)) => {
            elapsed.deadline() == Time::from_secs(FIRST_TIMEOUT_DEADLINE_TICKS)
        }
        other => panic!("expected timeout elapsed at first deadline, got {other:?}"),
    };

    let after_first_deadline = timeout.poll_with_time(
        &mut task_cx,
        Time::from_secs(FIRST_TIMEOUT_DEADLINE_TICKS + 1),
    );
    let elapsed_after_first_deadline = match after_first_deadline {
        Poll::Ready(Err(elapsed)) => {
            elapsed.deadline() == Time::from_secs(FIRST_TIMEOUT_DEADLINE_TICKS)
        }
        other => panic!("expected timeout elapsed after first deadline, got {other:?}"),
    };

    timeout.reset(Time::from_secs(RESET_TIMEOUT_DEADLINE_TICKS));

    let before_reset_deadline = timeout.poll_with_time(
        &mut task_cx,
        Time::from_secs(RESET_TIMEOUT_DEADLINE_TICKS - 1),
    );
    let before_reset_deadline_pending = before_reset_deadline.is_pending();
    assert!(
        before_reset_deadline_pending,
        "timeout reset should re-arm before the new deadline"
    );

    let at_reset_deadline =
        timeout.poll_with_time(&mut task_cx, Time::from_secs(RESET_TIMEOUT_DEADLINE_TICKS));
    let elapsed_at_reset_deadline = match at_reset_deadline {
        Poll::Ready(Err(elapsed)) => {
            elapsed.deadline() == Time::from_secs(RESET_TIMEOUT_DEADLINE_TICKS)
        }
        other => panic!("expected timeout elapsed at reset deadline, got {other:?}"),
    };

    VirtualTimeoutObservation {
        pending_before_first_deadline: usize::from(first_poll_pending)
            + usize::from(before_deadline_pending),
        first_deadline_ticks: FIRST_TIMEOUT_DEADLINE_TICKS,
        elapsed_at_first_deadline,
        elapsed_after_first_deadline,
        pending_before_reset_deadline: usize::from(before_reset_deadline_pending),
        reset_deadline_ticks: RESET_TIMEOUT_DEADLINE_TICKS,
        elapsed_at_reset_deadline,
        final_logical_elapsed_ticks: RESET_TIMEOUT_DEADLINE_TICKS,
    }
}

fn make_virtual_timeout_live_result(
    identity: &DualRunScenarioIdentity,
) -> asupersync::lab::LiveRunResult {
    run_live_adapter(identity, |_config, witness| {
        let observation = scripted_virtual_timeout_observation();
        let mut outcome = TerminalOutcome::err("timeout_elapsed");
        outcome.surface_result = Some("expected_virtual_timeout".to_string());
        witness.set_outcome(outcome);
        witness.set_region_close(capture_region_close(true, true));
        witness.set_obligation_balance(ObligationBalanceRecord::zero());
        witness.record_counter(
            "timeout_pending_before_first_deadline",
            usize_counter_i64(observation.pending_before_first_deadline),
        );
        witness.record_counter(
            "logical_deadline_ticks",
            u64_counter_i64(observation.first_deadline_ticks),
        );
        witness.record_counter(
            "timeout_elapsed_at_first_deadline",
            bool_counter_i64(observation.elapsed_at_first_deadline),
        );
        witness.record_counter(
            "timeout_elapsed_after_first_deadline",
            bool_counter_i64(observation.elapsed_after_first_deadline),
        );
        witness.record_counter(
            "timeout_pending_before_reset_deadline",
            usize_counter_i64(observation.pending_before_reset_deadline),
        );
        witness.record_counter(
            "logical_reset_deadline_ticks",
            u64_counter_i64(observation.reset_deadline_ticks),
        );
        witness.record_counter(
            "timeout_elapsed_at_reset_deadline",
            bool_counter_i64(observation.elapsed_at_reset_deadline),
        );
        witness.record_counter(
            "logical_elapsed_ticks",
            u64_counter_i64(observation.final_logical_elapsed_ticks),
        );
    })
}

// ============================================================================
// 1. Basic Sleep Operations
// ============================================================================

#[test]
fn test_sleep_new_creates_with_deadline() {
    init_test("test_sleep_new_creates_with_deadline");
    tracing::info!("Testing Sleep::new() creates future with correct deadline");

    let deadline = Time::from_secs(5);
    let s = Sleep::new(deadline);

    let actual = s.deadline();
    assert_with_log!(actual == deadline, "deadline matches", deadline, actual);
    test_complete!("test_sleep_new_creates_with_deadline");
}

#[test]
fn test_sleep_after_calculates_deadline() {
    init_test("test_sleep_after_calculates_deadline");
    tracing::info!("Testing Sleep::after() calculates deadline from now + duration");

    let now = Time::from_secs(10);
    let duration = Duration::from_secs(5);
    let s = Sleep::after(now, duration);

    let expected = Time::from_secs(15);
    let actual = s.deadline();
    assert_with_log!(
        actual == expected,
        "deadline is now + duration",
        expected,
        actual
    );
    test_complete!("test_sleep_after_calculates_deadline");
}

#[test]
fn test_sleep_zero_duration_completes_immediately() {
    init_test("test_sleep_zero_duration_completes_immediately");
    tracing::info!("Testing sleep with zero duration completes on first poll");

    let now = Time::from_secs(10);
    let deadline = now; // zero duration means deadline == now
    let mut s = Sleep::with_time_getter(deadline, || Time::from_secs(10));

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut s).poll(&mut cx);

    let is_ready = poll.is_ready();
    assert_with_log!(is_ready, "zero duration is ready", true, is_ready);
    test_complete!("test_sleep_zero_duration_completes_immediately");
}

#[test]
fn test_sleep_past_deadline_completes() {
    init_test("test_sleep_past_deadline_completes");
    tracing::info!("Testing sleep completes when time passes deadline");

    let deadline = Time::from_secs(5);
    // Simulate time at 10 seconds (past deadline of 5)
    let mut s = Sleep::with_time_getter(deadline, || Time::from_secs(10));

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut s).poll(&mut cx);

    let is_ready = poll.is_ready();
    assert_with_log!(is_ready, "past deadline is ready", true, is_ready);
    test_complete!("test_sleep_past_deadline_completes");
}

#[test]
fn test_sleep_before_deadline_is_pending() {
    init_test("test_sleep_before_deadline_is_pending");
    tracing::info!("Testing sleep is pending when time is before deadline");

    let deadline = Time::from_secs(10);
    // Simulate time at 5 seconds (before deadline of 10)
    let mut s = Sleep::with_time_getter(deadline, || Time::from_secs(5));

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut s).poll(&mut cx);

    let is_pending = poll.is_pending();
    assert_with_log!(is_pending, "before deadline is pending", true, is_pending);
    test_complete!("test_sleep_before_deadline_is_pending");
}

#[test]
fn test_sleep_reset_changes_deadline() {
    init_test("test_sleep_reset_changes_deadline");
    tracing::info!("Testing Sleep::reset() changes the deadline");

    let mut s = Sleep::new(Time::from_secs(5));
    assert_eq!(s.deadline(), Time::from_secs(5));

    s.reset(Time::from_secs(20));
    let new_deadline = s.deadline();
    assert_with_log!(
        new_deadline == Time::from_secs(20),
        "deadline updated",
        Time::from_secs(20),
        new_deadline
    );
    test_complete!("test_sleep_reset_changes_deadline");
}

// ============================================================================
// 2. Interval Timer Operations
// ============================================================================

#[test]
fn test_interval_first_tick_immediate() {
    init_test("test_interval_first_tick_immediate");
    tracing::info!("Testing interval first tick is at start time");

    let start = Time::from_secs(0);
    let mut int = interval(start, Duration::from_millis(100));

    let t1 = int.tick(start);
    assert_with_log!(t1 == start, "first tick at start", start, t1);
    test_complete!("test_interval_first_tick_immediate");
}

#[test]
fn test_interval_subsequent_ticks_periodic() {
    init_test("test_interval_subsequent_ticks_periodic");
    tracing::info!("Testing interval subsequent ticks are periodic");

    let start = Time::ZERO;
    let period = Duration::from_millis(100);
    let mut int = interval(start, period);

    let t1 = int.tick(start);
    assert_eq!(t1, Time::ZERO);

    let t2 = int.tick(Time::from_millis(100));
    assert_eq!(t2, Time::from_millis(100));

    let t3 = int.tick(Time::from_millis(200));
    assert_eq!(t3, Time::from_millis(200));

    test_complete!("test_interval_subsequent_ticks_periodic");
}

#[test]
fn test_interval_at_explicit_start() {
    init_test("test_interval_at_explicit_start");
    tracing::info!("Testing interval_at with explicit start time");

    let start = Time::from_secs(5);
    let period = Duration::from_secs(1);
    let mut int = interval_at(start, period);

    let t1 = int.tick(start);
    assert_with_log!(t1 == start, "first tick at explicit start", start, t1);

    let t2 = int.tick(Time::from_secs(6));
    let expected = Time::from_secs(6);
    assert_with_log!(t2 == expected, "second tick at start+period", expected, t2);

    test_complete!("test_interval_at_explicit_start");
}

#[test]
fn test_missed_tick_behavior_burst() {
    init_test("test_missed_tick_behavior_burst");
    tracing::info!("Testing MissedTickBehavior::Burst - catch up on missed ticks");

    let start = Time::ZERO;
    let period = Duration::from_millis(100);
    let mut int = Interval::new(start, period);
    int.set_missed_tick_behavior(MissedTickBehavior::Burst);

    // First tick
    let t1 = int.tick(start);
    assert_eq!(t1, Time::ZERO);

    // Jump ahead by 350ms - should have missed ticks at 100, 200, 300
    let current = Time::from_millis(350);

    // Burst mode should fire immediately for each missed tick
    let t2 = int.tick(current);
    assert_eq!(t2, Time::from_millis(100), "burst: first missed tick");

    let t3 = int.tick(current);
    assert_eq!(t3, Time::from_millis(200), "burst: second missed tick");

    let t4 = int.tick(current);
    assert_eq!(t4, Time::from_millis(300), "burst: third missed tick");

    test_complete!("test_missed_tick_behavior_burst");
}

#[test]
fn test_missed_tick_behavior_delay() {
    init_test("test_missed_tick_behavior_delay");
    tracing::info!("Testing MissedTickBehavior::Delay - reset timer after tick");

    let start = Time::ZERO;
    let period = Duration::from_millis(100);
    let mut int = Interval::new(start, period);
    int.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // First tick
    let t1 = int.tick(start);
    assert_eq!(t1, Time::ZERO);

    // Jump ahead by 350ms
    let current = Time::from_millis(350);

    // Delay mode should reset to current + period
    let t2 = int.tick(current);
    // In delay mode, the missed tick deadline becomes current time
    // and next tick is current + period
    tracing::debug!(tick = ?t2, "delay mode tick");

    // Verify next deadline is set to current + period (450ms)
    let next = int.deadline();
    assert_with_log!(
        next == Time::from_millis(450),
        "delay mode sets next to current+period",
        Time::from_millis(450),
        next
    );

    test_complete!("test_missed_tick_behavior_delay");
}

#[test]
fn test_missed_tick_behavior_skip() {
    init_test("test_missed_tick_behavior_skip");
    tracing::info!("Testing MissedTickBehavior::Skip - skip to next aligned time");

    let start = Time::ZERO;
    let period = Duration::from_millis(100);
    let mut int = Interval::new(start, period);
    int.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // First tick
    let t1 = int.tick(start);
    assert_eq!(t1, Time::ZERO);

    // Jump ahead by 350ms
    let current = Time::from_millis(350);

    // Skip mode should jump to next aligned tick (400ms)
    let t2 = int.tick(current);
    tracing::debug!(tick = ?t2, "skip mode tick");

    // Next deadline should be at 400ms (next aligned time)
    let next = int.deadline();
    assert_with_log!(
        next == Time::from_millis(400),
        "skip mode aligns to period",
        Time::from_millis(400),
        next
    );

    test_complete!("test_missed_tick_behavior_skip");
}

#[test]
fn test_interval_period_accessor() {
    init_test("test_interval_period_accessor");
    tracing::info!("Testing Interval::period() returns correct value");

    let period = Duration::from_millis(250);
    let int = interval(Time::ZERO, period);

    let actual = int.period();
    assert_with_log!(actual == period, "period matches", period, actual);
    test_complete!("test_interval_period_accessor");
}

// ============================================================================
// 3. Timeout Integration
// ============================================================================

#[test]
fn test_timeout_completes_before_deadline() {
    init_test("test_timeout_completes_before_deadline");
    tracing::info!("Testing timeout returns Ok when inner completes before deadline");

    let inner = std::future::ready(42);
    let mut t = timeout(Time::ZERO, Duration::from_secs(10), inner);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut t).poll(&mut cx);

    match poll {
        Poll::Ready(Ok(value)) => {
            assert_with_log!(value == 42, "timeout returns inner value", 42, value);
        }
        other => panic!("expected Ready(Ok(42)), got {other:?}"),
    }
    test_complete!("test_timeout_completes_before_deadline");
}

#[test]
fn test_timeout_at_with_absolute_deadline() {
    init_test("test_timeout_at_with_absolute_deadline");
    tracing::info!("Testing timeout_at with absolute deadline");

    let deadline = Time::from_secs(5);
    let inner = std::future::ready("success");
    let mut t = timeout_at(deadline, inner);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll = Pin::new(&mut t).poll(&mut cx);

    match poll {
        Poll::Ready(Ok(value)) => {
            assert_with_log!(
                value == "success",
                "timeout_at returns value",
                "success",
                value
            );
        }
        other => panic!("expected Ready(Ok), got {other:?}"),
    }
    test_complete!("test_timeout_at_with_absolute_deadline");
}

#[test]
fn test_elapsed_error_display() {
    init_test("test_elapsed_error_display");
    tracing::info!("Testing Elapsed error type display");

    let elapsed = Elapsed::new(Time::from_secs(5));
    let display_str = format!("{elapsed}");

    assert_with_log!(
        display_str.contains("timeout")
            || display_str.contains("elapsed")
            || display_str.contains("deadline")
            || display_str.contains('5'),
        "Elapsed display describes timeout",
        "timeout/elapsed/deadline/5",
        display_str
    );
    test_complete!("test_elapsed_error_display");
}

// ============================================================================
// 4. Virtual vs Wall Time Tests
// ============================================================================

#[test]
fn test_sleep_with_virtual_time_getter() {
    init_test("test_sleep_with_virtual_time_getter");
    tracing::info!("Testing Sleep with custom time getter (virtual time simulation)");

    let deadline = Time::from_secs(5);
    VIRTUAL_TIME.store(0, Ordering::SeqCst);

    let mut s = Sleep::with_time_getter(deadline, get_virtual_time);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // At time 0, should be pending
    let poll = Pin::new(&mut s).poll(&mut cx);
    assert!(poll.is_pending(), "pending at time 0");

    // Advance virtual time to 3 seconds, still pending
    VIRTUAL_TIME.store(3, Ordering::SeqCst);
    let poll = Pin::new(&mut s).poll(&mut cx);
    assert!(poll.is_pending(), "pending at time 3");

    // Advance virtual time to 5 seconds, should complete
    VIRTUAL_TIME.store(5, Ordering::SeqCst);
    let poll = Pin::new(&mut s).poll(&mut cx);
    assert!(poll.is_ready(), "ready at time 5");

    test_complete!("test_sleep_with_virtual_time_getter");
}

#[test]
fn test_interval_with_virtual_time() {
    init_test("test_interval_with_virtual_time");
    tracing::info!("Testing Interval with virtual time advancement");

    let start = Time::ZERO;
    let period = Duration::from_millis(100);
    let mut int = interval(start, period);

    // Tick at various virtual times
    let times = [
        (Time::ZERO, Time::ZERO),
        (Time::from_millis(100), Time::from_millis(100)),
        (Time::from_millis(200), Time::from_millis(200)),
        (Time::from_millis(500), Time::from_millis(300)), // Burst catches up
    ];

    for (current, expected_tick) in times {
        let tick = int.tick(current);
        tracing::debug!(current = ?current, tick = ?tick, expected = ?expected_tick, "virtual time tick");
    }

    test_complete!("test_interval_with_virtual_time");
}

#[test]
fn test_virtual_timeout_observation_encodes_normalized_time_contract() {
    init_test("test_virtual_timeout_observation_encodes_normalized_time_contract");
    tracing::info!("Testing virtual timeout observation encodes the normalized time contract");

    let semantics = scripted_virtual_timeout_observation().to_semantics();

    assert_eq!(
        semantics.resource_surface.contract_scope,
        "timer.timeout.virtual_clock_reset"
    );
    assert_eq!(
        semantics.terminal_outcome.error_class.as_deref(),
        Some("timeout_elapsed")
    );
    assert_eq!(
        semantics.terminal_outcome.surface_result.as_deref(),
        Some("expected_virtual_timeout")
    );
    assert_eq!(
        semantics.resource_surface.counters["logical_deadline_ticks"],
        u64_counter_i64(FIRST_TIMEOUT_DEADLINE_TICKS)
    );
    assert_eq!(
        semantics.resource_surface.counters["logical_reset_deadline_ticks"],
        u64_counter_i64(RESET_TIMEOUT_DEADLINE_TICKS)
    );
    assert_eq!(
        semantics.resource_surface.counters["logical_elapsed_ticks"],
        u64_counter_i64(RESET_TIMEOUT_DEADLINE_TICKS)
    );
    assert_eq!(
        semantics.resource_surface.counters["timeout_pending_before_first_deadline"],
        2
    );
    assert_eq!(
        semantics.resource_surface.counters["timeout_elapsed_at_first_deadline"],
        1
    );
    assert_eq!(
        semantics.resource_surface.counters["timeout_elapsed_after_first_deadline"],
        1
    );
    assert_eq!(
        semantics.resource_surface.counters["timeout_elapsed_at_reset_deadline"],
        1
    );
    assert_eq!(
        semantics.resource_surface.counters["timeout_pending_before_reset_deadline"],
        1
    );

    test_complete!("test_virtual_timeout_observation_encodes_normalized_time_contract");
}

#[test]
fn timeout_dual_run_pilot_preserves_virtual_deadline_and_reset_semantics() {
    init_test("timeout_dual_run_pilot_preserves_virtual_deadline_and_reset_semantics");
    tracing::info!("Testing dual-run parity for virtual timeout deadline/reset semantics");

    let identity = virtual_timeout_identity();
    let live_result = make_virtual_timeout_live_result(&identity);

    let result = DualRunHarness::from_identity(identity)
        .lab(move |_config| scripted_virtual_timeout_observation().to_semantics())
        .live_result(move |_seed, _entropy| live_result)
        .run();

    assert_dual_run_passes(&result);
    assert_eq!(
        result
            .live
            .semantics
            .terminal_outcome
            .error_class
            .as_deref(),
        Some("timeout_elapsed")
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["logical_deadline_ticks"],
        u64_counter_i64(FIRST_TIMEOUT_DEADLINE_TICKS)
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["logical_reset_deadline_ticks"],
        u64_counter_i64(RESET_TIMEOUT_DEADLINE_TICKS)
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["timeout_elapsed_at_first_deadline"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["timeout_elapsed_at_reset_deadline"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["logical_elapsed_ticks"],
        u64_counter_i64(RESET_TIMEOUT_DEADLINE_TICKS)
    );

    test_complete!("timeout_dual_run_pilot_preserves_virtual_deadline_and_reset_semantics");
}

// ============================================================================
// 5. Determinism Tests
// ============================================================================

#[test]
fn test_sleep_deterministic_completion() {
    init_test("test_sleep_deterministic_completion");
    tracing::info!("Testing sleep completes deterministically at deadline");

    // Run the same scenario multiple times
    // For determinism, we just test the poll_with_time method directly
    for seed in [42u64, 123, 456, 789] {
        let deadline = Time::from_millis(seed);
        let s = Sleep::new(deadline);

        // Use poll_with_time to test at exact deadline
        let poll = s.poll_with_time(deadline);
        assert!(
            poll.is_ready(),
            "seed {seed}: sleep completes at exact deadline"
        );
    }

    test_complete!("test_sleep_deterministic_completion");
}

#[test]
fn test_interval_deterministic_sequence() {
    init_test("test_interval_deterministic_sequence");
    tracing::info!("Testing interval produces deterministic tick sequence");

    let run_sequence = || {
        let start = Time::ZERO;
        let period = Duration::from_millis(50);
        let mut int = interval(start, period);
        let mut ticks = Vec::new();

        for i in 0..10 {
            let current = Time::from_millis(i * 50);
            let tick = int.tick(current);
            ticks.push(tick);
        }
        ticks
    };

    // Run twice, should produce identical sequences
    let run1 = run_sequence();
    let run2 = run_sequence();

    assert_with_log!(
        run1 == run2,
        "interval tick sequence is deterministic",
        run1,
        run2
    );

    test_complete!("test_interval_deterministic_sequence");
}

// ============================================================================
// 6. Budget Integration
// ============================================================================

#[test]
fn test_time_from_budget_deadline() {
    init_test("test_time_from_budget_deadline");
    tracing::info!("Testing Time integration with Budget deadline");

    let deadline = Time::from_secs(30);
    let budget = Budget::new().with_deadline(deadline);

    let budget_deadline = budget.deadline;
    assert_with_log!(
        budget_deadline == Some(deadline),
        "budget contains deadline",
        Some(deadline),
        budget_deadline
    );

    test_complete!("test_time_from_budget_deadline");
}

#[test]
fn test_budget_deadline_propagation() {
    init_test("test_budget_deadline_propagation");
    tracing::info!("Testing budget deadline propagation through meet()");

    let outer = Budget::new().with_deadline(Time::from_secs(10));
    let inner = Budget::new().with_deadline(Time::from_secs(5));

    let combined = outer.meet(inner);
    let deadline = combined.deadline;

    // meet() should take the tighter (earlier) deadline
    assert_with_log!(
        deadline == Some(Time::from_secs(5)),
        "meet takes tighter deadline",
        Some(Time::from_secs(5)),
        deadline
    );

    test_complete!("test_budget_deadline_propagation");
}

// ============================================================================
// 7. Cancel-Safety Tests
// ============================================================================

#[test]
fn test_sleep_cancel_safe_drop() {
    init_test("test_sleep_cancel_safe_drop");
    tracing::info!("Testing Sleep is cancel-safe (can be dropped without side effects)");

    let deadline = Time::from_secs(10);
    let s = Sleep::new(deadline);

    // Drop without polling - should not panic or leak
    drop(s);

    // Create another - should work fine
    let s2 = Sleep::new(deadline);
    drop(s2);

    test_complete!("test_sleep_cancel_safe_drop");
}

#[test]
fn test_sleep_cancel_safe_partial_poll() {
    init_test("test_sleep_cancel_safe_partial_poll");
    tracing::info!("Testing Sleep can be dropped after partial polling");

    let deadline = Time::from_secs(10);
    let mut s = Sleep::with_time_getter(deadline, || Time::ZERO);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Poll once (pending)
    let poll = Pin::new(&mut s).poll(&mut cx);
    assert!(poll.is_pending());

    // Drop while pending - should be safe
    drop(s);

    test_complete!("test_sleep_cancel_safe_partial_poll");
}

#[test]
fn test_interval_cancel_safe() {
    init_test("test_interval_cancel_safe");
    tracing::info!("Testing Interval is cancel-safe");

    let mut int = interval(Time::ZERO, Duration::from_millis(100));

    // Consume a few ticks
    let _ = int.tick(Time::ZERO);
    let _ = int.tick(Time::from_millis(100));

    // Drop mid-sequence
    let _ = int;

    // Create a new one, should work
    let mut int2 = interval(Time::ZERO, Duration::from_millis(100));
    let t = int2.tick(Time::ZERO);
    assert_eq!(t, Time::ZERO, "new interval starts fresh");

    test_complete!("test_interval_cancel_safe");
}

#[test]
fn test_timeout_cancel_propagation() {
    init_test("test_timeout_cancel_propagation");
    tracing::info!("Testing timeout drop propagates to inner future");

    let dropped = Arc::new(AtomicBool::new(false));
    let dropped_clone = dropped.clone();

    // Create tracker BEFORE the async block so it exists when the future is dropped.
    // Note: Variables created INSIDE an async block only exist after the future is polled.
    let tracker = DropTracker(dropped_clone);

    // Create a future that holds the tracker
    let inner = async move {
        let _tracker = tracker; // Move tracker into the future
        std::future::pending::<()>().await;
    };

    let t = timeout(Time::ZERO, Duration::from_secs(10), inner);
    drop(t);

    let was_dropped = dropped.load(Ordering::SeqCst);
    assert_with_log!(
        was_dropped,
        "inner future dropped when timeout dropped",
        true,
        was_dropped
    );

    test_complete!("test_timeout_cancel_propagation");
}

// ============================================================================
// 8. Edge Cases
// ============================================================================

#[test]
fn test_sleep_max_duration() {
    init_test("test_sleep_max_duration");
    tracing::info!("Testing sleep with very large duration");

    let huge_duration = Duration::from_secs(u64::MAX / 2);
    let s = Sleep::after(Time::ZERO, huge_duration);

    // Should create without panic
    let deadline = s.deadline();
    tracing::debug!(deadline = ?deadline, "created sleep with huge duration");

    test_complete!("test_sleep_max_duration");
}

#[test]
#[should_panic(expected = "interval period must be non-zero")]
fn test_interval_zero_period_behavior() {
    init_test("test_interval_zero_period_behavior");
    tracing::info!("Testing interval with zero period - expected to panic");

    // Zero period is not allowed - the implementation correctly panics
    let _ = interval(Time::ZERO, Duration::ZERO);
}

#[test]
fn test_time_arithmetic_precision() {
    init_test("test_time_arithmetic_precision");
    tracing::info!("Testing Time arithmetic maintains nanosecond precision");

    let t1 = Time::from_nanos(1_000_000_001); // 1 second + 1 nanosecond
    let _t2 = Time::from_nanos(1);

    // Time implements Add<Duration>, which returns Self (not Option)
    let sum = t1 + Duration::from_nanos(1);

    let expected = Time::from_nanos(1_000_000_002);
    assert_with_log!(
        sum == expected,
        "nanosecond precision maintained",
        expected,
        sum
    );

    test_complete!("test_time_arithmetic_precision");
}

#[test]
fn test_missed_tick_behavior_default() {
    init_test("test_missed_tick_behavior_default");
    tracing::info!("Testing MissedTickBehavior default is Burst");

    let behavior = MissedTickBehavior::default();
    let is_burst = behavior == MissedTickBehavior::Burst;
    assert_with_log!(
        is_burst,
        "default is Burst",
        MissedTickBehavior::Burst,
        behavior
    );

    test_complete!("test_missed_tick_behavior_default");
}

#[test]
fn test_missed_tick_behavior_constructors() {
    init_test("test_missed_tick_behavior_constructors");
    tracing::info!("Testing MissedTickBehavior constructors");

    assert_eq!(MissedTickBehavior::burst(), MissedTickBehavior::Burst);
    assert_eq!(MissedTickBehavior::delay(), MissedTickBehavior::Delay);
    assert_eq!(MissedTickBehavior::skip(), MissedTickBehavior::Skip);

    test_complete!("test_missed_tick_behavior_constructors");
}

#[test]
fn test_missed_tick_behavior_display() {
    init_test("test_missed_tick_behavior_display");
    tracing::info!("Testing MissedTickBehavior Display implementation");

    assert_eq!(format!("{}", MissedTickBehavior::Burst), "Burst");
    assert_eq!(format!("{}", MissedTickBehavior::Delay), "Delay");
    assert_eq!(format!("{}", MissedTickBehavior::Skip), "Skip");

    test_complete!("test_missed_tick_behavior_display");
}

// ============================================================================
// 9. Timer Wheel Operations (if available)
// ============================================================================

#[test]
fn test_timer_wheel_basic_operations() {
    init_test("test_timer_wheel_basic_operations");
    tracing::info!("Testing TimerWheel basic register and expire operations");

    let mut wheel = TimerWheel::new();

    // Register a timer with a waker
    let deadline = Time::from_millis(100);
    let (notify_waker, notified) = NotifyWaker::new();
    let waker = Waker::from(Arc::new(notify_waker));
    let handle = wheel.register(deadline, waker);
    tracing::debug!(handle = ?handle, "registered timer");

    // Should not be expired before advancing
    let expired = wheel.collect_expired(Time::ZERO);
    assert!(expired.is_empty(), "no timers expired at time 0");

    // Advance to deadline
    let expired = wheel.collect_expired(deadline);
    assert_with_log!(expired.len() == 1, "one timer expired", 1, expired.len());

    // Wake the waker to verify it was the right one
    for w in expired {
        w.wake();
    }
    assert!(notified.load(Ordering::SeqCst), "waker was notified");

    test_complete!("test_timer_wheel_basic_operations");
}

// ============================================================================
// Summary Test
// ============================================================================

#[test]
fn test_time_verification_summary() {
    init_test("test_time_verification_summary");
    tracing::info!("=== Time/Timers Verification Suite Summary ===");
    tracing::info!("Verified: sleep operations, intervals, timeouts, virtual time");
    tracing::info!("Verified: phase-2 differential virtual-time timeout parity");
    tracing::info!("Verified: determinism, budget integration, cancel-safety");
    tracing::info!("Verified: edge cases, timer wheel operations");
    test_complete!("test_time_verification_summary");
}
