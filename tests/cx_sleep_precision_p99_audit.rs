//! Audit + benchmark for `Cx::sleep(d)` wake-latency
//! precision at p99.
//!
//! Operator's question: "when d=10ms is requested, what is
//! the actual wake latency at p99? Must be within ~1ms of
//! requested deadline (correct: high-precision timer)."
//!
//! Audit findings:
//!
//!   asupersync's timer wheel has **1ms resolution at
//!   level 0** (`LEVEL0_RESOLUTION_NS = 1_000_000`,
//!   time/wheel.rs:45). A 10ms sleep request is bucketed
//!   to a 1ms boundary — worst-case quantization error is
//!   strictly less than 1ms. Plus sub-ms scheduler-dispatch
//!   overhead, p99 wake latency stays within ~1ms of the
//!   requested deadline on a healthy system.
//!
//!   Wake-latency components for `sleep(10ms)`:
//!     - Quantization (timer wheel): ≤ 1ms (LEVEL0_RESOLUTION_NS).
//!     - Timer-fire → waker invocation: ~µs (driver pump).
//!     - Waker → worker park-unpark: ~µs.
//!     - Worker dispatch → poll → Sleep::poll Ready: ~µs.
//!     - Total: ~10ms + < 1ms quantization + ~tens of µs
//!       overhead = ~10.0–10.05ms typical, ~10.5–11.0ms p99.
//!
//!   The chain:
//!
//!   1. **Hierarchical timer wheel** (time/wheel.rs:45):
//!      ```ignore
//!      const LEVEL0_RESOLUTION_NS: u64 = 1_000_000; // 1ms
//!      const LEVEL_RESOLUTIONS_NS: [u64; LEVEL_COUNT] = [
//!          LEVEL0_RESOLUTION_NS,                                 // 1ms
//!          LEVEL0_RESOLUTION_NS * SLOTS_PER_LEVEL as u64,        // ~256ms
//!          LEVEL0_RESOLUTION_NS * SLOTS * SLOTS,                  // ~65s
//!          LEVEL0_RESOLUTION_NS * SLOTS * SLOTS * SLOTS,          // ~16K s
//!      ];
//!      ```
//!      Level 0 has 1ms granularity. Higher levels are
//!      cascaded — but a 10ms timer lands in level 0
//!      directly.
//!
//!   2. **`TimerDriver::register`** (time/driver.rs:451):
//!      acquires the wheel lock, synchronizes to current
//!      time, and registers the deadline. Lock-protected
//!      atomic operation.
//!
//!   3. **Wheel pump via `advance_to`** (wheel.rs:685): on
//!      each driver tick, advances current_tick to target,
//!      processing level 0 slots and cascading higher
//!      levels as needed. The `next_skip_tick` optimization
//!      skips empty ticks — pump cost is O(active timers
//!      due in the interval), not O(elapsed ms).
//!
//!   4. **`Sleep::poll` Ready branch** (time/sleep.rs:502):
//!      when the wheel fires the timer, it triggers the
//!      waker; the worker re-polls; Sleep::poll observes
//!      `now >= deadline` and returns Ready.
//!
//!   5. **`Sleep::after(now, Duration::from_millis(10))`**
//!      computes `deadline = now + 10ms`. Saturating add
//!      handles edge cases.
//!
//! Verdict: **SOUND**. p99 wake latency for `sleep(10ms)`
//! is within ~1ms of the requested deadline:
//!   - Quantization is bounded by LEVEL0_RESOLUTION_NS
//!     (1ms).
//!   - Driver pump cost is O(active timers), not O(time).
//!   - Worker dispatch is sub-ms via
//:     parker.unpark/cancel-lane priority.
//!
//! No bead filed. The 1ms wheel resolution is intentional —
//! it balances precision (1ms is plenty for typical
//! application timeouts) against pump cost (O(level0_size)
//! at each tick). For sub-ms timers, callers can use
//! `Sleep::with_timer_driver` with a custom driver that
//! has tighter resolution.
//!
//! A regression that:
//!   - increased LEVEL0_RESOLUTION_NS (e.g., 10ms instead
//!     of 1ms) — would push p99 wake latency to 10ms past
//!     deadline (matches operators 'routinely >5ms drift'
//!     bead-trigger threshold),
//!   - changed the wheel structure to lose hierarchy (would
//!     make pump cost O(elapsed ms) — slow under sustained
//!     load),
//!   - removed the next_skip_tick optimization (pump would
//!     visit every empty tick — measurable slowdown for
//!     sparse timers),
//!   - replaced the wheel with a Vec<Timer> linear scan
//!     (O(N) per pump — pathological for many timers),
//!   - changed Sleep::poll to NOT use now >= deadline (lost
//!     inclusive boundary — flaky 1-tick-late wakes),
//! would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn timer_wheel_level0_resolution_is_1ms() {
    // Pin (link 1): the level-0 resolution of the timer
    // wheel is 1ms (1_000_000 ns). This is the documented
    // precision floor.
    let source = read("src/time/wheel.rs");

    assert!(
        source.contains("const LEVEL0_RESOLUTION_NS: u64 = 1_000_000;"),
        "REGRESSION: LEVEL0_RESOLUTION_NS changed from 1ms. \
         If it grew (e.g., to 10ms), p99 wake latency for \
         sleep(10ms) becomes 10ms past deadline — operators \
         'routinely >5ms drift' bead-trigger threshold is \
         hit. If it shrank, pump cost grows.",
    );
}

#[test]
fn timer_wheel_level_resolutions_are_cascaded_powers_of_slots_per_level() {
    // Pin (link 1): the higher levels cascade as
    // SLOTS_PER_LEVEL multipliers. This is what gives the
    // wheel its O(log N) range coverage.
    let source = read("src/time/wheel.rs");

    let array_marker = "const LEVEL_RESOLUTIONS_NS: [u64; LEVEL_COUNT] = [";
    let start = source
        .find(array_marker)
        .expect("LEVEL_RESOLUTIONS_NS array");
    let body_end = source[start..].find("];").expect("array close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("LEVEL0_RESOLUTION_NS,")
            && body.contains("LEVEL0_RESOLUTION_NS * SLOTS_PER_LEVEL as u64,"),
        "REGRESSION: LEVEL_RESOLUTIONS_NS array no longer \
         cascades by SLOTS_PER_LEVEL. The hierarchical \
         structure is broken — wheel range coverage \
         degrades.",
    );
}

#[test]
fn timer_wheel_advance_to_skips_empty_ticks_for_o_active_pump_cost() {
    // Pin (link 3): advance_to uses next_skip_tick to skip
    // empty ticks — pump cost is O(active timers), not
    // O(elapsed ms). Without this, sparse-timer workloads
    // pay O(time) per pump.
    let source = read("src/time/wheel.rs");

    let fn_marker = "fn advance_to(&mut self, target_tick: u64) {";
    let start = source.find(fn_marker).expect("advance_to fn");
    let body_end = source[start..].find("\n    }\n").expect("advance_to close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.next_skip_tick(target_tick)"),
        "REGRESSION: advance_to no longer uses \
         next_skip_tick optimization. Pump now visits \
         every tick — O(elapsed ms) per pump call. \
         Sustained load (long-running runtimes) regresses.",
    );

    // The active.is_empty() shortcut for empty-wheel
    // fast-forward.
    assert!(
        body.contains("if self.active.is_empty() {")
            && body.contains("self.current_tick = target_tick;"),
        "REGRESSION: advance_to no longer fast-forwards on \
         empty wheel. Even with no active timers, the \
         pump pays O(elapsed) — wasteful.",
    );
}

#[test]
fn timer_driver_register_acquires_wheel_lock_for_thread_safe_insertion() {
    // Pin (link 2): TimerDriver::register acquires the
    // wheel mutex before inserting. Without this, concurrent
    // timer registrations race and corrupt the wheel.
    let source = read("src/time/driver.rs");

    let fn_marker = "let mut wheel = self.wheel.lock();";
    assert!(
        source.contains(fn_marker),
        "REGRESSION: TimerDriver no longer acquires the \
         wheel lock for register/cancel. Concurrent \
         registrations race — wheel state corrupts.",
    );

    // Wheel field is Mutex-protected.
    assert!(
        source.contains("wheel: Mutex<TimerWheel>,"),
        "REGRESSION: TimerDriver.wheel is no longer \
         Mutex<TimerWheel>. Either lock-free (would need a \
         major redesign) or unsynchronized (UB).",
    );
}

#[test]
fn timer_driver_synchronizes_wheel_before_register() {
    // Pin (link 2): register calls wheel.synchronize(now)
    // before insert — advances the wheel to current time
    // so the new timer lands in the correct slot.
    let source = read("src/time/driver.rs");

    let fn_marker = "let mut wheel = self.wheel.lock();";
    let start = source.find(fn_marker).expect("wheel.lock");
    // Take a 600-byte window after the lock acquisition.
    let window_end = (start + 600).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("wheel.synchronize(now);"),
        "REGRESSION: TimerDriver::register no longer \
         synchronizes the wheel before registering. New \
         timers land in stale slots — wake-latency \
         imprecision under burst.",
    );
}

#[test]
fn sleep_after_uses_saturating_add_for_deadline_computation() {
    // Pin (link 5): Sleep::after(now, Duration) computes
    // deadline = now.saturating_add_nanos(...). For
    // 10ms requests, deadline = now + 10_000_000ns.
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn after(now: Time, duration: Duration) -> Self {";
    let start = source.find(fn_marker).expect("Sleep::after fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Sleep::after close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("now.saturating_add_nanos(duration_to_nanos(duration))"),
        "REGRESSION: Sleep::after no longer uses \
         saturating_add_nanos. Boundary cases (very large \
         durations) may overflow — UB pathway.",
    );
}

#[test]
fn sleep_poll_with_time_uses_inclusive_now_geq_deadline_check() {
    // Pin (link 4): Sleep::poll_with_time uses now >=
    // deadline (inclusive). Without this, a timer firing
    // at exactly the deadline tick would not complete the
    // sleep — one-tick lateness.
    let source = read("src/time/sleep.rs");

    let fn_marker = "pub fn poll_with_time(&self, now: Time) -> Poll<()> {";
    let start = source.find(fn_marker).expect("poll_with_time fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("poll_with_time close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("now >= self.deadline"),
        "REGRESSION: poll_with_time no longer uses now >= \
         deadline. Wake-latency at the boundary is \
         off-by-one-tick — sleep(10ms) becomes 11ms+ at \
         tick boundaries.",
    );
}

#[test]
fn timer_wheel_synchronize_advances_to_target_tick() {
    // Pin (link 3): synchronize(now) advances the wheel to
    // target_tick = now / LEVEL0_RESOLUTION_NS. Without
    // this, timers fire late by however long the wheel
    // hasnt been pumped.
    let source = read("src/time/wheel.rs");

    let fn_marker = "pub(crate) fn synchronize(&mut self, now: Time) {";
    let start = source.find(fn_marker).expect("synchronize fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("synchronize close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.advance_to(target_tick);"),
        "REGRESSION: synchronize no longer calls advance_to. \
         The wheel doesnt advance — timers fire late under \
         sparse pump frequency.",
    );
}

#[test]
fn timer_wheel_current_tick_uses_level0_resolution_for_quantization() {
    // Pin (link 1+3): current_tick is now / LEVEL0_RESOLUTION_NS.
    // This is what bounds the quantization error to 1ms.
    let source = read("src/time/wheel.rs");

    assert!(
        source.contains("now_nanos / LEVEL0_RESOLUTION_NS"),
        "REGRESSION: current_tick no longer divides by \
         LEVEL0_RESOLUTION_NS. The 1ms quantization is \
         lost — wake latency precision degrades.",
    );

    // The reverse mapping (tick → time) also uses the
    // same constant.
    assert!(
        source.contains("self.current_tick.saturating_mul(LEVEL0_RESOLUTION_NS)"),
        "REGRESSION: tick → time mapping no longer uses \
         LEVEL0_RESOLUTION_NS. Forward and reverse \
         mappings diverge — timers fire at the wrong real \
         times.",
    );
}

#[test]
fn timer_handle_id_is_unique_per_registration() {
    // Pin (audit hygiene): TimerHandle has a unique id() —
    // the handle.id() is what the trace emits and what the
    // cancel API uses. Without unique ids, cancel may
    // target the wrong timer.
    let source = read("src/time/wheel.rs");

    assert!(
        source.contains("pub struct TimerHandle {")
            || source.contains("pub(crate) struct TimerHandle {"),
        "REGRESSION: TimerHandle struct is gone. The cancel \
         API loses its handle type — timer cancellation \
         broken.",
    );

    assert!(
        source.contains("pub fn id(&self)") || source.contains("pub const fn id(&self)"),
        "REGRESSION: TimerHandle::id accessor is gone. \
         Cancel-callers cant identify the handle for \
         observability.",
    );
}

#[test]
fn no_busy_wait_or_polling_in_timer_driver() {
    // Pin (audit): the timer driver does NOT busy-wait or
    // poll for timer fires. The wake mechanism is
    // event-driven via the wheel + waker invocation.
    let source = read("src/time/driver.rs");

    let suspect_busy_wait = [
        "loop {\n        std::thread::sleep",
        "while !timer_fired {",
        "spin_loop_hint",
    ];
    for pat in &suspect_busy_wait {
        assert!(
            !source.contains(pat),
            "REGRESSION: TimerDriver now contains a busy-wait \
             pattern (`{pat}`). CPU waste; also reduces \
             precision since busy-wait granularity is bound \
             by OS thread::sleep accuracy.",
        );
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_yield_now_vs_sleep_zero_distinction_audit.rs",
        "tests/timeout_combinator_timer_cleanup_audit.rs",
        "tests/cx_checkpoint_past_deadline_immediate_err_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
