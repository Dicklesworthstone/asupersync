//! Channel clock skew fault injection integration tests (bd-2ktrc.4).
//!
//! Validates the `SkewClock` wrapper under various clock skew scenarios.
//! Pass criteria:
//!
//! 1. **Static offset**: Constant offset correctly shifts all time readings.
//! 2. **Drift**: Progressive drift accumulates proportionally to elapsed time.
//! 3. **Jump**: One-time clock correction fires exactly once at trigger point.
//! 4. **Jitter**: Random symmetric perturbation stays within bounds.
//! 5. **Determinism**: Same seed produces identical skew sequence.
//! 6. **Saturation**: Negative offsets saturate at zero, not underflow.
//! 7. **Timer interaction**: Skewed clock correctly affects timer driver deadlines.
//! 8. **Evidence logging**: Skew events are logged to EvidenceSink.
//! 9. **Stats tracking**: All operations are counted accurately.

use asupersync::channel::clock_skew::{ClockSkewConfig, SkewClock};
use asupersync::evidence_sink::{CollectorSink, EvidenceSink};
use asupersync::time::{TimeSource, TimerDriver, VirtualClock};
use asupersync::types::Time;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Wake;

struct FlagWaker(AtomicBool);
impl Wake for FlagWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn make_base() -> Arc<VirtualClock> {
    Arc::new(VirtualClock::new())
}

fn make_sink() -> (Arc<CollectorSink>, Arc<dyn EvidenceSink>) {
    let c = Arc::new(CollectorSink::new());
    (c.clone(), c)
}

// ---------------------------------------------------------------------------
// Criterion 1: Static offset
// ---------------------------------------------------------------------------

#[test]
fn static_offset_shifts_all_readings() {
    let base = make_base();
    let (_, sink) = make_sink();
    let config = ClockSkewConfig::new(1).with_static_offset_ms(25);
    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    for sec in 1..=10u64 {
        base.set(Time::from_secs(sec));
        let t = skewed.now();
        let expected = sec * 1_000_000_000 + 25_000_000;
        assert_eq!(
            t,
            Time::from_nanos(expected),
            "Mismatch at {sec}s: got {t:?}"
        );
    }
}

#[test]
fn negative_offset_shifts_behind() {
    let base = make_base();
    let (_, sink) = make_sink();
    let config = ClockSkewConfig::new(1).with_static_offset_ms(-30);
    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    base.set(Time::from_secs(5));
    let t = skewed.now();
    assert_eq!(t, Time::from_nanos(4_970_000_000));
}

// ---------------------------------------------------------------------------
// Criterion 2: Drift
// ---------------------------------------------------------------------------

#[test]
fn drift_accumulates_proportionally() {
    let base = make_base();
    let (_, sink) = make_sink();
    // +2ms per second of base time
    let config = ClockSkewConfig::new(1).with_drift_rate(2_000_000);
    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    // At 0s: drift = 0
    assert_eq!(skewed.now(), Time::ZERO);

    // At 10s: drift = 20ms
    base.set(Time::from_secs(10));
    assert_eq!(skewed.now(), Time::from_nanos(10_020_000_000));

    // At 50s: drift = 100ms
    base.set(Time::from_secs(50));
    assert_eq!(skewed.now(), Time::from_nanos(50_100_000_000));
}

#[test]
fn negative_drift_slows_clock() {
    let base = make_base();
    let (_, sink) = make_sink();
    // -1ms per second
    let config = ClockSkewConfig::new(1).with_drift_rate(-1_000_000);
    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    base.set(Time::from_secs(100));
    // drift = -100ms
    assert_eq!(skewed.now(), Time::from_nanos(99_900_000_000));
}

// ---------------------------------------------------------------------------
// Criterion 3: Jump
// ---------------------------------------------------------------------------

#[test]
fn jump_fires_exactly_once() {
    let base = make_base();
    let (_, sink) = make_sink();
    // Jump +200ms at 5s
    let config = ClockSkewConfig::new(1).with_jump(5_000_000_000, 200_000_000);
    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    // Before trigger
    base.set(Time::from_secs(3));
    assert_eq!(skewed.now(), Time::from_secs(3));
    assert!(!skewed.stats().jump_fired);

    // At trigger
    base.set(Time::from_secs(6));
    assert_eq!(skewed.now(), Time::from_nanos(6_200_000_000));
    assert!(skewed.stats().jump_fired);

    // Read multiple more times — jump remains but doesn't double
    base.set(Time::from_secs(10));
    assert_eq!(skewed.now(), Time::from_nanos(10_200_000_000));
    base.set(Time::from_secs(20));
    assert_eq!(skewed.now(), Time::from_nanos(20_200_000_000));
}

#[test]
fn jump_backward_monotonicity_violation() {
    let base = make_base();
    let (_, sink) = make_sink();
    // Jump -500ms at 2s (simulates NTP correction)
    let config = ClockSkewConfig::new(1).with_jump(2_000_000_000, -500_000_000);
    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    // Before jump: at 1.8s
    base.set(Time::from_nanos(1_800_000_000));
    let before = skewed.now();
    assert_eq!(before, Time::from_nanos(1_800_000_000));

    // After jump: at 2.1s, skewed = 2.1s - 0.5s = 1.6s (monotonicity violation)
    base.set(Time::from_nanos(2_100_000_000));
    let after = skewed.now();
    assert_eq!(after, Time::from_nanos(1_600_000_000));

    // This is a valid monotonicity violation that the system under test should handle
    assert!(
        after < before,
        "Jump backward should cause monotonicity violation"
    );
}

// ---------------------------------------------------------------------------
// Criterion 4: Jitter
// ---------------------------------------------------------------------------

#[test]
fn jitter_stays_within_bounds() {
    let base = make_base();
    let (_, sink) = make_sink();
    let max_jitter = 10_000_000u64; // 10ms
    let config = ClockSkewConfig::new(42).with_jitter(1.0, max_jitter);
    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    // Set base far from zero to avoid saturation effects
    base.set(Time::from_secs(1000));

    for _ in 0..200 {
        let t = skewed.now();
        let diff = t.as_nanos().abs_diff(Time::from_secs(1000).as_nanos());
        assert!(
            diff < max_jitter,
            "Jitter {diff}ns exceeds max {max_jitter}ns"
        );
    }

    assert_eq!(skewed.stats().jitter_count, 200);
}

// ---------------------------------------------------------------------------
// Criterion 5: Determinism
// ---------------------------------------------------------------------------

#[test]
fn same_seed_same_skew_sequence() {
    let base1 = make_base();
    let base2 = make_base();
    let (_, sink1) = make_sink();
    let (_, sink2) = make_sink();
    let config = ClockSkewConfig::new(999)
        .with_static_offset_ms(5)
        .with_drift_rate(100_000)
        .with_jitter(0.5, 1_000_000);

    let s1 = SkewClock::new(base1.clone() as Arc<dyn TimeSource>, config.clone(), sink1);
    let s2 = SkewClock::new(base2.clone() as Arc<dyn TimeSource>, config, sink2);

    let mut times1 = Vec::new();
    let mut times2 = Vec::new();

    for sec in 1..=50u64 {
        base1.set(Time::from_secs(sec));
        base2.set(Time::from_secs(sec));
        times1.push(s1.now());
        times2.push(s2.now());
    }

    assert_eq!(times1, times2, "Determinism violated");
}

// ---------------------------------------------------------------------------
// Criterion 6: Saturation
// ---------------------------------------------------------------------------

#[test]
fn negative_offset_saturates_at_zero() {
    let base = make_base();
    let (_, sink) = make_sink();
    let config = ClockSkewConfig::new(1).with_static_offset_ms(-1000); // -1s
    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    // Base at 500ms — offset would make it -500ms, saturates to 0
    base.set(Time::from_millis(500));
    assert_eq!(skewed.now(), Time::ZERO);
}

#[test]
fn positive_offset_saturates_at_max() {
    let base = make_base();
    let (_, sink) = make_sink();
    // Set very large positive offset
    let config = ClockSkewConfig::new(1).with_static_offset_ns(i64::MAX);
    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    base.set(Time::MAX);
    let t = skewed.now();
    assert_eq!(t, Time::MAX);
}

// ---------------------------------------------------------------------------
// Criterion 7: Timer driver interaction
// ---------------------------------------------------------------------------

#[test]
fn skewed_clock_affects_timer_expiry() {
    let base = make_base();
    let (_, sink) = make_sink();
    // Clock is 100ms ahead
    let config = ClockSkewConfig::new(1).with_static_offset_ms(100);
    let skewed_clock: Arc<SkewClock> = Arc::new(SkewClock::new(
        base.clone() as Arc<dyn TimeSource>,
        config,
        sink,
    ));

    // Create a timer driver using the skewed clock
    let driver = TimerDriver::with_clock(skewed_clock);

    // Register timer at 1s
    let woken = Arc::new(FlagWaker(AtomicBool::new(false)));
    let waker = Arc::clone(&woken).into();
    let _handle = driver.register(Time::from_secs(1), waker);

    // Base at 0.85s → skewed reads 0.95s → timer should NOT fire
    base.set(Time::from_millis(850));
    let fired = driver.process_timers();
    assert_eq!(fired, 0, "Timer should not fire at skewed 950ms");
    assert!(!woken.0.load(Ordering::SeqCst));

    // Base at 0.95s → skewed reads 1.05s → timer SHOULD fire
    base.set(Time::from_millis(950));
    let fired = driver.process_timers();
    assert_eq!(fired, 1, "Timer should fire at skewed 1050ms");
    assert!(woken.0.load(Ordering::SeqCst));
}

#[test]
fn behind_clock_delays_timer_expiry() {
    let base = make_base();
    let (_, sink) = make_sink();
    // Clock is 200ms behind
    let config = ClockSkewConfig::new(1).with_static_offset_ms(-200);
    let skewed_clock: Arc<SkewClock> = Arc::new(SkewClock::new(
        base.clone() as Arc<dyn TimeSource>,
        config,
        sink,
    ));

    let driver = TimerDriver::with_clock(skewed_clock);

    let woken = Arc::new(FlagWaker(AtomicBool::new(false)));
    let waker = Arc::clone(&woken).into();
    let _handle = driver.register(Time::from_secs(1), waker);

    // Base at 1.0s → skewed reads 0.8s → timer should NOT fire
    base.set(Time::from_secs(1));
    let fired = driver.process_timers();
    assert_eq!(
        fired, 0,
        "Timer should not fire when skewed clock reads 800ms"
    );

    // Base at 1.2s → skewed reads 1.0s → timer SHOULD fire
    base.set(Time::from_millis(1200));
    let fired = driver.process_timers();
    assert_eq!(fired, 1, "Timer should fire when skewed clock reads 1000ms");
    assert!(woken.0.load(Ordering::SeqCst));
}

// ---------------------------------------------------------------------------
// Criterion 8: Evidence logging
// ---------------------------------------------------------------------------

#[test]
fn evidence_logged_for_clock_jump() {
    let base = make_base();
    let (collector, sink) = make_sink();
    let config = ClockSkewConfig::new(1).with_jump(1_000_000_000, 50_000_000);
    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    // Trigger the jump
    base.set(Time::from_secs(2));
    let _ = skewed.now();

    let entries = collector.entries();
    assert!(
        !entries.is_empty(),
        "Expected evidence entries for clock jump"
    );
    let jump_entry = entries
        .iter()
        .find(|e| e.action.contains("clock_jump"))
        .expect("Expected clock_jump evidence entry");
    assert_eq!(jump_entry.component, "clock_skew_injector");
}

// ---------------------------------------------------------------------------
// Criterion 9: Stats tracking
// ---------------------------------------------------------------------------

#[test]
fn stats_accurate_across_operations() {
    let base = make_base();
    let (_, sink) = make_sink();
    let config = ClockSkewConfig::new(42)
        .with_static_offset_ms(10)
        .with_jitter(1.0, 1_000_000) // always jitter
        .with_jump(5_000_000_000, 100_000_000);

    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    // 20 reads before jump
    for sec in 1..=4u64 {
        base.set(Time::from_secs(sec));
        for _ in 0..5 {
            let _ = skewed.now();
        }
    }

    let stats = skewed.stats();
    assert_eq!(stats.reads, 20);
    assert_eq!(stats.skewed_reads, 20); // All have offset
    assert_eq!(stats.jitter_count, 20); // All have jitter (probability=1.0)
    assert!(!stats.jump_fired);

    // Trigger jump
    base.set(Time::from_secs(10));
    let _ = skewed.now();

    let stats = skewed.stats();
    assert_eq!(stats.reads, 21);
    assert!(stats.jump_fired);
    assert!(stats.max_abs_skew_ns > 0);
}

// ---------------------------------------------------------------------------
// Combined scenarios
// ---------------------------------------------------------------------------

#[test]
fn all_skew_modes_combined() {
    let base = make_base();
    let (_, sink) = make_sink();
    let config = ClockSkewConfig::new(42)
        .with_static_offset_ms(5) // +5ms
        .with_drift_rate(1_000_000) // +1ms/s
        .with_jitter(0.5, 500_000) // 50% chance, ±0.5ms
        .with_jump(10_000_000_000, -20_000_000); // -20ms at 10s

    let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

    // At 5s: offset=5ms, drift=5ms, maybe jitter, no jump
    base.set(Time::from_secs(5));
    let t = skewed.now();
    // Base component: 5ms + 5ms = 10ms without jitter
    let expected_base = 5_010_000_000u64;
    let diff = t.as_nanos().abs_diff(expected_base);
    assert!(
        diff < 500_000, // within jitter bounds
        "Expected ~{expected_base}ns ±500us, got {t:?} (diff={diff}ns)"
    );

    // At 15s: offset=5ms, drift=15ms, jump=-20ms → net=0ms
    base.set(Time::from_secs(15));
    let t = skewed.now();
    let expected_base = 15_000_000_000u64; // 5+15-20 = 0ms net offset
    let diff = t.as_nanos().abs_diff(expected_base);
    assert!(
        diff < 500_000,
        "Expected ~{expected_base}ns ±500us, got {t:?} (diff={diff}ns)"
    );
}
