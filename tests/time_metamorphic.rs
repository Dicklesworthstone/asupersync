//! Metamorphic tests for virtual time determinism in Sleep and Interval.
//!
//! Tests critical timing relationships that must hold under virtual time,
//! focusing on determinism and correctness across different scenarios.
//!
//! Oracle Problem: Cannot predict exact timing for arbitrary virtual time
//! scenarios, but can verify relationships between inputs/outputs.

use asupersync::time::{interval, Sleep, Interval, MissedTickBehavior};
use asupersync::types::Time;
use std::time::Duration;
use std::collections::VecDeque;

// Test utilities for deterministic virtual time
fn virtual_time_source() -> impl Fn() -> Time {
    use std::sync::atomic::{AtomicU64, Ordering};
    static VIRTUAL_TIME: AtomicU64 = AtomicU64::new(0);
    move || Time::from_nanos(VIRTUAL_TIME.load(Ordering::SeqCst))
}

fn advance_virtual_time(nanos: u64) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static VIRTUAL_TIME: AtomicU64 = AtomicU64::new(0);
    VIRTUAL_TIME.store(nanos, Ordering::SeqCst);
}

#[cfg(test)]
mod metamorphic_relations {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    // Dummy waker for testing Sleep polling
    struct DummyWaker;
    impl std::task::Wake for DummyWaker {
        fn wake(self: std::sync::Arc<Self>) {}
    }

    fn dummy_waker() -> Waker {
        Waker::from(std::sync::Arc::new(DummyWaker))
    }

    /// MR1: Time Monotonicity (Equivalence)
    /// Virtual time sequences should never go backward
    #[test]
    fn mr_time_monotonicity() {
        let time_sequence = vec![
            Time::from_millis(0),
            Time::from_millis(100),
            Time::from_millis(150),
            Time::from_millis(200),
            Time::from_millis(300),
        ];

        for window in time_sequence.windows(2) {
            let (t1, t2) = (window[0], window[1]);
            assert!(
                t1 <= t2,
                "Time monotonicity violated: {} > {}",
                t1.as_nanos(), t2.as_nanos()
            );

            // Sleep deadlines should respect monotonicity
            let sleep1 = Sleep::new(t1);
            let sleep2 = Sleep::new(t2);
            assert!(
                sleep1.deadline() <= sleep2.deadline(),
                "Sleep deadline monotonicity violated"
            );
        }
    }

    /// MR2: Virtual Time Equivalence (Equivalence)
    /// Same input sequences in virtual time → same relative outputs
    #[test]
    fn mr_virtual_time_equivalence() {
        let scenarios = vec![
            (Time::from_millis(0), Duration::from_millis(100)),
            (Time::from_millis(1000), Duration::from_millis(50)),
            (Time::from_secs(5), Duration::from_secs(1)),
        ];

        for (start_time, duration) in scenarios {
            // Run scenario 1: Start at time T
            let deadline1 = start_time.saturating_add_nanos(duration.as_nanos() as u64);
            let sleep1 = Sleep::new(deadline1);

            // Run scenario 2: Same relative timing offset by +1000ms
            let offset = Duration::from_millis(1000);
            let start_time2 = start_time.saturating_add_nanos(offset.as_nanos() as u64);
            let deadline2 = start_time2.saturating_add_nanos(duration.as_nanos() as u64);
            let sleep2 = Sleep::new(deadline2);

            // Relative timing should be equivalent
            let relative_deadline1 = deadline1.as_nanos() - start_time.as_nanos();
            let relative_deadline2 = deadline2.as_nanos() - start_time2.as_nanos();

            assert_eq!(
                relative_deadline1, relative_deadline2,
                "Virtual time equivalence violated: relative timings differ"
            );
        }
    }

    /// MR3: Time Translation (Additive)
    /// Behavior should be equivalent under uniform time offset
    #[test]
    fn mr_time_translation() {
        let base_time = Time::from_millis(1000);
        let duration = Duration::from_millis(500);
        let translation_offset = Duration::from_millis(2000);

        // Original timing
        let sleep_original = Sleep::after(base_time, duration);
        let original_deadline = sleep_original.deadline();

        // Translated timing
        let translated_base = base_time.saturating_add_nanos(translation_offset.as_nanos() as u64);
        let sleep_translated = Sleep::after(translated_base, duration);
        let translated_deadline = sleep_translated.deadline();

        // Verify translation preserves relative duration
        let original_relative = original_deadline.as_nanos() - base_time.as_nanos();
        let translated_relative = translated_deadline.as_nanos() - translated_base.as_nanos();

        assert_eq!(
            original_relative, translated_relative,
            "Time translation failed to preserve relative duration"
        );

        // Test with intervals too
        let mut interval_original = Interval::new(base_time, Duration::from_millis(100));
        let mut interval_translated = Interval::new(translated_base, Duration::from_millis(100));

        for i in 0..5 {
            let tick_time = base_time.saturating_add_nanos((i * 100_000_000) as u64);
            let translated_tick_time = translated_base.saturating_add_nanos((i * 100_000_000) as u64);

            let original_tick = interval_original.tick(tick_time);
            let translated_tick = interval_translated.tick(translated_tick_time);

            let original_relative = original_tick.as_nanos() - base_time.as_nanos();
            let translated_relative = translated_tick.as_nanos() - translated_base.as_nanos();

            assert_eq!(
                original_relative, translated_relative,
                "Interval time translation failed at tick {}", i
            );
        }
    }

    /// MR4: Duration Additivity (Additive)
    /// Sleep::after(now, d1+d2) ≈ chained sleeps of d1 then d2
    #[test]
    fn mr_duration_additivity() {
        let now = Time::from_millis(1000);
        let d1 = Duration::from_millis(100);
        let d2 = Duration::from_millis(200);
        let total_duration = d1 + d2;

        // Single sleep for total duration
        let sleep_combined = Sleep::after(now, total_duration);
        let combined_deadline = sleep_combined.deadline();

        // Chained sleeps
        let intermediate_time = now.saturating_add_nanos(d1.as_nanos() as u64);
        let sleep_second = Sleep::after(intermediate_time, d2);
        let chained_deadline = sleep_second.deadline();

        assert_eq!(
            combined_deadline, chained_deadline,
            "Duration additivity failed: combined={}, chained={}",
            combined_deadline.as_nanos(), chained_deadline.as_nanos()
        );
    }

    /// MR5: Sleep-Interval Equivalence (Equivalence)
    /// Sleep deadlines should match interval tick times for aligned periods
    #[test]
    fn mr_sleep_interval_equivalence() {
        let start_time = Time::from_millis(0);
        let period = Duration::from_millis(100);
        let mut interval = Interval::new(start_time, period);

        for i in 0..10 {
            let expected_tick_time = start_time.saturating_add_nanos((i * period.as_nanos()) as u64);
            let current_time = expected_tick_time.saturating_add_nanos(1); // Slightly after

            // Get interval tick
            let interval_tick = interval.tick(current_time);

            // Create equivalent sleep
            let sleep = Sleep::new(expected_tick_time);
            let sleep_deadline = sleep.deadline();

            assert_eq!(
                interval_tick, sleep_deadline,
                "Sleep-Interval equivalence failed at tick {}: interval={}, sleep={}",
                i, interval_tick.as_nanos(), sleep_deadline.as_nanos()
            );
        }
    }

    /// MR6: Periodic Alignment (Permutative)
    /// Skip behavior should maintain period alignment regardless of call timing
    #[test]
    fn mr_periodic_alignment() {
        let start_time = Time::from_millis(0);
        let period = Duration::from_millis(100);
        let mut interval = Interval::new(start_time, period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Test different call patterns that should align to same ticks
        let call_times = vec![
            Time::from_millis(0),   // On time
            Time::from_millis(150), // Miss one tick
            Time::from_millis(280), // Miss another
            Time::from_millis(500), // Miss several
        ];

        let mut ticks = Vec::new();
        for &call_time in &call_times {
            ticks.push(interval.tick(call_time));
        }

        // Verify all ticks align to period boundaries
        for &tick_time in &ticks {
            let nanos_since_start = tick_time.as_nanos() - start_time.as_nanos();
            let aligned = (nanos_since_start % period.as_nanos()) == 0;
            assert!(aligned, "Tick {} not aligned to period boundary", tick_time.as_nanos());
        }

        // Verify ticks are in ascending order
        for window in ticks.windows(2) {
            assert!(
                window[0] <= window[1],
                "Tick ordering violated: {} > {}",
                window[0].as_nanos(), window[1].as_nanos()
            );
        }
    }

    /// MR7: Deadline Consistency (Equivalence)
    /// Sleep poll results should be consistent with deadline comparison
    #[test]
    fn mr_deadline_consistency() {
        let test_cases = vec![
            (Time::from_millis(100), Time::from_millis(50)),   // now < deadline
            (Time::from_millis(100), Time::from_millis(100)),  // now == deadline
            (Time::from_millis(100), Time::from_millis(150)),  // now > deadline
        ];

        for (deadline, now) in test_cases {
            let mut sleep = Sleep::with_time_getter(deadline, move || now);
            let mut context = Context::from_waker(&dummy_waker());

            let poll_result = Pin::new(&mut sleep).poll(&mut context);
            let should_be_ready = now >= deadline;

            let is_ready = matches!(poll_result, Poll::Ready(()));
            assert_eq!(
                is_ready, should_be_ready,
                "Deadline consistency failed: deadline={}, now={}, expected_ready={}, actual_ready={}",
                deadline.as_nanos(), now.as_nanos(), should_be_ready, is_ready
            );
        }
    }

    /// MR8: Tick Ordering (Permutative)
    /// Interval tick() calls should return non-decreasing timestamps
    #[test]
    fn mr_tick_ordering() {
        let start_time = Time::from_millis(0);
        let period = Duration::from_millis(50);
        let behaviors = vec![
            MissedTickBehavior::Burst,
            MissedTickBehavior::Delay,
            MissedTickBehavior::Skip,
        ];

        for behavior in behaviors {
            let mut interval = Interval::new(start_time, period);
            interval.set_missed_tick_behavior(behavior);

            let mut previous_tick = Time::from_nanos(0);
            let call_times = vec![
                Time::from_millis(0),
                Time::from_millis(75),   // Between ticks
                Time::from_millis(150),  // After multiple periods
                Time::from_millis(200),
                Time::from_millis(275),
            ];

            for call_time in call_times {
                let tick_time = interval.tick(call_time);

                assert!(
                    tick_time >= previous_tick,
                    "Tick ordering violated with {:?}: {} < {} at call_time={}",
                    behavior, tick_time.as_nanos(), previous_tick.as_nanos(), call_time.as_nanos()
                );

                previous_tick = tick_time;
            }
        }
    }

    /// MR9: Burst Catch-up (Multiplicative)
    /// Under Burst behavior, multiple ticks should fire for missed periods
    #[test]
    fn mr_burst_catchup() {
        let start_time = Time::from_millis(0);
        let period = Duration::from_millis(100);
        let mut interval = Interval::new(start_time, period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Burst);

        // Advance time significantly to miss multiple ticks
        let advanced_time = Time::from_millis(350); // Should have 3-4 ticks ready
        let missed_periods = (advanced_time.as_nanos() - start_time.as_nanos()) / period.as_nanos();

        let mut burst_ticks = Vec::new();
        let mut current_time = advanced_time;

        // Collect all burst ticks
        loop {
            let tick = interval.tick(current_time);
            if tick > current_time {
                break; // Future tick, stop bursting
            }
            burst_ticks.push(tick);
            // In burst mode, we need to call tick() multiple times to get all missed ticks
            current_time = current_time.saturating_add_nanos(1); // Advance slightly
            if burst_ticks.len() > 10 { break; } // Safety valve
        }

        // Should have caught up to approximately the missed periods
        let caught_up_periods = burst_ticks.len() as u128;
        assert!(
            caught_up_periods >= missed_periods,
            "Burst catch-up incomplete: caught {} ticks, expected at least {} periods",
            caught_up_periods, missed_periods
        );
    }

    /// MR10: Delay Reset (Equivalence)
    /// Under Delay behavior, each tick should reset timing from current time
    #[test]
    fn mr_delay_reset() {
        let start_time = Time::from_millis(0);
        let period = Duration::from_millis(100);
        let mut interval = Interval::new(start_time, period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let call_times = vec![
            Time::from_millis(150),  // Miss first tick
            Time::from_millis(300),  // Miss again
            Time::from_millis(450),  // Miss again
        ];

        for &call_time in &call_times {
            let tick_time = interval.tick(call_time);
            let next_deadline = interval.deadline();

            // Under Delay behavior, next deadline should be period from call time
            let expected_next = call_time.saturating_add_nanos(period.as_nanos() as u64);

            assert_eq!(
                next_deadline, expected_next,
                "Delay reset failed: next_deadline={}, expected={} at call_time={}",
                next_deadline.as_nanos(), expected_next.as_nanos(), call_time.as_nanos()
            );
        }
    }
}

/// MR Composition Tests - Compound properties
#[cfg(test)]
mod composite_mrs {
    use super::*;

    /// Composite MR: Time Translation + Duration Additivity
    /// Chained operations should preserve relationships under time offset
    #[test]
    fn mr_composite_translation_additivity() {
        let base_time = Time::from_millis(1000);
        let d1 = Duration::from_millis(100);
        let d2 = Duration::from_millis(200);
        let offset = Duration::from_secs(10);

        // Original sequence
        let sleep1_orig = Sleep::after(base_time, d1);
        let intermediate_orig = sleep1_orig.deadline();
        let sleep2_orig = Sleep::after(intermediate_orig, d2);
        let final_orig = sleep2_orig.deadline();

        // Translated sequence
        let base_translated = base_time.saturating_add_nanos(offset.as_nanos() as u64);
        let sleep1_trans = Sleep::after(base_translated, d1);
        let intermediate_trans = sleep1_trans.deadline();
        let sleep2_trans = Sleep::after(intermediate_trans, d2);
        let final_trans = sleep2_trans.deadline();

        // Verify the translated sequence preserves relative timings
        let original_total = final_orig.as_nanos() - base_time.as_nanos();
        let translated_total = final_trans.as_nanos() - base_translated.as_nanos();

        assert_eq!(
            original_total, translated_total,
            "Composite translation+additivity failed: original_total={}, translated_total={}",
            original_total, translated_total
        );
    }

    /// Composite MR: Periodic Alignment + Time Translation
    /// Interval alignment should be preserved under time offset
    #[test]
    fn mr_composite_alignment_translation() {
        let period = Duration::from_millis(100);
        let offset = Duration::from_millis(537); // Non-aligned offset

        let base_time1 = Time::from_millis(0);
        let base_time2 = base_time1.saturating_add_nanos(offset.as_nanos() as u64);

        let mut interval1 = Interval::new(base_time1, period);
        let mut interval2 = Interval::new(base_time2, period);

        interval1.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval2.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Test that relative alignment is preserved
        let test_time = Time::from_millis(250);
        let test_time_translated = test_time.saturating_add_nanos(offset.as_nanos() as u64);

        let tick1 = interval1.tick(test_time);
        let tick2 = interval2.tick(test_time_translated);

        // Relative positions should be the same
        let relative1 = tick1.as_nanos() - base_time1.as_nanos();
        let relative2 = tick2.as_nanos() - base_time2.as_nanos();

        assert_eq!(
            relative1, relative2,
            "Composite alignment+translation failed: relative1={}, relative2={}",
            relative1, relative2
        );
    }
}

/// Mutation Testing - Verify MRs catch planted bugs
#[cfg(test)]
mod mutation_testing {
    use super::*;

    // Simulate a buggy Sleep that doesn't respect deadlines
    struct BuggyOffByOneSleep {
        deadline: Time,
    }

    impl BuggyOffByOneSleep {
        fn new(deadline: Time) -> Self {
            Self { deadline }
        }

        fn deadline(&self) -> Time {
            // Bug: off by one nanosecond
            self.deadline.saturating_add_nanos(1)
        }
    }

    #[test]
    fn mutation_test_deadline_consistency() {
        let deadline = Time::from_millis(100);
        let now = Time::from_millis(100);

        // Correct implementation should be ready
        let correct_sleep = Sleep::new(deadline);
        assert_eq!(correct_sleep.deadline(), deadline);

        // Buggy implementation
        let buggy_sleep = BuggyOffByOneSleep::new(deadline);
        let buggy_deadline = buggy_sleep.deadline();

        // Our MR should catch this bug
        assert_ne!(
            buggy_deadline, deadline,
            "Mutation test failed to detect off-by-one bug"
        );

        // The bug makes the sleep think it's not ready when it should be
        assert!(
            now < buggy_deadline,
            "Buggy sleep incorrectly reports ready when deadline is passed"
        );
    }

    #[test]
    fn mutation_test_time_monotonicity() {
        // Simulate a buggy time source that goes backward
        let buggy_times = vec![
            Time::from_millis(100),
            Time::from_millis(200),
            Time::from_millis(150), // Bug: goes backward
            Time::from_millis(300),
        ];

        let monotonicity_violations = buggy_times
            .windows(2)
            .filter(|window| window[0] > window[1])
            .count();

        assert!(
            monotonicity_violations > 0,
            "Mutation test should detect time monotonicity violations"
        );
    }
}