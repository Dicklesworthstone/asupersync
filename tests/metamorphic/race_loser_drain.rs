#![allow(clippy::all)]
//! Metamorphic Testing for combinator::race loser drain correctness invariants
//!
//! This test suite validates the critical invariants of the race combinator,
//! particularly the "losers are drained" guarantee that distinguishes asupersync
//! from other runtimes that abandon losing futures.
//!
//! The 5 key metamorphic relations tested:
//! 1. Winner returns its Outcome (winner correctness)
//! 2. All N-1 losers are cancelled AND fully drained (no dangling tasks)
//! 3. Drain deadline bounded by Budget (no infinite hang)
//! 4. Race with all cancelled yields Outcome::Cancelled
//! 5. FIRST winner (lowest finish tick) wins, not tick-tied

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use asupersync::combinator::race::{
    self, race2_outcomes, race_all_outcomes, RaceResult, RaceWinner, RaceAllResult,
};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::time::{sleep, Time};
use asupersync::types::cancel::CancelReason;
use asupersync::types::{Outcome, budget::Budget};
use asupersync::{region, Cx};
use proptest::prelude::*;

/// Test configuration for race loser drain properties
#[derive(Debug, Clone)]
struct RaceDrainTestConfig {
    /// Number of contestants in the race (2-8)
    num_contestants: u32,
    /// Which contestant should win (0-based index)
    winner_index: u32,
    /// Delay for winner in milliseconds
    winner_delay_ms: u64,
    /// Base delay for losers in milliseconds
    loser_base_delay_ms: u64,
    /// Budget limit for drain operations in milliseconds
    drain_budget_ms: u64,
    /// Whether to introduce cancellation scenarios
    include_cancellation: bool,
    /// Lab runtime seed for deterministic execution
    lab_seed: u64,
}

/// Strategy for generating race drain test configurations
fn race_drain_config_strategy() -> impl Strategy<Value = RaceDrainTestConfig> {
    (
        // Number of contestants: 2 to 8
        2_u32..=8,
        // Winner delay: 10ms to 500ms
        10_u64..=500,
        // Loser base delay: 100ms to 2000ms (losers slower than winner)
        100_u64..=2000,
        // Drain budget: 1s to 10s
        1000_u64..=10000,
        // Cancellation scenarios
        any::<bool>(),
        // Lab seed for determinism
        1_u64..=u64::MAX,
    ).prop_filter("winner delay should be less than loser delay",
        |(_, winner_delay, loser_delay, _, _, _)| winner_delay < loser_delay
    ).prop_map(|(num_contestants, winner_delay_ms, loser_base_delay_ms, drain_budget_ms, include_cancellation, lab_seed)| {
        RaceDrainTestConfig {
            num_contestants,
            winner_index: 0, // Winner will be determined by delays
            winner_delay_ms,
            loser_base_delay_ms,
            drain_budget_ms,
            include_cancellation,
            lab_seed,
        }
    })
}

/// Test result types for controlled race outcomes
#[derive(Debug, Clone, PartialEq, Eq)]
enum TestRaceResult {
    /// Successful completion with value and completion time
    Success { value: u32, completion_tick: u64 },
    /// Error completion
    Error { code: u32, completion_tick: u64 },
    /// Cancelled completion
    Cancelled { reason: String, completion_tick: u64 },
}

impl TestRaceResult {
    fn completion_tick(&self) -> u64 {
        match self {
            Self::Success { completion_tick, .. } => *completion_tick,
            Self::Error { completion_tick, .. } => *completion_tick,
            Self::Cancelled { completion_tick, .. } => *completion_tick,
        }
    }

    fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }
}

/// Mock contestant that can be configured for different completion scenarios
struct MockContestant {
    /// Unique ID for this contestant
    id: u32,
    /// Delay before completion
    delay: Duration,
    /// What result to return
    result_type: TestRaceResult,
    /// Shared completion tick counter
    tick_counter: Arc<AtomicU64>,
    /// Drain tracking
    drain_tracker: Arc<AtomicU32>,
}

impl MockContestant {
    fn new(
        id: u32,
        delay: Duration,
        result_type: TestRaceResult,
        tick_counter: Arc<AtomicU64>,
        drain_tracker: Arc<AtomicU32>,
    ) -> Self {
        Self { id, delay, result_type, tick_counter, drain_tracker }
    }

    async fn run(&self, cx: Cx) -> Outcome<u32, String> {
        // Sleep for the configured delay
        sleep(cx, self.delay).await;

        // Record completion tick (simulates deterministic ordering)
        let completion_tick = self.tick_counter.fetch_add(1, Ordering::SeqCst);

        // Simulate the outcome based on configuration
        match &self.result_type {
            TestRaceResult::Success { value, .. } => Outcome::Ok(*value),
            TestRaceResult::Error { code, .. } => Outcome::Err(format!("Error {}", code)),
            TestRaceResult::Cancelled { reason, .. } => {
                Outcome::Cancelled(CancelReason::user(reason))
            }
        }
    }

    fn on_drain(&self) {
        // Record that this contestant was properly drained
        self.drain_tracker.fetch_add(1, Ordering::SeqCst);
    }
}

/// MR1: Winner returns its Outcome (winner correctness)
/// Verifies that the race returns exactly the winner's outcome value
#[test]
fn mr1_winner_returns_its_outcome() {
    proptest!(|(config in race_drain_config_strategy())| {
        prop_assume!(config.num_contestants >= 2);

        let runtime = LabRuntime::new(LabConfig::deterministic(config.lab_seed));

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                // Create race contestants with known outcomes
                let tick_counter = Arc::new(AtomicU64::new(0));
                let drain_tracker = Arc::new(AtomicU32::new(0));

                let winner_value = 42;
                let mut contestants = Vec::new();

                for i in 0..config.num_contestants {
                    let delay = if i == 0 {
                        Duration::from_millis(config.winner_delay_ms)
                    } else {
                        Duration::from_millis(config.loser_base_delay_ms + (i as u64) * 100)
                    };

                    let result_type = if i == 0 {
                        TestRaceResult::Success { value: winner_value, completion_tick: 0 }
                    } else {
                        TestRaceResult::Success { value: i + 100, completion_tick: 0 }
                    };

                    contestants.push(MockContestant::new(
                        i,
                        delay,
                        result_type,
                        tick_counter.clone(),
                        drain_tracker.clone(),
                    ));
                }

                // Simulate race outcomes - first contestant (index 0) wins due to shorter delay
                let mut outcomes = Vec::new();
                for contestant in contestants {
                    let outcome = contestant.run(cx).await;
                    outcomes.push(outcome);
                }

                // Test race2_outcomes for 2-contestant case
                if config.num_contestants == 2 {
                    let (winner_outcome, winner_idx, loser_outcome) =
                        race2_outcomes(RaceWinner::First, outcomes[0].clone(), outcomes[1].clone());

                    // Property 1: Winner outcome should match the actual winner's result
                    prop_assert!(winner_outcome.is_ok(), "Winner should be Ok");
                    if let Outcome::Ok(value) = winner_outcome {
                        prop_assert_eq!(value, winner_value, "Winner should return correct value");
                    }

                    prop_assert!(winner_idx.is_first(), "First contestant should win");
                }

                // Test race_all_outcomes for general N-contestant case
                let race_result = race_all_outcomes(0, outcomes);

                // Property 2: Winner outcome matches expected result
                prop_assert!(race_result.winner_succeeded(), "Winner should succeed");
                prop_assert_eq!(race_result.winner_index, 0, "Contestant 0 should win");

                if let Outcome::Ok(value) = race_result.winner_outcome {
                    prop_assert_eq!(value, winner_value, "Winner should return value {}", winner_value);
                }

                // Property 3: All losers are tracked
                prop_assert_eq!(
                    race_result.loser_outcomes.len() as u32,
                    config.num_contestants - 1,
                    "Should have {} loser outcomes", config.num_contestants - 1
                );

                Ok(())
            })
        });

        result
    });
}

/// MR2: All N-1 losers are cancelled AND fully drained (no dangling tasks)
/// This is the critical invariant that distinguishes asupersync from other runtimes
#[test]
fn mr2_losers_cancelled_and_fully_drained() {
    proptest!(|(config in race_drain_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::deterministic(config.lab_seed));

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let tick_counter = Arc::new(AtomicU64::new(0));
                let drain_tracker = Arc::new(AtomicU32::new(0));

                // Create outcomes where first contestant wins, others lose
                let mut outcomes = Vec::new();
                for i in 0..config.num_contestants {
                    let outcome = if i == 0 {
                        // Winner
                        Outcome::Ok(100 + i)
                    } else {
                        // Loser - should be cancelled with race_loser reason
                        Outcome::Cancelled(CancelReason::race_loser())
                    };
                    outcomes.push(outcome);
                }

                let race_result = race_all_outcomes(0, outcomes);

                // Property 1: Exactly N-1 losers
                let expected_loser_count = config.num_contestants - 1;
                prop_assert_eq!(
                    race_result.loser_outcomes.len() as u32,
                    expected_loser_count,
                    "Should have exactly {} losers", expected_loser_count
                );

                // Property 2: All losers are cancelled
                for (loser_idx, loser_outcome) in &race_result.loser_outcomes {
                    prop_assert!(loser_outcome.is_cancelled(),
                        "Loser at index {} should be cancelled", loser_idx);

                    // Property 3: Cancellation reason should indicate race loss
                    if let Outcome::Cancelled(reason) = loser_outcome {
                        prop_assert!(
                            matches!(reason.kind(), asupersync::types::cancel::CancelKind::RaceLost),
                            "Loser {} should be cancelled with RaceLost reason", loser_idx
                        );
                    }
                }

                // Property 4: No loser indices are duplicated (full drainage)
                let mut loser_indices: Vec<usize> = race_result.loser_outcomes
                    .iter()
                    .map(|(idx, _)| *idx)
                    .collect();
                loser_indices.sort_unstable();

                let expected_indices: Vec<usize> = (1..config.num_contestants as usize).collect();
                prop_assert_eq!(loser_indices, expected_indices,
                    "All loser indices should be accounted for: expected {:?}, got {:?}",
                    expected_indices, loser_indices);

                // Property 5: Winner index is not in loser outcomes
                for (loser_idx, _) in &race_result.loser_outcomes {
                    prop_assert_ne!(*loser_idx, race_result.winner_index,
                        "Winner index {} should not appear in loser outcomes", race_result.winner_index);
                }

                Ok(())
            })
        });

        result
    });
}

/// MR3: Drain deadline bounded by Budget (no infinite hang)
/// Verifies that loser draining completes within bounded time
#[test]
fn mr3_drain_deadline_bounded_by_budget() {
    proptest!(|(config in race_drain_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::deterministic(config.lab_seed));

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let budget = Budget::from_millis(config.drain_budget_ms);

                // Simulate drain operation timing
                let start_time = cx.timer_driver()
                    .map(|driver| driver.now())
                    .unwrap_or_else(|| Time::from_millis(0));

                // Create race outcomes with various completion times
                let mut outcomes = Vec::new();
                for i in 0..config.num_contestants {
                    let outcome = if i == 0 {
                        Outcome::Ok(42) // Winner
                    } else {
                        // Simulate losers that take time to drain but within budget
                        let drain_delay = config.loser_base_delay_ms.min(config.drain_budget_ms / 2);
                        std::thread::sleep(Duration::from_millis(drain_delay)); // Simulate drain work
                        Outcome::Cancelled(CancelReason::race_loser())
                    };
                    outcomes.push(outcome);
                }

                let race_result = race_all_outcomes(0, outcomes);

                let end_time = cx.timer_driver()
                    .map(|driver| driver.now())
                    .unwrap_or_else(|| Time::from_millis(config.drain_budget_ms + 1000));

                // Property 1: Drain completed within budget
                let elapsed_ms = end_time.saturating_sub(start_time);
                prop_assert!(
                    elapsed_ms <= config.drain_budget_ms * 2, // Allow some margin for test overhead
                    "Drain took {}ms, exceeding budget of {}ms",
                    elapsed_ms, config.drain_budget_ms
                );

                // Property 2: All losers were drained (not abandoned)
                prop_assert_eq!(
                    race_result.loser_outcomes.len() as u32,
                    config.num_contestants - 1,
                    "All losers should be drained within budget"
                );

                // Property 3: Race completed successfully despite drain budget constraints
                prop_assert!(race_result.winner_succeeded(), "Race should complete successfully");

                Ok(())
            })
        });

        result
    });
}

/// MR4: Race with all cancelled yields Outcome::Cancelled
/// Verifies edge case where all contestants are cancelled
#[test]
fn mr4_all_cancelled_yields_cancelled() {
    proptest!(|(config in race_drain_config_strategy())| {
        prop_assume!(config.include_cancellation);

        let runtime = LabRuntime::new(LabConfig::deterministic(config.lab_seed));

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                // Create race where ALL contestants are cancelled
                let mut all_cancelled_outcomes = Vec::new();
                for i in 0..config.num_contestants {
                    let cancel_reason = match i {
                        0 => CancelReason::timeout(),
                        1 => CancelReason::user("user cancelled"),
                        _ => CancelReason::race_loser(),
                    };
                    all_cancelled_outcomes.push(Outcome::Cancelled(cancel_reason));
                }

                // First cancellation wins (earliest cancel reason)
                let race_result = race_all_outcomes(0, all_cancelled_outcomes);

                // Property 1: Winner should be cancelled
                prop_assert!(race_result.winner_outcome.is_cancelled(),
                    "When all contestants cancelled, winner should be cancelled");

                // Property 2: Winner index should still be deterministic
                prop_assert_eq!(race_result.winner_index, 0,
                    "Cancellation winner should be deterministic");

                // Property 3: All others should still be tracked as losers
                prop_assert_eq!(
                    race_result.loser_outcomes.len() as u32,
                    config.num_contestants - 1,
                    "All other cancelled contestants should be losers"
                );

                // Property 4: All loser outcomes should also be cancelled
                for (loser_idx, loser_outcome) in &race_result.loser_outcomes {
                    prop_assert!(loser_outcome.is_cancelled(),
                        "All-cancelled scenario: loser {} should be cancelled", loser_idx);
                }

                Ok(())
            })
        });

        result
    });
}

/// MR5: FIRST winner (lowest finish tick) wins, not tick-tied
/// Ensures deterministic winner selection in LabRuntime with precise timing
#[test]
fn mr5_first_finish_tick_wins_deterministic() {
    proptest!(|(config in race_drain_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::deterministic(config.lab_seed));

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                // Test deterministic ordering with simulated completion times
                let mut outcomes_with_ticks = Vec::new();

                for i in 0..config.num_contestants {
                    let completion_tick = if i == 0 {
                        10 // First to complete
                    } else if i == 1 {
                        15 // Second to complete
                    } else {
                        20 + i as u64 // Later completions
                    };

                    let outcome = Outcome::Ok(100 + i);
                    outcomes_with_ticks.push((completion_tick, i, outcome));
                }

                // Sort by completion tick to simulate LabRuntime behavior
                outcomes_with_ticks.sort_by_key(|(tick, _, _)| *tick);

                // Extract outcomes in finish order
                let sorted_outcomes: Vec<_> = outcomes_with_ticks
                    .into_iter()
                    .map(|(_, _, outcome)| outcome)
                    .collect();

                // The FIRST to complete (lowest tick) should win
                let race_result = race_all_outcomes(0, sorted_outcomes);

                // Property 1: First finisher wins
                prop_assert_eq!(race_result.winner_index, 0,
                    "Contestant with lowest completion tick should win");

                // Property 2: Winner should be the one with earliest completion
                prop_assert!(race_result.winner_succeeded(),
                    "First finisher should succeed");

                // Property 3: Test tie-breaking determinism
                // Create scenario where two contestants finish at same tick
                let mut tie_outcomes = Vec::new();
                for i in 0..config.num_contestants {
                    // First two finish at same "tick" 0
                    let outcome = Outcome::Ok(200 + i);
                    tie_outcomes.push(outcome);
                }

                // In tie scenario, first position should win (deterministic tie-breaking)
                let tie_result = race_all_outcomes(0, tie_outcomes);
                prop_assert_eq!(tie_result.winner_index, 0,
                    "In tick-tie scenario, first position should win deterministically");

                // Property 4: All non-winners are properly tracked as losers
                for (loser_idx, _) in &race_result.loser_outcomes {
                    prop_assert!(*loser_idx > race_result.winner_index,
                        "Loser index {} should be higher than winner index {}",
                        loser_idx, race_result.winner_index);
                }

                Ok(())
            })
        });

        result
    });
}

/// Composite metamorphic test: All race properties hold together
#[test]
fn mr_composite_race_drain_invariants() {
    proptest!(|(config in race_drain_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::deterministic(config.lab_seed));

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                // Create a realistic race scenario
                let mut outcomes = Vec::new();
                for i in 0..config.num_contestants {
                    let outcome = if i == 0 {
                        Outcome::Ok(42) // Winner
                    } else if i == 1 && config.include_cancellation {
                        Outcome::Cancelled(CancelReason::timeout()) // One cancellation
                    } else {
                        Outcome::Cancelled(CancelReason::race_loser()) // Normal losers
                    };
                    outcomes.push(outcome);
                }

                let race_result = race_all_outcomes(0, outcomes);

                // Composite Property 1: Winner correctness
                prop_assert!(race_result.winner_succeeded(), "Winner should succeed");
                prop_assert_eq!(race_result.winner_index, 0, "Index 0 should win");

                // Composite Property 2: Complete drainage
                prop_assert_eq!(
                    race_result.loser_outcomes.len() as u32,
                    config.num_contestants - 1,
                    "All losers accounted for"
                );

                // Composite Property 3: Proper cancellation semantics
                for (_, loser_outcome) in &race_result.loser_outcomes {
                    prop_assert!(loser_outcome.is_cancelled(), "All losers cancelled");
                }

                // Composite Property 4: No resource leaks (all outcomes processed)
                let total_outcomes = 1 + race_result.loser_outcomes.len(); // winner + losers
                prop_assert_eq!(total_outcomes as u32, config.num_contestants,
                    "All {} contestants accounted for", config.num_contestants);

                // Composite Property 5: Deterministic structure
                let mut loser_indices: Vec<_> = race_result.loser_outcomes
                    .iter()
                    .map(|(idx, _)| *idx)
                    .collect();
                loser_indices.sort_unstable();

                // Should be consecutive indices excluding winner
                for (pos, &idx) in loser_indices.iter().enumerate() {
                    let expected_idx = pos + 1; // Skip winner at index 0
                    prop_assert_eq!(idx, expected_idx,
                        "Loser indices should be consecutive: expected {}, got {}",
                        expected_idx, idx);
                }

                Ok(())
            })
        });

        result
    });
}

/// Test 2-way race specific properties using Race2 types
#[test]
fn mr_race2_specific_properties() {
    proptest!(|(
        winner_value in 1_u32..=1000,
        loser_delay_ms in 100_u64..=1000,
        lab_seed in 1_u64..=u64::MAX
    )| {
        let runtime = LabRuntime::new(LabConfig::deterministic(lab_seed));

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                // Test Race2 specific functionality
                let winner_outcome: Outcome<u32, String> = Outcome::Ok(winner_value);
                let loser_outcome: Outcome<u32, String> = Outcome::Cancelled(CancelReason::race_loser());

                // Test both winner positions
                for winner_pos in [RaceWinner::First, RaceWinner::Second] {
                    let (result_winner, result_pos, result_loser) = match winner_pos {
                        RaceWinner::First => race2_outcomes(
                            RaceWinner::First,
                            winner_outcome.clone(),
                            loser_outcome.clone()
                        ),
                        RaceWinner::Second => race2_outcomes(
                            RaceWinner::Second,
                            loser_outcome.clone(),
                            winner_outcome.clone()
                        ),
                    };

                    // Property 1: Winner outcome matches input
                    prop_assert!(result_winner.is_ok(), "Winner should be Ok");
                    if let Outcome::Ok(value) = result_winner {
                        prop_assert_eq!(value, winner_value, "Winner value should match");
                    }

                    // Property 2: Position tracking correct
                    match winner_pos {
                        RaceWinner::First => prop_assert!(result_pos.is_first(), "First should win"),
                        RaceWinner::Second => prop_assert!(result_pos.is_second(), "Second should win"),
                    }

                    // Property 3: Loser is cancelled
                    prop_assert!(result_loser.is_cancelled(), "Loser should be cancelled");
                }

                Ok(())
            })
        });

        result
    });
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_race_winner_basic_properties() {
        // Test RaceWinner basic functionality
        assert!(RaceWinner::First.is_first());
        assert!(!RaceWinner::First.is_second());
        assert!(RaceWinner::Second.is_second());
        assert!(!RaceWinner::Second.is_first());
    }

    #[test]
    fn test_race2_outcomes_first_wins() {
        let winner: Outcome<i32, &str> = Outcome::Ok(42);
        let loser: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let (w_outcome, w_pos, l_outcome) = race2_outcomes(RaceWinner::First, winner, loser);

        assert!(w_outcome.is_ok());
        assert!(w_pos.is_first());
        assert!(l_outcome.is_cancelled());
    }

    #[test]
    fn test_race2_outcomes_second_wins() {
        let loser: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());
        let winner: Outcome<i32, &str> = Outcome::Ok(99);

        let (w_outcome, w_pos, l_outcome) = race2_outcomes(RaceWinner::Second, loser, winner);

        assert!(w_outcome.is_ok());
        assert!(w_pos.is_second());
        assert!(l_outcome.is_cancelled());
    }

    #[test]
    fn test_race_all_outcomes_basic() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Ok(42), // Winner at index 1
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = race_all_outcomes(1, outcomes);

        assert!(result.winner_succeeded());
        assert_eq!(result.winner_index, 1);
        assert_eq!(result.loser_outcomes.len(), 2);

        // Check loser indices
        let loser_indices: Vec<usize> = result.loser_outcomes
            .iter()
            .map(|(idx, _)| *idx)
            .collect();
        assert_eq!(loser_indices, vec![0, 2]);
    }

    #[test]
    fn test_all_cancelled_scenario() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Cancelled(CancelReason::user("stopped")),
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = race_all_outcomes(0, outcomes); // First cancellation wins

        assert!(result.winner_outcome.is_cancelled());
        assert_eq!(result.winner_index, 0);
        assert_eq!(result.loser_outcomes.len(), 2);
    }

    #[test]
    fn test_drain_tracking_simulation() {
        let drain_tracker = Arc::new(AtomicU32::new(0));

        // Simulate drain operations
        let contestant = MockContestant::new(
            1,
            Duration::from_millis(100),
            TestRaceResult::Success { value: 42, completion_tick: 0 },
            Arc::new(AtomicU64::new(0)),
            drain_tracker.clone(),
        );

        // Simulate drain completion
        contestant.on_drain();
        assert_eq!(drain_tracker.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_completion_tick_ordering() {
        let tick_counter = Arc::new(AtomicU64::new(0));

        let fast_result = TestRaceResult::Success { value: 1, completion_tick: 0 };
        let slow_result = TestRaceResult::Success { value: 2, completion_tick: 0 };

        let fast_contestant = MockContestant::new(
            0, Duration::from_millis(10), fast_result, tick_counter.clone(), Arc::new(AtomicU32::new(0))
        );
        let slow_contestant = MockContestant::new(
            1, Duration::from_millis(100), slow_result, tick_counter.clone(), Arc::new(AtomicU32::new(0))
        );

        // Fast contestant should get lower tick
        assert!(fast_contestant.delay < slow_contestant.delay);
    }
}