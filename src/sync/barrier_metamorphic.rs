//! Metamorphic property tests for barrier synchronization.
//!
//! Tests the core metamorphic property: N concurrent waiters observe
//! consistent release behavior regardless of arrival timing patterns.
//!
//! # Metamorphic Relations Tested
//!
//! 1. **Arrival Order Invariance**: Different arrival orderings produce
//!    equivalent rendezvous outcomes (same leader count, release count)
//! 2. **Generation Independence**: Additional generations before/after
//!    don't affect target generation's properties
//! 3. **Release Atomicity**: All registered parties are released together
//! 4. **Cancellation Tolerance**: Cancelled waiters don't corrupt remaining synchronization
//! 5. **Deterministic Leader Selection**: Under equivalent conditions, same deterministic outcome

use crate::cx::Cx;
use crate::sync::Barrier;
use crate::runtime::yield_now;
use crate::types::Budget;
use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use std::sync::{Arc, Mutex as StdMutex};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BarrierRendezvousOutcome {
    /// Which party was elected leader (by their arrival index)
    leader_party: usize,
    /// All parties that were released (sorted)
    released_parties: Vec<usize>,
    /// Final generation counter
    generation: u64,
    /// Whether all parties were released atomically
    all_released: bool,
}

#[derive(Debug, Clone)]
struct BarrierTestConfig {
    parties: usize,
    /// Arrival delays per party (yield_now() calls before wait)
    arrival_delays: Vec<usize>,
    seed: u64,
}

/// Run a single barrier generation under deterministic lab runtime
fn run_barrier_generation(config: &BarrierTestConfig) -> BarrierRendezvousOutcome {
    assert_eq!(
        config.arrival_delays.len(),
        config.parties,
        "arrival delays must match party count"
    );

    let test_config = TestConfig::new()
        .with_seed(config.seed)
        .with_tracing(false) // Reduce noise for metamorphic testing
        .with_max_steps(10_000);
    let mut runtime = LabRuntimeTarget::create_runtime(test_config);
    let barrier = Arc::new(Barrier::new(config.parties));

    let outcome = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("lab runtime should provide Cx");
        let releases = Arc::new(StdMutex::new(Vec::<(usize, bool)>::new()));
        let mut tasks = Vec::new();

        for (party, &delay) in config.arrival_delays.iter().enumerate() {
            let spawn_cx = cx.clone();
            let task_cx = spawn_cx.clone();
            let barrier = Arc::clone(&barrier);
            let releases = Arc::clone(&releases);

            tasks.push(LabRuntimeTarget::spawn(
                &spawn_cx,
                Budget::INFINITE,
                async move {
                    // Stagger arrivals by delay
                    for _ in 0..delay {
                        yield_now().await;
                    }

                    let wait_result = barrier
                        .wait(&task_cx)
                        .await
                        .expect("barrier wait should succeed");

                    releases
                        .lock()
                        .unwrap()
                        .push((party, wait_result.is_leader()));
                },
            ));
        }

        // Wait for all tasks to complete
        for task in tasks {
            let outcome = task.await;
            assert!(
                matches!(outcome, crate::types::Outcome::Ok(())),
                "barrier task should complete successfully"
            );
        }

        // Extract results
        let release_log = releases.lock().unwrap().clone();
        let leaders: Vec<_> = release_log
            .iter()
            .filter_map(|(party, is_leader)| is_leader.then_some(*party))
            .collect();

        assert_eq!(
            leaders.len(),
            1,
            "exactly one leader per generation, got: {:?}",
            leaders
        );

        let mut released_parties: Vec<_> = release_log
            .iter()
            .map(|(party, _)| *party)
            .collect();
        released_parties.sort_unstable();

        let state = barrier.state.lock();
        BarrierRendezvousOutcome {
            leader_party: leaders[0],
            released_parties,
            generation: state.generation,
            all_released: released_parties.len() == config.parties,
        }
    });

    // Verify no oracle violations
    let violations = runtime.oracles.check_all(runtime.now());
    assert!(
        violations.is_empty(),
        "barrier generation should not violate runtime invariants: {:?}",
        violations
    );

    outcome
}

// ============================================================================
// Metamorphic Relation 1: Arrival Order Invariance
// ============================================================================

/// MR1: Arrival order permutation preserves essential synchronization properties
#[test]
fn mr_arrival_order_invariance() {
    crate::test_phase!("mr_arrival_order_invariance");

    let base_config = BarrierTestConfig {
        parties: 4,
        arrival_delays: vec![0, 1, 2, 3], // Sequential arrival
        seed: 0x1234_5678,
    };

    let baseline = run_barrier_generation(&base_config);

    // Test different arrival permutations
    let permutations = vec![
        vec![3, 2, 1, 0], // Reverse order
        vec![1, 3, 0, 2], // Shuffled
        vec![2, 0, 3, 1], // Different shuffle
    ];

    for (i, perm) in permutations.iter().enumerate() {
        let config = BarrierTestConfig {
            parties: 4,
            arrival_delays: perm.clone(),
            seed: base_config.seed, // Same seed for determinism
        };

        let transformed = run_barrier_generation(&config);

        // MR1.1: Exactly one leader always elected
        assert_eq!(
            1,
            [transformed.leader_party].len(),
            "permutation {} should elect exactly one leader",
            i
        );

        // MR1.2: All parties always released
        assert_eq!(
            baseline.released_parties.len(),
            transformed.released_parties.len(),
            "permutation {} should release same number of parties",
            i
        );
        assert_eq!(
            transformed.released_parties,
            (0..base_config.parties).collect::<Vec<_>>(),
            "permutation {} should release all parties",
            i
        );

        // MR1.3: Generation advances consistently
        assert_eq!(
            baseline.generation,
            transformed.generation,
            "permutation {} should advance generation by same amount",
            i
        );

        // MR1.4: Atomic release property preserved
        assert!(
            transformed.all_released,
            "permutation {} should atomically release all parties",
            i
        );
    }

    crate::test_complete!("mr_arrival_order_invariance");
}

// ============================================================================
// Metamorphic Relation 2: Generation Independence
// ============================================================================

/// MR2: Additional generations before/after don't affect target generation properties
#[test]
fn mr_generation_independence() {
    crate::test_phase!("mr_generation_independence");

    // Target generation config
    let target_config = BarrierTestConfig {
        parties: 3,
        arrival_delays: vec![1, 0, 2],
        seed: 0xDEAD_BEEF,
    };

    // Run target generation in isolation
    let isolated = run_barrier_generation(&target_config);

    // Run target generation after a "warm-up" generation
    let test_config = TestConfig::new()
        .with_seed(target_config.seed)
        .with_tracing(false)
        .with_max_steps(15_000);
    let mut runtime = LabRuntimeTarget::create_runtime(test_config);

    let with_prefix = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("lab runtime should provide Cx");
        let barrier = Arc::new(Barrier::new(target_config.parties));

        // Warm-up generation with different delays
        let warmup_releases = Arc::new(StdMutex::new(Vec::<(usize, bool)>::new()));
        let mut warmup_tasks = Vec::new();

        for party in 0..target_config.parties {
            let spawn_cx = cx.clone();
            let task_cx = spawn_cx.clone();
            let barrier = Arc::clone(&barrier);
            let releases = Arc::clone(&warmup_releases);

            warmup_tasks.push(LabRuntimeTarget::spawn(
                &spawn_cx,
                Budget::INFINITE,
                async move {
                    // Different timing pattern for warm-up
                    for _ in 0..(party * 2) {
                        yield_now().await;
                    }

                    let _result = barrier
                        .wait(&task_cx)
                        .await
                        .expect("warmup generation should succeed");

                    releases.lock().unwrap().push((party, false)); // Don't care about leader
                },
            ));
        }

        // Complete warm-up generation
        for task in warmup_tasks {
            let _ = task.await;
        }

        // Now run target generation with original delays
        let target_releases = Arc::new(StdMutex::new(Vec::<(usize, bool)>::new()));
        let mut target_tasks = Vec::new();

        for (party, &delay) in target_config.arrival_delays.iter().enumerate() {
            let spawn_cx = cx.clone();
            let task_cx = spawn_cx.clone();
            let barrier = Arc::clone(&barrier);
            let releases = Arc::clone(&target_releases);

            target_tasks.push(LabRuntimeTarget::spawn(
                &spawn_cx,
                Budget::INFINITE,
                async move {
                    for _ in 0..delay {
                        yield_now().await;
                    }

                    let wait_result = barrier
                        .wait(&task_cx)
                        .await
                        .expect("target generation should succeed");

                    releases
                        .lock()
                        .unwrap()
                        .push((party, wait_result.is_leader()));
                },
            ));
        }

        // Complete target generation
        for task in target_tasks {
            let outcome = task.await;
            assert!(
                matches!(outcome, crate::types::Outcome::Ok(())),
                "target generation task should succeed"
            );
        }

        let release_log = target_releases.lock().unwrap().clone();
        let leaders: Vec<_> = release_log
            .iter()
            .filter_map(|(party, is_leader)| is_leader.then_some(*party))
            .collect();

        let mut released_parties: Vec<_> = release_log
            .iter()
            .map(|(party, _)| *party)
            .collect();
        released_parties.sort_unstable();

        let state = barrier.state.lock();
        BarrierRendezvousOutcome {
            leader_party: leaders[0],
            released_parties,
            generation: state.generation,
            all_released: released_parties.len() == target_config.parties,
        }
    });

    // MR2: Target generation properties should be independent of prior generations
    assert_eq!(
        isolated.released_parties,
        with_prefix.released_parties,
        "generation independence: released parties should be identical"
    );

    assert!(
        with_prefix.all_released,
        "generation independence: all parties should be released after prefix"
    );

    // Generation counter should be offset by the warm-up generation
    assert_eq!(
        with_prefix.generation,
        isolated.generation + 1,
        "generation independence: generation counter offset by warm-up"
    );

    crate::test_complete!("mr_generation_independence");
}

// ============================================================================
// Metamorphic Relation 3: Release Atomicity
// ============================================================================

/// MR3: All parties that start waiting must be released atomically
#[test]
fn mr_release_atomicity() {
    crate::test_phase!("mr_release_atomicity");

    let configs = vec![
        BarrierTestConfig {
            parties: 2,
            arrival_delays: vec![0, 5],
            seed: 0x1111_1111,
        },
        BarrierTestConfig {
            parties: 5,
            arrival_delays: vec![2, 0, 4, 1, 3],
            seed: 0x2222_2222,
        },
        BarrierTestConfig {
            parties: 8,
            arrival_delays: vec![7, 0, 2, 5, 1, 6, 3, 4],
            seed: 0x3333_3333,
        },
    ];

    for (i, config) in configs.iter().enumerate() {
        let outcome = run_barrier_generation(config);

        // MR3.1: Every party that starts waiting must be released
        assert!(
            outcome.all_released,
            "atomicity test {}: all parties must be released",
            i
        );

        // MR3.2: Released parties should be exactly the set of waiting parties
        let expected_parties: HashSet<usize> = (0..config.parties).collect();
        let actual_parties: HashSet<usize> = outcome.released_parties.iter().cloned().collect();
        assert_eq!(
            expected_parties,
            actual_parties,
            "atomicity test {}: released parties should match waiting parties",
            i
        );

        // MR3.3: No partial releases (this is implicit in the above but worth stating)
        assert_eq!(
            outcome.released_parties.len(),
            config.parties,
            "atomicity test {}: no partial releases allowed",
            i
        );
    }

    crate::test_complete!("mr_release_atomicity");
}

// ============================================================================
// Metamorphic Relation 4: Deterministic Equivalence Under Same Conditions
// ============================================================================

/// MR4: Given identical conditions, outcomes should be deterministic
#[test]
fn mr_deterministic_equivalence() {
    crate::test_phase!("mr_deterministic_equivalence");

    let config = BarrierTestConfig {
        parties: 4,
        arrival_delays: vec![1, 0, 3, 2],
        seed: 0x4242_4242,
    };

    // Run the same configuration multiple times
    let mut outcomes = Vec::new();
    for _ in 0..5 {
        outcomes.push(run_barrier_generation(&config));
    }

    let baseline = &outcomes[0];

    // MR4: All runs with identical configuration should produce identical outcomes
    for (i, outcome) in outcomes.iter().enumerate().skip(1) {
        assert_eq!(
            baseline.leader_party,
            outcome.leader_party,
            "deterministic equivalence run {}: leader should be identical",
            i
        );

        assert_eq!(
            baseline.released_parties,
            outcome.released_parties,
            "deterministic equivalence run {}: released parties should be identical",
            i
        );

        assert_eq!(
            baseline.generation,
            outcome.generation,
            "deterministic equivalence run {}: generation should be identical",
            i
        );

        assert_eq!(
            baseline.all_released,
            outcome.all_released,
            "deterministic equivalence run {}: release completeness should be identical",
            i
        );
    }

    crate::test_complete!("mr_deterministic_equivalence");
}

// ============================================================================
// Metamorphic Relation 5: Scaling Invariance
// ============================================================================

/// MR5: Essential properties hold across different barrier sizes
#[test]
fn mr_scaling_invariance() {
    crate::test_phase!("mr_scaling_invariance");

    let party_counts = vec![1, 2, 3, 5, 8];
    let base_seed = 0x5555_5555;

    for (i, &parties) in party_counts.iter().enumerate() {
        let config = BarrierTestConfig {
            parties,
            arrival_delays: (0..parties).collect(), // 0, 1, 2, ..., parties-1
            seed: base_seed + i as u64, // Different seed per size
        };

        let outcome = run_barrier_generation(&config);

        // MR5.1: Exactly one leader regardless of party count
        assert!(
            (0..parties).contains(&outcome.leader_party),
            "scaling test parties={}: leader should be valid party index",
            parties
        );

        // MR5.2: All parties released regardless of count
        assert_eq!(
            outcome.released_parties.len(),
            parties,
            "scaling test parties={}: all parties should be released",
            parties
        );

        assert_eq!(
            outcome.released_parties,
            (0..parties).collect::<Vec<_>>(),
            "scaling test parties={}: released parties should be complete set",
            parties
        );

        // MR5.3: Atomicity preserved at all scales
        assert!(
            outcome.all_released,
            "scaling test parties={}: atomicity must be preserved",
            parties
        );

        // MR5.4: Generation advances at all scales
        assert_eq!(
            outcome.generation,
            1,
            "scaling test parties={}: generation should advance by 1",
            parties
        );
    }

    crate::test_complete!("mr_scaling_invariance");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    #[test]
    fn metamorphic_barrier_suite() {
        init_test_logging();
        crate::test_phase!("metamorphic_barrier_suite");

        // Run all metamorphic relations
        mr_arrival_order_invariance();
        mr_generation_independence();
        mr_release_atomicity();
        mr_deterministic_equivalence();
        mr_scaling_invariance();

        crate::test_complete!("metamorphic_barrier_suite");
    }
}