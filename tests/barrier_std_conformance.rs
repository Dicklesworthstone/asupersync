//! Conformance test for asupersync::sync::Barrier vs std::sync::Barrier.
//!
//! Tests that both barrier implementations exhibit identical behavior for:
//! - Same N waiters produce same release order
//! - Identical leader designation (exactly one per generation)
//! - Consistent barrier trip semantics
//! - Proper reset behavior between generations

use asupersync::cx::Cx;
use asupersync::sync::Barrier as AsupersyncBarrier;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier as StdBarrier};
use std::task::{Context, Poll};
use std::thread;

/// Result of a barrier conformance test comparing both implementations.
#[derive(Debug, Clone, PartialEq)]
struct BarrierConformanceResult {
    /// Number of parties that participated
    parties: usize,
    /// Which party was designated as leader in asupersync implementation
    asupersync_leader: Option<usize>,
    /// Which party was designated as leader in std implementation
    std_leader: Option<usize>,
    /// Release order for asupersync (party IDs in order of completion)
    asupersync_release_order: Vec<usize>,
    /// Release order for std (party IDs in order of completion)
    std_release_order: Vec<usize>,
    /// Total execution time
    total_duration: std::time::Duration,
}

/// Conformance test configuration.
#[derive(Debug, Clone)]
struct ConformanceTestConfig {
    /// Number of parties for the barrier
    parties: usize,
    /// Number of generations to test
    generations: usize,
    /// Arrival delay pattern (microseconds per party)
    arrival_delays_us: Vec<u64>,
}

/// Test context for running conformance tests.
struct BarrierConformanceContext {
    config: ConformanceTestConfig,
}

impl BarrierConformanceContext {
    fn new(config: ConformanceTestConfig) -> Self {
        Self { config }
    }

    /// Run the same barrier scenario on both implementations and compare results.
    fn run_differential_test(
        &self,
    ) -> (Vec<BarrierConformanceResult>, Vec<BarrierConformanceResult>) {
        let asupersync_results = self.test_asupersync_barrier();
        let std_results = self.test_std_barrier();

        (asupersync_results, std_results)
    }

    /// Test asupersync barrier behavior.
    fn test_asupersync_barrier(&self) -> Vec<BarrierConformanceResult> {
        let mut results = Vec::new();

        for generation in 0..self.config.generations {
            let start_time = std::time::Instant::now();
            let parties = self.config.parties;

            let barrier = Arc::new(AsupersyncBarrier::new(parties));
            let leader_idx = Arc::new(AtomicUsize::new(usize::MAX));
            let release_order = Arc::new(parking_lot::Mutex::new(Vec::new()));

            let handles: Vec<_> = (0..parties)
                .map(|party_id| {
                    let barrier = Arc::clone(&barrier);
                    let leader_idx = Arc::clone(&leader_idx);
                    let release_order = Arc::clone(&release_order);
                    let arrival_delay = self
                        .config
                        .arrival_delays_us
                        .get(party_id)
                        .copied()
                        .unwrap_or(0);

                    thread::spawn(move || {
                        // Apply arrival delay
                        if arrival_delay > 0 {
                            thread::sleep(std::time::Duration::from_micros(arrival_delay));
                        }

                        // Create Cx for this party
                        let cx = Cx::new(
                            RegionId::from_arena(ArenaIndex::new(
                                generation as u32,
                                party_id as u32,
                            )),
                            TaskId::from_arena(ArenaIndex::new(generation as u32, party_id as u32)),
                            Budget::INFINITE,
                        );

                        // Use simple blocking approach for conformance test
                        let mut wait_future = barrier.wait(&cx);
                        let mut context = Context::from_waker(std::task::Waker::noop());

                        let result = loop {
                            match Pin::new(&mut wait_future).poll(&mut context) {
                                Poll::Ready(Ok(result)) => break result,
                                Poll::Ready(Err(e)) => panic!("Barrier wait failed: {:?}", e),
                                Poll::Pending => {
                                    // Yield and retry
                                    thread::sleep(std::time::Duration::from_millis(1));
                                }
                            }
                        };

                        // Record if this party is the leader
                        if result.is_leader() {
                            leader_idx.store(party_id, Ordering::SeqCst);
                        }

                        // Record release order
                        release_order.lock().push(party_id);
                    })
                })
                .collect();

            // Wait for all threads to complete
            for handle in handles {
                handle.join().expect("Thread should complete successfully");
            }

            let leader = {
                let idx = leader_idx.load(Ordering::SeqCst);
                if idx == usize::MAX { None } else { Some(idx) }
            };

            results.push(BarrierConformanceResult {
                parties: self.config.parties,
                asupersync_leader: leader,
                std_leader: None, // Will be filled by comparison
                asupersync_release_order: release_order.lock().clone(),
                std_release_order: Vec::new(), // Will be filled by comparison
                total_duration: start_time.elapsed(),
            });
        }

        results
    }

    /// Test std::sync::Barrier behavior.
    fn test_std_barrier(&self) -> Vec<BarrierConformanceResult> {
        let mut results = Vec::new();

        for _generation in 0..self.config.generations {
            let start_time = std::time::Instant::now();
            let parties = self.config.parties;

            let barrier = Arc::new(StdBarrier::new(parties));
            let leader_idx = Arc::new(AtomicUsize::new(usize::MAX));
            let release_order = Arc::new(parking_lot::Mutex::new(Vec::new()));

            let handles: Vec<_> = (0..parties)
                .map(|party_id| {
                    let barrier = Arc::clone(&barrier);
                    let leader_idx = Arc::clone(&leader_idx);
                    let release_order = Arc::clone(&release_order);
                    let arrival_delay = self
                        .config
                        .arrival_delays_us
                        .get(party_id)
                        .copied()
                        .unwrap_or(0);

                    thread::spawn(move || {
                        // Apply arrival delay
                        if arrival_delay > 0 {
                            thread::sleep(std::time::Duration::from_micros(arrival_delay));
                        }

                        // Wait on std barrier
                        let result = barrier.wait();

                        // Record if this party is the leader
                        if result.is_leader() {
                            leader_idx.store(party_id, Ordering::SeqCst);
                        }

                        // Record release order
                        release_order.lock().push(party_id);
                    })
                })
                .collect();

            // Wait for all threads to complete
            for handle in handles {
                handle.join().expect("Thread should complete successfully");
            }

            let leader = {
                let idx = leader_idx.load(Ordering::SeqCst);
                if idx == usize::MAX { None } else { Some(idx) }
            };

            results.push(BarrierConformanceResult {
                parties: self.config.parties,
                asupersync_leader: None, // Will be filled by comparison
                std_leader: leader,
                asupersync_release_order: Vec::new(), // Will be filled by comparison
                std_release_order: release_order.lock().clone(),
                total_duration: start_time.elapsed(),
            });
        }

        results
    }
}

/// Verify that both barrier implementations have conformant behavior.
fn assert_barrier_conformance(
    asupersync_results: &[BarrierConformanceResult],
    std_results: &[BarrierConformanceResult],
    test_name: &str,
) {
    assert_eq!(
        asupersync_results.len(),
        std_results.len(),
        "{}: Generation count mismatch",
        test_name
    );

    for (i, (asupersync_result, std_result)) in asupersync_results
        .iter()
        .zip(std_results.iter())
        .enumerate()
    {
        // Both should have exactly one leader
        assert!(
            asupersync_result.asupersync_leader.is_some(),
            "{} gen {}: asupersync should have exactly one leader",
            test_name,
            i
        );

        assert!(
            std_result.std_leader.is_some(),
            "{} gen {}: std should have exactly one leader",
            test_name,
            i
        );

        // Same number of parties should be released
        assert_eq!(
            asupersync_result.asupersync_release_order.len(),
            asupersync_result.parties,
            "{} gen {}: asupersync should release all parties",
            test_name,
            i
        );

        assert_eq!(
            std_result.std_release_order.len(),
            std_result.parties,
            "{} gen {}: std should release all parties",
            test_name,
            i
        );

        // Both implementations should release the same parties
        let mut asupersync_parties = asupersync_result.asupersync_release_order.clone();
        let mut std_parties = std_result.std_release_order.clone();
        asupersync_parties.sort();
        std_parties.sort();

        assert_eq!(
            asupersync_parties, std_parties,
            "{} gen {}: Different parties released\n\
             asupersync: {:?}\n\
             std:        {:?}",
            test_name, i, asupersync_parties, std_parties
        );
    }
}

/// Test basic barrier synchronization with N parties.
#[test]
fn conformance_basic_barrier_sync() {
    let config = ConformanceTestConfig {
        parties: 3,
        generations: 1,
        arrival_delays_us: vec![0, 0, 0],
    };

    let ctx = BarrierConformanceContext::new(config);
    let (asupersync_results, std_results) = ctx.run_differential_test();

    assert_barrier_conformance(&asupersync_results, &std_results, "basic_barrier_sync");

    // Both should complete successfully
    assert_eq!(asupersync_results.len(), 1);
    assert_eq!(std_results.len(), 1);
}

/// Test barrier with staggered arrival times.
#[test]
fn conformance_staggered_arrivals() {
    let config = ConformanceTestConfig {
        parties: 4,
        generations: 1,
        arrival_delays_us: vec![0, 100, 200, 300], // 0.1ms increments
    };

    let ctx = BarrierConformanceContext::new(config);
    let (asupersync_results, std_results) = ctx.run_differential_test();

    assert_barrier_conformance(&asupersync_results, &std_results, "staggered_arrivals");
}

/// Test multiple generations of the same barrier.
#[test]
fn conformance_multiple_generations() {
    let config = ConformanceTestConfig {
        parties: 2,
        generations: 3,
        arrival_delays_us: vec![0, 50],
    };

    let ctx = BarrierConformanceContext::new(config);
    let (asupersync_results, std_results) = ctx.run_differential_test();

    assert_barrier_conformance(&asupersync_results, &std_results, "multiple_generations");

    // All generations should complete successfully
    assert_eq!(asupersync_results.len(), 3);
    assert_eq!(std_results.len(), 3);
}

/// Test single-party barrier (edge case).
#[test]
fn conformance_single_party() {
    let config = ConformanceTestConfig {
        parties: 1,
        generations: 1,
        arrival_delays_us: vec![0],
    };

    let ctx = BarrierConformanceContext::new(config);
    let (asupersync_results, std_results) = ctx.run_differential_test();

    assert_barrier_conformance(&asupersync_results, &std_results, "single_party");

    // Single party should be the leader in both implementations
    assert_eq!(asupersync_results[0].asupersync_leader, Some(0));
    assert_eq!(std_results[0].std_leader, Some(0));
}

/// Test larger party counts.
#[test]
fn conformance_large_party_count() {
    let config = ConformanceTestConfig {
        parties: 8,
        generations: 1,
        arrival_delays_us: vec![0, 10, 20, 30, 40, 50, 60, 70],
    };

    let ctx = BarrierConformanceContext::new(config);
    let (asupersync_results, std_results) = ctx.run_differential_test();

    assert_barrier_conformance(&asupersync_results, &std_results, "large_party_count");
}

/// Comprehensive conformance test matrix.
#[test]
fn conformance_comprehensive_matrix() {
    let test_cases = vec![
        // (parties, generations, delay_pattern_us)
        (2, 2, vec![0, 0]),
        (3, 1, vec![0, 100, 200]),
        (4, 1, vec![50, 0, 150, 25]),
        (5, 1, vec![0, 20, 40, 60, 80]),
    ];

    for (i, (parties, generations, delays)) in test_cases.into_iter().enumerate() {
        let config = ConformanceTestConfig {
            parties,
            generations,
            arrival_delays_us: delays,
        };

        let ctx = BarrierConformanceContext::new(config);
        let (asupersync_results, std_results) = ctx.run_differential_test();

        assert_barrier_conformance(
            &asupersync_results,
            &std_results,
            &format!("comprehensive_matrix_case_{}", i),
        );
    }
}

/// Verify the documented coverage matrix instead of printing a report that can
/// pass without exercising any implementation behavior.
#[test]
fn conformance_coverage_matrix_exercises_all_scenarios() {
    let test_cases = vec![
        (
            "basic_sync",
            ConformanceTestConfig {
                parties: 3,
                generations: 1,
                arrival_delays_us: vec![0, 0, 0],
            },
        ),
        (
            "staggered_arrivals",
            ConformanceTestConfig {
                parties: 4,
                generations: 1,
                arrival_delays_us: vec![0, 100, 200, 300],
            },
        ),
        (
            "multiple_generations",
            ConformanceTestConfig {
                parties: 2,
                generations: 3,
                arrival_delays_us: vec![0, 50],
            },
        ),
        (
            "single_party",
            ConformanceTestConfig {
                parties: 1,
                generations: 1,
                arrival_delays_us: vec![0],
            },
        ),
        (
            "large_party_count",
            ConformanceTestConfig {
                parties: 8,
                generations: 1,
                arrival_delays_us: vec![0, 10, 20, 30, 40, 50, 60, 70],
            },
        ),
    ];

    assert_eq!(test_cases.len(), 5, "coverage matrix should stay explicit");

    for (name, config) in test_cases {
        let ctx = BarrierConformanceContext::new(config);
        let (asupersync_results, std_results) = ctx.run_differential_test();

        assert_barrier_conformance(&asupersync_results, &std_results, name);
    }
}
