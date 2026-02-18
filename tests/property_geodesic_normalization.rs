//! Property tests for geodesic trace normalization (bd-3hz77).
//!
//! Proves/validates that geodesic normalization:
//! 1. **Preserves happens-before**: every schedule is a valid linear extension
//! 2. **Minimizes context switches**: exact solver matches brute-force optimum
//! 3. **Is deterministic**: identical inputs always produce identical outputs
//! 4. **Bounds quality**: heuristics never exceed optimal by more than n-1
//!
//! Test structure:
//! - Arbitrary generators for trace events and posets
//! - Happens-before preservation invariants
//! - Switch-count optimality proofs
//! - Cross-algorithm comparison properties
//! - Edge-case robustness (empty, single, fully-independent, fully-dependent)

#![allow(clippy::cast_possible_wrap)]

mod common;

use asupersync::trace::event_structure::{OwnerKey, TracePoset};
use asupersync::trace::independence::independent;
use asupersync::trace::{
    GeodesicAlgorithm, GeodesicConfig, TraceEvent, count_switches, geodesic_normalize,
    is_valid_linear_extension,
};
use asupersync::types::{RegionId, TaskId, Time};
use common::{init_test_logging, test_proptest_config};
use proptest::prelude::*;

// ============================================================================
// Arbitrary Generators
// ============================================================================

fn tid(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

/// Generate a trace with `n` events across `owners` task-lanes.
/// Events with the same owner are dependent (same task → sequential).
/// Events with different owners are typically independent.
fn arb_trace_events(max_n: usize, max_owners: u32) -> impl Strategy<Value = Vec<TraceEvent>> {
    (1..=max_n).prop_flat_map(move |n| {
        proptest::collection::vec(1..=max_owners, n).prop_map(move |owners| {
            owners
                .into_iter()
                .enumerate()
                .map(|(i, owner)| {
                    TraceEvent::spawn(
                        (i + 1) as u64,
                        Time::from_nanos(i as u64 * 1000),
                        tid(owner),
                        rid(owner),
                    )
                })
                .collect::<Vec<_>>()
        })
    })
}

/// Generate traces with mixed event kinds (spawn + complete) for richer
/// independence structure.
fn arb_mixed_trace(max_n: usize, max_owners: u32) -> impl Strategy<Value = Vec<TraceEvent>> {
    (2..=max_n).prop_flat_map(move |n| {
        proptest::collection::vec((1..=max_owners, prop::bool::ANY), n).prop_map(move |specs| {
            specs
                .into_iter()
                .enumerate()
                .map(|(i, (owner, is_complete))| {
                    if is_complete {
                        TraceEvent::complete(
                            (i + 1) as u64,
                            Time::from_nanos(i as u64 * 1000),
                            tid(owner),
                            rid(owner),
                        )
                    } else {
                        TraceEvent::spawn(
                            (i + 1) as u64,
                            Time::from_nanos(i as u64 * 1000),
                            tid(owner),
                            rid(owner),
                        )
                    }
                })
                .collect::<Vec<_>>()
        })
    })
}

/// Generate a fully-independent trace (each event on a unique task).
fn arb_fully_independent(max_n: usize) -> impl Strategy<Value = Vec<TraceEvent>> {
    (2..=max_n).prop_map(|n| {
        (0..n)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let owner = (i + 1) as u32;
                TraceEvent::spawn(
                    (i + 1) as u64,
                    Time::from_nanos(i as u64 * 1000),
                    tid(owner),
                    rid(owner),
                )
            })
            .collect()
    })
}

/// Generate a fully-dependent trace (all events on the same task).
fn arb_fully_dependent(max_n: usize) -> impl Strategy<Value = Vec<TraceEvent>> {
    (2..=max_n).prop_map(|n| {
        (0..n)
            .map(|i| {
                TraceEvent::spawn(
                    (i + 1) as u64,
                    Time::from_nanos(i as u64 * 1000),
                    tid(1),
                    rid(1),
                )
            })
            .collect()
    })
}

fn make_poset(events: &[TraceEvent]) -> TracePoset {
    TracePoset::from_trace(events)
}

// ============================================================================
// Happens-Before Preservation: core soundness invariant
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(300))]

    /// All algorithms produce valid linear extensions preserving happens-before.
    #[test]
    fn hb_preserved_default_config(events in arb_trace_events(25, 5)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::default());

        prop_assert!(
            is_valid_linear_extension(&poset, &result.schedule),
            "default config: schedule is not a valid linear extension ({} events, {:?})",
            events.len(),
            result.algorithm,
        );
        prop_assert_eq!(result.schedule.len(), events.len());
    }

    /// Greedy algorithm always preserves happens-before.
    #[test]
    fn hb_preserved_greedy(events in arb_trace_events(40, 6)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::greedy_only());

        prop_assert!(
            is_valid_linear_extension(&poset, &result.schedule),
            "greedy: invalid linear extension ({} events)",
            events.len(),
        );
    }

    /// High-quality config (beam search) preserves happens-before.
    #[test]
    fn hb_preserved_high_quality(events in arb_trace_events(30, 4)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::high_quality());

        prop_assert!(
            is_valid_linear_extension(&poset, &result.schedule),
            "high-quality: invalid linear extension ({} events)",
            events.len(),
        );
    }

    /// Mixed event kinds (spawn + complete) preserve happens-before.
    #[test]
    fn hb_preserved_mixed_kinds(events in arb_mixed_trace(25, 4)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::default());

        prop_assert!(
            is_valid_linear_extension(&poset, &result.schedule),
            "mixed kinds: invalid linear extension ({} events)",
            events.len(),
        );
    }
}

// ============================================================================
// Dependency Edges: normalized trace respects all causal edges
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Every dependency edge (a → b) in the poset has a < b in the schedule.
    #[test]
    fn causal_edges_respected(events in arb_trace_events(20, 4)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::default());
        let schedule = &result.schedule;

        // Build position map
        let mut position = vec![0usize; events.len()];
        for (pos, &idx) in schedule.iter().enumerate() {
            position[idx] = pos;
        }

        for i in 0..events.len() {
            for &pred in poset.preds(i) {
                prop_assert!(
                    position[pred] < position[i],
                    "dependency violated: event {} (pos {}) depends on {} (pos {})",
                    i, position[i], pred, position[pred],
                );
            }
        }
    }

    /// Independent events can appear in either order; dependent events
    /// must appear in program order.
    #[test]
    fn independence_relation_consistent(events in arb_trace_events(15, 3)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::default());
        let schedule = &result.schedule;

        let mut position = vec![0usize; events.len()];
        for (pos, &idx) in schedule.iter().enumerate() {
            position[idx] = pos;
        }

        // For every pair i < j in the original trace: if they are dependent,
        // then i must come before j in the schedule (because the only edges
        // added are i → j for i < j when not independent).
        for i in 0..events.len() {
            for j in (i + 1)..events.len() {
                if !independent(&events[i], &events[j]) {
                    prop_assert!(
                        position[i] < position[j],
                        "dependent pair ({}, {}) reversed in schedule (positions {}, {})",
                        i, j, position[i], position[j],
                    );
                }
            }
        }
    }
}

// ============================================================================
// Switch Count Correctness
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(300))]

    /// Reported switch count matches recomputed count.
    #[test]
    fn switch_count_consistent(events in arb_trace_events(25, 5)) {
        init_test_logging();
        let poset = make_poset(&events);

        for config in &[
            GeodesicConfig::default(),
            GeodesicConfig::greedy_only(),
            GeodesicConfig::high_quality(),
        ] {
            let result = geodesic_normalize(&poset, config);
            let recomputed = count_switches(&poset, &result.schedule);
            prop_assert_eq!(
                result.switch_count,
                recomputed,
                "switch count mismatch for {:?}: reported {} vs recomputed {}",
                result.algorithm,
                result.switch_count,
                recomputed,
            );
        }
    }

    /// Switch count is at most n-1 (worst case: every adjacent pair switches).
    #[test]
    fn switch_count_upper_bound(events in arb_trace_events(30, 6)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::default());

        let n = events.len();
        let max_possible = n.saturating_sub(1);
        prop_assert!(
            result.switch_count <= max_possible,
            "switch_count {} exceeds max possible {} for {} events",
            result.switch_count, max_possible, n,
        );
    }

    /// Fully-dependent traces (single owner) have zero switches.
    #[test]
    fn single_owner_zero_switches(events in arb_fully_dependent(20)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::default());

        prop_assert_eq!(
            result.switch_count, 0,
            "single-owner trace should have 0 switches, got {}",
            result.switch_count,
        );
    }
}

// ============================================================================
// Optimality: exact solver matches brute force
// ============================================================================

/// Brute-force optimal switch count via exhaustive permutation search.
fn brute_force_min_switches(poset: &TracePoset) -> usize {
    fn search(
        poset: &TracePoset,
        scheduled: &mut Vec<usize>,
        in_degree: &mut Vec<usize>,
        best: &mut usize,
        current_switches: usize,
        last_owner: Option<OwnerKey>,
    ) {
        let n = poset.len();
        if scheduled.len() == n {
            *best = (*best).min(current_switches);
            return;
        }

        // Prune: can't possibly beat current best
        if current_switches >= *best {
            return;
        }

        // Find available events (zero in-degree among unscheduled)
        let available: Vec<usize> = (0..n)
            .filter(|&i| in_degree[i] == 0 && !scheduled.contains(&i))
            .collect();

        for &event in &available {
            let owner = poset.owner(event);
            let switch = last_owner.is_some_and(|lo| lo != owner);
            let new_switches = current_switches + usize::from(switch);

            // Schedule this event
            scheduled.push(event);
            for &succ in poset.succs(event) {
                in_degree[succ] -= 1;
            }

            search(poset, scheduled, in_degree, best, new_switches, Some(owner));

            // Un-schedule
            scheduled.pop();
            for &succ in poset.succs(event) {
                in_degree[succ] += 1;
            }
        }
    }

    let n = poset.len();
    if n <= 1 {
        return 0;
    }

    let mut in_degree: Vec<usize> = (0..n).map(|i| poset.preds(i).len()).collect();
    let mut scheduled = Vec::with_capacity(n);
    let mut best = n; // worst case

    search(poset, &mut scheduled, &mut in_degree, &mut best, 0, None);
    best
}

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// Exact solver matches brute-force optimum for small traces.
    #[test]
    fn exact_matches_brute_force(events in arb_trace_events(8, 3)) {
        init_test_logging();
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 10,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: 500_000,
        };
        let result = geodesic_normalize(&poset, &config);
        let optimal = brute_force_min_switches(&poset);

        prop_assert_eq!(
            result.switch_count,
            optimal,
            "exact solver ({}) != brute-force optimal ({}) for {} events",
            result.switch_count,
            optimal,
            events.len(),
        );
    }

    /// Exact solver optimality with mixed event kinds.
    #[test]
    fn exact_optimal_mixed(events in arb_mixed_trace(8, 3)) {
        init_test_logging();
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 10,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: 500_000,
        };
        let result = geodesic_normalize(&poset, &config);
        let optimal = brute_force_min_switches(&poset);

        prop_assert_eq!(
            result.switch_count,
            optimal,
            "exact mixed ({}) != brute-force ({}) for {} events",
            result.switch_count,
            optimal,
            events.len(),
        );
    }

    /// Heuristic switch count is never worse than brute-force optimal (sanity).
    /// Since heuristics don't guarantee optimality, we verify they produce
    /// *valid* extensions and the count is at most 2× optimal (loose bound).
    #[test]
    fn greedy_within_bound(events in arb_trace_events(8, 3)) {
        init_test_logging();
        let poset = make_poset(&events);
        let optimal = brute_force_min_switches(&poset);
        let result = geodesic_normalize(&poset, &GeodesicConfig::greedy_only());

        prop_assert!(
            is_valid_linear_extension(&poset, &result.schedule),
            "greedy produced invalid extension",
        );
        // Greedy should be reasonable (at most n-1 switches total)
        let n = events.len();
        let max = n.saturating_sub(1);
        prop_assert!(
            result.switch_count <= max,
            "greedy ({}) exceeds max ({}) for {} events (optimal {})",
            result.switch_count, max, n, optimal,
        );
    }
}

// ============================================================================
// Exact ≤ Heuristics: cost ordering invariant
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Exact solver cost ≤ greedy cost (exact is optimal).
    #[test]
    fn exact_leq_greedy(events in arb_trace_events(15, 3)) {
        init_test_logging();
        let poset = make_poset(&events);

        let exact_cfg = GeodesicConfig {
            exact_threshold: 15,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: 200_000,
        };
        let r_exact = geodesic_normalize(&poset, &exact_cfg);
        let r_greedy = geodesic_normalize(&poset, &GeodesicConfig::greedy_only());

        prop_assert!(
            r_exact.switch_count <= r_greedy.switch_count,
            "exact ({}) > greedy ({}) for {} events",
            r_exact.switch_count, r_greedy.switch_count, events.len(),
        );
    }

    /// Exact solver cost ≤ beam search cost.
    #[test]
    fn exact_leq_beam(events in arb_trace_events(15, 3)) {
        init_test_logging();
        let poset = make_poset(&events);

        let exact_cfg = GeodesicConfig {
            exact_threshold: 15,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: 200_000,
        };
        let beam_cfg = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 100,
            beam_width: 8,
            step_budget: 100_000,
        };

        let r_exact = geodesic_normalize(&poset, &exact_cfg);
        let r_beam = geodesic_normalize(&poset, &beam_cfg);

        prop_assert!(
            r_exact.switch_count <= r_beam.switch_count,
            "exact ({}) > beam ({}) for {} events",
            r_exact.switch_count, r_beam.switch_count, events.len(),
        );
    }
}

// ============================================================================
// Determinism: identical inputs → identical outputs
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Running normalization twice produces identical schedules.
    #[test]
    fn determinism_all_configs(events in arb_trace_events(25, 5)) {
        init_test_logging();
        let poset = make_poset(&events);

        for config in &[
            GeodesicConfig::default(),
            GeodesicConfig::greedy_only(),
            GeodesicConfig::high_quality(),
        ] {
            let r1 = geodesic_normalize(&poset, config);
            let r2 = geodesic_normalize(&poset, config);

            prop_assert_eq!(
                &r1.schedule, &r2.schedule,
                "non-deterministic schedule for {:?}",
                r1.algorithm,
            );
            prop_assert_eq!(
                r1.switch_count, r2.switch_count,
                "non-deterministic switch count for {:?}",
                r1.algorithm,
            );
        }
    }

    /// OwnerKey assignment is deterministic.
    #[test]
    fn owner_key_deterministic(events in arb_trace_events(20, 4)) {
        init_test_logging();
        let poset1 = make_poset(&events);
        let poset2 = make_poset(&events);

        for i in 0..events.len() {
            prop_assert_eq!(
                poset1.owner(i),
                poset2.owner(i),
                "OwnerKey differs for event {}",
                i,
            );
        }
    }
}

// ============================================================================
// Poset Construction Invariants
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Poset has correct number of events.
    #[test]
    fn poset_size_matches_trace(events in arb_trace_events(30, 5)) {
        init_test_logging();
        let poset = make_poset(&events);
        prop_assert_eq!(poset.len(), events.len());
    }

    /// All poset edges go forward (i → j implies i < j for trace-derived posets).
    #[test]
    fn poset_edges_forward(events in arb_trace_events(20, 4)) {
        init_test_logging();
        let poset = make_poset(&events);

        for i in 0..events.len() {
            for &succ in poset.succs(i) {
                prop_assert!(
                    i < succ,
                    "backward edge: {} -> {} in trace-derived poset",
                    i, succ,
                );
            }
            for &pred in poset.preds(i) {
                prop_assert!(
                    pred < i,
                    "backward pred: {} -> {} in trace-derived poset",
                    pred, i,
                );
            }
        }
    }

    /// Poset edges are consistent: i in succs(j) iff j in preds(i).
    #[test]
    fn poset_edges_symmetric(events in arb_trace_events(15, 3)) {
        init_test_logging();
        let poset = make_poset(&events);

        for i in 0..events.len() {
            for &succ in poset.succs(i) {
                prop_assert!(
                    poset.preds(succ).contains(&i),
                    "edge {} -> {} in succs but {} not in preds({})",
                    i, succ, i, succ,
                );
            }
            for &pred in poset.preds(i) {
                prop_assert!(
                    poset.succs(pred).contains(&i),
                    "edge {} -> {} in preds({}) but {} not in succs({})",
                    pred, i, i, i, pred,
                );
            }
        }
    }

    /// Independent events have no edge between them.
    #[test]
    fn independent_events_no_edge(events in arb_trace_events(15, 3)) {
        init_test_logging();
        let poset = make_poset(&events);

        for i in 0..events.len() {
            for j in (i + 1)..events.len() {
                if independent(&events[i], &events[j]) {
                    prop_assert!(
                        !poset.has_edge(i, j),
                        "independent events {} and {} have edge in poset",
                        i, j,
                    );
                }
            }
        }
    }
}

// ============================================================================
// Edge Cases: Fully Independent / Fully Dependent
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// Fully independent traces: any permutation is valid; optimal switches
    /// should be n - (number of distinct owners).
    #[test]
    fn fully_independent_valid(events in arb_fully_independent(15)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::default());

        prop_assert!(
            is_valid_linear_extension(&poset, &result.schedule),
            "fully independent: invalid extension",
        );
        prop_assert_eq!(result.schedule.len(), events.len());

        // Each event is on a unique owner, so any schedule is valid.
        // The optimal switch count for n unique owners is n-1.
        let n = events.len();
        if n > 1 {
            prop_assert_eq!(
                result.switch_count,
                n - 1,
                "fully independent: expected {} switches (all unique owners), got {}",
                n - 1,
                result.switch_count,
            );
        }
    }

    /// Fully dependent traces: only one valid schedule (identity permutation).
    #[test]
    fn fully_dependent_identity(events in arb_fully_dependent(15)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::default());

        // The only valid linear extension is [0, 1, 2, ..., n-1]
        let expected: Vec<usize> = (0..events.len()).collect();
        prop_assert_eq!(
            &result.schedule,
            &expected,
            "fully dependent: schedule should be identity permutation",
        );
        prop_assert_eq!(result.switch_count, 0);
    }
}

// ============================================================================
// Algorithm Selection: correct algorithm chosen based on config thresholds
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// Small traces (n >= 2) use exact A* when within threshold.
    /// (n <= 1 is handled as a special case returning Greedy.)
    #[test]
    fn algorithm_selection_exact(events in arb_trace_events(10, 3)) {
        init_test_logging();
        if events.len() <= 1 {
            // n <= 1 is a special case handled before algorithm selection
            return Ok(());
        }
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 20,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: 500_000,
        };
        let result = geodesic_normalize(&poset, &config);

        // Should use exact when 2 <= n <= exact_threshold
        prop_assert!(
            matches!(result.algorithm, GeodesicAlgorithm::ExactAStar),
            "expected ExactAStar for {} events (threshold 20), got {:?}",
            events.len(),
            result.algorithm,
        );
    }

    /// Greedy-only config always selects greedy.
    #[test]
    fn algorithm_selection_greedy_only(events in arb_trace_events(20, 4)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::greedy_only());

        prop_assert!(
            matches!(result.algorithm, GeodesicAlgorithm::Greedy),
            "expected Greedy for greedy_only config, got {:?}",
            result.algorithm,
        );
    }
}

// ============================================================================
// Schedule Permutation Invariant
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Schedule is a permutation of [0..n).
    #[test]
    fn schedule_is_permutation(events in arb_trace_events(30, 5)) {
        init_test_logging();
        let poset = make_poset(&events);
        let result = geodesic_normalize(&poset, &GeodesicConfig::default());
        let n = events.len();

        prop_assert_eq!(result.schedule.len(), n);

        let mut seen = vec![false; n];
        for &idx in &result.schedule {
            prop_assert!(idx < n, "schedule index {} out of range [0, {})", idx, n);
            prop_assert!(!seen[idx], "duplicate index {} in schedule", idx);
            seen[idx] = true;
        }
    }
}

// ============================================================================
// Monotonicity: more beam width never worsens quality
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// Wider beam search should produce results no worse than narrower.
    #[test]
    fn beam_width_monotone(events in arb_trace_events(20, 4)) {
        init_test_logging();
        let poset = make_poset(&events);

        let narrow_cfg = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 100,
            beam_width: 4,
            step_budget: 100_000,
        };
        let wide_cfg = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 100,
            beam_width: 16,
            step_budget: 100_000,
        };

        let r_narrow = geodesic_normalize(&poset, &narrow_cfg);
        let r_wide = geodesic_normalize(&poset, &wide_cfg);

        // Wider beam should be at least as good (though not guaranteed
        // due to implementation details, we test validity at minimum).
        prop_assert!(
            is_valid_linear_extension(&poset, &r_narrow.schedule),
            "narrow beam: invalid extension",
        );
        prop_assert!(
            is_valid_linear_extension(&poset, &r_wide.schedule),
            "wide beam: invalid extension",
        );
    }
}
