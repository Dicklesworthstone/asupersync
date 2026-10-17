    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::TraceEvent;
    use crate::trace::event_structure::TracePoset;
    use crate::types::{RegionId, TaskId, Time};

    fn make_poset(events: &[TraceEvent]) -> TracePoset {
        TracePoset::from_trace(events)
    }

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    #[test]
    fn empty_trace() {
        let poset = make_poset(&[]);
        let result = normalize(&poset, &GeodesicConfig::default());
        assert!(result.schedule.is_empty());
        assert_eq!(result.switch_count, 0);
    }

    #[test]
    fn single_event() {
        let events = [TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))];
        let poset = make_poset(&events);
        let result = normalize(&poset, &GeodesicConfig::default());
        assert_eq!(result.schedule, vec![0]);
        assert_eq!(result.switch_count, 0);
    }

    #[test]
    fn independent_same_owner_no_switches() {
        // Two independent events with same owner -> 0 switches
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
        ];
        let poset = make_poset(&events);

        // Note: these are dependent (same task), so only one valid order
        let result = normalize(&poset, &GeodesicConfig::default());
        assert!(is_valid_linear_extension(&poset, &result.schedule));
        assert_eq!(result.switch_count, 0);
    }

    #[test]
    fn independent_different_owners_one_switch() {
        // Two independent events with different owners -> 1 switch
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);
        let result = normalize(&poset, &GeodesicConfig::default());

        assert!(is_valid_linear_extension(&poset, &result.schedule));
        // Two events with different owners always have 1 switch
        assert_eq!(result.switch_count, 1);
    }

    #[test]
    fn greedy_prefers_same_owner() {
        // Events: A1, B1, A2, B2 where A* has owner 1, B* has owner 2
        // A1 -> A2 (dependent), B1 -> B2 (dependent), others independent
        // Optimal: A1, A2, B1, B2 (1 switch) or B1, B2, A1, A2 (1 switch)
        // Bad: A1, B1, A2, B2 (3 switches)
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)), // A1
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)), // B1
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)), // A2
            TraceEvent::complete(4, Time::ZERO, tid(2), rid(2)), // B2
        ];
        let poset = make_poset(&events);
        let result = normalize(&poset, &GeodesicConfig::greedy_only());

        assert!(is_valid_linear_extension(&poset, &result.schedule));
        // Greedy should achieve 1 switch (group by owner)
        assert_eq!(
            result.switch_count, 1,
            "Expected 1 switch, got {}",
            result.switch_count
        );
    }

    #[test]
    fn beam_search_finds_optimal() {
        // Same test case as above but with beam search
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(4, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);
        let result = normalize(&poset, &GeodesicConfig::high_quality());

        assert!(is_valid_linear_extension(&poset, &result.schedule));
        assert_eq!(result.switch_count, 1);
    }

    #[test]
    fn deterministic_results() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(3, Time::ZERO, tid(3), rid(3)),
            TraceEvent::complete(4, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(5, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);

        let r1 = normalize(&poset, &GeodesicConfig::default());
        let r2 = normalize(&poset, &GeodesicConfig::default());

        assert_eq!(r1.schedule, r2.schedule);
        assert_eq!(r1.switch_count, r2.switch_count);
    }

    #[test]
    fn valid_linear_extension_check() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
        ];
        let poset = make_poset(&events);

        // Valid: spawn before poll
        assert!(is_valid_linear_extension(&poset, &[0, 1]));

        // Invalid: poll before spawn (violates dependency)
        assert!(!is_valid_linear_extension(&poset, &[1, 0]));

        // Invalid: wrong length
        assert!(!is_valid_linear_extension(&poset, &[0]));

        // Invalid: duplicate
        assert!(!is_valid_linear_extension(&poset, &[0, 0]));
    }

    #[test]
    fn switch_count_calculation() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(3, Time::ZERO, tid(1), rid(1)),
        ];
        let poset = make_poset(&events);

        // Schedule [0, 2, 1]: owner1, owner1, owner2 -> 1 switch
        // But we need to check if this is valid first
        // Events 0 and 2 are both task 1 events, so they might be dependent

        // Let's just test the counting function
        // [0, 1, 2] if all independent would be: owner1, owner2, owner1 -> 2 switches
        let count = count_switches(&poset, &[0, 1, 2]);
        assert_eq!(count, 2);
    }

    #[test]
    fn fallback_on_budget_exhaustion() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);

        // Very low budget should trigger fallback
        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 1000,
            beam_width: 100,
            step_budget: 1, // Very low budget
        };
        let result = normalize(&poset, &config);

        // Should still produce a valid result
        assert!(is_valid_linear_extension(&poset, &result.schedule));
    }

    #[test]
    fn large_trace_uses_greedy() {
        // Create a trace larger than beam_threshold
        let n: u32 = 150;
        let events: Vec<TraceEvent> = (0..n)
            .map(|i| TraceEvent::spawn(u64::from(i), Time::ZERO, tid(i), rid(i)))
            .collect();
        let poset = make_poset(&events);

        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 100, // Less than n
            beam_width: 8,
            step_budget: 1_000_000,
        };
        let result = normalize(&poset, &config);

        assert_eq!(result.algorithm, GeodesicAlgorithm::Greedy);
        assert!(is_valid_linear_extension(&poset, &result.schedule));
    }

    fn brute_force_min_switches(poset: &TracePoset) -> usize {
        fn dfs(
            poset: &TracePoset,
            indeg: &mut [usize],
            available: &mut Vec<usize>,
            schedule_len: usize,
            current_owner: Option<OwnerKey>,
            switches: usize,
            best: &mut usize,
        ) {
            if switches >= *best {
                return;
            }
            if schedule_len == poset.len() {
                *best = switches;
                return;
            }

            available.sort_unstable();
            let candidates = available.clone();

            for chosen in candidates {
                let owner = poset.owner(chosen);
                let mut next_switches = switches;
                if let Some(prev) = current_owner {
                    if prev != owner {
                        next_switches += 1;
                    }
                }

                // Apply choice
                let idx = available
                    .iter()
                    .position(|&v| v == chosen)
                    .expect("chosen must be available");
                available.remove(idx);

                let mut newly_available = Vec::new();
                for &succ in poset.succs(chosen) {
                    indeg[succ] -= 1;
                    if indeg[succ] == 0 {
                        newly_available.push(succ);
                    }
                }
                available.extend(newly_available.iter().copied());

                dfs(
                    poset,
                    indeg,
                    available,
                    schedule_len + 1,
                    Some(owner),
                    next_switches,
                    best,
                );

                // Undo choice
                available.retain(|&v| v != chosen);
                available.push(chosen);
                for &succ in poset.succs(chosen) {
                    if indeg[succ] == 0 {
                        if let Some(pos) = available.iter().position(|&v| v == succ) {
                            available.remove(pos);
                        }
                    }
                    indeg[succ] += 1;
                }
            }
        }

        let n = poset.len();
        let mut indeg: Vec<usize> = (0..n).map(|i| poset.preds(i).len()).collect();
        let mut available: Vec<usize> = (0..n).filter(|&i| indeg[i] == 0).collect();
        let mut best = usize::MAX;
        dfs(poset, &mut indeg, &mut available, 0, None, 0, &mut best);
        best
    }

    #[test]
    fn exact_solver_matches_bruteforce_two_chains() {
        let r = rid(1);
        let t1 = tid(1);
        let t2 = tid(2);

        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, t1, r),
            TraceEvent::spawn(2, Time::ZERO, t2, r),
            TraceEvent::schedule(3, Time::ZERO, t1, r),
            TraceEvent::schedule(4, Time::ZERO, t2, r),
            TraceEvent::poll(5, Time::ZERO, t1, r),
            TraceEvent::poll(6, Time::ZERO, t2, r),
            TraceEvent::yield_task(7, Time::ZERO, t1, r),
            TraceEvent::yield_task(8, Time::ZERO, t2, r),
            TraceEvent::complete(9, Time::ZERO, t1, r),
            TraceEvent::complete(10, Time::ZERO, t2, r),
        ];
        let poset = make_poset(&events);

        let config = GeodesicConfig {
            exact_threshold: 10,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: 200_000,
        };
        let result = normalize(&poset, &config);

        assert_eq!(result.algorithm, GeodesicAlgorithm::ExactAStar);
        assert!(is_valid_linear_extension(&poset, &result.schedule));

        let brute = brute_force_min_switches(&poset);
        assert_eq!(result.switch_count, brute);
    }

    // ================================================================
    // bd-28sb acceptance criteria tests
    // ================================================================

    fn foata_flatten_switch_cost(events: &[TraceEvent]) -> usize {
        use crate::trace::canonicalize::canonicalize;
        use crate::trace::event_structure::OwnerKey;
        let foata = canonicalize(events);
        let flat = foata.flatten();
        if flat.len() < 2 {
            return 0;
        }
        flat.windows(2)
            .filter(|w| OwnerKey::for_event(&w[0]) != OwnerKey::for_event(&w[1]))
            .count()
    }

    fn verify_exact_acceptance(events: &[TraceEvent], label: &str) {
        let poset = make_poset(events);
        let n = poset.len();
        if n == 0 {
            return;
        }
        let config = GeodesicConfig {
            exact_threshold: 64,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: 500_000,
        };
        let result = normalize(&poset, &config);
        assert!(
            is_valid_linear_extension(&poset, &result.schedule),
            "{label}: not a valid linear extension"
        );
        let foata_cost = foata_flatten_switch_cost(events);
        assert!(
            result.switch_count <= foata_cost,
            "{label}: exact ({}) > foata ({foata_cost})",
            result.switch_count,
        );
        if n <= 10 {
            let brute = brute_force_min_switches(&poset);
            assert_eq!(
                result.switch_count, brute,
                "{label}: exact ({}) != brute ({brute})",
                result.switch_count,
            );
        }
    }

    #[test]
    fn exact_cost_leq_foata_two_parallel_chains() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::complete(3, Time::ZERO, tid(1), r),
            TraceEvent::complete(4, Time::ZERO, tid(2), r),
        ];
        verify_exact_acceptance(&events, "two_parallel_chains");
    }

    #[test]
    fn exact_cost_leq_foata_three_tasks() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::poll(4, Time::ZERO, tid(1), r),
            TraceEvent::poll(5, Time::ZERO, tid(2), r),
            TraceEvent::poll(6, Time::ZERO, tid(3), r),
            TraceEvent::complete(7, Time::ZERO, tid(1), r),
            TraceEvent::complete(8, Time::ZERO, tid(2), r),
            TraceEvent::complete(9, Time::ZERO, tid(3), r),
        ];
        verify_exact_acceptance(&events, "three_tasks");
    }

    #[test]
    fn exact_cost_leq_foata_diamond() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::complete(4, Time::ZERO, tid(2), r),
            TraceEvent::complete(5, Time::ZERO, tid(3), r),
            TraceEvent::complete(6, Time::ZERO, tid(1), r),
        ];
        verify_exact_acceptance(&events, "diamond");
    }

    #[test]
    fn exact_cost_leq_foata_single_chain() {
        let r = rid(1);
        let t = tid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, t, r),
            TraceEvent::schedule(2, Time::ZERO, t, r),
            TraceEvent::poll(3, Time::ZERO, t, r),
            TraceEvent::yield_task(4, Time::ZERO, t, r),
            TraceEvent::complete(5, Time::ZERO, t, r),
        ];
        verify_exact_acceptance(&events, "single_chain");
    }

    #[test]
    fn exact_cost_leq_foata_star() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::spawn(4, Time::ZERO, tid(4), r),
            TraceEvent::spawn(5, Time::ZERO, tid(5), r),
        ];
        verify_exact_acceptance(&events, "star");
    }

    #[test]
    fn exact_cost_leq_foata_asymmetric() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::poll(3, Time::ZERO, tid(1), r),
            TraceEvent::complete(4, Time::ZERO, tid(2), r),
            TraceEvent::yield_task(5, Time::ZERO, tid(1), r),
            TraceEvent::complete(6, Time::ZERO, tid(1), r),
        ];
        verify_exact_acceptance(&events, "asymmetric");
    }

    #[test]
    fn exact_cost_leq_foata_four_tasks() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::spawn(4, Time::ZERO, tid(4), r),
            TraceEvent::complete(5, Time::ZERO, tid(1), r),
            TraceEvent::complete(6, Time::ZERO, tid(2), r),
            TraceEvent::complete(7, Time::ZERO, tid(3), r),
            TraceEvent::complete(8, Time::ZERO, tid(4), r),
        ];
        verify_exact_acceptance(&events, "four_tasks");
    }

    #[test]
    fn exact_cost_leq_foata_mixed_regions() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(3, Time::ZERO, tid(3), rid(1)),
            TraceEvent::complete(4, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(5, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(6, Time::ZERO, tid(3), rid(1)),
        ];
        verify_exact_acceptance(&events, "mixed_regions");
    }

    #[test]
    fn exhaustive_bruteforce_n2_to_n8() {
        let r = rid(1);
        let shapes: Vec<(&str, Vec<TraceEvent>)> = vec![
            (
                "n2_ind",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), r),
                ],
            ),
            (
                "n2_same",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::poll(2, Time::ZERO, tid(1), r),
                ],
            ),
            (
                "n3_ind",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), r),
                    TraceEvent::spawn(3, Time::ZERO, tid(3), r),
                ],
            ),
            (
                "n4_chain",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::schedule(2, Time::ZERO, tid(1), r),
                    TraceEvent::poll(3, Time::ZERO, tid(1), r),
                    TraceEvent::complete(4, Time::ZERO, tid(1), r),
                ],
            ),
            (
                "n6_2chains",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), r),
                    TraceEvent::schedule(3, Time::ZERO, tid(1), r),
                    TraceEvent::schedule(4, Time::ZERO, tid(2), r),
                    TraceEvent::complete(5, Time::ZERO, tid(1), r),
                    TraceEvent::complete(6, Time::ZERO, tid(2), r),
                ],
            ),
            (
                "n8_4chains",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), r),
                    TraceEvent::spawn(3, Time::ZERO, tid(3), r),
                    TraceEvent::spawn(4, Time::ZERO, tid(4), r),
                    TraceEvent::complete(5, Time::ZERO, tid(1), r),
                    TraceEvent::complete(6, Time::ZERO, tid(2), r),
                    TraceEvent::complete(7, Time::ZERO, tid(3), r),
                    TraceEvent::complete(8, Time::ZERO, tid(4), r),
                ],
            ),
            (
                "n7_asym",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), r),
                    TraceEvent::schedule(3, Time::ZERO, tid(1), r),
                    TraceEvent::poll(4, Time::ZERO, tid(1), r),
                    TraceEvent::yield_task(5, Time::ZERO, tid(1), r),
                    TraceEvent::complete(6, Time::ZERO, tid(1), r),
                    TraceEvent::complete(7, Time::ZERO, tid(2), r),
                ],
            ),
            (
                "n5_ind_multiregion",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
                    TraceEvent::spawn(3, Time::ZERO, tid(3), rid(3)),
                    TraceEvent::spawn(4, Time::ZERO, tid(4), rid(4)),
                    TraceEvent::spawn(5, Time::ZERO, tid(5), rid(5)),
                ],
            ),
        ];
        for (label, events) in &shapes {
            verify_exact_acceptance(events, label);
        }
    }

    #[test]
    fn exact_deterministic_across_runs() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::poll(4, Time::ZERO, tid(1), r),
            TraceEvent::poll(5, Time::ZERO, tid(2), r),
            TraceEvent::complete(6, Time::ZERO, tid(1), r),
            TraceEvent::complete(7, Time::ZERO, tid(2), r),
            TraceEvent::complete(8, Time::ZERO, tid(3), r),
        ];
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 64,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: 500_000,
        };
        let first = normalize(&poset, &config);
        for i in 1..10 {
            let run = normalize(&poset, &config);
            assert_eq!(first.schedule, run.schedule, "Run {i} differs");
            assert_eq!(first.switch_count, run.switch_count, "Run {i} cost differs");
        }
    }

    #[test]
    fn heuristic_admissibility() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::complete(4, Time::ZERO, tid(1), r),
            TraceEvent::complete(5, Time::ZERO, tid(2), r),
            TraceEvent::complete(6, Time::ZERO, tid(3), r),
        ];
        let poset = make_poset(&events);
        let brute_optimal = brute_force_min_switches(&poset);
        let h_start = owner_switch_lower_bound(&poset, 0, None);
        assert!(
            h_start <= brute_optimal,
            "h({h_start}) > optimal({brute_optimal}): inadmissible"
        );
    }

    // ========================================================================
    // bd-3dre: Property tests (soundness, equivalence, determinism)
    // ========================================================================

    use proptest::prelude::*;

    /// Strategy: generate a small trace with n events across k owners.
    /// Events with the same owner form dependency chains (same task id →
    /// sequential via `from_trace`). Events with different owners are
    /// independent.
    fn arb_trace(max_n: usize, max_owners: u32) -> impl Strategy<Value = Vec<TraceEvent>> {
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

    fn preserves_happens_before(poset: &TracePoset, schedule: &[usize]) -> bool {
        let n = poset.len();
        if schedule.len() != n {
            return false;
        }

        let mut seen = vec![false; n];
        let mut position = vec![0usize; n];
        for (pos, &idx) in schedule.iter().enumerate() {
            if idx >= n || seen[idx] {
                return false;
            }
            seen[idx] = true;
            position[idx] = pos;
        }

        for i in 0..n {
            for &pred in poset.preds(i) {
                if position[pred] >= position[i] {
                    return false;
                }
            }
        }

        true
    }

    // ========================================================================
    // Decision ledger tests
    // ========================================================================

    #[cfg(feature = "test-internals")]
    #[test]
    fn ledger_exact_has_algorithm_selected() {
        let events = [
            TraceEvent::spawn(1, Time::from_nanos(0), tid(1), rid(1)),
            TraceEvent::spawn(2, Time::from_nanos(1000), tid(2), rid(2)),
            TraceEvent::spawn(3, Time::from_nanos(2000), tid(1), rid(1)),
        ];
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 10,
            beam_threshold: 0,
            beam_width: 0,
            step_budget: 100_000,
        };
        let ledger = normalize_with_ledger(&poset, &config);

        // Must have at least one AlgorithmSelected entry
        let has_algo = ledger.entries.iter().any(|e| {
            matches!(
                e,
                DecisionEntry::AlgorithmSelected {
                    algorithm: GeodesicAlgorithm::ExactAStar,
                    ..
                }
            )
        });
        assert!(has_algo, "ledger missing AlgorithmSelected for exact");
        assert_eq!(ledger.result.schedule.len(), 3);
        assert!(is_valid_linear_extension(&poset, &ledger.result.schedule));
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn ledger_greedy_records_choices() {
        let events: Vec<TraceEvent> = (0u32..10)
            .map(|i| {
                TraceEvent::spawn(
                    u64::from(i + 1),
                    Time::from_nanos(u64::from(i) * 1000),
                    tid(i % 3),
                    rid(i % 3),
                )
            })
            .collect();
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 0,
            beam_width: 0,
            step_budget: 100_000,
        };
        let ledger = normalize_with_ledger(&poset, &config);

        // Must have greedy choice entries
        let greedy_count = ledger
            .entries
            .iter()
            .filter(|e| matches!(e, DecisionEntry::GreedyChoice { .. }))
            .count();
        assert_eq!(greedy_count, 10, "one greedy choice per event");

        // Result must match normalize()
        let plain = normalize(&poset, &config);
        assert_eq!(ledger.result.schedule, plain.schedule);
        assert_eq!(ledger.result.switch_count, plain.switch_count);
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn ledger_beam_records_prunes() {
        let events: Vec<TraceEvent> = (0u32..15)
            .map(|i| {
                TraceEvent::spawn(
                    u64::from(i + 1),
                    Time::from_nanos(u64::from(i) * 1000),
                    tid(i % 4),
                    rid(i % 4),
                )
            })
            .collect();
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 100,
            beam_width: 4,
            step_budget: 100_000,
        };
        let ledger = normalize_with_ledger(&poset, &config);

        // Must have beam prune entries
        let prune_count = ledger
            .entries
            .iter()
            .filter(|e| matches!(e, DecisionEntry::BeamPrune { .. }))
            .count();
        assert!(prune_count > 0, "beam search should produce prune entries");
        assert!(is_valid_linear_extension(&poset, &ledger.result.schedule));
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn ledger_deterministic() {
        let events: Vec<TraceEvent> = (0u32..12)
            .map(|i| {
                TraceEvent::spawn(
                    u64::from(i + 1),
                    Time::from_nanos(u64::from(i) * 1000),
                    tid(i % 3),
                    rid(i % 3),
                )
            })
            .collect();
        let poset = make_poset(&events);
        let config = GeodesicConfig::default();

        let ledger1 = normalize_with_ledger(&poset, &config);
        let ledger2 = normalize_with_ledger(&poset, &config);

        assert_eq!(ledger1.result.schedule, ledger2.result.schedule);
        assert_eq!(ledger1.result.switch_count, ledger2.result.switch_count);
        assert_eq!(ledger1.entries.len(), ledger2.entries.len());
        assert_eq!(ledger1.summary(), ledger2.summary());
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn ledger_summary_is_readable() {
        let events = [
            TraceEvent::spawn(1, Time::from_nanos(0), tid(1), rid(1)),
            TraceEvent::spawn(2, Time::from_nanos(1000), tid(2), rid(2)),
            TraceEvent::spawn(3, Time::from_nanos(2000), tid(1), rid(1)),
            TraceEvent::spawn(4, Time::from_nanos(3000), tid(2), rid(2)),
        ];
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 10,
            beam_threshold: 0,
            beam_width: 0,
            step_budget: 100_000,
        };
        let ledger = normalize_with_ledger(&poset, &config);
        let summary = ledger.summary();

        // Summary must contain key information
        assert!(
            summary.contains("algorithm="),
            "summary missing algorithm info"
        );
        assert!(
            summary.contains("switches="),
            "summary missing switch count"
        );
        assert!(!summary.is_empty());
    }

    proptest! {
        /// Soundness: exact solver always produces a valid linear extension.
        #[test]
        fn prop_soundness_exact(events in arb_trace(15, 4)) {
            let poset = make_poset(&events);
            let config = GeodesicConfig {
                exact_threshold: 15,
                beam_threshold: 0,
                beam_width: 1,
                step_budget: 200_000,
            };
            let result = normalize(&poset, &config);
            prop_assert!(
                is_valid_linear_extension(&poset, &result.schedule),
                "Exact solver produced invalid linear extension for {} events",
                events.len()
            );
            prop_assert_eq!(
                count_switches(&poset, &result.schedule),
                result.switch_count,
            );
        }

        /// Soundness: greedy solver always produces a valid linear extension.
        #[test]
        fn prop_soundness_greedy(events in arb_trace(30, 5)) {
            let poset = make_poset(&events);
            let result = normalize(&poset, &GeodesicConfig::greedy_only());
            prop_assert!(
                is_valid_linear_extension(&poset, &result.schedule),
                "Greedy produced invalid linear extension for {} events",
                events.len()
            );
            prop_assert_eq!(
                count_switches(&poset, &result.schedule),
                result.switch_count,
            );
        }

        /// Soundness: beam search always produces a valid linear extension.
        #[test]
        fn prop_soundness_beam(events in arb_trace(20, 4)) {
            let poset = make_poset(&events);
            let config = GeodesicConfig {
                exact_threshold: 0,
                beam_threshold: 100,
                beam_width: 8,
                step_budget: 100_000,
            };
            let result = normalize(&poset, &config);
            prop_assert!(
                is_valid_linear_extension(&poset, &result.schedule),
                "Beam search produced invalid linear extension for {} events",
                events.len()
            );
        }

        /// Determinism: same input always produces identical output across
        /// all algorithm tiers.
        #[test]
        fn prop_determinism(events in arb_trace(20, 4)) {
            let poset = make_poset(&events);
            for config in &[
                GeodesicConfig::default(),
                GeodesicConfig::greedy_only(),
                GeodesicConfig::high_quality(),
            ] {
                let r1 = normalize(&poset, config);
                let r2 = normalize(&poset, config);
                prop_assert_eq!(&r1.schedule, &r2.schedule);
                prop_assert_eq!(r1.switch_count, r2.switch_count);
            }
        }

        /// Happens-before preservation: normalized schedules always respect dependencies.
        #[test]
        fn prop_happens_before_preserved(events in arb_trace(25, 5)) {
            let poset = make_poset(&events);
            for config in &[
                GeodesicConfig::default(),
                GeodesicConfig::greedy_only(),
                GeodesicConfig::high_quality(),
            ] {
                let result = normalize(&poset, config);
                prop_assert!(
                    preserves_happens_before(&poset, &result.schedule),
                    "schedule violates happens-before for {} events",
                    events.len()
                );
            }
        }

        /// Equivalence: all algorithms produce schedules that are valid
        /// linear extensions of the same poset, and the exact solver
        /// (optimal) never has higher cost than heuristics.
        #[test]
        fn prop_equivalence_across_algorithms(events in arb_trace(15, 3)) {
            let poset = make_poset(&events);

            let exact_cfg = GeodesicConfig {
                exact_threshold: 15, beam_threshold: 0,
                beam_width: 1, step_budget: 200_000,
            };
            let greedy_cfg = GeodesicConfig::greedy_only();
            let beam_cfg = GeodesicConfig {
                exact_threshold: 0, beam_threshold: 100,
                beam_width: 8, step_budget: 100_000,
            };

            let r_exact = normalize(&poset, &exact_cfg);
            let r_greedy = normalize(&poset, &greedy_cfg);
            let r_beam = normalize(&poset, &beam_cfg);

            // All must be valid linear extensions
            prop_assert!(is_valid_linear_extension(&poset, &r_exact.schedule));
            prop_assert!(is_valid_linear_extension(&poset, &r_greedy.schedule));
            prop_assert!(is_valid_linear_extension(&poset, &r_beam.schedule));

            // All must include every event exactly once
            prop_assert_eq!(r_exact.schedule.len(), events.len());
            prop_assert_eq!(r_greedy.schedule.len(), events.len());
            prop_assert_eq!(r_beam.schedule.len(), events.len());

            // Exact solver is optimal: cost <= all heuristics
            prop_assert!(
                r_exact.switch_count <= r_greedy.switch_count,
                "exact {} > greedy {}", r_exact.switch_count, r_greedy.switch_count,
            );
            prop_assert!(
                r_exact.switch_count <= r_beam.switch_count,
                "exact {} > beam {}", r_exact.switch_count, r_beam.switch_count,
            );
        }

        /// Optimality: for tiny traces, exact solver matches brute force.
        #[test]
        fn prop_optimality_small(events in arb_trace(8, 3)) {
            let poset = make_poset(&events);
            let config = GeodesicConfig {
                exact_threshold: 10,
                beam_threshold: 0,
                beam_width: 1,
                step_budget: 500_000,
            };
            let result = normalize(&poset, &config);
            let brute = brute_force_min_switches(&poset);
            prop_assert_eq!(
                result.switch_count, brute,
                "exact {} != brute {} for {} events",
                result.switch_count, brute, events.len(),
            );
        }

        /// Default normalization is optimal for small traces (exact solver path).
        #[test]
        fn prop_default_min_switches_small(events in arb_trace(8, 3)) {
            let poset = make_poset(&events);
            let result = normalize(&poset, &GeodesicConfig::default());
            let brute = brute_force_min_switches(&poset);
            prop_assert_eq!(
                result.switch_count, brute,
                "default {} != brute {} for {} events",
                result.switch_count, brute, events.len(),
            );
        }

        /// Regression: geodesic cost is never worse than Foata-flatten cost.
        #[test]
        fn prop_geodesic_leq_foata(events in arb_trace(15, 4)) {
            let poset = make_poset(&events);
            let config = GeodesicConfig {
                exact_threshold: 15,
                beam_threshold: 0,
                beam_width: 1,
                step_budget: 200_000,
            };
            let result = normalize(&poset, &config);
            let foata_cost = foata_flatten_switch_cost(&events);
            prop_assert!(
                result.switch_count <= foata_cost,
                "geodesic {} > foata {} for {} events",
                result.switch_count, foata_cost, events.len(),
            );
        }
    }

    // =========================================================================
    // Additional decision ledger tests
    // =========================================================================

    #[cfg(feature = "test-internals")]
    #[test]
    fn ledger_empty_trace() {
        let poset = make_poset(&[]);
        let ledger = normalize_with_ledger(&poset, &GeodesicConfig::default());
        assert!(ledger.entries.is_empty());
        assert_eq!(ledger.result.switch_count, 0);
        assert!(ledger.result.schedule.is_empty());
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn ledger_single_event() {
        let events = [TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))];
        let poset = make_poset(&events);
        let ledger = normalize_with_ledger(&poset, &GeodesicConfig::default());
        assert!(ledger.entries.is_empty());
        assert_eq!(ledger.result.schedule, vec![0]);
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn ledger_greedy_shows_owner_match() {
        // Chain of same-owner events followed by different owner
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(4, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);
        let ledger = normalize_with_ledger(&poset, &GeodesicConfig::greedy_only());

        let greedy_choices: Vec<_> = ledger
            .entries
            .iter()
            .filter_map(|e| {
                if let DecisionEntry::GreedyChoice { owner_match, .. } = e {
                    Some(*owner_match)
                } else {
                    None
                }
            })
            .collect();

        // First step has no previous owner
        assert!(!greedy_choices[0], "first step has no previous owner");
        // Middle steps are same-owner continuations
        for &m in &greedy_choices[1..greedy_choices.len() - 1] {
            assert!(m, "continuation of same owner should match");
        }
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn ledger_result_matches_normalize() {
        // Ledger result must match plain normalize for all config presets
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(4, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);

        for config in &[
            GeodesicConfig::default(),
            GeodesicConfig::greedy_only(),
            GeodesicConfig::high_quality(),
        ] {
            let plain = normalize(&poset, config);
            let ledger = normalize_with_ledger(&poset, config);
            assert_eq!(plain.schedule, ledger.result.schedule);
            assert_eq!(plain.switch_count, ledger.result.switch_count);
        }
    }
