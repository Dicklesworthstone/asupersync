    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::{CancelReason, RegionId, TaskId, Time};

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    #[test]
    fn no_races_in_independent_trace() {
        // Two independent spawns: no races.
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];
        let analysis = detect_races(&events);
        assert!(analysis.is_race_free());
        assert_eq!(estimated_classes(&events), 1);
    }

    #[test]
    fn race_between_dependent_events() {
        // Two events on the same task: they're dependent and adjacent.
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let analysis = detect_races(&events);
        assert_eq!(analysis.race_count(), 1);
        assert_eq!(analysis.races[0].earlier, 0);
        assert_eq!(analysis.races[0].later, 1);
    }

    #[test]
    fn no_race_with_transitive_dependency() {
        // A -> B -> C: A and C are dependent but B intervenes.
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
        ];
        let analysis = detect_races(&events);
        // Races: (0,1) and (1,2) are immediate.
        // (0,2) has intervening event 1 that depends on both -> NOT a race.
        assert_eq!(analysis.race_count(), 2);
        // Verify (0,2) is not in the races list.
        assert!(
            !analysis
                .races
                .iter()
                .any(|r| r.earlier == 0 && r.later == 2)
        );
    }

    #[test]
    fn races_in_concurrent_task_region_interaction() {
        // Region create writes R1; spawn in R1 reads R1 -> dependent.
        // Two such spawns in R1: no direct dependency between spawns.
        let events = [
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
        ];
        let analysis = detect_races(&events);
        // (0,1): dependent (write R1 vs read R1), no intervening -> race
        // (0,2): dependent (write R1 vs read R1), but (1) also depends on (0)
        //        AND (1) is independent of (2) (different tasks, same region read)
        //        So no intervening event depends on BOTH (0) and (2) -> race
        // (1,2): independent (different tasks, both only read R1) -> no race
        let race_pairs: Vec<(usize, usize)> = analysis
            .races
            .iter()
            .map(|r| (r.earlier, r.later))
            .collect();
        assert!(race_pairs.contains(&(0, 1)));
        assert!(race_pairs.contains(&(0, 2)));
        assert!(!race_pairs.contains(&(1, 2)));
    }

    #[test]
    fn racing_events_deduplicates() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let indices = racing_events(&events);
        assert_eq!(indices, vec![0, 1]);
    }

    #[test]
    fn empty_trace_no_races() {
        let analysis = detect_races(&[]);
        assert!(analysis.is_race_free());
    }

    #[test]
    fn estimated_classes_respects_a_complete_region_spawn_model() {
        use crate::trace::canonicalize::TraceMonoid;

        // Enumerate every order of Create(R), Spawn(A, R), Spawn(B, R).
        // The model admits a spawn only after its region exists. Its two legal
        // executions differ only by independent spawns, so there is one class.
        let permutations = [
            [0_u32, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        let mut legal_orders = 0;
        let mut classes: Vec<TraceMonoid> = Vec::new();
        let mut bounds = Vec::new();
        for order in permutations {
            let mut region_exists = false;
            let mut events = Vec::new();
            for (index, operation) in order.into_iter().enumerate() {
                if operation != 0 && !region_exists {
                    events.clear();
                    break;
                }
                let seq = u64::try_from(index).unwrap() + 1;
                let event = if operation == 0 {
                    region_exists = true;
                    TraceEvent::region_created(seq, Time::ZERO, rid(1), None)
                } else {
                    TraceEvent::spawn(seq, Time::ZERO, tid(operation), rid(1))
                };
                events.push(event);
            }
            if events.is_empty() {
                continue;
            }
            legal_orders += 1;
            assert_eq!(events.len(), 3);
            assert!(!detect_races(&events).is_race_free());
            assert!(crate::trace::independence::independent(
                &events[1], &events[2],
            ));
            let class = TraceMonoid::from_events(&events);
            if !classes.iter().any(|known| known.equivalent_exact(&class)) {
                classes.push(class);
            }
            bounds.push(estimated_classes(&events));
        }
        assert_eq!(legal_orders, 2);
        assert_eq!(classes.len(), 1);
        assert!(bounds.into_iter().all(|bound| bound <= classes.len()));
    }

    #[test]
    fn race_candidates_do_not_certify_alternative_executions() {
        let events = [
            TraceEvent::cancel_request(
                1,
                Time::ZERO,
                tid(1),
                rid(1),
                CancelReason::user("first"),
            ),
            TraceEvent::cancel_request(
                2,
                Time::ZERO,
                tid(2),
                rid(1),
                CancelReason::user("second"),
            ),
        ];
        assert_eq!(detect_races(&events).race_count(), 1);
        assert_eq!(detect_hb_races(&events).race_count(), 1);
        assert_eq!(estimated_classes(&events), 1);
    }

    #[test]
    fn estimated_classes_fail_closed_for_same_task_sequence() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        assert_eq!(detect_races(&events).race_count(), 1);
        assert_eq!(estimated_classes(&events), 1);
    }

    #[test]
    fn backtrack_points_correspond_to_races() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let analysis = detect_races(&events);
        assert_eq!(analysis.backtrack_points.len(), analysis.race_count());
        assert_eq!(analysis.backtrack_points[0].divergence_index, 0);
    }

    #[test]
    fn hb_race_detector_ignores_same_task() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let hb = HappensBeforeGraph::from_trace(&events);
        assert!(hb.happens_before(0, 1));
        assert!(!hb.happens_before(1, 0));
        assert!(!hb.happens_before(0, 2));

        let report = detect_hb_races(&events);
        assert!(report.is_race_free());
    }

    #[test]
    fn hb_race_detector_detects_region_conflict() {
        let reason = CancelReason::user("test");
        let events = [
            TraceEvent::cancel_request(1, Time::ZERO, tid(1), rid(1), reason.clone()),
            TraceEvent::cancel_request(2, Time::ZERO, tid(2), rid(1), reason),
        ];
        let report = detect_hb_races(&events);
        assert_eq!(report.race_count(), 1);
        assert_eq!(
            report.races[0].kind,
            RaceKind::Resource(Resource::Region(rid(1)))
        );
    }

    #[test]
    fn hb_race_detector_skips_non_task_events() {
        let events = [
            TraceEvent::timer_scheduled(1, Time::ZERO, 7, Time::from_nanos(10)),
            TraceEvent::timer_fired(2, Time::from_nanos(10), 7),
        ];
        let report = detect_hb_races(&events);
        assert!(report.is_race_free());
    }

    #[test]
    fn trace_coverage_analysis_empty() {
        let analysis = trace_coverage_analysis(&[]);
        assert_eq!(analysis.event_count, 0);
        assert_eq!(analysis.immediate_race_count, 0);
        assert_eq!(analysis.hb_race_count, 0);
        assert_eq!(analysis.estimated_classes, 1);
        assert_eq!(analysis.racing_event_count, 0);
        assert!((analysis.race_density - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn trace_coverage_analysis_concurrent_tasks() {
        let events = [
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
        ];
        let analysis = trace_coverage_analysis(&events);
        assert_eq!(analysis.event_count, 3);
        assert!(analysis.immediate_race_count >= 1);
        assert_eq!(analysis.estimated_classes, 1);
        assert!(analysis.racing_event_count >= 1);
        assert!(analysis.race_density > 0.0);
    }

    #[test]
    fn resource_race_distribution_from_hb() {
        let reason = CancelReason::user("test");
        let events = [
            TraceEvent::cancel_request(1, Time::ZERO, tid(1), rid(1), reason.clone()),
            TraceEvent::cancel_request(2, Time::ZERO, tid(2), rid(1), reason),
        ];
        let report = detect_hb_races(&events);
        let dist = ResourceRaceDistribution::from_report(&report);
        assert_eq!(dist.total(), 1);
        assert_eq!(dist.resource_count(), 1);
    }

    #[test]
    fn sleep_set_deduplication() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let bp = BacktrackPoint {
            race: Race {
                earlier: 0,
                later: 1,
            },
            divergence_index: 0,
        };
        let mut sleep = SleepSet::new();
        assert!(!sleep.contains(&bp, &events));
        sleep.insert(&bp, &events);
        assert!(sleep.contains(&bp, &events));
        assert_eq!(sleep.len(), 1);
    }

    #[test]
    fn sleep_set_distinguishes_same_shape_races_on_different_tasks() {
        let left_events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let right_events = [
            TraceEvent::spawn(1, Time::ZERO, tid(2), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(2), rid(1)),
        ];
        let bp = BacktrackPoint {
            race: Race {
                earlier: 0,
                later: 1,
            },
            divergence_index: 0,
        };

        let mut sleep = SleepSet::new();
        sleep.insert(&bp, &left_events);

        assert!(
            !sleep.contains(&bp, &right_events),
            "sleep-set key must include semantic endpoint identity, not just kind/index shape"
        );
    }

    #[test]
    fn sleep_set_deduplicates_same_race_when_trace_order_is_reversed() {
        let reason = CancelReason::user("test");
        let left_events = [
            TraceEvent::cancel_request(1, Time::ZERO, tid(1), rid(1), reason.clone()),
            TraceEvent::cancel_request(2, Time::ZERO, tid(2), rid(1), reason.clone()),
        ];
        let right_events = [
            TraceEvent::cancel_request(1, Time::ZERO, tid(2), rid(1), reason.clone()),
            TraceEvent::cancel_request(2, Time::ZERO, tid(1), rid(1), reason),
        ];
        let bp = BacktrackPoint {
            race: Race {
                earlier: 0,
                later: 1,
            },
            divergence_index: 0,
        };

        let mut sleep = SleepSet::new();
        sleep.insert(&bp, &left_events);

        assert!(
            sleep.contains(&bp, &right_events),
            "sleep-set key should treat the same race as explored even when the endpoints swap order"
        );
    }

    #[test]
    fn detected_race_debug_clone_eq() {
        let race = DetectedRace {
            race: Race {
                earlier: 0,
                later: 1,
            },
            kind: RaceKind::Resource(Resource::GlobalClock),
            earlier_task: None,
            later_task: None,
            earlier_kind: TraceEventKind::Spawn,
            later_kind: TraceEventKind::Spawn,
        };
        let cloned = race.clone();
        assert_eq!(race, cloned);
        let dbg = format!("{race:?}");
        assert!(dbg.contains("DetectedRace"));
    }
