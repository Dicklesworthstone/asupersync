    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::replay::{CompactTaskId, TraceMetadata};

    fn meta() -> TraceMetadata {
        TraceMetadata::new(42)
    }

    fn tid(n: u64) -> CompactTaskId {
        CompactTaskId(n)
    }

    fn rid(n: u64) -> CompactRegionId {
        CompactRegionId(n)
    }

    /// Build a simple trace with one root region and two child regions.
    /// Root (region 0) has children region 1 and region 2.
    /// Region 1 has task 1, region 2 has task 2.
    /// The "failure" is caused by task 2 in region 2.
    fn hierarchical_trace() -> ReplayTrace {
        let events = vec![
            // Event 0: seed
            ReplayEvent::RngSeed { seed: 42 },
            // Event 1: root region
            ReplayEvent::RegionCreated {
                region: rid(0),
                parent: None,
                at_tick: 0,
            },
            // Event 2: child region 1
            ReplayEvent::RegionCreated {
                region: rid(1),
                parent: Some(rid(0)),
                at_tick: 1,
            },
            // Event 3: task 1 spawned in region 1
            ReplayEvent::TaskSpawned {
                task: tid(1),
                region: rid(1),
                at_tick: 2,
            },
            // Event 4: task 1 scheduled
            ReplayEvent::TaskScheduled {
                task: tid(1),
                at_tick: 3,
            },
            // Event 5: task 1 completed
            ReplayEvent::TaskCompleted {
                task: tid(1),
                outcome: 0,
            },
            // Event 6: region 1 closed
            ReplayEvent::RegionClosed {
                region: rid(1),
                outcome: 0,
            },
            // Event 7: child region 2
            ReplayEvent::RegionCreated {
                region: rid(2),
                parent: Some(rid(0)),
                at_tick: 4,
            },
            // Event 8: task 2 spawned in region 2
            ReplayEvent::TaskSpawned {
                task: tid(2),
                region: rid(2),
                at_tick: 5,
            },
            // Event 9: task 2 scheduled (CRITICAL)
            ReplayEvent::TaskScheduled {
                task: tid(2),
                at_tick: 6,
            },
            // Event 10: task 2 completed with error (CRITICAL - the failure)
            ReplayEvent::TaskCompleted {
                task: tid(2),
                outcome: 1, // Error
            },
            // Event 11: region 2 closed
            ReplayEvent::RegionClosed {
                region: rid(2),
                outcome: 1,
            },
            // Event 12: root region closed
            ReplayEvent::RegionClosed {
                region: rid(0),
                outcome: 1,
            },
        ];

        ReplayTrace {
            metadata: meta(),
            events,
            cursor: 0,
        }
    }

    /// Oracle: failure is reproduced if any TaskCompleted with outcome=1 is present.
    fn error_oracle(trace: &ReplayTrace) -> bool {
        trace
            .events
            .iter()
            .any(|e| matches!(e, ReplayEvent::TaskCompleted { outcome: 1, .. }))
    }

    #[test]
    fn build_tree_from_hierarchical_trace() {
        let trace = hierarchical_trace();
        let (tree, roots) = build_region_tree(&trace.events);

        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], rkey(rid(0)));

        let root = tree.get(&rkey(rid(0))).unwrap();
        assert_eq!(root.children.len(), 2);

        // Region 1 and 2 should be children of root.
        let children_set: BTreeSet<RegionKey> = root.children.iter().copied().collect();
        assert!(children_set.contains(&rkey(rid(1))));
        assert!(children_set.contains(&rkey(rid(2))));
    }

    #[test]
    fn top_down_prunes_irrelevant_region() {
        let trace = hierarchical_trace();
        let config = DeltaDebugConfig {
            verify_minimality: false,
            ..Default::default()
        };

        let result = minimize(&trace, &config, error_oracle);

        // Region 1 (task 1) should be pruned since it doesn't affect the failure.
        // Events 2-6 (region 1 lifecycle + task 1) should be removed.
        assert!(
            result.minimized_event_count < trace.events.len(),
            "should have pruned some events: {} >= {}",
            result.minimized_event_count,
            trace.events.len()
        );

        // The minimized trace should still reproduce the failure.
        assert!(error_oracle(&result.minimized));
    }

    #[test]
    fn minimality_verification_works() {
        let trace = hierarchical_trace();
        let config = DeltaDebugConfig {
            verify_minimality: true,
            ..Default::default()
        };

        let result = minimize(&trace, &config, error_oracle);

        // After minimality verification, every remaining event should be necessary.
        // The absolute minimum is just the failing TaskCompleted event.
        assert!(result.minimized_event_count >= 1);
        assert!(error_oracle(&result.minimized));
    }

    #[test]
    fn flat_trace_ddmin() {
        // A trace with no region hierarchy — pure ddmin.
        let events: Vec<ReplayEvent> = (0..20)
            .map(|i| ReplayEvent::TaskScheduled {
                task: tid(i),
                at_tick: i,
            })
            .collect();

        let trace = ReplayTrace {
            metadata: meta(),
            events,
            cursor: 0,
        };

        // Failure requires task 7 to be scheduled.
        let oracle = |t: &ReplayTrace| -> bool {
            t.events.iter().any(|e| {
                matches!(
                    e,
                    ReplayEvent::TaskScheduled { task, .. } if task.0 == 7
                )
            })
        };

        let config = DeltaDebugConfig {
            hierarchical: false,
            verify_minimality: true,
            ..Default::default()
        };

        let result = minimize(&trace, &config, oracle);

        // Should find that only the task-7 event is necessary.
        assert_eq!(result.minimized_event_count, 1);
        assert!(oracle(&result.minimized));
    }

    #[test]
    fn empty_trace_panics() {
        let trace = ReplayTrace::new(meta());
        let result = std::panic::catch_unwind(|| {
            minimize(&trace, &DeltaDebugConfig::default(), |_| true);
        });
        assert!(result.is_err());
    }

    #[test]
    fn oracle_must_accept_full_trace() {
        let trace = ReplayTrace {
            metadata: meta(),
            events: vec![ReplayEvent::RngSeed { seed: 1 }],
            cursor: 0,
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            minimize(&trace, &DeltaDebugConfig::default(), |_| false);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn budget_limits_oracle_calls() {
        let events: Vec<ReplayEvent> = (0..100)
            .map(|i| ReplayEvent::TaskScheduled {
                task: tid(i),
                at_tick: i,
            })
            .collect();

        let trace = ReplayTrace {
            metadata: meta(),
            events,
            cursor: 0,
        };

        let config = DeltaDebugConfig {
            max_evaluations: 5,
            hierarchical: false,
            verify_minimality: false,
            ..Default::default()
        };

        // Always-true oracle: every subset "reproduces".
        let result = minimize(&trace, &config, |_| true);
        assert!(result.stats.oracle_calls <= 5);
        assert!(result.stats.budget_exhausted);
    }

    #[test]
    fn reduction_ratio_correct() {
        let trace = hierarchical_trace();
        let config = DeltaDebugConfig::default();
        let result = minimize(&trace, &config, error_oracle);

        #[allow(clippy::cast_precision_loss)]
        let expected_ratio =
            1.0 - (result.minimized_event_count as f64 / trace.events.len() as f64);
        assert!((result.reduction_ratio - expected_ratio).abs() < 0.001);
    }

    #[test]
    fn narrative_generation() {
        let trace = hierarchical_trace();
        let config = DeltaDebugConfig::default();
        let result = minimize(&trace, &config, error_oracle);
        let narrative = generate_narrative(&trace, &result);

        assert!(narrative.contains("Trace Minimization Report"));
        assert!(narrative.contains("Critical Events"));
        assert!(narrative.contains("Oracle evaluations"));
    }

    #[test]
    fn multiple_critical_events() {
        // Failure requires BOTH task 3 and task 7.
        let events: Vec<ReplayEvent> = (0..15)
            .map(|i| ReplayEvent::TaskScheduled {
                task: tid(i),
                at_tick: i,
            })
            .collect();

        let trace = ReplayTrace {
            metadata: meta(),
            events,
            cursor: 0,
        };

        let oracle = |t: &ReplayTrace| -> bool {
            let has_3 = t
                .events
                .iter()
                .any(|e| matches!(e, ReplayEvent::TaskScheduled { task, .. } if task.0 == 3));
            let has_7 = t
                .events
                .iter()
                .any(|e| matches!(e, ReplayEvent::TaskScheduled { task, .. } if task.0 == 7));
            has_3 && has_7
        };

        let config = DeltaDebugConfig {
            hierarchical: false,
            verify_minimality: true,
            ..Default::default()
        };

        let result = minimize(&trace, &config, oracle);

        // Should find exactly 2 critical events.
        assert_eq!(result.minimized_event_count, 2);
        assert!(oracle(&result.minimized));
    }

    #[test]
    fn minimality_verification_revisits_earlier_events_after_later_removal() {
        let events: Vec<ReplayEvent> = (0..3)
            .map(|i| ReplayEvent::TaskScheduled {
                task: tid(i),
                at_tick: i,
            })
            .collect();

        let metadata = meta();
        let mut oracle = |t: &ReplayTrace| -> bool {
            let scheduled: BTreeSet<u64> = t
                .events
                .iter()
                .filter_map(|event| match event {
                    ReplayEvent::TaskScheduled { task, .. } => Some(task.0),
                    _ => None,
                })
                .collect();

            scheduled == BTreeSet::from([0, 1, 2])
                || scheduled == BTreeSet::from([0, 2])
                || scheduled == BTreeSet::from([2])
        };

        let keep = BTreeSet::from([0, 1, 2]);
        let mut stats = MinimizationStats::default();
        let config = DeltaDebugConfig::default();

        let (result, verified) =
            verify_minimality_pass(&events, &metadata, &keep, &mut oracle, &mut stats, &config);

        assert_eq!(result, BTreeSet::from([2]));
        assert_eq!(stats.events_pruned_minimality, 2);
        assert!(verified);
    }

    #[test]
    fn deterministic_minimization() {
        let trace = hierarchical_trace();
        let config = DeltaDebugConfig::default();

        let result1 = minimize(&trace, &config, error_oracle);
        let result2 = minimize(&trace, &config, error_oracle);

        assert_eq!(result1.minimized_event_count, result2.minimized_event_count);
        assert_eq!(result1.critical_indices, result2.critical_indices);
    }

    #[test]
    fn display_impl() {
        let trace = hierarchical_trace();
        let config = DeltaDebugConfig::default();
        let result = minimize(&trace, &config, error_oracle);
        let display = format!("{result}");
        assert!(display.contains("DeltaDebug:"));
        assert!(display.contains("reduction"));
    }

    // =========================================================================
    // Wave 26: Data-type trait coverage
    // =========================================================================

    #[test]
    fn delta_debug_config_debug() {
        let config = DeltaDebugConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("DeltaDebugConfig"));
        assert!(dbg.contains("max_evaluations"));
        assert!(dbg.contains("verify_minimality"));
        assert!(dbg.contains("hierarchical"));
    }

    #[test]
    fn delta_debug_config_clone() {
        let config = DeltaDebugConfig {
            max_evaluations: 42,
            verify_minimality: false,
            hierarchical: false,
            initial_chunk_size: 8,
        };
        let config2 = config;
        assert_eq!(config2.max_evaluations, 42);
        assert!(!config2.verify_minimality);
        assert!(!config2.hierarchical);
        assert_eq!(config2.initial_chunk_size, 8);
    }

    #[test]
    fn delta_debug_config_default_fields() {
        let config = DeltaDebugConfig::default();
        assert_eq!(config.max_evaluations, 0);
        assert!(config.verify_minimality);
        assert!(config.hierarchical);
        assert_eq!(config.initial_chunk_size, 0);
    }

    #[test]
    fn minimization_stats_debug() {
        let stats = MinimizationStats::default();
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("MinimizationStats"));
        assert!(dbg.contains("oracle_calls"));
        assert!(dbg.contains("regions_pruned"));
    }

    #[test]
    fn minimization_stats_clone() {
        let stats = MinimizationStats {
            oracle_calls: 10,
            regions_pruned: 3,
            events_pruned_top_down: 20,
            events_pruned_bottom_up: 5,
            events_pruned_minimality: 2,
            budget_exhausted: true,
            minimality_verified: false,
        };
        let stats2 = stats;
        assert_eq!(stats2.oracle_calls, 10);
        assert_eq!(stats2.regions_pruned, 3);
        assert_eq!(stats2.events_pruned_top_down, 20);
        assert_eq!(stats2.events_pruned_bottom_up, 5);
        assert_eq!(stats2.events_pruned_minimality, 2);
        assert!(stats2.budget_exhausted);
        assert!(!stats2.minimality_verified);
    }

    #[test]
    fn minimization_stats_default_fields() {
        let stats = MinimizationStats::default();
        assert_eq!(stats.oracle_calls, 0);
        assert_eq!(stats.regions_pruned, 0);
        assert_eq!(stats.events_pruned_top_down, 0);
        assert_eq!(stats.events_pruned_bottom_up, 0);
        assert_eq!(stats.events_pruned_minimality, 0);
        assert!(!stats.budget_exhausted);
        assert!(!stats.minimality_verified);
    }

    #[test]
    fn minimization_stats_serialize() {
        let stats = MinimizationStats {
            oracle_calls: 7,
            regions_pruned: 2,
            events_pruned_top_down: 10,
            events_pruned_bottom_up: 3,
            events_pruned_minimality: 1,
            budget_exhausted: false,
            minimality_verified: true,
        };
        let json = serde_json::to_string(&stats).expect("serialize");
        assert!(json.contains("\"oracle_calls\":7"));
        assert!(json.contains("\"regions_pruned\":2"));
        assert!(json.contains("\"minimality_verified\":true"));
    }

    #[test]
    fn delta_debug_result_debug() {
        let trace = hierarchical_trace();
        let config = DeltaDebugConfig {
            verify_minimality: false,
            ..Default::default()
        };
        let result = minimize(&trace, &config, error_oracle);
        let dbg = format!("{result:?}");
        assert!(dbg.contains("DeltaDebugResult"));
        assert!(dbg.contains("minimized"));
        assert!(dbg.contains("reduction_ratio"));
    }

    #[test]
    fn delta_debug_result_display_format() {
        let trace = hierarchical_trace();
        let config = DeltaDebugConfig::default();
        let result = minimize(&trace, &config, error_oracle);
        let display = format!("{result}");
        // Format: "DeltaDebug: X -> Y events (Z% reduction, N oracle calls, M regions pruned)"
        assert!(display.contains("->"));
        assert!(display.contains("events"));
        assert!(display.contains("oracle calls"));
        assert!(display.contains("regions pruned"));
    }
