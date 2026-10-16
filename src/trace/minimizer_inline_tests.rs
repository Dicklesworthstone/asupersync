    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn make_scenario(n_tasks: usize, failing_task: usize) -> Vec<ScenarioElement> {
        let mut elems = Vec::new();
        // Region 0 (root) is implicit. Only child regions are elements.
        elems.push(ScenarioElement::CreateRegion {
            region_idx: 1,
            parent_idx: 0,
        });
        elems.push(ScenarioElement::CreateRegion {
            region_idx: 2,
            parent_idx: 0,
        });

        for i in 0..n_tasks {
            let region = if i == failing_task { 1 } else { 2 };
            elems.push(ScenarioElement::SpawnTask {
                task_idx: i,
                region_idx: region,
                lane: (i % 4) as u8,
            });
            let n_obl = 1 + (i % 3);
            for j in 0..n_obl {
                elems.push(ScenarioElement::CreateObligation {
                    task_idx: i,
                    region_idx: region,
                    kind: ObligationKind::SendPermit,
                    commit: true,
                    is_late: i == failing_task && j == 0,
                });
            }
        }
        elems.push(ScenarioElement::AdvanceTime { nanos: 1000 });
        elems.push(ScenarioElement::CancelRegion { region_idx: 1 });
        elems.push(ScenarioElement::AdvanceTime { nanos: 1_000_000 });
        elems
    }

    fn leak_checker(target_task: usize) -> impl Fn(&[ScenarioElement]) -> bool {
        move |subset: &[ScenarioElement]| {
            let has_late = subset.iter().any(|e| {
                matches!(e, ScenarioElement::CreateObligation { task_idx, is_late: true, .. } if *task_idx == target_task)
            });
            let has_cancel = subset
                .iter()
                .any(|e| matches!(e, ScenarioElement::CancelRegion { region_idx: 1 }));
            let has_region = subset
                .iter()
                .any(|e| matches!(e, ScenarioElement::CreateRegion { region_idx: 1, .. }));
            let has_task = subset.iter().any(|e| {
                matches!(e, ScenarioElement::SpawnTask { task_idx, .. } if *task_idx == target_task)
            });
            has_late && has_cancel && has_region && has_task
        }
    }

    #[test]
    fn synthetic_known_minimum() {
        let elems = make_scenario(100, 42);
        assert!(elems.len() > 100);
        let report = TraceMinimizer::minimize(&elems, leak_checker(42));
        assert_eq!(report.minimized_count, 4);
        assert!(report.is_minimal);
        assert!(report.reduction_ratio > 0.95);
        assert!(report.replay_attempts < 100);
    }

    #[test]
    fn determinism_10_runs() {
        let elems = make_scenario(50, 7);
        let first = TraceMinimizer::minimize(&elems, leak_checker(7));
        for _ in 0..9 {
            let run = TraceMinimizer::minimize(&elems, leak_checker(7));
            assert_eq!(run.minimized_indices, first.minimized_indices);
        }
    }

    #[test]
    fn scaling_sub_linear() {
        let sizes = [100, 500, 1000];
        let mut counts = Vec::new();
        for &sz in &sizes {
            let elems = make_scenario(sz, sz / 2);
            let r = TraceMinimizer::minimize(&elems, leak_checker(sz / 2));
            counts.push(r.replay_attempts);
        }
        #[allow(clippy::cast_precision_loss)]
        let ratio = counts[2] as f64 / counts[0] as f64;
        #[allow(clippy::cast_precision_loss)]
        let size_ratio = sizes[2] as f64 / sizes[0] as f64;
        assert!(
            ratio < size_ratio,
            "replay scaling ({ratio:.1}x) should be < size scaling ({size_ratio:.1}x)"
        );
    }

    #[test]
    fn narrative_contains_essentials() {
        let elems = make_scenario(10, 3);
        let report = TraceMinimizer::minimize(&elems, leak_checker(3));
        let md = generate_narrative(&report);
        assert!(md.contains("Minimized Failure Narrative"));
        assert!(md.contains("obligation leak"));
        assert!(md.contains("Statistics"));
    }

    #[test]
    fn already_minimal_scenario() {
        let elems = vec![
            ScenarioElement::CreateRegion {
                region_idx: 1,
                parent_idx: 0,
            },
            ScenarioElement::SpawnTask {
                task_idx: 0,
                region_idx: 1,
                lane: 0,
            },
            ScenarioElement::CreateObligation {
                task_idx: 0,
                region_idx: 1,
                kind: ObligationKind::SendPermit,
                commit: true,
                is_late: true,
            },
            ScenarioElement::CancelRegion { region_idx: 1 },
        ];
        let report = TraceMinimizer::minimize(&elems, leak_checker(0));
        assert_eq!(report.minimized_count, 4);
        assert!(report.is_minimal);
    }

    // Pure data-type tests (wave 16 – CyanBarn)

    #[test]
    fn scenario_element_debug() {
        let elem = ScenarioElement::AdvanceTime { nanos: 100 };
        let dbg = format!("{elem:?}");
        assert!(dbg.contains("AdvanceTime"));
    }

    #[test]
    fn scenario_element_clone_eq() {
        let a = ScenarioElement::CreateRegion {
            region_idx: 1,
            parent_idx: 0,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn scenario_element_ne() {
        let a = ScenarioElement::AdvanceTime { nanos: 100 };
        let b = ScenarioElement::AdvanceTime { nanos: 200 };
        assert_ne!(a, b);
    }

    #[test]
    fn scenario_element_display_all() {
        let cases: Vec<ScenarioElement> = vec![
            ScenarioElement::CreateRegion {
                region_idx: 1,
                parent_idx: 0,
            },
            ScenarioElement::SpawnTask {
                task_idx: 5,
                region_idx: 2,
                lane: 3,
            },
            ScenarioElement::CreateObligation {
                task_idx: 1,
                region_idx: 0,
                kind: ObligationKind::SendPermit,
                commit: true,
                is_late: false,
            },
            ScenarioElement::CreateObligation {
                task_idx: 2,
                region_idx: 0,
                kind: ObligationKind::SendPermit,
                commit: false,
                is_late: true,
            },
            ScenarioElement::AdvanceTime { nanos: 1000 },
            ScenarioElement::CancelRegion { region_idx: 3 },
        ];

        let displays: Vec<String> = cases.iter().map(std::string::ToString::to_string).collect();
        assert!(displays[0].contains("create_region"));
        assert!(displays[1].contains("spawn_task"));
        assert!(displays[2].contains("obligation"));
        assert!(displays[2].contains("commit"));
        assert!(displays[3].contains("abort"));
        assert!(displays[3].contains("LATE"));
        assert!(displays[4].contains("advance_time"));
        assert!(displays[5].contains("cancel_region"));
    }

    #[test]
    fn scenario_element_region_idx() {
        assert_eq!(
            ScenarioElement::CreateRegion {
                region_idx: 5,
                parent_idx: 0
            }
            .region_idx(),
            Some(5)
        );
        assert_eq!(
            ScenarioElement::SpawnTask {
                task_idx: 0,
                region_idx: 3,
                lane: 0
            }
            .region_idx(),
            Some(3)
        );
        assert_eq!(
            ScenarioElement::CancelRegion { region_idx: 7 }.region_idx(),
            Some(7)
        );
        assert_eq!(
            ScenarioElement::AdvanceTime { nanos: 100 }.region_idx(),
            None
        );
    }

    #[test]
    fn step_kind_debug_clone_copy_eq() {
        let kind = StepKind::TopDownPrune;
        let cloned = kind;
        let copied = kind;
        assert_eq!(cloned, copied);
        assert_eq!(kind, StepKind::TopDownPrune);
        assert_ne!(kind, StepKind::BottomUpRemove);
    }

    #[test]
    fn step_kind_display_all() {
        assert_eq!(StepKind::TopDownPrune.to_string(), "top_down_prune");
        assert_eq!(StepKind::BottomUpRemove.to_string(), "bottom_up_remove");
        assert_eq!(StepKind::MinimalityCheck.to_string(), "minimality_check");
    }

    #[test]
    fn minimization_step_debug_clone() {
        let step = MinimizationStep {
            kind: StepKind::BottomUpRemove,
            events_remaining: 10,
            events_removed: 3,
            replay_result: true,
            replay_time_ms: 42,
        };
        let dbg = format!("{step:?}");
        assert!(dbg.contains("MinimizationStep"));

        let cloned = step;
        assert_eq!(cloned.events_remaining, 10);
        assert_eq!(cloned.replay_time_ms, 42);
    }

    #[test]
    fn minimization_report_debug() {
        let elems = make_scenario(5, 1);
        let report = TraceMinimizer::minimize(&elems, leak_checker(1));
        let dbg = format!("{report:?}");
        assert!(dbg.contains("MinimizationReport"));
    }

    #[test]
    fn minimization_report_minimized_elements() {
        let elems = make_scenario(5, 1);
        let report = TraceMinimizer::minimize(&elems, leak_checker(1));
        let minimized = report.minimized_elements();
        assert_eq!(minimized.len(), report.minimized_count);
    }

    /// br-asupersync-qu7yet — `minimize_with_clock(LogicalMinimizerClock)`
    /// produces a deterministic report: the per-step `replay_time_ms`
    /// values are derived from a monotonic counter rather than wall
    /// clock, so the same input gives byte-stable timing fields across
    /// runs.
    #[test]
    fn logical_clock_yields_deterministic_timings() {
        let elems = make_scenario(5, 1);

        let clock_a = LogicalMinimizerClock::new();
        let report_a = TraceMinimizer::minimize_with_clock(&elems, leak_checker(1), &clock_a);
        let clock_b = LogicalMinimizerClock::new();
        let report_b = TraceMinimizer::minimize_with_clock(&elems, leak_checker(1), &clock_b);

        // wall_time_ms and per-step ms must match across two runs with
        // matching logical clocks (the wall-clock variant would not
        // satisfy this).
        assert_eq!(report_a.wall_time_ms, report_b.wall_time_ms);
        let times_a: Vec<u64> = report_a.steps.iter().map(|s| s.replay_time_ms).collect();
        let times_b: Vec<u64> = report_b.steps.iter().map(|s| s.replay_time_ms).collect();
        assert_eq!(times_a, times_b);
    }
