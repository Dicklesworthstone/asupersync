    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn test_path(id: u64) -> TransportPath {
        TransportPath::new(
            PathId(id),
            format!("path-{id}"),
            format!("10.0.0.{id}:8080"),
        )
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // Test 1: Path state predicates
    #[test]
    fn test_path_state() {
        init_test("test_path_state");
        let active = PathState::Active.is_usable();
        crate::assert_with_log!(active, "active usable", true, active);
        let degraded = PathState::Degraded.is_usable();
        crate::assert_with_log!(degraded, "degraded usable", true, degraded);
        let unavailable = PathState::Unavailable.is_usable();
        crate::assert_with_log!(!unavailable, "unavailable not usable", false, unavailable);
        let closed = PathState::Closed.is_usable();
        crate::assert_with_log!(!closed, "closed not usable", false, closed);
        crate::test_complete!("test_path_state");
    }

    // Test 2: Path characteristics quality score
    #[test]
    fn test_quality_score() {
        init_test("test_quality_score");
        let high = PathCharacteristics::high_quality();
        let backup = PathCharacteristics::backup();

        let high_score = high.quality_score();
        let backup_score = backup.quality_score();
        let higher = high_score > backup_score;
        crate::assert_with_log!(higher, "high > backup quality", true, higher);
        crate::test_complete!("test_quality_score");
    }

    #[test]
    fn path_characteristics_exports_path_quality_snapshot() {
        init_test("path_characteristics_exports_path_quality_snapshot");
        let chars = PathCharacteristics {
            latency_ms: 75,
            loss_rate: 0.125,
            jitter_ms: 39,
            ..PathCharacteristics::default()
        };

        let quality = chars.encoding_path_quality();

        assert_eq!(quality.rtt_ewma_ms, 75);
        assert_eq!(quality.loss_ewma_permille, 125);
        assert_eq!(quality.reorder_depth, 3);
        crate::test_complete!("path_characteristics_exports_path_quality_snapshot");
    }

    // Test 3: Path statistics
    #[test]
    fn test_path_statistics() {
        init_test("test_path_statistics");
        let path = test_path(1);

        path.record_receipt(Time::from_secs(1));
        path.record_receipt(Time::from_secs(2));
        path.record_duplicate();
        path.record_loss();

        let received = path.symbols_received.load(Ordering::Relaxed);
        crate::assert_with_log!(received == 2, "symbols_received", 2, received);
        let duplicates = path.duplicates_received.load(Ordering::Relaxed);
        crate::assert_with_log!(duplicates == 1, "duplicates_received", 1, duplicates);
        let duplicate_rate = path.duplicate_rate();
        crate::assert_with_log!(
            duplicate_rate > 0.0,
            "duplicate_rate > 0",
            true,
            duplicate_rate > 0.0
        );
        let loss_rate = path.effective_loss_rate();
        crate::assert_with_log!(
            loss_rate > 0.0,
            "effective_loss_rate > 0",
            true,
            loss_rate > 0.0
        );
        crate::test_complete!("test_path_statistics");
    }

    #[test]
    fn transport_path_exports_observed_path_quality_snapshot() {
        init_test("transport_path_exports_observed_path_quality_snapshot");
        let path = test_path(1).with_characteristics(PathCharacteristics {
            latency_ms: 90,
            loss_rate: 0.01,
            jitter_ms: 10,
            ..PathCharacteristics::default()
        });

        path.record_receipt(Time::from_secs(1));
        path.record_receipt(Time::from_secs(2));
        path.record_duplicate();
        path.record_loss();

        let quality = path.encoding_path_quality();

        assert_eq!(quality.rtt_ewma_ms, 90);
        assert_eq!(quality.loss_ewma_permille, 333);
        assert_eq!(quality.reorder_depth, 4);
        crate::test_complete!("transport_path_exports_observed_path_quality_snapshot");
    }

    // Test 4: PathSet selection - UseAll
    #[test]
    fn test_path_set_use_all() {
        init_test("test_path_set_use_all");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        set.register(test_path(3));
        set.register(test_path(1));
        set.register(test_path(2));

        let selected = set.select_paths();
        let len = selected.len();
        crate::assert_with_log!(len == 3, "selected len", 3, len);
        let ids: Vec<PathId> = selected.iter().map(|path| path.id).collect();
        crate::assert_with_log!(
            ids == vec![PathId(1), PathId(2), PathId(3)],
            "use_all returns stable PathId order",
            vec![PathId(1), PathId(2), PathId(3)],
            ids
        );
        crate::test_complete!("test_path_set_use_all");
    }

    // Test 4.1: PathSet selection skips unusable paths
    #[test]
    fn test_path_set_skips_unusable() {
        init_test("test_path_set_skips_unusable");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        let down = test_path(1);
        down.set_state(PathState::Unavailable);
        let up = test_path(2);
        up.set_state(PathState::Active);

        set.register(down);
        set.register(up);

        let selected = set.select_paths();
        let len = selected.len();
        crate::assert_with_log!(len == 1, "selected len", 1, len);
        let id = selected[0].id;
        crate::assert_with_log!(id == PathId(2), "selected path id", PathId(2), id);
        crate::test_complete!("test_path_set_skips_unusable");
    }

    // Test 5: PathSet selection - BestQuality
    #[test]
    fn test_path_set_best_quality() {
        init_test("test_path_set_best_quality");
        let set = PathSet::new(PathSelectionPolicy::BestQuality { count: 2 });

        set.register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        set.register(test_path(2).with_characteristics(PathCharacteristics::backup()));
        set.register(test_path(3).with_characteristics(PathCharacteristics::default()));

        let selected = set.select_paths();
        let len = selected.len();
        crate::assert_with_log!(len == 2, "selected len", 2, len);
        // First should be high quality
        let first_score = selected[0].characteristics.quality_score();
        let second_score = selected[1].characteristics.quality_score();
        let ordered = first_score > second_score;
        crate::assert_with_log!(ordered, "quality order", true, ordered);
        crate::test_complete!("test_path_set_best_quality");
    }

    #[test]
    fn test_path_set_best_quality_tie_breaks_by_path_id() {
        init_test("test_path_set_best_quality_tie_breaks_by_path_id");
        let set = PathSet::new(PathSelectionPolicy::BestQuality { count: 2 });

        let tied = || PathCharacteristics {
            latency_ms: 25,
            bandwidth_bps: 2_000_000,
            loss_rate: 0.01,
            jitter_ms: 4,
            is_primary: false,
            priority: 100,
        };
        set.register(test_path(9).with_characteristics(tied()));
        set.register(test_path(2).with_characteristics(tied()));
        set.register(test_path(5).with_characteristics(PathCharacteristics::backup()));

        let selected = set.select_paths();
        let ids: Vec<PathId> = selected.iter().map(|path| path.id).collect();
        crate::assert_with_log!(
            ids == vec![PathId(2), PathId(9)],
            "best-quality ties prefer lower PathId",
            vec![PathId(2), PathId(9)],
            ids
        );

        crate::test_complete!("test_path_set_best_quality_tie_breaks_by_path_id");
    }

    #[test]
    fn test_path_set_best_quality_penalizes_nan_loss_rate() {
        init_test("test_path_set_best_quality_penalizes_nan_loss_rate");
        let set = PathSet::new(PathSelectionPolicy::BestQuality { count: 1 });

        let invalid_loss = PathCharacteristics {
            latency_ms: 1,
            bandwidth_bps: u64::MAX,
            loss_rate: f64::NAN,
            jitter_ms: 0,
            is_primary: false,
            priority: 1,
        };
        let invalid_score = invalid_loss.quality_score();
        crate::assert_with_log!(
            invalid_score.is_finite(),
            "invalid loss rate produces finite quality score",
            true,
            invalid_score.is_finite()
        );

        set.register(test_path(1).with_characteristics(invalid_loss));
        set.register(test_path(2).with_characteristics(PathCharacteristics::high_quality()));

        let selected = set.select_paths();
        let ids: Vec<PathId> = selected.iter().map(|path| path.id).collect();
        crate::assert_with_log!(
            ids == vec![PathId(2)],
            "best-quality penalizes non-finite loss rate",
            vec![PathId(2)],
            ids
        );

        crate::test_complete!("test_path_set_best_quality_penalizes_nan_loss_rate");
    }

    // Test 5.1: PathSet selection - ByPriority
    #[test]
    fn test_path_set_by_priority() {
        init_test("test_path_set_by_priority");
        let set = PathSet::new(PathSelectionPolicy::ByPriority { count: 2 });

        set.register(test_path(1).with_characteristics(PathCharacteristics {
            priority: 50,
            ..Default::default()
        }));
        set.register(test_path(2).with_characteristics(PathCharacteristics {
            priority: 10,
            ..Default::default()
        }));
        set.register(test_path(3).with_characteristics(PathCharacteristics {
            priority: 30,
            ..Default::default()
        }));

        let selected = set.select_paths();
        let mut priorities: Vec<u32> = selected
            .iter()
            .map(|p| p.characteristics.priority)
            .collect();
        priorities.sort_unstable();
        crate::assert_with_log!(
            priorities == vec![10, 30],
            "priority selection",
            vec![10, 30],
            priorities
        );
        crate::test_complete!("test_path_set_by_priority");
    }

    #[test]
    fn test_path_set_by_priority_tie_breaks_by_path_id() {
        init_test("test_path_set_by_priority_tie_breaks_by_path_id");
        let set = PathSet::new(PathSelectionPolicy::ByPriority { count: 2 });

        set.register(test_path(8).with_characteristics(PathCharacteristics {
            priority: 10,
            ..Default::default()
        }));
        set.register(test_path(3).with_characteristics(PathCharacteristics {
            priority: 10,
            ..Default::default()
        }));
        set.register(test_path(5).with_characteristics(PathCharacteristics {
            priority: 20,
            ..Default::default()
        }));

        let selected = set.select_paths();
        let ids: Vec<PathId> = selected.iter().map(|path| path.id).collect();
        crate::assert_with_log!(
            ids == vec![PathId(3), PathId(8)],
            "priority ties prefer lower PathId",
            vec![PathId(3), PathId(8)],
            ids
        );

        crate::test_complete!("test_path_set_by_priority_tie_breaks_by_path_id");
    }

    #[test]
    fn test_path_set_primary_only_exposes_conservative_fallback() {
        init_test("test_path_set_primary_only_exposes_conservative_fallback");
        let set = PathSet::new(PathSelectionPolicy::PrimaryOnly);

        set.register(test_path(3).with_characteristics(PathCharacteristics::backup()));
        set.register(test_path(1).with_characteristics(PathCharacteristics {
            latency_ms: 15,
            bandwidth_bps: 4_000_000,
            loss_rate: 0.02,
            jitter_ms: 3,
            is_primary: false,
            priority: 20,
        }));

        let selected = set.select_paths();
        crate::assert_with_log!(
            selected.is_empty(),
            "primary_only keeps existing empty selection behavior",
            true,
            selected.is_empty()
        );

        let decision = set.select_paths_with_decision();
        crate::assert_with_log!(
            decision.selected.is_empty(),
            "decision selected remains empty",
            true,
            decision.selected.is_empty()
        );
        crate::assert_with_log!(
            decision.fallback_policy_id() == Some("best-quality"),
            "fallback policy id",
            Some("best-quality"),
            decision.fallback_policy_id()
        );
        crate::assert_with_log!(
            decision.downgrade_reason_id() == Some("no-primary-path"),
            "downgrade reason id",
            Some("no-primary-path"),
            decision.downgrade_reason_id()
        );
        let fallback_ids = decision.fallback_ids();
        let expected_ids = [PathId(1)];
        crate::assert_with_log!(
            fallback_ids.as_slice() == expected_ids.as_slice(),
            "fallback picks best available path",
            expected_ids.as_slice(),
            fallback_ids.as_slice()
        );

        crate::test_complete!("test_path_set_primary_only_exposes_conservative_fallback");
    }

    #[test]
    fn test_path_set_best_quality_reports_requested_paths_unavailable() {
        init_test("test_path_set_best_quality_reports_requested_paths_unavailable");
        let set = PathSet::new(PathSelectionPolicy::BestQuality { count: 2 });

        set.register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        let unavailable = test_path(2).with_characteristics(PathCharacteristics::backup());
        unavailable.set_state(PathState::Unavailable);
        set.register(unavailable);

        let decision = set.select_paths_with_decision();
        let selected_ids = decision.selected_ids();
        let expected_ids = [PathId(1)];
        crate::assert_with_log!(
            selected_ids.as_slice() == expected_ids.as_slice(),
            "best-quality keeps usable selection",
            expected_ids.as_slice(),
            selected_ids.as_slice()
        );
        crate::assert_with_log!(
            decision.fallback.is_empty(),
            "no separate fallback paths needed",
            true,
            decision.fallback.is_empty()
        );
        crate::assert_with_log!(
            decision.downgrade_reason
                == Some(PathSelectionDowngradeReason::RequestedPathsUnavailable {
                    requested: 2,
                    available: 1,
                }),
            "downgrade records insufficient usable paths",
            Some(PathSelectionDowngradeReason::RequestedPathsUnavailable {
                requested: 2,
                available: 1,
            }),
            decision.downgrade_reason
        );

        crate::test_complete!("test_path_set_best_quality_reports_requested_paths_unavailable");
    }

    #[test]
    fn metamorphic_unusable_decoy_paths_do_not_affect_bounded_selection() {
        init_test("metamorphic_unusable_decoy_paths_do_not_affect_bounded_selection");

        fn bounded_selection_signature(
            policy: PathSelectionPolicy,
            include_unusable_decoy: bool,
        ) -> (
            Vec<PathId>,
            Vec<PathId>,
            usize,
            Option<PathSelectionDowngradeReason>,
        ) {
            let set = PathSet::new(policy);

            set.register(test_path(2).with_characteristics(PathCharacteristics {
                latency_ms: 10,
                bandwidth_bps: 10_000_000,
                loss_rate: 0.001,
                jitter_ms: 2,
                is_primary: true,
                priority: 10,
            }));
            set.register(test_path(5).with_characteristics(PathCharacteristics {
                latency_ms: 40,
                bandwidth_bps: 3_000_000,
                loss_rate: 0.02,
                jitter_ms: 8,
                is_primary: false,
                priority: 30,
            }));
            set.register(test_path(8).with_characteristics(PathCharacteristics {
                latency_ms: 120,
                bandwidth_bps: 500_000,
                loss_rate: 0.08,
                jitter_ms: 20,
                is_primary: false,
                priority: 80,
            }));

            if include_unusable_decoy {
                let decoy = test_path(1).with_characteristics(PathCharacteristics {
                    latency_ms: 1,
                    bandwidth_bps: u64::MAX,
                    loss_rate: 0.0,
                    jitter_ms: 0,
                    is_primary: true,
                    priority: 0,
                });
                decoy.set_state(PathState::Unavailable);
                set.register(decoy);
            }

            let decision = set.select_paths_with_decision();
            (
                decision.selected_ids().into_vec(),
                decision.rejected_ids().into_vec(),
                decision.available_path_count(),
                decision.downgrade_reason,
            )
        }

        for policy in [
            PathSelectionPolicy::BestQuality { count: 2 },
            PathSelectionPolicy::ByPriority { count: 2 },
        ] {
            let baseline = bounded_selection_signature(policy, false);
            let with_decoy = bounded_selection_signature(policy, true);
            assert_eq!(
                baseline, with_decoy,
                "{policy:?} must ignore unusable paths before ranking candidates"
            );
        }

        crate::test_complete!("metamorphic_unusable_decoy_paths_do_not_affect_bounded_selection");
    }

    #[test]
    fn test_experimental_transport_decision_gate_disabled_falls_back_to_round_robin() {
        init_test("test_experimental_transport_decision_gate_disabled_falls_back_to_round_robin");

        let aggregator = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::UseAll,
            experiment_gate: ExperimentalTransportGate::Disabled,
            ..AggregatorConfig::default()
        });

        aggregator
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));
        aggregator
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        aggregator.paths().register(test_path(2));

        let decision = aggregator.experimental_transport_decision(TransportExperimentContext::new(
            "TW-MULTIPATH",
            "aa08-gate-disabled-001",
        ));

        crate::assert_with_log!(
            decision.path_policy_id() == "use-all",
            "requested policy id preserved",
            "use-all",
            decision.path_policy_id()
        );
        crate::assert_with_log!(
            decision.effective_path_policy_id() == "round-robin",
            "effective policy falls back to conservative round-robin",
            "round-robin",
            decision.effective_path_policy_id()
        );
        crate::assert_with_log!(
            decision.downgrade_reason_id() == Some("experimental-gate-disabled"),
            "preview gate downgrade emitted",
            Some("experimental-gate-disabled"),
            decision.downgrade_reason_id()
        );
        crate::assert_with_log!(
            decision.path_decision.selected_path_count() == 1,
            "round-robin selects one conservative path",
            1,
            decision.path_decision.selected_path_count()
        );
        let selected_ids = decision.path_decision.selected_ids();
        let expected_ids = [PathId(1)];
        crate::assert_with_log!(
            selected_ids.as_slice() == expected_ids.as_slice(),
            "conservative round-robin remains deterministic",
            expected_ids.as_slice(),
            selected_ids.as_slice()
        );

        crate::test_complete!(
            "test_experimental_transport_decision_gate_disabled_falls_back_to_round_robin"
        );
    }

    #[test]
    fn test_experimental_transport_decision_preview_honors_multipath_policy() {
        init_test("test_experimental_transport_decision_preview_honors_multipath_policy");

        let aggregator = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::BestQuality { count: 2 },
            experiment_gate: ExperimentalTransportGate::MultipathPreview,
            ..AggregatorConfig::default()
        });

        aggregator
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        aggregator
            .paths()
            .register(test_path(2).with_characteristics(PathCharacteristics {
                latency_ms: 20,
                bandwidth_bps: 5_000_000,
                loss_rate: 0.01,
                jitter_ms: 5,
                is_primary: false,
                priority: 20,
            }));
        aggregator
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));

        let decision = aggregator.experimental_transport_decision(TransportExperimentContext::new(
            "TW-MULTIPATH",
            "aa08-preview-001",
        ));

        crate::assert_with_log!(
            decision.effective_path_policy_id() == "best-quality",
            "preview gate honors requested multipath policy",
            "best-quality",
            decision.effective_path_policy_id()
        );
        crate::assert_with_log!(
            decision.downgrade_reason.is_none(),
            "no gate downgrade when preview enabled",
            true,
            decision.downgrade_reason.is_none()
        );
        let selected_ids = decision.path_decision.selected_ids();
        let expected_ids = [PathId(1), PathId(2)];
        crate::assert_with_log!(
            selected_ids.as_slice() == expected_ids.as_slice(),
            "best-quality preview selects deterministic top paths",
            expected_ids.as_slice(),
            selected_ids.as_slice()
        );

        crate::test_complete!(
            "test_experimental_transport_decision_preview_honors_multipath_policy"
        );
    }

    #[test]
    fn test_experimental_transport_decision_coding_preview_stays_fail_closed() {
        init_test("test_experimental_transport_decision_coding_preview_stays_fail_closed");

        let aggregator = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::RoundRobin,
            experiment_gate: ExperimentalTransportGate::MultipathPreview,
            coding_policy: TransportCodingPolicy::RaptorQFecPreview,
            ..AggregatorConfig::default()
        });

        aggregator.paths().register(test_path(7));

        let decision = aggregator.experimental_transport_decision(TransportExperimentContext::new(
            "TW-BURST",
            "aa08-coding-001",
        ));

        crate::assert_with_log!(
            decision.coding_policy_id() == "raptorq-fec-preview",
            "requested coding policy id preserved",
            "raptorq-fec-preview",
            decision.coding_policy_id()
        );
        crate::assert_with_log!(
            decision.effective_coding_policy_id() == "disabled",
            "coding preview falls back until RaptorQ closure completes",
            "disabled",
            decision.effective_coding_policy_id()
        );
        crate::assert_with_log!(
            decision.downgrade_reason_id() == Some("raptorq-closure-pending"),
            "coding downgrade reason emitted",
            Some("raptorq-closure-pending"),
            decision.downgrade_reason_id()
        );

        let log_fields = decision.log_fields();
        crate::assert_with_log!(
            log_fields.get("workload_id").map(String::as_str) == Some("TW-BURST"),
            "workload id logged",
            Some("TW-BURST"),
            log_fields.get("workload_id").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("path_count").map(String::as_str) == Some("1"),
            "usable path count logged",
            Some("1"),
            log_fields.get("path_count").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("selected_path_ids").map(String::as_str) == Some("7"),
            "selected path ids logged",
            Some("7"),
            log_fields.get("selected_path_ids").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("fallback_path_count").map(String::as_str) == Some("0"),
            "fallback path count logged",
            Some("0"),
            log_fields.get("fallback_path_count").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields
                .get("benchmark_correlation_id")
                .map(String::as_str)
                == Some("aa08-coding-001"),
            "benchmark correlation logged",
            Some("aa08-coding-001"),
            log_fields
                .get("benchmark_correlation_id")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("downgrade_reason").map(String::as_str)
                == Some("raptorq-closure-pending"),
            "downgrade reason logged",
            Some("raptorq-closure-pending"),
            log_fields.get("downgrade_reason").map(String::as_str)
        );

        crate::test_complete!(
            "test_experimental_transport_decision_coding_preview_stays_fail_closed"
        );
    }

    #[test]
    fn test_experimental_transport_decision_logs_combined_downgrade_reason_vector() {
        init_test("test_experimental_transport_decision_logs_combined_downgrade_reason_vector");

        let aggregator = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::UseAll,
            experiment_gate: ExperimentalTransportGate::Disabled,
            coding_policy: TransportCodingPolicy::RaptorQFecPreview,
            ..AggregatorConfig::default()
        });

        aggregator.paths().register(test_path(1));

        let decision = aggregator.experimental_transport_decision(TransportExperimentContext::new(
            "TW-CODED-MULTIPATH",
            "aa08-combined-downgrade-001",
        ));
        let reason_ids = decision.downgrade_reason_ids();
        let expected_reasons = ["experimental-gate-disabled", "raptorq-closure-pending"];

        crate::assert_with_log!(
            decision.downgrade_reason_id() == Some("experimental-gate-disabled"),
            "single downgrade reason remains the first reason",
            Some("experimental-gate-disabled"),
            decision.downgrade_reason_id()
        );
        crate::assert_with_log!(
            reason_ids.as_slice() == expected_reasons.as_slice(),
            "combined downgrade reason vector preserves all fallbacks in deterministic order",
            expected_reasons.as_slice(),
            reason_ids.as_slice()
        );

        let log_fields = decision.log_fields();
        crate::assert_with_log!(
            log_fields.get("downgrade_reason").map(String::as_str)
                == Some("experimental-gate-disabled"),
            "first downgrade reason remains logged",
            Some("experimental-gate-disabled"),
            log_fields.get("downgrade_reason").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("downgrade_reasons").map(String::as_str)
                == Some("experimental-gate-disabled,raptorq-closure-pending"),
            "full downgrade reason vector logged",
            Some("experimental-gate-disabled,raptorq-closure-pending"),
            log_fields.get("downgrade_reasons").map(String::as_str)
        );

        crate::test_complete!(
            "test_experimental_transport_decision_logs_combined_downgrade_reason_vector"
        );
    }

    #[test]
    fn test_experimental_transport_decision_logs_fallback_inventory() {
        init_test("test_experimental_transport_decision_logs_fallback_inventory");

        let aggregator = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::PrimaryOnly,
            experiment_gate: ExperimentalTransportGate::MultipathPreview,
            ..AggregatorConfig::default()
        });

        aggregator
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));
        aggregator
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics {
                latency_ms: 15,
                bandwidth_bps: 4_000_000,
                loss_rate: 0.02,
                jitter_ms: 3,
                is_primary: false,
                priority: 20,
            }));

        let decision = aggregator.experimental_transport_decision(TransportExperimentContext::new(
            "TW-HANDOFF",
            "aa08-fallback-001",
        ));
        let log_fields = decision.log_fields();

        crate::assert_with_log!(
            log_fields.get("path_count").map(String::as_str) == Some("2"),
            "available path inventory logged",
            Some("2"),
            log_fields.get("path_count").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("selected_path_ids").map(String::as_str) == Some(""),
            "selected path ids stay empty when no primary path is usable",
            Some(""),
            log_fields.get("selected_path_ids").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("fallback_path_count").map(String::as_str) == Some("1"),
            "fallback path count logged",
            Some("1"),
            log_fields.get("fallback_path_count").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("fallback_path_ids").map(String::as_str) == Some("1"),
            "fallback path ids logged",
            Some("1"),
            log_fields.get("fallback_path_ids").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("rejected_path_ids").map(String::as_str) == Some("1,3"),
            "rejected path ids preserve the request-level alternatives",
            Some("1,3"),
            log_fields.get("rejected_path_ids").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("path_downgrade_reason").map(String::as_str) == Some("no-primary-path"),
            "path downgrade reason logged",
            Some("no-primary-path"),
            log_fields.get("path_downgrade_reason").map(String::as_str)
        );
        crate::assert_with_log!(
            log_fields.get("fairness_state").map(String::as_str)
                == Some(
                    "requested_policy=primary-only;effective_policy=primary-only;available=2;selected=0;rejected=2;fallback=1",
                ),
            "fairness state captures rejected and fallback counts",
            Some(
                "requested_policy=primary-only;effective_policy=primary-only;available=2;selected=0;rejected=2;fallback=1",
            ),
            log_fields.get("fairness_state").map(String::as_str)
        );

        crate::test_complete!("test_experimental_transport_decision_logs_fallback_inventory");
    }

    fn assert_transport_decision_log_keyset(fields: &BTreeMap<String, String>) {
        let actual: std::collections::BTreeSet<&str> = fields.keys().map(String::as_str).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "workload_id",
            "benchmark_correlation_id",
            "experimental_gate_id",
            "path_policy_id",
            "effective_path_policy_id",
            "requested_path_count",
            "path_count",
            "selected_path_count",
            "fallback_path_count",
            "rejected_path_count",
            "selected_path_ids",
            "fallback_path_ids",
            "rejected_path_ids",
            "path_pressure_snapshot",
            "fairness_policy_id",
            "fairness_state",
            "fallback_policy_id",
            "path_downgrade_reason",
            "downgrade_reason",
            "downgrade_reasons",
            "coding_policy_id",
            "effective_coding_policy_id",
        ]
        .into_iter()
        .collect();

        crate::assert_with_log!(
            actual == expected,
            "transport decision log fields stay aligned with the AA-08 contract keyset",
            format!("{expected:?}"),
            format!("{actual:?}")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_experimental_transport_decision_log_fields_cover_contract_modes() {
        init_test("test_experimental_transport_decision_log_fields_cover_contract_modes");

        let gate_disabled = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::UseAll,
            experiment_gate: ExperimentalTransportGate::Disabled,
            ..AggregatorConfig::default()
        });
        gate_disabled
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));
        gate_disabled
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        gate_disabled.paths().register(test_path(2));

        let gate_disabled_fields = gate_disabled
            .experimental_transport_decision(TransportExperimentContext::new(
                "TW-MULTIPATH",
                "aa08-gate-contract-001",
            ))
            .log_fields();
        assert_transport_decision_log_keyset(&gate_disabled_fields);
        crate::assert_with_log!(
            gate_disabled_fields
                .get("requested_path_count")
                .map(String::as_str)
                == Some("all"),
            "unbounded policies log requested_path_count as all",
            Some("all"),
            gate_disabled_fields
                .get("requested_path_count")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            gate_disabled_fields
                .get("effective_path_policy_id")
                .map(String::as_str)
                == Some("round-robin"),
            "gate-disabled preview logs conservative effective policy",
            Some("round-robin"),
            gate_disabled_fields
                .get("effective_path_policy_id")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            gate_disabled_fields
                .get("selected_path_count")
                .map(String::as_str)
                == Some("1"),
            "gate-disabled preview logs the conservative selected path count",
            Some("1"),
            gate_disabled_fields
                .get("selected_path_count")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            gate_disabled_fields
                .get("rejected_path_ids")
                .map(String::as_str)
                == Some("2,3"),
            "gate-disabled preview logs round-robin rejected alternatives",
            Some("2,3"),
            gate_disabled_fields
                .get("rejected_path_ids")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            gate_disabled_fields
                .get("fairness_policy_id")
                .map(String::as_str)
                == Some("transport-multipath-fairness-v1"),
            "fairness policy id is stable",
            Some("transport-multipath-fairness-v1"),
            gate_disabled_fields
                .get("fairness_policy_id")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            gate_disabled_fields
                .get("path_downgrade_reason")
                .map(String::as_str)
                == Some(""),
            "gate-level fallback keeps path_downgrade_reason empty",
            Some(""),
            gate_disabled_fields
                .get("path_downgrade_reason")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            gate_disabled_fields
                .get("downgrade_reason")
                .map(String::as_str)
                == Some("experimental-gate-disabled"),
            "gate-level fallback logs the preview downgrade reason",
            Some("experimental-gate-disabled"),
            gate_disabled_fields
                .get("downgrade_reason")
                .map(String::as_str)
        );

        let bounded_preview = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::BestQuality { count: 2 },
            experiment_gate: ExperimentalTransportGate::MultipathPreview,
            ..AggregatorConfig::default()
        });
        bounded_preview
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics::high_quality()));
        bounded_preview
            .paths()
            .register(test_path(2).with_characteristics(PathCharacteristics {
                latency_ms: 20,
                bandwidth_bps: 5_000_000,
                loss_rate: 0.01,
                jitter_ms: 5,
                is_primary: false,
                priority: 20,
            }));
        bounded_preview
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));

        let bounded_preview_fields = bounded_preview
            .experimental_transport_decision(TransportExperimentContext::new(
                "TW-MULTIPATH",
                "aa08-bounded-contract-001",
            ))
            .log_fields();
        assert_transport_decision_log_keyset(&bounded_preview_fields);
        crate::assert_with_log!(
            bounded_preview_fields
                .get("requested_path_count")
                .map(String::as_str)
                == Some("2"),
            "bounded multipath preview logs requested path count",
            Some("2"),
            bounded_preview_fields
                .get("requested_path_count")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            bounded_preview_fields
                .get("selected_path_ids")
                .map(String::as_str)
                == Some("1,2"),
            "bounded multipath preview logs deterministic selected path ids",
            Some("1,2"),
            bounded_preview_fields
                .get("selected_path_ids")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            bounded_preview_fields
                .get("fallback_path_ids")
                .map(String::as_str)
                == Some(""),
            "bounded preview leaves fallback inventory empty when the request is honored",
            Some(""),
            bounded_preview_fields
                .get("fallback_path_ids")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            bounded_preview_fields
                .get("rejected_path_count")
                .map(String::as_str)
                == Some("1"),
            "bounded preview logs rejected alternative count",
            Some("1"),
            bounded_preview_fields
                .get("rejected_path_count")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            bounded_preview_fields
                .get("rejected_path_ids")
                .map(String::as_str)
                == Some("3"),
            "bounded preview logs deterministic rejected alternative ids",
            Some("3"),
            bounded_preview_fields
                .get("rejected_path_ids")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            bounded_preview_fields
                .get("path_pressure_snapshot")
                .map(|snapshot| snapshot.contains("3:active:"))
                == Some(true),
            "pressure snapshot includes rejected active path evidence",
            Some(true),
            bounded_preview_fields
                .get("path_pressure_snapshot")
                .map(|snapshot| snapshot.contains("3:active:"))
        );
        crate::assert_with_log!(
            bounded_preview_fields
                .get("downgrade_reason")
                .map(String::as_str)
                == Some(""),
            "bounded preview leaves gate-level downgrade empty when honored",
            Some(""),
            bounded_preview_fields
                .get("downgrade_reason")
                .map(String::as_str)
        );

        let primary_fallback = MultipathAggregator::new(AggregatorConfig {
            path_policy: PathSelectionPolicy::PrimaryOnly,
            experiment_gate: ExperimentalTransportGate::MultipathPreview,
            ..AggregatorConfig::default()
        });
        primary_fallback
            .paths()
            .register(test_path(3).with_characteristics(PathCharacteristics::backup()));
        primary_fallback
            .paths()
            .register(test_path(1).with_characteristics(PathCharacteristics {
                latency_ms: 15,
                bandwidth_bps: 4_000_000,
                loss_rate: 0.02,
                jitter_ms: 3,
                is_primary: false,
                priority: 20,
            }));

        let primary_fallback_fields = primary_fallback
            .experimental_transport_decision(TransportExperimentContext::new(
                "TW-HANDOFF",
                "aa08-path-fallback-001",
            ))
            .log_fields();
        assert_transport_decision_log_keyset(&primary_fallback_fields);
        crate::assert_with_log!(
            primary_fallback_fields
                .get("fallback_policy_id")
                .map(String::as_str)
                == Some("best-quality"),
            "primary-path fallback logs the conservative fallback policy",
            Some("best-quality"),
            primary_fallback_fields
                .get("fallback_policy_id")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            primary_fallback_fields
                .get("fallback_path_ids")
                .map(String::as_str)
                == Some("1"),
            "primary-path fallback logs deterministic fallback path ids",
            Some("1"),
            primary_fallback_fields
                .get("fallback_path_ids")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            primary_fallback_fields
                .get("path_downgrade_reason")
                .map(String::as_str)
                == Some("no-primary-path"),
            "primary-path fallback logs the path-level downgrade reason",
            Some("no-primary-path"),
            primary_fallback_fields
                .get("path_downgrade_reason")
                .map(String::as_str)
        );
        crate::assert_with_log!(
            primary_fallback_fields
                .get("downgrade_reason")
                .map(String::as_str)
                == Some(""),
            "primary-path fallback keeps gate-level downgrade empty",
            Some(""),
            primary_fallback_fields
                .get("downgrade_reason")
                .map(String::as_str)
        );

        crate::test_complete!(
            "test_experimental_transport_decision_log_fields_cover_contract_modes"
        );
    }

    #[test]
    fn test_path_set_register_advances_next_id() {
        init_test("test_path_set_register_advances_next_id");

        let set = PathSet::new(PathSelectionPolicy::RoundRobin);
        set.register(test_path(0));

        let created = set.create_path(
            "generated",
            "localhost:9000",
            PathCharacteristics::default(),
        );
        crate::assert_with_log!(
            created == PathId(1),
            "create_path advances beyond caller-supplied ids",
            PathId(1),
            created
        );
        crate::assert_with_log!(
            set.get(PathId(0)).is_some(),
            "original registered path is preserved",
            true,
            set.get(PathId(0)).is_some()
        );

        crate::test_complete!("test_path_set_register_advances_next_id");
    }

    // Test 6: Deduplicator basic operation
    #[test]
    fn test_deduplicator_basic() {
        init_test("test_deduplicator_basic");
        let dedup = SymbolDeduplicator::new(DeduplicatorConfig::default());

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let path = PathId(1);
        let now = Time::ZERO;

        // First time - not duplicate
        let first = dedup.check_and_record(&symbol, path, now);
        crate::assert_with_log!(first, "first record", true, first);

        // Second time - duplicate
        let second = dedup.check_and_record(&symbol, path, now);
        crate::assert_with_log!(!second, "second duplicate", false, second);

        let stats = dedup.stats();
        crate::assert_with_log!(
            stats.unique_symbols == 1,
            "unique_symbols",
            1,
            stats.unique_symbols
        );
        crate::assert_with_log!(
            stats.duplicates_detected == 1,
            "duplicates_detected",
            1,
            stats.duplicates_detected
        );
        crate::test_complete!("test_deduplicator_basic");
    }

    // Test 7: Deduplicator tracks first path
    #[test]
    fn test_deduplicator_tracks_path() {
        init_test("test_deduplicator_tracks_path");
        let config = DeduplicatorConfig {
            track_path: true,
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let path1 = PathId(1);
        let path2 = PathId(2);

        dedup.check_and_record(&symbol, path1, Time::ZERO);
        dedup.check_and_record(&symbol, path2, Time::ZERO); // Duplicate

        let first = dedup.first_path(symbol.object_id(), symbol.id());
        crate::assert_with_log!(first == Some(path1), "first path", Some(path1), first);
        crate::test_complete!("test_deduplicator_tracks_path");
    }

    // Test 8: Reorderer in-order delivery
    #[test]
    fn test_reorderer_in_order() {
        init_test("test_reorderer_in_order");
        let config = ReordererConfig {
            immediate_delivery: false,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver symbols in order
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s1 = Symbol::new_for_test(1, 0, 1, &[1]);
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);

        let ready0 = reorderer.process(s0, path, now);
        let ready1 = reorderer.process(s1, path, now);
        let ready2 = reorderer.process(s2, path, now);

        let len0 = ready0.len();
        crate::assert_with_log!(len0 == 1, "ready0 len", 1, len0);
        let len1 = ready1.len();
        crate::assert_with_log!(len1 == 1, "ready1 len", 1, len1);
        let len2 = ready2.len();
        crate::assert_with_log!(len2 == 1, "ready2 len", 1, len2);

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.in_order_deliveries == 3,
            "in_order_deliveries",
            3,
            stats.in_order_deliveries
        );
        crate::assert_with_log!(
            stats.reordered_deliveries == 0,
            "reordered_deliveries",
            0,
            stats.reordered_deliveries
        );
        crate::test_complete!("test_reorderer_in_order");
    }

    #[test]
    fn reorderer_prune_reclaims_empty_idle_states() {
        init_test("reorderer_prune_reclaims_empty_idle_states");
        let config = ReordererConfig {
            immediate_delivery: false,
            entry_ttl: Time::from_secs(10),
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);

        // Deliver an in-order symbol so object (1,0) gets a state whose buffer is
        // empty and whose last_delivery is set to t=1s.
        let s = Symbol::new_for_test(1, 0, 0, &[0]);
        let ready = reorderer.process(s, path, Time::from_secs(1));
        crate::assert_with_log!(ready.len() == 1, "in-order delivered", 1, ready.len());
        let tracked = reorderer.stats().objects_tracked;
        crate::assert_with_log!(tracked == 1, "state created", 1, tracked);

        // Not yet idle past the TTL: the state is retained.
        let pruned_early = reorderer.prune(Time::from_secs(5));
        crate::assert_with_log!(pruned_early == 0, "recent state retained", 0, pruned_early);
        let tracked_early = reorderer.stats().objects_tracked;
        crate::assert_with_log!(tracked_early == 1, "still tracked", 1, tracked_early);

        // Empty and idle past the TTL: reclaimed.
        let pruned = reorderer.prune(Time::from_secs(20));
        crate::assert_with_log!(pruned == 1, "stale empty state reclaimed", 1, pruned);
        let tracked_after = reorderer.stats().objects_tracked;
        crate::assert_with_log!(tracked_after == 0, "map reclaimed", 0, tracked_after);

        crate::test_complete!("reorderer_prune_reclaims_empty_idle_states");
    }

    #[test]
    fn reorderer_prune_keeps_buffered_states() {
        init_test("reorderer_prune_keeps_buffered_states");
        let config = ReordererConfig {
            immediate_delivery: false,
            entry_ttl: Time::from_secs(10),
            max_sequence_gap: 100,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);

        // An out-of-order symbol (esi=5, base expects 0) is buffered, not
        // delivered: the state is non-empty. Even far past the TTL, prune must
        // keep it so a not-yet-deliverable symbol is never silently discarded.
        let s = Symbol::new_for_test(1, 0, 5, &[5]);
        let ready = reorderer.process(s, path, Time::from_secs(1));
        crate::assert_with_log!(
            ready.is_empty(),
            "out-of-order buffered",
            true,
            ready.is_empty()
        );

        let pruned = reorderer.prune(Time::from_secs(100));
        crate::assert_with_log!(pruned == 0, "buffered state retained", 0, pruned);
        let tracked = reorderer.stats().objects_tracked;
        crate::assert_with_log!(tracked == 1, "still tracked", 1, tracked);

        crate::test_complete!("reorderer_prune_keeps_buffered_states");
    }

    #[test]
    fn reorderer_max_objects_fails_open_without_dropping() {
        init_test("reorderer_max_objects_fails_open_without_dropping");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_objects: 2,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);
        let now = Time::ZERO;

        // Two distinct objects fill the cap; each in-order symbol is delivered
        // and creates a state.
        for obj in 1..=2u64 {
            let s = Symbol::new_for_test(obj, 0, 0, &[0]);
            let ready = reorderer.process(s, path, now);
            crate::assert_with_log!(ready.len() == 1, "delivered", 1, ready.len());
        }
        let at_cap = reorderer.stats().objects_tracked;
        crate::assert_with_log!(at_cap == 2, "at cap", 2, at_cap);

        // A third distinct object is past the cap: its symbol is still delivered
        // (fail-open, no loss) but no new reorder state is created.
        let s3 = Symbol::new_for_test(3, 0, 0, &[0]);
        let ready3 = reorderer.process(s3, path, now);
        crate::assert_with_log!(
            ready3.len() == 1,
            "over-cap symbol still delivered",
            1,
            ready3.len()
        );
        let after = reorderer.stats().objects_tracked;
        crate::assert_with_log!(after == 2, "no new state past cap", 2, after);

        crate::test_complete!("reorderer_max_objects_fails_open_without_dropping");
    }

    // Test 9: Reorderer out-of-order buffering
    #[test]
    fn test_reorderer_out_of_order() {
        init_test("test_reorderer_out_of_order");
        let config = ReordererConfig {
            immediate_delivery: false,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver out of order: 0, 2, 1
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);
        let s1 = Symbol::new_for_test(1, 0, 1, &[1]);

        let ready0 = reorderer.process(s0, path, now);
        let len0 = ready0.len();
        crate::assert_with_log!(len0 == 1, "ready0 len", 1, len0); // s0 delivered

        let ready2 = reorderer.process(s2, path, now);
        let len2 = ready2.len();
        crate::assert_with_log!(len2 == 0, "ready2 len", 0, len2); // s2 buffered, waiting for s1

        let ready1 = reorderer.process(s1, path, now);
        let len1 = ready1.len();
        crate::assert_with_log!(len1 == 2, "ready1 len", 2, len1); // s1 and s2 delivered

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.in_order_deliveries == 2,
            "in_order_deliveries",
            2,
            stats.in_order_deliveries
        );
        crate::assert_with_log!(
            stats.reordered_deliveries == 1,
            "reordered_deliveries",
            1,
            stats.reordered_deliveries
        );
        crate::test_complete!("test_reorderer_out_of_order");
    }

    // Test 10: Reorderer timeout flush
    #[test]
    fn test_reorderer_timeout() {
        init_test("test_reorderer_timeout");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_wait_time: Time::from_millis(100),
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);

        // Deliver out of order: 0, 2 (skip 1)
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);

        reorderer.process(s0, path, Time::ZERO);
        reorderer.process(s2, path, Time::from_millis(10));

        // Before timeout
        let flushed = reorderer.flush_timeouts(Time::from_millis(50));
        let len_before = flushed.len();
        crate::assert_with_log!(len_before == 0, "flushed before len", 0, len_before);

        // After timeout
        let flushed = reorderer.flush_timeouts(Time::from_millis(200));
        let len_after = flushed.len();
        crate::assert_with_log!(len_after == 1, "flushed after len", 1, len_after); // s2 flushed
        crate::test_complete!("test_reorderer_timeout");
    }

    // Test 10.1: Reorderer gap too large gives up and advances
    #[test]
    fn test_reorderer_gap_too_large_advances() {
        init_test("test_reorderer_gap_too_large_advances");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_sequence_gap: 2,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        let path = PathId(1);
        let now = Time::ZERO;

        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let s5 = Symbol::new_for_test(1, 0, 5, &[5]);
        let s6 = Symbol::new_for_test(1, 0, 6, &[6]);

        let out0 = reorderer.process(s0, path, now);
        crate::assert_with_log!(out0.len() == 1, "out0 len", 1, out0.len());

        // Gap 4 > max_sequence_gap => deliver immediately and advance
        let out5 = reorderer.process(s5, path, now);
        crate::assert_with_log!(out5.len() == 1, "out5 len", 1, out5.len());

        let out6 = reorderer.process(s6, path, now);
        crate::assert_with_log!(out6.len() == 1, "out6 len", 1, out6.len());

        crate::test_complete!("test_reorderer_gap_too_large_advances");
    }

    // Test 11: MultipathAggregator basic flow
    #[test]
    fn test_aggregator_basic() {
        init_test("test_aggregator_basic");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);

        let result = aggregator.process(symbol.clone(), path, Time::ZERO);
        crate::assert_with_log!(
            !result.was_duplicate,
            "first not duplicate",
            false,
            result.was_duplicate
        );

        // Duplicate
        let result2 = aggregator.process(symbol, path, Time::ZERO);
        crate::assert_with_log!(
            result2.was_duplicate,
            "duplicate flagged",
            true,
            result2.was_duplicate
        );
        let ready_empty = result2.ready.is_empty();
        crate::assert_with_log!(ready_empty, "ready empty", true, ready_empty);
        crate::test_complete!("test_aggregator_basic");
    }

    // Test 11.1: MultipathAggregator deduplicates across paths
    #[test]
    fn test_aggregator_multi_path_dedup() {
        init_test("test_aggregator_multi_path_dedup");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let p1 =
            aggregator
                .paths()
                .create_path("p1", "localhost:1", PathCharacteristics::default());
        let p2 = aggregator
            .paths()
            .create_path("p2", "localhost:2", PathCharacteristics::backup());

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);

        let first = aggregator.process(symbol.clone(), p1, Time::ZERO);
        crate::assert_with_log!(
            !first.was_duplicate,
            "first unique",
            false,
            first.was_duplicate
        );

        let second = aggregator.process(symbol, p2, Time::ZERO);
        crate::assert_with_log!(
            second.was_duplicate,
            "duplicate across paths",
            true,
            second.was_duplicate
        );

        let stats = aggregator.dedup.stats();
        crate::assert_with_log!(
            stats.unique_symbols == 1,
            "unique symbols",
            1,
            stats.unique_symbols
        );
        crate::assert_with_log!(
            stats.duplicates_detected == 1,
            "duplicates detected",
            1,
            stats.duplicates_detected
        );

        let path = aggregator.paths().get(p2);
        crate::assert_with_log!(path.is_some(), "path exists", true, path.is_some());
        if let Some(path) = path {
            let duplicates = path.duplicates_received.load(Ordering::Relaxed);
            crate::assert_with_log!(duplicates == 1, "path duplicates", 1, duplicates);
        }

        crate::test_complete!("test_aggregator_multi_path_dedup");
    }

    #[test]
    fn aggregator_collects_fungible_symbols_from_union_of_sources() {
        init_test("aggregator_collects_fungible_symbols_from_union_of_sources");
        let aggregator = MultipathAggregator::new(AggregatorConfig::default());
        let p1 =
            aggregator
                .paths()
                .create_path("p1", "localhost:1", PathCharacteristics::default());
        let p2 = aggregator
            .paths()
            .create_path("p2", "localhost:2", PathCharacteristics::backup());

        let s0 = Symbol::new_for_test(42, 0, 0, &[0]);
        let object_id = s0.object_id();
        let report = aggregator.collect_fungible_symbols_until(
            object_id,
            3,
            [
                (s0, p1),
                (Symbol::new_for_test(42, 0, 0, &[0]), p2),
                (Symbol::new_for_test(42, 0, 2, &[2]), p2),
                (Symbol::new_for_test(42, 0, 1, &[1]), p1),
            ],
            Time::ZERO,
        );

        assert!(report.complete);
        assert_eq!(report.unique_symbols, 3);
        assert_eq!(report.duplicate_symbols, 1);
        assert_eq!(report.contributing_paths, vec![p1, p2]);
        let stats = aggregator.stats();
        assert_eq!(stats.dedup.unique_symbols, 3);
        assert_eq!(stats.dedup.duplicates_detected, 1);
    }

    #[test]
    fn fungible_collection_does_not_count_over_cap_duplicates_as_progress() {
        init_test("fungible_collection_does_not_count_over_cap_duplicates_as_progress");
        // A per-object cap of 1 forces the dedup past its limit immediately:
        // past the cap `check_and_record` passes every symbol through as unique
        // (so the decoder is never starved), which means it can no longer detect
        // a re-presented duplicate. Without local de-duplication that duplicate
        // would inflate decode progress and let the target be reached with fewer
        // than `target_unique_symbols` distinct symbols — a false completion
        // (fyihql).
        let config = AggregatorConfig {
            dedup: DeduplicatorConfig {
                max_symbols_per_object: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let aggregator = MultipathAggregator::new(config);
        let p1 =
            aggregator
                .paths()
                .create_path("p1", "localhost:1", PathCharacteristics::default());

        let object_id = Symbol::new_for_test(7, 0, 0, &[0]).object_id();
        // esi0 recorded (under cap); esi1 over cap (pass-through, unique); esi1
        // AGAIN over cap (the duplicate that must NOT count); esi2 over cap.
        let report = aggregator.collect_fungible_symbols_until(
            object_id,
            3,
            [
                (Symbol::new_for_test(7, 0, 0, &[0]), p1),
                (Symbol::new_for_test(7, 0, 1, &[1]), p1),
                (Symbol::new_for_test(7, 0, 1, &[1]), p1),
                (Symbol::new_for_test(7, 0, 2, &[2]), p1),
            ],
            Time::ZERO,
        );

        // Exactly 3 DISTINCT symbols (esi0, esi1, esi2); the re-presented esi1
        // is a duplicate, not a fourth unit of progress.
        crate::assert_with_log!(
            report.unique_symbols == 3,
            "distinct unique count",
            3,
            report.unique_symbols
        );
        crate::assert_with_log!(
            report.duplicate_symbols == 1,
            "the over-cap repeat is counted as a duplicate",
            1,
            report.duplicate_symbols
        );
        crate::assert_with_log!(
            report.complete,
            "completes on 3 distinct symbols",
            true,
            report.complete
        );

        crate::test_complete!("fungible_collection_does_not_count_over_cap_duplicates_as_progress");
    }

    #[test]
    fn fungible_symbol_path_bypasses_reorder_buffer_for_raptorq() {
        init_test("fungible_symbol_path_bypasses_reorder_buffer_for_raptorq");
        let aggregator = MultipathAggregator::new(AggregatorConfig {
            enable_reordering: true,
            reorder: ReordererConfig {
                immediate_delivery: false,
                max_sequence_gap: 0,
                ..Default::default()
            },
            ..Default::default()
        });
        let path = aggregator.paths().create_path(
            "source-a",
            "localhost:7000",
            PathCharacteristics::default(),
        );

        let result = aggregator.process_fungible_symbol(
            Symbol::new_for_test(77, 0, 9, &[9]),
            path,
            Time::ZERO,
        );

        assert!(!result.was_duplicate);
        assert_eq!(result.path, path);
        assert_eq!(result.first_path, Some(path));
        assert_eq!(result.ready.as_ref().map(Symbol::esi), Some(9));
        let stats = aggregator.stats();
        assert_eq!(
            stats.reorder.symbols_buffered, 0,
            "fungible RaptorQ symbols should not enter sequence reorder buffers"
        );
    }

    // Test 12: MultipathAggregator object completion
    #[test]
    fn test_aggregator_object_complete() {
        init_test("test_aggregator_object_complete");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let object_id = symbol.object_id();

        aggregator.process(symbol.clone(), path, Time::ZERO);

        // Clear state
        aggregator.object_complete(object_id);

        // Same symbol is now "new" again
        let result = aggregator.process(symbol, path, Time::ZERO);
        crate::assert_with_log!(
            !result.was_duplicate,
            "post-complete not duplicate",
            false,
            result.was_duplicate
        );
        crate::test_complete!("test_aggregator_object_complete");
    }

    // Test 13: PathSet aggregate stats
    #[test]
    fn test_path_set_stats() {
        init_test("test_path_set_stats");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        let p1 = set.create_path(
            "p1",
            "a",
            PathCharacteristics {
                bandwidth_bps: 1_000_000,
                ..Default::default()
            },
        );
        let p2 = set.create_path(
            "p2",
            "b",
            PathCharacteristics {
                bandwidth_bps: 2_000_000,
                ..Default::default()
            },
        );

        if let Some(path) = set.get(p1) {
            path.symbols_received.store(100, Ordering::Relaxed);
        }
        if let Some(path) = set.get(p2) {
            path.symbols_received.store(200, Ordering::Relaxed);
        }

        let stats = set.stats();
        crate::assert_with_log!(stats.path_count == 2, "path_count", 2, stats.path_count);
        crate::assert_with_log!(
            stats.total_received == 300,
            "total_received",
            300,
            stats.total_received
        );
        crate::assert_with_log!(
            stats.aggregate_bandwidth_bps == 3_000_000,
            "aggregate_bandwidth_bps",
            3_000_000,
            stats.aggregate_bandwidth_bps
        );
        crate::test_complete!("test_path_set_stats");
    }

    #[test]
    fn path_set_stats_aggregate_bandwidth_counts_only_usable_paths() {
        init_test("path_set_stats_aggregate_bandwidth_counts_only_usable_paths");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        let active = set.create_path(
            "active",
            "active.example:8080",
            PathCharacteristics {
                bandwidth_bps: 1_000_000,
                ..Default::default()
            },
        );
        let degraded = set.create_path(
            "degraded",
            "degraded.example:8080",
            PathCharacteristics {
                bandwidth_bps: 2_000_000,
                ..Default::default()
            },
        );
        let unavailable = set.create_path(
            "unavailable",
            "unavailable.example:8080",
            PathCharacteristics {
                bandwidth_bps: 4_000_000,
                ..Default::default()
            },
        );
        let closed = set.create_path(
            "closed",
            "closed.example:8080",
            PathCharacteristics {
                bandwidth_bps: 8_000_000,
                ..Default::default()
            },
        );

        set.set_state(degraded, PathState::Degraded);
        set.set_state(unavailable, PathState::Unavailable);
        set.set_state(closed, PathState::Closed);

        if let Some(path) = set.get(active) {
            path.symbols_received.store(10, Ordering::Relaxed);
        }
        if let Some(path) = set.get(unavailable) {
            path.symbols_received.store(99, Ordering::Relaxed);
        }

        let stats = set.stats();
        crate::assert_with_log!(stats.path_count == 4, "path_count", 4, stats.path_count);
        crate::assert_with_log!(
            stats.usable_count == 2,
            "active + degraded are usable",
            2,
            stats.usable_count
        );
        crate::assert_with_log!(
            stats.aggregate_bandwidth_bps == 3_000_000,
            "aggregate bandwidth excludes unavailable and closed paths",
            3_000_000,
            stats.aggregate_bandwidth_bps
        );
        crate::assert_with_log!(
            stats.total_received == 109,
            "symbol counters remain state-independent",
            109,
            stats.total_received
        );
        crate::test_complete!("path_set_stats_aggregate_bandwidth_counts_only_usable_paths");
    }

    // Test 14: Immediate delivery mode
    #[test]
    fn test_immediate_delivery() {
        init_test("test_immediate_delivery");
        let config = ReordererConfig {
            immediate_delivery: true,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);

        // Out of order should still deliver immediately
        let s5 = Symbol::new_for_test(1, 0, 5, &[5]);
        let ready = reorderer.process(s5, PathId(1), Time::ZERO);

        let len = ready.len();
        crate::assert_with_log!(len == 1, "ready len", 1, len);
        crate::test_complete!("test_immediate_delivery");
    }

    // Test 15: Aggregator stats
    #[test]
    fn test_aggregator_stats() {
        init_test("test_aggregator_stats");
        let config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(config);

        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        for i in 0..10 {
            let symbol = Symbol::new_for_test(1, 0, i, &[i as u8]);
            aggregator.process(symbol, path, Time::ZERO);
        }

        let stats = aggregator.stats();
        crate::assert_with_log!(
            stats.total_processed == 10,
            "total_processed",
            10,
            stats.total_processed
        );
        crate::assert_with_log!(
            stats.paths.path_count == 1,
            "path_count",
            1,
            stats.paths.path_count
        );
        crate::test_complete!("test_aggregator_stats");
    }

    // ========================================================================
    // Audit regression tests
    // ========================================================================

    #[test]
    fn flush_respects_interval_gating() {
        init_test("flush_respects_interval_gating");
        let config = AggregatorConfig {
            flush_interval: Time::from_millis(100),
            ..Default::default()
        };
        let aggregator = MultipathAggregator::new(config);
        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        // Process a symbol with out-of-order ESI to put something in the reorderer buffer
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);
        aggregator.process(s2, path, Time::ZERO);

        // Flush too soon — should return empty
        let early = aggregator.flush(Time::from_millis(50));
        crate::assert_with_log!(
            early.is_empty(),
            "flush before interval returns empty",
            true,
            early.is_empty()
        );

        // Flush after interval — should succeed
        let later = aggregator.flush(Time::from_millis(200));
        // Symbol 2 was buffered waiting for 0,1 — if max_wait_time passed, it should flush
        // (default max_wait_time is 100ms, and symbol was received at t=0, flush at t=200)
        crate::assert_with_log!(
            later.len() == 1,
            "flush after interval returns buffered symbol",
            1,
            later.len()
        );

        crate::test_complete!("flush_respects_interval_gating");
    }

    #[test]
    fn dedup_prune_removes_expired_objects() {
        init_test("dedup_prune_removes_expired_objects");
        let config = DeduplicatorConfig {
            entry_ttl: Time::from_secs(10),
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);
        let path = PathId(1);

        // Record a symbol at t=0
        let s = Symbol::new_for_test(1, 0, 0, &[1]);
        dedup.check_and_record(&s, path, Time::ZERO);

        let before = dedup.stats();
        crate::assert_with_log!(
            before.objects_tracked == 1,
            "1 object tracked before prune",
            1,
            before.objects_tracked
        );

        // Prune at t=5 (within TTL) — should keep
        let pruned_early = dedup.prune(Time::from_secs(5));
        crate::assert_with_log!(pruned_early == 0, "nothing pruned early", 0, pruned_early);

        // Prune at t=15 (past TTL) — should remove
        let pruned_late = dedup.prune(Time::from_secs(15));
        crate::assert_with_log!(pruned_late == 1, "1 object pruned", 1, pruned_late);

        let after = dedup.stats();
        crate::assert_with_log!(
            after.objects_tracked == 0,
            "0 objects after prune",
            0,
            after.objects_tracked
        );

        crate::test_complete!("dedup_prune_removes_expired_objects");
    }

    #[test]
    fn reorderer_late_duplicate_ignored() {
        init_test("reorderer_late_duplicate_ignored");
        let config = ReordererConfig {
            immediate_delivery: false,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver 0, 1, 2 in order
        reorderer.process(Symbol::new_for_test(1, 0, 0, &[0]), path, now);
        reorderer.process(Symbol::new_for_test(1, 0, 1, &[1]), path, now);
        reorderer.process(Symbol::new_for_test(1, 0, 2, &[2]), path, now);

        // Late duplicate: seq 0 again
        let late = reorderer.process(Symbol::new_for_test(1, 0, 0, &[0]), path, now);
        crate::assert_with_log!(
            late.is_empty(),
            "late duplicate produces no output",
            true,
            late.is_empty()
        );

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.in_order_deliveries == 3,
            "still 3 in-order deliveries",
            3,
            stats.in_order_deliveries
        );

        crate::test_complete!("reorderer_late_duplicate_ignored");
    }

    #[test]
    fn path_set_round_robin_cycles() {
        init_test("path_set_round_robin_cycles");
        let set = PathSet::new(PathSelectionPolicy::RoundRobin);

        set.register(test_path(2));
        set.register(test_path(1));

        // RoundRobin should select one path per call, cycling through
        let mut ids = Vec::new();
        for _ in 0..4 {
            let selected = set.select_paths();
            crate::assert_with_log!(
                selected.len() == 1,
                "round robin selects 1",
                1,
                selected.len()
            );
            ids.push(selected[0].id);
        }

        crate::assert_with_log!(
            ids == vec![PathId(1), PathId(2), PathId(1), PathId(2)],
            "round robin follows stable PathId order",
            vec![PathId(1), PathId(2), PathId(1), PathId(2)],
            ids
        );

        crate::test_complete!("path_set_round_robin_cycles");
    }

    #[test]
    fn metamorphic_round_robin_ignores_registration_order_and_unusable_decoys() {
        init_test("metamorphic_round_robin_ignores_registration_order_and_unusable_decoys");

        fn round_robin_sequence(
            registration_order: &[u64],
            include_unusable_decoys: bool,
        ) -> Vec<PathId> {
            let set = PathSet::new(PathSelectionPolicy::RoundRobin);
            for id in registration_order {
                set.register(test_path(*id));
            }

            if include_unusable_decoys {
                let low_decoy = test_path(0);
                low_decoy.set_state(PathState::Unavailable);
                set.register(low_decoy);

                let high_decoy = test_path(99);
                high_decoy.set_state(PathState::Closed);
                set.register(high_decoy);
            }

            (0..6)
                .map(|_| {
                    let selected = set.select_paths();
                    assert_eq!(selected.len(), 1);
                    selected[0].id
                })
                .collect()
        }

        let baseline = round_robin_sequence(&[3, 1, 2], false);
        let permuted_with_decoys = round_robin_sequence(&[2, 3, 1], true);

        assert_eq!(
            baseline, permuted_with_decoys,
            "round-robin path cycling must depend on usable PathId membership, not insertion order or unusable paths"
        );

        crate::test_complete!(
            "metamorphic_round_robin_ignores_registration_order_and_unusable_decoys"
        );
    }

    #[test]
    fn path_set_remove_path() {
        init_test("path_set_remove_path");
        let set = PathSet::new(PathSelectionPolicy::UseAll);

        let id = set.register(test_path(1));
        set.register(test_path(2));

        crate::assert_with_log!(set.count() == 2, "2 paths", 2, set.count());

        let removed = set.remove(id);
        crate::assert_with_log!(removed.is_some(), "removed path", true, removed.is_some());
        crate::assert_with_log!(set.count() == 1, "1 path after remove", 1, set.count());

        // Remove again — should return None
        let removed_again = set.remove(id);
        crate::assert_with_log!(
            removed_again.is_none(),
            "double remove returns None",
            true,
            removed_again.is_none()
        );

        crate::test_complete!("path_set_remove_path");
    }

    #[test]
    fn aggregation_error_display_variants() {
        init_test("aggregation_error_display_variants");

        let e1 = AggregationError::PathNotFound { path: PathId(42) };
        crate::assert_with_log!(
            e1.to_string().contains("42"),
            "path not found contains id",
            true,
            e1.to_string().contains("42")
        );

        let e2 = AggregationError::PathUnavailable { path: PathId(7) };
        crate::assert_with_log!(
            e2.to_string().contains("unavailable"),
            "path unavailable display",
            true,
            e2.to_string().contains("unavailable")
        );

        let e3 = AggregationError::InvalidSequence {
            object_id: ObjectId::new(0, 1),
            expected: 5,
            received: 10,
        };
        let msg = e3.to_string();
        crate::assert_with_log!(
            msg.contains("expected 5") && msg.contains("got 10"),
            "invalid sequence display",
            true,
            msg.contains("expected 5") && msg.contains("got 10")
        );

        crate::test_complete!("aggregation_error_display_variants");
    }

    // ========================================================================
    // Bug-fix regression tests
    // ========================================================================

    /// Regression: large gap reset must drain buffered symbols, not drop them.
    #[test]
    fn reorderer_large_gap_delivers_buffered_before_reset() {
        init_test("reorderer_large_gap_delivers_buffered_before_reset");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_sequence_gap: 3,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);
        let now = Time::ZERO;

        // Deliver seq 0 in-order.
        let s0 = Symbol::new_for_test(1, 0, 0, &[0]);
        let out0 = reorderer.process(s0, path, now);
        crate::assert_with_log!(out0.len() == 1, "s0 delivered", 1, out0.len());

        // Buffer seq 2 and 3 (out-of-order, waiting for seq 1).
        let s2 = Symbol::new_for_test(1, 0, 2, &[2]);
        let s3 = Symbol::new_for_test(1, 0, 3, &[3]);
        let out2 = reorderer.process(s2, path, now);
        let out3 = reorderer.process(s3, path, now);
        crate::assert_with_log!(out2.is_empty(), "s2 buffered", 0, out2.len());
        crate::assert_with_log!(out3.is_empty(), "s3 buffered", 0, out3.len());

        // Now deliver seq 100 — gap is 99 > max_sequence_gap(3).
        // Buffered symbols 2 and 3 must be delivered, not dropped.
        let s100 = Symbol::new_for_test(1, 0, 100, &[100]);
        let out100 = reorderer.process(s100, path, now);
        crate::assert_with_log!(
            out100.len() == 3,
            "large gap delivers buffered + new",
            3,
            out100.len()
        );

        crate::test_complete!("reorderer_large_gap_delivers_buffered_before_reset");
    }

    /// Regression: dedup must enforce max_objects limit.
    #[test]
    fn dedup_enforces_max_objects() {
        init_test("dedup_enforces_max_objects");
        let config = DeduplicatorConfig {
            max_objects: 2,
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);
        let path = PathId(1);

        // Record symbols for 2 different objects — both should be tracked.
        let s1 = Symbol::new_for_test(1, 0, 0, &[1]);
        let s2 = Symbol::new_for_test(2, 0, 0, &[2]);
        crate::assert_with_log!(
            dedup.check_and_record(&s1, path, Time::ZERO),
            "obj1 unique",
            true,
            true
        );
        crate::assert_with_log!(
            dedup.check_and_record(&s2, path, Time::ZERO),
            "obj2 unique",
            true,
            true
        );

        // Third object exceeds max_objects — should still return true (unique)
        // but NOT be tracked (so a duplicate won't be detected).
        let s3 = Symbol::new_for_test(3, 0, 0, &[3]);
        let result = dedup.check_and_record(&s3, path, Time::ZERO);
        crate::assert_with_log!(result, "obj3 treated as unique", true, result);

        let stats = dedup.stats();
        crate::assert_with_log!(
            stats.objects_tracked == 2,
            "only 2 objects tracked",
            2,
            stats.objects_tracked
        );
        crate::assert_with_log!(
            stats.unique_symbols == 3,
            "all unique symbols counted",
            3,
            stats.unique_symbols
        );

        crate::test_complete!("dedup_enforces_max_objects");
    }

    /// Regression: dedup must enforce max_symbols_per_object limit.
    #[test]
    fn dedup_enforces_max_symbols_per_object() {
        init_test("dedup_enforces_max_symbols_per_object");
        let config = DeduplicatorConfig {
            max_symbols_per_object: 3,
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);
        let path = PathId(1);

        // Record 3 symbols for object 1 — all should be tracked.
        for i in 0..3 {
            let s = Symbol::new_for_test(1, 0, i, &[i as u8]);
            let unique = dedup.check_and_record(&s, path, Time::ZERO);
            crate::assert_with_log!(unique, "symbol unique", true, unique);
        }

        // 4th symbol for the same object exceeds the limit: it is NOT recorded
        // but is still reported unique (passed through), because the per-object
        // `seen` set spans all of an object's blocks and discarding past-cap
        // symbols would starve the RaptorQ decoder on any multi-block transfer.
        // De-duplication of past-cap symbols is the consumer's responsibility
        // (see collect_fungible_symbols_until, fyihql).
        let s4 = Symbol::new_for_test(1, 0, 3, &[3]);
        let result = dedup.check_and_record(&s4, path, Time::ZERO);
        crate::assert_with_log!(
            result,
            "over-limit symbol passed through as unique (not starved)",
            true,
            result
        );

        let stats = dedup.stats();
        crate::assert_with_log!(
            stats.symbols_tracked == 3,
            "only 3 symbols tracked",
            3,
            stats.symbols_tracked
        );
        crate::assert_with_log!(
            stats.unique_symbols == 4,
            "all unique symbols counted",
            4,
            stats.unique_symbols
        );

        crate::test_complete!("dedup_enforces_max_symbols_per_object");
    }

    #[test]
    fn dedup_zero_symbol_capacity_does_not_track_empty_objects() {
        init_test("dedup_zero_symbol_capacity_does_not_track_empty_objects");
        let config = DeduplicatorConfig {
            max_symbols_per_object: 0,
            ..Default::default()
        };
        let dedup = SymbolDeduplicator::new(config);
        let path = PathId(1);
        let symbol = Symbol::new_for_test(1, 0, 0, &[1]);

        let first = dedup.check_and_record(&symbol, path, Time::ZERO);
        let second = dedup.check_and_record(&symbol, path, Time::ZERO);

        crate::assert_with_log!(
            first && second,
            "zero symbol capacity treats every arrival as untracked unique",
            true,
            first && second
        );
        let stats = dedup.stats();
        crate::assert_with_log!(
            stats.objects_tracked == 0,
            "zero symbol capacity must not leave empty per-object state",
            0,
            stats.objects_tracked
        );
        crate::assert_with_log!(
            stats.symbols_tracked == 0,
            "zero symbol capacity must not track symbol ids",
            0,
            stats.symbols_tracked
        );
        crate::assert_with_log!(
            stats.unique_symbols == 2,
            "untracked arrivals are still counted as unique attempts",
            2,
            stats.unique_symbols
        );
        crate::assert_with_log!(
            stats.duplicates_detected == 0,
            "untracked arrivals cannot be classified as duplicates",
            0,
            stats.duplicates_detected
        );

        crate::test_complete!("dedup_zero_symbol_capacity_does_not_track_empty_objects");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn aggregator_buffer_full_forces_flush() {
        init_test("aggregator_buffer_full_forces_flush");
        let config = AggregatorConfig {
            reorder: ReordererConfig {
                immediate_delivery: false,
                max_buffer_per_object: 1,
                max_sequence_gap: 10,
                ..Default::default()
            },
            ..Default::default()
        };
        let aggregator = MultipathAggregator::new(config);
        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        // Deliver seq 0, buffer seq 2, then flush seq 2 and deliver seq 3 because the reorder buffer is full.
        let seq0 = aggregator.process(Symbol::new_for_test(1, 0, 0, &[0]), path, Time::ZERO);
        crate::assert_with_log!(
            seq0.ready.len() == 1,
            "seq0 delivered immediately",
            1,
            seq0.ready.len()
        );

        let seq2 = aggregator.process(
            Symbol::new_for_test(1, 0, 2, &[2]),
            path,
            Time::from_millis(1),
        );
        crate::assert_with_log!(
            seq2.ready.is_empty(),
            "seq2 buffered with no output",
            true,
            seq2.ready.is_empty()
        );

        let first_seq3 = aggregator.process(
            Symbol::new_for_test(1, 0, 3, &[3]),
            path,
            Time::from_millis(2),
        );
        crate::assert_with_log!(
            !first_seq3.was_duplicate,
            "buffer-full flush is not classified as duplicate",
            false,
            first_seq3.was_duplicate
        );
        crate::assert_with_log!(
            first_seq3.ready.len() == 2,
            "buffer-full flush produces buffered output",
            2,
            first_seq3.ready.len()
        );
        crate::assert_with_log!(
            first_seq3.ready[0].esi() == 2,
            "buffer-full flush produces seq2",
            2,
            first_seq3.ready[0].esi()
        );
        crate::assert_with_log!(
            first_seq3.ready[1].esi() == 3,
            "buffer-full flush produces seq3",
            3,
            first_seq3.ready[1].esi()
        );

        let stats = aggregator.dedup.stats();
        crate::assert_with_log!(
            stats.unique_symbols == 3,
            "dedup unique count tracks the three delivered symbols",
            3,
            stats.unique_symbols
        );
        crate::assert_with_log!(
            stats.symbols_tracked == 3,
            "dedup tracks the three delivered symbols only",
            3,
            stats.symbols_tracked
        );

        crate::test_complete!("aggregator_buffer_full_forces_flush");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn aggregator_delivers_late_unique_symbol_after_gap_advance_once() {
        init_test("aggregator_delivers_late_unique_symbol_after_gap_advance_once");
        let config = AggregatorConfig {
            reorder: ReordererConfig {
                immediate_delivery: false,
                max_sequence_gap: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let aggregator = MultipathAggregator::new(config);
        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        let seq0 = aggregator.process(Symbol::new_for_test(1, 0, 0, &[0]), path, Time::ZERO);
        crate::assert_with_log!(
            seq0.ready.len() == 1,
            "seq0 delivered immediately",
            1,
            seq0.ready.len()
        );

        let seq2 = aggregator.process(
            Symbol::new_for_test(1, 0, 2, &[2]),
            path,
            Time::from_millis(1),
        );
        crate::assert_with_log!(
            seq2.ready.len() == 1,
            "large gap advances past missing seq1 and delivers seq2",
            1,
            seq2.ready.len()
        );

        let late_seq1 = aggregator.process(
            Symbol::new_for_test(1, 0, 1, &[1]),
            path,
            Time::from_millis(2),
        );
        crate::assert_with_log!(
            !late_seq1.was_duplicate,
            "late seq1 is unique on first arrival",
            false,
            late_seq1.was_duplicate
        );
        crate::assert_with_log!(
            late_seq1.ready.len() == 1,
            "late unique seq1 is still delivered to fungible decoder",
            1,
            late_seq1.ready.len()
        );
        crate::assert_with_log!(
            late_seq1.ready[0].esi() == 1,
            "late unique output is seq1",
            1,
            late_seq1.ready[0].esi()
        );

        let duplicate_seq1 = aggregator.process(
            Symbol::new_for_test(1, 0, 1, &[1]),
            path,
            Time::from_millis(3),
        );
        crate::assert_with_log!(
            duplicate_seq1.was_duplicate,
            "retransmitted late seq1 is still deduped",
            true,
            duplicate_seq1.was_duplicate
        );
        crate::assert_with_log!(
            duplicate_seq1.ready.is_empty(),
            "duplicate late seq1 produces no output",
            true,
            duplicate_seq1.ready.is_empty()
        );

        let stats = aggregator.dedup.stats();
        crate::assert_with_log!(
            stats.unique_symbols == 3,
            "dedup tracks seq0 seq2 and late seq1 as unique",
            3,
            stats.unique_symbols
        );
        crate::assert_with_log!(
            stats.duplicates_detected == 1,
            "dedup rejects retransmitted late seq1",
            1,
            stats.duplicates_detected
        );

        crate::test_complete!("aggregator_delivers_late_unique_symbol_after_gap_advance_once");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn aggregator_delivers_late_unique_symbol_after_timeout_advance_once() {
        init_test("aggregator_delivers_late_unique_symbol_after_timeout_advance_once");
        let config = AggregatorConfig {
            reorder: ReordererConfig {
                immediate_delivery: false,
                max_sequence_gap: 10,
                max_wait_time: Time::from_millis(5),
                ..Default::default()
            },
            flush_interval: Time::ZERO,
            ..Default::default()
        };
        let aggregator = MultipathAggregator::new(config);
        let path = aggregator.paths().create_path(
            "test",
            "localhost:8080",
            PathCharacteristics::default(),
        );

        let seq0 = aggregator.process(Symbol::new_for_test(1, 0, 0, &[0]), path, Time::ZERO);
        crate::assert_with_log!(
            seq0.ready.len() == 1,
            "seq0 delivered immediately",
            1,
            seq0.ready.len()
        );

        let seq2 = aggregator.process(
            Symbol::new_for_test(1, 0, 2, &[2]),
            path,
            Time::from_millis(1),
        );
        crate::assert_with_log!(
            seq2.ready.is_empty(),
            "seq2 buffered while waiting for seq1",
            true,
            seq2.ready.is_empty()
        );

        let flushed = aggregator.flush(Time::from_millis(10));
        crate::assert_with_log!(
            flushed.len() == 1,
            "timeout advances past missing seq1 and flushes seq2",
            1,
            flushed.len()
        );
        crate::assert_with_log!(
            flushed[0].esi() == 2,
            "timeout flush output is seq2",
            2,
            flushed[0].esi()
        );

        let late_seq1 = aggregator.process(
            Symbol::new_for_test(1, 0, 1, &[1]),
            path,
            Time::from_millis(11),
        );
        crate::assert_with_log!(
            !late_seq1.was_duplicate,
            "late seq1 after timeout advance is unique on first arrival",
            false,
            late_seq1.was_duplicate
        );
        crate::assert_with_log!(
            late_seq1.ready.len() == 1,
            "late unique seq1 is delivered after timeout advance",
            1,
            late_seq1.ready.len()
        );
        crate::assert_with_log!(
            late_seq1.ready[0].esi() == 1,
            "late unique timeout output is seq1",
            1,
            late_seq1.ready[0].esi()
        );

        let duplicate_seq1 = aggregator.process(
            Symbol::new_for_test(1, 0, 1, &[1]),
            path,
            Time::from_millis(12),
        );
        crate::assert_with_log!(
            duplicate_seq1.was_duplicate,
            "retransmitted timeout-late seq1 is still deduped",
            true,
            duplicate_seq1.was_duplicate
        );
        crate::assert_with_log!(
            duplicate_seq1.ready.is_empty(),
            "duplicate timeout-late seq1 produces no output",
            true,
            duplicate_seq1.ready.is_empty()
        );

        let stats = aggregator.dedup.stats();
        crate::assert_with_log!(
            stats.unique_symbols == 3,
            "dedup tracks seq0 seq2 and timeout-late seq1 as unique",
            3,
            stats.unique_symbols
        );
        crate::assert_with_log!(
            stats.duplicates_detected == 1,
            "dedup rejects retransmitted timeout-late seq1",
            1,
            stats.duplicates_detected
        );

        crate::test_complete!("aggregator_delivers_late_unique_symbol_after_timeout_advance_once");
    }

    /// Flush timeout advances next_expected and drains consecutive.
    #[test]
    fn flush_timeout_drains_consecutive_after_advance() {
        init_test("flush_timeout_drains_consecutive_after_advance");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_wait_time: Time::from_millis(50),
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);

        // Deliver seq 0.
        reorderer.process(Symbol::new_for_test(1, 0, 0, &[0]), path, Time::ZERO);

        // Buffer seq 2 at t=0 (will time out at t=50).
        reorderer.process(Symbol::new_for_test(1, 0, 2, &[2]), path, Time::ZERO);

        // Buffer seq 3 at t=40 (will time out at t=90).
        reorderer.process(
            Symbol::new_for_test(1, 0, 3, &[3]),
            path,
            Time::from_millis(40),
        );

        // Flush at t=60: seq 2 timed out (waited 60ms > 50ms).
        // Seq 3 has NOT timed out (waited 20ms < 50ms).
        // After flushing seq 2, next_expected advances to 3,
        // and the consecutive drain pops seq 3 from the buffer.
        let flushed = reorderer.flush_timeouts(Time::from_millis(60));
        crate::assert_with_log!(
            flushed.len() == 2,
            "seq 2 flushed + seq 3 drained",
            2,
            flushed.len()
        );

        let stats = reorderer.stats();
        crate::assert_with_log!(
            stats.symbols_buffered == 0,
            "buffer empty after drain",
            0,
            stats.symbols_buffered
        );

        crate::test_complete!("flush_timeout_drains_consecutive_after_advance");
    }

    #[test]
    fn reorderer_large_gap_u32_max_does_not_overflow() {
        init_test("reorderer_large_gap_u32_max_does_not_overflow");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_sequence_gap: 1,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);

        // seq=u32::MAX when next_expected=0 is a late duplicate in wrapping
        // arithmetic (u32::MAX is logically just before 0), so it is dropped.
        let out = reorderer.process(Symbol::new_for_test(1, 0, u32::MAX, &[1]), path, Time::ZERO);
        crate::assert_with_log!(
            out.is_empty(),
            "u32::MAX is late dup (wrapping)",
            true,
            out.is_empty()
        );

        // Verify a genuine forward gap still works: seq=2 when next_expected=0.
        let out2 = reorderer.process(Symbol::new_for_test(1, 0, 2, &[2]), path, Time::ZERO);
        // gap=2 > max_sequence_gap=1, so gap-too-large branch delivers it.
        crate::assert_with_log!(out2.len() == 1, "forward gap delivered", 1, out2.len());

        crate::test_complete!("reorderer_large_gap_u32_max_does_not_overflow");
    }

    #[test]
    fn flush_timeouts_handles_large_seq_cutoff() {
        init_test("flush_timeouts_handles_large_seq_cutoff");
        let config = ReordererConfig {
            immediate_delivery: false,
            max_wait_time: Time::from_millis(1),
            // Allow a forward gap up to i32::MAX (half the u32 space) which
            // is the maximum representable forward distance in wrapping arithmetic.
            max_sequence_gap: i32::MAX as u32,
            ..Default::default()
        };
        let reorderer = SymbolReorderer::new(config);
        let path = PathId(1);

        // Forward gap of 100 from next_expected=0 → buffered.
        let out = reorderer.process(Symbol::new_for_test(1, 0, 100, &[9]), path, Time::ZERO);
        crate::assert_with_log!(
            out.is_empty(),
            "seq=100 symbol buffered",
            true,
            out.is_empty()
        );

        let flushed = reorderer.flush_timeouts(Time::from_millis(2));
        crate::assert_with_log!(
            flushed.len() == 1,
            "flush emits buffered symbol",
            1,
            flushed.len()
        );
        crate::assert_with_log!(
            flushed[0].esi() == 100,
            "flushed esi is 100",
            100,
            flushed[0].esi()
        );

        crate::test_complete!("flush_timeouts_handles_large_seq_cutoff");
    }

    // =========================================================================
    // Wave 29: Data-type trait coverage
    // =========================================================================

    #[test]
    fn path_id_debug_clone_copy_display() {
        let id = PathId::new(42);
        assert!(format!("{id:?}").contains("42"));
        assert_eq!(format!("{id}"), "Path(42)");
        let cloned = id;
        let copied = id; // Copy
        assert_eq!(cloned, copied);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn path_id_ord_hash() {
        use std::collections::HashSet;
        let a = PathId(1);
        let b = PathId(2);
        assert!(a < b);
        assert!(b > a);
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(a); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn path_state_debug_clone_copy_eq() {
        let state = PathState::Active;
        assert!(format!("{state:?}").contains("Active"));
        let cloned = state;
        let copied = state; // Copy
        assert_eq!(cloned, copied);
        assert_ne!(PathState::Active, PathState::Closed);
    }

    #[test]
    fn path_state_from_u8_all_variants() {
        assert_eq!(PathState::from_u8(0), PathState::Active);
        assert_eq!(PathState::from_u8(1), PathState::Degraded);
        assert_eq!(PathState::from_u8(2), PathState::Unavailable);
        assert_eq!(PathState::from_u8(3), PathState::Closed);
        assert_eq!(PathState::from_u8(255), PathState::Closed); // fallback
    }

    #[test]
    fn path_characteristics_debug_clone_default() {
        let chars = PathCharacteristics::default();
        assert!(format!("{chars:?}").contains("PathCharacteristics"));
        assert_eq!(chars.latency_ms, 50);
        assert_eq!(chars.bandwidth_bps, 1_000_000);
        assert!((chars.loss_rate - 0.01).abs() < f64::EPSILON);
        assert_eq!(chars.jitter_ms, 10);
        assert!(!chars.is_primary);
        assert_eq!(chars.priority, 100);
        let cloned = chars.clone();
        assert_eq!(cloned.latency_ms, chars.latency_ms);
    }

    #[test]
    fn path_selection_policy_debug_clone_copy_default() {
        let policy = PathSelectionPolicy::default();
        assert_eq!(policy, PathSelectionPolicy::UseAll);
        assert!(format!("{policy:?}").contains("UseAll"));
        let cloned = policy;
        let copied = policy; // Copy
        assert_eq!(cloned, copied);
    }

    #[test]
    fn path_set_stats_debug_clone() {
        let stats = PathSetStats {
            path_count: 3,
            usable_count: 2,
            total_received: 100,
            total_lost: 5,
            total_duplicates: 10,
            aggregate_bandwidth_bps: 5_000_000,
        };
        assert!(format!("{stats:?}").contains("PathSetStats"));
        let stats2 = stats;
        assert_eq!(stats2.path_count, 3);
        assert_eq!(stats2.total_received, 100);
    }

    #[test]
    fn deduplicator_config_debug_clone_default() {
        let config = DeduplicatorConfig::default();
        assert!(format!("{config:?}").contains("DeduplicatorConfig"));
        assert_eq!(config.max_symbols_per_object, 10_000);
        assert_eq!(config.max_objects, 1_000);
        assert!(config.track_path);
        let cloned = config.clone();
        assert_eq!(cloned.max_objects, config.max_objects);
    }

    #[test]
    fn deduplicator_stats_debug_clone() {
        let stats = DeduplicatorStats {
            objects_tracked: 5,
            symbols_tracked: 50,
            duplicates_detected: 3,
            unique_symbols: 47,
        };
        assert!(format!("{stats:?}").contains("DeduplicatorStats"));
        let stats2 = stats;
        assert_eq!(stats2.objects_tracked, 5);
    }

    #[test]
    fn reorderer_config_debug_clone_default() {
        let config = ReordererConfig::default();
        assert!(format!("{config:?}").contains("ReordererConfig"));
        assert_eq!(config.max_buffer_per_object, 1_000);
        assert!(!config.immediate_delivery);
        assert_eq!(config.max_sequence_gap, 100);
        let cloned = config.clone();
        assert_eq!(cloned.max_buffer_per_object, config.max_buffer_per_object);
    }

    #[test]
    fn reorderer_stats_debug_clone() {
        let stats = ReordererStats {
            objects_tracked: 2,
            symbols_buffered: 10,
            in_order_deliveries: 50,
            reordered_deliveries: 5,
            timeout_deliveries: 1,
        };
        assert!(format!("{stats:?}").contains("ReordererStats"));
        let stats2 = stats;
        assert_eq!(stats2.symbols_buffered, 10);
    }

    #[test]
    fn aggregator_config_debug_clone_default() {
        let config = AggregatorConfig::default();
        assert!(format!("{config:?}").contains("AggregatorConfig"));
        assert!(config.enable_reordering);
        assert_eq!(config.path_policy, PathSelectionPolicy::UseAll);
        let cloned = config.clone();
        assert_eq!(cloned.enable_reordering, config.enable_reordering);
    }

    #[test]
    fn aggregation_error_debug_clone() {
        let err = AggregationError::PathNotFound { path: PathId(1) };
        assert!(format!("{err:?}").contains("PathNotFound"));
        let cloned = err;
        assert!(format!("{cloned}").contains("not found"));
    }

    #[test]
    fn aggregation_error_is_std_error() {
        let err: &dyn std::error::Error = &AggregationError::PathUnavailable { path: PathId(1) };
        let _ = format!("{err}");
        assert!(err.source().is_none());
    }

    #[test]
    fn aggregation_error_into_error() {
        let err = AggregationError::BufferOverflow {
            object_id: ObjectId::new(0, 1),
        };
        let generic: Error = err.into();
        let msg = format!("{generic}");
        assert!(msg.contains("buffer overflow") || msg.contains("overflow"));
    }

    #[test]
    fn transport_path_state_transitions() {
        let path = test_path(1);
        assert_eq!(path.state(), PathState::Active);
        path.set_state(PathState::Degraded);
        assert_eq!(path.state(), PathState::Degraded);
        path.set_state(PathState::Closed);
        assert_eq!(path.state(), PathState::Closed);
    }

    #[test]
    fn transport_path_zero_stats_rates() {
        let path = test_path(1);
        assert!((path.effective_loss_rate() - 0.0).abs() < f64::EPSILON);
        assert!((path.duplicate_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn process_result_debug() {
        let result = ProcessResult {
            ready: vec![],
            was_duplicate: false,
            path: PathId(1),
        };
        assert!(format!("{result:?}").contains("ProcessResult"));
    }

    // ========================================================================
    // Audit regression: quality_score with zero bandwidth (SapphireHill 2026-03-12)
    // ========================================================================

    #[test]
    fn quality_score_zero_bandwidth_is_finite() {
        init_test("quality_score_zero_bandwidth_is_finite");
        let chars = PathCharacteristics {
            bandwidth_bps: 0,
            ..Default::default()
        };
        let score = chars.quality_score();
        crate::assert_with_log!(
            score.is_finite(),
            "zero bandwidth produces finite score",
            true,
            score.is_finite()
        );
        crate::assert_with_log!(
            score >= 0.0,
            "zero bandwidth score is non-negative",
            true,
            score >= 0.0
        );
        crate::test_complete!("quality_score_zero_bandwidth_is_finite");
    }

    #[test]
    fn quality_score_clamps_finite_loss_rate_bounds() {
        init_test("quality_score_clamps_finite_loss_rate_bounds");
        let no_loss = PathCharacteristics {
            loss_rate: 0.0,
            ..Default::default()
        };
        let negative_loss = PathCharacteristics {
            loss_rate: -0.75,
            ..Default::default()
        };
        let total_loss = PathCharacteristics {
            loss_rate: 1.0,
            ..Default::default()
        };
        let excessive_loss = PathCharacteristics {
            loss_rate: 2.5,
            ..Default::default()
        };

        assert!(
            (negative_loss.quality_score() - no_loss.quality_score()).abs() < f64::EPSILON,
            "negative finite loss rates must clamp to no-loss scoring"
        );
        assert!(
            (excessive_loss.quality_score() - total_loss.quality_score()).abs() < f64::EPSILON,
            "loss rates above one must clamp to total-loss scoring"
        );
        assert!(
            no_loss.quality_score() > total_loss.quality_score(),
            "bounded finite loss should preserve lower-loss preference"
        );
        crate::test_complete!("quality_score_clamps_finite_loss_rate_bounds");
    }

    #[test]
    fn transport_aggregator_comprehensive_report_format_golden_snapshot() {
        init_test("transport_aggregator_comprehensive_report_format_golden_snapshot");

        // Create a comprehensive aggregator scenario for golden snapshot testing
        let aggregator_config = AggregatorConfig::default();
        let aggregator = MultipathAggregator::new(aggregator_config);

        // Setup realistic paths with varying characteristics
        let primary_path = aggregator.paths().create_path(
            "primary_fiber",
            "fiber-endpoint-1",
            PathCharacteristics {
                latency_ms: 15,
                bandwidth_bps: 1_000_000_000, // 1 Gbps
                loss_rate: 0.001,
                jitter_ms: 2,
                is_primary: true,
                priority: 1,
            },
        );

        let backup_path = aggregator.paths().create_path(
            "backup_wireless",
            "wireless-endpoint-2",
            PathCharacteristics {
                latency_ms: 45,
                bandwidth_bps: 100_000_000, // 100 Mbps
                loss_rate: 0.015,
                jitter_ms: 12,
                is_primary: false,
                priority: 2,
            },
        );

        let degraded_path = aggregator.paths().create_path(
            "degraded_satellite",
            "satellite-endpoint-3",
            PathCharacteristics {
                latency_ms: 600,
                bandwidth_bps: 10_000_000, // 10 Mbps
                loss_rate: 0.05,
                jitter_ms: 50,
                is_primary: false,
                priority: 3,
            },
        );

        // Simulate some activity on the paths
        if let Some(path) = aggregator.paths().get(primary_path) {
            path.symbols_received.store(15420, Ordering::Relaxed);
            path.symbols_lost.store(18, Ordering::Relaxed);
            path.duplicates_received.store(23, Ordering::Relaxed);
            path.state.store(PathState::Active as u8, Ordering::Relaxed);
        }

        if let Some(path) = aggregator.paths().get(backup_path) {
            path.symbols_received.store(8765, Ordering::Relaxed);
            path.symbols_lost.store(134, Ordering::Relaxed);
            path.duplicates_received.store(67, Ordering::Relaxed);
            path.state.store(PathState::Active as u8, Ordering::Relaxed);
        }

        if let Some(path) = aggregator.paths().get(degraded_path) {
            path.symbols_received.store(2341, Ordering::Relaxed);
            path.symbols_lost.store(892, Ordering::Relaxed);
            path.duplicates_received.store(12, Ordering::Relaxed);
            path.state
                .store(PathState::Degraded as u8, Ordering::Relaxed);
        }

        // Generate comprehensive aggregation report
        let report = generate_aggregation_report(&aggregator);

        // Create golden snapshot for aggregation report format
        insta::with_settings!({
            snapshot_path => "../tests/snapshots",
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_snapshot!("transport_aggregator_comprehensive_report_format", report);
        });

        crate::test_complete!("transport_aggregator_comprehensive_report_format_golden_snapshot");
    }

    fn percentile_index(len: usize, percentile: usize) -> usize {
        debug_assert!(len > 0);
        let rank = percentile.saturating_mul(len).saturating_add(99) / 100;
        rank.saturating_sub(1).min(len - 1)
    }

    fn append_u32_percentiles(report: &mut String, label: &str, values: &[u32]) {
        if values.is_empty() {
            return;
        }

        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        for percentile in [50, 90, 100] {
            let value = sorted[percentile_index(sorted.len(), percentile)];
            report.push_str(&format!("{}p{}: {}\n", label, percentile, value));
        }
    }

    fn append_u64_percentiles(report: &mut String, label: &str, values: &[u64]) {
        if values.is_empty() {
            return;
        }

        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        for percentile in [50, 90, 100] {
            let value = sorted[percentile_index(sorted.len(), percentile)];
            report.push_str(&format!("{}p{}: {}\n", label, percentile, value));
        }
    }

    fn append_f64_percentiles(report: &mut String, label: &str, values: &[f64]) {
        if values.is_empty() {
            return;
        }

        let mut sorted = values.to_vec();
        sorted.sort_by(|left, right| left.total_cmp(right));
        for percentile in [50, 90, 100] {
            let value = sorted[percentile_index(sorted.len(), percentile)];
            report.push_str(&format!("{}p{}: {:.4}\n", label, percentile, value));
        }
    }

    /// Generate a structured aggregation report for golden snapshot testing
    fn generate_aggregation_report(aggregator: &MultipathAggregator) -> String {
        let mut report = String::new();
        let mut received_values = Vec::new();
        let mut lost_values = Vec::new();
        let mut duplicate_values = Vec::new();
        let mut latency_values = Vec::new();
        let mut bandwidth_values = Vec::new();
        let mut loss_rate_values = Vec::new();
        let mut jitter_values = Vec::new();

        report.push_str("=== Transport Aggregator Report ===\n\n");

        // Path Set Statistics
        let path_stats = aggregator.paths().stats();
        report.push_str("[path_set_summary]\n");
        report.push_str(&format!("path_count: {}\n", path_stats.path_count));
        report.push_str(&format!("usable_count: {}\n", path_stats.usable_count));
        report.push_str(&format!("total_received: {}\n", path_stats.total_received));
        report.push_str(&format!("total_lost: {}\n", path_stats.total_lost));
        report.push_str(&format!(
            "total_duplicates: {}\n",
            path_stats.total_duplicates
        ));
        report.push_str(&format!(
            "aggregate_bandwidth_bps: {}\n",
            path_stats.aggregate_bandwidth_bps
        ));
        report.push_str(&format!(
            "loss_rate: {:.4}\n",
            if path_stats.total_received + path_stats.total_lost > 0 {
                path_stats.total_lost as f64
                    / (path_stats.total_received + path_stats.total_lost) as f64
            } else {
                0.0
            }
        ));
        report.push('\n');

        // Individual Path Details
        report.push_str("[individual_paths]\n");
        for path_id in 0..path_stats.path_count {
            let pid = PathId::new(path_id as u64);
            if let Some(path) = aggregator.paths().get(pid) {
                let state = PathState::from_u8(path.state.load(Ordering::Relaxed));
                let received = path.symbols_received.load(Ordering::Relaxed);
                let lost = path.symbols_lost.load(Ordering::Relaxed);
                let duplicates = path.duplicates_received.load(Ordering::Relaxed);

                received_values.push(received);
                lost_values.push(lost);
                duplicate_values.push(duplicates);
                latency_values.push(path.characteristics.latency_ms);
                bandwidth_values.push(path.characteristics.bandwidth_bps);
                loss_rate_values.push(path.characteristics.loss_rate);
                jitter_values.push(path.characteristics.jitter_ms);

                report.push_str(&format!("path_{}:\n", path_id));
                report.push_str(&format!("  id: Path({})\n", path_id));
                report.push_str(&format!("  state: {:?}\n", state));
                report.push_str(&format!("  is_usable: {}\n", state.is_usable()));
                report.push_str(&format!("  symbols_received: {}\n", received));
                report.push_str(&format!("  symbols_lost: {}\n", lost));
                report.push_str(&format!("  duplicates_received: {}\n", duplicates));
                report.push_str("  characteristics:\n");
                report.push_str(&format!(
                    "    latency_ms: {}\n",
                    path.characteristics.latency_ms
                ));
                report.push_str(&format!(
                    "    bandwidth_bps: {}\n",
                    path.characteristics.bandwidth_bps
                ));
                report.push_str(&format!(
                    "    loss_rate: {:.3}\n",
                    path.characteristics.loss_rate
                ));
                report.push_str(&format!(
                    "    jitter_ms: {}\n",
                    path.characteristics.jitter_ms
                ));
                report.push_str(&format!(
                    "    is_primary: {}\n",
                    path.characteristics.is_primary
                ));
                report.push_str(&format!(
                    "    priority: {}\n",
                    path.characteristics.priority
                ));
                report.push('\n');
            }
        }

        report.push_str("[path_percentiles]\n");
        append_u64_percentiles(&mut report, "symbols_received_", &received_values);
        append_u64_percentiles(&mut report, "symbols_lost_", &lost_values);
        append_u64_percentiles(&mut report, "duplicates_received_", &duplicate_values);
        append_u32_percentiles(&mut report, "latency_ms_", &latency_values);
        append_u64_percentiles(&mut report, "bandwidth_bps_", &bandwidth_values);
        append_f64_percentiles(&mut report, "loss_rate_", &loss_rate_values);
        append_u32_percentiles(&mut report, "jitter_ms_", &jitter_values);
        report.push('\n');

        // Aggregator Statistics
        let agg_stats = aggregator.stats();
        report.push_str("[aggregator_stats]\n");
        report.push_str(&format!("total_processed: {}\n", agg_stats.total_processed));
        report.push_str("deduplicator:\n");
        report.push_str(&format!(
            "  objects_tracked: {}\n",
            agg_stats.dedup.objects_tracked
        ));
        report.push_str(&format!(
            "  symbols_tracked: {}\n",
            agg_stats.dedup.symbols_tracked
        ));
        report.push_str(&format!(
            "  duplicates_detected: {}\n",
            agg_stats.dedup.duplicates_detected
        ));
        report.push_str(&format!(
            "  unique_symbols: {}\n",
            agg_stats.dedup.unique_symbols
        ));
        report.push_str("reorderer:\n");
        report.push_str(&format!(
            "  objects_tracked: {}\n",
            agg_stats.reorder.objects_tracked
        ));
        report.push_str(&format!(
            "  symbols_buffered: {}\n",
            agg_stats.reorder.symbols_buffered
        ));
        report.push_str(&format!(
            "  in_order_deliveries: {}\n",
            agg_stats.reorder.in_order_deliveries
        ));
        report.push_str(&format!(
            "  reordered_deliveries: {}\n",
            agg_stats.reorder.reordered_deliveries
        ));
        report.push_str(&format!(
            "  timeout_deliveries: {}\n",
            agg_stats.reorder.timeout_deliveries
        ));

        report.trim_end().to_string()
    }
