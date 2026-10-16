    use super::*;
    use crate::net::atp::quic::metrics::{AtpTransportMetrics, PathDoctorAssessment};

    fn create_test_metrics(
        path_id: &str,
        loss_rate: f64,
        rtt_micros: u64,
        stability: f64,
    ) -> AtpTransportMetrics {
        AtpTransportMetrics {
            connection_id: "test_conn".to_string(),
            path_id: path_id.to_string(),
            smoothed_rtt_micros: Some(rtt_micros),
            latest_rtt_micros: Some(rtt_micros),
            rttvar_micros: Some(rtt_micros / 10),
            bytes_in_flight: 1200,
            congestion_window_bytes: 12_000,
            ssthresh_bytes: 24_000,
            pto_count: 0,
            congestion_limited: false,
            anti_amplification_limited: false,
            packets_sent: 100,
            packets_lost: (loss_rate * 100.0) as u64,
            packets_acked: ((1.0 - loss_rate) * 100.0) as u64,
            loss_rate,
            path_stability: stability,
            last_updated: Instant::now(),
            path_doctor_assessment: Some(PathDoctorAssessment {
                health_score: 1.0 - loss_rate,
                detected_issues: Vec::new(),
                recommendations: Vec::new(),
                performance_class: PathPerformanceClass::from_metrics(&AtpTransportMetrics {
                    connection_id: format!("test_conn_{path_id}"),
                    path_id: path_id.to_string(),
                    smoothed_rtt_micros: Some(rtt_micros),
                    latest_rtt_micros: Some(rtt_micros),
                    rttvar_micros: Some(rtt_micros / 10),
                    bytes_in_flight: 1200,
                    congestion_window_bytes: 12_000,
                    ssthresh_bytes: 24_000,
                    pto_count: 0,
                    congestion_limited: false,
                    anti_amplification_limited: false,
                    packets_sent: 100,
                    packets_lost: (loss_rate * 100.0) as u64,
                    packets_acked: ((1.0 - loss_rate) * 100.0) as u64,
                    loss_rate,
                    path_stability: stability,
                    last_updated: Instant::now(),
                    path_doctor_assessment: None,
                }),
            }),
        }
    }

    #[test]
    fn transfer_brain_path_selection() {
        let mut brain = AtpTransferBrain::new();

        // Add some paths with different qualities
        brain.update_path_metrics(create_test_metrics("good_path", 0.01, 50_000, 0.9));
        brain.update_path_metrics(create_test_metrics("poor_path", 0.9, 800_000, 0.1));
        brain.update_path_metrics(create_test_metrics("excellent_path", 0.005, 30_000, 0.95));

        let decision = brain
            .make_transfer_decision(
                "test_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("Should make decision");

        // Should prefer excellent path, then good path, and exclude poor path
        assert_eq!(decision.selected_paths[0], "excellent_path");
        assert_eq!(decision.selected_paths[1], "good_path");
        assert_eq!(decision.selected_paths.len(), 2);
    }

    #[test]
    fn repair_decision_logic() {
        let mut brain = AtpTransferBrain::new();

        // Add path with high loss rate
        brain.update_path_metrics(create_test_metrics("lossy_path", 0.08, 100_000, 0.7));

        let decision = brain
            .make_transfer_decision(
                "test_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("Should make decision");

        // Should enable repair due to high loss rate (0.08 > 0.05 threshold)
        assert!(decision.enable_repair);
        assert!(decision.fec_rate.is_some());
    }

    #[test]
    fn loss_detection_result_forces_bounded_repair_pressure_on_clean_path() {
        let mut brain = AtpTransferBrain::new();
        brain.update_path_metrics(create_test_metrics("clean_path", 0.0, 50_000, 0.95));

        let pressure = brain
            .apply_loss_detection_result(&LossDetectionResult {
                lost_packets: Vec::new(),
                lost_packet_count: 0,
                lost_bytes: 8_192,
                detection_method: LossDetectionMethod::PacketThreshold,
                confidence: 0.85,
                recommendations: vec![LossRecommendation::EnableFec { rate: 0.42 }],
            })
            .expect("explicit FEC recommendation should latch pressure");

        assert_eq!(pressure.fec_rate, 0.3);
        assert_eq!(brain.loss_repair_pressure(), Some(pressure));

        let decision = brain
            .make_transfer_decision(
                "loss_pressure_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert!(decision.enable_repair);
        assert_eq!(decision.fec_rate, Some(0.3));
        assert!(decision.reason_vector.iter().any(|reason| {
            reason.code == DecisionReasonCode::RepairEnabled
                && reason.detail.contains("loss_pressure_rate=0.300000")
                && reason.detail.contains("lost_bytes=8192")
        }));
    }

    #[test]
    fn transfer_loss_signal_drives_congestion_and_repair_decisions() {
        let mut brain = AtpTransferBrain::new();
        brain.update_path_metrics(create_test_metrics("lossy_signal_path", 0.0, 50_000, 0.95));

        let pressure = brain
            .apply_transfer_loss_signal(TransferLossSignal {
                loss_pressure: 0.12,
                repair_rate_hint: Some(0.18),
                cwnd_reduction_factor: Some(0.5),
                pacing_rate_hint: Some(100_000),
                prefer_bbr: true,
                confidence: 0.9,
            })
            .expect("repair hint should latch bounded FEC pressure");

        assert_eq!(pressure.fec_rate, 0.18);
        assert_eq!(
            brain
                .loss_transfer_signal()
                .expect("signal should be latched")
                .loss_pressure,
            0.12
        );

        let decision = brain
            .make_transfer_decision(
                "loss_signal_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert!(decision.enable_repair);
        assert_eq!(decision.fec_rate, Some(0.18));
        assert_eq!(decision.congestion_params.initial_cwnd, 3_000);
        assert_eq!(decision.congestion_params.max_cwnd, 24_000);
        assert_eq!(
            decision.congestion_params.algorithm,
            CongestionAlgorithm::Bbr
        );
        assert_eq!(decision.congestion_params.pacing_rate, Some(100_000));
        assert_eq!(decision.pressure_snapshot.loss_detector_pressure, 0.12);
        assert_eq!(decision.pressure_snapshot.loss_detector_confidence, 0.9);
    }

    #[test]
    fn clean_transfer_loss_signal_clears_stale_detector_pressure() {
        let mut brain = AtpTransferBrain::new();
        brain.update_path_metrics(create_test_metrics("clean_path", 0.0, 50_000, 0.95));

        assert!(
            brain
                .apply_transfer_loss_signal(TransferLossSignal {
                    loss_pressure: 0.10,
                    repair_rate_hint: Some(0.15),
                    cwnd_reduction_factor: Some(0.75),
                    pacing_rate_hint: Some(250_000),
                    prefer_bbr: false,
                    confidence: 0.8,
                })
                .is_some()
        );
        assert!(brain.loss_transfer_signal().is_some());

        assert!(
            brain
                .apply_transfer_loss_signal(TransferLossSignal {
                    loss_pressure: 0.0,
                    repair_rate_hint: None,
                    cwnd_reduction_factor: None,
                    pacing_rate_hint: None,
                    prefer_bbr: false,
                    confidence: 1.0,
                })
                .is_none()
        );
        assert_eq!(brain.loss_transfer_signal(), None);
        assert_eq!(brain.loss_repair_pressure(), None);

        let decision = brain
            .make_transfer_decision(
                "clean_signal_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert!(!decision.enable_repair);
        assert_eq!(decision.congestion_params.pacing_rate, None);
        assert_eq!(
            decision.congestion_params.algorithm,
            CongestionAlgorithm::AtpAdaptive
        );
    }

    #[test]
    fn empty_or_non_finite_loss_detection_clears_repair_pressure() {
        let mut brain = AtpTransferBrain::new();
        brain.update_path_metrics(create_test_metrics("clean_path", 0.0, 50_000, 0.95));

        assert!(
            brain
                .apply_loss_detection_result(&LossDetectionResult {
                    lost_packets: Vec::new(),
                    lost_packet_count: 0,
                    lost_bytes: 4_096,
                    detection_method: LossDetectionMethod::PacketThreshold,
                    confidence: 1.0,
                    recommendations: vec![LossRecommendation::EnableFec { rate: 0.1 }],
                })
                .is_some()
        );

        assert!(
            brain
                .apply_loss_detection_result(&LossDetectionResult {
                    lost_packets: Vec::new(),
                    lost_packet_count: 0,
                    lost_bytes: 0,
                    detection_method: LossDetectionMethod::PacketThreshold,
                    confidence: f64::NAN,
                    recommendations: vec![LossRecommendation::EnableFec { rate: f64::NAN }],
                })
                .is_none()
        );
        assert_eq!(brain.loss_repair_pressure(), None);

        let decision = brain
            .make_transfer_decision(
                "clean_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert!(!decision.enable_repair);
        assert_eq!(decision.fec_rate, None);
    }

    #[test]
    fn relay_selection_uses_configured_candidate() {
        let policy = TransferPolicy {
            relay_candidates: vec![
                RelayCandidate {
                    relay_id: "relay_slow".to_string(),
                    assisted_path_id: Some("poor_direct".to_string()),
                    priority: 10,
                    added_latency_micros: 80_000,
                    cost_micros_per_mib: 400_000,
                },
                RelayCandidate {
                    relay_id: "relay_fast".to_string(),
                    assisted_path_id: Some("poor_direct".to_string()),
                    priority: 5,
                    added_latency_micros: 20_000,
                    cost_micros_per_mib: 100_000,
                },
            ],
            ..TransferPolicy::default()
        };
        let mut brain = AtpTransferBrain::with_policy(policy);
        let mut metrics = create_test_metrics("poor_direct", 0.04, 250_000, 0.1);
        metrics
            .path_doctor_assessment
            .as_mut()
            .unwrap()
            .performance_class = PathPerformanceClass::Fair;
        brain.update_path_metrics(metrics);

        let decision = brain
            .make_transfer_decision(
                "relay_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert!(decision.use_relay);
        assert_eq!(decision.suggested_relay.as_deref(), Some("relay_fast"));
    }

    #[test]
    fn completion_report_records_prediction_error_ratio() {
        let mut brain = AtpTransferBrain::new();
        brain.update_path_metrics(create_test_metrics("test_path", 0.01, 100_000, 0.8));

        let decision = brain
            .make_transfer_decision(
                "ratio_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");
        let actual = decision.estimated_completion_time.saturating_mul(2);
        brain.report_transfer_completion("ratio_transfer", actual, true);

        let outcome = brain
            .decision_history
            .outcomes
            .get(&decision.decision_id)
            .expect("outcome");
        assert!(outcome.success);
        assert!(outcome.performance_ratio > 0.0);
        assert!(outcome.performance_ratio < 1.0);
    }

    #[test]
    fn path_ranking_calculation() {
        let brain = AtpTransferBrain::new();

        let good_metrics = create_test_metrics("good", 0.02, 50_000, 0.9);
        let poor_metrics = create_test_metrics("poor", 0.9, 800_000, 0.1);

        let good_score = brain.calculate_path_ranking(&good_metrics);
        let poor_score = brain.calculate_path_ranking(&poor_metrics);

        assert!(
            good_score > poor_score,
            "Good path should rank higher than poor path"
        );
        assert!(good_score > 0.7, "Good path should have high score");
        assert!(poor_score < 0.5, "Poor path should have low score");
    }

    #[test]
    fn completion_time_estimation() {
        let mut brain = AtpTransferBrain::new();

        // Path with known characteristics
        brain.update_path_metrics(create_test_metrics("test_path", 0.01, 100_000, 0.8));

        let transfer_size = 1_000_000; // 1MB
        let completion_time =
            brain.estimate_completion_time(&["test_path".to_string()], transfer_size);

        // Should estimate reasonable completion time (not zero or extremely long)
        assert!(completion_time.as_secs() > 0);
        assert!(completion_time.as_secs() < 3600); // Less than 1 hour
    }

    #[test]
    fn equal_scores_use_deterministic_tie_break_and_record_evidence() {
        let policy = TransferPolicy {
            max_paths_per_transfer: 1,
            min_path_quality: 0.0,
            ..TransferPolicy::default()
        };
        let mut brain = AtpTransferBrain::with_policy(policy);

        brain.update_path_metrics(create_test_metrics("z_path", 0.01, 50_000, 0.9));
        brain.update_path_metrics(create_test_metrics("a_path", 0.01, 50_000, 0.9));

        let decision = brain
            .make_transfer_decision(
                "tie_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert_eq!(decision.decision_id, "tie_transfer_0");
        assert_eq!(decision.selected_paths, vec!["a_path"]);
        assert_eq!(decision.replay_pointer, "atp-transfer-brain:tie_transfer_0");
        assert_eq!(
            brain.decision_history.decisions[0].decision_id,
            decision.decision_id
        );
        assert_eq!(decision.rejected_paths.len(), 1);
        assert_eq!(decision.rejected_paths[0].path_id, "z_path");
        assert!(matches!(
            decision.rejected_paths[0].reason,
            PathRejectionReason::PathLimitReached { max_paths: 1 }
        ));
        assert!(
            decision
                .reason_vector
                .iter()
                .any(|reason| reason.code == DecisionReasonCode::DeterministicTieBreak)
        );
        assert_eq!(
            decision
                .fairness_state
                .active_transfers_by_path
                .get("a_path"),
            Some(&0)
        );
    }

    #[test]
    fn zero_path_limit_fails_closed_without_empty_confidence() {
        let policy = TransferPolicy {
            max_paths_per_transfer: 0,
            min_path_quality: 0.0,
            ..TransferPolicy::default()
        };
        let mut brain = AtpTransferBrain::with_policy(policy);

        brain.update_path_metrics(create_test_metrics("good_path", 0.01, 50_000, 0.95));

        let decision = brain.make_transfer_decision(
            "zero_limit_transfer".to_string(),
            1_000_000,
            TransferPriority::Normal,
        );

        assert!(decision.is_err());
        assert!(brain.decision_history.decisions.is_empty());
    }

    #[test]
    fn rejected_paths_explain_quality_and_class_failures() {
        let policy = TransferPolicy {
            min_path_quality: 0.2,
            ..TransferPolicy::default()
        };
        let mut brain = AtpTransferBrain::with_policy(policy);

        brain.update_path_metrics(create_test_metrics("good_path", 0.01, 50_000, 0.95));
        brain.update_path_metrics(create_test_metrics("low_score_path", 0.15, 200_000, 0.3));
        brain
            .paths
            .get_mut("low_score_path")
            .expect("low score path should exist")
            .ranking_score = 0.1;

        let mut unusable = create_test_metrics("unusable_path", 0.01, 50_000, 0.95);
        unusable
            .path_doctor_assessment
            .as_mut()
            .unwrap()
            .performance_class = PathPerformanceClass::Unusable;
        brain.update_path_metrics(unusable);

        let decision = brain
            .make_transfer_decision(
                "reject_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert_eq!(decision.selected_paths, vec!["good_path"]);
        assert_eq!(decision.rejected_paths.len(), 2);
        assert!(decision.rejected_paths.iter().any(|path| {
            path.path_id == "low_score_path"
                && matches!(
                    path.reason,
                    PathRejectionReason::BelowQualityThreshold { threshold, .. }
                    if (threshold - 0.2).abs() < f64::EPSILON
                )
        }));
        assert!(decision.rejected_paths.iter().any(|path| {
            path.path_id == "unusable_path"
                && matches!(
                    path.reason,
                    PathRejectionReason::UnschedulablePerformanceClass {
                        performance_class: Some(PathPerformanceClass::Unusable)
                    }
                )
        }));
        assert!(
            decision
                .reason_vector
                .iter()
                .any(|reason| reason.code == DecisionReasonCode::PathSelected)
        );
        assert!(
            decision
                .reason_vector
                .iter()
                .any(|reason| reason.code == DecisionReasonCode::PathRejected)
        );
    }

    #[test]
    fn pressure_snapshot_records_selected_path_pressure() {
        let mut brain = AtpTransferBrain::new();
        let mut metrics = create_test_metrics("limited_path", 0.08, 100_000, 0.8);
        metrics.congestion_limited = true;
        metrics.anti_amplification_limited = true;
        metrics.congestion_window_bytes = 24_000;
        brain.update_path_metrics(metrics);

        let decision = brain
            .make_transfer_decision(
                "pressure_transfer".to_string(),
                1_000_000,
                TransferPriority::High,
            )
            .expect("decision");

        assert_eq!(decision.pressure_snapshot.selected_path_count, 1);
        assert_eq!(decision.pressure_snapshot.max_loss_rate, 0.08);
        assert_eq!(decision.pressure_snapshot.min_cwnd_bytes, 24_000);
        assert_eq!(decision.pressure_snapshot.congestion_limited_path_count, 1);
        assert_eq!(
            decision
                .pressure_snapshot
                .anti_amplification_limited_path_count,
            1
        );
        assert!(decision.enable_repair);
        assert!(
            decision
                .reason_vector
                .iter()
                .any(|reason| reason.code == DecisionReasonCode::RepairEnabled)
        );
    }

    #[test]
    fn non_finite_path_scores_fail_closed() {
        let mut brain = AtpTransferBrain::new();
        let mut non_finite = create_test_metrics("nan_path", 0.01, 50_000, f64::NAN);
        non_finite.path_stability = f64::NAN;
        brain.update_path_metrics(non_finite);
        brain.update_path_metrics(create_test_metrics("good_path", 0.01, 50_000, 0.95));

        let rankings = brain.path_rankings();
        assert_eq!(rankings.get("nan_path"), Some(&0.0));

        let decision = brain
            .make_transfer_decision(
                "finite_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert_eq!(decision.selected_paths, vec!["good_path"]);
        assert!(decision.rejected_paths.iter().any(|path| {
            path.path_id == "nan_path"
                && matches!(
                    path.reason,
                    PathRejectionReason::BelowQualityThreshold { score, .. }
                    if score == 0.0
                )
        }));
    }
