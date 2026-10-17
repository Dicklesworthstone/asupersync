    use super::*;
    use crate::atp::object::ContentId;

    fn test_object_id() -> ObjectId {
        ObjectId::content(ContentId::from_bytes(b"test-object"))
    }

    fn create_test_path() -> PathCharacteristics {
        PathCharacteristics {
            rtt_ms: 50.0,
            bandwidth_bps: 10_000_000,
            loss_rate: 0.02, // 2% loss
            jitter_ms: 5.0,
            bdp_bytes: 62_500,
            stability_score: 0.8,
            uses_relay: false,
            relay_cost_per_byte: 0.0,
            is_mobile: false,
            is_high_latency: false,
        }
    }

    fn create_test_transfer() -> TransferState {
        TransferState {
            object_size_bytes: 1_000_000, // 1MB
            bytes_transferred: 800_000,   // 80% complete
            missing_chunks: 10,
            missing_bytes: 200_000,
            is_resume: false,
            elapsed_time: Duration::from_secs(5),
            retransmit_attempts: 3,
            available_peers: 1,
            memory_pressure: 0.3,
            cpu_pressure: 0.4,
        }
    }

    fn create_test_telemetry() -> RepairTelemetry {
        RepairTelemetry {
            object_id: test_object_id(),
            mode: RepairMode::Tail,
            predicted_roi: RepairRoi {
                expected_time_saved: Duration::from_millis(100),
                encode_cpu_cost: Duration::from_millis(10),
                decode_cpu_cost: Duration::from_millis(5),
                bandwidth_overhead: 1000,
                memory_overhead: 500,
                coordination_cost: Duration::ZERO,
                benefit_score: 2.0,
                cost_score: 1.0,
                roi_ratio: 1.5,
                confidence: 0.8,
            },
            actual_repair_time: Duration::from_millis(90),
            actual_encode_cpu: Duration::from_millis(12),
            actual_decode_cpu: Duration::from_millis(6),
            actual_bandwidth_used: 1200,
            repair_symbols_sent: 5,
            repair_symbols_decoded: 5,
            success: true,
            actual_benefit_score: 2.1,
            actual_roi_ratio: 1.6,
            measured_at: SystemTime::now(),
        }
    }

    #[test]
    fn test_repair_coordinator_creation() {
        let config = RepairCoordinatorConfig::default();
        let coordinator = RepairCoordinator::new(config);

        assert_eq!(coordinator.decision_history.len(), 0);
        assert_eq!(coordinator.telemetry.len(), 0);
    }

    #[test]
    fn test_repair_mode_descriptions() {
        assert_eq!(
            RepairMode::Off.description(),
            "no repair - exact retransmission only"
        );
        assert_eq!(
            RepairMode::Tail.description(),
            "tail repair for last missing chunks"
        );
        assert!(RepairMode::Swarm.requires_multi_source());
        assert!(!RepairMode::Tail.requires_multi_source());
    }

    #[test]
    fn test_path_quality_assessment() {
        let config = RepairCoordinatorConfig::default();
        let coordinator = RepairCoordinator::new(config);
        let path = create_test_path();

        let quality = coordinator.assess_path_quality(&path);
        assert!(quality > 0.0 && quality <= 1.0);
    }

    #[test]
    fn test_applicable_modes() {
        let config = RepairCoordinatorConfig::default();
        let coordinator = RepairCoordinator::new(config);
        let path = create_test_path();
        let transfer = create_test_transfer();

        let modes = coordinator.get_applicable_modes(&path, &transfer);

        // Should include Off, Tail (80% complete), and Lossy (2% loss)
        assert!(modes.contains(&RepairMode::Off));
        assert!(modes.contains(&RepairMode::Tail));
        assert!(modes.contains(&RepairMode::Lossy));
    }

    #[test]
    fn test_roi_calculation_off_mode() -> Result<()> {
        let config = RepairCoordinatorConfig::default();
        let coordinator = RepairCoordinator::new(config);
        let path = create_test_path();
        let transfer = create_test_transfer();

        let roi = coordinator.calculate_roi(RepairMode::Off, &path, &transfer)?;

        assert_eq!(roi.roi_ratio, 0.0);
        assert_eq!(roi.expected_time_saved, Duration::ZERO);
        assert!(!roi.justifies_repair(1.0));

        Ok(())
    }

    #[test]
    fn test_roi_calculation_tail_mode() -> Result<()> {
        let config = RepairCoordinatorConfig::default();
        let coordinator = RepairCoordinator::new(config);
        let path = create_test_path();
        let transfer = create_test_transfer();

        let roi = coordinator.calculate_roi(RepairMode::Tail, &path, &transfer)?;

        assert!(roi.roi_ratio > 0.0);
        assert!(roi.confidence > 0.0);

        Ok(())
    }

    #[test]
    fn test_repair_decision() -> Result<()> {
        let config = RepairCoordinatorConfig {
            min_roi_threshold: 0.5, // Lower threshold for test
            ..RepairCoordinatorConfig::default()
        };
        let mut coordinator = RepairCoordinator::new(config);
        let path = create_test_path();
        let transfer = create_test_transfer();
        let object_id = test_object_id();

        let decision = coordinator.decide_repair_mode(
            object_id,
            &path,
            &transfer,
            TraceId::from_parts(1, 1),
        )?;

        // Should make a decision
        assert!(!decision.reasoning.is_empty());
        assert!(decision.roi.confidence > 0.0);

        Ok(())
    }

    #[test]
    fn decision_history_zero_limit_retains_no_entries() -> Result<()> {
        let config = RepairCoordinatorConfig {
            max_decision_history: 0,
            max_decisions_per_minute: 10,
            ..RepairCoordinatorConfig::default()
        };
        let mut coordinator = RepairCoordinator::new(config);
        let path = create_test_path();
        let transfer = create_test_transfer();

        coordinator.decide_repair_mode(
            test_object_id(),
            &path,
            &transfer,
            TraceId::from_parts(1, 1),
        )?;

        assert!(coordinator.decision_history.is_empty());

        Ok(())
    }

    #[test]
    fn decision_history_sub_ten_limit_drains_oldest_entries() -> Result<()> {
        let config = RepairCoordinatorConfig {
            max_decision_history: 2,
            max_decisions_per_minute: 10,
            ..RepairCoordinatorConfig::default()
        };
        let mut coordinator = RepairCoordinator::new(config);
        let path = create_test_path();
        let transfer = create_test_transfer();

        for sequence in 0..5 {
            coordinator.decide_repair_mode(
                test_object_id(),
                &path,
                &transfer,
                TraceId::from_parts(1, sequence),
            )?;
        }

        assert_eq!(coordinator.decision_history.len(), 2);

        Ok(())
    }

    #[test]
    fn test_telemetry_recording() {
        let config = RepairCoordinatorConfig::default();
        let mut coordinator = RepairCoordinator::new(config);

        coordinator
            .record_telemetry(create_test_telemetry())
            .expect("Telemetry recording failed");

        assert_eq!(coordinator.telemetry.len(), 1);
        assert!(coordinator.mode_statistics.contains_key(&RepairMode::Tail));

        let stats = &coordinator.mode_statistics[&RepairMode::Tail];
        assert_eq!(stats.usage_count, 1);
        assert_eq!(stats.success_rate, 1.0);
    }

    #[test]
    fn telemetry_history_zero_limit_retains_no_entries() {
        let config = RepairCoordinatorConfig {
            max_telemetry_history: 0,
            max_telemetry_per_minute: 10,
            ..RepairCoordinatorConfig::default()
        };
        let mut coordinator = RepairCoordinator::new(config);

        coordinator
            .record_telemetry(create_test_telemetry())
            .expect("Telemetry recording failed");

        assert!(coordinator.telemetry.is_empty());
    }

    #[test]
    fn telemetry_history_sub_ten_limit_drains_oldest_entries() {
        let config = RepairCoordinatorConfig {
            max_telemetry_history: 2,
            max_telemetry_per_minute: 10,
            ..RepairCoordinatorConfig::default()
        };
        let mut coordinator = RepairCoordinator::new(config);

        for sequence in 0..5 {
            let mut telemetry = create_test_telemetry();
            telemetry.actual_roi_ratio += sequence as f64;
            coordinator
                .record_telemetry(telemetry)
                .expect("Telemetry recording failed");
        }

        assert_eq!(coordinator.telemetry.len(), 2);
    }
