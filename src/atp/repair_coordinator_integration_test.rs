//! Integration tests for ATP-G economically adaptive RaptorQ repair.
//!
//! Demonstrates repair mode selection based on network conditions and telemetry,
//! validating that RepairCoordinator chooses appropriate repair strategies.

#[cfg(test)]
mod tests {
    use super::super::repair_coordinator::*;
    use crate::atp::object::ObjectId;
    use crate::types::TraceId;
    use std::time::Duration;

    /// Test repair mode selection for different network scenarios
    #[test]
    fn test_repair_mode_selection_scenarios() {
        let config = RepairCoordinatorConfig {
            min_roi_threshold: 1.1, // Lower threshold for testing
            ..RepairCoordinatorConfig::default()
        };
        let mut coordinator = RepairCoordinator::new(config);

        // Scenario 1: Clean path - should prefer no repair
        let clean_path = PathCharacteristics {
            rtt_ms: 20.0,
            bandwidth_bps: 100_000_000, // 100 Mbps
            loss_rate: 0.001,           // 0.1% loss
            stability_score: 0.95,
            uses_relay: false,
            ..PathCharacteristics::default()
        };

        let small_transfer = TransferState {
            object_size_bytes: 1_000_000,  // 1MB
            bytes_transferred: 900_000,    // 90% complete
            missing_chunks: 2,
            missing_bytes: 100_000,
            is_resume: false,
            available_peers: 1,
            ..TransferState::default()
        };

        let decision = coordinator
            .decide_repair_mode(
                ObjectId::from("test-clean"),
                &clean_path,
                &small_transfer,
                TraceId::from_raw(0x1234),
            )
            .unwrap();

        // Should prefer tail repair for nearly complete transfer
        // but may choose Off if ROI doesn't justify repair
        assert!(matches!(decision.mode, RepairMode::Off | RepairMode::Tail));

        // Scenario 2: Lossy path - should use lossy repair
        let lossy_path = PathCharacteristics {
            rtt_ms: 100.0,
            bandwidth_bps: 10_000_000, // 10 Mbps
            loss_rate: 0.05,           // 5% loss
            stability_score: 0.7,
            uses_relay: false,
            ..PathCharacteristics::default()
        };

        let large_transfer = TransferState {
            object_size_bytes: 100_000_000, // 100MB
            bytes_transferred: 50_000_000,  // 50% complete
            missing_chunks: 100,
            missing_bytes: 50_000_000,
            is_resume: false,
            retransmit_attempts: 5,
            available_peers: 1,
            ..TransferState::default()
        };

        let decision = coordinator
            .decide_repair_mode(
                ObjectId::from("test-lossy"),
                &lossy_path,
                &large_transfer,
                TraceId::from_raw(0x5678),
            )
            .unwrap();

        assert!(matches!(decision.mode, RepairMode::Lossy));
        assert!(decision.roi.roi_ratio > 1.0);

        // Scenario 3: Resume transfer - should use resume repair
        let resume_transfer = TransferState {
            object_size_bytes: 50_000_000, // 50MB
            bytes_transferred: 20_000_000, // 40% complete
            missing_chunks: 60,
            missing_bytes: 30_000_000,
            is_resume: true, // Resume scenario
            retransmit_attempts: 2,
            available_peers: 1,
            ..TransferState::default()
        };

        let decision = coordinator
            .decide_repair_mode(
                ObjectId::from("test-resume"),
                &lossy_path,
                &resume_transfer,
                TraceId::from_raw(0x9ABC),
            )
            .unwrap();

        assert!(matches!(
            decision.mode,
            RepairMode::ResumeRepair | RepairMode::Lossy
        ));

        // Scenario 4: Relay expensive - should use relay repair mode
        let relay_path = PathCharacteristics {
            rtt_ms: 200.0,
            bandwidth_bps: 5_000_000, // 5 Mbps
            loss_rate: 0.02,          // 2% loss
            stability_score: 0.8,
            uses_relay: true,
            relay_cost_per_byte: 0.001, // $0.001 per byte
            ..PathCharacteristics::default()
        };

        let decision = coordinator
            .decide_repair_mode(
                ObjectId::from("test-relay"),
                &relay_path,
                &large_transfer,
                TraceId::from_raw(0xDEF0),
            )
            .unwrap();

        assert!(matches!(
            decision.mode,
            RepairMode::RelayExpensive | RepairMode::Lossy
        ));

        // Scenario 5: Multi-peer swarm - needs multi-source scheduler
        let swarm_transfer = TransferState {
            available_peers: 5, // Multiple peers available
            ..large_transfer
        };

        // For swarm mode, we would need multi-source scheduler
        let decision = coordinator
            .decide_repair_mode(
                ObjectId::from("test-swarm"),
                &clean_path,
                &swarm_transfer,
                TraceId::from_raw(0x1111),
            )
            .unwrap();

        // Should not use swarm mode without multi-source scheduler
        assert!(!matches!(decision.mode, RepairMode::Swarm));
    }

    /// Test ROI calculation accuracy
    #[test]
    fn test_roi_calculation() {
        let coordinator = RepairCoordinator::new(RepairCoordinatorConfig::default());

        let path = PathCharacteristics {
            rtt_ms: 100.0,
            bandwidth_bps: 10_000_000,
            loss_rate: 0.03, // 3% loss
            ..PathCharacteristics::default()
        };

        let transfer = TransferState {
            object_size_bytes: 10_000_000, // 10MB
            missing_chunks: 50,
            missing_bytes: 5_000_000, // 5MB missing
            retransmit_attempts: 3,
            ..TransferState::default()
        };

        // Test ROI calculation for lossy mode
        let roi = coordinator
            .calculate_roi(RepairMode::Lossy, &path, &transfer)
            .unwrap();

        // Should have positive ROI for lossy scenario
        assert!(roi.roi_ratio > 0.0);
        assert!(roi.expected_time_saved > Duration::ZERO);
        assert!(roi.confidence > 0.0);
        assert!(roi.bandwidth_overhead > 0);

        // Test ROI calculation for off mode
        let off_roi = coordinator
            .calculate_roi(RepairMode::Off, &path, &transfer)
            .unwrap();

        assert_eq!(off_roi.roi_ratio, 0.0);
        assert_eq!(off_roi.expected_time_saved, Duration::ZERO);
        assert!(!off_roi.justifies_repair(1.0));
    }

    /// Test telemetry recording and statistics
    #[test]
    fn test_telemetry_and_statistics() {
        let mut coordinator = RepairCoordinator::new(RepairCoordinatorConfig::default());

        // Record telemetry for successful repair
        let telemetry = RepairTelemetry {
            object_id: ObjectId::from("test-telemetry"),
            mode: RepairMode::Lossy,
            predicted_roi: RepairRoi {
                roi_ratio: 1.5,
                expected_time_saved: Duration::from_millis(500),
                encode_cpu_cost: Duration::from_millis(50),
                decode_cpu_cost: Duration::from_millis(25),
                bandwidth_overhead: 1000,
                memory_overhead: 500,
                coordination_cost: Duration::ZERO,
                benefit_score: 3.0,
                cost_score: 2.0,
                confidence: 0.8,
            },
            actual_repair_time: Duration::from_millis(450),
            actual_encode_cpu: Duration::from_millis(55),
            actual_decode_cpu: Duration::from_millis(30),
            actual_bandwidth_used: 1200,
            repair_symbols_sent: 10,
            repair_symbols_decoded: 10,
            success: true,
            actual_benefit_score: 3.2,
            actual_roi_ratio: 1.6,
            measured_at: std::time::SystemTime::now(),
        };

        coordinator.record_telemetry(telemetry);

        // Verify statistics are updated
        let stats = coordinator.get_mode_statistics();
        assert!(stats.contains_key(&RepairMode::Lossy));

        let lossy_stats = &stats[&RepairMode::Lossy];
        assert_eq!(lossy_stats.usage_count, 1);
        assert_eq!(lossy_stats.success_rate, 1.0);
        assert!((lossy_stats.avg_predicted_roi - 1.5).abs() < 0.01);
        assert!((lossy_stats.avg_actual_roi - 1.6).abs() < 0.01);

        // Test decision history
        let history = coordinator.get_decision_history(10);
        assert!(history.len() <= 10);
    }

    /// Test repair mode descriptions and metadata
    #[test]
    fn test_repair_mode_metadata() {
        // Test mode descriptions match epic requirements
        assert_eq!(
            RepairMode::Off.description(),
            "no repair - exact retransmission only"
        );
        assert_eq!(
            RepairMode::Tail.description(),
            "tail repair for last missing chunks"
        );
        assert_eq!(
            RepairMode::Lossy.description(),
            "preemptive repair for lossy paths"
        );
        assert_eq!(
            RepairMode::ResumeRepair.description(),
            "repair gaps from interrupted transfers"
        );
        assert_eq!(
            RepairMode::Swarm.description(),
            "multi-peer swarm coordination"
        );
        assert_eq!(
            RepairMode::RelayExpensive.description(),
            "minimize relay bandwidth usage"
        );

        // Test multi-source requirements
        assert!(RepairMode::Swarm.requires_multi_source());
        assert!(RepairMode::Broadcast.requires_multi_source());
        assert!(!RepairMode::Tail.requires_multi_source());
        assert!(!RepairMode::Lossy.requires_multi_source());

        // Test overhead multipliers are reasonable
        assert_eq!(RepairMode::Off.typical_overhead_multiplier(), 0.0);
        assert!(RepairMode::Tail.typical_overhead_multiplier() > 0.0);
        assert!(RepairMode::Tail.typical_overhead_multiplier() < RepairMode::Lossy.typical_overhead_multiplier());
        assert!(RepairMode::RelayExpensive.typical_overhead_multiplier() > RepairMode::ResumeRepair.typical_overhead_multiplier());
    }
}