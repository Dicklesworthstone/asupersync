    use super::*;
    use crate::net::quic_native::{
        AckRange, PacketNumberSpace, QuicTransportMachine, RttEstimator, SentPacketMeta,
    };

    fn create_test_packet(space: PacketNumberSpace, pn: u64, time: u64) -> SentPacketMeta {
        SentPacketMeta {
            space,
            packet_number: pn,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            time_sent_micros: time,
        }
    }

    fn test_transport_state(rtt: &RttEstimator) -> LossTransportState {
        LossTransportState::from_rtt_and_recovery(rtt, 4_800, 12_000)
    }

    fn packet_threshold_only_detector() -> AtpLossDetector {
        AtpLossDetector::with_config(LossDetectionConfig {
            adaptive_packet_threshold: false,
            enable_early_retransmit: false,
            ..LossDetectionConfig::default()
        })
    }

    #[test]
    fn datagram_loss_sample_emits_advisory_recommendations() {
        let mut detector = AtpLossDetector::new();

        let result = detector.observe_datagram_loss_sample(
            100,
            10,
            Some(Duration::from_millis(25)),
            120_000,
            240_000,
        );

        assert_eq!(result.lost_packets.len(), 10);
        assert_eq!(result.lost_packet_count, 10);
        assert_eq!(result.lost_bytes, 12_000);
        let signal = result.transfer_signal(100);
        assert_eq!(signal.loss_pressure, 0.1);
        assert_eq!(signal.cwnd_reduction_factor, Some(0.5));
        assert!(
            signal
                .repair_rate_hint
                .is_some_and(|rate| (rate - 0.15).abs() < f64::EPSILON)
        );
        assert!(result.recommendations.iter().any(|recommendation| {
            matches!(
                recommendation,
                LossRecommendation::ReduceCongestionWindow { .. }
            )
        }));
    }

    #[test]
    fn transfer_signal_keeps_congestion_hints_out_of_fec_pressure() {
        let result = LossDetectionResult {
            lost_packets: Vec::new(),
            lost_packet_count: 0,
            lost_bytes: 0,
            detection_method: LossDetectionMethod::PacketThreshold,
            confidence: 0.9,
            recommendations: vec![
                LossRecommendation::ReduceCongestionWindow { factor: 0.5 },
                LossRecommendation::EnablePacing { rate: 75_000 },
                LossRecommendation::SwitchCongestionControl {
                    algorithm: "bbr".to_string(),
                },
            ],
        };

        let signal = result.transfer_signal(100);

        assert_eq!(signal.loss_pressure, 0.0);
        assert_eq!(signal.repair_rate_hint, None);
        assert_eq!(signal.cwnd_reduction_factor, Some(0.5));
        assert_eq!(signal.pacing_rate_hint, Some(75_000));
        assert!(signal.prefer_bbr);
    }

    #[test]
    fn transfer_signal_bounds_explicit_fec_pressure() {
        let result = LossDetectionResult {
            lost_packets: Vec::new(),
            lost_packet_count: 0,
            lost_bytes: 0,
            detection_method: LossDetectionMethod::PacketThreshold,
            confidence: 1.0,
            recommendations: vec![
                LossRecommendation::EnableFec { rate: 0.01 },
                LossRecommendation::EnableFec { rate: 0.9 },
                LossRecommendation::EnableFec { rate: f64::NAN },
            ],
        };

        let signal = result.transfer_signal(0);

        assert_eq!(signal.loss_pressure, 0.3);
        assert_eq!(signal.repair_rate_hint, Some(0.3));
    }

    #[test]
    fn loss_detector_packet_threshold() {
        let mut detector = packet_threshold_only_detector();
        let rtt = RttEstimator::default();

        // Send packets 0-5
        for pn in 0..6 {
            detector.on_packet_sent(create_test_packet(
                PacketNumberSpace::ApplicationData,
                pn,
                pn * 1000,
            ));
        }

        // ACK packet 5 (should cause 0, 1, 2 to be declared lost via packet threshold)
        let ack_ranges = [AckRange::new(5, 5).unwrap()];
        let result = detector
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &ack_ranges,
                0,
                10_000,
                &test_transport_state(&rtt),
            )
            .expect("Should detect losses");

        assert_eq!(result.lost_packets.len(), 3); // Packets 0, 1, 2 lost
        assert_eq!(
            result.detection_method,
            LossDetectionMethod::PacketThreshold
        );
        assert!(
            result
                .lost_packets
                .iter()
                .all(|packet| matches!(packet.reason, LossReason::PacketThreshold { .. }))
        );
        assert_eq!(detector.metrics().time_threshold_losses, 0);
    }

    #[test]
    fn time_threshold_waits_until_boundary_is_reachable() {
        let mut detector = packet_threshold_only_detector();
        let rtt = RttEstimator::default();

        // Default base RTT is 333ms, so the 9/8 time threshold is far beyond
        // this 10ms ACK. Packet 0 has timestamp zero and must not be upgraded
        // to a combined packet+time loss by a saturated boundary of zero.
        for pn in 0..6 {
            detector.on_packet_sent(create_test_packet(
                PacketNumberSpace::ApplicationData,
                pn,
                pn * 1000,
            ));
        }

        let ack_ranges = [AckRange::new(5, 5).unwrap()];
        let result = detector
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &ack_ranges,
                0,
                10_000,
                &test_transport_state(&rtt),
            )
            .expect("packet-threshold losses should be detected");

        assert_eq!(
            result
                .lost_packets
                .iter()
                .map(|packet| (packet.packet_number, packet.reason))
                .collect::<Vec<_>>(),
            vec![
                (0, LossReason::PacketThreshold { threshold: 3 }),
                (1, LossReason::PacketThreshold { threshold: 3 }),
                (2, LossReason::PacketThreshold { threshold: 3 }),
            ]
        );
        assert_eq!(
            result.detection_method,
            LossDetectionMethod::PacketThreshold
        );
        assert_eq!(detector.metrics().time_threshold_losses, 0);
    }

    #[test]
    fn loss_detector_time_threshold() {
        let mut detector = AtpLossDetector::new();
        let mut rtt = RttEstimator::default();
        rtt.update(100_000, 0); // 100ms RTT

        // Send packets with significant time gaps
        detector.on_packet_sent(create_test_packet(PacketNumberSpace::ApplicationData, 0, 0));
        detector.on_packet_sent(create_test_packet(
            PacketNumberSpace::ApplicationData,
            1,
            1000,
        ));

        // ACK packet 1 much later (should cause packet 0 to be lost via time threshold)
        let ack_ranges = [AckRange::new(1, 1).unwrap()];
        let result = detector
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &ack_ranges,
                0,
                200_000, // 200ms later
                &test_transport_state(&rtt),
            )
            .expect("Should detect losses");

        assert_eq!(result.lost_packets.len(), 1); // Packet 0 lost
        assert_eq!(result.detection_method, LossDetectionMethod::TimeThreshold);
    }

    #[test]
    fn loss_pattern_analysis() {
        let mut detector = AtpLossDetector::new();

        // Drive a burst-loss packet pattern.
        for _ in 0..5 {
            let rtt = RttEstimator::default();
            for pn in 0..10 {
                detector.on_packet_sent(create_test_packet(
                    PacketNumberSpace::ApplicationData,
                    pn,
                    pn * 1000,
                ));
            }

            // Lose packets 0-4 (burst)
            let ack_ranges = [AckRange::new(9, 5).unwrap()];
            let _result = detector
                .on_ack_received(
                    PacketNumberSpace::ApplicationData,
                    &ack_ranges,
                    0,
                    50_000,
                    &test_transport_state(&rtt),
                )
                .unwrap();
        }

        // Should detect burst pattern
        detector.analyze_loss_patterns();
        assert!(
            detector
                .pattern_analyzer
                .patterns
                .contains(&LossPattern::Burst)
        );
    }

    #[test]
    fn reordering_detection() {
        let mut tracker = ReorderingTracker::new();
        let initial_threshold = tracker.current_threshold;

        // Drive reordering-threshold adaptation.
        tracker.adapt_threshold();

        assert!(tracker.current_threshold > initial_threshold);
    }

    #[test]
    fn loss_pattern_analysis_records_transport_recovery_state() {
        let mut detector = AtpLossDetector::new();
        let mut rtt = RttEstimator::default();
        rtt.update(100_000, 0);
        let transport_state = LossTransportState::from_rtt_and_recovery(&rtt, 6_000, 24_000);

        for pn in 0..6 {
            detector.on_packet_sent(create_test_packet(
                PacketNumberSpace::ApplicationData,
                pn,
                pn * 1000,
            ));
        }

        let ack_ranges = [AckRange::new(5, 5).unwrap()];
        let result = detector
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &ack_ranges,
                0,
                10_000,
                &transport_state,
            )
            .expect("Should detect losses");

        assert!(!result.lost_packets.is_empty());
        let event = detector
            .pattern_analyzer
            .loss_events
            .back()
            .expect("loss event recorded");
        assert_eq!(event.conditions.rtt_micros, Some(100_000));
        assert_eq!(event.conditions.rttvar_micros, Some(50_000));
        assert_eq!(event.conditions.bytes_in_flight, 6_000);
        assert_eq!(event.conditions.congestion_window, 24_000);
    }

    #[test]
    fn transport_state_reads_native_quic_recovery_counters() {
        let mut transport = QuicTransportMachine::new();
        transport.on_packet_sent(create_test_packet(
            PacketNumberSpace::ApplicationData,
            0,
            18_000,
        ));
        transport.on_packet_sent(create_test_packet(
            PacketNumberSpace::ApplicationData,
            1,
            20_000,
        ));

        let initial_state = LossTransportState::from_transport(&transport);
        assert_eq!(initial_state.bytes_in_flight, 2_400);
        assert_eq!(
            initial_state.congestion_window,
            transport.congestion_window_bytes()
        );
        assert_eq!(initial_state.latest_rtt_micros, None);

        // The new 30 ms RTT sets a 33.75 ms loss delay; packet 0 is only 32 ms old.
        let ack = transport.on_ack_received(PacketNumberSpace::ApplicationData, &[1], 0, 50_000);
        assert_eq!(ack.lost_packets, 0);
        let acked_state = LossTransportState::from_transport(&transport);
        assert_eq!(acked_state.bytes_in_flight, 1_200);
        assert_eq!(acked_state.latest_rtt_micros, Some(30_000));
        assert_eq!(acked_state.smoothed_rtt_micros, Some(30_000));
        assert_eq!(acked_state.rttvar_micros, Some(15_000));
    }

    #[test]
    fn ack_matching_canonicalizes_ranges_before_hash_lookup() {
        let mut detector = AtpLossDetector::new();
        let rtt = RttEstimator::default();

        for pn in 0..13 {
            detector.on_packet_sent(create_test_packet(
                PacketNumberSpace::ApplicationData,
                pn,
                pn * 1000,
            ));
        }

        let ack_ranges = [
            AckRange::new(9, 7).unwrap(),
            AckRange::new(3, 1).unwrap(),
            AckRange::new(8, 5).unwrap(),
        ];
        let result = detector
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &ack_ranges,
                0,
                10_000,
                &test_transport_state(&rtt),
            )
            .expect("ACK ranges should be processed");

        assert_eq!(
            result
                .lost_packets
                .iter()
                .map(|packet| packet.packet_number)
                .collect::<Vec<_>>(),
            vec![0, 4]
        );
        assert_eq!(
            detector.spaces[PacketNumberSpace::ApplicationData as usize]
                .sent_packets
                .iter()
                .map(|packet| packet.packet_number)
                .collect::<Vec<_>>(),
            vec![10, 11, 12]
        );
    }

    #[test]
    fn ack_matching_ignores_unsent_packet_numbers() {
        let mut detector = AtpLossDetector::new();
        let rtt = RttEstimator::default();

        for pn in 0..5 {
            detector.on_packet_sent(create_test_packet(
                PacketNumberSpace::ApplicationData,
                pn,
                pn * 1000,
            ));
        }

        let ack_ranges = [AckRange::new(1_000_000, 1_000_000).unwrap()];
        let result = detector
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &ack_ranges,
                0,
                10_000,
                &test_transport_state(&rtt),
            )
            .expect("Unsent ACK should not fail");

        assert!(result.lost_packets.is_empty());
        assert_eq!(
            detector.spaces[PacketNumberSpace::ApplicationData as usize]
                .sent_packets
                .iter()
                .map(|packet| packet.packet_number)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn early_retransmit_threshold_does_not_overflow_at_max_packet_number() {
        let mut detector = AtpLossDetector::new();
        let rtt = RttEstimator::default();

        detector.on_packet_sent(create_test_packet(
            PacketNumberSpace::ApplicationData,
            u64::MAX - 1,
            1_000,
        ));
        detector.on_packet_sent(create_test_packet(
            PacketNumberSpace::ApplicationData,
            u64::MAX,
            1_100,
        ));

        let ack_ranges = [AckRange::new(u64::MAX - 1, u64::MAX - 1).unwrap()];
        let result = detector
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &ack_ranges,
                0,
                2_000,
                &test_transport_state(&rtt),
            )
            .expect("overflow-edge ACK should be processed");

        assert!(result.lost_packets.is_empty());
        assert_eq!(
            detector.spaces[PacketNumberSpace::ApplicationData as usize]
                .sent_packets
                .iter()
                .map(|packet| packet.packet_number)
                .collect::<Vec<_>>(),
            vec![u64::MAX]
        );
    }

    #[test]
    fn late_ack_of_declared_lost_packet_records_one_spurious_loss() {
        let mut detector = packet_threshold_only_detector();
        let rtt = RttEstimator::default();

        for pn in 0..6 {
            detector.on_packet_sent(create_test_packet(
                PacketNumberSpace::ApplicationData,
                pn,
                pn * 1000,
            ));
        }

        let initial_ack = [AckRange::new(5, 5).unwrap()];
        let loss = detector
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &initial_ack,
                0,
                10_000,
                &test_transport_state(&rtt),
            )
            .expect("initial ACK should detect losses");
        assert_eq!(
            loss.lost_packets
                .iter()
                .map(|packet| packet.packet_number)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(detector.metrics().false_losses, 0);

        let late_ack = [AckRange::new(0, 0).unwrap()];
        let late_result = detector
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &late_ack,
                0,
                11_000,
                &test_transport_state(&rtt),
            )
            .expect("late ACK should be processed");
        assert!(late_result.lost_packets.is_empty());
        assert_eq!(detector.metrics().false_losses, 1);
        assert!(
            detector
                .pattern_analyzer
                .patterns
                .contains(&LossPattern::Reordering)
        );

        let duplicate_late_result = detector
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &late_ack,
                0,
                12_000,
                &test_transport_state(&rtt),
            )
            .expect("duplicate late ACK should be processed");
        assert!(duplicate_late_result.lost_packets.is_empty());
        assert_eq!(detector.metrics().false_losses, 1);
    }
