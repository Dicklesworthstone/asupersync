    use super::*;
    use crate::net::quic_native::{PacketNumberSpace, RttEstimator, SentPacketMeta};

    fn create_test_packet(pn: u64, time_micros: u64) -> SentPacketMeta {
        SentPacketMeta {
            space: PacketNumberSpace::ApplicationData,
            packet_number: pn,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            time_sent_micros: time_micros,
        }
    }

    fn test_conditions() -> NetworkConditions {
        NetworkConditions {
            rtt_micros: Some(100_000),
            rttvar_micros: Some(25_000),
            loss_rate: 0.0,
            bytes_in_flight: 6000,
            congestion_window: 12_000,
        }
    }

    #[test]
    fn persistent_congestion_detection_basic() {
        let mut detector = PersistentCongestionDetector::new();
        let mut rtt = RttEstimator::default();
        rtt.update(100_000, 0); // 100ms RTT

        // Create lost packets spanning enough time for persistent congestion
        let lost_packets = vec![
            create_test_packet(0, 0),
            create_test_packet(1, 50_000),
            create_test_packet(2, 400_000), // 400ms span > 3 * 100ms threshold
        ];

        let result = detector.check_persistent_congestion(
            &lost_packets,
            &rtt,
            3600,  // bytes in flight
            12000, // congestion window
            Instant::now(),
        );

        assert!(result.is_persistent_congestion);
        assert!(result.severity > 0.0);
        assert!(!result.recommendations.is_empty());
    }

    #[test]
    fn persistent_congestion_not_detected() {
        let mut detector = PersistentCongestionDetector::new();
        let mut rtt = RttEstimator::default();
        rtt.update(100_000, 0); // 100ms RTT

        // Create lost packets with short span
        let lost_packets = vec![
            create_test_packet(0, 0),
            create_test_packet(1, 50_000), // Only 50ms span < 3 * 100ms threshold
        ];

        let result = detector.check_persistent_congestion(
            &lost_packets,
            &rtt,
            2400,  // bytes in flight
            12000, // congestion window
            Instant::now(),
        );

        assert!(!result.is_persistent_congestion);
        assert!(result.severity < 0.5);
    }

    #[test]
    fn congestion_severity_calculation() {
        let detector = PersistentCongestionDetector::new();

        let conditions = NetworkConditions {
            rtt_micros: Some(200_000), // 200ms
            rttvar_micros: Some(50_000),
            loss_rate: 0.1,
            bytes_in_flight: 6000,
            congestion_window: 12000,
        };

        let severity = detector.calculate_congestion_severity(
            &conditions,
            600_000, // 600ms duration
            300_000, // 300ms threshold
        );

        assert!(
            severity > 0.3,
            "Severity should be significant: {}",
            severity
        );
        assert!(severity < 1.0, "Severity should be bounded: {}", severity);
    }

    #[test]
    fn epoch_management() {
        let mut detector = PersistentCongestionDetector::new();
        let now = Instant::now();

        // Start epoch
        detector.start_or_extend_epoch(0.6, now);
        assert!(detector.current_epoch.is_some());
        assert_eq!(detector.metrics.total_episodes, 1);

        // Extend epoch
        detector.start_or_extend_epoch(0.8, now);
        assert!(detector.current_epoch.is_some());
        assert_eq!(detector.metrics.total_episodes, 1); // Should not increment

        // End epoch
        detector.end_current_epoch(now + Duration::from_millis(100));
        assert!(detector.current_epoch.is_none());
        assert!(detector.metrics.total_duration_micros > 0);
    }

    #[test]
    fn adaptive_threshold_calculation() {
        let detector = PersistentCongestionDetector::with_config(PersistentCongestionConfig {
            adaptive_threshold: true,
            ..Default::default()
        });

        let mut rtt = RttEstimator::default();
        rtt.update(100_000, 0); // 100ms base RTT
        rtt.update(150_000, 0); // Variable RTT to create variance

        let threshold = detector.calculate_threshold_duration(&rtt);
        let base_threshold = 100_000.0 * 3.0; // Base threshold

        // Adaptive threshold should be different from base
        assert_ne!(threshold as f64, base_threshold);
        assert!(threshold >= detector.config.min_duration_micros);
    }

    #[test]
    fn rtt_spike_requires_positive_increasing_baseline() {
        let mut detector = PersistentCongestionDetector::new();

        detector.on_rtt_spike(0, 100_000, test_conditions());
        detector.on_rtt_spike(100_000, 100_000, test_conditions());
        detector.on_rtt_spike(100_000, 90_000, test_conditions());

        assert!(detector.congestion_events.is_empty());

        detector.on_rtt_spike(100_000, 250_000, test_conditions());
        assert_eq!(detector.congestion_events.len(), 1);
    }

    #[test]
    fn cwnd_reduction_requires_positive_decrease() {
        let mut detector = PersistentCongestionDetector::new();

        detector.on_cwnd_reduction(0, 0, test_conditions());
        detector.on_cwnd_reduction(10_000, 10_000, test_conditions());
        detector.on_cwnd_reduction(10_000, 12_000, test_conditions());
        detector.on_cwnd_reduction(10_000, 9_500, test_conditions());

        assert!(detector.congestion_events.is_empty());

        detector.on_cwnd_reduction(10_000, 8_000, test_conditions());
        assert_eq!(detector.congestion_events.len(), 1);
    }

    #[test]
    fn tracking_window_that_precedes_instant_epoch_keeps_current_events() {
        let mut detector = PersistentCongestionDetector::with_config(PersistentCongestionConfig {
            tracking_window_micros: u64::MAX,
            ..Default::default()
        });

        detector.on_pto_event(test_conditions());

        assert_eq!(detector.congestion_events.len(), 1);
    }

    #[test]
    fn ending_epoch_before_start_saturates_to_zero_duration() {
        let mut detector = PersistentCongestionDetector::new();
        let now = Instant::now();

        detector.start_or_extend_epoch(0.6, now);
        let earlier = now.checked_sub(Duration::from_millis(1)).unwrap_or(now);
        detector.end_current_epoch(earlier);

        assert_eq!(detector.metrics.total_duration_micros, 0);
        assert!(detector.metrics.avg_episode_duration_micros.abs() < f64::EPSILON);
        assert!(detector.current_epoch.is_none());
    }

    #[test]
    fn loss_rate_uses_saturating_sum_and_is_capped() {
        let detector = PersistentCongestionDetector::new();
        let lost_packets = [
            SentPacketMeta {
                bytes: u64::MAX,
                ..create_test_packet(0, 0)
            },
            SentPacketMeta {
                bytes: u64::MAX,
                ..create_test_packet(1, 10)
            },
        ];

        let loss_rate = detector.estimate_loss_rate(&lost_packets, 1200);

        assert!((loss_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_threshold_doubling_is_saturating() {
        let detector = PersistentCongestionDetector::new();

        let confidence = detector.calculate_detection_confidence(0.5, u64::MAX, u64::MAX);

        assert!(confidence.is_finite());
        assert!(confidence > 0.0);
    }
