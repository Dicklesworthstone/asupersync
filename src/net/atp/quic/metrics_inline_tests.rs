    use super::*;
    use crate::net::quic_native::QuicTransportMachine;

    #[test]
    fn path_performance_classification() {
        let mut metrics = AtpTransportMetrics {
            connection_id: "test".to_string(),
            path_id: "path1".to_string(),
            smoothed_rtt_micros: Some(30_000), // 30ms
            latest_rtt_micros: Some(32_000),
            rttvar_micros: Some(5_000),
            bytes_in_flight: 1200,
            congestion_window_bytes: 12_000,
            ssthresh_bytes: 24_000,
            pto_count: 0,
            congestion_limited: false,
            anti_amplification_limited: false,
            packets_sent: 100,
            packets_lost: 1,
            packets_acked: 99,
            loss_rate: 0.01,
            path_stability: 0.95,
            last_updated: Instant::now(),
            path_doctor_assessment: None,
        };

        // Should be excellent with low RTT, low loss, no congestion, high stability
        assert_eq!(
            PathPerformanceClass::from_metrics(&metrics),
            PathPerformanceClass::Excellent
        );

        // Higher loss should degrade performance
        metrics.loss_rate = 0.1;
        assert_eq!(
            PathPerformanceClass::from_metrics(&metrics),
            PathPerformanceClass::Good
        );

        // High RTT should further degrade
        metrics.smoothed_rtt_micros = Some(400_000); // 400ms
        assert_eq!(
            PathPerformanceClass::from_metrics(&metrics),
            PathPerformanceClass::Poor
        );
    }

    #[test]
    fn saturating_load_guard_accepts_flat_rss_and_responsive_host() {
        let config = SaturatingLoadGuardConfig::new(8 * 1024 * 1024, 8.0, 0.85, 3);
        let baseline = 128 * 1024 * 1024;
        let samples = [
            SaturatingLoadSample {
                elapsed_ms: 0,
                baseline_rss_bytes: baseline,
                rss_bytes: baseline + 1024 * 1024,
                loadavg_1m: 2.0,
                cpu_pressure: 0.20,
                goodput_bps: 700 * 1024 * 1024,
            },
            SaturatingLoadSample {
                elapsed_ms: 200,
                baseline_rss_bytes: baseline,
                rss_bytes: baseline + 2 * 1024 * 1024,
                loadavg_1m: 3.5,
                cpu_pressure: 0.40,
                goodput_bps: 930 * 1024 * 1024,
            },
            SaturatingLoadSample {
                elapsed_ms: 400,
                baseline_rss_bytes: baseline,
                rss_bytes: baseline + 2 * 1024 * 1024,
                loadavg_1m: 4.0,
                cpu_pressure: 0.50,
                goodput_bps: 920 * 1024 * 1024,
            },
        ];

        let report = SaturatingLoadGuardReport::evaluate(config, &samples);

        assert!(report.passed, "{report:?}");
        assert!(report.violations.is_empty());
        assert_eq!(report.sample_count, 3);
        assert_eq!(report.peak_rss_growth_bytes, 2 * 1024 * 1024);
        assert_eq!(report.peak_goodput_bps, 930 * 1024 * 1024);
        assert!(
            report.pacer_responsiveness_pressure > 0.0
                && report.pacer_responsiveness_pressure < 1.0
        );
    }

    #[test]
    fn saturating_load_guard_fails_closed_on_rss_load_and_cpu_pressure() {
        let config = SaturatingLoadGuardConfig::new(4 * 1024 * 1024, 4.0, 0.70, 2);
        let baseline = 64 * 1024 * 1024;
        let samples = [
            SaturatingLoadSample {
                elapsed_ms: 0,
                baseline_rss_bytes: baseline,
                rss_bytes: baseline + 1024 * 1024,
                loadavg_1m: 3.0,
                cpu_pressure: 0.30,
                goodput_bps: 100,
            },
            SaturatingLoadSample {
                elapsed_ms: 200,
                baseline_rss_bytes: baseline,
                rss_bytes: baseline + 12 * 1024 * 1024,
                loadavg_1m: 5.5,
                cpu_pressure: 0.95,
                goodput_bps: 200,
            },
        ];

        let report = SaturatingLoadGuardReport::evaluate(config, &samples);

        assert!(!report.passed);
        assert_eq!(report.pacer_responsiveness_pressure, 1.0);
        assert!(report.violations.iter().any(|violation| matches!(
            violation,
            SaturatingLoadGuardViolation::RssGrowthExceeded {
                observed_bytes,
                cap_bytes
            } if *observed_bytes == 12 * 1024 * 1024 && *cap_bytes == 4 * 1024 * 1024
        )));
        assert!(report.violations.iter().any(|violation| matches!(
            violation,
            SaturatingLoadGuardViolation::LoadAverageExceeded { observed, cap }
                if (*observed - 5.5).abs() < f64::EPSILON && (*cap - 4.0).abs() < f64::EPSILON
        )));
        assert!(report.violations.iter().any(|violation| matches!(
            violation,
            SaturatingLoadGuardViolation::CpuPressureExceeded { observed, cap }
                if (*observed - 0.95).abs() < f64::EPSILON && (*cap - 0.70).abs() < f64::EPSILON
        )));
    }

    #[test]
    fn saturating_load_guard_requires_enough_samples() {
        let config = SaturatingLoadGuardConfig::new(1024, 1.0, 0.5, 3);
        let sample = SaturatingLoadSample {
            elapsed_ms: 0,
            baseline_rss_bytes: 4096,
            rss_bytes: 4096,
            loadavg_1m: 0.1,
            cpu_pressure: 0.1,
            goodput_bps: 1,
        };

        let report = SaturatingLoadGuardReport::evaluate(config, &[sample]);

        assert!(!report.passed);
        assert_eq!(report.pacer_responsiveness_pressure, 1.0);
        assert_eq!(
            report.violations,
            vec![SaturatingLoadGuardViolation::InsufficientSamples {
                observed: 1,
                required: 3
            }]
        );
    }

    #[test]
    fn anti_amplification_limits() {
        let mut limiter = AntiAmplificationLimiter::new();

        // No peer bytes received yet, so sending any bytes exceeds the budget.
        limiter.on_packet_sent(1000);
        assert!(limiter.is_limited());

        // Receive 400 bytes from the peer: the server may send up to 1200 bytes.
        limiter.on_datagram_received(400);
        assert!(!limiter.is_limited());

        // Sending beyond the 3x received budget is limited.
        limiter.on_packet_sent(201);
        assert!(limiter.is_limited());

        // Receiving an ACK validates the address and lifts the limiter.
        limiter.on_ack_received(0);
        assert!(!limiter.is_limited());
    }

    #[test]
    fn path_stability_tracking() {
        let mut tracker = PathStabilityTracker::new();

        // Add consistent RTT samples
        for _ in 0..10 {
            tracker.update_rtt(50_000); // Consistent 50ms
        }

        let stable_score = tracker.stability_score();
        assert!(
            stable_score > 0.9,
            "Consistent RTT should give high stability"
        );

        // Add variable RTT samples
        for rtt in [25_000, 75_000, 40_000, 90_000, 30_000] {
            tracker.update_rtt(rtt);
        }

        let variable_score = tracker.stability_score();
        assert!(
            variable_score < stable_score,
            "Variable RTT should reduce stability"
        );

        // Add loss events
        tracker.on_packet_lost();
        tracker.on_packet_lost();

        let loss_score = tracker.stability_score();
        assert!(
            loss_score < variable_score,
            "Packet loss should further reduce stability"
        );
    }

    #[test]
    fn metrics_collector_integration() {
        let mut collector =
            AtpTransportMetricsCollector::new("conn123".to_string(), "path456".to_string());

        let mut transport = QuicTransportMachine::new();

        // Send some packets
        collector.on_packet_sent(1200);
        collector.on_packet_sent(1200);

        // Ack one packet
        collector.on_packet_acked(1200);

        // Lose one packet
        collector.on_packet_lost(1200);

        // Record PTO backoff in both the transport machine and collector.
        transport.on_pto_expired();
        transport.on_pto_expired();
        collector.on_pto_expired();
        collector.on_pto_expired();

        let metrics = collector.current_metrics(&transport);

        assert_eq!(metrics.packets_sent, 2);
        assert_eq!(metrics.packets_acked, 1);
        assert_eq!(metrics.packets_lost, 1);
        assert_eq!(metrics.pto_count, 2);
        assert_eq!(metrics.loss_rate, 0.5);
        assert_eq!(metrics.connection_id, "conn123");
        assert_eq!(metrics.path_id, "path456");
    }
