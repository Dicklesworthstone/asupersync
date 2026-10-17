    use super::*;
    use std::time::Duration;

    #[test]
    fn test_network_truth_collector() {
        let collector = NetworkTruthCollector::new();

        // Record some observations
        collector.record_rtt(Duration::from_millis(50));
        collector.record_ack_delay(Duration::from_millis(5));
        collector.record_loss_event();
        collector.record_pto_event();

        // Verify metrics were updated
        assert_eq!(collector.metrics().rtt.count(), 1);
        assert_eq!(collector.metrics().ack_delay.count(), 1);
        assert_eq!(collector.metrics().loss_events.get(), 1);
        assert_eq!(collector.metrics().pto_events.get(), 1);
    }

    #[test]
    fn test_pressure_model_hysteresis() {
        let mut model = PressureModel::new();

        // Initial update should work
        model.update(0.5, 0.3, 0.2, 0.1);
        assert_eq!(model.overall, 0.275);

        // Small change should not update due to hysteresis
        let old_overall = model.overall;
        model.update(0.52, 0.31, 0.21, 0.11);
        assert_eq!(model.overall, old_overall);

        // Large change should update
        model.update(0.8, 0.7, 0.6, 0.5);
        assert!(model.overall > old_overall);
    }

    #[test]
    fn test_path_quality_estimate() {
        let estimate = MetricEstimate {
            value: 50.0,
            lower_bound: 45.0,
            upper_bound: 55.0,
            sample_count: 100,
        };

        // Verify confidence interval makes sense
        assert!(estimate.lower_bound <= estimate.value);
        assert!(estimate.value <= estimate.upper_bound);
        assert!(estimate.sample_count > 0);
    }

    #[test]
    fn test_buffer_pressure_bounds() {
        let collector = NetworkTruthCollector::new();

        // Test boundary values
        collector.update_buffer_pressure(0.0, 0.0);
        assert_eq!(collector.metrics().send_buffer_pressure.get(), 0);
        assert_eq!(collector.metrics().recv_buffer_pressure.get(), 0);

        collector.update_buffer_pressure(1.0, 1.0);
        assert_eq!(collector.metrics().send_buffer_pressure.get(), 100);
        assert_eq!(collector.metrics().recv_buffer_pressure.get(), 100);
    }

    #[test]
    fn test_metric_estimates_serialization() {
        let estimate = MetricEstimate {
            value: 42.0,
            lower_bound: 40.0,
            upper_bound: 44.0,
            sample_count: 1000,
        };

        // Test that serialization works (for CLI/JSON output)
        let json = serde_json::to_string(&estimate).unwrap();
        let deserialized: MetricEstimate = serde_json::from_str(&json).unwrap();

        assert_eq!(estimate.value, deserialized.value);
        assert_eq!(estimate.sample_count, deserialized.sample_count);
    }
