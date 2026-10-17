    use super::*;

    #[test]
    fn test_quality_metrics_creation() {
        let metrics = QualityMetrics::new();
        assert_eq!(metrics.transfer_metrics.len(), 0);
        assert_eq!(metrics.peer_metrics.len(), 0);
    }

    #[test]
    fn test_start_transfer_tracking() {
        let mut metrics = QualityMetrics::new();
        let transfer_id = MailboxTransferId::new();

        metrics.start_transfer_tracking(transfer_id);

        assert!(metrics.transfer_metrics.contains_key(&transfer_id));
        assert_eq!(metrics.global_metrics.active_transfers, 1);
    }

    #[test]
    fn test_start_peer_tracking() {
        let mut metrics = QualityMetrics::new();
        let peer_id = PeerId::new("test-peer");

        metrics.start_peer_tracking(peer_id.clone());

        assert!(metrics.peer_metrics.contains_key(&peer_id));
        assert_eq!(metrics.global_metrics.active_peers, 1);
    }

    #[test]
    fn test_record_metrics() {
        let mut metrics = QualityMetrics::new();
        let transfer_id = MailboxTransferId::new();
        let peer_id = PeerId::new("test-peer");

        metrics.start_transfer_tracking(transfer_id);
        metrics.start_peer_tracking(peer_id.clone());

        metrics.record_download_rate(&transfer_id, 1_000_000.0);
        metrics.record_peer_response_time(&transfer_id, &peer_id, Duration::from_millis(100));

        let transfer_metrics = metrics.transfer_metrics.get(&transfer_id).unwrap();
        assert_eq!(transfer_metrics.download_rate_history.len(), 1);
        assert_eq!(
            transfer_metrics
                .peer_response_times
                .get(&peer_id)
                .unwrap()
                .len(),
            1
        );

        let peer_metrics = metrics.peer_metrics.get(&peer_id).unwrap();
        assert_eq!(peer_metrics.response_times.len(), 1);
    }

    #[test]
    fn test_timestamped_metric() {
        let metric = TimestampedMetric::new(42.0);
        assert_eq!(metric.value, 42.0);
        assert!(metric.metadata.is_none());

        let metric_with_meta = TimestampedMetric::with_metadata(42.0, "test".to_string());
        assert_eq!(metric_with_meta.value, 42.0);
        assert_eq!(metric_with_meta.metadata, Some("test".to_string()));
    }
