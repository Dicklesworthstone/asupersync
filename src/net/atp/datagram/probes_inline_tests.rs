    use super::*;
    use crate::net::atp::datagram::transport::DatagramTransport;

    #[test]
    fn test_probe_creation() {
        let probe = PathProbe::new_request(123, ProbeType::Rtt, 1, 42);
        assert_eq!(probe.probe_id, 123);
        assert_eq!(probe.probe_type, ProbeType::Rtt);
        assert_eq!(probe.path_id, 1);
        assert_eq!(probe.sequence, 42);
        assert!(!probe.is_response);

        let response = probe.new_response();
        assert_eq!(response.probe_id, 123);
        assert!(response.is_response);
    }

    #[test]
    fn test_probe_encoding_decoding() {
        let probe = PathProbe::new_request(456, ProbeType::Discovery, 2, 100)
            .with_challenge(vec![1, 2, 3, 4]);

        let encoded = probe.encode().unwrap();
        let decoded = PathProbe::decode(&encoded).unwrap();

        assert_eq!(decoded.probe_id, probe.probe_id);
        assert_eq!(decoded.probe_type, probe.probe_type);
        assert_eq!(decoded.challenge, probe.challenge);
    }

    #[test]
    fn test_probe_manager() {
        let transport = DatagramTransport::default_enabled();
        let mut manager = ProbeManager::new(transport);

        // Create probe
        let _frame = manager.create_probe(ProbeType::Rtt, 1).unwrap();
        assert_eq!(manager.pending_count(), 1);

        // Verify stats updated
        let stats = manager.get_path_stats(1).unwrap();
        assert_eq!(stats.probes_sent, 1);
        assert_eq!(stats.responses_received, 0);
    }

    #[test]
    fn test_validation_probe_carries_entropy_challenge() {
        let transport = DatagramTransport::default_enabled();
        let mut manager = ProbeManager::new(transport);

        let frame = manager.create_probe(ProbeType::Validation, 7).unwrap();
        let probe = PathProbe::decode(frame.payload()).unwrap();
        let challenge = probe.challenge.expect("validation challenge");

        assert_eq!(challenge.len(), PROBE_CHALLENGE_LEN);
    }

    #[test]
    fn test_probe_response_rtt_uses_local_send_instant() {
        let transport = DatagramTransport::default_enabled();
        let mut manager = ProbeManager::new(transport);
        let request = PathProbe::new_request(99, ProbeType::Rtt, 7, 1);
        let sent_at = Instant::now()
            .checked_sub(Duration::from_millis(50))
            .expect("instant subtraction");

        manager
            .pending_probes
            .insert(request.probe_id, (request.clone(), sent_at));
        manager
            .path_stats
            .entry(request.path_id)
            .or_default()
            .update_probe_sent();

        let mut response = request.new_response();
        response.timestamp = request.timestamp;
        manager.handle_probe_response(response).unwrap();

        let stats = manager.get_path_stats(request.path_id).unwrap();
        assert_eq!(stats.responses_received, 1);
        assert!(stats.min_rtt_us >= 50_000);
    }

    #[test]
    fn test_probe_response_metadata_mismatch_is_ignored() {
        let transport = DatagramTransport::default_enabled();
        let mut manager = ProbeManager::new(transport);
        let request = PathProbe::new_request(100, ProbeType::Rtt, 7, 1);

        manager
            .pending_probes
            .insert(request.probe_id, (request.clone(), Instant::now()));
        manager
            .path_stats
            .entry(request.path_id)
            .or_default()
            .update_probe_sent();

        let mut response = request.new_response();
        response.path_id = 8;
        manager.handle_probe_response(response).unwrap();

        let original_path_stats = manager.get_path_stats(request.path_id).unwrap();
        assert_eq!(original_path_stats.responses_received, 0);
        assert!(manager.get_path_stats(8).is_none());
    }

    #[test]
    fn test_probe_stats() {
        let mut stats = ProbeStats::default();

        // Send probe
        stats.update_probe_sent();
        assert_eq!(stats.probes_sent, 1);
        assert_eq!(stats.loss_ratio, 1.0);

        // Receive response
        stats.update_response_received(Duration::from_millis(50));
        assert_eq!(stats.responses_received, 1);
        assert_eq!(stats.loss_ratio, 0.0);
        assert_eq!(stats.min_rtt_us, 50_000);
        assert_eq!(stats.avg_rtt_us, 50_000.0);

        // Check health
        assert!(stats.is_healthy());
    }

    #[test]
    fn test_probe_types() {
        assert_eq!(ProbeType::Discovery.priority(), DatagramPriority::High);
        assert_eq!(ProbeType::Bandwidth.priority(), DatagramPriority::Low);
        assert!(ProbeType::Discovery.timeout() > ProbeType::Validation.timeout());
        assert!(ProbeType::Bandwidth.payload_size() > ProbeType::Rtt.payload_size());
    }

    #[test]
    fn test_rtt_calculation() {
        let request = PathProbe::new_request(1, ProbeType::Rtt, 1, 1);
        let mut response = request.new_response();
        response.timestamp = request.timestamp + 10_000;

        let rtt = request.calculate_rtt(&response);
        assert_eq!(rtt, Some(Duration::from_millis(10)));
    }

    #[test]
    fn test_cleanup_expired_probes() {
        let transport = DatagramTransport::default_enabled();
        let mut manager = ProbeManager::new(transport);

        // Create probe
        manager.create_probe(ProbeType::Rtt, 1).unwrap();
        assert_eq!(manager.pending_count(), 1);

        // Cleanup with recent timestamp - should retain
        manager.cleanup_expired_probes(Instant::now());
        assert_eq!(manager.pending_count(), 1);

        // Cleanup with old timestamp - should remove
        manager.cleanup_expired_probes(Instant::now() + Duration::from_secs(60));
        assert_eq!(manager.pending_count(), 0);
    }
