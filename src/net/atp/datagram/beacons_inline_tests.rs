    use super::*;

    #[test]
    fn test_path_beacon_creation() {
        let measurement = BeaconMeasurement::with_rtt(50000, 5000);
        let beacon = PathBeacon::new(1, 42, BeaconType::Periodic, measurement);

        assert_eq!(beacon.sequence, 1);
        assert_eq!(beacon.path_id, 42);
        assert_eq!(beacon.beacon_type, BeaconType::Periodic);
        assert_eq!(beacon.measurement_data.srtt_us, Some(50000));
    }

    #[test]
    fn test_beacon_encoding() {
        let beacon = PathBeacon::periodic(1, 42);
        let encoded = beacon.encode().unwrap();
        let decoded = PathBeacon::decode(&encoded).unwrap();

        assert_eq!(decoded.sequence, beacon.sequence);
        assert_eq!(decoded.path_id, beacon.path_id);
        assert_eq!(decoded.beacon_type, beacon.beacon_type);
        assert_eq!(decoded.control_round_seq, 0);
    }

    #[test]
    fn test_beacon_metadata() {
        let beacon = PathBeacon::periodic(1, 42);
        let metadata = beacon.metadata();

        assert_eq!(metadata.correlation_id, Some(1));
        assert_eq!(metadata.path_id, Some(42));
        assert_eq!(metadata.priority, DatagramPriority::Normal);
        assert_eq!(metadata.payload_class, "beacon_periodic");
    }

    #[test]
    fn test_probe_beacon_creation() {
        let measurement = BeaconMeasurement::with_rtt(50_000, 5_000);
        let beacon = PathBeacon::probe(7, 42, measurement);

        assert_eq!(beacon.sequence, 7);
        assert_eq!(beacon.path_id, 42);
        assert_eq!(beacon.beacon_type, BeaconType::Probe);
        assert_eq!(beacon.metadata().priority, DatagramPriority::High);
    }

    #[test]
    fn test_response_to_preserves_request_correlation() {
        let mut request =
            PathBeacon::probe(7, 42, BeaconMeasurement::empty()).with_control_round_seq(9);
        request.send_timestamp = 1234;

        let response =
            PathBeacon::response_to(&request, BeaconMeasurement::with_rtt(50_000, 5_000));

        assert_eq!(response.sequence, request.sequence);
        assert_eq!(response.path_id, request.path_id);
        assert_eq!(response.control_round_seq, 9);
        assert_eq!(response.send_timestamp, 1234);
        assert_eq!(response.beacon_type, BeaconType::Response);
        assert_eq!(response.measurement_data.srtt_us, Some(50_000));
    }

    #[test]
    fn test_beacon_stats() {
        let mut stats = BeaconStats::new(42);

        assert_eq!(stats.path_id, 42);
        assert_eq!(stats.sent_count, 0);
        assert_eq!(stats.received_count, 0);

        stats.record_sent(1);
        stats.record_sent(2);
        assert_eq!(stats.sent_count, 2);
        assert_eq!(stats.last_sent_sequence, 2);

        stats.record_received(1);
        assert_eq!(stats.received_count, 1);

        stats.record_response(Duration::from_millis(50));
        stats.record_response(Duration::from_millis(60));

        assert_eq!(stats.response_count, 2);
        assert_eq!(stats.avg_rtt, Some(Duration::from_millis(55)));
        assert_eq!(stats.loss_rate, 0.0); // 2 responses / 2 sent = 0% loss
    }

    #[test]
    fn test_beacon_manager() {
        let mut manager = BeaconManager::new(Duration::from_secs(1));

        // Should send initial beacon
        assert!(manager.should_send_beacon(1));

        let measurement = BeaconMeasurement::empty();
        let beacon = manager.create_beacon(1, measurement);
        assert_eq!(beacon.path_id, 1);
        assert_eq!(beacon.sequence, 1);

        // Should not send again immediately
        assert!(!manager.should_send_beacon(1));

        // Process a beacon response.
        let response_beacon =
            PathBeacon::response(beacon.sequence, beacon.path_id, BeaconMeasurement::empty());
        let response = manager.process_received_beacon(response_beacon);
        assert!(response.is_none()); // Response beacons don't generate responses

        // Check stats
        let stats = manager.get_path_stats(1).unwrap();
        assert_eq!(stats.sent_count, 1);
        assert_eq!(stats.received_count, 1);
    }

    #[test]
    fn test_beacon_type_enabling() {
        let mut manager = BeaconManager::default();

        assert!(manager.is_beacon_type_enabled(BeaconType::Periodic));
        assert!(!manager.is_beacon_type_enabled(BeaconType::Migration));

        manager.set_beacon_type_enabled(BeaconType::Migration, true);
        assert!(manager.is_beacon_type_enabled(BeaconType::Migration));

        manager.set_beacon_type_enabled(BeaconType::Periodic, false);
        assert!(!manager.is_beacon_type_enabled(BeaconType::Periodic));
        assert!(!manager.should_send_beacon(1)); // No beacon when disabled
    }

    #[test]
    fn test_beacon_scheduler_probe_and_keepalive() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::with_intervals(
            42,
            now,
            Duration::from_secs(10),
            Duration::from_secs(30),
        );

        let first = scheduler
            .next_action(now, BeaconMeasurement::empty())
            .expect("initial probe is due");
        assert_eq!(first.beacon.beacon_type, BeaconType::Probe);
        assert_eq!(first.beacon.control_round_seq, 1);
        assert_eq!(first.idle_for, Duration::ZERO);
        assert_eq!(first.missed_probes, 0);

        let reply_at = now + Duration::from_millis(50);
        scheduler.observe_probe_result(reply_at, Duration::from_millis(50));
        assert_eq!(scheduler.latest_rtt(), Some(Duration::from_millis(50)));
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Active);
        assert!(
            scheduler
                .next_action(
                    reply_at + Duration::from_secs(1),
                    BeaconMeasurement::empty(),
                )
                .is_none()
        );

        let keepalive = scheduler
            .next_action(
                reply_at + Duration::from_secs(11),
                BeaconMeasurement::empty(),
            )
            .expect("idle keepalive is due");
        assert_eq!(keepalive.beacon.beacon_type, BeaconType::Keepalive);
        assert_eq!(keepalive.beacon.control_round_seq, 2);
        assert!(keepalive.idle_for >= Duration::from_secs(10));
    }

    #[test]
    fn test_beacon_scheduler_probe_due_takes_priority_over_keepalive() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::with_intervals(
            42,
            now,
            Duration::from_secs(2),
            Duration::from_secs(2),
        );

        let first = scheduler
            .next_action(now, BeaconMeasurement::empty())
            .expect("initial probe is due");
        assert_eq!(first.beacon.beacon_type, BeaconType::Probe);
        scheduler.observe_probe_result(now, Duration::from_millis(10));

        let action = scheduler
            .next_action(now + Duration::from_secs(2), BeaconMeasurement::empty())
            .expect("probe and keepalive are both due");

        assert_eq!(action.beacon.beacon_type, BeaconType::Probe);
        assert_eq!(action.beacon.control_round_seq, 2);
    }

    #[test]
    fn test_beacon_scheduler_tracks_missed_probe_budget_and_recovery() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::with_intervals(
            9,
            now,
            Duration::from_secs(30),
            Duration::from_secs(2),
        )
        .with_missed_probe_budget(2);

        let first = scheduler
            .next_action(now, BeaconMeasurement::empty())
            .expect("initial probe is due");
        assert_eq!(first.beacon.beacon_type, BeaconType::Probe);
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Active);

        let second = scheduler
            .next_action(now + Duration::from_secs(2), BeaconMeasurement::empty())
            .expect("missed probe should schedule a replacement probe");
        assert_eq!(second.beacon.beacon_type, BeaconType::Probe);
        assert_eq!(second.missed_probes, 1);
        assert_eq!(scheduler.missed_probes(), 1);
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Suspect);

        let third = scheduler
            .next_action(now + Duration::from_secs(4), BeaconMeasurement::empty())
            .expect("second miss should schedule a replacement probe");
        assert_eq!(third.beacon.beacon_type, BeaconType::Probe);
        assert_eq!(third.missed_probes, 2);
        assert!(scheduler.peer_liveness_expired());

        let recovered_at = now + Duration::from_secs(4) + Duration::from_millis(75);
        scheduler.observe_probe_result(recovered_at, Duration::from_millis(75));
        assert_eq!(scheduler.latest_rtt(), Some(Duration::from_millis(75)));
        assert_eq!(scheduler.missed_probes(), 0);
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Active);
    }

    #[test]
    fn test_beacon_scheduler_default_budget_tolerates_long_lossy_rq_spray() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::new(9, now);

        let first = scheduler
            .next_action(now, BeaconMeasurement::empty())
            .expect("initial probe is due");
        assert_eq!(first.beacon.beacon_type, BeaconType::Probe);
        assert_eq!(first.missed_probes, 0);
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Active);

        let tolerated_silence =
            DEFAULT_PROBE_INTERVAL * u32::from(DEFAULT_MAX_MISSED_PROBES.saturating_sub(1));
        assert!(
            tolerated_silence >= Duration::from_secs(180),
            "MATRIX-1 50M/broken sprays ran about 172-185s before the old liveness trip"
        );

        for missed in 1..DEFAULT_MAX_MISSED_PROBES {
            let at = now + DEFAULT_PROBE_INTERVAL * u32::from(missed);
            let action = scheduler
                .next_action(at, BeaconMeasurement::empty())
                .expect("replacement probe remains due during long spray");
            assert_eq!(action.beacon.beacon_type, BeaconType::Probe);
            assert_eq!(action.missed_probes, missed);
            assert_eq!(scheduler.missed_probes(), missed);
            assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Suspect);
            assert!(
                !scheduler.peer_liveness_expired(),
                "default liveness must not fail before the full missed-probe budget"
            );
        }

        let expired_at = now + DEFAULT_PROBE_INTERVAL * u32::from(DEFAULT_MAX_MISSED_PROBES);
        let expired = scheduler
            .next_action(expired_at, BeaconMeasurement::empty())
            .expect("final missed probe schedules one more replacement probe");
        assert_eq!(expired.missed_probes, DEFAULT_MAX_MISSED_PROBES);
        assert!(scheduler.peer_liveness_expired());
    }

    #[test]
    fn test_beacon_scheduler_old_response_does_not_clear_new_pending_probe() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::with_intervals(
            7,
            now,
            Duration::from_secs(30),
            Duration::from_secs(2),
        )
        .with_missed_probe_budget(3);

        let first = scheduler
            .next_action(now, BeaconMeasurement::empty())
            .expect("initial probe is due");
        let second_at = now + Duration::from_secs(2);
        let second = scheduler
            .next_action(second_at, BeaconMeasurement::empty())
            .expect("replacement probe is due after first miss");
        assert_eq!(first.beacon.control_round_seq, 1);
        assert_eq!(second.beacon.control_round_seq, 2);
        assert_eq!(second.missed_probes, 1);

        let old_response = PathBeacon::response_to(&first.beacon, BeaconMeasurement::empty());
        assert!(
            scheduler
                .process_inbound_beacon(second_at + Duration::from_millis(50), old_response)
                .is_none()
        );
        assert_eq!(scheduler.missed_probes(), 1);
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Suspect);

        let third = scheduler
            .next_action(now + Duration::from_secs(4), BeaconMeasurement::empty())
            .expect("newer pending probe should still time out");
        assert_eq!(third.beacon.beacon_type, BeaconType::Probe);
        assert_eq!(third.beacon.control_round_seq, 3);
        assert_eq!(third.missed_probes, 2);
    }

    #[test]
    fn test_beacon_scheduler_ignores_disabled_and_stale_control_beacons() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::with_intervals(
            42,
            now,
            Duration::from_secs(10),
            Duration::from_secs(2),
        );

        let legacy = PathBeacon::probe(1, 42, BeaconMeasurement::empty());
        assert!(scheduler.process_inbound_beacon(now, legacy).is_none());

        let fresh = PathBeacon::probe(2, 42, BeaconMeasurement::empty()).with_control_round_seq(3);
        let response = scheduler
            .process_inbound_beacon(now, fresh.clone())
            .expect("fresh control beacon should be answered");
        assert_eq!(response.beacon.beacon_type, BeaconType::Response);
        assert_eq!(response.beacon.control_round_seq, 3);
        assert!(scheduler.process_inbound_beacon(now, fresh).is_none());

        let stale = PathBeacon::keepalive(3, 42).with_control_round_seq(2);
        assert!(scheduler.process_inbound_beacon(now, stale).is_none());
    }

    #[test]
    fn test_beacon_scheduler_can_disable_control_output() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::new(42, now);
        scheduler.disable_control();

        assert!(!scheduler.control_enabled());
        assert!(
            scheduler
                .next_action(now + DEFAULT_PROBE_INTERVAL, BeaconMeasurement::empty())
                .is_none()
        );
    }

    #[test]
    fn test_beacon_scheduler_does_not_reuse_exhausted_control_round() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::new(42, now);
        scheduler.next_control_round_seq = u64::MAX;

        let action = scheduler
            .next_action(now, BeaconMeasurement::empty())
            .expect("final control round can be emitted once");

        assert_eq!(action.beacon.control_round_seq, u64::MAX);
        assert!(!scheduler.control_enabled());
        assert!(
            scheduler
                .next_action(now + DEFAULT_PROBE_INTERVAL, BeaconMeasurement::empty())
                .is_none()
        );
    }

    #[test]
    fn test_beacon_scheduler_peer_activity_resets_liveness_and_idle_window() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::with_intervals(
            11,
            now,
            Duration::from_secs(5),
            Duration::from_secs(10),
        );

        let _first = scheduler
            .next_action(now, BeaconMeasurement::empty())
            .expect("initial probe is due");
        let _second = scheduler
            .next_action(now + Duration::from_secs(10), BeaconMeasurement::empty())
            .expect("missed probe is due");
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Suspect);

        let peer_activity_at = now + Duration::from_secs(11);
        scheduler.mark_peer_activity(peer_activity_at);
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Active);
        assert!(
            scheduler
                .next_action(
                    peer_activity_at + Duration::from_secs(4),
                    BeaconMeasurement::empty(),
                )
                .is_none(),
            "recent peer activity should suppress keepalive and replacement probe"
        );

        let keepalive = scheduler
            .next_action(
                peer_activity_at + Duration::from_secs(6),
                BeaconMeasurement::empty(),
            )
            .expect("idle keepalive is due after the reset window");
        assert_eq!(keepalive.beacon.beacon_type, BeaconType::Keepalive);
        assert!(keepalive.idle_for >= Duration::from_secs(5));
    }
