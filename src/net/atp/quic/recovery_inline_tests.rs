    use super::*;
    use crate::cx::Cx;

    fn sent_packet(
        space: PacketNumberSpace,
        packet_number: u64,
        time_sent_micros: u64,
    ) -> SentPacketMeta {
        SentPacketMeta {
            space,
            packet_number,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            time_sent_micros,
        }
    }

    #[test]
    fn recovery_manager_lifecycle() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());
        let cx = Cx::for_testing();

        // Begin handshake
        let result = manager.begin_handshake(&cx);
        assert!(result.is_ok());

        // Should log recovery state change
        let events = manager.recovery_log();
        assert_eq!(events.len(), 1);
        if let RecoveryEventType::RecoveryStateChanged { new_state, .. } = &events[0].event_type {
            assert_eq!(new_state, "handshaking");
        } else {
            panic!("Expected RecoveryStateChanged event");
        }
    }

    #[test]
    fn anti_amplification_limits() {
        let mut tracker = AntiAmplificationTracker::new();

        // No bytes received, can't send anything
        assert!(!tracker.can_send(1000));

        // Receive 400 bytes, can send up to 1200 bytes
        tracker.on_datagram_received(400);
        assert!(tracker.can_send(1000));
        assert!(tracker.can_send(1200));
        assert!(!tracker.can_send(1201));

        // Send 1000 bytes
        tracker.on_packet_sent(1000);

        // Only 200 bytes left
        assert!(tracker.can_send(200));
        assert!(!tracker.can_send(201));

        // Receiving an ACK validates the address.
        tracker.on_ack_received();
        assert!(tracker.can_send(5000)); // Address validated, can send freely
    }

    #[test]
    fn recovery_event_logging() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());

        // Send a packet
        let packet = SentPacketMeta {
            space: PacketNumberSpace::Initial,
            packet_number: 1,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            time_sent_micros: 1000,
        };

        let result = manager.on_packet_sent(packet);
        assert!(result.is_err()); // Should fail due to anti-amplification

        // Should log the limit event
        let events = manager.recovery_log();
        assert!(!events.is_empty());
    }

    #[test]
    fn pto_timer_management() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());

        // Initially no timers
        assert!(manager.timers.is_empty());

        // Send packet should create PTO timer
        // First validate address
        manager.anti_amplification.address_validated = true;

        let packet = SentPacketMeta {
            space: PacketNumberSpace::Initial,
            packet_number: 1,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            time_sent_micros: 1000,
        };

        let result = manager.on_packet_sent(packet);
        assert!(result.is_ok());

        // Should have created a PTO timer
        assert!(!manager.timers.is_empty());
    }

    #[test]
    fn pto_timer_deadline_is_anchored_to_connection_start() {
        // Regression: `pto_deadline_micros` returns an ABSOLUTE deadline on the
        // connection-start micros axis. It must be mapped to wall-clock through
        // the stable `connection_start` epoch, not added to `Instant::now()`
        // (which would push the PTO far into the future so it never fires).
        // The exact-offset invariant below fails on the old `Instant::now()`
        // anchoring (off by the construction->schedule delta) and holds on the
        // fixed `connection_start` anchoring.
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());
        manager.anti_amplification.address_validated = true;

        let packet = SentPacketMeta {
            space: PacketNumberSpace::Initial,
            packet_number: 1,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            // A packet "sent" well into the connection: this is the term that
            // makes the deadline absolute rather than a small relative offset.
            time_sent_micros: 30_000_000,
        };
        assert!(manager.on_packet_sent(packet).is_ok());

        let expected_micros = manager
            .transport
            .pto_deadline_micros(0)
            .expect("pto deadline must exist while a packet is in flight");
        let timer = manager
            .timers
            .values()
            .next()
            .expect("on_packet_sent must arm a PTO timer");
        assert_eq!(
            timer.deadline.duration_since(manager.connection_start),
            Duration::from_micros(expected_micros),
            "PTO deadline must be exactly connection_start + deadline_micros"
        );
    }

    #[test]
    fn ack_loss_logs_concrete_packets_method_delay_and_space() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());
        manager.anti_amplification.address_validated = true;

        for packet_number in 0..6 {
            let packet = sent_packet(
                PacketNumberSpace::ApplicationData,
                packet_number,
                10_000 + packet_number,
            );
            assert!(manager.on_packet_sent(packet).is_ok());
        }

        let ack = manager.on_ack_received(PacketNumberSpace::ApplicationData, &[5], 0, 20_000);
        assert!(ack.is_ok());

        let loss_event = manager
            .recovery_log()
            .iter()
            .find_map(|event| match &event.event_type {
                RecoveryEventType::LossDetected {
                    lost_packets,
                    detection_method,
                    loss_delay_micros,
                } => Some((
                    event.space,
                    lost_packets,
                    detection_method,
                    loss_delay_micros,
                )),
                _ => None,
            });
        assert!(loss_event.is_some(), "expected loss event in recovery log");
        let Some(loss_event) = loss_event else {
            return;
        };

        assert_eq!(loss_event.0, Some(PacketNumberSpace::ApplicationData));
        assert_eq!(loss_event.1, &vec![0, 1, 2]);
        assert!(matches!(loss_event.2, LossDetectionMethod::PacketThreshold));
        assert!(*loss_event.3 > 0);
    }

    #[test]
    fn pto_expiry_logs_incrementing_count_backoff_and_snapshot() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());

        assert!(
            manager
                .on_pto_expired(PacketNumberSpace::ApplicationData)
                .is_ok()
        );
        assert!(
            manager
                .on_pto_expired(PacketNumberSpace::ApplicationData)
                .is_ok()
        );

        let pto_events: Vec<_> = manager
            .recovery_log()
            .iter()
            .filter_map(|event| match event.event_type {
                RecoveryEventType::PtoExpired {
                    pto_count,
                    backoff_level,
                } => Some((
                    event.space,
                    pto_count,
                    backoff_level,
                    event.transport_state.pto_count,
                )),
                _ => None,
            })
            .collect();

        assert_eq!(
            pto_events,
            vec![
                (Some(PacketNumberSpace::ApplicationData), 1, 1, 1),
                (Some(PacketNumberSpace::ApplicationData), 2, 2, 2),
            ]
        );
    }

    #[test]
    fn ack_resets_pto_count_before_snapshot_logging() {
        let mut manager = AtpRecoveryManager::new("test_conn".to_string());
        manager.anti_amplification.address_validated = true;
        assert!(
            manager
                .on_packet_sent(sent_packet(PacketNumberSpace::ApplicationData, 7, 10_000))
                .is_ok()
        );
        assert!(
            manager
                .on_pto_expired(PacketNumberSpace::ApplicationData)
                .is_ok()
        );
        assert!(
            manager
                .on_pto_expired(PacketNumberSpace::ApplicationData)
                .is_ok()
        );

        let ack = manager.on_ack_received(PacketNumberSpace::ApplicationData, &[7], 0, 20_000);
        assert!(ack.is_ok());

        let ack_event = manager
            .recovery_log()
            .iter()
            .find(|event| matches!(event.event_type, RecoveryEventType::AckReceived { .. }));
        assert!(ack_event.is_some(), "expected ack event in recovery log");
        let Some(ack_event) = ack_event else {
            return;
        };

        assert_eq!(ack_event.space, Some(PacketNumberSpace::ApplicationData));
        assert_eq!(ack_event.transport_state.pto_count, 0);
    }
