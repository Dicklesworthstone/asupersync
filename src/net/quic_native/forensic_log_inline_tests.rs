    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::{Value, json};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn scrub_forensic_manifest(mut value: Value) -> Value {
        if let Some(map) = value.as_object_mut() {
            if let Some(trace_fingerprint) = map.get_mut("trace_fingerprint") {
                *trace_fingerprint = Value::String("[TRACE_FINGERPRINT]".into());
            }
        }
        value
    }

    fn qlog_event_matches(event: &Value, category: &str, name: &str) -> bool {
        let category_matches = event
            .get(1)
            .and_then(Value::as_str)
            .is_some_and(|value| category.eq(value));
        let name_matches = event
            .get(2)
            .and_then(Value::as_str)
            .is_some_and(|value| name.eq(value));
        category_matches && name_matches
    }

    #[test]
    fn test_logger_records_events() {
        init_test("test_logger_records_events");

        let logger = QuicH3ForensicLogger::new("QH3-E2-TEST", 0xCAFE, "test_logger_records_events");

        logger.log(
            100,
            "quic_transport",
            QuicH3Event::PacketSent {
                pn_space: "initial".into(),
                packet_number: 0,
                size_bytes: 1200,
                ack_eliciting: true,
                in_flight: true,
                send_time_us: 100,
            },
        );
        logger.log(
            200,
            "quic_transport",
            QuicH3Event::AckReceived {
                pn_space: "initial".into(),
                acked_ranges: vec![(0, 0)],
                ack_delay_us: 50,
                acked_packets: 1,
                acked_bytes: 1200,
            },
        );
        logger.log(
            300,
            "quic_stream",
            QuicH3Event::StreamOpened {
                stream_id: 0,
                direction: "bidi".into(),
                role: "client".into(),
                is_local: true,
            },
        );
        logger.log(
            400,
            "h3_request",
            QuicH3Event::RequestStarted {
                stream_id: 0,
                method: "GET".into(),
                scheme: "https".into(),
                authority: "localhost".into(),
                path: "/".into(),
            },
        );

        assert_eq!(logger.event_count(), 4);

        let by_cat = logger.events_by_category();
        assert_eq!(by_cat.get("quic_transport"), Some(&2));
        assert_eq!(by_cat.get("quic_stream"), Some(&1));
        assert_eq!(by_cat.get("h3_request"), Some(&1));

        crate::test_complete!("test_logger_records_events");
    }

    #[test]
    fn test_ndjson_roundtrip() {
        init_test("test_ndjson_roundtrip");

        let logger = QuicH3ForensicLogger::new("QH3-ROUNDTRIP", 0xBEEF, "test_ndjson_roundtrip");

        logger.log(
            0,
            "test_harness",
            QuicH3Event::ScenarioStarted {
                scenario_id: "QH3-ROUNDTRIP".into(),
                seed: 0xBEEF,
                config_hash: "abc123".into(),
                test_file: "forensic_log.rs".into(),
                test_function: "test_ndjson_roundtrip".into(),
            },
        );
        logger.log(
            1000,
            "quic_transport",
            QuicH3Event::PacketSent {
                pn_space: "handshake".into(),
                packet_number: 0,
                size_bytes: 1200,
                ack_eliciting: true,
                in_flight: true,
                send_time_us: 1000,
            },
        );
        logger.log(
            2000,
            "quic_connection",
            QuicH3Event::StateChanged {
                from_state: "idle".into(),
                to_state: "handshaking".into(),
                trigger: "begin_handshake".into(),
            },
        );

        let tmp = tempfile::TempDir::new().expect("create temp dir");
        let ndjson_path = tmp.path().join("events.ndjson");

        logger.write_ndjson(&ndjson_path).expect("write ndjson");

        // Read back and verify
        let contents = std::fs::read_to_string(&ndjson_path).expect("read ndjson");
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "expected 3 NDJSON lines, got {}",
            lines.len()
        );

        // Verify each line is valid JSON with correct envelope fields
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
            assert_eq!(parsed["v"], 1);
            assert_eq!(parsed["subsystem"], "quic_h3_native");
            assert_eq!(parsed["test_id"], "test_ndjson_roundtrip");
            assert_eq!(parsed["seed"], "0xBEEF");
        }

        // Verify first event is scenario_started
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "scenario_started");
        assert_eq!(first["category"], "test_harness");

        // Verify second event has correct data
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["event"], "packet_sent");
        assert_eq!(second["data"]["pn_space"], "handshake");

        crate::test_complete!("test_ndjson_roundtrip");
    }

    #[test]
    fn qlog_export_preserves_packet_path_cancel_and_replay_context() {
        init_test("qlog_export_preserves_packet_path_cancel_and_replay_context");

        let logger = QuicH3ForensicLogger::new(
            "QH3-QLOG-EXPORT",
            0xCAFE_BABE,
            "qlog_export_preserves_packet_path_cancel_and_replay_context",
        );

        logger.log(
            10,
            "quic_transport",
            QuicH3Event::PacketSent {
                pn_space: "application".into(),
                packet_number: 7,
                size_bytes: 1180,
                ack_eliciting: true,
                in_flight: true,
                send_time_us: 10,
            },
        );
        logger.log(
            20,
            "quic_path",
            QuicH3Event::PathValidationStarted {
                path_id: "path-a".into(),
                local_addr: "192.0.2.10:4433".into(),
                remote_addr: "198.51.100.20:4433".into(),
                challenge_len: 8,
            },
        );
        logger.log(
            30,
            "quic_path",
            QuicH3Event::PathValidationCompleted {
                path_id: "path-a".into(),
                validated: true,
                reason: "path_response_matched".into(),
                new_active_path: true,
            },
        );
        logger.log(
            40,
            "quic_path",
            QuicH3Event::MigrationObserved {
                from_path_id: "path-a".into(),
                to_path_id: "path-b".into(),
                reason: "nat_rebinding".into(),
                stream_state_preserved: true,
            },
        );
        logger.log(
            50,
            "cancel_region",
            QuicH3Event::CancelRequested {
                scope: "connection".into(),
                reason: "test_shutdown".into(),
                trigger: "region_close".into(),
            },
        );

        let qlog = logger.to_qlog_json();
        assert_eq!(qlog["qlog_version"], "0.3");
        assert_eq!(qlog["qlog_format"], "JSON");
        assert_eq!(
            qlog["traces"][0]["common_fields"]["seed"],
            "0x00000000CAFEBABE"
        );
        assert!(
            qlog["traces"][0]["common_fields"]["replay_command"]
                .as_str()
                .unwrap()
                .contains("ASUPERSYNC_SEED=0xCAFEBABE")
        );

        let events = qlog["traces"][0]["events"].as_array().unwrap();
        assert_eq!(events.len(), 5);
        assert!(events.iter().any(|event| {
            qlog_event_matches(event, "transport", "packet_sent")
                && event
                    .get(3)
                    .and_then(|data| data.get("packet_number"))
                    .and_then(Value::as_u64)
                    .is_some_and(|packet_number| packet_number == 7)
        }));
        assert!(events.iter().any(|event| {
            qlog_event_matches(event, "connectivity", "migration_observed")
                && event
                    .get(3)
                    .and_then(|data| data.get("reason"))
                    .and_then(Value::as_str)
                    .is_some_and(|reason| "nat_rebinding".eq(reason))
        }));
        assert!(
            events
                .iter()
                .any(|event| { qlog_event_matches(event, "recovery", "cancel_requested") })
        );

        let tmp = tempfile::TempDir::new().expect("create temp dir");
        let qlog_path = tmp.path().join("scenario.qlog.json");
        logger.write_qlog_json(&qlog_path).expect("write qlog json");
        let contents = std::fs::read_to_string(&qlog_path).expect("read qlog json");
        let parsed: Value = serde_json::from_str(&contents).expect("valid qlog json");
        assert_eq!(parsed["traces"][0]["events"].as_array().unwrap().len(), 5);

        crate::test_complete!("qlog_export_preserves_packet_path_cancel_and_replay_context");
    }

    #[test]
    fn qlog_export_preserves_ack_loss_pto_close_and_failure_context() {
        init_test("qlog_export_preserves_ack_loss_pto_close_and_failure_context");

        let logger = QuicH3ForensicLogger::new(
            "QH3-QLOG-FAILURE",
            0xA9,
            "qlog_export_preserves_ack_loss_pto_close_and_failure_context",
        );

        logger.log(
            10,
            "quic_transport",
            QuicH3Event::AckReceived {
                pn_space: "application".into(),
                acked_ranges: vec![(4, 8), (12, 12)],
                ack_delay_us: 25,
                acked_packets: 6,
                acked_bytes: 7200,
            },
        );
        logger.log(
            20,
            "quic_transport",
            QuicH3Event::LossDetected {
                pn_space: "application".into(),
                lost_packets: 2,
                lost_bytes: 2400,
                detection_method: "packet_threshold".into(),
            },
        );
        logger.log(
            30,
            "quic_transport",
            QuicH3Event::PtoFired {
                pto_count: 2,
                backoff_multiplier: 4,
                deadline_us: 50_000,
                probe_space: "application".into(),
            },
        );
        logger.log(
            40,
            "quic_connection",
            QuicH3Event::CloseInitiated {
                close_code: 0x100,
                close_method: "cancelled".into(),
                drain_timeout_us: 2_000_000,
            },
        );
        logger.log(
            50,
            "test_harness",
            QuicH3Event::ScenarioCompleted {
                scenario_id: "QH3-QLOG-FAILURE".into(),
                seed: 0xA9,
                passed: false,
                duration_us: 50,
                event_count: 5,
                failure_class: "assertion_failure".into(),
            },
        );

        let qlog = logger.to_qlog_json();
        assert_eq!(
            qlog["traces"][0]["common_fields"]["seed"],
            "0x00000000000000A9"
        );
        assert!(
            qlog["traces"][0]["common_fields"]["replay_command"]
                .as_str()
                .unwrap()
                .contains("ASUPERSYNC_SEED=0xA9")
        );

        let events = qlog["traces"][0]["events"].as_array().unwrap();
        assert_eq!(events.len(), 5);
        assert!(events.iter().any(|event| {
            qlog_event_matches(event, "transport", "ack_received")
                && event
                    .get(3)
                    .and_then(|data| data.get("acked_packets"))
                    .and_then(Value::as_u64)
                    .is_some_and(|acked_packets| acked_packets == 6)
        }));
        assert!(events.iter().any(|event| {
            qlog_event_matches(event, "transport", "loss_detected")
                && event
                    .get(3)
                    .and_then(|data| data.get("detection_method"))
                    .and_then(Value::as_str)
                    .is_some_and(|method| "packet_threshold".eq(method))
        }));
        assert!(events.iter().any(|event| {
            qlog_event_matches(event, "transport", "pto_fired")
                && event
                    .get(3)
                    .and_then(|data| data.get("backoff_multiplier"))
                    .and_then(Value::as_u64)
                    .is_some_and(|backoff| backoff == 4)
        }));
        assert!(events.iter().any(|event| qlog_event_matches(
            event,
            "connectivity",
            "close_initiated"
        )));
        assert!(events.iter().any(|event| qlog_event_matches(
            event,
            "simulation",
            "scenario_completed"
        )));

        let manifest = QuicH3ScenarioManifest::from_logger(&logger, false, 50);
        assert_eq!(manifest.failure_class, "assertion_failure");
        assert!(manifest.replay_command.contains("ASUPERSYNC_SEED=0xA9"));
        let failure = manifest
            .failure_fingerprint
            .as_ref()
            .expect("failure manifest should include last event context");
        assert_eq!(failure.bucket, "assertion_failure");
        assert_eq!(
            failure
                .last_event_before_failure
                .as_ref()
                .and_then(|event| event.get("event_count"))
                .and_then(Value::as_u64),
            Some(5)
        );

        crate::test_complete!("qlog_export_preserves_ack_loss_pto_close_and_failure_context");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_manifest_from_logger() {
        init_test("test_manifest_from_logger");

        let logger =
            QuicH3ForensicLogger::new("QH3-E2-MANIFEST", 0xDEAD_BEEF, "test_manifest_from_logger");

        // Transport events
        logger.log(
            100,
            "quic_transport",
            QuicH3Event::PacketSent {
                pn_space: "initial".into(),
                packet_number: 0,
                size_bytes: 1200,
                ack_eliciting: true,
                in_flight: true,
                send_time_us: 100,
            },
        );
        logger.log(
            200,
            "quic_transport",
            QuicH3Event::AckReceived {
                pn_space: "initial".into(),
                acked_ranges: vec![(0, 0)],
                ack_delay_us: 50,
                acked_packets: 1,
                acked_bytes: 1200,
            },
        );
        logger.log(
            300,
            "quic_transport",
            QuicH3Event::RttUpdated {
                latest_rtt_us: 20_000,
                smoothed_rtt_us: 20_000,
                rttvar_us: 10_000,
                min_rtt_us: 20_000,
                ack_delay_us: 50,
            },
        );
        logger.log(
            400,
            "quic_transport",
            QuicH3Event::CwndUpdated {
                old_cwnd: 14_720,
                new_cwnd: 15_920,
                ssthresh: u64::MAX,
                bytes_in_flight: 1200,
                reason: "slow_start".into(),
            },
        );

        // Connection lifecycle
        logger.log(
            50,
            "quic_connection",
            QuicH3Event::StateChanged {
                from_state: "idle".into(),
                to_state: "handshaking".into(),
                trigger: "begin_handshake".into(),
            },
        );
        logger.log(
            500,
            "quic_connection",
            QuicH3Event::StateChanged {
                from_state: "handshaking".into(),
                to_state: "established".into(),
                trigger: "handshake_confirmed".into(),
            },
        );
        logger.log(
            550,
            "cancel_region",
            QuicH3Event::CancelRequested {
                scope: "connection".into(),
                reason: "test_shutdown".into(),
                trigger: "user".into(),
            },
        );
        logger.log(
            560,
            "cancel_region",
            QuicH3Event::RegionStateChanged {
                region_id: 1,
                from_state: "open".into(),
                to_state: "draining".into(),
                live_children: 2,
                outstanding_obligations: 1,
            },
        );
        logger.log(
            575,
            "cancel_region",
            QuicH3Event::CloseInitiated {
                close_code: 0x100,
                close_method: "graceful".into(),
                drain_timeout_us: 2_000_000,
            },
        );

        // H3 events
        logger.log(
            600,
            "quic_stream",
            QuicH3Event::StreamOpened {
                stream_id: 0,
                direction: "bidi".into(),
                role: "client".into(),
                is_local: true,
            },
        );
        logger.log(
            700,
            "h3_request",
            QuicH3Event::RequestStarted {
                stream_id: 0,
                method: "GET".into(),
                scheme: "https".into(),
                authority: "localhost".into(),
                path: "/index.html".into(),
            },
        );
        logger.log(
            800,
            "h3_request",
            QuicH3Event::ResponseReceived {
                stream_id: 0,
                status_code: 200,
                header_count: 3,
                body_bytes: 4096,
            },
        );
        logger.log(
            900,
            "h3_control",
            QuicH3Event::SettingsExchanged {
                direction: "sent".into(),
                max_field_section_size: 65536,
                qpack_max_table_capacity: 0,
                qpack_blocked_streams: 0,
            },
        );

        // Invariants
        logger.log_invariant(
            1000,
            "inv.quic.handshake_completes",
            "pass",
            "Both endpoints reached Established",
        );
        logger.log_invariant(
            1100,
            "inv.quic.rtt_positive",
            "pass",
            "smoothed_rtt=20000us",
        );

        let manifest = QuicH3ScenarioManifest::from_logger(&logger, true, 1_100_000);

        // Verify basic fields
        assert_eq!(manifest.schema_id, FORENSIC_MANIFEST_SCHEMA_ID);
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.scenario_id, "QH3-E2-MANIFEST");
        assert_eq!(manifest.seed, "0x00000000DEADBEEF");
        assert!(manifest.passed);
        assert_eq!(manifest.duration_us, 1_100_000);
        assert_eq!(manifest.failure_class, "passed");
        assert!(manifest.failure_fingerprint.is_none());

        // Verify transport summary
        assert_eq!(manifest.transport_summary.packets_sent, 1);
        assert_eq!(manifest.transport_summary.packets_acked, 1);
        assert_eq!(manifest.transport_summary.bytes_sent, 1200);
        assert_eq!(manifest.transport_summary.bytes_acked, 1200);
        assert_eq!(manifest.transport_summary.smoothed_rtt_us, Some(20_000));
        assert_eq!(manifest.transport_summary.min_rtt_us, Some(20_000));
        assert_eq!(manifest.transport_summary.cwnd, 15_920);
        assert_eq!(manifest.transport_summary.final_state, "established");

        // Verify H3 summary
        assert_eq!(manifest.h3_summary.requests_sent, 1);
        assert_eq!(manifest.h3_summary.responses_received, 1);
        assert_eq!(manifest.h3_summary.streams_opened, 1);
        assert!(manifest.h3_summary.settings_exchanged);

        // Verify connection lifecycle
        assert_eq!(manifest.connection_lifecycle.len(), 2);
        assert_eq!(manifest.connection_lifecycle[0].from_state, "idle");
        assert_eq!(manifest.connection_lifecycle[0].to_state, "handshaking");
        assert_eq!(manifest.connection_lifecycle[1].to_state, "established");

        // Verify cancel/region correlation summary
        assert_eq!(manifest.cancel_region_summary.cancellation_requests, 1);
        assert_eq!(manifest.cancel_region_summary.region_transitions, 1);
        assert_eq!(manifest.cancel_region_summary.first_cancel_ts_us, Some(550));
        assert_eq!(
            manifest.cancel_region_summary.first_close_initiated_ts_us,
            Some(575)
        );
        assert_eq!(
            manifest.cancel_region_summary.cancel_to_close_latency_us,
            Some(25)
        );

        // Verify invariants
        assert_eq!(manifest.invariant_ids.len(), 2);
        assert!(
            manifest
                .invariant_ids
                .contains(&"inv.quic.handshake_completes".to_string())
        );
        assert!(
            manifest
                .invariant_ids
                .contains(&"inv.quic.rtt_positive".to_string())
        );
        assert_eq!(manifest.invariant_verdicts.len(), 2);
        assert_eq!(manifest.invariant_verdicts[0].verdict, "pass");

        // Verify event timeline
        assert_eq!(manifest.event_timeline.total_events, 15);
        assert_eq!(
            manifest.event_timeline.by_category.get("quic_transport"),
            Some(&4)
        );
        assert_eq!(
            manifest.event_timeline.by_category.get("cancel_region"),
            Some(&3)
        );

        // Verify replay command
        assert!(
            manifest
                .replay_command
                .contains("ASUPERSYNC_SEED=0xDEADBEEF")
        );
        assert!(
            manifest
                .replay_command
                .contains("test_manifest_from_logger")
        );

        // Verify trace fingerprint is non-empty
        assert!(!manifest.trace_fingerprint.is_empty());

        // Verify manifest can be written and read back as JSON
        let tmp = tempfile::TempDir::new().expect("create temp dir");
        let manifest_path = tmp.path().join("manifest.json");
        manifest.write_json(&manifest_path).expect("write manifest");

        let contents = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let parsed: serde_json::Value =
            serde_json::from_str(&contents).expect("valid manifest JSON");
        assert_eq!(parsed["schema_id"], FORENSIC_MANIFEST_SCHEMA_ID);
        assert_eq!(parsed["passed"], true);

        crate::test_complete!("test_manifest_from_logger");
    }

    #[test]
    fn test_invariant_logging() {
        init_test("test_invariant_logging");

        let logger = QuicH3ForensicLogger::new("QH3-INV-TEST", 0xFACE, "test_invariant_logging");

        logger.log_invariant(
            100,
            "inv.quic.handshake_completes",
            "pass",
            "Handshake completed on both sides",
        );
        logger.log_invariant(
            200,
            "inv.quic.rtt_positive",
            "pass",
            "smoothed_rtt=15000us after first ACK",
        );
        logger.log_invariant(
            300,
            "inv.h3.settings_before_other_frames",
            "fail",
            "DATA frame preceded SETTINGS on control stream",
        );
        logger.log_invariant(
            400,
            "inv.quic.cwnd_never_below_minimum",
            "skip",
            "No cwnd events",
        );

        assert_eq!(logger.event_count(), 4);

        let by_cat = logger.events_by_category();
        assert_eq!(by_cat.get("test_harness"), Some(&4));

        // Build manifest and check invariant fields
        let manifest = QuicH3ScenarioManifest::from_logger(&logger, false, 500_000);
        assert!(!manifest.passed);
        assert_eq!(manifest.failure_class, "assertion_failure");

        // Invariant IDs should be sorted and deduped
        assert_eq!(manifest.invariant_ids.len(), 4);
        assert_eq!(
            manifest.invariant_ids[0],
            "inv.h3.settings_before_other_frames"
        );
        assert_eq!(
            manifest.invariant_ids[1],
            "inv.quic.cwnd_never_below_minimum"
        );
        assert_eq!(manifest.invariant_ids[2], "inv.quic.handshake_completes");
        assert_eq!(manifest.invariant_ids[3], "inv.quic.rtt_positive");

        // Verdicts preserve insertion order
        assert_eq!(manifest.invariant_verdicts.len(), 4);
        assert_eq!(
            manifest.invariant_verdicts[0].invariant_id,
            "inv.quic.handshake_completes"
        );
        assert_eq!(manifest.invariant_verdicts[0].verdict, "pass");
        assert_eq!(
            manifest.invariant_verdicts[2].invariant_id,
            "inv.h3.settings_before_other_frames"
        );
        assert_eq!(manifest.invariant_verdicts[2].verdict, "fail");
        assert_eq!(manifest.invariant_verdicts[3].verdict, "skip");

        // Failure fingerprint should be populated on failure
        assert!(manifest.failure_fingerprint.is_some());
        let fp = manifest.failure_fingerprint.as_ref().unwrap();
        assert_eq!(fp.bucket, "assertion_failure");

        // Write NDJSON and verify invariant events have the invariant field set
        let tmp = tempfile::TempDir::new().expect("create temp dir");
        let ndjson_path = tmp.path().join("invariants.ndjson");
        logger.write_ndjson(&ndjson_path).expect("write ndjson");

        let contents = std::fs::read_to_string(&ndjson_path).expect("read ndjson");
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 4);

        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
            assert_eq!(parsed["event"], "invariant_checkpoint");
            assert_eq!(parsed["category"], "test_harness");
            // The invariant field should be set for checkpoint events
            assert!(
                parsed["invariant"].is_string(),
                "invariant field should be set"
            );
        }

        // Verify specific invariant fields in the first event
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["invariant"], "inv.quic.handshake_completes");
        assert_eq!(first["data"]["verdict"], "pass");

        crate::test_complete!("test_invariant_logging");
    }

    #[test]
    fn forensic_manifest_snapshot_scrubbed() {
        init_test("forensic_manifest_snapshot_scrubbed");

        let logger = QuicH3ForensicLogger::new(
            "QH3-SNAP-MANIFEST",
            0x1234,
            "forensic_manifest_snapshot_scrubbed",
        );

        logger.log(
            10,
            "quic_connection",
            QuicH3Event::StateChanged {
                from_state: "idle".into(),
                to_state: "handshaking".into(),
                trigger: "client_start".into(),
            },
        );
        logger.log_invariant(
            25,
            "inv.quic.handshake_completes",
            "pass",
            "handshake finished in test harness",
        );
        logger.log(
            40,
            "quic_connection",
            QuicH3Event::StateChanged {
                from_state: "handshaking".into(),
                to_state: "established".into(),
                trigger: "handshake_confirmed".into(),
            },
        );

        let manifest = QuicH3ScenarioManifest::from_logger(&logger, true, 55);

        insta::assert_json_snapshot!(
            "forensic_manifest_scrubbed",
            scrub_forensic_manifest(json!({
                "scenario_id": manifest.scenario_id,
                "seed": manifest.seed,
                "trace_fingerprint": manifest.trace_fingerprint,
                "replay_command": manifest.replay_command,
                "failure_class": manifest.failure_class,
                "invariant_ids": manifest.invariant_ids,
                "invariant_verdicts": manifest.invariant_verdicts,
                "event_timeline": manifest.event_timeline,
                "connection_lifecycle": manifest.connection_lifecycle,
                "passed": manifest.passed,
                "duration_us": manifest.duration_us,
            }))
        );
    }

    #[test]
    fn quic_h3_event_debug_clone() {
        let ev = QuicH3Event::PacketSent {
            pn_space: "initial".into(),
            packet_number: 0,
            size_bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            send_time_us: 100,
        };
        let dbg = format!("{ev:?}");
        assert!(dbg.contains("PacketSent"), "{dbg}");
        let cloned = ev;
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn cancel_region_event_names_and_levels() {
        let cancel = QuicH3Event::CancelRequested {
            scope: "connection".into(),
            reason: "manual".into(),
            trigger: "user".into(),
        };
        assert_eq!(cancel.event_name(), "cancel_requested");
        assert_eq!(cancel.default_level(), "INFO");

        let region = QuicH3Event::RegionStateChanged {
            region_id: 7,
            from_state: "open".into(),
            to_state: "draining".into(),
            live_children: 1,
            outstanding_obligations: 0,
        };
        assert_eq!(region.event_name(), "region_state_changed");
        assert_eq!(region.default_level(), "DEBUG");
    }

    #[test]
    fn invariant_verdict_debug_clone() {
        let v = InvariantVerdict {
            invariant_id: "inv.test".into(),
            verdict: "pass".into(),
            details: "ok".into(),
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("inv.test"), "{dbg}");
        let cloned = v;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn event_timeline_debug_clone() {
        let t = EventTimeline {
            total_events: 42,
            by_category: BTreeMap::new(),
            by_level: BTreeMap::new(),
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("42"), "{dbg}");
        let cloned = t;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn transport_summary_debug_clone_default() {
        let s = TransportSummary::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("TransportSummary"), "{dbg}");
        assert_eq!(s.packets_sent, 0);
        let cloned = s;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn h3_summary_debug_clone_default() {
        let h = H3Summary::default();
        let dbg = format!("{h:?}");
        assert!(dbg.contains("H3Summary"), "{dbg}");
        assert_eq!(h.requests_sent, 0);
        assert!(!h.settings_exchanged);
        let cloned = h;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn cancel_region_summary_debug_clone_default() {
        let s = CancelRegionSummary::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("CancelRegionSummary"), "{dbg}");
        assert_eq!(s.cancellation_requests, 0);
        assert_eq!(s.region_transitions, 0);
        assert!(s.cancel_to_close_latency_us.is_none());
        let cloned = s;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn lifecycle_transition_debug_clone() {
        let t = LifecycleTransition {
            from_state: "idle".into(),
            to_state: "handshaking".into(),
            ts_us: 100,
            trigger: "begin".into(),
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("idle"), "{dbg}");
        let cloned = t;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn failure_fingerprint_debug_clone() {
        let f = FailureFingerprint {
            bucket: "timeout".into(),
            assertion: Some("expected ok".into()),
            backtrace_hash: None,
            last_event_before_failure: None,
        };
        let dbg = format!("{f:?}");
        assert!(dbg.contains("timeout"), "{dbg}");
        let cloned = f;
        assert_eq!(format!("{cloned:?}"), dbg);
    }
