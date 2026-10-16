    use super::*;
    use crate::net::atp::handshake::state_machine::EndpointRole;

    #[test]
    fn test_tracer_creation() {
        let tracer = HandshakeTracer::new(TraceLevel::Debug, 1000);
        assert_eq!(tracer.entries.len(), 0);
        assert_eq!(tracer.min_level, TraceLevel::Debug);
        assert_eq!(tracer.max_entries, 1000);
    }

    #[test]
    fn test_trace_filtering_by_level() {
        let mut tracer = HandshakeTracer::new(TraceLevel::Debug, 100);

        let info_entry = TraceEntry::new(0, TraceLevel::Info, "test", "info_event", json!({}));
        let error_entry = TraceEntry::new(1, TraceLevel::Error, "test", "error_event", json!({}));
        let verbose_entry =
            TraceEntry::new(2, TraceLevel::Verbose, "test", "verbose_event", json!({}));

        tracer.trace(info_entry);
        tracer.trace(error_entry);
        tracer.trace(verbose_entry); // Should be filtered out

        assert_eq!(tracer.entries.len(), 2);
    }

    #[test]
    fn test_zero_capacity_trace_drops_entries_without_panic() {
        let mut tracer = HandshakeTracer::new(TraceLevel::Verbose, 0);

        tracer.trace(TraceEntry::new(
            0,
            TraceLevel::Error,
            "test",
            "dropped_event",
            json!({}),
        ));
        tracer.trace_packet_protection("rx", PacketSpace::Initial, 0, 1200);

        assert!(tracer.entries().is_empty());
        assert_eq!(tracer.summary()["total_events"], 0);
    }

    #[test]
    fn test_trace_capacity_eviction_keeps_newest_entries() {
        let mut tracer = HandshakeTracer::new(TraceLevel::Verbose, 2);

        tracer.trace(TraceEntry::new(
            0,
            TraceLevel::Info,
            "test",
            "first_event",
            json!({}),
        ));
        tracer.trace(TraceEntry::new(
            1,
            TraceLevel::Info,
            "test",
            "second_event",
            json!({}),
        ));
        tracer.trace(TraceEntry::new(
            2,
            TraceLevel::Info,
            "test",
            "third_event",
            json!({}),
        ));

        assert_eq!(tracer.entries().len(), 2);
        assert_eq!(tracer.entries()[0].event, "second_event");
        assert_eq!(tracer.entries()[1].event, "third_event");
    }

    #[test]
    fn test_default_tracer_uses_info_threshold_and_capacity() {
        let tracer = HandshakeTracer::default();

        assert_eq!(tracer.min_level, TraceLevel::Info);
        assert_eq!(tracer.max_entries, 10000);
    }

    #[test]
    fn test_handshake_event_tracing() {
        let mut tracer = HandshakeTracer::new(TraceLevel::Debug, 100);

        let event = HandshakeEvent::Started {
            role: EndpointRole::Client,
            initial_version: 0x00000001,
            region_id: "test-region".to_string(),
        };

        tracer.trace_handshake_event(&event, Some("test-region".to_string()));

        assert_eq!(tracer.entries.len(), 1);
        assert_eq!(tracer.entries[0].category, "handshake");
        assert_eq!(tracer.entries[0].event, "started");
    }

    #[test]
    fn test_qlog_generation() {
        let mut tracer = HandshakeTracer::new(TraceLevel::Debug, 100);

        let entry = TraceEntry::new(
            0,
            TraceLevel::Info,
            "handshake",
            "started",
            json!({"role": "Client"}),
        );
        tracer.trace(entry);

        let qlog = tracer.to_qlog();
        assert!(qlog.get("qlog_version").is_some());
        assert!(qlog.get("traces").is_some());
    }

    #[test]
    fn test_trace_analysis() {
        let entries = vec![
            TraceEntry::new(0, TraceLevel::Info, "handshake", "started", json!({})),
            TraceEntry::new(100, TraceLevel::Info, "handshake", "completed", json!({})),
        ];

        let completion_time = TraceAnalyzer::find_completion_time(&entries);
        assert_eq!(completion_time, Some(100));

        let failure_info = TraceAnalyzer::find_failure_info(&entries);
        assert!(failure_info.is_none());
    }

    #[test]
    fn test_trace_validation() {
        // Valid trace
        let valid_entries = vec![
            TraceEntry::new(0, TraceLevel::Info, "handshake", "started", json!({})),
            TraceEntry::new(100, TraceLevel::Info, "handshake", "completed", json!({})),
        ];

        let issues = TraceAnalyzer::validate_trace(&valid_entries);
        assert!(issues.is_empty());

        // Invalid trace - no completion
        let invalid_entries = vec![TraceEntry::new(
            0,
            TraceLevel::Info,
            "handshake",
            "started",
            json!({}),
        )];

        let issues = TraceAnalyzer::validate_trace(&invalid_entries);
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_summary_generation() {
        let mut tracer = HandshakeTracer::new(TraceLevel::Debug, 100);

        tracer.trace(TraceEntry::new(
            0,
            TraceLevel::Info,
            "handshake",
            "started",
            json!({}),
        ));
        tracer.trace(TraceEntry::new(
            50,
            TraceLevel::Debug,
            "protection",
            "encrypt",
            json!({}),
        ));
        tracer.trace(TraceEntry::new(
            100,
            TraceLevel::Info,
            "handshake",
            "completed",
            json!({}),
        ));

        let summary = tracer.summary();
        assert_eq!(summary["total_events"], 3);
        assert_eq!(summary["total_duration_ms"], 100);
    }
