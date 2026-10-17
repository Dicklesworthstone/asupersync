    use super::*;
    use crate::atp::path::{
        PathCandidateId, PathFailureKind, PathKind, PathOutcome, PathSuccessKind, PathTraceId,
    };
    use crate::atp::platform::DeterministicLabPlatformProvider;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn path_candidate(raw: u64, kind: PathKind) -> PathCandidate {
        PathCandidate::new(
            PathCandidateId::new(raw),
            kind,
            PathTraceId::new(90_000 + raw),
        )
    }

    fn relay_fallback_race() -> PathRace {
        let direct = PathCandidateId::new(1);
        let relay = PathCandidateId::new(2);
        let tailscale = PathCandidateId::new(3);
        let mut race = PathRace::new();
        race.add_candidate(path_candidate(direct.get(), PathKind::NatPunchedUdp))
            .expect("direct candidate");
        race.add_candidate(path_candidate(relay.get(), PathKind::AtpRelayTcpTls443))
            .expect("relay candidate");
        race.add_candidate(path_candidate(tailscale.get(), PathKind::TailscaleIp))
            .expect("tailscale candidate");
        race.start_all().expect("start race");
        race.record_outcome(
            direct,
            PathOutcome::failure(PathFailureKind::UdpBlocked, 10_000).with_bytes(120, 0),
        )
        .expect("direct failure");
        race.record_outcome(
            relay,
            PathOutcome::success(PathSuccessKind::RelaySelected, 22_000, Some(9_000))
                .with_bytes(512, 512),
        )
        .expect("relay success");
        race
    }

    #[test]
    fn path_doctor_document_reports_relay_fallback_and_loser_drain_trace() {
        init_test("path_doctor_document_reports_relay_fallback_and_loser_drain_trace");
        let document = build_path_doctor_document("peer-alpha", &relay_fallback_race());

        assert_eq!(document.schema_version, ATP_PATH_DOCTOR_SCHEMA);
        assert_eq!(document.summary.overall_health, "degraded");
        assert_eq!(document.summary.reason_code, "relay_fallback_validated");
        assert_eq!(document.summary.selected_family.as_deref(), Some("relay"));
        assert_eq!(document.summary.candidate_count, 3);
        assert_eq!(document.summary.failure_count, 1);
        assert_eq!(document.summary.drained_loser_count, 1);

        let selected = document.selected_path.as_ref().expect("selected path");
        assert_eq!(selected.candidate_id, 2);
        assert_eq!(selected.kind, "atp_relay_tcp_tls_443");
        assert_eq!(selected.observed_rtt_micros, Some(9_000));

        let direct = document
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == 1)
            .expect("direct candidate");
        assert_eq!(direct.state, "failed");
        assert_eq!(direct.outcome.as_deref(), Some("failure_udp_blocked"));

        let tailscale = document
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == 3)
            .expect("tailscale candidate");
        assert_eq!(tailscale.state, "drained_loser");
        assert!(tailscale.drained_loser);
        assert_eq!(tailscale.winner_candidate_id, Some(2));

        assert!(document.trace.iter().all(|entry| {
            entry.schema_version == ATP_PATH_TRACE_ATTEMPT_SCHEMA && !entry.detail.is_empty()
        }));
        assert!(document.trace.iter().any(|entry| {
            entry.candidate_id == 3 && entry.detail.contains("lost to candidate 2")
        }));
        assert_eq!(
            document.recommendations[0].code,
            "tcp_tls_443_fallback_selected"
        );
        crate::test_complete!("path_doctor_document_reports_relay_fallback_and_loser_drain_trace");
    }

    #[test]
    fn path_doctor_json_and_human_output_have_stable_fields() {
        init_test("path_doctor_json_and_human_output_have_stable_fields");
        let document = build_path_doctor_document("peer-alpha", &relay_fallback_race());
        let json = serde_json::to_value(&document).expect("serialize path doctor");

        assert_eq!(json["schema_version"], ATP_PATH_DOCTOR_SCHEMA);
        assert_eq!(json["summary"]["reason_code"], "relay_fallback_validated");
        assert_eq!(json["selected_path"]["family"], "relay");
        assert_eq!(
            json["trace"][0]["schema_version"],
            ATP_PATH_TRACE_ATTEMPT_SCHEMA
        );

        let rendered = render_path_doctor_human(&document);
        assert!(rendered.contains("Schema: asupersync.atp.doctor.path.v1"));
        assert!(rendered.contains("Overall: degraded reason=relay_fallback_validated"));
        assert!(
            rendered.contains(
                "Selected: candidate=2 kind=atp_relay_tcp_tls_443 family=relay trace=90002"
            )
        );
        assert!(rendered.contains("Recommendations: 1"));
        crate::test_complete!("path_doctor_json_and_human_output_have_stable_fields");
    }

    #[test]
    fn platform_doctor_document_has_stable_shape() {
        init_test("platform_doctor_document_has_stable_shape");
        let provider = DeterministicLabPlatformProvider::fully_supported();
        let document = build_platform_doctor_document(&provider);

        assert_eq!(document.schema_version, ATP_PLATFORM_DOCTOR_SCHEMA);
        assert_eq!(document.report.filesystem.sparse_files.name, "sparse_files");
        assert_eq!(document.logs.len(), 11);
        assert!(
            document
                .logs
                .iter()
                .any(|entry| entry.capability == "service_manager"
                    && entry.measurement_kind == "measured")
        );
        crate::test_complete!("platform_doctor_document_has_stable_shape");
    }

    #[test]
    fn platform_doctor_logs_failed_and_skipped_probe_details() {
        init_test("platform_doctor_logs_failed_and_skipped_probe_details");
        let provider = DeterministicLabPlatformProvider::conservative_degradation();
        let document = build_platform_doctor_document(&provider);

        let sparse = document
            .logs
            .iter()
            .find(|entry| entry.capability == "sparse_files")
            .expect("sparse log");
        assert_eq!(
            sparse.degradation_reason.as_deref(),
            Some("write into quarantine before verified exposure")
        );

        let service = document
            .logs
            .iter()
            .find(|entry| entry.capability == "service_manager")
            .expect("service-manager log");
        assert_eq!(service.probe_source, "skipped");
        assert!(service.skip_reason.is_some());
        assert_eq!(
            service.suggested_recovery_command.as_deref(),
            Some("run atpd under a supported service manager")
        );
        crate::test_complete!("platform_doctor_logs_failed_and_skipped_probe_details");
    }

    #[test]
    fn platform_doctor_human_output_has_stable_sections() {
        init_test("platform_doctor_human_output_has_stable_sections");
        let provider = DeterministicLabPlatformProvider::fully_supported();
        let document = build_platform_doctor_document(&provider);
        let rendered = render_platform_doctor_human(&document);

        assert!(rendered.contains("Schema: asupersync.atp.doctor.platform.v1"));
        assert!(rendered.contains("Filesystem:"));
        assert!(rendered.contains("Network:"));
        assert!(rendered.contains("Service:"));
        assert!(rendered.contains("Degradation policy:"));
        assert!(rendered.contains("Structured probe logs: 11"));
        crate::test_complete!("platform_doctor_human_output_has_stable_sections");
    }

    #[test]
    fn platform_doctor_json_output_has_stable_fields() {
        init_test("platform_doctor_json_output_has_stable_fields");
        let provider = DeterministicLabPlatformProvider::conservative_degradation();
        let document = build_platform_doctor_document(&provider);
        let json = serde_json::to_value(&document).expect("serialize doctor document");

        assert_eq!(json["schema_version"], ATP_PLATFORM_DOCTOR_SCHEMA);
        assert_eq!(
            json["report"]["degradation_policy"]["disk_writer_mode"],
            "contiguous-verified-quarantine"
        );
        assert!(json["logs"].as_array().expect("logs array").iter().any(
            |entry| entry["capability"] == "ipv6"
                && entry["suggested_recovery_command"]
                    == "enable IPv6 loopback/networking on this host"
        ));
        crate::test_complete!("platform_doctor_json_output_has_stable_fields");
    }
