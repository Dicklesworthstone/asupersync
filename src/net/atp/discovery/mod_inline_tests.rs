    use super::*;

    fn socket(address: &str) -> SocketAddr {
        address.parse().expect("socket address")
    }

    #[test]
    fn lan_discovery_is_silent_when_disabled() {
        let policy = PathDiscoveryPolicy::safe_default();
        let advertisement =
            LanPeerAdvertisement::maybe_new(policy, "peer-a", socket("192.168.1.10:41641"), 1, 1)
                .expect("disabled is not an error");

        assert_eq!(advertisement, None);
    }

    #[test]
    fn lan_discovery_advertises_and_deduplicates_local_peers() {
        let policy = PathDiscoveryPolicy::safe_default().with_lan_discovery(true);
        let advertisement =
            LanPeerAdvertisement::maybe_new(policy, "peer-a", socket("192.168.1.10:41641"), 1, 1)
                .expect("advertisement")
                .expect("enabled");
        let report = discover_direct_paths(
            policy,
            PathDiscoveryInputs {
                lan_advertisements: vec![advertisement.clone(), advertisement],
                ..PathDiscoveryInputs::default()
            },
        );

        assert_eq!(report.candidates.len(), 1);
        assert_eq!(
            report.candidates[0].source,
            DirectCandidateSource::LanDiscovery
        );
        assert_eq!(
            report.rejections[0].reason,
            DirectCandidateRejection::DuplicateAdvertisement
        );
        assert_eq!(report.logs[0].event, "candidate_available");
    }

    #[test]
    fn explicit_direct_endpoint_reports_validation_errors() {
        let policy = PathDiscoveryPolicy::safe_default();
        let err = explicit_direct_candidate(
            policy,
            "not an endpoint",
            PathCandidateId::new(1),
            PathTraceId::new(2),
        )
        .expect_err("invalid endpoint");

        assert_eq!(
            err.candidate_source,
            DirectCandidateSource::ExplicitDirectUdp
        );
        assert_eq!(err.reason, DirectCandidateRejection::InvalidEndpoint);
        assert!(err.detail.contains("endpoint parse failed"));
    }

    #[test]
    fn explicit_direct_endpoint_builds_candidate() {
        let candidate = explicit_direct_candidate(
            PathDiscoveryPolicy::safe_default(),
            "198.51.100.20:41641",
            PathCandidateId::new(7),
            PathTraceId::new(8),
        )
        .expect("candidate");

        assert_eq!(candidate.source, DirectCandidateSource::ExplicitDirectUdp);
        assert_eq!(candidate.metrics.preference_rank, 20);
        assert_eq!(
            candidate.to_path_candidate().kind,
            PathKind::ExplicitPublicUdp
        );
    }

    #[test]
    fn public_ipv6_candidate_is_ranked_ahead_when_policy_prefers_it() {
        let report = discover_direct_paths(
            PathDiscoveryPolicy::safe_default(),
            PathDiscoveryInputs {
                explicit_direct_endpoint: Some("198.51.100.20:41641".to_string()),
                local_udp_endpoints: vec![socket("[2606:4700:4700::1111]:41641")],
                platform_ipv6_available: true,
                ..PathDiscoveryInputs::default()
            },
        );

        assert_eq!(report.candidates.len(), 2);
        assert_eq!(
            report.candidates[0].source,
            DirectCandidateSource::PublicIpv6
        );
        assert_eq!(report.selected, Some(report.candidates[0].id));
    }

    #[test]
    fn public_ipv6_candidate_requires_platform_and_public_address() {
        let report = discover_direct_paths(
            PathDiscoveryPolicy::safe_default(),
            PathDiscoveryInputs {
                local_udp_endpoints: vec![socket("[fd00::1]:41641")],
                platform_ipv6_available: true,
                ..PathDiscoveryInputs::default()
            },
        );

        assert!(report.candidates.is_empty());
        assert_eq!(
            report.rejections[1].reason,
            DirectCandidateRejection::NotPublicIpv6
        );

        let report = discover_direct_paths(
            PathDiscoveryPolicy::safe_default(),
            PathDiscoveryInputs {
                local_udp_endpoints: vec![socket("[2606:4700:4700::1111]:41641")],
                platform_ipv6_available: false,
                ..PathDiscoveryInputs::default()
            },
        );
        assert_eq!(
            report.rejections[1].reason,
            DirectCandidateRejection::Ipv6Unavailable
        );
    }

    #[test]
    fn lan_discovery_rejects_non_link_local_169_space() {
        let policy = PathDiscoveryPolicy::safe_default().with_lan_discovery(true);
        let err =
            LanPeerAdvertisement::maybe_new(policy, "peer-a", socket("169.1.2.3:41641"), 1, 1)
                .expect_err("only 169.254/16 is IPv4 link-local");

        assert_eq!(err.candidate_source, DirectCandidateSource::LanDiscovery);
        assert_eq!(err.reason, DirectCandidateRejection::NotLanAddress);
        assert_eq!(err.detail, "public-ipv4:41641");
    }

    #[test]
    fn public_ipv6_rejects_ipv4_embedded_addresses() {
        let report = discover_direct_paths(
            PathDiscoveryPolicy::safe_default(),
            PathDiscoveryInputs {
                local_udp_endpoints: vec![
                    socket("[::ffff:10.0.0.1]:41641"),
                    socket("[::c000:0201]:41641"),
                ],
                platform_ipv6_available: true,
                ..PathDiscoveryInputs::default()
            },
        );

        assert!(report.candidates.is_empty());
        assert_eq!(
            report
                .rejections
                .iter()
                .filter(|rejection| {
                    rejection.source == DirectCandidateSource::PublicIpv6
                        && rejection.reason == DirectCandidateRejection::NotPublicIpv6
                })
                .count(),
            2
        );
    }

    #[test]
    fn tailscale_provider_is_optional_and_reports_absence_without_network_dependency() {
        let report = discover_direct_paths(
            PathDiscoveryPolicy::safe_default(),
            PathDiscoveryInputs::default(),
        );

        assert!(report.candidates.is_empty());
        assert!(report.rejections.iter().any(|rejection| {
            rejection.source == DirectCandidateSource::TailscaleProvider
                && rejection.reason == DirectCandidateRejection::TailscaleNotPresent
        }));
        assert!(report.logs.iter().any(|log| {
            log.source == DirectCandidateSource::TailscaleProvider
                && log.event == "candidate_rejected"
                && log.rejection == Some(DirectCandidateRejection::TailscaleNotPresent)
        }));
    }

    #[test]
    fn tailscale_policy_distinguishes_disabled_forbidden_allowed_and_preferred() {
        let tailscale = TailscaleCandidateObservation::new(
            socket("100.100.10.20:41641"),
            TailscaleDetectionSource::LabProvider,
            1_000,
        );
        let public_ipv6 = socket("[2606:4700:4700::1111]:41641");

        let disabled = discover_direct_paths(
            PathDiscoveryPolicy::safe_default()
                .with_tailscale_policy(TailscalePathPolicy::Disabled),
            PathDiscoveryInputs {
                tailscale_candidates: vec![tailscale.clone()],
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );
        assert!(disabled.candidates.is_empty());
        assert!(disabled.rejections.iter().any(|rejection| {
            rejection.source == DirectCandidateSource::TailscaleProvider
                && rejection.reason == DirectCandidateRejection::PolicyDisabled
        }));

        let forbidden = discover_direct_paths(
            PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Forbid),
            PathDiscoveryInputs {
                tailscale_candidates: vec![tailscale.clone()],
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );
        assert!(forbidden.candidates.is_empty());
        assert!(forbidden.rejections.iter().any(|rejection| {
            rejection.source == DirectCandidateSource::TailscaleProvider
                && rejection.reason == DirectCandidateRejection::PolicyForbidden
        }));

        let allowed = discover_direct_paths(
            PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Allow),
            PathDiscoveryInputs {
                local_udp_endpoints: vec![public_ipv6],
                tailscale_candidates: vec![tailscale.clone()],
                platform_ipv6_available: true,
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );
        assert_eq!(
            allowed.selected.and_then(|id| {
                allowed
                    .candidates
                    .iter()
                    .find(|candidate| candidate.id == id)
                    .map(|candidate| candidate.source)
            }),
            Some(DirectCandidateSource::PublicIpv6)
        );

        let preferred = discover_direct_paths(
            PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Prefer),
            PathDiscoveryInputs {
                local_udp_endpoints: vec![public_ipv6],
                tailscale_candidates: vec![tailscale],
                platform_ipv6_available: true,
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );
        assert_eq!(
            preferred.selected.and_then(|id| {
                preferred
                    .candidates
                    .iter()
                    .find(|candidate| candidate.id == id)
                    .map(|candidate| candidate.source)
            }),
            Some(DirectCandidateSource::TailscaleProvider)
        );
    }

    #[test]
    fn tailscale_candidates_are_redacted_validated_and_stale_checked() {
        let report = discover_direct_paths(
            PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Prefer),
            PathDiscoveryInputs {
                explicit_direct_endpoint: Some("198.51.100.20:41641".to_string()),
                tailscale_candidates: vec![TailscaleCandidateObservation::new(
                    socket("100.100.10.20:41641"),
                    TailscaleDetectionSource::LabProvider,
                    1_000,
                )],
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );

        assert_eq!(
            report
                .selected
                .and_then(|id| report
                    .candidates
                    .iter()
                    .find(|candidate| candidate.id == id))
                .map(|candidate| candidate.source),
            Some(DirectCandidateSource::TailscaleProvider)
        );
        let doctor = report.doctor_report();
        let selected = doctor.selected.as_ref().expect("selected Tailscale");
        assert_eq!(selected.kind, PathKind::TailscaleIp);
        assert_eq!(selected.endpoint_scope, "tailscale-ipv4:41641");
        assert_eq!(
            selected.evidence,
            "tailscale_lab_provider_candidate_validated"
        );
        assert!(
            doctor.guidance.contains(
                &"keep_native_direct_or_atp_relay_fallback_because_tailscale_is_optional"
            )
        );
        assert!(
            doctor
                .candidates
                .iter()
                .all(|candidate| !candidate.endpoint_scope.contains("100.100.10.20"))
        );

        let stale = discover_direct_paths(
            PathDiscoveryPolicy::safe_default()
                .with_tailscale_policy(TailscalePathPolicy::Allow)
                .with_tailscale_max_staleness_micros(10),
            PathDiscoveryInputs {
                tailscale_candidates: vec![TailscaleCandidateObservation::new(
                    socket("100.100.10.20:41641"),
                    TailscaleDetectionSource::StatusCommand,
                    1_000,
                )],
                now_micros: 1_011,
                ..PathDiscoveryInputs::default()
            },
        );
        assert!(stale.candidates.is_empty());
        assert!(stale.rejections.iter().any(|rejection| {
            rejection.source == DirectCandidateSource::TailscaleProvider
                && rejection.reason == DirectCandidateRejection::StaleCandidate
                && rejection.detail.contains("source=status_command")
                && !rejection.detail.contains("100.100.10.20")
        }));

        let future_dated = discover_direct_paths(
            PathDiscoveryPolicy::safe_default()
                .with_tailscale_policy(TailscalePathPolicy::Allow)
                .with_tailscale_max_staleness_micros(30_000_000),
            PathDiscoveryInputs {
                tailscale_candidates: vec![TailscaleCandidateObservation::new(
                    socket("100.100.10.20:41641"),
                    TailscaleDetectionSource::StatusCommand,
                    2_001,
                )],
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );
        assert!(future_dated.candidates.is_empty());
        assert!(future_dated.rejections.iter().any(|rejection| {
            rejection.source == DirectCandidateSource::TailscaleProvider
                && rejection.reason == DirectCandidateRejection::StaleCandidate
                && rejection.detail.contains("observed_at=future")
                && !rejection.detail.contains("100.100.10.20")
        }));

        let wrong_network = discover_direct_paths(
            PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Allow),
            PathDiscoveryInputs {
                tailscale_candidates: vec![TailscaleCandidateObservation::new(
                    socket("10.0.0.2:41641"),
                    TailscaleDetectionSource::LocalInterface,
                    1_000,
                )],
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );
        assert!(wrong_network.rejections.iter().any(|rejection| {
            rejection.source == DirectCandidateSource::TailscaleProvider
                && rejection.reason == DirectCandidateRejection::NotTailscaleAddress
                && rejection.detail == "private-ipv4:41641"
        }));
    }

    #[test]
    fn path_doctor_reports_availability_rejections_and_guidance_without_endpoint_leaks() {
        let report = run_discovery_scenario(PathDiscoveryScenario::Ipv6Available);

        assert_eq!(report.schema_version, ATP_PATH_DOCTOR_SCHEMA);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(
            report.selected.as_ref().map(|candidate| candidate.source),
            Some(DirectCandidateSource::PublicIpv6)
        );
        assert_eq!(report.candidates[0].endpoint_scope, "public-ipv6:41641");
        assert!(
            report
                .guidance
                .contains(&"attempt_public_ipv6_candidate_first")
        );
    }

    #[test]
    fn deterministic_scenarios_cover_pnemzp_paths() {
        let scenarios = [
            PathDiscoveryScenario::LanDiscovery,
            PathDiscoveryScenario::ExplicitDirect,
            PathDiscoveryScenario::Ipv6Available,
            PathDiscoveryScenario::TailscaleLabProvider,
            PathDiscoveryScenario::Ipv6Unavailable,
            PathDiscoveryScenario::PolicyDenied,
        ];
        let reports = scenarios
            .into_iter()
            .map(run_discovery_scenario)
            .collect::<Vec<_>>();

        assert_eq!(
            reports[0]
                .selected
                .as_ref()
                .map(|candidate| candidate.source),
            Some(DirectCandidateSource::LanDiscovery)
        );
        assert_eq!(
            reports[1]
                .selected
                .as_ref()
                .map(|candidate| candidate.source),
            Some(DirectCandidateSource::ExplicitDirectUdp)
        );
        assert_eq!(
            reports[2]
                .selected
                .as_ref()
                .map(|candidate| candidate.source),
            Some(DirectCandidateSource::PublicIpv6)
        );
        assert_eq!(
            reports[3]
                .selected
                .as_ref()
                .map(|candidate| candidate.source),
            Some(DirectCandidateSource::TailscaleProvider)
        );
        assert!(reports[4].selected.is_none());
        assert_eq!(
            reports[5].guidance,
            vec!["enable_at_least_one_direct_path_policy_or_configure_relay"]
        );
    }

    #[test]
    fn tailscale_lab_provider_scenario_is_redaction_safe() {
        let report = run_discovery_scenario(PathDiscoveryScenario::TailscaleLabProvider);

        assert_eq!(
            report.selected.as_ref().map(|candidate| candidate.source),
            Some(DirectCandidateSource::TailscaleProvider)
        );
        let candidate = report.selected.as_ref().expect("candidate");
        assert_eq!(candidate.endpoint_scope, "tailscale-ipv4:41641");
        assert_eq!(
            candidate.evidence,
            "tailscale_lab_provider_candidate_validated"
        );
    }
