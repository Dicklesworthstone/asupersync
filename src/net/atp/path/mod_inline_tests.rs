    use super::*;
    use crate::net::atp::stun::{ObservationRequest, ObservedEndpoint};

    fn endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, address, port).expect("endpoint")
    }

    fn ipv6_endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv6, address, port).expect("endpoint")
    }

    fn tailscale_candidate(address: &str) -> TailscaleProviderCandidate {
        TailscaleProviderCandidate::new(
            "node-1",
            "peer-a",
            ipv6_endpoint(address, 41_641),
            Some("peer-a.tailnet.ts.net".to_owned()),
            Some(7),
            123,
        )
        .expect("tailscale candidate")
    }

    fn router_assist_candidate(
        provider_label: &str,
        protocol: RouterAssistProtocol,
        external_port: u16,
        lease_lifetime_micros: u64,
        observed_at_micros: u64,
    ) -> RouterAssistProviderCandidate {
        RouterAssistProviderCandidate::new(
            provider_label,
            protocol,
            endpoint("10.0.0.2", 41_641),
            endpoint("198.51.100.7", external_port),
            lease_lifetime_micros,
            observed_at_micros,
        )
        .expect("router-assist candidate")
    }

    fn observation(
        local: ObservedEndpoint,
        observed: ObservedEndpoint,
        nonce: u64,
    ) -> EndpointObservation {
        EndpointObservation::from_request(ObservationRequest {
            local_endpoint: local,
            observed_endpoint: observed,
            observer_id: format!("observer-{nonce}"),
            probe_nonce: nonce,
            observed_at_micros: nonce,
        })
        .expect("observation")
    }

    fn path_candidate(id: u64, preference_rank: u8, observed_at_micros: u64) -> AtpPathCandidate {
        let remote_port = 41_641u16
            .checked_add(u16::try_from(id).expect("small test path id"))
            .expect("test path port in range");
        AtpPathCandidate::new(
            AtpPathId::new(id),
            AtpPathEndpoints::new(
                endpoint("10.0.0.2", 41_641),
                endpoint("198.51.100.7", remote_port),
            ),
            preference_rank,
            observed_at_micros,
            format!("candidate-{id}"),
            format!("verifier-{id}"),
        )
        .expect("path candidate")
    }

    #[test]
    fn path_rejection_rejects_success_status_without_archiving() {
        let active = path_candidate(0, 10, 1);
        let candidate = path_candidate(1, 5, 2);
        let mut manager = AtpPathManager::new(active);

        manager
            .request_migration(candidate, PathMigrationReason::ActiveMigration, 10)
            .expect("migration requested");

        let err = manager
            .reject_migration(AtpPathId::new(1), PathMigrationStatus::Committed, 11)
            .expect_err("committed is not a rejection status");
        assert_eq!(err, PathMigrationError::InvalidRejectionStatus);
        assert!(manager.pending().contains_key(&AtpPathId::new(1)));
        assert!(manager.history().is_empty());

        let err = manager
            .reject_migration(AtpPathId::new(1), PathMigrationStatus::Validated, 12)
            .expect_err("validated is not a rejection status");
        assert_eq!(err, PathMigrationError::InvalidRejectionStatus);
        assert!(manager.pending().contains_key(&AtpPathId::new(1)));
        assert!(manager.history().is_empty());

        let rejected = manager
            .reject_migration(AtpPathId::new(1), PathMigrationStatus::Rejected, 13)
            .expect("explicit rejection");
        assert_eq!(rejected.status(), PathMigrationStatus::Rejected);
        assert!(manager.pending().is_empty());
        assert_eq!(manager.history().len(), 1);
    }

    #[test]
    fn classifies_udp_blocked_without_observations() {
        let evidence = NatEvidence::new(
            endpoint("10.0.0.2", 40_000),
            Vec::new(),
            UdpProbe::Blocked,
            HairpinBehavior::Unknown,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::UdpBlocked);
        assert_eq!(classification.confidence, NatConfidence::High);
        assert_eq!(classification.caveat, "udp_probe_blocked");
    }

    #[test]
    fn classifies_ipv6_direct_when_ipv6_is_observed() {
        let local = ipv6_endpoint("2001:db8::1", 40_000);
        let observed = ipv6_endpoint("2001:db8::1", 40_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![observation(local, observed, 1)],
            UdpProbe::Succeeded,
            HairpinBehavior::Supported,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::Ipv6Direct);
        assert_eq!(classification.confidence, NatConfidence::High);
    }

    #[test]
    fn classifies_hard_nat_when_observers_disagree() {
        let local = endpoint("10.0.0.2", 40_000);
        let observed_a = endpoint("198.51.100.10", 50_000);
        let observed_b = endpoint("198.51.100.10", 51_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![
                observation(local.clone(), observed_a, 1),
                observation(local, observed_b, 2),
            ],
            UdpProbe::Succeeded,
            HairpinBehavior::NotSupported,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::HardSymmetricNat);
        assert_eq!(classification.hairpin, HairpinBehavior::NotSupported);
    }

    #[test]
    fn classifies_stable_mapping_as_easy_nat() {
        let local = endpoint("10.0.0.2", 40_000);
        let observed = endpoint("198.51.100.10", 50_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![
                observation(local.clone(), observed.clone(), 1),
                observation(local, observed, 2),
            ],
            UdpProbe::Succeeded,
            HairpinBehavior::Unknown,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::LikelyEasyNat);
        assert_eq!(classification.confidence, NatConfidence::Medium);
    }

    #[test]
    fn classifies_unknown_when_udp_probe_has_no_observations() {
        let evidence = NatEvidence::new(
            endpoint("10.0.0.2", 40_000),
            Vec::new(),
            UdpProbe::NotMeasured,
            HairpinBehavior::Unknown,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::Unknown);
        assert_eq!(classification.confidence, NatConfidence::Low);
        assert_eq!(classification.caveat, "no_observations");
    }

    #[test]
    fn tailscale_disabled_ignores_provider_output() {
        let set = select_tailscale_candidates(
            TailscalePreference::Disabled,
            Ok(vec![tailscale_candidate("fd7a:115c:a1e0::1")]),
        );

        assert!(set.candidates().is_empty());
        assert_eq!(set.caveat(), "tailscale_disabled");
        assert!(set.provider_failure().is_none());
    }

    #[test]
    fn tailscale_provider_failure_is_nonfatal() {
        let failure = TailscaleProviderFailure::new("tailscaled_unreachable").expect("failure");
        let set = select_tailscale_candidates(TailscalePreference::Prefer, Err(failure));

        assert!(set.candidates().is_empty());
        assert_eq!(set.caveat(), "tailscale_provider_failed_nonfatal");
        assert_eq!(
            set.provider_failure().map(TailscaleProviderFailure::reason),
            Some("tailscaled_unreachable")
        );
    }

    #[test]
    fn tailscale_candidate_has_metrics_and_proof_summary() {
        let set = select_tailscale_candidates(
            TailscalePreference::Prefer,
            Ok(vec![tailscale_candidate("fd7a:115c:a1e0::2")]),
        );

        let candidate = &set.candidates()[0];
        assert_eq!(set.caveat(), "tailscale_preferred");
        assert_eq!(candidate.endpoint().address(), "fd7a:115c:a1e0::2");
        assert_eq!(candidate.metrics().preference_rank, 10);
        assert_eq!(candidate.metrics().expected_rtt_micros, Some(5_000));
        assert_eq!(candidate.proof_summary().node_id, "node-1");
        assert_eq!(candidate.proof_summary().peer_label, "peer-a");
        assert!(candidate.proof_summary().magic_dns_present);
        assert_eq!(
            candidate.proof_summary().caveat,
            "tailscale_magic_dns_candidate"
        );
    }

    #[test]
    fn router_assist_disabled_ignores_provider_candidates() {
        let candidate =
            router_assist_candidate("upnp", RouterAssistProtocol::UpnpIgd, 49_152, 60_000_000, 1);

        let set =
            select_router_assist_candidates(RouterAssistPolicy::DISABLED, Ok(vec![candidate]));

        assert_eq!(set.caveat(), "router_assist_disabled");
        assert!(set.candidates().is_empty());
        assert!(set.selected().is_none());
        assert!(!set.is_required());
    }

    #[test]
    fn router_assist_requires_explicit_mapping_capability() {
        let policy = RouterAssistPolicy::new(false, 60_000_000);
        let candidate =
            router_assist_candidate("pcp", RouterAssistProtocol::Pcp, 50_000, 60_000_000, 1);

        let set = select_router_assist_candidates(policy, Ok(vec![candidate]));

        assert_eq!(set.caveat(), "router_assist_mapping_capability_denied");
        assert!(set.candidates().is_empty());
        assert!(set.selected().is_none());
        assert!(set.provider_failure().is_none());
    }

    #[test]
    fn router_assist_provider_failure_is_nonfatal() {
        let policy = RouterAssistPolicy::new(true, 60_000_000);
        let failure =
            RouterAssistProviderFailure::new("router control socket unavailable").expect("failure");

        let set = select_router_assist_candidates(policy, Err(failure));

        assert_eq!(set.caveat(), "router_assist_provider_failed_nonfatal");
        assert!(set.candidates().is_empty());
        assert!(set.selected().is_none());
        assert_eq!(
            set.provider_failure()
                .map(RouterAssistProviderFailure::reason),
            Some("router control socket unavailable")
        );
    }

    #[test]
    fn router_assist_selection_filters_lifetime_and_prefers_pcp() {
        let policy = RouterAssistPolicy::new(true, 60_000_000);
        let expired_by_policy = router_assist_candidate(
            "long-upnp",
            RouterAssistProtocol::UpnpIgd,
            49_152,
            120_000_000,
            1,
        );
        let nat_pmp = router_assist_candidate(
            "nat-pmp",
            RouterAssistProtocol::NatPmp,
            49_153,
            30_000_000,
            2,
        );
        let pcp = router_assist_candidate("pcp", RouterAssistProtocol::Pcp, 49_154, 30_000_000, 3);

        let set =
            select_router_assist_candidates(policy, Ok(vec![expired_by_policy, nat_pmp, pcp]));

        assert_eq!(set.caveat(), "router_assist_candidate_selected");
        assert_eq!(set.candidates().len(), 2);
        let selected = set.selected().expect("selected pcp mapping");
        assert_eq!(selected.protocol(), RouterAssistProtocol::Pcp);
        assert_eq!(selected.protocol().code(), "pcp");
        assert_eq!(selected.external_endpoint().port(), 49_154);
    }

    #[test]
    fn path_doctor_reports_hard_nat_fallback_without_router_mutation() {
        let local = endpoint("10.0.0.2", 40_000);
        let observed_a = endpoint("198.51.100.10", 50_000);
        let observed_b = endpoint("198.51.100.10", 51_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![
                observation(local.clone(), observed_a, 1),
                observation(local, observed_b, 2),
            ],
            UdpProbe::Succeeded,
            HairpinBehavior::NotSupported,
        );
        let router_assist =
            select_router_assist_candidates(RouterAssistPolicy::DISABLED, Ok(Vec::new()));

        let report =
            build_router_assist_path_doctor_report(classify_nat(&evidence), &router_assist);

        assert_eq!(report.nat_profile(), NatProfile::HardSymmetricNat);
        assert_eq!(report.nat_confidence(), NatConfidence::High);
        assert_eq!(report.hairpin(), HairpinBehavior::NotSupported);
        assert_eq!(report.nat_caveat(), "incompatible_observed_mappings");
        assert_eq!(report.router_assist_caveat(), "router_assist_disabled");
        assert_eq!(report.router_assist_protocol(), None);
        assert_eq!(report.recommendation().code(), "use_relay_or_tailscale");
        assert_eq!(
            report.mutation_status(),
            RouterAssistMutationStatus::Disabled
        );
        assert!(!report.router_state_change_authorized());
    }

    #[test]
    fn path_doctor_marks_router_assist_as_explicitly_authorized() {
        let local = endpoint("10.0.0.2", 40_000);
        let observed_a = endpoint("198.51.100.10", 50_000);
        let observed_b = endpoint("198.51.100.10", 51_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![
                observation(local.clone(), observed_a, 1),
                observation(local, observed_b, 2),
            ],
            UdpProbe::Succeeded,
            HairpinBehavior::NotSupported,
        );
        let policy = RouterAssistPolicy::new(true, 60_000_000);
        let candidate =
            router_assist_candidate("pcp", RouterAssistProtocol::Pcp, 49_154, 30_000_000, 3);
        let router_assist = select_router_assist_candidates(policy, Ok(vec![candidate]));

        let report =
            build_router_assist_path_doctor_report(classify_nat(&evidence), &router_assist);

        assert_eq!(
            report.recommendation().code(),
            "try_router_assist_then_relay"
        );
        assert_eq!(
            report.router_assist_protocol(),
            Some(RouterAssistProtocol::Pcp)
        );
        assert_eq!(
            report.mutation_status().code(),
            "router_assist_explicitly_authorized_candidate"
        );
        assert!(report.router_state_change_authorized());
    }

    #[test]
    fn tailscale_input_rejects_blank_identifiers() {
        let err = TailscaleProviderCandidate::new(
            " ",
            "peer-a",
            ipv6_endpoint("fd7a:115c:a1e0::3", 41_641),
            None,
            None,
            1,
        )
        .expect_err("blank node id");
        assert_eq!(err, TailscaleCandidateError::EmptyNodeId);

        let err = TailscaleProviderFailure::new(" ").expect_err("blank failure");
        assert_eq!(err, TailscaleCandidateError::EmptyFailureReason);
    }
