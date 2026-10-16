    use super::*;

    fn endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, address, port).expect("endpoint")
    }

    fn ipv6_endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv6, address, port).expect("endpoint")
    }

    fn probe(
        local_endpoint: ObservedEndpoint,
        observed_endpoint: ObservedEndpoint,
        probe_nonce: u64,
    ) -> EndpointProbeObservation {
        EndpointObservation::from_request(ObservationRequest {
            local_endpoint,
            observed_endpoint,
            observer_id: format!("rendezvous-{probe_nonce}"),
            probe_nonce,
            observed_at_micros: probe_nonce * 10,
        })
        .expect("valid observation")
        .into()
    }

    #[test]
    fn observation_records_observed_endpoint_and_nonce() {
        let observation = EndpointObservation::from_request(ObservationRequest {
            local_endpoint: endpoint("10.0.0.2", 40_000),
            observed_endpoint: endpoint("198.51.100.10", 50_000),
            observer_id: "rendezvous-a".to_owned(),
            probe_nonce: 7,
            observed_at_micros: 99,
        })
        .expect("valid observation");

        assert_eq!(observation.observer_id(), "rendezvous-a");
        assert_eq!(observation.probe_nonce(), 7);
        assert_eq!(observation.local_endpoint().address(), "10.0.0.2");
        assert_eq!(observation.observed_endpoint().port(), 50_000);
    }

    #[test]
    fn observation_rejects_blank_observer_and_zero_nonce() {
        let err = EndpointObservation::from_request(ObservationRequest {
            local_endpoint: endpoint("10.0.0.2", 40_000),
            observed_endpoint: endpoint("198.51.100.10", 50_000),
            observer_id: " ".to_owned(),
            probe_nonce: 7,
            observed_at_micros: 99,
        })
        .expect_err("blank observer");
        assert_eq!(err, ObservationError::EmptyObserverId);

        let err = EndpointObservation::from_request(ObservationRequest {
            local_endpoint: endpoint("10.0.0.2", 40_000),
            observed_endpoint: endpoint("198.51.100.10", 50_000),
            observer_id: "rendezvous-a".to_owned(),
            probe_nonce: 0,
            observed_at_micros: 99,
        })
        .expect_err("zero nonce");
        assert_eq!(err, ObservationError::ZeroProbeNonce);
    }

    #[test]
    fn endpoint_rejects_empty_address_and_zero_port() {
        assert_eq!(
            ObservedEndpoint::new(EndpointFamily::Ipv4, " ", 1).expect_err("empty address"),
            ObservationError::EmptyAddress
        );
        assert_eq!(
            ObservedEndpoint::new(EndpointFamily::Ipv6, "2001:db8::1", 0).expect_err("zero port"),
            ObservationError::ZeroPort
        );
    }

    #[test]
    fn endpoint_probe_observation_records_blocked_probe_metadata() {
        let probe = EndpointProbeObservation::blocked(endpoint("10.0.0.2", 40_000), "rv-a", 9, 99)
            .expect("blocked probe");

        assert!(!probe.probe_succeeded());
        assert_eq!(probe.observer_id(), "rv-a");
        assert_eq!(probe.probe_nonce(), 9);
        assert_eq!(probe.observed_at_micros(), 99);
        assert_eq!(probe.observed_endpoint(), None);
        assert_eq!(probe.local_endpoint().address(), "10.0.0.2");
    }

    #[test]
    fn endpoint_nat_classifier_reports_missing_observations_as_unknown() {
        let assessment = classify_endpoint_nat(&[]);

        assert_eq!(assessment.kind, EndpointNatKind::Unknown);
        assert_eq!(assessment.hairpin, EndpointHairpinSupport::Unknown);
        assert_eq!(assessment.confidence, EndpointNatConfidence::Low);
        assert_eq!(assessment.observed_public_endpoint, None);
        assert_eq!(assessment.caveat, "missing_endpoint_observation");
    }

    #[test]
    fn endpoint_nat_classifier_reports_blocked_when_probes_fail() {
        let assessment = classify_endpoint_nat(&[EndpointProbeObservation::blocked(
            endpoint("10.0.0.2", 40_000),
            "rv-a",
            3,
            30,
        )
        .expect("blocked")]);

        assert_eq!(assessment.kind, EndpointNatKind::UdpBlocked);
        assert_eq!(assessment.hairpin, EndpointHairpinSupport::Unknown);
        assert_eq!(assessment.confidence, EndpointNatConfidence::High);
        assert_eq!(assessment.observed_public_endpoint, None);
        assert_eq!(assessment.caveat, "no_udp_probe_reached_rendezvous");
    }

    #[test]
    fn endpoint_nat_classifier_distinguishes_ipv6_direct_path() {
        let local = ipv6_endpoint("2001:db8::10", 49_152);
        let assessment = classify_endpoint_nat(&[probe(local.clone(), local.clone(), 4)]);

        assert_eq!(assessment.kind, EndpointNatKind::Ipv6Direct);
        assert_eq!(assessment.confidence, EndpointNatConfidence::Medium);
        assert_eq!(assessment.observed_public_endpoint, Some(local));
        assert_eq!(assessment.caveat, "ipv6_endpoint_observed_directly");
    }

    #[test]
    fn endpoint_nat_classifier_reports_public_ipv4_direct_path() {
        let local = endpoint("198.51.100.10", 49_152);
        let assessment = classify_endpoint_nat(&[probe(local.clone(), local.clone(), 5)]);

        assert_eq!(assessment.kind, EndpointNatKind::PublicIpv4Direct);
        assert_eq!(assessment.confidence, EndpointNatConfidence::Medium);
        assert_eq!(assessment.observed_public_endpoint, Some(local));
        assert_eq!(assessment.caveat, "ipv4_endpoint_observed_directly");
    }

    #[test]
    fn endpoint_nat_classifier_reports_stable_mapping_as_likely_easy_nat() {
        let public = endpoint("198.51.100.20", 62_000);
        let observations = [
            probe(endpoint("10.0.0.2", 49_152), public.clone(), 6).with_hairpin_result(true),
            probe(endpoint("10.0.0.2", 49_152), public.clone(), 7),
        ];

        let assessment = classify_endpoint_nat(&observations);

        assert_eq!(assessment.kind, EndpointNatKind::LikelyEasyNat);
        assert_eq!(assessment.hairpin, EndpointHairpinSupport::Supported);
        assert_eq!(assessment.confidence, EndpointNatConfidence::High);
        assert_eq!(assessment.observed_public_endpoint, Some(public));
        assert_eq!(assessment.caveat, "stable_public_mapping_observed");
    }

    #[test]
    fn endpoint_nat_classifier_reports_multiple_mappings_as_hard_or_symmetric_nat() {
        let observations = [
            probe(
                endpoint("10.0.0.2", 49_152),
                endpoint("198.51.100.20", 62_000),
                8,
            )
            .with_hairpin_result(false),
            probe(
                endpoint("10.0.0.2", 49_152),
                endpoint("198.51.100.21", 62_001),
                9,
            ),
        ];

        let assessment = classify_endpoint_nat(&observations);

        assert_eq!(assessment.kind, EndpointNatKind::HardOrSymmetricNat);
        assert_eq!(assessment.hairpin, EndpointHairpinSupport::Unsupported);
        assert_eq!(assessment.confidence, EndpointNatConfidence::High);
        assert_eq!(assessment.observed_public_endpoint, None);
        assert_eq!(assessment.caveat, "multiple_public_mappings_observed");
    }

    #[test]
    fn endpoint_nat_classifier_reports_contradictory_multi_local_observations_as_unknown() {
        let observations = [
            probe(
                endpoint("10.0.0.2", 49_152),
                endpoint("198.51.100.20", 62_000),
                10,
            ),
            probe(
                endpoint("10.0.0.3", 49_153),
                endpoint("198.51.100.21", 62_001),
                11,
            ),
        ];

        let assessment = classify_endpoint_nat(&observations);

        assert_eq!(assessment.kind, EndpointNatKind::Unknown);
        assert_eq!(assessment.hairpin, EndpointHairpinSupport::Unknown);
        assert_eq!(assessment.confidence, EndpointNatConfidence::Low);
        assert_eq!(assessment.observed_public_endpoint, None);
        assert_eq!(assessment.caveat, "multiple_local_endpoints_observed");
    }
