    use super::*;
    use crate::net::atp::stun::{EndpointFamily, ObservationRequest, ObservedEndpoint};
    use futures_lite::future::block_on;

    fn peer(byte: u8) -> PeerId {
        PeerId::new([byte; 32]).expect("peer id")
    }

    fn nonce(raw: u128) -> TransferNonce {
        TransferNonce::new(raw).expect("transfer nonce")
    }

    fn candidate_nonce(raw: u128) -> CandidateNonce {
        CandidateNonce::new(raw).expect("candidate nonce")
    }

    fn endpoint(port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, "198.51.100.10", port).expect("endpoint")
    }

    fn private_endpoint(port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, "10.0.0.2", port).expect("endpoint")
    }

    fn observation(probe_nonce: u64, observed_port: u16) -> EndpointObservation {
        EndpointObservation::from_request(ObservationRequest {
            local_endpoint: private_endpoint(40_000),
            observed_endpoint: endpoint(observed_port),
            observer_id: "rendezvous-a".to_owned(),
            probe_nonce,
            observed_at_micros: 10,
        })
        .expect("observation")
    }

    fn signed_candidate(
        peer_id: PeerId,
        transfer_nonce: TransferNonce,
        candidate_nonce: CandidateNonce,
    ) -> SignedCandidate {
        SignedCandidate::new(
            peer_id,
            transfer_nonce,
            candidate_nonce,
            Candidate::new(endpoint(50_000), CandidateTransport::Udp, 1_000),
            CandidateSignature::new(vec![1, 2, 3]).expect("signature"),
        )
    }

    fn relay_authorization(
        relay_peer_id: PeerId,
        subject_peer_id: PeerId,
        transfer_nonce: TransferNonce,
    ) -> RelayAuthorization {
        RelayAuthorization::new(
            relay_peer_id,
            subject_peer_id,
            transfer_nonce,
            1_000,
            CandidateSignature::new(vec![9, 9]).expect("relay signature"),
        )
    }

    fn signed_relay_candidate(
        peer_id: PeerId,
        transfer_nonce: TransferNonce,
        candidate_nonce: CandidateNonce,
        authorization: Option<RelayAuthorization>,
    ) -> SignedCandidate {
        let mut candidate = Candidate::new(endpoint(50_010), CandidateTransport::Relay, 1_000);
        if let Some(authorization) = authorization {
            candidate = candidate.with_relay_authorization(authorization);
        }
        SignedCandidate::new(
            peer_id,
            transfer_nonce,
            candidate_nonce,
            candidate,
            CandidateSignature::new(vec![1, 2, 3]).expect("signature"),
        )
    }

    struct RelayVerifier {
        relay_authorization_valid: bool,
    }

    impl CandidateSignatureVerifier for RelayVerifier {
        fn verify(&self, candidate: &SignedCandidate) -> bool {
            candidate.signature().bytes() == [1, 2, 3] // ubs:ignore - test oracle
        }

        fn verify_relay_authorization(
            &self,
            _candidate: &SignedCandidate,
            authorization: &RelayAuthorization,
        ) -> bool {
            self.relay_authorization_valid && authorization.signature().bytes() == [9, 9] // ubs:ignore - test oracle
        }
    }

    #[test]
    fn relay_authorization_binding_helpers_match_expected_values() {
        let peer_a = peer(1);
        let peer_b = peer(2);
        let nonce_a = nonce(7);
        let nonce_b = nonce(8);

        assert!(constant_time_peer_id_eq(peer_a, peer_a));
        assert!(!constant_time_peer_id_eq(peer_a, peer_b));
        assert!(constant_time_transfer_nonce_eq(nonce_a, nonce_a));
        assert!(!constant_time_transfer_nonce_eq(nonce_a, nonce_b));
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[9, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 3, 4]));
    }

    #[test]
    fn accepts_valid_signed_candidate() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));
        let signed = signed_candidate(peer(1), transfer_nonce, candidate_nonce(9));

        service
            .register_candidate(10, signed, &|candidate: &SignedCandidate| {
                candidate.signature().bytes() == [1, 2, 3]
            })
            .expect("accepted");

        assert_eq!(
            service
                .session(transfer_nonce)
                .expect("session")
                .candidates()
                .len(),
            1
        );
    }

    #[test]
    fn records_endpoint_observation_and_exchanges_peer_view() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        let peer_b = peer(2);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));

        let receipt = service
            .record_endpoint_observation(10, peer_a, transfer_nonce, observation(21, 50_001))
            .expect("observation accepted");
        assert_eq!(receipt.peer_id(), peer_a);
        assert_eq!(receipt.observed_endpoint().port(), 50_001);

        service
            .register_candidate(
                10,
                signed_candidate(peer_b, transfer_nonce, candidate_nonce(9)),
                &|candidate: &SignedCandidate| candidate.signature().bytes() == [1, 2, 3],
            )
            .expect("peer candidate accepted");

        let exchange = service
            .exchange_for_peer(11, transfer_nonce, peer_a)
            .expect("exchange");
        assert_eq!(exchange.observed_public_endpoints().len(), 1);
        assert_eq!(exchange.observed_public_endpoints()[0].port(), 50_001);
        assert_eq!(exchange.peer_candidates().len(), 1);
        assert_eq!(exchange.peer_candidates()[0].peer_id(), peer_b);
        assert_eq!(
            exchange.remaining_attempts(),
            Quotas::default().max_attempts_per_peer
        );
        assert_eq!(exchange.session_expires_at_micros(), 1_000);
        assert_eq!(
            service
                .events()
                .iter()
                .map(ServiceEvent::kind)
                .collect::<Vec<_>>(),
            vec![
                ServiceEventKind::SessionOpened,
                ServiceEventKind::EndpointObservationAccepted,
                ServiceEventKind::CandidateAccepted,
            ]
        );
    }

    #[test]
    fn exchange_filters_own_and_expired_candidates() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        let peer_b = peer(2);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));

        service
            .register_candidate(
                10,
                signed_candidate(peer_a, transfer_nonce, candidate_nonce(9)),
                &|_: &SignedCandidate| true,
            )
            .expect("own candidate accepted");
        let short_lived_peer_candidate = SignedCandidate::new(
            peer_b,
            transfer_nonce,
            candidate_nonce(10),
            Candidate::new(endpoint(50_020), CandidateTransport::Udp, 20),
            CandidateSignature::new(vec![1, 2, 3]).expect("signature"),
        );
        service
            .register_candidate(10, short_lived_peer_candidate, &|_: &SignedCandidate| true)
            .expect("short-lived peer candidate accepted");

        let exchange = service
            .exchange_for_peer(30, transfer_nonce, peer_a)
            .expect("exchange");
        assert!(exchange.peer_candidates().is_empty());
    }

    #[test]
    fn rejects_malformed_peer_id_and_zero_nonces() {
        assert_eq!(
            PeerId::new([0; 32]).expect_err("zero peer"),
            Error::MalformedPeerId
        );
        assert_eq!(
            TransferNonce::new(0).expect_err("zero transfer"),
            Error::ZeroNonce
        );
        assert_eq!(
            CandidateNonce::new(0).expect_err("zero candidate"),
            Error::ZeroNonce
        );
    }

    #[test]
    fn rejects_bad_signature_and_nonce_replay() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));
        let signed = signed_candidate(peer(1), transfer_nonce, candidate_nonce(9));

        assert_eq!(
            service
                .register_candidate(10, signed.clone(), &|_: &SignedCandidate| false)
                .expect_err("bad signature"),
            Error::InvalidSignature
        );

        service
            .register_candidate(10, signed.clone(), &|_: &SignedCandidate| true)
            .expect("first use");
        assert_eq!(
            service
                .register_candidate(10, signed, &|_: &SignedCandidate| true)
                .expect_err("replay"),
            Error::NonceReplay
        );
    }

    #[test]
    fn rejects_expired_session_and_candidate() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(transfer_nonce, 20, Quotas::default()));
        let signed = signed_candidate(peer(1), transfer_nonce, candidate_nonce(9));

        assert_eq!(
            service
                .register_candidate(20, signed, &|_: &SignedCandidate| true)
                .expect_err("expired session"),
            Error::ExpiredSession
        );

        let live_nonce = nonce(8);
        service.open_session(Session::new(live_nonce, 1_000, Quotas::default()));
        let expired_candidate = SignedCandidate::new(
            peer(1),
            live_nonce,
            candidate_nonce(10),
            Candidate::new(endpoint(50_001), CandidateTransport::Udp, 20),
            CandidateSignature::new(vec![1]).expect("signature"),
        );
        assert_eq!(
            service
                .register_candidate(20, expired_candidate, &|_: &SignedCandidate| true)
                .expect_err("expired candidate"),
            Error::ExpiredCandidate
        );

        let outliving_candidate = SignedCandidate::new(
            peer(1),
            live_nonce,
            candidate_nonce(11),
            Candidate::new(endpoint(50_002), CandidateTransport::Udp, 1_001),
            CandidateSignature::new(vec![1]).expect("signature"),
        );
        assert_eq!(
            service
                .register_candidate(20, outliving_candidate, &|_: &SignedCandidate| true)
                .expect_err("candidate outlives session"),
            Error::CandidateOutlivesSession
        );
    }

    #[test]
    fn enforces_peer_and_total_quotas() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(
            transfer_nonce,
            1_000,
            Quotas {
                max_candidates_per_peer: 1,
                max_total_candidates: 2,
                max_observations_per_peer: 4,
                max_total_observations: 32,
                max_attempts_per_peer: 8,
            },
        ));

        service
            .register_candidate(
                10,
                signed_candidate(peer(1), transfer_nonce, candidate_nonce(1)),
                &|_: &SignedCandidate| true,
            )
            .expect("first peer candidate");
        assert_eq!(
            service
                .register_candidate(
                    10,
                    signed_candidate(peer(1), transfer_nonce, candidate_nonce(2)),
                    &|_: &SignedCandidate| true,
                )
                .expect_err("peer quota"),
            Error::QuotaExceeded
        );

        service
            .register_candidate(
                10,
                signed_candidate(peer(2), transfer_nonce, candidate_nonce(3)),
                &|_: &SignedCandidate| true,
            )
            .expect("second peer candidate");
        assert_eq!(
            service
                .register_candidate(
                    10,
                    signed_candidate(peer(3), transfer_nonce, candidate_nonce(4)),
                    &|_: &SignedCandidate| true,
                )
                .expect_err("total quota"),
            Error::QuotaExceeded
        );
    }

    #[test]
    fn endpoint_observation_replay_and_quota_are_rejected() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        service.open_session(Session::new(
            transfer_nonce,
            1_000,
            Quotas {
                max_candidates_per_peer: 8,
                max_total_candidates: 32,
                max_observations_per_peer: 1,
                max_total_observations: 1,
                max_attempts_per_peer: 8,
            },
        ));

        service
            .record_endpoint_observation(10, peer_a, transfer_nonce, observation(21, 50_001))
            .expect("first observation");
        assert_eq!(
            service
                .record_endpoint_observation(10, peer_a, transfer_nonce, observation(21, 50_001))
                .expect_err("observation replay"),
            Error::NonceReplay
        );
        assert_eq!(
            service
                .record_endpoint_observation(10, peer_a, transfer_nonce, observation(22, 50_002))
                .expect_err("observation quota"),
            Error::QuotaExceeded
        );
    }

    #[test]
    fn grants_attempts_until_peer_budget_is_exhausted() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        service.open_session(Session::new(
            transfer_nonce,
            1_000,
            Quotas {
                max_candidates_per_peer: 8,
                max_total_candidates: 32,
                max_observations_per_peer: 4,
                max_total_observations: 32,
                max_attempts_per_peer: 1,
            },
        ));

        let grant = service
            .grant_attempt(10, peer_a, transfer_nonce)
            .expect("first attempt");
        assert_eq!(grant.used_attempts, 1);
        assert_eq!(grant.remaining_attempts, 0);
        assert_eq!(grant.expires_at_micros, 1_000);
        assert_eq!(
            service
                .grant_attempt(11, peer_a, transfer_nonce)
                .expect_err("attempt quota"),
            Error::QuotaExceeded
        );

        let exchange = service
            .exchange_for_peer(12, transfer_nonce, peer_a)
            .expect("exchange");
        assert_eq!(exchange.remaining_attempts(), 0);
    }

    #[test]
    fn conditional_relay_policy_rejects_local_destinations() {
        let cx = Cx::for_testing_with_io();
        let context = CapabilityContext {
            label: "conditional-relay".to_owned(),
            relay_capability: RelayCapability::Conditional,
            ipv6_capability: Ipv6Capability::Denied,
            max_candidate_ttl_micros: CANDIDATE_TTL_DEFAULT_MICROS,
        };

        assert!(block_on(
            context.check_relay_to(&cx, "relay.example.net:443")
        ));
        assert!(!block_on(context.check_relay_to(&cx, "localhost:443")));
        assert!(!block_on(context.check_relay_to(&cx, "127.0.0.1:443")));
        assert!(!block_on(context.check_relay_to(&cx, "10.0.0.7:443")));
    }

    #[test]
    fn conditional_ipv6_policy_requires_public_ipv6_endpoint() {
        let cx = Cx::for_testing_with_io();
        let context = CapabilityContext {
            label: "conditional-ipv6".to_owned(),
            relay_capability: RelayCapability::Denied,
            ipv6_capability: Ipv6Capability::Conditional,
            max_candidate_ttl_micros: CANDIDATE_TTL_DEFAULT_MICROS,
        };

        assert!(block_on(
            context.check_ipv6_direct_to(&cx, "[2606:4700:4700::1111]:443")
        ));
        assert!(!block_on(context.check_ipv6_direct_to(&cx, "[::1]:443")));
        assert!(!block_on(
            context.check_ipv6_direct_to(&cx, "198.51.100.10:443")
        ));
    }

    #[test]
    fn capability_context_bounds_transport_and_candidate_ttl() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let relay = peer(9);
        service.open_session(
            Session::new(transfer_nonce, 1_000, Quotas::default()).with_trusted_relays(&[relay]),
        );

        let no_relay =
            CapabilityContext::new("direct-only", 1_000, false, true).expect("capability context");
        let relay_candidate = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(9),
            Some(relay_authorization(relay, peer(1), transfer_nonce)),
        )
        .with_capability_context(no_relay);
        assert_eq!(
            service
                .register_candidate(
                    10,
                    relay_candidate,
                    &RelayVerifier {
                        relay_authorization_valid: true,
                    },
                )
                .expect_err("relay disallowed"),
            Error::CapabilityMismatch
        );

        let short_ttl =
            CapabilityContext::new("short-ttl", 5, true, true).expect("capability context");
        let long_ttl_candidate = signed_candidate(peer(1), transfer_nonce, candidate_nonce(10))
            .with_capability_context(short_ttl);
        assert_eq!(
            service
                .register_candidate(10, long_ttl_candidate, &|_: &SignedCandidate| true)
                .expect_err("ttl too long"),
            Error::CandidateTtlExceeded
        );
    }

    #[test]
    fn relay_candidates_require_authorization_and_trusted_relay_identity() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));

        let missing_auth =
            signed_relay_candidate(peer(1), transfer_nonce, candidate_nonce(9), None);
        assert_eq!(
            service
                .register_candidate(
                    10,
                    missing_auth,
                    &RelayVerifier {
                        relay_authorization_valid: true,
                    },
                )
                .expect_err("missing relay auth"),
            Error::RelayAuthorizationFailed
        );

        let untrusted_auth = relay_authorization(peer(9), peer(1), transfer_nonce);
        let untrusted = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(10),
            Some(untrusted_auth),
        );
        assert_eq!(
            service
                .register_candidate(
                    10,
                    untrusted,
                    &RelayVerifier {
                        relay_authorization_valid: true,
                    },
                )
                .expect_err("untrusted relay"),
            Error::RelayAuthorizationFailed
        );
    }

    #[test]
    fn accepts_relay_candidate_only_with_bound_relay_authorization() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let relay = peer(9);
        service.open_session(
            Session::new(transfer_nonce, 1_000, Quotas::default()).with_trusted_relays(&[relay]),
        );

        let signed = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(9),
            Some(relay_authorization(relay, peer(1), transfer_nonce)),
        );
        service
            .register_candidate(
                10,
                signed,
                &RelayVerifier {
                    relay_authorization_valid: true,
                },
            )
            .expect("relay accepted");

        assert_eq!(
            service
                .session(transfer_nonce)
                .expect("session")
                .candidates()
                .len(),
            1
        );
    }

    #[test]
    fn rejects_relay_authorization_confusion_and_bad_signature() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let relay = peer(9);
        service.open_session(
            Session::new(transfer_nonce, 1_000, Quotas::default()).with_trusted_relays(&[relay]),
        );

        let wrong_subject = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(9),
            Some(relay_authorization(relay, peer(2), transfer_nonce)),
        );
        assert_eq!(
            service
                .register_candidate(
                    10,
                    wrong_subject,
                    &RelayVerifier {
                        relay_authorization_valid: true,
                    },
                )
                .expect_err("wrong relay subject"),
            Error::RelayAuthorizationFailed
        );

        let bad_signature = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(10),
            Some(relay_authorization(relay, peer(1), transfer_nonce)),
        );
        assert_eq!(
            service
                .register_candidate(
                    10,
                    bad_signature,
                    &RelayVerifier {
                        relay_authorization_valid: false,
                    },
                )
                .expect_err("bad relay signature"),
            Error::RelayAuthorizationFailed
        );
    }

    #[test]
    fn relay_authorization_failures_keep_private_diagnostics() {
        let transfer_nonce = nonce(7);
        let relay = peer(9);
        let session =
            Session::new(transfer_nonce, 1_000, Quotas::default()).with_trusted_relays(&[relay]);

        let wrong_subject = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(9),
            Some(relay_authorization(relay, peer(2), transfer_nonce)),
        );
        let detail = validate_relay_candidate(
            10,
            &wrong_subject,
            &session,
            &RelayVerifier {
                relay_authorization_valid: true,
            },
        )
        .expect_err("wrong relay subject");

        assert_eq!(detail, RelayCandidateValidationError::BindingMismatch);
        assert_eq!(detail.public_error(), Error::RelayAuthorizationFailed);
        assert_eq!(
            Error::RelayAuthorizationFailed.to_string(),
            "authorization failed"
        );
    }

    #[test]
    fn candidate_rejection_events_are_redaction_safe_and_public() {
        let config = ServiceConfig::new(
            "rv-redacted",
            Quotas {
                max_candidates_per_peer: 1,
                max_total_candidates: 8,
                max_observations_per_peer: 4,
                max_total_observations: 32,
                max_attempts_per_peer: 8,
            },
        )
        .expect("config")
        .with_log_peer_ids(false);
        let mut service = Service::with_config(config);
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        service.open_session(Session::new(
            transfer_nonce,
            1_000,
            service.config().default_quotas(),
        ));

        service
            .register_candidate(
                10,
                signed_candidate(peer_a, transfer_nonce, candidate_nonce(9)),
                &|_: &SignedCandidate| true,
            )
            .expect("first candidate accepted");
        let error = service
            .register_candidate(
                11,
                signed_candidate(peer_a, transfer_nonce, candidate_nonce(10)),
                &|_: &SignedCandidate| true,
            )
            .expect_err("peer quota rejection");

        assert_eq!(error, Error::QuotaExceeded);
        assert_eq!(
            service
                .events()
                .iter()
                .map(ServiceEvent::kind)
                .collect::<Vec<_>>(),
            vec![
                ServiceEventKind::SessionOpened,
                ServiceEventKind::CandidateAccepted,
                ServiceEventKind::CandidateRejected,
            ]
        );
        let rejected = service.events().last().expect("rejection event");
        assert_eq!(rejected.transfer_nonce(), transfer_nonce);
        assert_eq!(rejected.at_micros(), 11);
        assert_eq!(rejected.peer_id(), None);
        assert_eq!(rejected.error(), Some(&Error::QuotaExceeded));
    }

    #[test]
    fn restart_snapshot_preserves_active_state_and_replay_sets() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));
        service
            .record_endpoint_observation(10, peer_a, transfer_nonce, observation(21, 50_001))
            .expect("observation");
        service
            .register_candidate(
                10,
                signed_candidate(peer(2), transfer_nonce, candidate_nonce(9)),
                &|_: &SignedCandidate| true,
            )
            .expect("candidate");

        let mut restored = Service::restore(service.snapshot());
        let exchange = restored
            .exchange_for_peer(11, transfer_nonce, peer_a)
            .expect("exchange after restart");
        assert_eq!(exchange.observed_public_endpoints()[0].port(), 50_001);
        assert_eq!(exchange.peer_candidates().len(), 1);
        assert!(restored.events().is_empty());
        assert_eq!(
            restored
                .record_endpoint_observation(12, peer_a, transfer_nonce, observation(21, 50_001))
                .expect_err("replay survives restart"),
            Error::NonceReplay
        );
    }

    #[test]
    fn service_config_controls_restart_retention_and_log_redaction() {
        assert_eq!(
            ServiceConfig::new(" ", Quotas::default()).expect_err("blank service id"),
            Error::EmptyServiceId
        );

        let config = ServiceConfig::new("rv-a", Quotas::default())
            .expect("config")
            .with_log_peer_ids(false)
            .with_retain_state_on_restart(false);
        let mut service = Service::with_config(config);
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));
        service
            .record_endpoint_observation(10, peer_a, transfer_nonce, observation(21, 50_001))
            .expect("observation");

        assert_eq!(service.config().service_id(), "rv-a");
        assert!(
            service
                .events()
                .iter()
                .all(|event| event.peer_id().is_none())
        );

        let restored = Service::restore(service.snapshot());
        assert!(restored.session(transfer_nonce).is_none());
        assert!(!restored.config().retain_state_on_restart());
    }
