    use super::*;

    fn agreement(max_donor_count: u32) -> BondingAgreement {
        BondingAgreement {
            protocol_version: BONDING_HANDSHAKE_VERSION,
            supported_transports: BTreeSet::from([BondTransport::DirectIp]),
            assignment_mode: BondingAssignmentMode::DynamicWindows,
            resume_supported: true,
            auth_required: true,
            max_donor_count,
        }
    }

    fn endpoint() -> SocketAddr {
        "127.0.0.1:8472".parse().expect("test endpoint")
    }

    #[test]
    fn handshake_degrades_to_static_residue_when_dynamic_windows_are_not_common() {
        let receiver = BondingHandshake::v1_static(
            [BondTransport::DirectIp, BondTransport::Tailscale],
            16,
            true,
        )
        .with_dynamic_windows(true)
        .with_resume(true)
        .with_extension_capability("phase-e.dynamic-window-v1");
        let donor = BondingHandshake::v1_static([BondTransport::Tailscale], 8, false)
            .with_extension_capability("donor-private-future");

        let agreement = receiver.negotiate(&donor).expect("compatible");

        assert_eq!(agreement.protocol_version, BONDING_HANDSHAKE_VERSION);
        assert_eq!(
            agreement.assignment_mode,
            BondingAssignmentMode::StaticResidue
        );
        assert!(!agreement.resume_supported);
        assert!(agreement.auth_required);
        assert_eq!(agreement.max_donor_count, 8);
        assert_eq!(
            agreement.supported_transports,
            BTreeSet::from([BondTransport::Tailscale])
        );
        assert!(agreement.supports_transport(BondTransport::Tailscale));
        assert!(!agreement.supports_transport(BondTransport::DirectIp));
    }

    #[test]
    fn handshake_selects_dynamic_windows_and_resume_when_both_peers_support_them() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_dynamic_windows(true)
            .with_resume(true);
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 12, true)
            .with_dynamic_windows(true)
            .with_resume(true);

        let agreement = receiver.negotiate(&donor).expect("compatible");

        assert_eq!(
            agreement.assignment_mode,
            BondingAssignmentMode::DynamicWindows
        );
        assert!(agreement.resume_supported);
        assert!(agreement.auth_required);
        assert_eq!(agreement.max_donor_count, 12);
        assert!(agreement.supports_transport(BondTransport::DirectIp));
    }

    #[test]
    fn handshake_ignores_unknown_extensions_but_refuses_no_common_transport() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_extension_capability("unknown.receiver.future");
        let donor = BondingHandshake::v1_static([BondTransport::Ssh], 16, true)
            .with_extension_capability("unknown.donor.future");

        let err = receiver.negotiate(&donor).expect_err("no common transport");
        assert_eq!(err, BondingHandshakeError::NoCommonTransport);
    }

    #[test]
    fn handshake_refuses_incompatible_versions_with_typed_error() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_protocol_range(2, 2);
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true);

        let err = receiver.negotiate(&donor).expect_err("version mismatch");

        assert_eq!(
            err,
            BondingHandshakeError::IncompatibleProtocolVersion {
                local_min: 2,
                local_max: 2,
                peer_min: BONDING_HANDSHAKE_VERSION,
                peer_max: BONDING_HANDSHAKE_VERSION,
            }
        );
        assert!(err.to_string().contains("incompatible"));
    }

    #[test]
    fn handshake_refuses_invalid_offer_shapes() {
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true);
        let version_zero = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_protocol_range(0, BONDING_HANDSHAKE_VERSION);
        assert_eq!(
            version_zero.negotiate(&donor),
            Err(BondingHandshakeError::InvalidProtocolRange {
                min: 0,
                max: BONDING_HANDSHAKE_VERSION,
            })
        );

        let zero_donors = BondingHandshake::v1_static([BondTransport::DirectIp], 0, true);
        assert_eq!(
            zero_donors.negotiate(&donor),
            Err(BondingHandshakeError::InvalidDonorCount { donor_count: 0 })
        );

        let too_many_donors =
            BondingHandshake::v1_static([BondTransport::DirectIp], MAX_BONDING_DONORS + 1, true);
        assert_eq!(
            too_many_donors.negotiate(&donor),
            Err(BondingHandshakeError::TooManyDonors {
                donor_count: MAX_BONDING_DONORS + 1,
                max: MAX_BONDING_DONORS,
            })
        );
    }

    #[test]
    fn control_registry_accepts_every_unique_donor_connection() {
        let mut registry = BondingControlRegistry::new(3).expect("registry");

        registry
            .enroll_donor(2, agreement(3))
            .expect("donor 2 enrolled");
        registry
            .enroll_donor(0, agreement(3))
            .expect("donor 0 enrolled");

        assert_eq!(registry.expected_donor_count(), 3);
        assert_eq!(registry.enrolled_count(), 2);
        assert!(!registry.is_complete());
        assert!(registry.agreement_for(1).is_none());
        assert_eq!(registry.enrolled_donor_indices(), vec![0, 2]);
        assert_eq!(registry.missing_donor_indices(), vec![1]);

        registry
            .enroll_donor(1, agreement(3))
            .expect("donor 1 enrolled");

        assert!(registry.is_complete());
        assert!(registry.agreement_for(1).is_some());
        assert_eq!(registry.enrolled_donor_indices(), vec![0, 1, 2]);
        assert_eq!(registry.missing_donor_indices(), Vec::<u32>::new());
    }

    #[test]
    fn control_registry_fails_closed_for_invalid_donor_connections() {
        assert_eq!(
            BondingControlRegistry::new(0),
            Err(BondingHandshakeError::InvalidDonorCount { donor_count: 0 })
        );

        let mut registry = BondingControlRegistry::new(2).expect("registry");
        registry
            .enroll_donor(0, agreement(2))
            .expect("donor 0 enrolled");

        assert_eq!(
            registry.enroll_donor(0, agreement(2)),
            Err(BondingHandshakeError::DuplicateDonorControl { donor_index: 0 })
        );
        assert_eq!(
            registry.enroll_donor(2, agreement(2)),
            Err(BondingHandshakeError::DonorIndexOutOfRange {
                donor_index: 2,
                donor_count: 2,
            })
        );
        assert_eq!(
            registry.enroll_donor(1, agreement(1)),
            Err(BondingHandshakeError::AgreementDonorCountTooSmall {
                donor_index: 1,
                expected_donor_count: 2,
                agreement_max_donor_count: 1,
            })
        );
    }

    #[test]
    fn receiver_control_plane_assigns_distinct_indices_and_one_udp_endpoint() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 3, true);
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 3, false);
        let auth = BondAuthKeyRef::ControlPlane("bond-key-7".to_string());
        let mut control =
            BondingReceiverControlPlane::new(receiver, 3, vec![endpoint()], Some(auth.clone()))
                .expect("control plane");
        let mut admission_traces = Vec::new();

        for expected_index in 0..3 {
            let enrollment = control.enroll_next_donor(&donor).expect("enrolled");
            let trace = enrollment.admission_trace();

            assert_eq!(enrollment.donor_index, expected_index);
            assert_eq!(enrollment.assignment.donor_index, expected_index);
            assert_eq!(enrollment.assignment.donor_count, 3);
            assert_eq!(
                enrollment.assignment.receiver_udp_endpoints,
                vec![endpoint()]
            );
            assert_eq!(enrollment.assignment.auth_key_ref, Some(auth.clone()));
            assert!(enrollment.assignment.owns_esi(expected_index));
            assert_eq!(enrollment.agreement.max_donor_count, 3);
            assert!(
                enrollment
                    .agreement
                    .supports_transport(BondTransport::DirectIp)
            );
            assert_eq!(trace.schema_version, BONDING_DONOR_ADMISSION_TRACE_SCHEMA);
            assert_eq!(trace.event, "bonding_donor_admitted");
            assert_eq!(trace.donor_index, expected_index);
            assert_eq!(trace.donor_count, 3);
            assert_eq!(trace.protocol_version, BONDING_HANDSHAKE_VERSION);
            assert_eq!(trace.receiver_udp_endpoints, vec![endpoint()]);
            let trace_json = serde_json::to_value(&trace).expect("trace serializes");
            assert_eq!(
                trace_json["schema_version"].as_str(),
                Some(BONDING_DONOR_ADMISSION_TRACE_SCHEMA)
            );
            assert_eq!(trace_json["event"].as_str(), Some("bonding_donor_admitted"));
            assert_eq!(
                trace_json["donor_index"].as_u64(),
                Some(expected_index as u64)
            );
            admission_traces.push(trace);
        }

        assert!(control.is_complete());
        assert_eq!(control.registry().enrolled_donor_indices(), vec![0, 1, 2]);
        assert_eq!(
            admission_traces
                .iter()
                .map(|trace| trace.donor_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(
            control.enroll_next_donor(&donor),
            Err(BondingHandshakeError::TooManyDonorControls {
                expected_donor_count: 3,
            })
        );
    }

    #[test]
    fn receiver_control_plane_fails_closed_for_invalid_admission_shape() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 2, false);

        assert_eq!(
            BondingReceiverControlPlane::new(receiver.clone(), 3, vec![endpoint()], None),
            Err(BondingHandshakeError::ReceiverDonorCountTooSmall {
                expected_donor_count: 3,
                receiver_max_donor_count: 2,
            })
        );
        assert_eq!(
            BondingReceiverControlPlane::new(receiver.clone(), 2, Vec::new(), None),
            Err(BondingHandshakeError::NoReceiverUdpEndpoint)
        );

        let auth_required = BondingHandshake::v1_static([BondTransport::DirectIp], 2, true);
        assert_eq!(
            BondingReceiverControlPlane::new(auth_required, 2, vec![endpoint()], None),
            Err(BondingHandshakeError::MissingRequiredAuthKeyRef)
        );
    }

    #[test]
    fn receiver_control_plane_failed_donor_offer_does_not_consume_slot() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 3, false);
        let mut control = BondingReceiverControlPlane::new(receiver, 3, vec![endpoint()], None)
            .expect("control plane");

        let donor_too_small = BondingHandshake::v1_static([BondTransport::DirectIp], 2, false);
        assert_eq!(
            control.enroll_next_donor(&donor_too_small),
            Err(BondingHandshakeError::AgreementDonorCountTooSmall {
                donor_index: 0,
                expected_donor_count: 3,
                agreement_max_donor_count: 2,
            })
        );
        assert_eq!(control.registry().enrolled_count(), 0);
        assert_eq!(control.registry().missing_donor_indices(), vec![0, 1, 2]);
        assert!(!control.is_complete());

        let compatible_donor = BondingHandshake::v1_static([BondTransport::DirectIp], 3, false);
        let enrollment = control
            .enroll_next_donor(&compatible_donor)
            .expect("compatible donor should still receive first slot");
        assert_eq!(enrollment.donor_index, 0);
        assert_eq!(enrollment.assignment.donor_index, 0);
        assert_eq!(control.registry().enrolled_donor_indices(), vec![0]);
    }
