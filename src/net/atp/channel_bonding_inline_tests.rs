    use super::*;
    use crate::security::{AuthenticatedSymbol, SecurityContext};
    use crate::types::{Symbol, SymbolId, SymbolKind};

    fn sample_proof() -> BondDonorByteProof {
        BondDonorByteProof::from_entries(vec![
            BondDonorProofEntry::from_bytes(0, "alpha.txt", b"alpha"),
            BondDonorProofEntry::from_bytes(1, "dir/beta.txt", b"beta"),
        ])
        .expect("valid proof")
    }

    #[test]
    fn donor_esi_partition_covers_without_overlap() {
        for donor_count in [1, 2, 3, 5, 8] {
            let limit = 257u32;
            let mut owners = vec![0u32; limit as usize];
            for donor_index in 0..donor_count {
                for esi in 0..limit {
                    if owns_esi(donor_index, donor_count, esi) {
                        owners[esi as usize] += 1;
                    }
                }
                let stream = DonorEsiStream::new(donor_index, donor_count).expect("valid stream");
                for (seq, esi) in stream.take(32).enumerate() {
                    assert_eq!(
                        esi,
                        esi_for_donor(donor_index, donor_count, seq as u32).expect("esi")
                    );
                    assert!(owns_esi(donor_index, donor_count, esi));
                }
            }
            assert!(owners.iter().all(|owner_count| *owner_count == 1));
        }
    }

    #[test]
    fn n_one_owns_every_esi() {
        for esi in 0..512 {
            assert!(owns_esi(0, 1, esi));
            assert_eq!(esi_for_donor(0, 1, esi).expect("esi"), esi);
        }
    }

    #[test]
    fn donor_esi_partition_rejects_invalid_or_overflowing_inputs() {
        assert_eq!(
            DonorEsiStream::new(0, 0).unwrap_err(),
            ChannelBondingError::InvalidDonorCount { donor_count: 0 }
        );
        assert_eq!(
            esi_for_donor(2, 2, 0).unwrap_err(),
            ChannelBondingError::InvalidDonorIndex {
                donor_index: 2,
                donor_count: 2,
            }
        );
        assert_eq!(
            esi_for_donor(u32::MAX - 1, u32::MAX, 1).unwrap_err(),
            ChannelBondingError::EsiOverflow
        );
    }

    #[test]
    fn donor_esi_stream_yields_final_u32_esi_once() {
        let mut stream = DonorEsiStream::new(0, 1).expect("single donor stream");
        stream.next_seq = Some(u32::MAX);

        assert_eq!(stream.next(), Some(u32::MAX));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn descriptor_accepts_matching_donor_proof() {
        let proof = sample_proof();
        let descriptor = BondTransferDescriptor::from_donor_proof(
            "sample",
            true,
            1200,
            256 * 1024,
            Some("env:ATP_BOND_AUTH_KEY".to_string()),
            proof.entries.clone(),
        )
        .expect("descriptor");

        descriptor
            .verify_donor_byte_match(&proof)
            .expect("matching donor proof accepted");
    }

    #[test]
    fn descriptor_rejects_content_mismatch_fail_closed() {
        let proof = sample_proof();
        let descriptor = BondTransferDescriptor::from_donor_proof(
            "sample",
            true,
            1200,
            256 * 1024,
            None,
            proof.entries.clone(),
        )
        .expect("descriptor");
        let tampered = BondDonorByteProof::from_entries(vec![
            BondDonorProofEntry::from_bytes(0, "alpha.txt", b"alpha"),
            BondDonorProofEntry::from_bytes(1, "dir/beta.txt", b"tampered"),
        ])
        .expect("tampered proof is internally consistent");

        let err = descriptor
            .verify_donor_byte_match(&tampered)
            .expect_err("mismatch rejected");
        assert!(matches!(
            err,
            ChannelBondingError::TransferIdMismatch { .. }
                | ChannelBondingError::MerkleRootMismatch { .. }
                | ChannelBondingError::EntryMismatch { .. }
        ));
    }

    #[test]
    fn descriptor_rejects_same_sha_with_wrong_content_id_merkle() {
        let proof = sample_proof();
        let descriptor = BondTransferDescriptor::from_donor_proof(
            "sample",
            true,
            1200,
            256 * 1024,
            None,
            proof.entries.clone(),
        )
        .expect("descriptor");
        let mut forged_entries = proof.entries.clone();
        forged_entries[0].content_id_hex = "11".repeat(32);
        let forged = BondDonorByteProof {
            transfer_id: proof.transfer_id,
            total_bytes: proof.total_bytes,
            merkle_root_hex: proof.merkle_root_hex,
            entries: forged_entries,
        };

        let err = descriptor
            .verify_donor_byte_match(&forged)
            .expect_err("wrong content id rejected");
        assert!(matches!(
            err,
            ChannelBondingError::MerkleRootMismatch { .. }
        ));
    }

    #[test]
    fn entry_object_id_is_deterministic_and_entry_specific() {
        let transfer = "0123456789abcdef0123456789abcdef";
        let first = entry_object_id(transfer, 0);
        assert_eq!(first, entry_object_id(transfer, 0));
        assert_ne!(first, entry_object_id(transfer, 1));
        assert_ne!(first, entry_object_id("different", 0));
    }

    #[test]
    fn assignment_windows_restrict_static_residue() {
        let assignment = DonorAssignment {
            donor_index: 1,
            donor_count: 3,
            esi_windows: Some(vec![EsiWindow::new(0, 10)]),
            receiver_udp_endpoints: Vec::new(),
            auth_key_ref: Some("keyfile:/run/asupersync/bond.key".to_string()),
        };
        assignment.validate().expect("valid assignment");
        assert!(assignment.owns_esi(1));
        assert!(assignment.owns_esi(4));
        assert!(!assignment.owns_esi(10));
        assert!(!assignment.owns_esi(2));
    }

    #[test]
    fn assignment_windows_are_exact_static_residue_intersections() {
        let windows = vec![EsiWindow::new(2, 11), EsiWindow::new(15, 22)];
        for donor_count in [2, 3, 5, 8] {
            for donor_index in 0..donor_count {
                let assignment = DonorAssignment {
                    donor_index,
                    donor_count,
                    esi_windows: Some(windows.clone()),
                    receiver_udp_endpoints: Vec::new(),
                    auth_key_ref: None,
                };
                assignment.validate().expect("valid assignment");

                for esi in 0..25 {
                    let expected = owns_esi(donor_index, donor_count, esi)
                        && windows.iter().any(|window| window.contains(esi));
                    assert_eq!(
                        assignment.owns_esi(esi),
                        expected,
                        "donor {donor_index}/{donor_count} ownership mismatch for esi {esi}"
                    );
                }
            }
        }
    }

    #[test]
    fn assignment_validation_rejects_invalid_window_and_donor_ceiling() {
        let invalid_window = DonorAssignment {
            donor_index: 0,
            donor_count: 1,
            esi_windows: Some(vec![EsiWindow::new(5, 5)]),
            receiver_udp_endpoints: Vec::new(),
            auth_key_ref: None,
        };
        assert_eq!(
            invalid_window.validate().unwrap_err(),
            ChannelBondingError::InvalidEsiWindow {
                start_inclusive: 5,
                end_exclusive: 5,
            }
        );

        let too_many_donors = DonorAssignment {
            donor_index: 0,
            donor_count: MAX_STATIC_RESIDUE_DONORS + 1,
            esi_windows: None,
            receiver_udp_endpoints: Vec::new(),
            auth_key_ref: None,
        };
        assert_eq!(
            too_many_donors.validate().unwrap_err(),
            ChannelBondingError::TooManyDonors {
                donor_count: MAX_STATIC_RESIDUE_DONORS + 1,
                max: MAX_STATIC_RESIDUE_DONORS,
            }
        );
    }

    #[test]
    fn handshake_degrades_to_static_residue_when_dynamic_missing() {
        let receiver = BondingHandshake::v1_static(
            [BondTransport::DirectIp, BondTransport::Tailscale],
            16,
            true,
        )
        .with_dynamic_windows(true)
        .with_resume(true)
        .with_extension_capability("phase-e.dynamic-window-v1");
        let donor = BondingHandshake::v1_static([BondTransport::Tailscale], 8, false);

        let agreement = receiver.negotiate(&donor).expect("compatible");
        assert_eq!(agreement.protocol_version, BONDING_PROTOCOL_VERSION);
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
    fn handshake_selects_dynamic_windows_when_both_peers_support_them() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_dynamic_windows(true)
            .with_resume(true)
            .with_extension_capability("receiver-private-future");
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 12, true)
            .with_dynamic_windows(true)
            .with_resume(true)
            .with_extension_capability("donor-private-future");

        let agreement = receiver.negotiate(&donor).expect("compatible");

        assert_eq!(
            agreement.assignment_mode,
            BondingAssignmentMode::DynamicWindows
        );
        assert!(agreement.resume_supported);
        assert_eq!(agreement.max_donor_count, 12);
        assert!(agreement.supports_transport(BondTransport::DirectIp));
    }

    #[test]
    fn handshake_ignores_unknown_extensions_but_refuses_no_common_transport() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_extension_capability("unknown.receiver.future");
        let donor = BondingHandshake::v1_static([BondTransport::Tailscale], 16, true)
            .with_extension_capability("unknown.donor.future");

        let err = receiver.negotiate(&donor).expect_err("no common transport");
        assert_eq!(err, ChannelBondingError::NoCommonTransport);
    }

    #[test]
    fn handshake_refuses_incompatible_versions() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_protocol_range(2, 2);
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true);

        let err = receiver.negotiate(&donor).expect_err("version mismatch");
        assert!(matches!(
            err,
            ChannelBondingError::IncompatibleProtocolVersion { .. }
        ));
    }

    #[test]
    fn handshake_refuses_invalid_version_zero_and_donor_ceiling() {
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true);
        let version_zero = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_protocol_range(0, BONDING_PROTOCOL_VERSION);
        let err = version_zero.negotiate(&donor).expect_err("version zero");
        assert_eq!(
            err,
            ChannelBondingError::InvalidProtocolRange {
                min: 0,
                max: BONDING_PROTOCOL_VERSION,
            }
        );

        let zero_donors = BondingHandshake::v1_static([BondTransport::DirectIp], 0, true);
        let err = zero_donors.negotiate(&donor).expect_err("zero donors");
        assert_eq!(
            err,
            ChannelBondingError::InvalidDonorCount { donor_count: 0 }
        );

        let too_many_donors = BondingHandshake::v1_static(
            [BondTransport::DirectIp],
            MAX_STATIC_RESIDUE_DONORS + 1,
            true,
        );
        let err = too_many_donors
            .negotiate(&donor)
            .expect_err("donor ceiling exceeds phase-a cap");
        assert_eq!(
            err,
            ChannelBondingError::TooManyDonors {
                donor_count: MAX_STATIC_RESIDUE_DONORS + 1,
                max: MAX_STATIC_RESIDUE_DONORS,
            }
        );
    }

    #[test]
    fn security_model_rejects_argv_and_disabled_fail_closed_layers() {
        let mut model = BondingSecurityModel {
            auth_key: BondAuthKeyRef {
                key_id: "bond-key-1".to_string(),
                control_plane: BondAuthControlPlane::Ssh,
                location: BondAuthKeyLocation::EnvVar("ATP_BOND_AUTH_KEY".to_string()),
            },
            auth_before_decode: true,
            fail_closed_on_merkle_mismatch: true,
        };
        model.validate().expect("valid security model");

        model.auth_key.location = BondAuthKeyLocation::Argv("--bond-key=secret".to_string());
        assert_eq!(
            model.validate().unwrap_err(),
            ChannelBondingError::InsecureAuthKeyDelivery
        );

        model.auth_key.location = BondAuthKeyLocation::EnvVar("ATP_BOND_AUTH_KEY".to_string());
        model.auth_before_decode = false;
        assert_eq!(
            model.validate().unwrap_err(),
            ChannelBondingError::AuthBeforeDecodeDisabled
        );

        model.auth_before_decode = true;
        model.fail_closed_on_merkle_mismatch = false;
        assert_eq!(
            model.validate().unwrap_err(),
            ChannelBondingError::MerkleFailClosedDisabled
        );
    }

    #[test]
    fn wrong_donor_auth_key_rejects_symbol_before_decode() {
        let signer = SecurityContext::for_testing(0xA11CE);
        let verifier = SecurityContext::for_testing(0xB0B);
        let symbol = Symbol::new(
            SymbolId::new_for_test(7, 0, 3),
            b"bonded repair".to_vec(),
            SymbolKind::Repair,
        );
        let signed = signer.sign_symbol(&symbol);
        let tag = *signed.tag();
        let mut received = AuthenticatedSymbol::from_parts(signed.into_symbol(), tag);

        let err = verifier
            .verify_authenticated_symbol(&mut received)
            .expect_err("wrong shared donor key must reject symbol");
        assert!(err.is_invalid_tag());
        assert!(!received.is_verified());
    }
