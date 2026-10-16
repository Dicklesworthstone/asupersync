    use super::*;
    use crate::atp::manifest::*;
    use crate::atp::object::{ContentId, ObjectId};
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn test_object_id(content: &[u8]) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(content))
    }

    fn create_test_repair_group() -> (RepairGroupId, RepairGroup) {
        let object_id = test_object_id(&[1, 2, 3, 4]);
        let group_id = RepairGroupId::new(&object_id, 0, 1024);

        let repair_group = RepairGroup {
            group_id: group_id.clone(),
            object_id,
            source_block_number: 0,
            chunk_range: ChunkRange {
                start_chunk: 0,
                end_chunk: 1,
                start_offset: 0,
                end_offset: 1024,
            },
            source_symbols_k: 1000,
            k_prime: 1024,
            symbol_size: 1024,
            repair_layout: RepairLayout {
                total_repair_symbols: 200,
                overhead_ratio: 0.2,
                systematic_config: SystematicConfig {
                    systematic_rows: 1000,
                    sub_symbols: 1,
                    alignment: 8,
                },
                interleaving: InterleavingPattern {
                    block_size: 1,
                    depth: 1,
                    pattern_type: InterleavingType::None,
                },
            },
            hash_domain: HashDomain {
                domain_id: "test".to_string(),
                hash_algorithm: HashAlgorithm::Sha256,
                context: vec![],
            },
            transform_policy: None,
            auth_domain: AuthenticationDomain {
                domain_id: "test-auth".to_string(),
                required_proof_strength: ProofStrength::Basic,
                auth_algorithm: AuthenticationAlgorithm::HmacSha256,
                peer_identity_required: false,
                transfer_identity_binding: false,
                session_binding: true,
            },
            capability_policy: None,
            manifest_root: MerkleRoot::new([0u8; 32]),
        };

        (group_id, repair_group)
    }

    fn baseline_repair_peer_score() -> RepairPeerScore {
        RepairPeerScore {
            path_quality: 80,
            upload_budget_bytes: 256 * 1024,
            rarity: 16,
            decode_usefulness: 80,
            trust: 80,
            relay_cost: 8,
            churn_risk: 4,
        }
    }

    fn baseline_repair_peer_candidate(
        peer_id: impl Into<String>,
        repair_group: &RepairGroup,
        score: RepairPeerScore,
    ) -> RepairPeerCandidate {
        RepairPeerCandidate {
            peer_id: peer_id.into(),
            manifest_root: repair_group.manifest_root.clone(),
            repair_group_id: repair_group.group_id.clone(),
            source_symbols_k: repair_group.source_symbols_k,
            k_prime: repair_group.k_prime,
            transform_policy: repair_group.transform_policy.clone(),
            auth_domain: repair_group.auth_domain.clone(),
            auth_state: RepairPeerAuthState::Authenticated,
            freshness: RepairPeerFreshness::Current,
            symbol_state: RepairSymbolState::New,
            score,
        }
    }

    fn mismatched_transform_policy() -> TransformOrder {
        TransformOrder {
            transforms: vec![TransformType::Encryption],
            hash_point: HashPoint::Ciphertext,
            verification_boundary: VerificationBoundary {
                relay_verifiable: VerificationLevel::TransferIntegrity,
                mailbox_verifiable: VerificationLevel::TransferIntegrity,
                e2e_verification_required: true,
                privacy_level: PrivacyLevel::FullPrivacy,
            },
        }
    }

    fn build_receiver(
        repair_group: RepairGroup,
    ) -> (RepairGroupId, MerkleRoot, ObjectId, RepairReceiver) {
        let group_id = repair_group.group_id.clone();
        let manifest_root = repair_group.manifest_root.clone();
        let object_id = repair_group.object_id.clone();

        let mut repair_groups = BTreeMap::new();
        repair_groups.insert(group_id.clone(), repair_group);

        (
            group_id,
            manifest_root.clone(),
            object_id,
            RepairReceiver::new(manifest_root, repair_groups),
        )
    }

    fn source_symbol_for_group(group_id: &RepairGroupId) -> RaptorQSymbol {
        RaptorQSymbol {
            index: 0,
            esi: 500,
            size_bytes: 1024,
            content_hash: [7u8; 32],
            is_source: true,
            repair_group_id: Some(group_id.clone()),
            auth_tag: None,
        }
    }

    fn hmac_tag_for(
        receiver: &RepairReceiver,
        symbol: &RaptorQSymbol,
        repair_group: &RepairGroup,
        auth_key: &[u8],
        session_binding: Option<Vec<u8>>,
    ) -> [u8; 32] {
        let session = RepairSessionContext::new(
            repair_group.group_id.clone(),
            Duration::from_secs(3600),
            auth_key.to_vec(),
            session_binding,
        );
        receiver
            .compute_hmac_sha256_tag(symbol, repair_group, &session)
            .expect("test key should produce an HMAC tag")
    }

    fn start_receiver_session(
        receiver: &mut RepairReceiver,
        group_id: &RepairGroupId,
        auth_key: &[u8],
        session_binding: Option<Vec<u8>>,
    ) {
        receiver
            .start_session(
                group_id.clone(),
                Duration::from_secs(3600),
                auth_key.to_vec(),
                session_binding,
            )
            .expect("test repair group should accept a session");
    }

    #[test]
    fn test_select_repair_symbol_peer_scores_and_tie_breaks() {
        let (_, repair_group) = create_test_repair_group();
        let high_score = RepairPeerScore {
            trust: 95,
            decode_usefulness: 90,
            rarity: 20,
            path_quality: 90,
            upload_budget_bytes: 512 * 1024,
            relay_cost: 2,
            churn_risk: 1,
        };
        let low_score = RepairPeerScore {
            trust: 90,
            decode_usefulness: 90,
            rarity: 20,
            path_quality: 90,
            upload_budget_bytes: 512 * 1024,
            relay_cost: 2,
            churn_risk: 1,
        };
        let candidates = vec![
            baseline_repair_peer_candidate("seed-z", &repair_group, low_score),
            baseline_repair_peer_candidate("seed-b", &repair_group, high_score),
            baseline_repair_peer_candidate("seed-a", &repair_group, high_score),
        ];

        let selection = select_repair_symbol_peer(&repair_group, &candidates, 10);

        assert_eq!(selection.selected_peer_id.as_deref(), Some("seed-a"));
        assert_eq!(selection.selected_score, Some(high_score));
        assert!(selection.rejected_peers.is_empty());
    }

    #[test]
    fn test_select_repair_symbol_peer_rejects_cross_domain_candidates() {
        let (_, repair_group) = create_test_repair_group();
        let mut wrong_auth_domain = repair_group.auth_domain.clone();
        wrong_auth_domain.domain_id = "other-auth-domain".to_string();

        let mut candidates = Vec::new();
        candidates.push(baseline_repair_peer_candidate(
            "valid",
            &repair_group,
            baseline_repair_peer_score(),
        ));

        let mut unauthenticated = baseline_repair_peer_candidate(
            "unauthenticated",
            &repair_group,
            baseline_repair_peer_score(),
        );
        unauthenticated.auth_state = RepairPeerAuthState::Unauthenticated;
        candidates.push(unauthenticated);

        let mut stale =
            baseline_repair_peer_candidate("stale", &repair_group, baseline_repair_peer_score());
        stale.freshness = RepairPeerFreshness::Stale;
        candidates.push(stale);

        let mut no_budget = baseline_repair_peer_candidate(
            "no-budget",
            &repair_group,
            baseline_repair_peer_score(),
        );
        no_budget.score.upload_budget_bytes = 0;
        candidates.push(no_budget);

        let mut duplicate = baseline_repair_peer_candidate(
            "duplicate",
            &repair_group,
            baseline_repair_peer_score(),
        );
        duplicate.symbol_state = RepairSymbolState::AlreadySeen;
        candidates.push(duplicate);

        let mut wrong_manifest = baseline_repair_peer_candidate(
            "wrong-manifest",
            &repair_group,
            baseline_repair_peer_score(),
        );
        wrong_manifest.manifest_root = MerkleRoot::new([1u8; 32]);
        candidates.push(wrong_manifest);

        let mut wrong_group = baseline_repair_peer_candidate(
            "wrong-group",
            &repair_group,
            baseline_repair_peer_score(),
        );
        wrong_group.repair_group_id = RepairGroupId::new(&test_object_id(&[9, 9, 9, 9]), 9, 1024);
        candidates.push(wrong_group);

        let mut wrong_k =
            baseline_repair_peer_candidate("wrong-k", &repair_group, baseline_repair_peer_score());
        wrong_k.source_symbols_k -= 1;
        candidates.push(wrong_k);

        let mut wrong_k_prime = baseline_repair_peer_candidate(
            "wrong-k-prime",
            &repair_group,
            baseline_repair_peer_score(),
        );
        wrong_k_prime.k_prime += 1;
        candidates.push(wrong_k_prime);

        let mut wrong_transform = baseline_repair_peer_candidate(
            "wrong-transform",
            &repair_group,
            baseline_repair_peer_score(),
        );
        wrong_transform.transform_policy = Some(mismatched_transform_policy());
        candidates.push(wrong_transform);

        let mut wrong_auth = baseline_repair_peer_candidate(
            "wrong-auth",
            &repair_group,
            baseline_repair_peer_score(),
        );
        wrong_auth.auth_domain = wrong_auth_domain;
        candidates.push(wrong_auth);

        let mut low_decode = baseline_repair_peer_candidate(
            "low-decode",
            &repair_group,
            baseline_repair_peer_score(),
        );
        low_decode.score.decode_usefulness = 2;
        candidates.push(low_decode);

        let selection = select_repair_symbol_peer(&repair_group, &candidates, 10);

        assert_eq!(selection.selected_peer_id.as_deref(), Some("valid"));
        assert_eq!(
            selection.rejected_peers.get("unauthenticated"),
            Some(&RepairPeerRejection::Unauthenticated)
        );
        assert_eq!(
            selection.rejected_peers.get("stale"),
            Some(&RepairPeerRejection::StalePeer)
        );
        assert_eq!(
            selection.rejected_peers.get("no-budget"),
            Some(&RepairPeerRejection::UploadBudgetExhausted)
        );
        assert_eq!(
            selection.rejected_peers.get("duplicate"),
            Some(&RepairPeerRejection::DuplicateSymbol)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-manifest"),
            Some(&RepairPeerRejection::ManifestMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-group"),
            Some(&RepairPeerRejection::RepairGroupMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-k"),
            Some(&RepairPeerRejection::SourceSymbolsMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-k-prime"),
            Some(&RepairPeerRejection::KPrimeMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-transform"),
            Some(&RepairPeerRejection::TransformPolicyMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-auth"),
            Some(&RepairPeerRejection::AuthDomainMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("low-decode"),
            Some(&RepairPeerRejection::LowDecodeUsefulness)
        );
        assert_eq!(
            RepairPeerRejection::SourceSymbolsMismatch.as_str(),
            "source_symbols_mismatch"
        );
    }

    #[test]
    fn test_hmac_authenticated_symbol_is_accepted_and_recorded() {
        let (_, repair_group) = create_test_repair_group();
        let (group_id, manifest_root, object_id, mut receiver) =
            build_receiver(repair_group.clone());
        let auth_key = b"receiver-auth-key";
        let session_binding = Some(b"peer-a-session".to_vec());

        start_receiver_session(&mut receiver, &group_id, auth_key, session_binding.clone());
        let mut symbol = source_symbol_for_group(&group_id);
        symbol.auth_tag = Some(hmac_tag_for(
            &receiver,
            &symbol,
            &repair_group,
            auth_key,
            session_binding,
        ));

        let result =
            receiver.validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string());

        assert_eq!(result, Ok(()));
        assert!(
            receiver
                .sessions
                .get(&group_id)
                .and_then(|session| session.was_received(symbol.esi))
                .is_some()
        );
    }

    #[test]
    fn test_missing_auth_tag_is_structured_and_does_not_poison_replay() {
        let (_, repair_group) = create_test_repair_group();
        let (group_id, manifest_root, object_id, mut receiver) =
            build_receiver(repair_group.clone());
        let auth_key = b"receiver-auth-key";
        let session_binding = Some(b"peer-a-session".to_vec());

        start_receiver_session(&mut receiver, &group_id, auth_key, session_binding.clone());
        let mut symbol = source_symbol_for_group(&group_id);

        let error = receiver
            .validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string())
            .expect_err("missing tag must fail closed");

        match error {
            RepairReceiveError::AuthenticationFailed(reason) => {
                assert_eq!(reason, RepairAuthenticationFailure::MissingTag);
                assert_eq!(reason.code(), "missing_auth_tag");
                assert_eq!(reason.owner_bead(), None);
            }
            other => panic!("expected missing auth tag, got {other:?}"),
        }
        assert!(
            receiver
                .sessions
                .get(&group_id)
                .and_then(|session| session.was_received(symbol.esi))
                .is_none()
        );

        symbol.auth_tag = Some(hmac_tag_for(
            &receiver,
            &symbol,
            &repair_group,
            auth_key,
            session_binding,
        ));
        assert_eq!(
            receiver.validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string()),
            Ok(())
        );
    }

    #[test]
    fn test_wrong_key_and_cross_peer_hmac_are_rejected_without_replay_poisoning() {
        let (_, repair_group) = create_test_repair_group();
        let (group_id, manifest_root, object_id, mut receiver) =
            build_receiver(repair_group.clone());
        let auth_key = b"receiver-auth-key";
        let session_binding = Some(b"peer-a-session".to_vec());

        start_receiver_session(&mut receiver, &group_id, auth_key, session_binding.clone());
        let mut symbol = source_symbol_for_group(&group_id);
        symbol.auth_tag = Some(hmac_tag_for(
            &receiver,
            &symbol,
            &repair_group,
            b"other-peer-key",
            Some(b"peer-b-session".to_vec()),
        ));

        let error = receiver
            .validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string())
            .expect_err("wrong key and peer binding must fail closed");

        match error {
            RepairReceiveError::AuthenticationFailed(
                RepairAuthenticationFailure::VerificationFailed {
                    algorithm,
                    domain_id,
                },
            ) => {
                assert_eq!(algorithm, AuthenticationAlgorithm::HmacSha256);
                assert_eq!(domain_id, "test-auth");
            }
            other => panic!("expected HMAC verification failure, got {other:?}"),
        }
        assert!(
            receiver
                .sessions
                .get(&group_id)
                .and_then(|session| session.was_received(symbol.esi))
                .is_none()
        );

        symbol.auth_tag = Some(hmac_tag_for(
            &receiver,
            &symbol,
            &repair_group,
            auth_key,
            session_binding,
        ));
        assert_eq!(
            receiver.validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string()),
            Ok(())
        );
    }

    #[test]
    fn test_eddsa_and_x25519_are_typed_fail_closed_with_owner_bead() {
        for algorithm in [
            AuthenticationAlgorithm::EdDsa,
            AuthenticationAlgorithm::X25519Ecdh,
        ] {
            let (_, mut repair_group) = create_test_repair_group();
            repair_group.auth_domain.auth_algorithm = algorithm;
            repair_group.auth_domain.peer_identity_required = true;
            repair_group.auth_domain.transfer_identity_binding = true;

            let (group_id, manifest_root, object_id, mut receiver) =
                build_receiver(repair_group.clone());
            start_receiver_session(
                &mut receiver,
                &group_id,
                b"receiver-auth-key",
                Some(b"peer-a-session".to_vec()),
            );

            let mut symbol = source_symbol_for_group(&group_id);
            symbol.auth_tag = Some([9u8; 32]);

            let error = receiver
                .validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string())
                .expect_err("unsupported repair auth algorithms must fail closed");

            match error {
                RepairReceiveError::AuthenticationFailed(
                    RepairAuthenticationFailure::UnsupportedAlgorithm {
                        algorithm: observed_algorithm,
                        domain_id,
                        owner_bead,
                    },
                ) => {
                    assert_eq!(observed_algorithm, algorithm);
                    assert_eq!(domain_id, "test-auth");
                    assert_eq!(owner_bead, REPAIR_AUTH_UNSUPPORTED_OWNER_BEAD);
                    let reason = RepairAuthenticationFailure::UnsupportedAlgorithm {
                        algorithm: observed_algorithm,
                        domain_id,
                        owner_bead,
                    };
                    assert_eq!(reason.code(), "unsupported_repair_auth_algorithm");
                    assert_eq!(reason.owner_bead(), Some("asupersync-to7e65.6"));
                    assert!(reason.to_string().contains("fail-closed"));
                }
                other => panic!("expected typed unsupported algorithm, got {other:?}"),
            }
            assert!(
                receiver
                    .sessions
                    .get(&group_id)
                    .and_then(|session| session.was_received(symbol.esi))
                    .is_none()
            );
        }
    }

    #[test]
    fn test_session_creation() {
        let (group_id, repair_group) = create_test_repair_group();
        let manifest_root = repair_group.manifest_root.clone();

        let mut repair_groups = BTreeMap::new();
        repair_groups.insert(group_id.clone(), repair_group);

        let mut receiver = RepairReceiver::new(manifest_root, repair_groups);

        // Should succeed
        let result = receiver.start_session(
            group_id.clone(),
            Duration::from_secs(3600),
            vec![1, 2, 3, 4],
            Some(b"test_session".to_vec()),
        );
        assert!(result.is_ok());

        // Should fail for unknown group
        let unknown_group = RepairGroupId::new(&test_object_id(&[5, 6, 7, 8]), 1, 512);
        let result = receiver.start_session(
            unknown_group,
            Duration::from_secs(3600),
            vec![1, 2, 3, 4],
            None,
        );
        assert!(matches!(
            result,
            Err(RepairReceiveError::UnknownRepairGroup(_))
        ));
    }

    #[test]
    fn test_symbol_parameter_validation() {
        let (group_id, repair_group) = create_test_repair_group();
        let manifest_root = repair_group.manifest_root.clone();

        let mut repair_groups = BTreeMap::new();
        repair_groups.insert(group_id.clone(), repair_group);

        let receiver = RepairReceiver::new(manifest_root.clone(), repair_groups);

        // Valid symbol
        let valid_symbol = RaptorQSymbol {
            index: 0,
            esi: 500,
            size_bytes: 1024,
            content_hash: [0u8; 32],
            is_source: true,
            repair_group_id: Some(group_id.clone()),
            auth_tag: Some([0u8; 32]),
        };

        // Should pass parameter validation (ignoring session/auth for this test)
        let result =
            receiver.validate_symbol_parameters(&valid_symbol, &receiver.repair_groups[&group_id]);
        assert!(result.is_ok());

        // Invalid ESI (too high)
        let invalid_esi_symbol = RaptorQSymbol {
            esi: 2000, // > k + total_repair_symbols
            ..valid_symbol.clone()
        };

        let result = receiver
            .validate_symbol_parameters(&invalid_esi_symbol, &receiver.repair_groups[&group_id]);
        assert!(
            matches!(result, Err(RepairReceiveError::ParameterMismatch { field, .. }) if field == "esi") // ubs:ignore - error field name comparison
        );

        // Invalid size
        let invalid_size_symbol = RaptorQSymbol {
            size_bytes: 512, // Should be 1024
            ..valid_symbol.clone()
        };

        let result = receiver
            .validate_symbol_parameters(&invalid_size_symbol, &receiver.repair_groups[&group_id]);
        assert!(
            matches!(result, Err(RepairReceiveError::ParameterMismatch { field, .. }) if field == "size_bytes") // ubs:ignore
        );
    }

    #[test]
    fn test_replay_detection() {
        let (group_id, _repair_group) = create_test_repair_group();

        let mut session = RepairSessionContext::new(
            group_id.clone(),
            Duration::from_secs(3600),
            vec![1, 2, 3, 4],
            None,
        );

        // First symbol should be accepted
        assert!(session.mark_received(100));

        // Same ESI should be detected as replay
        assert!(!session.mark_received(100));
        assert!(session.was_received(100).is_some());

        // Different ESI should be accepted
        assert!(session.mark_received(101));
    }

    #[test]
    fn test_session_expiry() {
        let (group_id, _) = create_test_repair_group();

        // Create session with very short duration
        let session =
            RepairSessionContext::new(group_id, Duration::from_millis(1), vec![1, 2, 3, 4], None);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(10));

        assert!(session.is_expired());
    }
