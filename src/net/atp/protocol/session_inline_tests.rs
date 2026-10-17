    use super::*;

    fn peers() -> (PeerId, PeerId) {
        (PeerId::from_label("alice"), PeerId::from_label("bob"))
    }

    fn relay_peer() -> PeerId {
        PeerId::from_label("relay-a")
    }

    fn alternate_relay_peer() -> PeerId {
        PeerId::from_label("relay-b")
    }

    #[test]
    fn peer_id_from_public_key_is_canonical_and_rejects_bad_material() {
        let public_key = b"ed25519:alice-device-public-key";
        let first = PeerId::from_public_key(public_key).unwrap();
        let second = PeerId::from_public_key(public_key).unwrap();

        assert_eq!(first, second);
        assert_ne!(first, PeerId::from_label("ed25519:alice-device-public-key"));
        assert_eq!(
            PeerId::from_public_key(&[]),
            Err(PeerIdentityError::EmptyPublicKey)
        );
        assert_eq!(
            PeerId::from_public_key(&[0; 32]),
            Err(PeerIdentityError::AllZeroPublicKey)
        );
    }

    fn manifest_root(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn grant_for(
        issuer: PeerId,
        subject: PeerId,
        actions: &[CapabilityAction],
        context: SessionContextKind,
    ) -> CapabilityGrant {
        CapabilityGrant::new(
            CapabilityGrantId::from_label("grant"),
            issuer,
            subject,
            actions.iter().copied(),
            if matches!(context, SessionContextKind::Relay) {
                CapabilityScope::for_context(context).with_relay_peer(relay_peer())
            } else {
                CapabilityScope::for_context(context)
            },
        )
    }

    fn hello_for(context: SessionContextKind) -> ClientHello {
        let (alice, bob) = peers();
        let hello = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed(context.code()),
            context,
            SessionTraceId::new(42),
        )
        .with_features(&[
            AtpFeature::EncryptionPolicy,
            AtpFeature::ProofBundles,
            AtpFeature::Resume,
            AtpFeature::Relay,
            AtpFeature::Mailbox,
            AtpFeature::Swarm,
            AtpFeature::Repair,
            AtpFeature::Datagrams,
        ])
        .with_requested_actions(&[CapabilityAction::Write])
        .with_grants(vec![grant_for(
            bob,
            alice,
            &[CapabilityAction::Write],
            context,
        )]);
        if matches!(context, SessionContextKind::Relay) {
            hello.with_relay_peer(relay_peer())
        } else {
            hello
        }
    }

    fn policy_for(context: SessionContextKind) -> SessionPolicy {
        let (_alice, bob) = peers();
        let policy = SessionPolicy::new(bob, 100)
            .with_supported_features(&[
                AtpFeature::EncryptionPolicy,
                AtpFeature::ProofBundles,
                AtpFeature::Resume,
                AtpFeature::Relay,
                AtpFeature::Mailbox,
                AtpFeature::Swarm,
                AtpFeature::Repair,
                AtpFeature::Datagrams,
            ])
            .with_required_features(&[AtpFeature::EncryptionPolicy])
            .with_required_actions(&[CapabilityAction::Write])
            .with_accepted_contexts(&[context]);
        if matches!(context, SessionContextKind::Relay) {
            policy.with_trusted_relays(&[relay_peer()])
        } else {
            policy
        }
    }

    #[test]
    fn received_hello_roundtrips_full_schema_and_known_downgrade_reasons() {
        for context in SessionContextKind::ALL {
            let mut hello = hello_for(context)
                .with_features(&AtpFeature::ALL)
                .with_manifest_root([5; 32])
                .with_path_id(PathCandidateId::new(7));
            let grant = &mut hello.grants[0];
            grant.expires_at_micros = Some(900);
            grant.delegation_depth = 3;
            grant.invite_scope = true;
            grant
                .scope
                .allowed_path_ids
                .extend([PathCandidateId::new(7), PathCandidateId::new(9)]);
            grant
                .scope
                .allowed_path_prefixes
                .extend(["/a".to_owned(), "/z/é".to_owned()]);
            grant.scope.allowed_relay_peers.insert(relay_peer());
            grant
                .scope
                .allowed_manifest_roots
                .extend([[1; 32], [5; 32]]);
            let encoded = hello.to_frame().unwrap();
            let decoded = ClientHello::from_frame(&encoded).unwrap();
            assert_eq!(decoded, hello);
            assert_eq!(decoded.to_frame().unwrap(), encoded);
            let mut supported = vec![AtpFeature::EncryptionPolicy];
            supported.extend(context.required_feature());
            let mut policy = policy_for(context).with_supported_features(&supported);
            let mut server = SessionNegotiator::server(hello.responder);
            let (ack, encoded, _) = server.accept_client_hello(&decoded, &mut policy).unwrap();
            assert_eq!(
                ack.downgrade_warnings.len(),
                AtpFeature::ALL.len() - supported.len()
            );
            let decoded = ServerHello::from_frame(&encoded).unwrap();
            assert_eq!(decoded, ack);
            assert_eq!(decoded.to_frame().unwrap(), encoded);
        }
    }

    #[test]
    fn received_hellos_refuse_every_truncation_wrong_type_size_and_trailing_byte() {
        let hello = hello_for(SessionContextKind::Direct);
        let mut policy = policy_for(SessionContextKind::Direct);
        let (_, ack, _) = SessionNegotiator::server(hello.responder)
            .accept_client_hello(&hello, &mut policy)
            .unwrap();
        let client = hello.to_frame().unwrap();
        for (frame, is_client) in [(&client, true), (&ack, false)] {
            let decode = |frame: &Frame| {
                if is_client {
                    ClientHello::from_frame(frame).map(|_| ())
                } else {
                    ServerHello::from_frame(frame).map(|_| ())
                }
            };
            for cut in 0..frame.payload.len() {
                let truncated = Frame::new(
                    frame.version(),
                    frame.frame_type(),
                    frame.payload[..cut].to_vec(),
                )
                .unwrap();
                assert!(
                    matches!(decode(&truncated), Err(SessionError::Frame(_))),
                    "cut={cut}"
                );
            }
            let mut trailing = frame.clone();
            trailing.payload.push(0);
            trailing.header.payload_length =
                crate::net::atp::protocol::VarInt(trailing.payload.len() as u64);
            assert!(matches!(
                decode(&trailing),
                Err(SessionError::Frame(FrameError::InvalidFormat(_)))
            ));
            let mut wrong = frame.clone();
            wrong.header.frame_type = FrameType::Data;
            assert!(matches!(
                decode(&wrong),
                Err(SessionError::Frame(FrameError::InvalidFormat(_)))
            ));
            wrong = frame.clone();
            wrong.header.version = ProtocolVersion(1);
            assert!(matches!(
                decode(&wrong),
                Err(SessionError::UnsupportedVersion(1))
            ));
            wrong = frame.clone();
            wrong.header.payload_length = crate::net::atp::protocol::VarInt(0);
            assert!(matches!(
                decode(&wrong),
                Err(SessionError::Frame(FrameError::InvalidFormat(_)))
            ));
            let oversized = Frame::new(
                frame.version(),
                frame.frame_type(),
                vec![0; crate::net::atp::protocol::MAX_FRAME_SIZE as usize + 1],
            )
            .unwrap();
            assert!(matches!(
                decode(&oversized),
                Err(SessionError::Frame(FrameError::FrameTooLarge { .. }))
            ));
        }
    }

    #[test]
    fn received_hello_counts_tags_duplicates_and_unknown_reasons_fail_closed() {
        let hello = hello_for(SessionContextKind::Direct).with_features(&AtpFeature::ALL);
        let encoded = hello.to_frame().unwrap();
        // Two peer ids, nonce, version, three absent optional fields, context,
        // then the u32 feature count and the sorted one-byte feature codes.
        for (offset, bytes) in [
            (96, vec![0, 0, 0, 1]),
            (100, vec![2]),
            (103, vec![255]),
            (104, u32::MAX.to_be_bytes().to_vec()),
            (108, vec![255]),
            (108, vec![1, 0]),
            (108, vec![0, 0]),
            (126, u32::MAX.to_be_bytes().to_vec()), // Requested action count.
            (130, vec![255]),                       // Requested action code.
            (139, u32::MAX.to_be_bytes().to_vec()), // Capability grant count.
        ] {
            let mut malformed = encoded.clone();
            malformed.payload[offset..offset + bytes.len()].copy_from_slice(&bytes);
            assert!(matches!(
                ClientHello::from_frame(&malformed),
                Err(SessionError::Frame(FrameError::InvalidFormat(_)))
            ));
        }
        let mut policy = policy_for(SessionContextKind::Direct);
        let (mut ack, _, _) = SessionNegotiator::server(hello.responder)
            .accept_client_hello(&hello, &mut policy)
            .unwrap();
        ack.downgrade_warnings[0].reason_code = "arbitrary_caller_reason";
        assert!(matches!(ServerHello::from_frame(&ack.to_frame().unwrap()),
            Err(SessionError::Frame(FrameError::InvalidFormat(message))) if message == "unknown downgrade reason"));
    }

    #[test]
    fn received_hello_vectors_preserve_existing_order_and_duplicates_exactly() {
        let mut hello = hello_for(SessionContextKind::Direct).with_features(&AtpFeature::ALL);
        let grant = hello.grants[0].clone();
        let mut changed_grant = grant.clone();
        changed_grant.valid_from_micros = 1;
        changed_grant.actions.insert(CapabilityAction::Receive);
        assert_eq!(grant.id, changed_grant.id);
        assert_ne!(grant, changed_grant);
        for grants in [
            vec![grant.clone(), grant.clone()],
            vec![grant.clone(), changed_grant.clone()],
            vec![changed_grant, grant.clone(), grant],
        ] {
            hello.grants = grants;
            let encoded = hello.to_frame().unwrap();
            let decoded = ClientHello::from_frame(&encoded).unwrap();
            assert_eq!(decoded, hello);
            assert_eq!(decoded.to_frame().unwrap(), encoded);
            assert_eq!(
                decoded.to_frame().unwrap().to_wire_bytes().unwrap(),
                encoded.to_wire_bytes().unwrap()
            );
        }

        let mut policy = policy_for(SessionContextKind::Direct);
        let (mut ack, _, _) = SessionNegotiator::server(hello.responder)
            .accept_client_hello(&hello, &mut policy)
            .unwrap();
        assert!(ack.downgrade_warnings.len() > 1);
        ack.downgrade_warnings.reverse();
        ack.downgrade_warnings
            .push(ack.downgrade_warnings[0].clone());
        ack.accepted_grants = vec![
            CapabilityGrantId::new([255; 16]),
            CapabilityGrantId::new([0; 16]),
            CapabilityGrantId::new([255; 16]),
        ];
        let encoded = ack.to_frame().unwrap();
        let decoded = ServerHello::from_frame(&encoded).unwrap();
        assert_eq!(decoded, ack);
        assert_eq!(decoded.to_frame().unwrap(), encoded);
        assert_eq!(
            decoded.to_frame().unwrap().to_wire_bytes().unwrap(),
            encoded.to_wire_bytes().unwrap()
        );
    }

    #[test]
    fn received_hello_nested_strings_are_length_bounded_utf8_and_unique() {
        let mut hello = hello_for(SessionContextKind::Direct);
        hello.grants[0].scope.allowed_path_prefixes =
            ["prefix-a".to_owned(), "prefix-b".to_owned()].into();
        let frame = hello.to_frame().unwrap();
        let offsets = frame
            .payload
            .windows(8)
            .enumerate()
            .filter_map(|(index, bytes)| (bytes == b"prefix-b").then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(offsets.len(), 1);
        let offset = offsets[0];
        for (start, bytes, expected) in [
            (
                offset - 4,
                u32::MAX.to_be_bytes().to_vec(),
                "hello field count exceeds remaining payload",
            ),
            (offset, vec![255], "hello string is not UTF-8"),
            (
                offset,
                b"prefix-a".to_vec(),
                "duplicate or noncanonical hello set entry",
            ),
        ] {
            let mut changed = frame.clone();
            changed.payload[start..start + bytes.len()].copy_from_slice(&bytes);
            assert!(matches!(ClientHello::from_frame(&changed),
                Err(SessionError::Frame(FrameError::InvalidFormat(message))) if message == expected));
        }
    }

    #[test]
    fn received_hello_identity_and_ack_tampering_reach_real_policy_refusal() {
        let hello = hello_for(SessionContextKind::Direct);
        let mut policy = policy_for(SessionContextKind::Direct);
        let mut changed = hello.to_frame().unwrap();
        changed.payload[32] ^= 1; // Actual received responder identity byte.
        let received = ClientHello::from_frame(&changed).unwrap();
        let error = SessionNegotiator::server(hello.responder)
            .accept_client_hello(&received, &mut policy)
            .unwrap_err();
        assert_eq!(error.code(), "peer_confusion");
        assert!(!policy.seen_nonces.contains(&hello.nonce));
        let (_, mut ack, _) = SessionNegotiator::server(hello.responder)
            .accept_client_hello(&hello, &mut policy)
            .unwrap();
        ack.payload[0] ^= 1; // Session id remains structurally valid, semantically wrong.
        let received = ServerHello::from_frame(&ack).unwrap();
        let mut client = SessionNegotiator::client(hello.initiator);
        client.start_client_hello(&hello).unwrap();
        assert_eq!(
            client
                .finish_client(&hello, &received, &policy)
                .unwrap_err()
                .code(),
            "session_id_mismatch"
        );
    }

    fn negotiate(
        hello: &ClientHello,
        policy: &mut SessionPolicy,
    ) -> Result<
        (
            NegotiatedSession,
            SessionProofArtifact,
            SessionProofArtifact,
        ),
        SessionError,
    > {
        let mut client = SessionNegotiator::client(hello.initiator);
        let mut server = SessionNegotiator::server(policy.local_peer);
        let client_frame = client.start_client_hello(hello)?;
        assert_eq!(client_frame.frame_type(), FrameType::Handshake);

        let (server_hello, server_frame, server_proof) =
            server.accept_client_hello(hello, policy)?;
        assert_eq!(server_frame.frame_type(), FrameType::HandshakeAck);

        let (session, client_proof) = client.finish_client(hello, &server_hello, policy)?;
        Ok((session, client_proof, server_proof))
    }

    #[test]
    fn direct_first_contact_pairing_establishes_session() {
        let hello = hello_for(SessionContextKind::Direct);
        let mut policy = policy_for(SessionContextKind::Direct);

        let (session, client_proof, server_proof) = negotiate(&hello, &mut policy).unwrap();

        assert_eq!(session.context, SessionContextKind::Direct);
        assert!(
            session
                .selected_features
                .contains(AtpFeature::EncryptionPolicy)
        );
        assert_eq!(session.accepted_grants.len(), 1);
        assert_eq!(client_proof.session_id, server_proof.session_id);
        assert_eq!(client_proof.rejected_reason, None);
        assert!(!client_proof.transcript_hash.is_empty());
    }

    #[test]
    fn relay_mailbox_and_swarm_contexts_require_matching_features() {
        for (context, feature, action) in [
            (
                SessionContextKind::Relay,
                AtpFeature::Relay,
                CapabilityAction::Relay,
            ),
            (
                SessionContextKind::Mailbox,
                AtpFeature::Mailbox,
                CapabilityAction::Mailbox,
            ),
            (
                SessionContextKind::Swarm,
                AtpFeature::Swarm,
                CapabilityAction::Seed,
            ),
        ] {
            let (alice, bob) = peers();
            let hello = ClientHello::new(
                alice,
                bob,
                TransferNonce::from_seed(context.code()),
                context,
                SessionTraceId::new(77),
            )
            .with_features(&[AtpFeature::EncryptionPolicy, feature])
            .with_requested_actions(&[action])
            .with_grants(vec![grant_for(bob, alice, &[action], context)]);
            let hello = if matches!(context, SessionContextKind::Relay) {
                hello.with_relay_peer(relay_peer())
            } else {
                hello
            };
            let policy = SessionPolicy::new(bob, 100)
                .with_supported_features(&[AtpFeature::EncryptionPolicy, feature])
                .with_required_features(&[AtpFeature::EncryptionPolicy])
                .with_required_actions(&[action])
                .with_accepted_contexts(&[context]);
            let mut policy = if matches!(context, SessionContextKind::Relay) {
                policy.with_trusted_relays(&[relay_peer()])
            } else {
                policy
            };

            let (session, _client_proof, _server_proof) = negotiate(&hello, &mut policy).unwrap();
            assert_eq!(session.context, context);
            assert!(session.selected_features.contains(feature));
        }
    }

    #[test]
    fn relay_context_requires_trusted_relay_identity() {
        let (alice, bob) = peers();
        let relay_grant = grant_for(
            bob,
            alice,
            &[CapabilityAction::Relay],
            SessionContextKind::Relay,
        );
        let base = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed("relay-auth"),
            SessionContextKind::Relay,
            SessionTraceId::new(88),
        )
        .with_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay])
        .with_requested_actions(&[CapabilityAction::Relay])
        .with_grants(vec![relay_grant]);

        let mut missing_policy = SessionPolicy::new(bob, 100)
            .with_supported_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay])
            .with_required_features(&[AtpFeature::EncryptionPolicy])
            .with_required_actions(&[CapabilityAction::Relay])
            .with_accepted_contexts(&[SessionContextKind::Relay])
            .with_trusted_relays(&[relay_peer()]);
        let mut server = SessionNegotiator::server(bob);
        let error = server
            .accept_client_hello(&base, &mut missing_policy)
            .unwrap_err();
        assert_eq!(error.code(), "missing_relay_identity");

        let mut untrusted_policy = SessionPolicy::new(bob, 100)
            .with_supported_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay])
            .with_required_features(&[AtpFeature::EncryptionPolicy])
            .with_required_actions(&[CapabilityAction::Relay])
            .with_accepted_contexts(&[SessionContextKind::Relay])
            .with_trusted_relays(&[relay_peer()]);
        let mut server = SessionNegotiator::server(bob);
        let error = server
            .accept_client_hello(
                &base.clone().with_relay_peer(alternate_relay_peer()),
                &mut untrusted_policy,
            )
            .unwrap_err();
        assert_eq!(error.code(), "untrusted_relay_identity");
    }

    #[test]
    fn relay_grant_scope_and_session_id_bind_relay_identity() {
        let (alice, bob) = peers();
        let grant = grant_for(
            bob,
            alice,
            &[CapabilityAction::Relay],
            SessionContextKind::Relay,
        );
        let hello = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed("relay-scope"),
            SessionContextKind::Relay,
            SessionTraceId::new(89),
        )
        .with_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay])
        .with_requested_actions(&[CapabilityAction::Relay])
        .with_relay_peer(alternate_relay_peer())
        .with_grants(vec![grant.clone()]);
        let policy = SessionPolicy::new(bob, 100)
            .with_supported_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay])
            .with_required_features(&[AtpFeature::EncryptionPolicy])
            .with_required_actions(&[CapabilityAction::Relay])
            .with_accepted_contexts(&[SessionContextKind::Relay])
            .with_trusted_relays(&[relay_peer(), alternate_relay_peer()]);

        match grant
            .validate_for(&hello, CapabilityAction::Relay, &policy)
            .expect_err("relay grant scope")
        {
            SessionError::RelayScopeDenied {
                relay_peer: Some(rejected),
            } => assert_eq!(rejected, alternate_relay_peer()),
            other => panic!("unexpected error: {other:?}"),
        }

        let selected = FeatureSet::from_slice(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay]);
        let relay_a_session =
            derive_session_id(&hello.clone().with_relay_peer(relay_peer()), &selected);
        let relay_b_session = derive_session_id(&hello, &selected);
        assert_ne!(relay_a_session, relay_b_session);
    }

    #[test]
    fn unsupported_optional_features_emit_downgrade_warnings() {
        let hello = hello_for(SessionContextKind::Direct).with_features(&[
            AtpFeature::EncryptionPolicy,
            AtpFeature::Repair,
            AtpFeature::Compression,
            AtpFeature::H3Adapter,
            AtpFeature::WebTransportAdapter,
        ]);
        let mut policy = policy_for(SessionContextKind::Direct)
            .with_supported_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Repair]);
        let mut server = SessionNegotiator::server(policy.local_peer);

        let (server_hello, _frame, proof) =
            server.accept_client_hello(&hello, &mut policy).unwrap();

        assert!(server_hello.selected_features.contains(AtpFeature::Repair));
        assert!(
            !server_hello
                .selected_features
                .contains(AtpFeature::Compression)
        );
        let warned = server_hello
            .downgrade_warnings
            .iter()
            .map(|warning| warning.feature)
            .collect::<BTreeSet<_>>();
        assert!(warned.contains(&AtpFeature::Compression));
        assert!(warned.contains(&AtpFeature::H3Adapter));
        assert!(warned.contains(&AtpFeature::WebTransportAdapter));
        assert_eq!(proof.selected_features, vec!["repair", "encryption_policy"]);
    }

    #[test]
    fn dataplane_redesign_capabilities_negotiate_by_intersection() {
        assert_eq!(
            ATP_DATAPLANE_REDESIGN_FEATURES.map(AtpFeature::code),
            [
                "bounded_k",
                "exact_deficit_need_more",
                "delivery_rate_credit",
                "control_arq_beacon",
                "fan_out",
                "multi_peer",
            ]
        );

        let hello = hello_for(SessionContextKind::Direct).with_features(&[
            AtpFeature::EncryptionPolicy,
            AtpFeature::BoundedK,
            AtpFeature::ExactDeficitNeedMore,
            AtpFeature::DeliveryRateCredit,
            AtpFeature::ControlArqBeacon,
            AtpFeature::FanOut,
            AtpFeature::MultiPeer,
        ]);
        let mut policy = policy_for(SessionContextKind::Direct).with_supported_features(&[
            AtpFeature::EncryptionPolicy,
            AtpFeature::BoundedK,
            AtpFeature::ExactDeficitNeedMore,
            AtpFeature::ControlArqBeacon,
        ]);
        let mut server = SessionNegotiator::server(policy.local_peer);

        let (server_hello, _frame, _proof) =
            server.accept_client_hello(&hello, &mut policy).unwrap();

        assert!(
            server_hello
                .selected_features
                .contains(AtpFeature::BoundedK)
        );
        assert!(
            server_hello
                .selected_features
                .contains(AtpFeature::ExactDeficitNeedMore)
        );
        assert!(
            server_hello
                .selected_features
                .contains(AtpFeature::ControlArqBeacon)
        );
        assert!(
            !server_hello
                .selected_features
                .contains(AtpFeature::DeliveryRateCredit)
        );
        assert!(!server_hello.selected_features.contains(AtpFeature::FanOut));
        assert!(
            !server_hello
                .selected_features
                .contains(AtpFeature::MultiPeer)
        );

        let warnings = server_hello
            .downgrade_warnings
            .iter()
            .map(|warning| (warning.feature, warning.reason_code))
            .collect::<BTreeSet<_>>();
        assert!(warnings.contains(&(
            AtpFeature::DeliveryRateCredit,
            "delivery_rate_credit_not_supported_by_peer"
        )));
        assert!(warnings.contains(&(AtpFeature::FanOut, "fan_out_not_supported_by_peer")));
        assert!(warnings.contains(&(AtpFeature::MultiPeer, "multi_peer_not_supported_by_peer")));
    }

    #[test]
    fn mixed_dataplane_peer_downgrades_extended_features_to_legacy() {
        let offered = [
            AtpFeature::EncryptionPolicy,
            AtpFeature::BoundedK,
            AtpFeature::ExactDeficitNeedMore,
            AtpFeature::DeliveryRateCredit,
            AtpFeature::ControlArqBeacon,
            AtpFeature::FanOut,
            AtpFeature::MultiPeer,
        ];
        let hello = hello_for(SessionContextKind::Direct).with_features(&offered);
        let mut policy = policy_for(SessionContextKind::Direct)
            .with_supported_features(&[AtpFeature::EncryptionPolicy]);
        let mut client = SessionNegotiator::client(hello.initiator);
        let mut server = SessionNegotiator::server(policy.local_peer);

        client.start_client_hello(&hello).unwrap();
        let (server_hello, _frame, server_proof) =
            server.accept_client_hello(&hello, &mut policy).unwrap();
        let (session, client_proof) = client
            .finish_client(&hello, &server_hello, &policy)
            .unwrap();

        assert_eq!(
            session.selected_features,
            FeatureSet::from_slice(&[AtpFeature::EncryptionPolicy])
        );
        for feature in ATP_DATAPLANE_REDESIGN_FEATURES {
            assert!(
                !session.selected_features.contains(feature),
                "legacy peer must not silently enable {}",
                feature.code()
            );
        }

        let warnings = server_hello
            .downgrade_warnings
            .iter()
            .map(|warning| (warning.feature, warning.reason_code))
            .collect::<BTreeSet<_>>();
        for feature in ATP_DATAPLANE_REDESIGN_FEATURES {
            assert!(
                warnings.contains(&(feature, feature.downgrade_reason_code())),
                "missing downgrade warning for {}",
                feature.code()
            );
        }
        assert_eq!(client_proof.selected_features, vec!["encryption_policy"]);
        assert_eq!(server_proof.selected_features, vec!["encryption_policy"]);
    }

    #[test]
    fn missing_required_dataplane_capability_fails_closed() {
        let hello = hello_for(SessionContextKind::Direct)
            .with_features(&[AtpFeature::EncryptionPolicy, AtpFeature::BoundedK]);
        let mut policy = policy_for(SessionContextKind::Direct)
            .with_supported_features(&[
                AtpFeature::EncryptionPolicy,
                AtpFeature::BoundedK,
                AtpFeature::ExactDeficitNeedMore,
            ])
            .with_required_features(&[
                AtpFeature::EncryptionPolicy,
                AtpFeature::ExactDeficitNeedMore,
            ]);
        let mut server = SessionNegotiator::server(policy.local_peer);

        let error = server.accept_client_hello(&hello, &mut policy).unwrap_err();

        assert_eq!(error.code(), "missing_required_feature");
        assert_eq!(
            error
                .proof()
                .and_then(|proof| proof.rejected_reason.as_deref()),
            Some("missing_required_feature")
        );
    }

    #[test]
    fn downgraded_server_reply_cannot_drop_client_required_dataplane_capability() {
        let hello = hello_for(SessionContextKind::Direct).with_features(&[
            AtpFeature::EncryptionPolicy,
            AtpFeature::ExactDeficitNeedMore,
        ]);
        let client_policy = SessionPolicy::new(hello.initiator, 100).with_required_features(&[
            AtpFeature::EncryptionPolicy,
            AtpFeature::ExactDeficitNeedMore,
        ]);
        let mut client = SessionNegotiator::client(hello.initiator);
        client.start_client_hello(&hello).unwrap();

        let selected_features = FeatureSet::from_slice(&[AtpFeature::EncryptionPolicy]);
        let server_hello = ServerHello {
            session_id: derive_session_id(&hello, &selected_features),
            acceptor: hello.responder,
            initiator: hello.initiator,
            nonce: hello.nonce,
            version: ProtocolVersion::CURRENT,
            context: SessionContextKind::Direct,
            selected_features,
            downgrade_warnings: vec![DowngradeWarning {
                feature: AtpFeature::ExactDeficitNeedMore,
                reason_code: AtpFeature::ExactDeficitNeedMore.downgrade_reason_code(),
            }],
            accepted_grants: Vec::new(),
            trace_id: hello.trace_id,
        };

        let error = client
            .finish_client(&hello, &server_hello, &client_policy)
            .unwrap_err();

        assert!(matches!(
            error,
            SessionError::MissingRequiredFeature(AtpFeature::ExactDeficitNeedMore)
        ));
        assert_eq!(error.code(), "missing_required_feature");
    }

    #[test]
    fn server_cannot_silently_select_unoffered_dataplane_capability() {
        let hello = hello_for(SessionContextKind::Direct)
            .with_features(&[AtpFeature::EncryptionPolicy, AtpFeature::BoundedK]);
        let policy = policy_for(SessionContextKind::Direct);
        let mut client = SessionNegotiator::client(hello.initiator);
        client.start_client_hello(&hello).unwrap();

        let selected_features = FeatureSet::from_slice(&[
            AtpFeature::EncryptionPolicy,
            AtpFeature::BoundedK,
            AtpFeature::DeliveryRateCredit,
        ]);
        let server_hello = ServerHello {
            session_id: derive_session_id(&hello, &selected_features),
            acceptor: hello.responder,
            initiator: hello.initiator,
            nonce: hello.nonce,
            version: ProtocolVersion::CURRENT,
            context: SessionContextKind::Direct,
            selected_features,
            downgrade_warnings: Vec::new(),
            accepted_grants: Vec::new(),
            trace_id: hello.trace_id,
        };

        let error = client
            .finish_client(&hello, &server_hello, &policy)
            .unwrap_err();

        assert!(matches!(
            error,
            SessionError::FeatureConfusion(AtpFeature::DeliveryRateCredit)
        ));
        assert_eq!(error.code(), "feature_confusion");
    }

    #[test]
    fn missing_required_feature_fails_closed() {
        let hello = hello_for(SessionContextKind::Direct).with_features(&[AtpFeature::Repair]);
        let mut policy = policy_for(SessionContextKind::Direct);
        let mut server = SessionNegotiator::server(policy.local_peer);

        let error = server.accept_client_hello(&hello, &mut policy).unwrap_err();

        assert_eq!(error.code(), "missing_required_feature");
        assert_eq!(
            error
                .proof()
                .and_then(|proof| proof.rejected_reason.as_deref()),
            Some("missing_required_feature")
        );
    }

    #[test]
    fn expired_and_revoked_grants_are_rejected() {
        let (alice, bob) = peers();
        let base = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed("expired"),
            SessionContextKind::Direct,
            SessionTraceId::new(1),
        )
        .with_features(&[AtpFeature::EncryptionPolicy])
        .with_requested_actions(&[CapabilityAction::Write]);
        let mut policy = policy_for(SessionContextKind::Direct);

        let expired = grant_for(
            bob,
            alice,
            &[CapabilityAction::Write],
            SessionContextKind::Direct,
        )
        .with_validity(0, 50);
        let mut server = SessionNegotiator::server(policy.local_peer);
        let error = server
            .accept_client_hello(&base.clone().with_grants(vec![expired]), &mut policy)
            .unwrap_err();
        assert_eq!(error.code(), "missing_grant_action");

        let revoked = grant_for(
            bob,
            alice,
            &[CapabilityAction::Write],
            SessionContextKind::Direct,
        )
        .revoked();
        let mut server = SessionNegotiator::server(policy.local_peer);
        let error = server
            .accept_client_hello(&base.with_grants(vec![revoked]), &mut policy)
            .unwrap_err();
        assert_eq!(error.code(), "missing_grant_action");
    }

    #[test]
    fn replayed_nonce_is_rejected_before_authorization() {
        let hello = hello_for(SessionContextKind::Direct);
        let mut policy = policy_for(SessionContextKind::Direct).with_seen_nonce(hello.nonce);
        let mut server = SessionNegotiator::server(policy.local_peer);

        let error = server.accept_client_hello(&hello, &mut policy).unwrap_err();

        assert_eq!(error.code(), "replayed_nonce");
    }

    #[test]
    fn successful_accept_records_nonce_for_future_replay_rejection() {
        let hello = hello_for(SessionContextKind::Direct);
        let mut policy = policy_for(SessionContextKind::Direct);
        let mut server = SessionNegotiator::server(policy.local_peer);

        server.accept_client_hello(&hello, &mut policy).unwrap();

        assert!(policy.seen_nonces.contains(&hello.nonce));

        let mut replay_server = SessionNegotiator::server(policy.local_peer);
        let error = replay_server
            .accept_client_hello(&hello, &mut policy)
            .unwrap_err();

        assert_eq!(error.code(), "replayed_nonce");
    }

    #[test]
    fn path_and_object_scope_escalation_is_rejected() {
        let (alice, bob) = peers();
        let allowed_path = PathCandidateId::new(7);
        let denied_path = PathCandidateId::new(8);
        let allowed_root = manifest_root(1);
        let denied_root = manifest_root(2);
        let scope = CapabilityScope::for_context(SessionContextKind::Direct)
            .with_path_id(allowed_path)
            .with_manifest_root(allowed_root);
        let grant = CapabilityGrant::new(
            CapabilityGrantId::from_label("scoped"),
            bob,
            alice,
            [CapabilityAction::Write],
            scope,
        );
        let mut policy = policy_for(SessionContextKind::Direct).require_manifest_binding();

        let path_escalation = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed("path-escalation"),
            SessionContextKind::Direct,
            SessionTraceId::new(2),
        )
        .with_features(&[AtpFeature::EncryptionPolicy])
        .with_requested_actions(&[CapabilityAction::Write])
        .with_manifest_root(allowed_root)
        .with_path_id(denied_path)
        .with_grants(vec![grant.clone()]);
        let mut server = SessionNegotiator::server(policy.local_peer);
        let error = server
            .accept_client_hello(&path_escalation, &mut policy)
            .unwrap_err();
        assert_eq!(error.code(), "missing_grant_action");

        let object_escalation = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed("object-escalation"),
            SessionContextKind::Direct,
            SessionTraceId::new(3),
        )
        .with_features(&[AtpFeature::EncryptionPolicy])
        .with_requested_actions(&[CapabilityAction::Write])
        .with_manifest_root(denied_root)
        .with_path_id(allowed_path)
        .with_grants(vec![grant]);
        let mut server = SessionNegotiator::server(policy.local_peer);
        let error = server
            .accept_client_hello(&object_escalation, &mut policy)
            .unwrap_err();
        assert_eq!(error.code(), "missing_grant_action");
    }

    #[test]
    fn invalid_transitions_fail_closed() {
        let hello = hello_for(SessionContextKind::Direct);
        let mut client = SessionNegotiator::client(hello.initiator);

        client.start_client_hello(&hello).unwrap();
        let error = client.start_client_hello(&hello).unwrap_err();

        assert_eq!(error.code(), "invalid_transition");
    }

    #[test]
    fn server_feature_confusion_is_rejected_by_client() {
        let hello =
            hello_for(SessionContextKind::Direct).with_features(&[AtpFeature::EncryptionPolicy]);
        let policy = policy_for(SessionContextKind::Direct);
        let mut client = SessionNegotiator::client(hello.initiator);
        client.start_client_hello(&hello).unwrap();

        let server_hello = ServerHello {
            session_id: derive_session_id(
                &hello,
                &FeatureSet::from_slice(&[AtpFeature::EncryptionPolicy, AtpFeature::Compression]),
            ),
            acceptor: hello.responder,
            initiator: hello.initiator,
            nonce: hello.nonce,
            version: ProtocolVersion::CURRENT,
            context: SessionContextKind::Direct,
            selected_features: FeatureSet::from_slice(&[
                AtpFeature::EncryptionPolicy,
                AtpFeature::Compression,
            ]),
            downgrade_warnings: Vec::new(),
            accepted_grants: vec![CapabilityGrantId::from_label("grant")],
            trace_id: hello.trace_id,
        };

        let error = client
            .finish_client(&hello, &server_hello, &policy)
            .unwrap_err();

        assert_eq!(error.code(), "feature_confusion");
    }
