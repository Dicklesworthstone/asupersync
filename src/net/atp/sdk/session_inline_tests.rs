    use super::*;
    use crate::cx::Cx;
    use crate::net::atp::protocol::{CapabilityGrantId, CapabilityScope};
    use futures_lite::future::block_on;

    fn grant_for_direct_peer(issuer: PeerId, subject: PeerId, label: &str) -> CapabilityGrant {
        CapabilityGrant::new(
            CapabilityGrantId::from_label(label),
            issuer,
            subject,
            [CapabilityAction::Read, CapabilityAction::Write],
            CapabilityScope::for_context(SessionContextKind::Direct),
        )
    }

    fn granted_direct_options(
        local_peer: PeerId,
        remote_peer: PeerId,
        label: &str,
    ) -> SessionOptions {
        SessionOptions::direct(remote_peer).with_grants(vec![grant_for_direct_peer(
            remote_peer,
            local_peer,
            label,
        )])
    }

    fn reachable_daemon_endpoint() -> (std::net::TcpListener, String) {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback daemon placeholder");
        let endpoint = listener
            .local_addr()
            .expect("read loopback daemon placeholder address")
            .to_string();
        (listener, endpoint)
    }

    async fn in_process_session(cx: &Cx, label: &str) -> AtpSession {
        let config = SessionConfig::default();
        let local_peer = config.local_peer;
        let sdk = AtpSdk::new_in_process(config);
        let peer = PeerId::from_label(label);
        sdk.open_session(cx, granted_direct_options(local_peer, peer, label))
            .await
            .unwrap()
    }

    #[test]
    fn session_options_construction() {
        let peer = PeerId::from_label("test_peer");

        let direct = SessionOptions::direct(peer);
        assert_eq!(direct.context, SessionContextKind::Direct);
        assert!(
            direct
                .required_capabilities
                .contains(&CapabilityAction::Write)
        );

        let relay = SessionOptions::relay(peer);
        assert_eq!(relay.context, SessionContextKind::Relay);
        assert!(
            relay
                .required_capabilities
                .contains(&CapabilityAction::Relay)
        );

        let mailbox = SessionOptions::mailbox(peer);
        assert_eq!(mailbox.context, SessionContextKind::Mailbox);
        assert!(
            mailbox
                .required_capabilities
                .contains(&CapabilityAction::Mailbox)
        );

        let swarm = SessionOptions::swarm(peer);
        assert_eq!(swarm.context, SessionContextKind::Swarm);
        assert!(
            swarm
                .required_capabilities
                .contains(&CapabilityAction::Seed)
        );
    }

    #[test]
    fn session_options_with_manifest() {
        let peer = PeerId::from_label("test_peer");
        let manifest_root = [42u8; 32];

        let options = SessionOptions::direct(peer).with_manifest_root(manifest_root);
        assert_eq!(options.manifest_root, Some(manifest_root));
    }

    #[test]
    fn transfer_nonce_uses_full_context_entropy() {
        let cx = Cx::for_testing();
        let nonce = generate_transfer_nonce(&cx);

        let mut weak_expansion = [0u8; 32];
        let weak_seed = cx.random_u64();
        for (i, byte) in weak_expansion.iter_mut().enumerate() {
            *byte = weak_seed.wrapping_add(i as u64) as u8;
        }

        assert!(!nonce.is_zero());
        assert_ne!(nonce.as_bytes(), &weak_expansion);
        assert_ne!(nonce, generate_transfer_nonce(&cx));
    }

    #[test]
    fn in_process_session_creation() {
        block_on(async {
            let config = SessionConfig::default();
            let local_peer = config.local_peer;
            let sdk = AtpSdk::new_in_process(config);

            let cx = Cx::for_testing();
            let peer = PeerId::from_label("remote_peer");
            let options = granted_direct_options(local_peer, peer, "sdk-session-grant");

            let session = sdk.open_session(&cx, options).await;
            assert!(session.is_ok());

            if let AtpOutcome::Ok(session) = session {
                assert_eq!(session.remote_peer(), peer);
                assert_eq!(session.context(), SessionContextKind::Direct);
                assert_eq!(session.session.accepted_grants.len(), 1);
                assert_ne!(session.session.transcript_hash.0, [0u8; 32]);
                assert_ne!(session.proof().transcript_hash, "0000000000000000");
            }
        });
    }

    /// br-asupersync-t1fblr.1: no transport compresses, so the default
    /// `enable_compression = true` must not make the session claim it.
    #[test]
    fn in_process_session_does_not_claim_unimplemented_compression() {
        block_on(async {
            assert!(SessionConfig::default().enable_compression);
            let cx = Cx::for_testing();
            let session = in_process_session(&cx, "no-compression-claim").await;
            assert!(!session.has_feature(AtpFeature::Compression));
            assert!(session.has_feature(AtpFeature::EncryptionPolicy));
            assert!(session.has_feature(AtpFeature::ProofBundles));
        });
    }

    #[test]
    fn in_process_session_rejects_empty_grants() {
        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let cx = Cx::for_testing();
            let peer = PeerId::from_label("remote_peer");
            let result = sdk.open_session(&cx, SessionOptions::direct(peer)).await;

            match result {
                AtpOutcome::Err(AtpError::Protocol(_)) => {}
                other => panic!("empty grants must not negotiate a session: {other:?}"),
            }
        });
    }

    #[test]
    fn daemon_session_creation_fails() {
        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_daemon_delegated(
                config,
                "localhost:8080".to_string(),
                Some("token".to_string()),
            );

            let cx = Cx::for_testing();
            let peer = PeerId::from_label("remote_peer");
            let options = SessionOptions::direct(peer);

            let session = sdk.open_session(&cx, options).await;
            assert!(session.is_err()); // No daemon service is listening for this test endpoint.
        });
    }

    #[test]
    fn daemon_session_creation_reachable_stub_uses_asup_e701() {
        block_on(async {
            let (_listener, endpoint) = reachable_daemon_endpoint();
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_daemon_delegated(config, endpoint, Some("token".to_string()));

            let cx = Cx::for_testing();
            let peer = PeerId::from_label("remote_peer");
            let options = SessionOptions::direct(peer);

            let session = sdk.open_session(&cx, options).await;
            match session {
                AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented)) => {}
                other => panic!(
                    "reachable daemon-delegated session stub must fail closed with ASUP-E701: {other:?}"
                ),
            }
        });
    }

    #[test]
    fn daemon_session_close_distinguishes_offline_from_unwired_stub() {
        block_on(async {
            let cx = Cx::for_testing();
            let (offline_listener, offline_endpoint) = reachable_daemon_endpoint();
            drop(offline_listener);
            let mut offline_session = in_process_session(&cx, "daemon-close-offline").await;
            offline_session.mode = SdkMode::DaemonDelegated {
                daemon_endpoint: offline_endpoint,
                auth_token: Some("token".to_string()),
            };
            match offline_session.close(&cx).await {
                AtpOutcome::Err(AtpError::Daemon(
                    crate::net::atp::protocol::DaemonError::DaemonOffline,
                )) => {}
                other => panic!("offline daemon close must report DaemonOffline: {other:?}"),
            }

            let (_listener, endpoint) = reachable_daemon_endpoint();
            let mut reachable_session = in_process_session(&cx, "daemon-close-reachable").await;
            reachable_session.mode = SdkMode::DaemonDelegated {
                daemon_endpoint: endpoint,
                auth_token: Some("token".to_string()),
            };
            match reachable_session.close(&cx).await {
                AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented)) => {}
                other => panic!(
                    "reachable daemon-delegated close stub must fail closed with ASUP-E701: {other:?}"
                ),
            }
        });
    }
