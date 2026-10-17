    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    #[cfg(feature = "tls")]
    use crate::tls::{Certificate, CertificateChain, RootCertStore};
    #[cfg(feature = "tls")]
    use std::time::Duration;

    #[cfg(feature = "tls")]
    const TEST_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.crt");

    #[cfg(feature = "tls")]
    fn fixed_cert_validity_time() -> rustls_pki_types::UnixTime {
        rustls_pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_780_000_000))
    }

    #[cfg(feature = "tls")]
    fn trusted_localhost_verifier() -> (QuicServerIdentityVerifier, CertificateChain) {
        let certs = Certificate::from_pem(TEST_CERT_PEM).expect("fixture cert parses");
        let mut roots = RootCertStore::empty();
        roots
            .add(&certs[0])
            .expect("fixture cert can be a test trust anchor");
        let verifier = QuicServerIdentityVerifier::from_root_store(roots).expect("build verifier");
        (verifier, CertificateChain::from(certs))
    }

    #[test]
    fn level_transitions_are_monotonic() {
        let mut m = QuicTlsMachine::new();
        assert_eq!(m.level(), CryptoLevel::Initial);
        m.on_handshake_keys_available().expect("handshake keys");
        assert_eq!(m.level(), CryptoLevel::Handshake);
        m.on_1rtt_keys_available().expect("1rtt keys");
        assert_eq!(m.level(), CryptoLevel::OneRtt);
        let err = m.advance_to(CryptoLevel::Initial).expect_err("must fail");
        assert_eq!(
            err,
            QuicTlsError::InvalidTransition {
                from: CryptoLevel::OneRtt,
                to: CryptoLevel::Initial
            }
        );
    }

    #[test]
    fn key_update_requires_confirmed_handshake() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        let err = m.request_local_key_update().expect_err("must fail");
        assert_eq!(err, QuicTlsError::HandshakeNotConfirmed);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn server_identity_verifier_rejects_empty_root_store() {
        let err = QuicServerIdentityVerifier::from_root_store(RootCertStore::empty())
            .expect_err("empty roots must fail closed");
        assert_eq!(err.code(), "server_identity_root_store_empty");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn server_identity_verifier_rejects_empty_presented_chain() {
        let (verifier, _) = trusted_localhost_verifier();
        let err = verifier
            .verify_server_chain(
                "localhost",
                CertificateChain::new(),
                fixed_cert_validity_time(),
            )
            .expect_err("empty peer chain must fail closed");
        assert_eq!(err.code(), "server_certificate_chain_empty");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn server_identity_verifier_rejects_wrong_hostname() {
        let (verifier, chain) = trusted_localhost_verifier();
        let err = verifier
            .verify_server_chain("not-localhost.example", chain, fixed_cert_validity_time())
            .expect_err("wrong hostname must fail closed");
        assert!(err.code().starts_with("server_certificate_"));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn server_identity_verifier_accepts_trusted_localhost_chain() {
        let (verifier, chain) = trusted_localhost_verifier();
        let receipt = verifier
            .verify_server_chain("localhost", chain, fixed_cert_validity_time())
            .expect("trusted localhost chain verifies");
        assert_eq!(receipt.chain_len, 1);
        assert_eq!(receipt.root_count, 1);
    }

    #[test]
    fn authenticated_completion_allows_data_but_not_key_updates() {
        let mut machine = QuicTlsMachine::new();
        machine.on_handshake_keys_available().unwrap();
        machine.enable_resumption();
        assert!(machine.can_send_0rtt());
        assert_eq!(
            machine.on_authenticated_handshake_complete(),
            Err(QuicTlsError::HandshakeNotConfirmed)
        );
        assert!(!machine.can_send_1rtt());
        machine.on_1rtt_keys_available().unwrap();
        assert!(!machine.can_send_1rtt(), "keys alone do not authenticate");
        machine.on_authenticated_handshake_complete().unwrap();
        assert!(machine.can_send_1rtt());
        assert!(!machine.can_send_0rtt());
        assert!(!machine.handshake_confirmed());
        assert_eq!(
            machine.request_local_key_update(),
            Err(QuicTlsError::HandshakeNotConfirmed)
        );
        assert_eq!(
            machine.on_peer_key_phase(true),
            Err(QuicTlsError::HandshakeNotConfirmed)
        );
        assert!(!machine.peer_key_phase_is_new_update(true, 1));
        assert!(!machine.local_key_phase());
        machine.on_handshake_confirmed().unwrap();
        assert!(machine.handshake_confirmed());
        assert!(matches!(
            machine.request_local_key_update().unwrap(),
            KeyUpdateEvent::LocalUpdateScheduled { .. }
        ));
    }

    #[test]
    fn local_key_update_flow() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");
        assert!(!m.local_key_phase());

        let scheduled = m.request_local_key_update().expect("schedule");
        assert_eq!(
            scheduled,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1
            }
        );
        let committed = m.commit_local_key_update().expect("commit");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1
            }
        );
        assert!(m.local_key_phase());
    }

    #[test]
    fn peer_key_phase_updates_are_applied() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        let evt = m.on_peer_key_phase(true).expect("peer update");
        assert_eq!(
            evt,
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: true,
                generation: 1
            }
        );
        assert!(m.remote_key_phase());
    }

    // --- gap-filling tests ---

    #[test]
    fn on_peer_key_phase_before_handshake_confirmed() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        // handshake NOT confirmed
        let err = m.on_peer_key_phase(true).expect_err("must fail");
        assert_eq!(err, QuicTlsError::HandshakeNotConfirmed);
    }

    #[test]
    fn on_peer_key_phase_same_phase_returns_no_change() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        // Remote phase starts at false; sending false again is same phase.
        let evt = m.on_peer_key_phase(false).expect("same phase");
        assert_eq!(evt, KeyUpdateEvent::NoChange);
        assert!(!m.remote_key_phase());
    }

    #[test]
    fn stale_peer_key_phase_rollback_is_rejected() {
        // asupersync-1bheeo (RFC 9001 §6.3, user-approved documented-behaviour
        // change): a phase flip is stale only when its packet number predates
        // the current generation's floor — a reordered packet of the previous
        // phase — not merely because it flips back to phase 0.
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        // Peer rotates to phase 1 at packet number 100 (sets the generation
        // floor to 100).
        let evt = m.on_peer_key_phase_pn(true, 100).expect("first update");
        assert_eq!(
            evt,
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: true,
                generation: 1,
            }
        );

        // A phase-0 packet numbered BELOW the floor is a delayed old-phase
        // packet, rejected as stale rather than rotating backwards.
        let err = m
            .on_peer_key_phase_pn(false, 50)
            .expect_err("stale rollback must fail");
        assert_eq!(err, QuicTlsError::StalePeerKeyPhase(false));
        assert!(m.remote_key_phase());
        assert_eq!(m.remote.generation, 1);
    }

    #[test]
    fn alternating_peer_key_updates_are_accepted() {
        // asupersync-1bheeo (RFC 9001 §6.3): key phases alternate, so a
        // long-lived connection processes repeated peer key updates,
        // disambiguated by increasing packet numbers.
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        let e1 = m.on_peer_key_phase_pn(true, 100).expect("update 1 (0->1)");
        assert_eq!(
            e1,
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: true,
                generation: 1,
            }
        );
        // The second update (1->0) — previously rejected by the one-update rule.
        let e2 = m.on_peer_key_phase_pn(false, 200).expect("update 2 (1->0)");
        assert_eq!(
            e2,
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: false,
                generation: 2,
            }
        );
        assert!(!m.remote_key_phase());
        let e3 = m.on_peer_key_phase_pn(true, 300).expect("update 3 (0->1)");
        assert_eq!(
            e3,
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: true,
                generation: 3,
            }
        );
        assert!(m.remote_key_phase());
        // A delayed phase-0 packet numbered below the gen-3 floor is stale.
        let err = m
            .on_peer_key_phase_pn(false, 250)
            .expect_err("delayed old-phase packet is stale");
        assert_eq!(err, QuicTlsError::StalePeerKeyPhase(false));
        assert_eq!(m.remote.generation, 3);
    }

    // asupersync-1bheeo: the live receive path must decide whether to install
    // next-generation keys BEFORE running AEAD (the replay window permits
    // decrypting once), so it needs a non-committing predicate that agrees
    // exactly with `on_peer_key_phase_pn`'s accept condition.
    #[test]
    fn peer_key_phase_is_new_update_matches_the_commit_condition() {
        let mut m = QuicTlsMachine::new();
        // Before the handshake is confirmed, no key update is possible.
        assert!(!m.peer_key_phase_is_new_update(true, 100));
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        // A flip to the other phase at the first generation is always genuine.
        assert!(m.peer_key_phase_is_new_update(true, 100));
        // The current phase is not an update (would be NoChange).
        assert!(!m.peer_key_phase_is_new_update(false, 100));

        // Predicate agrees with the committing call: accept the phase-1 update.
        assert!(m.peer_key_phase_is_new_update(true, 100));
        m.on_peer_key_phase_pn(true, 100).expect("commit update");

        // A phase-0 flip above the gen-1 floor is a genuine next update.
        assert!(m.peer_key_phase_is_new_update(false, 150));
        // A phase-0 flip BELOW the floor is a delayed old-phase packet, not an
        // update — it must be decrypted with the retained previous keys.
        assert!(!m.peer_key_phase_is_new_update(false, 50));
        // The predicate has not mutated any state.
        assert!(m.remote_key_phase());
        assert_eq!(m.remote.generation, 1);
    }

    #[test]
    fn double_request_local_key_update_is_idempotent() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        let first = m.request_local_key_update().expect("first request");
        assert_eq!(
            first,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1,
            }
        );

        // Second request while the first is still pending returns NoChange.
        let second = m.request_local_key_update().expect("second request");
        assert_eq!(second, KeyUpdateEvent::NoChange);
    }

    #[test]
    fn commit_local_key_update_without_prior_request() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        // No request_local_key_update was issued.
        let evt = m.commit_local_key_update().expect("commit without request");
        assert_eq!(evt, KeyUpdateEvent::NoChange);
        // Phase and generation remain at defaults.
        assert!(!m.local_key_phase());
    }

    #[test]
    fn multiple_key_update_generations() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        // Generation 0 -> 1
        m.request_local_key_update().expect("request gen1");
        m.commit_local_key_update().expect("commit gen1");
        assert!(m.local_key_phase()); // phase flipped to true
        assert_eq!(m.local.generation, 1);

        // Generation 1 -> 2
        let sched = m.request_local_key_update().expect("request gen2");
        assert_eq!(
            sched,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: false, // flips back
                generation: 2,
            }
        );
        let committed = m.commit_local_key_update().expect("commit gen2");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: false,
                generation: 2,
            }
        );
        assert!(!m.local_key_phase());
        assert_eq!(m.local.generation, 2);

        // Generation 2 -> 3
        let sched = m.request_local_key_update().expect("request gen3");
        assert_eq!(
            sched,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 3,
            }
        );
        let committed = m.commit_local_key_update().expect("commit gen3");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 3,
            }
        );
        assert!(m.local_key_phase());
        assert_eq!(m.local.generation, 3);
    }

    #[test]
    fn advance_to_skipping_handshake_level() {
        let mut m = QuicTlsMachine::new();
        assert_eq!(m.level(), CryptoLevel::Initial);

        // Skip directly from Initial to OneRtt.
        m.advance_to(CryptoLevel::OneRtt).expect("skip to 1rtt");
        assert_eq!(m.level(), CryptoLevel::OneRtt);

        // Going backwards must fail.
        let err = m
            .advance_to(CryptoLevel::Handshake)
            .expect_err("must fail backwards");
        assert_eq!(
            err,
            QuicTlsError::InvalidTransition {
                from: CryptoLevel::OneRtt,
                to: CryptoLevel::Handshake,
            }
        );
    }

    #[test]
    fn quic_tls_error_display_messages() {
        let e1 = QuicTlsError::HandshakeNotConfirmed;
        assert_eq!(e1.to_string(), "handshake not confirmed");

        let e2 = QuicTlsError::InvalidTransition {
            from: CryptoLevel::Handshake,
            to: CryptoLevel::Initial,
        };
        assert_eq!(
            e2.to_string(),
            "invalid crypto transition: Handshake -> Initial"
        );

        let e3 = QuicTlsError::StalePeerKeyPhase(true);
        assert_eq!(e3.to_string(), "stale peer key phase: true");

        let e4 = QuicTlsError::StalePeerKeyPhase(false);
        assert_eq!(e4.to_string(), "stale peer key phase: false");
    }

    #[test]
    fn crypto_level_ord_semantics() {
        assert!(CryptoLevel::Initial < CryptoLevel::Handshake);
        assert!(CryptoLevel::Handshake < CryptoLevel::OneRtt);
        assert!(CryptoLevel::Initial < CryptoLevel::OneRtt);

        // Verify ordering consistency with Ord trait.
        let mut levels = vec![
            CryptoLevel::OneRtt,
            CryptoLevel::Initial,
            CryptoLevel::Handshake,
        ];
        levels.sort();
        assert_eq!(
            levels,
            vec![
                CryptoLevel::Initial,
                CryptoLevel::Handshake,
                CryptoLevel::OneRtt,
            ]
        );
    }

    // =========================================================================
    // Wave 44 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn crypto_level_debug_clone_copy_eq() {
        let l = CryptoLevel::Initial;
        let copied = l;
        let cloned = l;
        assert_eq!(copied, cloned);
        assert_ne!(CryptoLevel::Initial, CryptoLevel::OneRtt);
        let dbg = format!("{l:?}");
        assert!(dbg.contains("Initial"), "{dbg}");
    }

    #[test]
    fn key_update_event_debug_clone_copy_eq() {
        let e1 = KeyUpdateEvent::NoChange;
        let e2 = KeyUpdateEvent::LocalUpdateScheduled {
            next_phase: true,
            generation: 1,
        };
        let e3 = KeyUpdateEvent::RemoteUpdateAccepted {
            new_phase: false,
            generation: 2,
        };
        assert!(format!("{e1:?}").contains("NoChange"));
        assert!(format!("{e2:?}").contains("LocalUpdateScheduled"));
        assert!(format!("{e3:?}").contains("RemoteUpdateAccepted"));
        let copied = e2;
        let cloned = e2;
        assert_eq!(copied, cloned);
        assert_ne!(e1, e2);
    }

    #[test]
    fn quic_tls_error_debug_clone_eq_display() {
        let e1 = QuicTlsError::HandshakeNotConfirmed;
        let e2 = QuicTlsError::InvalidTransition {
            from: CryptoLevel::Initial,
            to: CryptoLevel::OneRtt,
        };
        let e3 = QuicTlsError::StalePeerKeyPhase(true);

        assert!(format!("{e1:?}").contains("HandshakeNotConfirmed"));
        assert!(format!("{e1}").contains("handshake not confirmed"));
        assert!(format!("{e2}").contains("invalid crypto transition"));
        assert!(format!("{e3}").contains("stale peer key phase"));

        assert_eq!(e1.clone(), e1);
        assert_ne!(e1, e2);

        let err: &dyn std::error::Error = &e1;
        assert!(err.source().is_none());
    }

    #[test]
    fn quic_tls_machine_debug_clone_eq() {
        let m = QuicTlsMachine::new();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("QuicTlsMachine"), "{dbg}");
        let cloned = m.clone();
        assert_eq!(m, cloned);
    }

    #[test]
    fn zero_rtt_requires_resumption_and_pre_confirmation_state() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        assert!(!m.can_send_0rtt());

        m.enable_resumption();
        assert!(m.resumption_enabled());
        assert!(m.can_send_0rtt());

        m.on_1rtt_keys_available().expect("1rtt");
        assert!(m.can_send_0rtt());

        m.on_handshake_confirmed().expect("confirmed");
        assert!(!m.can_send_0rtt());
        assert!(m.can_send_1rtt());

        m.disable_resumption();
        assert!(!m.resumption_enabled());
        assert!(!m.can_send_0rtt());
    }

    #[cfg(feature = "tls")]
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// RFC 9001 Appendix A.1-A.3 header-protection masks in both directions.
    ///
    /// Initial keys derived from the client DCID `0x8394c8f03e515708` produce
    /// the published masks, the client's sending mask is the server's
    /// receiving mask (and vice versa), and the two directions differ.
    #[cfg(feature = "tls")]
    #[test]
    fn rustls_header_protection_masks_match_rfc9001_appendix_a_in_both_directions() {
        let dcid = hex("8394c8f03e515708");
        let transcript = QuicHandshakeTranscript::new();
        let mut client =
            RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Client).expect("client");
        let mut server =
            RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Server).expect("server");
        client
            .derive_keys(PacketProtectionSpace::Initial, &transcript, &dcid)
            .expect("client initial keys");
        server
            .derive_keys(PacketProtectionSpace::Initial, &transcript, &dcid)
            .expect("server initial keys");

        // A.2: sample from the client Initial, masked with the client hp key.
        let a2_sample = hex("d1b1c98dd7689fb8ec11d242b123dc9b");
        let a2_mask = [0x43u8, 0x7b, 0x9a, 0xec, 0x36];
        let client_local = client
            .header_protection_mask(PacketProtectionSpace::Initial, &a2_sample)
            .expect("client local mask");
        let server_remote = server
            .header_protection_mask_remote(PacketProtectionSpace::Initial, &a2_sample)
            .expect("server remote mask");
        // Byte 0 is delivered pre-masked to the bits a long header applies.
        assert_eq!(client_local.bytes[0], a2_mask[0] & 0x0f);
        assert_eq!(
            &client_local.bytes[1..],
            &a2_mask[1..],
            "all four pn mask bytes"
        );
        assert_eq!(
            server_remote, client_local,
            "server unmasks with the client key"
        );

        // A.3: sample from the server Initial, masked with the server hp key.
        let a3_sample = hex("2cd0991cd25b0aac406a5816b6394100");
        let a3_mask = [0x2eu8, 0xc0, 0xd8, 0x35, 0x6a];
        let server_local = server
            .header_protection_mask(PacketProtectionSpace::Initial, &a3_sample)
            .expect("server local mask");
        let client_remote = client
            .header_protection_mask_remote(PacketProtectionSpace::Initial, &a3_sample)
            .expect("client remote mask");
        assert_eq!(server_local.bytes[0], a3_mask[0] & 0x0f);
        assert_eq!(&server_local.bytes[1..], &a3_mask[1..]);
        assert_eq!(
            client_remote, server_local,
            "client unmasks with the server key"
        );

        // Direction matters: each side's own key is not the peer's key.
        assert_ne!(
            client
                .header_protection_mask_remote(PacketProtectionSpace::Initial, &a2_sample)
                .expect("client remote on A.2 sample"),
            client_local
        );
        assert_ne!(
            server
                .header_protection_mask_remote(PacketProtectionSpace::Initial, &a3_sample)
                .expect("server remote on A.3 sample"),
            server_local
        );

        // Short samples fail closed in both directions.
        assert_eq!(
            client
                .header_protection_mask_remote(PacketProtectionSpace::Initial, &a2_sample[..15])
                .expect_err("15-byte sample")
                .code(),
            "header_sample_too_short"
        );
        // Discarded keys fail closed in both directions.
        client
            .discard_keys(PacketProtectionSpace::Initial)
            .expect("discard");
        assert!(
            client
                .header_protection_mask_remote(PacketProtectionSpace::Initial, &a2_sample)
                .is_err()
        );
        assert!(
            client
                .header_protection_mask(PacketProtectionSpace::Initial, &a2_sample)
                .is_err()
        );
    }

    /// The deterministic lab provider is direction-symmetric, so the trait's
    /// default `header_protection_mask_remote` is its correct implementation.
    #[test]
    fn deterministic_header_protection_is_direction_symmetric() {
        let transcript = QuicHandshakeTranscript::new();
        let mut provider = DeterministicQuicCryptoProvider::new();
        provider
            .derive_keys(
                PacketProtectionSpace::OneRtt,
                &transcript,
                b"symmetric-seed",
            )
            .expect("keys");
        let sample = b"0123456789abcdef";
        let local = provider
            .header_protection_mask(PacketProtectionSpace::OneRtt, sample)
            .expect("local");
        let remote = provider
            .header_protection_mask_remote(PacketProtectionSpace::OneRtt, sample)
            .expect("remote");
        assert_eq!(local, remote);
        assert_ne!(local.bytes, [0u8; 5]);
    }
