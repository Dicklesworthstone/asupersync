    use super::*;
    use crate::bytes::{Bytes, BytesMut};
    use crate::cx::{Cx, cap};
    use crate::net::atp::protocol::quic_frames::QuicFrame;
    use crate::net::atp::protocol::varint::VarInt;
    use crate::trace::TraceBufferHandle;
    use crate::types::{Budget, RegionId, TaskId};

    fn test_cx() -> Cx<cap::All> {
        Cx::new(
            RegionId::new_for_test(0, 1),
            TaskId::testing_default(),
            Budget::INFINITE,
        )
    }

    fn test_cx_with_blocking_pool(
        region_seed: u32,
        threads: usize,
    ) -> (crate::runtime::blocking_pool::BlockingPool, Cx<cap::All>) {
        let pool = crate::runtime::blocking_pool::BlockingPool::new(threads, threads);
        let cx = Cx::new(
            RegionId::new_for_test(region_seed, 1),
            TaskId::new_for_test(region_seed, 0),
            Budget::INFINITE,
        )
        .with_blocking_pool_handle(Some(pool.handle()));
        (pool, cx)
    }

    fn encoded_application_payload() -> Vec<u8> {
        let mut payload = BytesMut::new();
        QuicFrame::Stream {
            stream_id: VarInt::from_u64_unchecked(0),
            offset: Some(VarInt::from_u64_unchecked(0)),
            data: Bytes::from_static(b"control-stream-bytes"),
            fin: false,
        }
        .encode(&mut payload)
        .expect("encode STREAM frame");
        QuicFrame::Datagram {
            data: Bytes::from_static(b"raptorq-symbol-datagram"),
        }
        .encode(&mut payload)
        .expect("encode DATAGRAM frame");
        payload.to_vec()
    }

    async fn deterministic_one_rtt_protection(
        cx: &Cx<cap::All>,
        seed: &'static [u8],
    ) -> AtpPacketProtection {
        let mut protection =
            AtpPacketProtection::new_client(true).expect("deterministic protection");
        let mut transcript = QuicHandshakeTranscript::new();
        transcript.record("client-finished", b"client");
        transcript.record("server-finished", b"server");
        let snapshot = protection
            .derive_keys(cx, PacketProtectionSpace::OneRtt, &transcript, seed)
            .await
            .expect("derive 1-rtt keys");
        assert_eq!(snapshot.space, PacketProtectionSpace::OneRtt);
        assert!(!snapshot.key_phase);
        protection
    }

    async fn deterministic_one_rtt_protection_with_logging(
        cx: &Cx<cap::All>,
        seed: &'static [u8],
        enable_proof_logging: bool,
    ) -> AtpPacketProtection {
        let mut protection = AtpPacketProtection::new(AtpPacketProtectionConfig {
            use_deterministic: true,
            enable_transcript_verification: true,
            enable_proof_logging,
            provider_options: ProviderOptions::Deterministic {
                scenario: "a4-packet-protection".to_string(),
            },
        })
        .expect("deterministic protection");
        let mut transcript = QuicHandshakeTranscript::new();
        transcript.record("client-finished", b"client");
        transcript.record("server-finished", b"server");
        protection
            .derive_keys(cx, PacketProtectionSpace::OneRtt, &transcript, seed)
            .await
            .expect("derive 1-rtt keys");
        protection
    }

    #[test]
    fn test_packet_protection_config_defaults() {
        let config = AtpPacketProtectionConfig::default();
        assert!(!config.use_deterministic);
        assert!(config.enable_transcript_verification);
        assert!(config.enable_proof_logging);
    }

    // asupersync-gsnci5: RFC 9001 §6.6 AEAD confidentiality accounting. Each
    // protected packet increments a per-key counter; crossing the soft
    // threshold marks a key update due, and rotating the key resets it.
    #[test]
    fn aead_confidentiality_counter_marks_key_update_due_and_resets_on_rotation() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection =
                deterministic_one_rtt_protection(&cx, b"aead-confidentiality-seed").await;
            // Exercise the threshold without protecting millions of packets.
            protection.set_key_update_confidentiality_threshold(4);
            let space = PacketProtectionSpace::OneRtt;
            let payload = encoded_application_payload();
            let aad = b"short-header confidentiality-counter";

            assert_eq!(protection.protected_packet_count(space), 0);
            assert!(!protection.confidentiality_key_update_due(space));

            for pn in 0..3u64 {
                protection
                    .protect_packet_now(
                        &cx,
                        PacketProtectionRequest {
                            space,
                            key_phase: false,
                            packet_number: pn,
                            associated_data: aad,
                            payload: &payload,
                        },
                    )
                    .expect("protect below threshold");
            }
            assert_eq!(protection.protected_packet_count(space), 3);
            assert!(
                !protection.confidentiality_key_update_due(space),
                "below the soft threshold no update is due"
            );

            protection
                .protect_packet_now(
                    &cx,
                    PacketProtectionRequest {
                        space,
                        key_phase: false,
                        packet_number: 3,
                        associated_data: aad,
                        payload: &payload,
                    },
                )
                .expect("protect at threshold");
            assert_eq!(protection.protected_packet_count(space), 4);
            assert!(
                protection.confidentiality_key_update_due(space),
                "reaching the soft threshold marks a key update due"
            );
            assert!(
                !protection.confidentiality_limit_reached(space),
                "the soft threshold is far below the 2^23 hard limit"
            );

            protection.note_local_key_update(space);
            assert_eq!(protection.protected_packet_count(space), 0);
            assert!(!protection.confidentiality_key_update_due(space));
        });
    }

    // asupersync-gsnci5: RFC 9001 §6.6 AEAD integrity accounting. A post-replay
    // authentication failure counts toward the integrity limit; a genuine
    // packet and a replay-window rejection do not.
    #[test]
    fn aead_integrity_counter_counts_authentication_failures_only() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection =
                deterministic_one_rtt_protection(&cx, b"aead-integrity-seed").await;
            let space = PacketProtectionSpace::OneRtt;
            let payload = encoded_application_payload();
            let aad = b"short-header integrity-counter";
            assert_eq!(protection.auth_failure_count(space), 0);

            let good = protection
                .protect_packet_now(
                    &cx,
                    PacketProtectionRequest {
                        space,
                        key_phase: false,
                        packet_number: 0,
                        associated_data: aad,
                        payload: &payload,
                    },
                )
                .expect("protect pn=0");
            let mut bad = protection
                .protect_packet_now(
                    &cx,
                    PacketProtectionRequest {
                        space,
                        key_phase: false,
                        packet_number: 1,
                        associated_data: aad,
                        payload: &payload,
                    },
                )
                .expect("protect pn=1");
            bad.ciphertext[0] ^= 0x5a;

            protection
                .unprotect_packet_now(&cx, &bad, aad)
                .expect_err("tampered ciphertext fails authentication");
            assert_eq!(
                protection.auth_failure_count(space),
                1,
                "a failed authentication counts toward the integrity limit"
            );
            assert!(!protection.integrity_limit_reached(space));

            protection
                .unprotect_packet_now(&cx, &good, aad)
                .expect("genuine packet authenticates");
            assert_eq!(
                protection.auth_failure_count(space),
                1,
                "a successful authentication does not increment the failure counter"
            );

            protection
                .unprotect_packet_now(&cx, &good, aad)
                .expect_err("accepted packet number is replay-rejected");
            assert_eq!(
                protection.auth_failure_count(space),
                1,
                "a replay-window rejection is screened before the AEAD and is not an integrity failure"
            );

            protection.note_peer_key_update(space);
            assert_eq!(protection.auth_failure_count(space), 0);
        });
    }

    #[test]
    fn aead_provider_profile_identifies_deterministic_test_path() {
        let protection = AtpPacketProtection::new_client(true).expect("deterministic protection");
        let profile = protection.aead_provider_profile();

        assert_eq!(profile.provider_kind, "deterministic-lab");
        assert_eq!(profile.backend, "deterministic-test-provider");
        assert_eq!(profile.tls_cipher_suite, "none");
        assert_eq!(profile.quic_aead, "deterministic-xor-tag");
        assert!(!profile.hardware.aes_gcm_capable());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn rustls_aead_provider_profile_reports_aes_gcm_hardware_probe() {
        let protection = AtpPacketProtection::new_client(false).expect("rustls protection");
        let profile = protection.aead_provider_profile();

        assert_eq!(profile.provider_kind, "rustls-quic-ring");
        assert_eq!(profile.backend, "rustls/ring");
        assert_eq!(profile.tls_cipher_suite, "TLS13_AES_128_GCM_SHA256");
        assert_eq!(profile.quic_aead, "AES-128-GCM");
        assert_ne!(profile.hardware.probe, "not-probed");
    }

    #[test]
    fn test_deterministic_protection_lifecycle() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let protection =
                AtpPacketProtection::new_client(true).expect("deterministic protection");

            assert_eq!(protection.provider_kind(), "deterministic");

            // Test transcript verification
            let transcript = QuicHandshakeTranscript::new();
            protection
                .verify_transcript(&cx, transcript.digest())
                .await
                .expect("transcript verification");
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_rustls_protection_creation() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let client = AtpPacketProtection::new_client(false).expect("rustls client protection");
            let server = AtpPacketProtection::new_server(false).expect("rustls server protection");

            assert_eq!(client.provider_kind(), "rustls-quic-ring");
            assert_eq!(server.provider_kind(), "rustls-quic-ring");

            let profile = client.aead_provider_profile();
            assert_eq!(profile.provider_kind, "rustls-quic-ring");
            assert_eq!(profile.backend, "rustls/ring");
            assert_eq!(profile.tls_cipher_suite, "TLS13_AES_128_GCM_SHA256");
            assert_eq!(profile.quic_aead, "AES-128-GCM");
            assert!(!profile.hardware.probe.is_empty());

            // Test basic operations don't panic
            let transcript = QuicHandshakeTranscript::new();
            client
                .verify_transcript(&cx, transcript.digest())
                .await
                .expect("client transcript verification");
            server
                .verify_transcript(&cx, transcript.digest())
                .await
                .expect("server transcript verification");
        });
    }

    #[test]
    fn test_error_mapping() {
        futures_lite::future::block_on(async {
            let _cx = test_cx();
            let protection =
                AtpPacketProtection::new_client(true).expect("deterministic protection");

            // Test error mapping
            let tls_error = QuicTlsError::HandshakeNotConfirmed;
            let atp_error = protection.map_tls_error(tls_error);

            match atp_error {
                AtpError::Protocol(ProtocolError::SessionStateMismatch) => {
                    // Expected
                }
                _ => panic!("Unexpected error mapping: {:?}", atp_error),
            }
        });
    }

    #[test]
    fn replay_window_is_bounded_and_stale_packets_fail_closed() {
        let mut window = PacketReplayWindow::default();
        let packet_count = REPLAY_WINDOW_CAPACITY as u64 + 8;

        for packet_number in 0..packet_count {
            assert!(
                !window.rejects(packet_number),
                "fresh packet {packet_number} should be inside the replay window"
            );
            window.accept(packet_number);
        }

        assert!(window.len() <= REPLAY_WINDOW_CAPACITY);
        assert!(window.rejects(0), "stale packet below the window is closed");
        assert!(
            window.rejects(packet_count - 1),
            "duplicate packet number is closed"
        );
        assert!(
            !window.rejects(packet_count),
            "next packet number is still accepted"
        );
    }

    #[test]
    fn one_rtt_application_payload_roundtrips_and_replay_fails_closed() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection =
                deterministic_one_rtt_protection(&cx, b"one-rtt-roundtrip-seed").await;
            let payload = encoded_application_payload();
            let aad = b"short-header pn=41 key_phase=0";

            let protected = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: false,
                        packet_number: 41,
                        associated_data: aad,
                        payload: &payload,
                    },
                )
                .await
                .expect("protect 1-rtt app payload");

            assert_eq!(protected.space, PacketProtectionSpace::OneRtt);
            assert_ne!(
                protected.ciphertext, payload,
                "payload should be protected, not copied as plaintext"
            );

            let unprotected = protection
                .unprotect_packet(&cx, &protected, aad)
                .await
                .expect("unprotect 1-rtt app payload");
            assert_eq!(unprotected.plaintext, payload);
            assert_eq!(protection.accepted_packet_count(), 1);

            let replay = protection
                .unprotect_packet(&cx, &protected, aad)
                .await
                .expect_err("same packet number in same space must be rejected");
            assert_eq!(replay, AtpError::Auth(AuthError::ReplayedNonce));
            assert_eq!(protection.accepted_packet_count(), 1);
        });
    }

    #[test]
    fn protect_packets_batches_ordered_one_rtt_payloads() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection = deterministic_one_rtt_protection(&cx, b"one-rtt-batch-seed").await;
            let payloads = [
                encoded_application_payload(),
                b"second application payload".to_vec(),
                b"third application payload".to_vec(),
            ];
            let associated_data = [
                b"batch short header pn=100".as_slice(),
                b"batch short header pn=101".as_slice(),
                b"batch short header pn=102".as_slice(),
            ];
            let requests = [
                PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: 100,
                    associated_data: associated_data[0],
                    payload: &payloads[0],
                },
                PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: 101,
                    associated_data: associated_data[1],
                    payload: &payloads[1],
                },
                PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: 102,
                    associated_data: associated_data[2],
                    payload: &payloads[2],
                },
            ];

            let protected = protection
                .protect_packets(&cx, &requests)
                .expect("batch protects");

            assert_eq!(protected.len(), requests.len());
            assert_eq!(
                protection.accepted_packet_count(),
                0,
                "protecting packets must not mutate the receive replay window"
            );

            for (idx, packet) in protected.iter().enumerate() {
                assert_eq!(packet.packet_number, requests[idx].packet_number);
                assert_ne!(packet.ciphertext, payloads[idx]);
                let unprotected = protection
                    .unprotect_packet(&cx, packet, associated_data[idx])
                    .await
                    .expect("batched packet unprotects");
                assert_eq!(unprotected.plaintext, payloads[idx]);
            }
            assert_eq!(protection.accepted_packet_count(), requests.len());
        });
    }

    #[test]
    fn unprotect_packets_batches_ordered_one_rtt_payloads() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection =
                deterministic_one_rtt_protection(&cx, b"one-rtt-unprotect-batch-seed").await;
            let payloads = [
                encoded_application_payload(),
                b"second batched encrypted payload".to_vec(),
                b"third batched encrypted payload".to_vec(),
            ];
            let associated_data = [
                b"batch unprotect short header pn=200".as_slice(),
                b"batch unprotect short header pn=201".as_slice(),
                b"batch unprotect short header pn=202".as_slice(),
            ];
            let protect_requests = [
                PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: 200,
                    associated_data: associated_data[0],
                    payload: &payloads[0],
                },
                PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: 201,
                    associated_data: associated_data[1],
                    payload: &payloads[1],
                },
                PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: 202,
                    associated_data: associated_data[2],
                    payload: &payloads[2],
                },
            ];

            let protected = protection
                .protect_packets(&cx, &protect_requests)
                .expect("batch protects");
            let unprotect_requests = protected
                .iter()
                .zip(associated_data)
                .map(|(packet, aad)| PacketUnprotectionRequest {
                    packet,
                    associated_data: aad,
                })
                .collect::<Vec<_>>();
            let unprotected = protection.unprotect_packets(&cx, &unprotect_requests);

            assert_eq!(unprotected.len(), payloads.len());
            for (idx, outcome) in unprotected.into_iter().enumerate() {
                let packet = outcome.expect("batched packet unprotects");
                assert_eq!(packet.packet_number, protect_requests[idx].packet_number);
                assert_eq!(packet.plaintext, payloads[idx]);
            }
            assert_eq!(protection.accepted_packet_count(), payloads.len());

            let replay = protection.unprotect_packets(&cx, &unprotect_requests[..1]);
            assert_eq!(replay.len(), 1);
            assert_eq!(
                replay
                    .into_iter()
                    .next()
                    .expect("one replay result")
                    .expect_err("same packet number in same space must be rejected"),
                AtpError::Auth(AuthError::ReplayedNonce)
            );
            assert_eq!(protection.accepted_packet_count(), payloads.len());
        });
    }

    #[test]
    fn parallel_unprotect_width_uses_receiver_blocking_pool_capacity() {
        let cx = test_cx();
        assert_eq!(
            packet_unprotect_parallel_width_for_cx(&cx, PARALLEL_UNPROTECT_MIN_PACKETS),
            1,
            "contexts without a receiver blocking pool must stay inline"
        );

        let (_pool, cx) = test_cx_with_blocking_pool(53, 4);
        assert_eq!(
            packet_unprotect_parallel_width_for_cx(&cx, PARALLEL_UNPROTECT_MIN_PACKETS - 1),
            1,
            "tiny socket batches should avoid offload overhead"
        );
        assert_eq!(
            packet_unprotect_parallel_width_for_cx(&cx, 16),
            2,
            "width should scale with chunk count and available blocking threads"
        );
        assert_eq!(
            packet_unprotect_parallel_width_for_cx(&cx, 64),
            4,
            "width should cap at the receiver blocking-pool capacity"
        );
    }

    #[test]
    fn parallel_unprotect_width_bounds_a_default_sized_pool_by_host_cores() {
        // br-asupersync-issue65-criticisms-kpmoy5.1.15: the runtime's default
        // pool caps at 512 threads for blocking I/O, which says nothing about CPUs.
        let pool = crate::runtime::blocking_pool::BlockingPool::new(0, 512);
        let cx = Cx::new(
            RegionId::new_for_test(54, 1),
            TaskId::new_for_test(54, 0),
            Budget::INFINITE,
        )
        .with_blocking_pool_handle(Some(pool.handle()));
        let packets = PARALLEL_UNPROTECT_TARGET_CHUNK_PACKETS * 1024;
        assert_eq!(
            packet_unprotect_parallel_width_for_cx(&cx, packets),
            512,
            "an explicitly sized pool's cap stands in for CPU width"
        );

        pool.handle().mark_default_sized();
        assert_eq!(
            packet_unprotect_parallel_width_for_cx(&cx, packets),
            host_cpu_parallelism().min(512),
            "the default pool's width must come from the host's cores"
        );
    }

    #[test]
    fn unprotect_packets_parallel_preserves_order_and_fails_closed() {
        futures_lite::future::block_on(async {
            let (_pool, cx) = test_cx_with_blocking_pool(54, 4);
            let mut protection =
                deterministic_one_rtt_protection(&cx, b"one-rtt-parallel-unprotect-seed").await;
            let payloads = (0..16)
                .map(|idx| format!("parallel encrypted payload {idx}").into_bytes())
                .collect::<Vec<_>>();
            let associated_data = (0..16)
                .map(|idx| format!("parallel short header pn={}", 500 + idx).into_bytes())
                .collect::<Vec<_>>();
            let protect_requests = payloads
                .iter()
                .zip(&associated_data)
                .enumerate()
                .map(|(idx, (payload, aad))| PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: 500 + u64::try_from(idx).expect("idx fits"),
                    associated_data: aad,
                    payload,
                })
                .collect::<Vec<_>>();

            let mut protected = protection
                .protect_packets(&cx, &protect_requests)
                .expect("batch protects");
            let tampered_index = 5;
            protected[tampered_index].ciphertext[0] ^= 0x5a;
            let unprotect_requests = protected
                .iter()
                .zip(&associated_data)
                .map(|(packet, aad)| PacketUnprotectionRequest {
                    packet,
                    associated_data: aad,
                })
                .collect::<Vec<_>>();

            let unprotected = protection
                .unprotect_packets_parallel(&cx, &unprotect_requests)
                .await;

            assert_eq!(unprotected.len(), payloads.len());
            for (idx, outcome) in unprotected.into_iter().enumerate() {
                if idx == tampered_index {
                    assert_eq!(
                        outcome.expect_err("tampered packet must fail closed"),
                        AtpError::Protocol(ProtocolError::InvalidFrameType)
                    );
                } else {
                    let packet = outcome.expect("untampered packet decrypts");
                    assert_eq!(packet.packet_number, protect_requests[idx].packet_number);
                    assert_eq!(packet.plaintext, payloads[idx]);
                }
            }
            assert_eq!(
                protection.accepted_packet_count(),
                payloads.len() - 1,
                "failed authentication must not poison replay state"
            );

            let replay_request = [PacketUnprotectionRequest {
                packet: &protected[0],
                associated_data: &associated_data[0],
            }];
            let replay = protection
                .unprotect_packets_parallel(&cx, &replay_request)
                .await;
            assert_eq!(
                replay
                    .into_iter()
                    .next()
                    .expect("one replay result")
                    .expect_err("accepted packet number must be rejected on replay"),
                AtpError::Auth(AuthError::ReplayedNonce)
            );
            assert_eq!(protection.accepted_packet_count(), payloads.len() - 1);
        });
    }

    #[test]
    fn unprotect_packets_parallel_applies_replay_window_in_order() {
        futures_lite::future::block_on(async {
            let (_pool, cx) = test_cx_with_blocking_pool(55, 4);
            let mut protection =
                deterministic_one_rtt_protection(&cx, b"one-rtt-parallel-replay-order-seed").await;
            let packet_numbers = std::iter::once(2_000)
                .chain(std::iter::once(0))
                .chain(2_001..2_015)
                .collect::<Vec<_>>();
            assert_eq!(packet_numbers.len(), 16);
            let payloads = packet_numbers
                .iter()
                .map(|pn| format!("parallel replay-order payload {pn}").into_bytes())
                .collect::<Vec<_>>();
            let associated_data = packet_numbers
                .iter()
                .map(|pn| format!("parallel replay-order short header pn={pn}").into_bytes())
                .collect::<Vec<_>>();
            let protect_requests = packet_numbers
                .iter()
                .zip(&payloads)
                .zip(&associated_data)
                .map(|((packet_number, payload), aad)| PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: *packet_number,
                    associated_data: aad,
                    payload,
                })
                .collect::<Vec<_>>();

            let protected = protection
                .protect_packets(&cx, &protect_requests)
                .expect("batch protects");
            let unprotect_requests = protected
                .iter()
                .zip(&associated_data)
                .map(|(packet, aad)| PacketUnprotectionRequest {
                    packet,
                    associated_data: aad,
                })
                .collect::<Vec<_>>();

            let unprotected = protection
                .unprotect_packets_parallel(&cx, &unprotect_requests)
                .await;

            match &unprotected[1] {
                Outcome::Err(err) => assert_eq!(
                    err,
                    &AtpError::Auth(AuthError::ReplayedNonce),
                    "packet 0 must become stale after packet 2000 is accepted"
                ),
                other => panic!("packet 0 must be replay-rejected, got {other:?}"),
            }
            for (idx, outcome) in unprotected.into_iter().enumerate() {
                if idx == 1 {
                    continue;
                }
                let packet = outcome.expect("non-stale packet decrypts");
                assert_eq!(packet.packet_number, packet_numbers[idx]);
                assert_eq!(packet.plaintext, payloads[idx]);
            }
            assert_eq!(
                protection.accepted_packet_count(),
                packet_numbers.len() - 1,
                "stale packet must not poison replay state"
            );
        });
    }

    #[test]
    fn replay_guard_is_active_when_proof_logging_is_disabled() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection = deterministic_one_rtt_protection_with_logging(
                &cx,
                b"proof-logging-disabled-seed",
                false,
            )
            .await;
            let payload = encoded_application_payload();
            let aad = b"short-header pn=55 key_phase=0";
            let protected = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: false,
                        packet_number: 55,
                        associated_data: aad,
                        payload: &payload,
                    },
                )
                .await
                .expect("protect");
            protection
                .unprotect_packet(&cx, &protected, aad)
                .await
                .expect("first decrypt succeeds");
            let replay = protection
                .unprotect_packet(&cx, &protected, aad)
                .await
                .expect_err("proof logging must not gate anti-replay");
            assert_eq!(replay, AtpError::Auth(AuthError::ReplayedNonce));
        });
    }

    #[test]
    fn tampered_ciphertext_fails_closed_without_poisoning_replay_guard() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection = deterministic_one_rtt_protection(&cx, b"tamper-seed").await;
            let payload = encoded_application_payload();
            let aad = b"short-header pn=7 key_phase=0";
            let protected = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: false,
                        packet_number: 7,
                        associated_data: aad,
                        payload: &payload,
                    },
                )
                .await
                .expect("protect");

            let mut tampered = protected.clone();
            tampered.ciphertext[0] ^= 0x5a;
            let err = protection
                .unprotect_packet(&cx, &tampered, aad)
                .await
                .expect_err("tampered ciphertext must fail authentication");
            assert_eq!(
                err,
                AtpError::Protocol(ProtocolError::InvalidFrameType),
                "BadPacketTag maps to fail-closed protocol rejection"
            );
            assert_eq!(
                protection.accepted_packet_count(),
                0,
                "failed authentication must not poison replay state"
            );

            let unprotected = protection
                .unprotect_packet(&cx, &protected, aad)
                .await
                .expect("original packet still decrypts after tampered attempt");
            assert_eq!(unprotected.plaintext, payload);
            assert_eq!(protection.accepted_packet_count(), 1);
        });
    }

    #[test]
    fn header_protection_and_key_phase_update_are_covered() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection = deterministic_one_rtt_protection(&cx, b"key-phase-seed").await;
            let mask = protection
                .header_protection_mask(&cx, PacketProtectionSpace::OneRtt, b"1234567890abcdef")
                .await
                .expect("header mask");
            assert_ne!(mask.bytes, [0; 5]);

            let update = protection
                .update_key(&cx, PacketProtectionSpace::OneRtt, true)
                .await
                .expect("key update");
            assert!(update.key_phase);
            assert_eq!(update.generation, 1);

            let payload = encoded_application_payload();
            let protected = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: true,
                        packet_number: 9,
                        associated_data: b"short-header pn=9 key_phase=1",
                        payload: &payload,
                    },
                )
                .await
                .expect("protect updated phase");
            let unprotected = protection
                .unprotect_packet(&cx, &protected, b"short-header pn=9 key_phase=1")
                .await
                .expect("unprotect updated phase");
            assert_eq!(unprotected.plaintext, payload);
            assert!(unprotected.proof.key_phase);
            assert_eq!(unprotected.proof.generation, 1);
        });
    }

    // asupersync-1bheeo: the receive and flush paths install next-generation
    // keys through `ensure_next_gen_keys`, which must advance the (single-shot,
    // bidirectional) rustls key ratchet at most once per rotation. A forged or
    // duplicated key-phase-flip packet that re-derived keys would put us at a
    // generation the peer never reaches and wedge the connection.
    #[test]
    fn ensure_next_gen_keys_is_idempotent_within_a_rotation() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection =
                deterministic_one_rtt_protection(&cx, b"key-update-idempotency-seed").await;
            let space = PacketProtectionSpace::OneRtt;

            // Initial keys are generation 0 under phase 0; the next generation
            // (phase 1) is not installed yet.
            assert!(!protection.next_gen_keys_installed(space, true));

            // First install advances the ratchet exactly once to generation 1.
            protection
                .ensure_next_gen_keys(&cx, space, true)
                .expect("install next-gen keys");
            assert!(protection.next_gen_keys_installed(space, true));
            assert_eq!(
                protection
                    .provider
                    .key_snapshot(space, true)
                    .expect("phase-1 keys installed")
                    .generation,
                1,
            );

            // A duplicated or forged same-phase flip must reuse the installed
            // keys, not advance the ratchet to generation 2.
            protection
                .ensure_next_gen_keys(&cx, space, true)
                .expect("idempotent re-install");
            assert_eq!(
                protection
                    .provider
                    .key_snapshot(space, true)
                    .expect("phase-1 keys still installed")
                    .generation,
                1,
                "ensure_next_gen_keys must be idempotent within a rotation",
            );

            // The next rotation (back to phase 0) is a distinct generation and
            // does advance the ratchet, to generation 2.
            assert!(!protection.next_gen_keys_installed(space, false));
            protection
                .ensure_next_gen_keys(&cx, space, false)
                .expect("install generation 2");
            assert_eq!(
                protection
                    .provider
                    .key_snapshot(space, false)
                    .expect("phase-0 keys re-installed")
                    .generation,
                2,
            );
            assert!(protection.next_gen_keys_installed(space, false));
        });
    }

    #[test]
    fn packet_number_replay_is_rejected_across_key_phase() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection = deterministic_one_rtt_protection(&cx, b"phase-replay-seed").await;
            let payload = encoded_application_payload();
            let first = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: false,
                        packet_number: 12,
                        associated_data: b"pn=12 phase=0",
                        payload: &payload,
                    },
                )
                .await
                .expect("protect first phase");
            protection
                .unprotect_packet(&cx, &first, b"pn=12 phase=0")
                .await
                .expect("accept first phase packet");

            protection
                .update_key(&cx, PacketProtectionSpace::OneRtt, true)
                .await
                .expect("update phase");
            let second = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: true,
                        packet_number: 12,
                        associated_data: b"pn=12 phase=1",
                        payload: &payload,
                    },
                )
                .await
                .expect("protect reused packet number with new phase");
            let err = protection
                .unprotect_packet(&cx, &second, b"pn=12 phase=1")
                .await
                .expect_err("packet numbers cannot be reused inside a PN space");
            assert_eq!(err, AtpError::Auth(AuthError::ReplayedNonce));
        });
    }

    #[test]
    fn packet_protection_traces_are_redacted() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let trace = TraceBufferHandle::new(16);
            cx.set_trace_buffer(trace.clone());
            let secret_seed = b"super-secret-a4-seed";
            let sensitive_payload = b"ATP_QUIC_TRACE_SECRET_PAYLOAD";
            let mut protection = deterministic_one_rtt_protection(&cx, secret_seed).await;
            let protected = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: false,
                        packet_number: 31,
                        associated_data: b"trace-aad",
                        payload: sensitive_payload,
                    },
                )
                .await
                .expect("protect");
            protection
                .unprotect_packet(&cx, &protected, b"trace-aad")
                .await
                .expect("unprotect");
            let replay = protection
                .unprotect_packet(&cx, &protected, b"trace-aad")
                .await
                .expect_err("replay");
            assert_eq!(replay, AtpError::Auth(AuthError::ReplayedNonce));

            let rendered = trace
                .snapshot()
                .iter()
                .map(|event| format!("{:?}", event.data))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(rendered.contains("atp_packet_protection_protect"));
            assert!(rendered.contains("atp_packet_protection_unprotect"));
            assert!(rendered.contains("atp_packet_protection_replay_rejected"));
            assert!(
                !rendered.contains("super-secret-a4-seed"),
                "trace must not contain key seed material: {rendered}"
            );
            assert!(
                !rendered.contains("ATP_QUIC_TRACE_SECRET_PAYLOAD"),
                "trace must not contain plaintext payload material: {rendered}"
            );
        });
    }
