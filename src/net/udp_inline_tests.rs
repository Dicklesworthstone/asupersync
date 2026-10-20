    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::stream::StreamExt;
    use crate::types::{Budget, RegionId, TaskId};
    use futures_lite::future;
    #[cfg(unix)]
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use std::sync::Arc;
    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[test]
    fn udp_buffer_config_clamps_to_cross_platform_bounds() {
        let config = UdpBufferConfig {
            recv_buffer_bytes: Some(1),
            send_buffer_bytes: Some(usize::MAX),
        }
        .clamped();

        assert_eq!(config.recv_buffer_bytes, Some(UDP_MIN_SOCKET_BUFFER_BYTES));
        assert_eq!(config.send_buffer_bytes, Some(UDP_MAX_SOCKET_BUFFER_BYTES));
    }

    /// br-asupersync-bi2462.21.2: a connected UDP socket can be re-targeted
    /// to a second peer on every platform.
    ///
    /// Linux replaces the peer directly; macOS answers `EISCONN` unless the
    /// association is dissolved first, which `connect` now does. Both peers
    /// must actually receive.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn udp_socket_reconnects_to_a_second_peer() {
        future::block_on(async {
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let first = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            let second = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            first
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            second
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();

            sender.connect(first.local_addr().unwrap()).await.unwrap();
            sender.send(b"to-first").await.unwrap();
            let mut buf = [0u8; 16];
            let (len, from) = first.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..len], b"to-first");
            assert_eq!(from, sender.local_addr().unwrap());

            // The re-target that returned EISCONN on macOS before the fix.
            sender
                .connect(second.local_addr().unwrap())
                .await
                .expect("re-connecting a connected UDP socket must succeed");
            sender.send(b"to-second").await.unwrap();
            let (len, from) = second.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..len], b"to-second");
            assert_eq!(from, sender.local_addr().unwrap());
            assert!(
                first.recv_from(&mut buf).is_err(),
                "the first peer must not receive after the re-target"
            );
        });
    }

    #[test]
    fn udp_capabilities_report_portable_batching() {
        future::block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let capabilities = socket.capabilities().unwrap();

            assert_eq!(capabilities.platform, UdpPlatform::current());
            assert_eq!(capabilities.address_family, UdpAddressFamily::Ipv4);
            assert!(capabilities.batching.portable_send_batch);
            assert!(capabilities.batching.portable_recv_batch);
            assert_eq!(
                capabilities.batching.native_send_batch,
                build_supports_native_sendmmsg()
            );
            assert!(!capabilities.batching.native_recv_batch);
        });
    }

    #[test]
    fn udp_default_capabilities_follow_compiled_native_paths() {
        let batching_supported = UdpBatchCapabilities::for_target_support(true);
        assert!(batching_supported.native_send_batch);
        let batching_portable = UdpBatchCapabilities::for_target_support(false);
        assert!(!batching_portable.native_send_batch);

        let android = UdpSendAccelerationCapabilities::for_target_support(true, true);
        assert_eq!(android.sendmmsg, UdpCapability::Supported);
        assert_eq!(android.gso, UdpCapability::Supported);

        let bsd = UdpSendAccelerationCapabilities::for_target_support(true, false);
        assert_eq!(bsd.sendmmsg, UdpCapability::Supported);
        assert_eq!(bsd.gso, UdpCapability::Unsupported);

        let portable = UdpSendAccelerationCapabilities::for_target_support(false, false);
        assert_eq!(portable.sendmmsg, UdpCapability::Unsupported);
        assert_eq!(portable.gso, UdpCapability::Unsupported);
    }

    #[test]
    fn udp_send_batch_plan_prefers_gso_sendmmsg_when_supported() {
        let dst = socket_addr("127.0.0.1:9000");
        let payloads = vec![vec![7; UDP_DEFAULT_GSO_SEGMENT_BYTES]; 130];
        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: dst,
                payload,
            })
            .collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy {
                max_sendmmsg_batch: 2,
                max_gso_segments: 64,
                ..UdpSendBatchStrategy::default()
            },
        );

        assert_eq!(plan.path, UdpSendBatchPath::GsoSendmmsg);
        assert_eq!(plan.datagrams, 130);
        assert_eq!(plan.payload_bytes, 130 * UDP_DEFAULT_GSO_SEGMENT_BYTES);
        // 44 full-size segments fill the 65,507-byte limit, so 130 datagrams
        // make 3 super-packets: 2 sendmmsg calls of at most 2.
        assert_eq!(plan.estimated_syscalls, 2);
        assert_eq!(plan.gso_segment_bytes, Some(UDP_DEFAULT_GSO_SEGMENT_BYTES));
        assert_eq!(plan.gso_segments_per_packet, Some(44));
    }

    #[test]
    fn udp_send_batch_plan_keeps_default_rq_datagrams_gso_eligible() {
        const DEFAULT_RQ_SYMBOL_BYTES: usize = 1400;
        const RQ_DATAGRAM_HEADER_BYTES: usize = 24;
        const RQ_AUTH_TAG_BYTES: usize = 32;
        let unauthenticated_rq_datagram_bytes = DEFAULT_RQ_SYMBOL_BYTES + RQ_DATAGRAM_HEADER_BYTES;
        let authenticated_rq_datagram_bytes =
            DEFAULT_RQ_SYMBOL_BYTES + RQ_DATAGRAM_HEADER_BYTES + RQ_AUTH_TAG_BYTES;
        assert_eq!(
            UDP_DEFAULT_GSO_SEGMENT_BYTES,
            authenticated_rq_datagram_bytes
        );

        let dst = socket_addr("127.0.0.1:9000");
        for rq_datagram_bytes in [
            unauthenticated_rq_datagram_bytes,
            authenticated_rq_datagram_bytes,
        ] {
            let payloads = vec![vec![7; rq_datagram_bytes]; 4];
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: dst,
                    payload,
                })
                .collect::<Vec<_>>();

            let plan = UdpSendBatchPlan::for_packets(
                &packets,
                UdpSendAccelerationCapabilities {
                    sendmmsg: UdpCapability::Supported,
                    gso: UdpCapability::Supported,
                    max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                    max_gso_segments: UDP_MAX_GSO_SEGMENTS,
                },
                UdpSendBatchStrategy::default(),
            );

            assert_eq!(plan.path, UdpSendBatchPath::Gso);
            assert_eq!(plan.gso_segment_bytes, Some(rq_datagram_bytes));
            assert_eq!(plan.estimated_syscalls, 1);
        }
    }

    #[test]
    fn udp_connected_send_batch_plan_keeps_rq_gso_window_eligible() {
        let payloads = vec![vec![7; UDP_DEFAULT_GSO_SEGMENT_BYTES]; UDP_MAX_GSO_SEGMENTS];
        let payload_refs = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_connected_payloads(
            &payload_refs,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        // 64 full-size segments are 93,184 bytes, more than one UDP datagram
        // can carry, so the window goes out as 44 + 20 segments in one
        // sendmmsg call.
        assert_eq!(plan.path, UdpSendBatchPath::GsoSendmmsg);
        assert_eq!(plan.datagrams, UDP_MAX_GSO_SEGMENTS);
        assert_eq!(
            plan.payload_bytes,
            UDP_MAX_GSO_SEGMENTS * UDP_DEFAULT_GSO_SEGMENT_BYTES
        );
        assert_eq!(plan.estimated_syscalls, 1);
        assert_eq!(plan.gso_segment_bytes, Some(UDP_DEFAULT_GSO_SEGMENT_BYTES));
        assert_eq!(plan.gso_segments_per_packet, Some(44));
        let segments = plan.gso_segments_per_packet.unwrap();
        assert!(segments * UDP_DEFAULT_GSO_SEGMENT_BYTES <= UDP_GSO_MAX_SUPER_PACKET_BYTES);
        assert!((segments + 1) * UDP_DEFAULT_GSO_SEGMENT_BYTES > UDP_GSO_MAX_SUPER_PACKET_BYTES);
    }

    #[test]
    fn udp_connected_send_batch_plan_batches_multiple_gso_windows() {
        let payloads = vec![vec![7; UDP_DEFAULT_GSO_SEGMENT_BYTES]; UDP_MAX_GSO_SEGMENTS * 2 + 1];
        let payload_refs = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_connected_payloads(
            &payload_refs,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::GsoSendmmsg);
        assert_eq!(plan.datagrams, UDP_MAX_GSO_SEGMENTS * 2 + 1);
        assert_eq!(plan.estimated_syscalls, 1);
        assert_eq!(plan.gso_segment_bytes, Some(UDP_DEFAULT_GSO_SEGMENT_BYTES));
        assert_eq!(plan.gso_segments_per_packet, Some(44));
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn native_connected_sendmmsg_addrs_stay_inline_for_rq_window() {
        let addrs = native_sendmmsg_none_addrs(UDP_MAX_GSO_SEGMENTS);

        assert_eq!(addrs.len(), UDP_MAX_GSO_SEGMENTS);
        assert!(addrs.iter().all(Option::is_none));
        assert!(!addrs.spilled());
    }

    #[test]
    fn udp_send_batch_plan_demotes_gso_after_socket_rejection() {
        future::block_on(async {
            let mut socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.gso_demoted = true;

            let dst = socket_addr("127.0.0.1:9000");
            let payloads = vec![vec![7; UDP_DEFAULT_GSO_SEGMENT_BYTES]; 4];
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: dst,
                    payload,
                })
                .collect::<Vec<_>>();

            let capabilities = socket.send_acceleration_capabilities();
            assert_eq!(capabilities.gso, UdpCapability::Unsupported);

            let plan = socket.plan_send_batch(&packets, UdpSendBatchStrategy::default());
            assert_ne!(plan.path, UdpSendBatchPath::Gso);
            assert_ne!(plan.path, UdpSendBatchPath::GsoSendmmsg);
            assert_eq!(plan.gso_segment_bytes, None);
            assert_eq!(plan.gso_segments_per_packet, None);
        });
    }

    #[test]
    fn udp_send_batch_plan_honors_capability_gso_segment_limit() {
        let dst = socket_addr("127.0.0.1:9000");
        let payloads = vec![vec![7; UDP_DEFAULT_GSO_SEGMENT_BYTES]; 9];
        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: dst,
                payload,
            })
            .collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: 2,
                max_gso_segments: 3,
            },
            UdpSendBatchStrategy {
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
                ..UdpSendBatchStrategy::default()
            },
        );

        assert_eq!(plan.path, UdpSendBatchPath::GsoSendmmsg);
        assert_eq!(plan.datagrams, 9);
        assert_eq!(plan.estimated_syscalls, 2);
        assert_eq!(plan.gso_segment_bytes, Some(UDP_DEFAULT_GSO_SEGMENT_BYTES));
        assert_eq!(plan.gso_segments_per_packet, Some(3));
    }

    #[test]
    fn udp_send_batch_plan_honors_capability_sendmmsg_batch_limit() {
        let dst = socket_addr("127.0.0.1:9000");
        let payloads = vec![vec![7; 64]; 9];
        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: dst,
                payload,
            })
            .collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Unsupported,
                max_sendmmsg_batch: 4,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy {
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                ..UdpSendBatchStrategy::default()
            },
        );

        assert_eq!(plan.path, UdpSendBatchPath::Sendmmsg);
        assert_eq!(plan.datagrams, 9);
        assert_eq!(plan.estimated_syscalls, 3);
        assert_eq!(plan.gso_segment_bytes, None);
        assert_eq!(plan.gso_segments_per_packet, None);
    }

    #[test]
    fn udp_send_batch_plan_uses_fixed_payload_size_for_gso_segment() {
        let dst = socket_addr("127.0.0.1:9000");
        let payloads = vec![vec![7; 900]; 4];
        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: dst,
                payload,
            })
            .collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::Gso);
        assert_eq!(plan.gso_segment_bytes, Some(900));
        assert_eq!(plan.gso_segments_per_packet, Some(4));
        assert_eq!(plan.estimated_syscalls, 1);
    }

    #[test]
    fn udp_send_batch_plan_accepts_large_quic_gso_segment_when_strategy_raises_limit() {
        let dst = socket_addr("127.0.0.1:9000");
        let plan_four_of = |segment_bytes: usize| {
            let payloads = vec![vec![7; segment_bytes]; 4];
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: dst,
                    payload,
                })
                .collect::<Vec<_>>();
            UdpSendBatchPlan::for_packets(
                &packets,
                UdpSendAccelerationCapabilities {
                    sendmmsg: UdpCapability::Supported,
                    gso: UdpCapability::Supported,
                    max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                    max_gso_segments: UDP_MAX_GSO_SEGMENTS,
                },
                UdpSendBatchStrategy {
                    gso_segment_bytes: 65_000,
                    max_gso_segments: 4,
                    ..UdpSendBatchStrategy::default()
                },
            )
        };

        // Four 16,000-byte segments fit one UDP datagram.
        let plan = plan_four_of(16_000);
        assert_eq!(plan.path, UdpSendBatchPath::Gso);
        assert_eq!(plan.datagrams, 4);
        assert_eq!(plan.payload_bytes, 64_000);
        assert_eq!(plan.estimated_syscalls, 1);
        assert_eq!(plan.gso_segment_bytes, Some(16_000));
        assert_eq!(plan.gso_segments_per_packet, Some(4));

        // Two 65,000-byte segments never fit one, which the kernel would
        // refuse with EMSGSIZE, so the batch is planned without GSO.
        let plan = plan_four_of(65_000);
        assert_eq!(plan.path, UdpSendBatchPath::Sendmmsg);
        assert_eq!(plan.payload_bytes, 260_000);
        assert_eq!(plan.estimated_syscalls, 1);
        assert_eq!(plan.gso_segment_bytes, None);
        assert_eq!(plan.gso_segments_per_packet, None);
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn native_send_backpressure_keeps_native_batch_path_retryable() {
        assert!(native_send_error_would_block(nix::errno::Errno::EAGAIN));
        assert!(native_send_error_would_block(
            nix::errno::Errno::EWOULDBLOCK
        ));
        assert!(native_send_error_would_block(nix::errno::Errno::ENOBUFS));
        assert!(!native_send_error_would_block(nix::errno::Errno::EINVAL));
    }

    #[test]
    fn udp_send_batch_plan_falls_back_to_sendmmsg_for_mixed_destinations() {
        let payload = [3u8; 64];
        let packets = [
            UdpOutboundDatagram {
                dst_addr: socket_addr("127.0.0.1:9001"),
                payload: &payload,
            },
            UdpOutboundDatagram {
                dst_addr: socket_addr("127.0.0.1:9002"),
                payload: &payload,
            },
        ];

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::Sendmmsg);
        assert_eq!(plan.estimated_syscalls, 1);
        assert_eq!(plan.gso_segment_bytes, None);
    }

    #[test]
    fn udp_send_batch_plan_rejects_variable_payload_gso_boundaries() {
        let dst = socket_addr("127.0.0.1:9004");
        let large = [4u8; UDP_DEFAULT_GSO_SEGMENT_BYTES];
        let small = [5u8; UDP_DEFAULT_GSO_SEGMENT_BYTES / 2];
        let packets = [
            UdpOutboundDatagram {
                dst_addr: dst,
                payload: &large,
            },
            UdpOutboundDatagram {
                dst_addr: dst,
                payload: &small,
            },
        ];

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::Sendmmsg);
        assert_eq!(plan.estimated_syscalls, 1);
        assert_eq!(plan.gso_segment_bytes, None);
        assert_eq!(plan.gso_segments_per_packet, None);
    }

    #[test]
    fn udp_send_batch_plan_chunks_large_sendmmsg_batches() {
        let dst = socket_addr("127.0.0.1:9003");
        let payloads = vec![vec![1u8; 16]; UDP_MAX_SENDMMSG_BATCH + 7];
        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: dst,
                payload,
            })
            .collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Unsupported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::Sendmmsg);
        assert_eq!(plan.datagrams, UDP_MAX_SENDMMSG_BATCH + 7);
        assert_eq!(plan.estimated_syscalls, 2);
        assert_eq!(plan.gso_segment_bytes, None);
    }

    #[test]
    fn udp_send_batch_plan_empty_batch_has_no_syscalls() {
        let plan = UdpSendBatchPlan::for_packets(
            &[],
            UdpSendAccelerationCapabilities::default(),
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::Empty);
        assert_eq!(plan.datagrams, 0);
        assert_eq!(plan.payload_bytes, 0);
        assert_eq!(plan.estimated_syscalls, 0);
    }

    #[test]
    fn udp_buffer_tuning_reports_observed_sizes() {
        future::block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let report = socket
                .tune_buffers(UdpBufferConfig {
                    recv_buffer_bytes: Some(16 * 1024),
                    send_buffer_bytes: Some(16 * 1024),
                })
                .unwrap();

            assert_eq!(report.requested_recv_buffer_bytes, Some(16 * 1024));
            assert_eq!(report.requested_send_buffer_bytes, Some(16 * 1024));
            assert!(report.applied_recv_buffer_bytes.is_some());
            assert!(report.applied_send_buffer_bytes.is_some());
        });
    }

    fn socket_addr(value: &str) -> SocketAddr {
        value.parse().expect("valid socket addr")
    }

    fn rendezvous_candidate() -> UdpRendezvousCandidate {
        UdpRendezvousCandidate::new(
            socket_addr("198.51.100.20:62000"),
            UdpRendezvousCandidateKind::ObservedUdp,
            100,
            2_000,
        )
    }

    fn rendezvous_signature() -> UdpRendezvousSignature {
        UdpRendezvousSignature::new("device-1", vec![7; 64])
    }

    fn rendezvous_set() -> UdpRendezvousCandidateSet {
        UdpRendezvousCandidateSet::new(
            "peer.alpha",
            [1; UDP_RENDEZVOUS_NONCE_BYTES],
            2_000,
            4,
            vec![rendezvous_candidate()],
            Some(rendezvous_signature()),
        )
    }

    #[test]
    fn udp_rendezvous_validation_accepts_signed_bounded_candidates() {
        let set = rendezvous_set();

        let result = validate_udp_rendezvous_candidates(&set, 1_000, &[]);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn udp_rendezvous_validation_rejects_malformed_peer_id() {
        let mut set = rendezvous_set();
        set.peer_id = "peer with spaces".to_string();

        let result = validate_udp_rendezvous_candidates(&set, 1_000, &[]);

        assert_eq!(result, Err(UdpRendezvousValidationError::InvalidPeerId));
    }

    #[test]
    fn udp_rendezvous_validation_rejects_replayed_nonce() {
        let set = rendezvous_set();

        let result = validate_udp_rendezvous_candidates(&set, 1_000, &[set.nonce]);

        assert_eq!(result, Err(UdpRendezvousValidationError::ReplayedNonce));
    }

    #[test]
    fn udp_rendezvous_validation_rejects_expired_offer_and_candidate() {
        let mut expired_offer = rendezvous_set();
        expired_offer.expires_at_millis = 1_000;

        let offer_result = validate_udp_rendezvous_candidates(&expired_offer, 1_000, &[]);

        assert_eq!(
            offer_result,
            Err(UdpRendezvousValidationError::ExpiredOffer)
        );

        let mut expired_candidate = rendezvous_set();
        expired_candidate.candidates[0].expires_at_millis = 1_000;

        let candidate_result = validate_udp_rendezvous_candidates(&expired_candidate, 1_000, &[]);

        assert_eq!(
            candidate_result,
            Err(UdpRendezvousValidationError::ExpiredCandidate)
        );
    }

    #[test]
    fn udp_rendezvous_validation_rejects_unbounded_candidate_and_attempt_budgets() {
        let mut too_many_candidates = rendezvous_set();
        too_many_candidates.candidates =
            vec![rendezvous_candidate(); UDP_RENDEZVOUS_MAX_CANDIDATES + 1];

        let candidates_result =
            validate_udp_rendezvous_candidates(&too_many_candidates, 1_000, &[]);

        assert_eq!(
            candidates_result,
            Err(UdpRendezvousValidationError::TooManyCandidates)
        );

        let mut too_many_attempts = rendezvous_set();
        too_many_attempts.attempt_budget = UDP_RENDEZVOUS_MAX_ATTEMPTS + 1;

        let attempts_result = validate_udp_rendezvous_candidates(&too_many_attempts, 1_000, &[]);

        assert_eq!(
            attempts_result,
            Err(UdpRendezvousValidationError::AttemptBudgetTooLarge)
        );
    }

    #[test]
    fn udp_rendezvous_validation_rejects_unsigned_or_zero_signature() {
        let mut unsigned = rendezvous_set();
        unsigned.signature = None;

        let unsigned_result = validate_udp_rendezvous_candidates(&unsigned, 1_000, &[]);

        assert_eq!(
            unsigned_result,
            Err(UdpRendezvousValidationError::MissingSignature)
        );

        let mut zero_signature = rendezvous_set();
        zero_signature.signature = Some(UdpRendezvousSignature::new("device-1", vec![0; 64]));

        let zero_result = validate_udp_rendezvous_candidates(&zero_signature, 1_000, &[]);

        assert_eq!(
            zero_result,
            Err(UdpRendezvousValidationError::InvalidSignatureBytes)
        );
    }

    #[test]
    fn udp_nat_classifier_reports_missing_observations_as_unknown() {
        let assessment = classify_udp_nat(&[]);

        assert_eq!(assessment.kind, UdpNatKind::Unknown);
        assert_eq!(assessment.hairpin, UdpHairpinSupport::Unknown);
        assert_eq!(assessment.confidence, UdpNatConfidence::Low);
        assert_eq!(assessment.observed_public_addr, None);
        assert_eq!(assessment.caveat, "missing_endpoint_observation");
    }

    #[test]
    fn udp_nat_classifier_reports_blocked_when_probes_fail() {
        let assessment = classify_udp_nat(&[UdpEndpointObservation::blocked(
            socket_addr("10.0.0.10:49152"),
            socket_addr("203.0.113.7:3478"),
        )]);

        assert_eq!(assessment.kind, UdpNatKind::UdpBlocked);
        assert_eq!(assessment.hairpin, UdpHairpinSupport::Unknown);
        assert_eq!(assessment.confidence, UdpNatConfidence::High);
        assert_eq!(assessment.observed_public_addr, None);
        assert_eq!(assessment.caveat, "no_udp_probe_reached_rendezvous");
    }

    #[test]
    fn udp_nat_classifier_distinguishes_ipv6_direct_path() {
        let local = socket_addr("[2001:db8::10]:49152");
        let assessment = classify_udp_nat(&[UdpEndpointObservation::observed(
            local,
            socket_addr("[2001:db8::1]:3478"),
            local,
        )]);

        assert_eq!(assessment.kind, UdpNatKind::Ipv6Direct);
        assert_eq!(assessment.confidence, UdpNatConfidence::Medium);
        assert_eq!(assessment.observed_public_addr, Some(local));
        assert_eq!(assessment.caveat, "ipv6_endpoint_observed_directly");
    }

    #[test]
    fn udp_nat_classifier_reports_stable_mapping_as_likely_easy_nat() {
        let public = socket_addr("198.51.100.20:62000");
        let observations = [
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.10:49152"),
                socket_addr("203.0.113.7:3478"),
                public,
            )
            .with_hairpin_result(true),
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.10:49152"),
                socket_addr("203.0.113.8:3478"),
                public,
            ),
        ];

        let assessment = classify_udp_nat(&observations);

        assert_eq!(assessment.kind, UdpNatKind::LikelyEasyNat);
        assert_eq!(assessment.hairpin, UdpHairpinSupport::Supported);
        assert_eq!(assessment.confidence, UdpNatConfidence::High);
        assert_eq!(assessment.observed_public_addr, Some(public));
        assert_eq!(assessment.caveat, "stable_public_mapping_observed");
    }

    #[test]
    fn udp_nat_classifier_reports_multiple_mappings_as_hard_or_symmetric_nat() {
        let observations = [
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.10:49152"),
                socket_addr("203.0.113.7:3478"),
                socket_addr("198.51.100.20:62000"),
            )
            .with_hairpin_result(false),
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.10:49152"),
                socket_addr("203.0.113.8:3478"),
                socket_addr("198.51.100.21:62001"),
            ),
        ];

        let assessment = classify_udp_nat(&observations);

        assert_eq!(assessment.kind, UdpNatKind::HardOrSymmetricNat);
        assert_eq!(assessment.hairpin, UdpHairpinSupport::Unsupported);
        assert_eq!(assessment.confidence, UdpNatConfidence::High);
        assert_eq!(assessment.observed_public_addr, None);
        assert_eq!(assessment.caveat, "multiple_public_mappings_observed");
    }

    #[test]
    fn udp_nat_classifier_treats_multiple_local_endpoints_as_unknown() {
        let observations = [
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.10:49152"),
                socket_addr("203.0.113.7:3478"),
                socket_addr("198.51.100.20:62000"),
            ),
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.11:49153"),
                socket_addr("203.0.113.8:3478"),
                socket_addr("198.51.100.21:62001"),
            ),
        ];

        let assessment = classify_udp_nat(&observations);

        assert_eq!(assessment.kind, UdpNatKind::Unknown);
        assert_eq!(assessment.confidence, UdpNatConfidence::Low);
        assert_eq!(assessment.observed_public_addr, None);
        assert_eq!(assessment.caveat, "multiple_local_endpoints_observed");
    }

    #[test]
    fn udp_unconnected_portable_batch_send_receive() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let packets = [
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"one",
                },
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"two",
                },
            ];
            let sent = sender
                .send_batch_to_with_strategy(
                    &packets,
                    UdpSendBatchStrategy {
                        prefer_sendmmsg: false,
                        prefer_gso: false,
                        ..UdpSendBatchStrategy::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(sent.packets_processed, 2);
            assert_eq!(sent.bytes_processed, 6);
            assert!(sent.fallback_used);
            assert!(!sent.native_send_batch_used);
            assert!(!sent.gso_send_used);

            let received = receiver.recv_batch_from(2, 16).await.unwrap();
            assert_eq!(received.report.packets_processed, 2);
            assert_eq!(
                received
                    .packets
                    .iter()
                    .map(|packet| packet.payload.as_slice())
                    .collect::<Vec<_>>(),
                vec![b"one".as_slice(), b"two".as_slice()]
            );
        });
    }

    #[test]
    fn udp_connected_portable_batch_send_receive() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender.connect(receiver_addr).await.unwrap();
            let payloads = [b"one".as_slice(), b"two".as_slice()];

            let sent = sender
                .send_connected_batch_with_strategy(
                    &payloads,
                    UdpSendBatchStrategy {
                        prefer_sendmmsg: false,
                        prefer_gso: false,
                        ..UdpSendBatchStrategy::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(sent.packets_processed, 2);
            assert_eq!(sent.bytes_processed, 6);
            assert!(sent.fallback_used);
            assert!(!sent.native_send_batch_used);
            assert!(!sent.gso_send_used);

            let received = receiver.recv_batch_from(2, 16).await.unwrap();
            assert_eq!(received.report.packets_processed, 2);
            assert_eq!(
                received
                    .packets
                    .iter()
                    .map(|packet| packet.payload.as_slice())
                    .collect::<Vec<_>>(),
                vec![b"one".as_slice(), b"two".as_slice()]
            );
        });
    }

    #[test]
    fn udp_unconnected_batch_send_prefers_native_sendmmsg_on_supported_targets() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let packets = [
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"native-one",
                },
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"native-two",
                },
            ];
            let sent = sender
                .send_batch_to_with_strategy(
                    &packets,
                    UdpSendBatchStrategy {
                        prefer_gso: false,
                        ..UdpSendBatchStrategy::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(sent.packets_processed, 2);
            assert_eq!(
                sent.bytes_processed,
                b"native-one".len() + b"native-two".len()
            );

            let native = build_supports_native_sendmmsg();
            assert_eq!(sent.native_send_batch_used, native);
            assert!(!sent.gso_send_used);
            assert_eq!(sent.fallback_used, !native);

            let received = receiver.recv_batch_from(2, 32).await.unwrap();
            assert_eq!(received.report.packets_processed, 2);
            assert_eq!(
                received
                    .packets
                    .iter()
                    .map(|packet| packet.payload.as_slice())
                    .collect::<Vec<_>>(),
                vec![b"native-one".as_slice(), b"native-two".as_slice()]
            );
        });
    }

    #[test]
    fn udp_connected_batch_send_prefers_native_sendmmsg_on_supported_targets() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender.connect(receiver_addr).await.unwrap();

            let packets = [
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"native-one",
                },
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"native-two",
                },
            ];
            let sent = sender
                .send_batch_to_with_strategy(
                    &packets,
                    UdpSendBatchStrategy {
                        prefer_gso: false,
                        ..UdpSendBatchStrategy::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(sent.packets_processed, 2);
            assert_eq!(
                sent.bytes_processed,
                b"native-one".len() + b"native-two".len()
            );

            let native = build_supports_native_sendmmsg();
            assert_eq!(sent.native_send_batch_used, native);
            assert!(!sent.gso_send_used);
            assert_eq!(sent.fallback_used, !native);

            let received = receiver.recv_batch_from(2, 32).await.unwrap();
            assert_eq!(received.report.packets_processed, 2);
            assert_eq!(
                received
                    .packets
                    .iter()
                    .map(|packet| packet.payload.as_slice())
                    .collect::<Vec<_>>(),
                vec![b"native-one".as_slice(), b"native-two".as_slice()]
            );
        });
    }

    #[test]
    fn udp_connected_batch_send_strategy_can_disable_gso() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender.connect(receiver_addr).await.unwrap();

            let payloads = (0..4)
                .map(|_| vec![7u8; UDP_DEFAULT_GSO_SEGMENT_BYTES])
                .collect::<Vec<_>>();
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload,
                })
                .collect::<Vec<_>>();
            let sent = sender
                .send_batch_to_with_strategy(
                    &packets,
                    UdpSendBatchStrategy {
                        prefer_gso: false,
                        ..UdpSendBatchStrategy::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(sent.packets_processed, packets.len());
            assert_eq!(
                sent.bytes_processed,
                packets
                    .iter()
                    .map(|packet| packet.payload.len())
                    .sum::<usize>()
            );

            let native = build_supports_native_sendmmsg();
            assert_eq!(sent.native_send_batch_used, native);
            assert!(!sent.gso_send_used);
            assert_eq!(sent.fallback_used, !native);

            let received = receiver
                .recv_batch_from(packets.len(), UDP_DEFAULT_GSO_SEGMENT_BYTES)
                .await
                .unwrap();
            assert_eq!(received.report.packets_processed, packets.len());
        });
    }

    #[test]
    fn udp_unconnected_batch_send_uses_gso_for_fixed_size_payloads_on_supported_targets() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let payloads = (0..4)
                .map(|idx| vec![idx as u8; UDP_DEFAULT_GSO_SEGMENT_BYTES])
                .collect::<Vec<_>>();
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload,
                })
                .collect::<Vec<_>>();

            let sent = sender.send_batch_to(&packets).await.unwrap();
            assert_eq!(sent.packets_processed, packets.len());
            assert_eq!(
                sent.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * packets.len()
            );

            let native = build_supports_native_sendmmsg();
            assert_eq!(sent.native_send_batch_used, native);
            assert_eq!(sent.gso_send_used, build_supports_udp_gso());
            assert_eq!(sent.fallback_used, !native);

            let received = receiver
                .recv_batch_from(packets.len(), UDP_DEFAULT_GSO_SEGMENT_BYTES)
                .await
                .unwrap();
            assert_eq!(received.report.packets_processed, packets.len());
            assert_eq!(
                received.report.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * packets.len()
            );

            let mut received_payloads = received
                .packets
                .iter()
                .map(|packet| packet.payload.clone())
                .collect::<Vec<_>>();
            received_payloads.sort_by_key(|payload| payload[0]);
            assert_eq!(received_payloads, payloads);
        });
    }

    #[test]
    fn udp_connected_batch_send_uses_gso_for_fixed_size_payloads_on_supported_targets() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender.connect(receiver_addr).await.unwrap();

            let payloads = (0..4)
                .map(|idx| vec![idx as u8; UDP_DEFAULT_GSO_SEGMENT_BYTES])
                .collect::<Vec<_>>();
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload,
                })
                .collect::<Vec<_>>();

            let sent = sender.send_batch_to(&packets).await.unwrap();
            assert_eq!(sent.packets_processed, packets.len());
            assert_eq!(
                sent.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * packets.len()
            );

            let native = build_supports_native_sendmmsg();
            assert_eq!(sent.native_send_batch_used, native);
            assert_eq!(sent.gso_send_used, build_supports_udp_gso());
            assert_eq!(sent.fallback_used, !native);

            let received = receiver
                .recv_batch_from(packets.len(), UDP_DEFAULT_GSO_SEGMENT_BYTES)
                .await
                .unwrap();
            assert_eq!(received.report.packets_processed, packets.len());
            assert_eq!(
                received.report.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * packets.len()
            );

            let mut received_payloads = received
                .packets
                .iter()
                .map(|packet| packet.payload.clone())
                .collect::<Vec<_>>();
            received_payloads.sort_by_key(|payload| payload[0]);
            assert_eq!(received_payloads, payloads);
        });
    }

    #[test]
    fn udp_connected_payload_batch_send_uses_gso_for_fixed_size_payloads_on_supported_targets() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender.connect(receiver_addr).await.unwrap();

            let payloads = (0..4)
                .map(|idx| vec![idx as u8; UDP_DEFAULT_GSO_SEGMENT_BYTES])
                .collect::<Vec<_>>();
            let payload_refs = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();

            let sent = sender.send_connected_batch(&payload_refs).await.unwrap();
            assert_eq!(sent.packets_processed, payload_refs.len());
            assert_eq!(
                sent.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * payload_refs.len()
            );

            let native = build_supports_native_sendmmsg();
            assert_eq!(sent.native_send_batch_used, native);
            assert_eq!(sent.gso_send_used, build_supports_udp_gso());
            assert_eq!(sent.fallback_used, !native);

            let received = receiver
                .recv_batch_from(payload_refs.len(), UDP_DEFAULT_GSO_SEGMENT_BYTES)
                .await
                .unwrap();
            assert_eq!(received.report.packets_processed, payload_refs.len());
            assert_eq!(
                received.report.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * payload_refs.len()
            );

            let mut received_payloads = received
                .packets
                .iter()
                .map(|packet| packet.payload.clone())
                .collect::<Vec<_>>();
            received_payloads.sort_by_key(|payload| payload[0]);
            assert_eq!(received_payloads, payloads);
        });
    }

    /// Receive `count` datagrams of at most `max_bytes`, sorted by first byte.
    async fn recv_sorted_payloads(
        receiver: &mut UdpSocket,
        count: usize,
        max_bytes: usize,
    ) -> Vec<Vec<u8>> {
        let mut payloads = Vec::with_capacity(count);
        while payloads.len() < count {
            let batch = receiver
                .recv_batch_from(count - payloads.len(), max_bytes)
                .await
                .unwrap();
            payloads.extend(batch.packets.into_iter().map(|packet| packet.payload));
        }
        payloads.sort_by_key(|payload| payload[0]);
        payloads
    }

    // An ATP-RQ send window is UDP_MAX_GSO_SEGMENTS datagrams of up to
    // UDP_DEFAULT_GSO_SEGMENT_BYTES: 93,184 bytes, more than one UDP datagram
    // can carry. Planned as one super-packet, the kernel refused it with
    // EMSGSIZE, the batch fell back to plain sendmmsg, and the socket never
    // used GSO again.
    #[test]
    fn udp_batch_send_keeps_gso_for_a_full_rq_window() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            receiver
                .tune_buffers(UdpBufferConfig {
                    recv_buffer_bytes: Some(4 * 1024 * 1024),
                    send_buffer_bytes: None,
                })
                .unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let payloads = (0..UDP_MAX_GSO_SEGMENTS)
                .map(|idx| vec![idx as u8; UDP_DEFAULT_GSO_SEGMENT_BYTES])
                .collect::<Vec<_>>();
            let window_bytes = UDP_DEFAULT_GSO_SEGMENT_BYTES * payloads.len();
            let native = build_supports_native_sendmmsg();
            let gso = UdpSendAccelerationCapabilities::default().gso;

            let mut connected = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            connected.connect(receiver_addr).await.unwrap();
            let payload_refs = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let sent = connected.send_connected_batch(&payload_refs).await.unwrap();
            assert_eq!(sent.packets_processed, payloads.len());
            assert_eq!(sent.bytes_processed, window_bytes);
            assert_eq!(sent.native_send_batch_used, native);
            assert_eq!(sent.gso_send_used, build_supports_udp_gso());
            assert_eq!(sent.error, None);
            assert_eq!(connected.send_acceleration_capabilities().gso, gso);
            let received =
                recv_sorted_payloads(&mut receiver, payloads.len(), UDP_DEFAULT_GSO_SEGMENT_BYTES)
                    .await;
            assert_eq!(received, payloads);

            let mut unconnected = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload,
                })
                .collect::<Vec<_>>();
            let sent = unconnected.send_batch_to(&packets).await.unwrap();
            assert_eq!(sent.packets_processed, payloads.len());
            assert_eq!(sent.bytes_processed, window_bytes);
            assert_eq!(sent.native_send_batch_used, native);
            assert_eq!(sent.gso_send_used, build_supports_udp_gso());
            assert_eq!(sent.error, None);
            assert_eq!(unconnected.send_acceleration_capabilities().gso, gso);
            let received =
                recv_sorted_payloads(&mut receiver, payloads.len(), UDP_DEFAULT_GSO_SEGMENT_BYTES)
                    .await;
            assert_eq!(received, payloads);
        });
    }

    // Any refused first GSO send used to disable GSO for the socket's lifetime,
    // even an error that has nothing to do with GSO (here EACCES, a limited
    // broadcast without SO_BROADCAST; in practice also ECONNREFUSED left on a
    // connected socket by an earlier ICMP port-unreachable).
    #[test]
    fn udp_batch_send_keeps_gso_after_a_send_error_unrelated_to_gso() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let payloads = (0..4)
                .map(|idx| vec![idx as u8; UDP_DEFAULT_GSO_SEGMENT_BYTES])
                .collect::<Vec<_>>();
            let gso = UdpSendAccelerationCapabilities::default().gso;

            let broadcast = socket_addr("255.255.255.255:9");
            let refused = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: broadcast,
                    payload,
                })
                .collect::<Vec<_>>();
            assert!(sender.send_batch_to(&refused).await.is_err());
            assert_eq!(sender.send_acceleration_capabilities().gso, gso);

            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload,
                })
                .collect::<Vec<_>>();
            let sent = sender.send_batch_to(&packets).await.unwrap();
            assert_eq!(sent.packets_processed, payloads.len());
            assert_eq!(sent.gso_send_used, build_supports_udp_gso());
            let received =
                recv_sorted_payloads(&mut receiver, payloads.len(), UDP_DEFAULT_GSO_SEGMENT_BYTES)
                    .await;
            assert_eq!(received, payloads);
        });
    }

    #[test]
    fn udp_send_recv_from() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();

            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let payload = b"ping";

            let sent = client.send_to(payload, server_addr).await.unwrap();
            assert_eq!(sent, payload.len());

            let mut buf = [0u8; 16];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], payload);
            assert_eq!(peer, client.local_addr().unwrap());
        });
    }

    #[test]
    fn udp_connected_send_recv() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();

            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();

            server.connect(client_addr).await.unwrap();
            client.connect(server_addr).await.unwrap();

            let sent = client.send(b"hello").await.unwrap();
            assert_eq!(sent, 5);

            let mut buf = [0u8; 16];
            let n = server.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello");

            let sent = server.send(b"world").await.unwrap();
            assert_eq!(sent, 5);

            let n = client.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"world");
        });
    }

    #[test]
    fn udp_recv_stream_yields_datagram() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            client.send_to(b"stream", server_addr).await.unwrap();

            let mut stream = server.recv_stream(32);
            let item = stream.next().await.unwrap().unwrap();
            assert_eq!(item.0, b"stream");
        });
    }

    #[test]
    fn udp_recv_stream_zero_buffer_does_not_drop_nonempty_datagram() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            client.send_to(b"stream", server_addr).await.unwrap();

            let mut stream = server.recv_stream(0);
            let item = stream.next().await.unwrap().unwrap();
            assert_eq!(item.0, b"s");
        });
    }

    #[test]
    fn udp_peek_does_not_consume() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            client.send_to(b"peek", server_addr).await.unwrap();

            let mut buf = [0u8; 16];
            let (n, _) = server.peek_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"peek");

            let (n, _) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"peek");
        });
    }

    #[test]
    fn udp_recv_from_rejects_empty_buffer_without_consuming_datagram() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();

            client.send_to(b"ping", server_addr).await.unwrap();

            let mut empty = [];
            let err = server.recv_from(&mut empty).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

            let mut buf = [0u8; 16];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            assert_eq!(peer, client_addr);
        });
    }

    #[test]
    fn polled_batch_reports_sent_prefix_before_destination_error_without_replaying_it() {
        future::block_on(async {
            let peer = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let packets = [
                UdpOutboundDatagram {
                    dst_addr: peer.local_addr().unwrap(),
                    payload: b"first",
                },
                UdpOutboundDatagram {
                    dst_addr: "127.0.0.1:0".parse().unwrap(),
                    payload: b"second",
                },
            ];
            let task_cx = Context::from_waker(std::task::Waker::noop());
            let Poll::Ready(Ok(report)) = sender.poll_send_batch_to_with_strategy(
                &task_cx,
                &packets,
                UdpSendBatchStrategy::default(),
            ) else {
                panic!("first datagram should be committed")
            };
            assert_eq!(report.packets_processed, 1);
            assert_eq!(report.bytes_processed, b"first".len());
            assert!(
                report.error.is_none(),
                "progress precedes the next concrete error"
            );
            assert!(matches!(
                sender.poll_send_batch_to_with_strategy(
                    &task_cx,
                    &packets[1..],
                    UdpSendBatchStrategy::default()
                ),
                Poll::Ready(Err(_))
            ));
            let repaired = [UdpOutboundDatagram {
                dst_addr: peer.local_addr().unwrap(),
                payload: b"second",
            }];
            let Poll::Ready(Ok(report)) = sender.poll_send_batch_to_with_strategy(
                &task_cx,
                &repaired,
                UdpSendBatchStrategy::default(),
            ) else {
                panic!("repaired suffix should send")
            };
            assert_eq!(report.packets_processed, 1);
            let mut payload = [0u8; 16];
            for expected in [b"first".as_slice(), b"second".as_slice()] {
                let (length, source) = peer.recv_from(&mut payload).unwrap();
                assert_eq!(source, sender.local_addr().unwrap());
                assert_eq!(&payload[..length], expected);
            }
            peer.set_nonblocking(true).unwrap();
            assert_eq!(
                peer.recv_from(&mut payload).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        });
    }

    #[test]
    fn polled_receive_keeps_scratch_and_consumes_nothing_until_ready() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            let task_cx = Context::from_waker(std::task::Waker::noop());
            let mut spare = Vec::new();
            for _ in 0..4 {
                assert!(
                    receiver
                        .poll_recv_batch_from_reusing(&task_cx, 4, 64, &mut spare)
                        .is_pending()
                );
                assert_eq!(spare.len(), 1, "losing polls retain reusable scratch");
            }
            peer.send_to(b"after pending", receiver.local_addr().unwrap())
                .unwrap();
            let Poll::Ready(Ok(batch)) =
                receiver.poll_recv_batch_from_reusing(&task_cx, 4, 64, &mut spare)
            else {
                panic!("queued loopback packet must be ready")
            };
            assert_eq!(batch.report.packets_processed, 1);
            assert_eq!(batch.packets[0].payload, b"after pending");
            assert_eq!(spare.len(), 1);
            assert!(
                receiver
                    .poll_recv_batch_from_reusing(&task_cx, 4, 64, &mut spare)
                    .is_pending()
            );
        });
    }

    #[test]
    fn udp_mdns_multicast_tuple_matches_rfc6762() {
        let std_socket = StdUdpSocket::bind("0.0.0.0:0").expect("bind socket");
        let socket = UdpSocket::from_std(std_socket).expect("wrap socket");

        let mdns_group = Ipv4Addr::new(224, 0, 0, 251);
        let mdns_interface = Ipv4Addr::UNSPECIFIED;
        socket
            .join_multicast_v4(mdns_group, mdns_interface)
            .expect("join mDNS group");
        socket
            .leave_multicast_v4(mdns_group, mdns_interface)
            .expect("leave mDNS group");

        let mdns_socket = std::net::SocketAddrV4::new(mdns_group, 5353);
        assert_eq!(mdns_socket.to_string(), "224.0.0.251:5353");
    }

    #[test]
    fn udp_socket_registers_on_wouldblock() {
        // Create a socket pair
        let std_server = StdUdpSocket::bind("127.0.0.1:0").expect("bind server");
        std_server.set_nonblocking(true).expect("nonblocking");

        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut socket = UdpSocket::from_std(std_server).expect("wrap socket");
        let waker = noop_waker();
        let cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];

        // poll_recv_from should return Pending and register with reactor
        let poll = socket.poll_recv_from(&cx, &mut buf);
        assert!(matches!(poll, Poll::Pending));
        assert!(socket.registration.is_some());
    }

    #[test]
    fn udp_try_clone_creates_independent_socket() {
        future::block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let cloned = socket.try_clone().unwrap();

            // Both should have same local address
            assert_eq!(socket.local_addr().unwrap(), cloned.local_addr().unwrap());

            // Cloned socket should have no registration
            assert!(cloned.registration.is_none());
        });
    }

    #[cfg(windows)]
    #[test]
    fn udp_icmp_unreachable_does_not_poison_reusable_windows_socket() {
        future::block_on(async {
            let dead_probe = StdUdpSocket::bind("127.0.0.1:0").expect("reserve UDP port");
            let dead_addr = dead_probe.local_addr().expect("reserved UDP address");
            drop(dead_probe);

            let mut socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(dead_addr).await.unwrap();
            socket.send(b"closed-port probe").await.unwrap();

            let mut buf = [0_u8; 32];
            for _ in 0..50 {
                std::thread::sleep(std::time::Duration::from_millis(10));
                match socket.inner.recv(&mut buf) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!(
                        "closed UDP peer poisoned reusable Windows socket: {error} ({:?})",
                        error.raw_os_error()
                    ),
                    Ok(size) => panic!("unexpected {size}-byte datagram from closed UDP peer"),
                }
            }

            let receiver = StdUdpSocket::bind(dead_addr).expect("bind replacement UDP peer");
            receiver
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            socket.connect(dead_addr).await.unwrap();
            socket.send(b"recovered").await.unwrap();
            let (size, _) = receiver
                .recv_from(&mut buf)
                .expect("receive after ICMP probe");
            assert_eq!(&buf[..size], b"recovered");
        });
    }

    #[cfg(unix)]
    #[test]
    fn udp_from_std_forces_nonblocking_mode() {
        let std_socket = StdUdpSocket::bind("127.0.0.1:0").expect("bind socket");
        let socket = UdpSocket::from_std(std_socket).expect("wrap socket");
        let flags = fcntl(socket.inner.as_ref(), FcntlArg::F_GETFL).expect("read socket flags");
        let is_nonblocking = OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK);
        assert!(
            is_nonblocking,
            "UdpSocket::from_std should force nonblocking mode"
        );
    }

    #[test]
    fn udp_large_datagram() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // Send a larger datagram (8KB)
            let payload = vec![0xAB; 8192];
            let sent = client.send_to(&payload, server_addr).await.unwrap();
            assert_eq!(sent, 8192);

            let mut buf = vec![0u8; 16384];
            let (n, _) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 8192);
            assert!(buf[..n].iter().all(|&b| b == 0xAB));
        });
    }

    #[test]
    fn udp_cancelled_operations_return_interrupted_without_registration() {
        future::block_on(async {
            let mut poll_recv_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let poll_recv_addr = poll_recv_socket.local_addr().unwrap();

            let mut poll_send_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let poll_send_addr = poll_send_socket.local_addr().unwrap();

            poll_send_socket.connect(poll_recv_addr).await.unwrap();
            poll_recv_socket.connect(poll_send_addr).await.unwrap();

            let mut send_to_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer_addr = peer_socket.local_addr().unwrap();

            let connect_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let cx = Cx::for_testing();
            cx.set_cancel_requested(true);
            let _guard = Cx::set_current(Some(cx));

            let waker = noop_waker();
            let task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 16];

            let connect_err = connect_socket.connect(peer_addr).await.unwrap_err();
            assert_eq!(connect_err.kind(), io::ErrorKind::Interrupted);
            assert!(connect_socket.peer_addr().is_err());

            let send_to =
                send_to_socket.poll_send_to(&task_cx, b"ping", std::slice::from_ref(&peer_addr));
            assert!(matches!(
                send_to,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ));
            assert!(send_to_socket.registration.is_none());

            let recv_from = poll_recv_socket.poll_recv_from(&task_cx, &mut buf);
            assert!(matches!(
                recv_from,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ));
            assert!(poll_recv_socket.registration.is_none());

            let send = poll_send_socket.poll_send(&task_cx, b"hello");
            assert!(matches!(
                send,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ));
            assert!(poll_send_socket.registration.is_none());

            let recv = poll_recv_socket.poll_recv(&task_cx, &mut buf);
            assert!(matches!(
                recv,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ));
            assert!(poll_recv_socket.registration.is_none());

            let peek_from = poll_recv_socket.poll_peek_from(&task_cx, &mut buf);
            assert!(matches!(
                peek_from,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ));
            assert!(poll_recv_socket.registration.is_none());
        });
    }

    #[test]
    fn udp_dos_prevention() {
        future::block_on(async {
            let mut socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // Test recv_batch_from DoS prevention - packet_size limit
            let result = socket.recv_batch_from(1, UDP_MAX_PACKET_SIZE + 1).await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("packet_size"));
            assert!(err.to_string().contains("UDP_MAX_PACKET_SIZE"));

            // Test recv_batch_from DoS prevention - max_packets limit
            let result = socket.recv_batch_from(UDP_MAX_BATCH_SIZE + 1, 1024).await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("max_packets"));
            assert!(err.to_string().contains("UDP_MAX_BATCH_SIZE"));

            // Test RecvStream DoS prevention - buffer size is clamped
            let mut socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let stream = RecvStream::new(&mut socket, usize::MAX);
            // Buffer should be clamped to UDP_MAX_PACKET_SIZE, not usize::MAX
            assert_eq!(stream.buf.len(), UDP_MAX_PACKET_SIZE);

            let stream_small = RecvStream::new(&mut socket, 0);
            // Buffer should be at least 1 byte
            assert_eq!(stream_small.buf.len(), 1);

            let stream_normal = RecvStream::new(&mut socket, 512);
            // Normal size should pass through unchanged
            assert_eq!(stream_normal.buf.len(), 512);
        });
    }

    #[test]
    fn recv_batch_from_guard_byte_distinguishes_exact_from_truncated_datagrams() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();

            // 1. Send exact packet_size (64 bytes)
            let exact_payload = vec![0xAA; 64];
            sender.send_to(&exact_payload, receiver_addr).await.unwrap();

            // Receive with packet_size = 64
            let batch = receiver.recv_batch_from(1, 64).await.unwrap();
            assert_eq!(batch.packets.len(), 1);
            assert_eq!(batch.packets[0].payload.len(), 64);
            assert_eq!(batch.packets[0].payload, exact_payload);
            assert!(
                !batch.packets[0].possibly_truncated,
                "exact MTU packet must NOT be flagged as truncated"
            );

            // 2. Send oversized datagram (65 bytes) with packet_size = 64
            let oversized_payload = vec![0xBB; 65];
            sender
                .send_to(&oversized_payload, receiver_addr)
                .await
                .unwrap();

            let batch = receiver.recv_batch_from(1, 64).await.unwrap();
            assert_eq!(batch.packets.len(), 1);
            assert_eq!(batch.packets[0].payload.len(), 64);
            assert_eq!(batch.packets[0].payload, &oversized_payload[..64]);
            assert!(
                batch.packets[0].possibly_truncated,
                "oversized packet must be flagged as truncated"
            );
        });
    }

    /// GH#85: deterministic registration ownership checks complement the
    /// native loopback regressions; model readiness does not supply UDP data.
    #[cfg(unix)]
    mod gh85_runtime_handoff {
        use super::*;
        use crate::runtime::reactor::Reactor;
        use crate::runtime::reactor_model::{LabReactorModel, ReactorOperation};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Wake;
        use std::time::Duration;

        #[derive(Default)]
        struct WakeCount(AtomicUsize);

        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn counted_waker() -> (Arc<WakeCount>, Waker) {
            let count = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&count));
            (count, waker)
        }

        fn source() -> StdUdpSocket {
            let source = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            source.set_nonblocking(true).unwrap();
            assert_eq!(
                source.recv_from(&mut [0u8; 1]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            source
        }

        fn with_driver<T>(driver: &IoDriverHandle, poll: impl FnOnce() -> T) -> T {
            let ambient = Cx::new_with_observability(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(0, 0),
                Budget::INFINITE,
                None,
                Some(driver.clone()),
                None,
            );
            let _guard = Cx::set_current(Some(ambient));
            poll()
        }

        fn arm_on(
            registration: &mut ReactorRegistration,
            source: &StdUdpSocket,
            driver: &IoDriverHandle,
            waker: &Waker,
        ) -> io::Result<Armed> {
            with_driver(driver, || {
                registration.arm(source, Interest::READABLE, waker)
            })
        }

        fn arm_shared_on(
            registration: &parking_lot::Mutex<ReactorRegistration>,
            source: &StdUdpSocket,
            driver: &IoDriverHandle,
            owner: u64,
            waker: &Waker,
        ) {
            with_driver(driver, || {
                let waker = waker.clone();
                let (armed, stranded, displaced) =
                    registration
                        .lock()
                        .arm_shared(source, Interest::READABLE, owner, waker);
                drop(displaced);
                assert_eq!(armed.unwrap(), Armed::Parked);
                assert!(stranded.is_empty());
            });
        }

        struct SharedWake {
            registration: std::sync::Weak<parking_lot::Mutex<ReactorRegistration>>,
            count: Arc<WakeCount>,
        }

        impl Wake for SharedWake {
            fn wake(self: Arc<Self>) {
                let registration = self.registration.upgrade().unwrap();
                let registration = registration
                    .try_lock()
                    .expect("shared wake must not hold the registration lock");
                let waiters = registration.shared_waiters.as_ref().unwrap();
                assert!(
                    waiters.waiters.try_lock().is_some(),
                    "shared wake must not hold the waiter list lock"
                );
                self.count.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[test]
        fn driverless_context_retires_live_registration_when_fallback_is_unavailable() {
            let model = Arc::new(LabReactorModel::new());
            let driver = IoDriverHandle::new(model.clone());
            let source = source();
            let mut registration = ReactorRegistration::new();
            let (count, waker) = counted_waker();
            assert_eq!(
                arm_on(&mut registration, &source, &driver, &waker).unwrap(),
                Armed::Parked
            );
            let token = registration.as_ref().unwrap().token();

            // No Cx can mean a caller is driving this registration manually.
            // Preserve that path, including its token and readiness interest.
            let _manual = Cx::set_current(None);
            assert_eq!(
                registration
                    .arm(&source, Interest::READABLE, &waker)
                    .unwrap(),
                Armed::Parked
            );
            assert_eq!(registration.as_ref().unwrap().token(), token);
            assert_eq!(model.fault_stats(ReactorOperation::Register).attempts, 1);
            model
                .schedule_ready(token, Interest::READABLE, Duration::ZERO)
                .unwrap();

            // A present, driverless Cx is different: its executor cannot
            // service this still-live dispatcher. Even failed fallback startup
            // must leave the caller able to re-poll instead of parked on it.
            let ambient = Cx::new_with_observability(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(0, 0),
                Budget::INFINITE,
                None,
                None,
                None,
            );
            let _current = Cx::set_current(Some(ambient));
            let _withheld = fallback_io_test_hooks::WithholdFallbackDriver::new();
            assert!(registration_needs_migration(
                registration.as_ref().unwrap(),
                false
            ));
            assert!(
                !registration_needs_migration(registration.as_ref().unwrap(), true),
                "an existing fallback registration already has the right owner"
            );
            assert_eq!(
                registration
                    .arm(&source, Interest::READABLE, &waker)
                    .unwrap(),
                Armed::SelfWake
            );
            assert!(registration.is_none());
            assert!(driver.is_empty());
            assert_eq!(model.registration_count(), 0);
            assert_eq!(model.fault_stats(ReactorOperation::Deregister).attempts, 1);
            assert_eq!(
                driver.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(),
                0
            );
            assert_eq!(count.0.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn departing_shared_waiter_notifies_survivor_to_rebind() {
            let old_model = Arc::new(LabReactorModel::new());
            let idle_model = Arc::new(LabReactorModel::new());
            let old_driver = IoDriverHandle::new(old_model.clone());
            let idle_driver = IoDriverHandle::new(idle_model.clone());
            let source = source();
            let registration = Arc::new(parking_lot::Mutex::new(ReactorRegistration::new()));
            let survivor = next_shared_waiter_owner();
            let departing = next_shared_waiter_owner();
            let survivor_count = Arc::new(WakeCount::default());
            let survivor_waker = Waker::from(Arc::new(SharedWake {
                registration: Arc::downgrade(&registration),
                count: Arc::clone(&survivor_count),
            }));
            let (departing_count, departing_waker) = counted_waker();

            arm_shared_on(
                &registration,
                &source,
                &old_driver,
                survivor,
                &survivor_waker,
            );
            arm_shared_on(
                &registration,
                &source,
                &idle_driver,
                departing,
                &departing_waker,
            );
            assert_eq!(registration.lock().shared_waiter_count(), 2);
            assert!(
                registration
                    .lock()
                    .as_ref()
                    .unwrap()
                    .belongs_to(&idle_driver)
            );
            assert_eq!(survivor_count.0.load(Ordering::SeqCst), 0);
            assert_eq!(departing_count.0.load(Ordering::SeqCst), 0);

            // Completing or cancelling the latest caller leaves its runtime
            // alive but idle. Departure must notify its peer without a turn
            // of that runtime; migration itself must not bounce peer wakes.
            let (removed, survivors) = registration.lock().forget_shared(departing);
            assert!(removed.is_some());
            drop(removed);
            assert_eq!(survivors.len(), 1);
            assert_eq!(registration.lock().shared_waiter_count(), 0);
            assert_eq!(survivor_count.0.load(Ordering::SeqCst), 0);
            for waiter in survivors {
                waiter.wake();
            }
            assert_eq!(survivor_count.0.load(Ordering::SeqCst), 1);
            assert_eq!(departing_count.0.load(Ordering::SeqCst), 0);
            let (removed, survivors) = registration.lock().forget_shared(departing);
            assert!(removed.is_none() && survivors.is_empty());

            arm_shared_on(
                &registration,
                &source,
                &old_driver,
                survivor,
                &survivor_waker,
            );
            let token = registration.lock().as_ref().unwrap().token();
            assert!(
                registration
                    .lock()
                    .as_ref()
                    .unwrap()
                    .belongs_to(&old_driver)
            );
            assert_eq!(idle_model.registration_count(), 0);
            assert!(idle_driver.is_empty());
            assert_eq!(survivor_count.0.load(Ordering::SeqCst), 1);
            old_model.set_ready(token, Interest::READABLE).unwrap();
            assert_eq!(
                old_driver
                    .turn_with(Some(Duration::ZERO), |_, _| {})
                    .unwrap(),
                1
            );
            assert_eq!(survivor_count.0.load(Ordering::SeqCst), 2);
            assert_eq!(departing_count.0.load(Ordering::SeqCst), 0);
            assert_eq!(registration.lock().shared_waiter_count(), 0);
            registration.lock().clear();
            assert_eq!(old_model.registration_count(), 0);
            assert!(old_driver.is_empty());
        }

        #[test]
        fn repeated_live_handoffs_discard_queued_old_readiness() {
            let models = [
                Arc::new(LabReactorModel::new()),
                Arc::new(LabReactorModel::new()),
            ];
            let drivers = [
                IoDriverHandle::new(models[0].clone()),
                IoDriverHandle::new(models[1].clone()),
            ];
            let source = source();
            let mut registration = ReactorRegistration::new();
            let (mut previous_count, first_waker) = counted_waker();
            assert_eq!(
                arm_on(&mut registration, &source, &drivers[0], &first_waker).unwrap(),
                Armed::Parked
            );
            let mut current = 0;

            // Both owners remain alive throughout every transfer. No turn of
            // the previous owner is needed to establish the new registration.
            for _ in 0..6 {
                let next = 1 - current;
                let old_token = registration.as_ref().unwrap().token();
                let old_wakes = previous_count.0.load(Ordering::SeqCst);
                models[current]
                    .schedule_ready(old_token, Interest::READABLE, Duration::ZERO)
                    .unwrap();
                assert_eq!(
                    models[current].next_event_time(),
                    Some(models[current].now())
                );
                let (next_count, next_waker) = counted_waker();
                assert_eq!(
                    arm_on(&mut registration, &source, &drivers[next], &next_waker).unwrap(),
                    Armed::Parked
                );
                let live = registration.as_ref().unwrap();
                assert!(live.belongs_to(&drivers[next]));
                assert!(!registration.on_fallback());
                assert_eq!(models[current].registration_count(), 0);
                assert_eq!(drivers[current].waker_count(), 0);
                assert_eq!(
                    models[current].is_armed(old_token).unwrap_err().kind(),
                    io::ErrorKind::NotFound
                );
                assert_eq!(
                    drivers[current]
                        .turn_with(Some(Duration::ZERO), |_, _| {})
                        .unwrap(),
                    0
                );
                assert_eq!(previous_count.0.load(Ordering::SeqCst), old_wakes);
                assert_eq!(next_count.0.load(Ordering::SeqCst), 0);
                let token = live.token();
                assert!(models[next].is_armed(token).unwrap());
                models[next].set_ready(token, Interest::READABLE).unwrap();
                assert_eq!(
                    drivers[next]
                        .turn_with(Some(Duration::ZERO), |_, _| {})
                        .unwrap(),
                    1
                );
                assert_eq!(next_count.0.load(Ordering::SeqCst), 1);
                assert_eq!(previous_count.0.load(Ordering::SeqCst), old_wakes);
                models[next].clear_ready(token, Interest::READABLE).unwrap();
                previous_count = next_count;
                current = next;
            }
            registration.clear();
            assert!(models.iter().all(|model| model.registration_count() == 0));
            assert!(drivers.iter().all(IoDriverHandle::is_empty));
        }

        #[test]
        fn shared_runtime_participants_rearm_without_replacing_the_token() {
            let model = Arc::new(LabReactorModel::new());
            let first = IoDriverHandle::new(model.clone());
            let second = first.for_runtime();
            let source = source();
            let mut registration = ReactorRegistration::new();
            let (old_count, old_waker) = counted_waker();
            let (new_count, new_waker) = counted_waker();
            assert_eq!(
                arm_on(&mut registration, &source, &first, &old_waker).unwrap(),
                Armed::Parked
            );
            let token = registration.as_ref().unwrap().token();
            assert_eq!(
                arm_on(&mut registration, &source, &second, &new_waker).unwrap(),
                Armed::Parked
            );
            let live = registration.as_ref().unwrap();
            assert_eq!(live.token(), token);
            assert!(live.belongs_to(&first) && live.belongs_to(&second));
            assert_eq!(model.fault_stats(ReactorOperation::Register).attempts, 1);
            assert_eq!(model.fault_stats(ReactorOperation::Deregister).attempts, 0);
            assert_eq!(model.registration_count(), 1);
            model.set_ready(token, Interest::READABLE).unwrap();
            assert_eq!(
                second.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(),
                1
            );
            assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
            assert_eq!(new_count.0.load(Ordering::SeqCst), 1);
            registration.clear();
            assert_eq!(model.registration_count(), 0);
            assert!(first.is_empty() && second.is_empty());
        }

        #[test]
        fn failed_replacement_leaves_no_old_registration_and_retries_new_driver() {
            let old_model = Arc::new(LabReactorModel::new());
            let new_model = Arc::new(LabReactorModel::new());
            let old_driver = IoDriverHandle::new(old_model.clone());
            let new_driver = IoDriverHandle::new(new_model.clone());
            let source = source();
            let mut registration = ReactorRegistration::new();
            let (old_count, old_waker) = counted_waker();
            let (new_count, new_waker) = counted_waker();
            assert_eq!(
                arm_on(&mut registration, &source, &old_driver, &old_waker).unwrap(),
                Armed::Parked
            );
            let old_token = registration.as_ref().unwrap().token();
            old_model
                .schedule_ready(old_token, Interest::READABLE, Duration::ZERO)
                .unwrap();
            new_model
                .fail_next(
                    ReactorOperation::Register,
                    None,
                    io::ErrorKind::PermissionDenied,
                )
                .unwrap();

            assert_eq!(
                arm_on(&mut registration, &source, &new_driver, &new_waker)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(registration.is_none());
            assert_eq!(old_model.registration_count(), 0);
            assert_eq!(new_model.registration_count(), 0);
            assert!(old_driver.is_empty() && new_driver.is_empty());
            assert_eq!(
                old_model.fault_stats(ReactorOperation::Deregister).attempts,
                1
            );
            assert_eq!(
                new_model
                    .fault_stats(ReactorOperation::Register)
                    .injected_failures,
                1
            );
            assert_eq!(
                old_driver
                    .turn_with(Some(Duration::ZERO), |_, _| {})
                    .unwrap(),
                0
            );
            assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
            assert_eq!(new_count.0.load(Ordering::SeqCst), 0);
            let failed_token = new_model.last_failure().unwrap().token.unwrap();

            assert_eq!(
                arm_on(&mut registration, &source, &new_driver, &new_waker).unwrap(),
                Armed::Parked
            );
            let live = registration.as_ref().unwrap();
            assert!(live.belongs_to(&new_driver));
            assert_ne!(live.token(), failed_token);
            assert_eq!(
                new_model.fault_stats(ReactorOperation::Register).attempts,
                2
            );
            new_model
                .set_ready(live.token(), Interest::READABLE)
                .unwrap();
            assert_eq!(
                new_driver
                    .turn_with(Some(Duration::ZERO), |_, _| {})
                    .unwrap(),
                1
            );
            assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
            assert_eq!(new_count.0.load(Ordering::SeqCst), 1);
            registration.clear();
            assert_eq!(new_model.registration_count(), 0);
            assert!(old_driver.is_empty() && new_driver.is_empty());
        }
    }

    /// GH#67 (asupersync-t64ggs): driverless UDP polls park on the
    /// process-global fallback I/O driver instead of self-waking.
    #[cfg(not(target_arch = "wasm32"))]
    mod gh67_fallback_io_driver {
        use super::*;
        use crate::net::udp::fallback_io_test_support::signal_waker;
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        fn bound_socket() -> UdpSocket {
            let std_socket = StdUdpSocket::bind("127.0.0.1:0").expect("bind");
            UdpSocket::from_std(std_socket).expect("wrap socket")
        }

        /// The defect: with no I/O driver on the current `Cx`, a `WouldBlock`
        /// poll re-woke its own waker synchronously, so an executor re-polled
        /// in a hot loop. The fixed path must (1) return `Pending` without any
        /// wake, (2) stay silent while the fd is idle, and (3) wake exactly
        /// once when a datagram arrives, from the fallback reactor pump.
        #[test]
        fn poll_recv_without_io_driver_parks_until_datagram_arrives() {
            assert!(
                Cx::current().is_none(),
                "test must run without an ambient Cx"
            );
            let mut socket = bound_socket();
            let local_addr = socket.local_addr().expect("local addr");
            let peer = StdUdpSocket::bind("127.0.0.1:0").expect("bind peer");
            let (signal, waker, rx) = signal_waker();
            let task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 64];

            assert!(matches!(
                socket.poll_recv_from(&task_cx, &mut buf),
                Poll::Pending
            ));
            assert_eq!(
                signal.hits.load(Ordering::SeqCst),
                0,
                "driverless poll must park, not self-wake (GH#67)"
            );
            assert!(
                socket.registration.on_fallback(),
                "driverless poll registers with the process-global fallback I/O driver"
            );
            assert!(
                rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "no wake may arrive while the socket is idle"
            );
            assert_eq!(signal.hits.load(Ordering::SeqCst), 0);

            peer.send_to(b"wake", local_addr).expect("send datagram");
            rx.recv_timeout(Duration::from_secs(5))
                .expect("fallback reactor pump delivers the readiness wake");
            assert_eq!(signal.hits.load(Ordering::SeqCst), 1);

            match socket.poll_recv_from(&task_cx, &mut buf) {
                Poll::Ready(Ok((len, from))) => {
                    assert_eq!(&buf[..len], b"wake");
                    assert_eq!(from, peer.local_addr().expect("peer addr"));
                }
                other => panic!("expected the datagram after the wake, got {other:?}"),
            }
        }

        /// Re-arming a fallback registration after it fired must deliver the
        /// next readiness wake too (oneshot reactor interest is re-armed per
        /// poll), and a second poll while idle must again stay silent.
        #[test]
        fn fallback_registration_rearms_after_each_wake() {
            assert!(Cx::current().is_none());
            let mut socket = bound_socket();
            let local_addr = socket.local_addr().expect("local addr");
            let peer = StdUdpSocket::bind("127.0.0.1:0").expect("bind peer");
            let (signal, waker, rx) = signal_waker();
            let task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 64];

            for round in 1..=3u8 {
                assert!(matches!(
                    socket.poll_recv_from(&task_cx, &mut buf),
                    Poll::Pending
                ));
                assert!(
                    rx.recv_timeout(Duration::from_millis(100)).is_err(),
                    "round {round}: idle socket must not wake"
                );
                peer.send_to(&[round], local_addr).expect("send datagram");
                rx.recv_timeout(Duration::from_secs(5))
                    .unwrap_or_else(|_| panic!("round {round}: readiness wake never arrived"));
                match socket.poll_recv_from(&task_cx, &mut buf) {
                    Poll::Ready(Ok((1, _))) => assert_eq!(buf[0], round),
                    other => panic!("round {round}: expected datagram, got {other:?}"),
                }
            }
            assert_eq!(signal.hits.load(Ordering::SeqCst), 3);
        }

        /// A socket parked on the fallback driver is handed to the ambient
        /// driver as soon as it is polled under a `Cx` that carries one.
        #[test]
        fn fallback_registration_migrates_to_ambient_io_driver() {
            assert!(Cx::current().is_none());
            let mut socket = bound_socket();
            let waker = noop_waker();
            let task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 8];

            assert!(matches!(
                socket.poll_recv_from(&task_cx, &mut buf),
                Poll::Pending
            ));
            assert!(socket.registration.on_fallback());

            let driver = IoDriverHandle::new(Arc::new(LabReactor::new()));
            assert_eq!(driver.waker_count(), 0);
            let ambient = Cx::new_with_observability(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(0, 0),
                Budget::INFINITE,
                None,
                Some(driver.clone()),
                None,
            );
            let _guard = Cx::set_current(Some(ambient));

            assert!(matches!(
                socket.poll_recv_from(&task_cx, &mut buf),
                Poll::Pending
            ));
            assert!(
                !socket.registration.on_fallback(),
                "ambient driver must take over the registration"
            );
            assert!(socket.registration.is_some());
            assert_eq!(
                driver.waker_count(),
                1,
                "the ambient driver now owns the socket's readiness waker"
            );

            // Re-arming under the ambient driver keeps it there.
            assert!(matches!(
                socket.poll_recv_from(&task_cx, &mut buf),
                Poll::Pending
            ));
            assert!(!socket.registration.on_fallback());
            assert_eq!(driver.waker_count(), 1);
        }

        /// One pump serves the whole process: repeated lookups return the same
        /// driver, so driverless sockets never spawn a thread each.
        #[test]
        fn global_fallback_io_driver_is_process_shared() {
            let first = global_fallback_io_driver().expect("fallback I/O driver on this target");
            let second = global_fallback_io_driver().expect("fallback I/O driver on this target");
            assert!(std::ptr::eq(first, second));
        }

        /// dofi11 LOW 4: a failed start of the fallback driver was cached as
        /// `None` for the life of the process, so one transient `EMFILE` left
        /// every driverless socket on the self-wake hot loop. It is retried
        /// now, with the calls between attempts doubling, and a started
        /// driver is never started again.
        #[test]
        fn a_failed_fallback_driver_start_is_retried_with_backoff() {
            let cell: &'static OnceLock<GlobalFallbackIoDriver> =
                Box::leak(Box::new(OnceLock::new()));
            let start = FallbackIoStarter::new();
            let attempts = std::cell::Cell::new(0_u32);
            let failing = || {
                attempts.set(attempts.get() + 1);
                Err(io::Error::other("no reactor backend"))
            };
            let mut attempted_at = Vec::new();
            for call in 1..=30 {
                let before = attempts.get();
                assert!(fallback_io_driver_from(cell, &start, failing).is_none());
                if attempts.get() > before {
                    attempted_at.push(call);
                }
            }
            assert_eq!(
                attempted_at,
                vec![1, 3, 7, 15],
                "attempts 2, 4 and 8 calls apart"
            );

            let succeeding = || {
                Ok(GlobalFallbackIoDriver {
                    driver: IoDriverHandle::new(Arc::new(LabReactor::new())),
                })
            };
            let mut call = 30;
            let started = loop {
                call += 1;
                if let Some(driver) = fallback_io_driver_from(cell, &start, succeeding) {
                    break driver;
                }
            };
            assert_eq!(
                call, 31,
                "the attempt 16 calls after the last failure starts it"
            );
            let again = fallback_io_driver_from(cell, &start, || {
                panic!("a started driver is not started again")
            })
            .expect("the started driver");
            assert!(std::ptr::eq(started, again));

            let mut capped = FallbackIoStart {
                failures: 64,
                calls_since_failure: 0,
            };
            assert!((1..FALLBACK_IO_MAX_RETRY_SPACING).all(|_| !capped.attempt_due()));
            assert!(
                capped.attempt_due(),
                "attempts stay at most 4096 calls apart"
            );

            // A target without a reactor backend (`Unsupported`) is tried once:
            // later calls return `None` without the lock or another attempt.
            let unsupported_cell: &'static OnceLock<GlobalFallbackIoDriver> =
                Box::leak(Box::new(OnceLock::new()));
            let unsupported_start = FallbackIoStarter::new();
            let unsupported_attempts = std::cell::Cell::new(0_u32);
            let unsupported = || {
                unsupported_attempts.set(unsupported_attempts.get() + 1);
                Err(io::Error::from(io::ErrorKind::Unsupported))
            };
            for _ in 0..10_000 {
                assert!(
                    fallback_io_driver_from(unsupported_cell, &unsupported_start, unsupported)
                        .is_none()
                );
            }
            assert_eq!(
                unsupported_attempts.get(),
                1,
                "an unsupported start is final"
            );
            assert!(
                !unsupported_start.state.is_locked(),
                "the start lock is free"
            );
        }

        /// The GH#67 follow-up probe reports what the fallback driver did for
        /// a driverless socket: a registration on the first idle poll, a
        /// re-arm on every later idle poll, and a dispatched wake per
        /// datagram. ATP's wait diagnostics use it to separate "no datagram
        /// reached the socket" from "the socket was never re-polled after its
        /// wake". Counters are process-global (other tests run concurrently),
        /// so every delta is a lower bound.
        #[test]
        fn fallback_probe_counts_registration_rearm_and_dispatch() {
            assert!(Cx::current().is_none());
            let mut socket = bound_socket();
            let local_addr = socket.local_addr().expect("local addr");
            let peer = StdUdpSocket::bind("127.0.0.1:0").expect("bind peer");
            let (_signal, waker, rx) = signal_waker();
            let task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 64];

            let before = fallback_io_driver_probe().unwrap_or_default();
            assert!(matches!(
                socket.poll_recv_from(&task_cx, &mut buf),
                Poll::Pending
            ));
            let registered =
                fallback_io_driver_probe().expect("driverless poll starts the fallback driver");
            assert!(
                registered.fallback_registrations > before.fallback_registrations,
                "idle poll registers on the fallback driver: {registered:?} vs {before:?}"
            );
            assert!(registered.registrations > before.registrations);

            assert!(matches!(
                socket.poll_recv_from(&task_cx, &mut buf),
                Poll::Pending
            ));
            let rearmed = fallback_io_driver_probe().expect("probe");
            assert!(
                rearmed.fallback_rearms > registered.fallback_rearms,
                "second idle poll re-arms the fallback registration: {rearmed:?}"
            );
            assert_eq!(
                rearmed.fallback_self_wakes, registered.fallback_self_wakes,
                "a parked poll never takes the legacy self-wake path"
            );

            peer.send_to(b"probe", local_addr).expect("send datagram");
            rx.recv_timeout(Duration::from_secs(5))
                .expect("fallback reactor pump delivers the readiness wake");
            let woken = fallback_io_driver_probe().expect("probe");
            assert!(
                woken.wakers_dispatched > rearmed.wakers_dispatched,
                "the pump dispatched the socket's wake: {woken:?} vs {rearmed:?}"
            );
            assert!(woken.events_received > rearmed.events_received);
            assert!(woken.polls > rearmed.polls);
            assert!(matches!(
                socket.poll_recv_from(&task_cx, &mut buf),
                Poll::Ready(Ok((5, _)))
            ));
        }
    }
