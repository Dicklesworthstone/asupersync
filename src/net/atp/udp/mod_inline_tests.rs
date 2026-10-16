    use super::*;
    use crate::test_utils::run_test_with_cx;

    #[test]
    fn config_rejects_zero_limits() {
        assert!(
            AtpUdpSocketConfig {
                max_packet_size: 0,
                ..AtpUdpSocketConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            AtpUdpSocketConfig {
                max_send_batch: 0,
                ..AtpUdpSocketConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            AtpUdpSocketConfig {
                max_recv_batch: 0,
                ..AtpUdpSocketConfig::default()
            }
            .validate()
            .is_err()
        );
    }

    // br-asupersync-vs1vdk U5: v0.4.3 accepted any non-zero max_send_batch
    // (send_batch_to splits a large batch itself); fb479e039 refused values
    // above UDP_MAX_BATCH_SIZE at bind.
    #[test]
    fn config_accepts_a_send_batch_above_one_kernel_batch() {
        assert!(
            AtpUdpSocketConfig {
                max_send_batch: UDP_MAX_BATCH_SIZE * 2,
                ..AtpUdpSocketConfig::default()
            }
            .validate()
            .is_ok()
        );
    }

    // br-asupersync-vs1vdk U4: an oversized packet in a later chunk was
    // refused after the earlier chunks had been sent, and the caller got only
    // the error: a retry sent those packets twice.
    #[test]
    fn send_packets_refuses_an_oversized_packet_before_sending_any() {
        run_test_with_cx(|cx| async move {
            let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
            receiver
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .expect("receiver timeout");
            let receiver_addr = receiver.local_addr().expect("receiver address");
            let mut socket = AtpUdpSocket::bind(
                &cx,
                "127.0.0.1:0",
                AtpUdpSocketConfig {
                    max_packet_size: 64,
                    max_send_batch: 2,
                    ..AtpUdpSocketConfig::default()
                },
            )
            .await
            .expect("bind ATP socket");
            let small = [7_u8; 8];
            let large = [7_u8; 100];
            let packets = [
                AtpUdpPacket {
                    dst_addr: receiver_addr,
                    payload: &small,
                },
                AtpUdpPacket {
                    dst_addr: receiver_addr,
                    payload: &small,
                },
                AtpUdpPacket {
                    dst_addr: receiver_addr,
                    payload: &large,
                },
            ];
            let error = socket
                .send_packets(&cx, &packets)
                .await
                .expect_err("an oversized packet is refused");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let mut buf = [0_u8; 128];
            assert!(
                receiver.recv_from(&mut buf).is_err(),
                "nothing was sent before the refusal"
            );
        });
    }

    // br-asupersync-vs1vdk U3: poll_recv_from did not check the endpoint
    // generation, so a handle from before a close and rebind took the new
    // endpoint's datagram (and replaced its receive waker).
    #[test]
    fn a_stale_lab_handle_cannot_receive_for_a_rebound_endpoint() {
        run_test_with_cx(|cx| async move {
            let network = LabAtpUdpNetwork::with_queue_capacity(4);
            let sender_addr: SocketAddr = "127.0.0.1:42021".parse().expect("sender address");
            let addr: SocketAddr = "127.0.0.1:42022".parse().expect("rebound address");
            let mut sender = network.bind(sender_addr).expect("bind sender");
            let mut stale = network.bind(addr).expect("bind first owner");
            stale.close();
            let _rebound = network.bind(addr).expect("rebind closed address");
            sender
                .send_to(&cx, b"for the rebound owner", addr)
                .await
                .expect("enqueue lab datagram");

            let mut buf = [0_u8; 64];
            let polled = stale.poll_recv_from(&Context::from_waker(Waker::noop()), &mut buf);
            assert!(
                matches!(polled, Poll::Ready(Err(ref error)) if error.kind() == io::ErrorKind::NotConnected),
                "{polled:?}"
            );
            assert_eq!(
                network.queued_datagrams(addr),
                Some(1),
                "the datagram stays queued for the rebound endpoint"
            );
        });
    }

    #[test]
    fn default_config_batches_one_udp_gso_window() {
        let config = AtpUdpSocketConfig::default();

        assert_eq!(ATP_UDP_DEFAULT_BATCH_SIZE, UDP_MAX_GSO_SEGMENTS);
        assert_eq!(config.max_send_batch, UDP_MAX_GSO_SEGMENTS);
        assert_eq!(config.max_recv_batch, UDP_MAX_GSO_SEGMENTS);
    }

    #[test]
    fn lab_network_close_discards_packets_and_allows_rebind() {
        run_test_with_cx(|cx| async move {
            let network = LabAtpUdpNetwork::with_queue_capacity(2);
            let sender_addr: SocketAddr = "127.0.0.1:42001".parse().expect("sender address");
            let receiver_addr: SocketAddr = "127.0.0.1:42002".parse().expect("receiver address");
            let mut sender = network.bind(sender_addr).expect("bind sender");
            let receiver = network.bind(receiver_addr).expect("bind receiver");

            sender
                .send_to(&cx, b"queued-before-close", receiver_addr)
                .await
                .expect("enqueue lab datagram");
            assert_eq!(network.queued_datagrams(receiver_addr), Some(1));
            drop(receiver);
            assert_eq!(network.queued_datagrams(receiver_addr), Some(0));
            assert!(
                network
                    .set_source_policy(receiver_addr, LabUdpLinkPolicy::default())
                    .is_err(),
                "a closed source must refuse policy changes"
            );

            let rebound = network.bind(receiver_addr).expect("rebind closed address");
            assert_eq!(rebound.local_addr(), receiver_addr);
            assert_eq!(
                network.source_stats(receiver_addr),
                Some(LabUdpLinkStats::default())
            );
        });
    }

    #[test]
    fn bind_reports_profile_and_doctor_outputs() {
        run_test_with_cx(|cx| async move {
            let socket = AtpUdpSocket::bind(
                &cx,
                "127.0.0.1:0",
                AtpUdpSocketConfig {
                    buffers: UdpBufferConfig {
                        recv_buffer_bytes: Some(16 * 1024),
                        send_buffer_bytes: Some(16 * 1024),
                    },
                    ..AtpUdpSocketConfig::default()
                },
            )
            .await
            .expect("bind ATP UDP socket");

            assert_eq!(socket.profile().source, "native-udp");
            assert!(socket.doctor_json().get("local_addr").is_some());
            assert!(socket.doctor_human().contains("udp local="));
        });
    }

    // capabilities() reported every IPv6 socket's dual-stack support as
    // Unknown, so a bind that required it always failed, even on a [::]
    // socket with IPV6_V6ONLY off (the Linux default) that does carry IPv4.
    #[test]
    fn bind_requiring_dual_stack_receives_ipv4_on_an_ipv6_socket() {
        if std::net::UdpSocket::bind("[::]:0").is_err() {
            eprintln!("skipped: this host has no IPv6");
            return;
        }
        run_test_with_cx(|cx| async move {
            let mut socket = AtpUdpSocket::bind(
                &cx,
                "[::]:0",
                AtpUdpSocketConfig {
                    require_dual_stack: true,
                    ..AtpUdpSocketConfig::default()
                },
            )
            .await
            .expect("a [::] socket with IPV6_V6ONLY off is dual-stack");
            assert_eq!(
                socket.profile().capabilities.dual_stack,
                UdpCapability::Supported
            );

            let port = socket.profile().local_addr.port();
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind IPv4 sender");
            sender
                .send_to(b"over ipv4", ("127.0.0.1", port))
                .expect("send to the dual-stack socket");
            let batch = socket.recv_packets(&cx).await.expect("receive");
            assert_eq!(batch.packets.len(), 1);
            assert_eq!(batch.packets[0].payload, b"over ipv4");
        });
    }

    #[test]
    fn lab_replay_handles_loss_reorder_truncation_stale_error_and_close() {
        run_test_with_cx(|cx| async move {
            let src_a = "127.0.0.1:10001".parse().unwrap();
            let src_b = "127.0.0.1:10002".parse().unwrap();
            let mut lab = LabAtpUdpSocket::default();
            lab.push_event(LabUdpEvent::Deliver {
                src_addr: src_a,
                payload: b"first".to_vec(),
                possibly_truncated: false,
            });
            lab.push_event(LabUdpEvent::Drop);
            lab.push_event(LabUdpEvent::Deliver {
                src_addr: src_b,
                payload: b"second".to_vec(),
                possibly_truncated: true,
            });
            lab.push_event(LabUdpEvent::StaleReady);
            assert!(lab.reorder(0, 2));

            let batch = lab.recv_available(&cx, 4).expect("replay lab UDP");
            assert_eq!(batch.packets.len(), 2);
            assert_eq!(batch.packets[0].src_addr, src_b);
            assert!(batch.packets[0].possibly_truncated);
            assert_eq!(batch.packets[1].src_addr, src_a);

            lab.push_event(LabUdpEvent::SocketError("boom".to_string()));
            let err = lab.recv_available(&cx, 1).expect_err("socket error");
            assert_eq!(err.kind(), io::ErrorKind::Other);

            lab.push_event(LabUdpEvent::Close);
            let err = lab.recv_available(&cx, 1).expect_err("close race");
            assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        });
    }
