    use super::*;
    use crate::test_utils::run_test_with_cx;

    #[test]
    fn default_config_uses_burst_tolerant_receive_buffer() {
        let config = QuicUdpEndpointConfig::default();
        assert_eq!(
            config.socket_recv_buffer_size,
            Some(QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES)
        );
        assert_eq!(
            config.socket_send_buffer_size,
            Some(QUIC_UDP_DEFAULT_SEND_BUFFER_BYTES)
        );
    }

    #[test]
    fn test_endpoint_bind_and_addresses() {
        run_test_with_cx(|cx| async move {
            let config = QuicUdpEndpointConfig::default();
            let endpoint = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                .await
                .expect("bind endpoint");

            // Should have a valid local address
            let addr = endpoint.local_addr();
            assert_eq!(addr.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
            assert_ne!(addr.port(), 0);

            // Should have a unique endpoint ID
            assert_ne!(endpoint.endpoint_id(), 0);
            assert!(endpoint.socket_capabilities().batching.portable_recv_batch);
            assert!(endpoint.buffer_report().applied_recv_buffer_bytes.is_some());
        });
    }

    #[test]
    fn explicit_owner_controls_native_polling_and_shutdown_releases_registration() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().expect("native worker context");
            let driver = owner.io_driver_handle().expect("native I/O driver");
            let baseline = driver.waker_count();
            let mut endpoint = QuicUdpEndpoint::bind(
                &owner,
                "127.0.0.1:0".parse().unwrap(),
                QuicUdpEndpointConfig::default(),
            )
            .await
            .unwrap();
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let unrelated = Cx::for_testing();
            unrelated.cancel_with(crate::types::CancelKind::User, None);
            {
                let _ambient = Cx::set_current(Some(unrelated));
                let task_cx = Context::from_waker(std::task::Waker::noop());
                assert!(
                    endpoint
                        .poll_receive_batch(&owner, &task_cx, 4)
                        .is_pending()
                );
                assert_eq!(driver.waker_count(), baseline + 1);
                let outgoing = [OutgoingPacket {
                    dst_addr: peer.local_addr().unwrap(),
                    data: b"explicit owner".to_vec(),
                    send_time: None,
                }];
                let Poll::Ready(Ok(sent)) = endpoint.poll_send_batch(&owner, &task_cx, &outgoing)
                else {
                    panic!("local UDP send must make progress")
                };
                assert_eq!(sent.packets_processed, 1);
                assert_eq!(sent.bytes_processed, b"explicit owner".len());
                assert!(endpoint.managed_send_socket.is_some());
            }
            let mut buffer = [0u8; 32];
            let (length, source) = peer.recv_from(&mut buffer).unwrap();
            assert_eq!(source, endpoint.local_addr());
            assert_eq!(&buffer[..length], b"explicit owner");
            owner.cancel_with(crate::types::CancelKind::User, None);
            assert_eq!(
                endpoint.shutdown(&owner).await,
                Err(QuicUdpEndpointError::Cancelled)
            );
            assert_eq!(
                driver.waker_count(),
                baseline,
                "retained endpoint must release its read registration"
            );
            assert!(endpoint.managed_send_socket.is_none());
        }));
    }

    #[test]
    fn test_endpoint_config_validation() {
        run_test_with_cx(|cx| async move {
            // Invalid max_packet_size
            let mut config = QuicUdpEndpointConfig::default();
            config.max_packet_size = 0;

            let result = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config).await;
            assert!(matches!(
                result,
                Err(QuicUdpEndpointError::InvalidConfig(_))
            ));

            // Invalid max_batch_size
            let mut config = QuicUdpEndpointConfig::default();
            config.max_batch_size = 0;

            let result = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config).await;
            assert!(matches!(
                result,
                Err(QuicUdpEndpointError::InvalidConfig(_))
            ));
        });
    }

    #[test]
    fn test_packet_send_receive_loop() {
        run_test_with_cx(|cx| async move {
            let config = QuicUdpEndpointConfig::default();

            // Create two endpoints
            let mut sender =
                QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config.clone())
                    .await
                    .expect("bind sender");
            let mut receiver = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                .await
                .expect("bind receiver");

            let receiver_addr = receiver.local_addr();

            // Send a packet
            let packet = OutgoingPacket {
                dst_addr: receiver_addr,
                data: b"hello quic".to_vec(),
                send_time: None,
            };

            let send_result = sender
                .send_batch(&cx, &[packet])
                .await
                .expect("send packet");
            assert_eq!(send_result.packets_processed, 1);
            assert_eq!(send_result.bytes_processed, 10);
            assert!(send_result.error.is_none());

            // Receive the packet
            let received = receiver
                .receive_batch(&cx, 1)
                .await
                .expect("receive packet");
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].data, b"hello quic");
            assert_eq!(received[0].src_addr.ip(), sender.local_addr().ip());

            // Check metrics
            let sender_metrics = sender.metrics();
            assert_eq!(
                sender_metrics
                    .packets_sent
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                sender_metrics
                    .bytes_sent
                    .load(std::sync::atomic::Ordering::Relaxed),
                10
            );

            let receiver_metrics = receiver.metrics();
            assert_eq!(
                receiver_metrics
                    .packets_received
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                receiver_metrics
                    .bytes_received
                    .load(std::sync::atomic::Ordering::Relaxed),
                10
            );
            assert_eq!(
                receiver_metrics
                    .receive_batches
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                receiver_metrics
                    .receive_full_batches
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                receiver_metrics
                    .max_receive_batch_packets
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                receiver_metrics
                    .receive_truncated_packets
                    .load(std::sync::atomic::Ordering::Relaxed),
                0
            );
        });
    }

    #[test]
    fn linux_proc_udp_snapshot_parser_reads_rx_queue_and_drops() {
        let local_addr: SocketAddr = "127.0.0.1:4660".parse().unwrap();
        let local_key = linux_proc_udp_key(local_addr).expect("ipv4 proc key");
        assert_eq!(local_key, "0100007F:1234");

        let line = format!(
            "  42: {local_key} 00000000:0000 07 00000000:0000002A 00:00000000 00000000 1000 0 12345 2 0000000000000000 9"
        );
        let snapshot =
            parse_linux_proc_udp_snapshot_line(&line, &local_key).expect("snapshot parses");

        assert_eq!(
            snapshot,
            UdpKernelReceiveSnapshot {
                rx_queue_bytes: 42,
                drops: 9,
            }
        );
        assert!(parse_linux_proc_udp_snapshot_line(&line, "0100007F:5678").is_none());
    }

    #[test]
    fn test_send_batch_processes_all_packets_across_configured_chunks() {
        run_test_with_cx(|cx| async move {
            let sender_config = QuicUdpEndpointConfig {
                max_batch_size: 2,
                ..QuicUdpEndpointConfig::default()
            };
            let receiver_config = QuicUdpEndpointConfig {
                max_batch_size: 8,
                ..QuicUdpEndpointConfig::default()
            };

            let mut sender =
                QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), sender_config)
                    .await
                    .expect("bind sender");
            let mut receiver =
                QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), receiver_config)
                    .await
                    .expect("bind receiver");

            let receiver_addr = receiver.local_addr();
            let expected_payloads = (0..5)
                .map(|index| format!("packet-{index}").into_bytes())
                .collect::<Vec<_>>();
            let packets = expected_payloads
                .iter()
                .map(|payload| OutgoingPacket {
                    dst_addr: receiver_addr,
                    data: payload.clone(),
                    send_time: None,
                })
                .collect::<Vec<_>>();
            let expected_bytes = expected_payloads.iter().map(Vec::len).sum::<usize>();

            let send_result = sender
                .send_batch(&cx, &packets)
                .await
                .expect("send chunked packet batch");
            assert_eq!(send_result.packets_processed, packets.len());
            assert_eq!(send_result.bytes_processed, expected_bytes);
            assert!(send_result.error.is_none());

            let received = receiver
                .receive_batch(&cx, packets.len())
                .await
                .expect("receive full packet batch");
            let mut received_payloads = received
                .into_iter()
                .map(|packet| packet.data)
                .collect::<Vec<_>>();
            received_payloads.sort();

            let mut expected_sorted = expected_payloads;
            expected_sorted.sort();
            assert_eq!(received_payloads, expected_sorted);

            assert_eq!(
                sender
                    .metrics()
                    .packets_sent
                    .load(std::sync::atomic::Ordering::Relaxed),
                5
            );
        });
    }

    #[test]
    fn packet_run_helpers_split_mixed_quic_tail_packets() {
        let dst = "127.0.0.1:9000".parse().unwrap();
        let packets = [
            OutgoingPacket {
                dst_addr: dst,
                data: vec![1; 65_000],
                send_time: None,
            },
            OutgoingPacket {
                dst_addr: dst,
                data: vec![2; 65_000],
                send_time: None,
            },
            OutgoingPacket {
                dst_addr: dst,
                data: vec![3; 1_200],
                send_time: None,
            },
        ];

        assert_eq!(homogeneous_packet_run_len(&packets), 2);
        let strategy = send_strategy_for_packet_run(&packets[..2], UdpSendBatchStrategy::default());
        assert_eq!(strategy.gso_segment_bytes, 65_000);
    }

    #[test]
    fn test_send_batch_uses_unconnected_native_gso_for_fixed_size_payloads_on_linux() {
        run_test_with_cx(|cx| async move {
            const TEST_GSO_SEGMENT_BYTES: usize = 1456;
            assert_eq!(
                TEST_GSO_SEGMENT_BYTES,
                crate::net::UDP_DEFAULT_GSO_SEGMENT_BYTES
            );

            let config = QuicUdpEndpointConfig::default();
            let mut sender =
                QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config.clone())
                    .await
                    .expect("bind sender");
            let mut receiver = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                .await
                .expect("bind receiver");

            let receiver_addr = receiver.local_addr();
            let payloads = (0..4)
                .map(|idx| vec![idx as u8; TEST_GSO_SEGMENT_BYTES])
                .collect::<Vec<_>>();
            let packets = payloads
                .iter()
                .map(|payload| OutgoingPacket {
                    dst_addr: receiver_addr,
                    data: payload.clone(),
                    send_time: None,
                })
                .collect::<Vec<_>>();

            let send_result = sender
                .send_batch(&cx, &packets)
                .await
                .expect("send fixed-size packet batch");
            assert_eq!(send_result.packets_processed, packets.len());
            assert_eq!(
                send_result.bytes_processed,
                TEST_GSO_SEGMENT_BYTES * packets.len()
            );

            if matches!(
                crate::net::UdpPlatform::current(),
                crate::net::UdpPlatform::Linux
            ) {
                assert!(send_result.native_send_batch_used);
                assert!(send_result.gso_send_used);
                assert!(!send_result.fallback_used);
            } else {
                assert!(!send_result.native_send_batch_used);
                assert!(send_result.fallback_used);
            }

            let received = receiver
                .receive_batch(&cx, packets.len())
                .await
                .expect("receive fixed-size packet batch");
            assert_eq!(received.len(), packets.len());
            let mut received_payloads = received
                .into_iter()
                .map(|packet| packet.data)
                .collect::<Vec<_>>();
            received_payloads.sort_by_key(|payload| payload[0]);
            assert_eq!(received_payloads, payloads);
        });
    }

    #[test]
    fn test_cancellation_during_receive() {
        run_test_with_cx(|cx| async move {
            let config = QuicUdpEndpointConfig::default();
            let mut endpoint = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                .await
                .expect("bind endpoint");

            cx.set_cancel_requested(true);
            let result = endpoint.receive_batch(&cx, 1).await;
            assert!(matches!(result, Err(QuicUdpEndpointError::Cancelled)));
        });
    }

    // A receive parked on an empty socket waits on socket readiness only.
    // Cancelling its owner from another thread must wake it: before the fix it
    // waited for the next datagram, here forever (bounded by the timeout).
    #[test]
    fn cancellation_wakes_a_receive_parked_on_an_empty_socket() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .with_reactor(crate::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().expect("native root context");
            let mut endpoint = QuicUdpEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                QuicUdpEndpointConfig::default(),
            )
            .await
            .expect("bind endpoint");
            let (parked_tx, parked_rx) = std::sync::mpsc::sync_channel(1);
            let canceller_cx = cx.clone();
            let canceller = std::thread::spawn(move || {
                parked_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("receive parked before cancellation");
                canceller_cx.set_cancel_requested(true);
            });
            let started = Instant::now();
            let mut parked = false;
            let result = {
                let mut receive = std::pin::pin!(endpoint.receive_batch(&cx, 1));
                crate::time::timeout(
                    cx.now(),
                    Duration::from_secs(5),
                    std::future::poll_fn(|task| {
                        let polled = std::future::Future::poll(receive.as_mut(), task);
                        if polled.is_pending() && !parked {
                            parked = true;
                            parked_tx.send(()).unwrap();
                        }
                        polled
                    }),
                )
                .await
                .expect("cancellation must wake the parked receive")
            };
            canceller.join().unwrap();
            eprintln!(
                "scenario=parked_receive_cancel parked={parked} elapsed={:?} result={result:?}",
                started.elapsed()
            );
            assert!(parked, "the receive parked before cancellation");
            assert!(
                matches!(result, Err(QuicUdpEndpointError::Cancelled)),
                "{result:?}"
            );
        });
    }

    #[test]
    fn test_cancellation_before_bind_fails_closed() {
        run_test_with_cx(|cx| async move {
            cx.set_cancel_requested(true);

            let config = QuicUdpEndpointConfig::default();
            let result = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config).await;
            assert!(matches!(result, Err(QuicUdpEndpointError::Cancelled)));
        });
    }
