    use super::*;
    use crate::net::quic_core::ConnectionId;
    use crate::test_utils::run_test_with_cx;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[derive(Default)]
    struct SelectionWake(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for SelectionWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn selection_packet_protection(cx: &Cx) -> crate::net::atp::quic::AtpPacketProtection {
        use crate::net::atp::quic::AtpPacketProtection;
        use crate::net::quic_native::{PacketProtectionSpace, QuicHandshakeTranscript};
        let mut transcript = QuicHandshakeTranscript::new();
        transcript.record("client_initial", b"managed selection client fixture");
        transcript.record("server_handshake", b"managed selection server fixture");
        let mut protection = AtpPacketProtection::new_client(true).unwrap();
        protection
            .derive_keys(
                cx,
                PacketProtectionSpace::OneRtt,
                &transcript,
                b"managed selection unit fixture, not authenticated handshake proof",
            )
            .await
            .unwrap();
        protection
    }

    async fn selection_fixture(
        owner: &Cx,
    ) -> (
        Cx,
        Arc<crate::time::VirtualClock>,
        crate::time::TimerDriverHandle,
        ManagedQuicEndpoint,
        std::net::UdpSocket,
        ConnectionId,
    ) {
        use crate::net::quic_native::PacketNumberSpace;
        use crate::time::{TimerDriverHandle, VirtualClock};
        let clock = Arc::new(VirtualClock::starting_at(crate::Time::from_secs(37)));
        let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            crate::types::RegionId::new_for_test(0, 1),
            crate::types::TaskId::new_for_test(0, 0),
            crate::types::Budget::INFINITE,
            None,
            owner.io_driver_handle(),
            None,
            Some(driver.clone()),
            None,
        );
        let protection = selection_packet_protection(&cx).await;
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut endpoint = ManagedQuicEndpoint::bind(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            ManagedEndpointConfig {
                packet_batch_size: 1,
                ..ManagedEndpointConfig::default()
            },
        )
        .await
        .unwrap();
        endpoint.timer_scheduler.now(&cx).unwrap();
        let cid = ConnectionId::new(&[7; 8]).unwrap();
        endpoint
            .create_connection_for_testing(&cx, cid, peer.local_addr().unwrap())
            .await
            .unwrap();
        endpoint
            .connection_router
            .install_packet_protection(&cx, cid, protection)
            .unwrap();
        // Only recovery state is planted. Selection, timer registration, packet
        // protection and UDP use production code; this is not a TLS/.76 proof.
        let connection = endpoint
            .connection_router
            .connection_mut_for_testing(&cx, cid)
            .unwrap();
        connection.begin_handshake(&cx).unwrap();
        connection.on_handshake_keys_available(&cx).unwrap();
        connection.on_1rtt_keys_available(&cx).unwrap();
        connection.record_verified_server_identity();
        connection.on_handshake_confirmed(&cx).unwrap();
        connection
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1_200,
                true,
                true,
                1_000,
            )
            .unwrap();
        endpoint
            .connection_router
            .refresh_connection_timer_for_testing(&cx, cid, 1_000)
            .unwrap();
        (cx, clock, driver, endpoint, peer, cid)
    }

    #[test]
    fn lifecycle_reaping_idle_endpoint_without_in_flight_packets_accepts_a_new_peer() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().unwrap();
            let mut endpoint = ManagedQuicEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                ManagedEndpointConfig {
                    max_connections: 1,
                    connection_idle_timeout_micros: 10_000_000,
                    ..ManagedEndpointConfig::default()
                },
            )
            .await
            .unwrap();
            let cid = ConnectionId::new(b"idle").unwrap();
            let replacement = ConnectionId::new(b"next").unwrap();
            let peer = "127.0.0.1:4450".parse().unwrap();
            endpoint
                .create_connection_for_testing(&cx, cid, peer)
                .await
                .unwrap();
            let deadline = endpoint
                .connection_router
                .next_timer_deadline()
                .expect("an idle route must have a deadline without any recovery flight");
            assert!(
                endpoint
                    .create_connection_for_testing(&cx, replacement, peer)
                    .await
                    .is_err()
            );
            endpoint.process_timer_events(&cx, deadline).await.unwrap();
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert!(endpoint.pending_outgoing.is_empty());
            endpoint
                .create_connection_for_testing(&cx, replacement, peer)
                .await
                .unwrap();
            assert_eq!(endpoint.connection_stats().active_connections, 1);
            endpoint.shutdown(&cx).await.unwrap();
        }));
    }

    fn witness_selection_io_wake(owner: &Cx, wake: &SelectionWake, before: usize) {
        let driver = owner.io_driver_handle().unwrap();
        for _ in 0..16 {
            driver.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap();
            if wake.0.load(Ordering::SeqCst) > before {
                return;
            }
        }
        panic!("managed selection: registered native read interest lost its UDP wake");
    }

    #[test]
    fn application_self_wake_services_ready_udp_and_protected_output() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, clock, driver, mut endpoint, peer, cid) = selection_fixture(&owner).await;
            let deadline = endpoint.connection_router.next_timer_deadline().unwrap();
            let advance = deadline.duration_since(endpoint.timer_scheduler.now(&cx).unwrap());
            clock.advance(u64::try_from(advance.as_nanos()).unwrap());
            endpoint.process_timer_events(&cx, deadline).await.unwrap();
            assert_eq!(
                endpoint.pending_outgoing.len(),
                1,
                "one real protected PTO packet"
            );
            let expected = endpoint
                .pending_outgoing
                .front()
                .unwrap()
                .packet
                .data
                .clone();
            let address = endpoint.local_addr();
            assert_eq!(peer.send_to(b"invalid QUIC", address).unwrap(), 12);
            let metrics = endpoint.udp_endpoint.metrics();
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed_calls = Arc::clone(&calls);
            let observed_metrics = Arc::clone(&metrics);
            let wake = Arc::new(SelectionWake::default());
            let waker = Waker::from(Arc::clone(&wake));
            let mut completed = false;
            {
                let mut run =
                    std::pin::pin!(endpoint.drive_event_loop(&cx, true, move |_, _, task_cx| {
                        observed_calls.fetch_add(1, Ordering::SeqCst);
                        if observed_metrics.packets_sent.load(Ordering::Relaxed) == 1
                            && observed_metrics.packets_received.load(Ordering::Relaxed) == 1
                        {
                            return Poll::Ready(Ok(()));
                        }
                        task_cx.waker().wake_by_ref();
                        Poll::Pending
                    }));
                for _ in 0..16 {
                    match run.as_mut().poll(&mut Context::from_waker(&waker)) {
                        Poll::Ready(result) => {
                            assert_eq!(result, Ok(Some(())));
                            completed = true;
                            break;
                        }
                        Poll::Pending => {
                            owner
                                .io_driver_handle()
                                .unwrap()
                                .turn_with(Some(Duration::ZERO), |_, _| {})
                                .unwrap();
                        }
                    }
                }
            }
            assert!(
                completed,
                "self-waking application must permit both I/O directions"
            );
            assert!(calls.load(Ordering::SeqCst) >= 3);
            assert!(endpoint.pending_outgoing.is_empty());
            let mut bytes = [0_u8; 1_200];
            let (length, from) = peer.recv_from(&mut bytes).unwrap();
            assert_eq!(from, address);
            assert_eq!(&bytes[..length], expected.as_slice());
            let crate::net::quic_core::ProtectedHeaderPrefix::Short { dst_cid, .. } =
                crate::net::quic_core::ProtectedHeaderPrefix::decode(&bytes[..length], cid.len())
                    .unwrap()
            else {
                panic!("actual output must carry a protected 1-RTT header");
            };
            assert_eq!(dst_cid, cid);
            let mut verifier = selection_packet_protection(&cx).await;
            let plaintext = crate::net::quic_native::connection_manager::unprotect_1rtt_packet(
                &cx,
                cid,
                &mut verifier,
                &bytes[..length],
            )
            .await
            .unwrap()
            .plaintext;
            assert!(
                crate::net::quic_native::NativeQuicConnection::decode_frames(&plaintext)
                    .unwrap()
                    .iter()
                    .any(|frame| matches!(
                        frame,
                        crate::net::atp::protocol::quic_frames::QuicFrame::Ping
                    ))
            );
            endpoint.shutdown(&cx).await.unwrap();
            assert_eq!(driver.pending_count(), 0);
        }));
    }

    #[test]
    fn application_proxy_detaches_parent_and_does_not_poll_on_waker_replacement() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, _, driver, mut endpoint, _, _) = selection_fixture(&owner).await;
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let retained = Arc::new(std::sync::Mutex::new(None::<Waker>));
            let observed_calls = Arc::clone(&calls);
            let observed_retained = Arc::clone(&retained);
            let old = Arc::new(SelectionWake::default());
            let new = Arc::new(SelectionWake::default());
            let old_waker = Waker::from(Arc::clone(&old));
            let new_waker = Waker::from(Arc::clone(&new));
            {
                let mut run =
                    std::pin::pin!(endpoint.drive_event_loop(&cx, true, move |_, _, task_cx| {
                        observed_calls.fetch_add(1, Ordering::SeqCst);
                        *observed_retained.lock().unwrap() = Some(task_cx.waker().clone());
                        Poll::<Result<(), ManagedEndpointError>>::Pending
                    }));
                assert!(
                    run.as_mut()
                        .poll(&mut Context::from_waker(&old_waker))
                        .is_pending()
                );
                assert!(
                    run.as_mut()
                        .poll(&mut Context::from_waker(&old_waker))
                        .is_pending()
                );
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert!(
                    run.as_mut()
                        .poll(&mut Context::from_waker(&new_waker))
                        .is_pending()
                );
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    1,
                    "changing parent is not application readiness"
                );
                let before_old = old.0.load(Ordering::SeqCst);
                let before_new = new.0.load(Ordering::SeqCst);
                retained.lock().unwrap().as_ref().unwrap().wake_by_ref();
                assert_eq!(old.0.load(Ordering::SeqCst), before_old);
                assert_eq!(new.0.load(Ordering::SeqCst), before_new + 1);
                assert!(
                    run.as_mut()
                        .poll(&mut Context::from_waker(&new_waker))
                        .is_pending()
                );
                assert_eq!(calls.load(Ordering::SeqCst), 2);
            }
            let before_old = old.0.load(Ordering::SeqCst);
            let before_new = new.0.load(Ordering::SeqCst);
            retained.lock().unwrap().as_ref().unwrap().wake_by_ref();
            assert_eq!(old.0.load(Ordering::SeqCst), before_old);
            assert_eq!(
                new.0.load(Ordering::SeqCst),
                before_new,
                "dropped driver's proxy is detached"
            );
            // Isolate the registration's owned parent reference from independent
            // socket/timer registrations to prove that reference is released.
            let parent = Arc::new(SelectionWake::default());
            let parent_waker = Waker::from(Arc::clone(&parent));
            let proxy = Arc::new(ManagedApplicationWake {
                ready: AtomicBool::new(false),
                parent: std::sync::Mutex::new(None),
            });
            let baseline = Arc::strong_count(&parent);
            {
                let _registration = ManagedApplicationRegistration(Some(Arc::clone(&proxy)));
                proxy.register_parent(&parent_waker);
                assert_eq!(Arc::strong_count(&parent), baseline + 1);
            }
            assert_eq!(Arc::strong_count(&parent), baseline);
            proxy.wake_by_ref();
            assert_eq!(parent.0.load(Ordering::SeqCst), 0);
            endpoint.shutdown(&cx).await.unwrap();
            assert_eq!(driver.pending_count(), 0);
        }));
    }

    #[test]
    fn received_batch_keeps_early_epoch_and_stamps_fresh_input_once_before_cancel() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, clock, _, mut endpoint, peer, _) = selection_fixture(&owner).await;
            let original = endpoint.timer_scheduler.now(&cx).unwrap();
            let early_time = original.checked_sub(Duration::from_millis(1)).unwrap();
            endpoint.authenticated_only = true;
            endpoint.pending_incoming.push_back(ManagedIncomingPacket {
                packet: ReceivedPacket {
                    src_addr: peer.local_addr().unwrap(),
                    data: b"retained early input".to_vec(),
                    receive_time: early_time,
                    transmit_time: None,
                },
                needs_clock_stamp: false,
            });
            assert_eq!(
                peer.send_to(b"fresh kernel input", endpoint.local_addr())
                    .unwrap(),
                18
            );
            let packets = endpoint.udp_endpoint.receive_batch(&cx, 1).await.unwrap();
            assert_eq!(packets.len(), 1);
            let wall_received = packets[0].receive_time;
            clock.advance(10_000_000_000);
            let mapped = endpoint.timer_scheduler.now(&cx).unwrap();
            assert_eq!(mapped.duration_since(original), Duration::from_secs(10));
            assert!(mapped.duration_since(wall_received) >= Duration::from_secs(9));
            cx.cancel_with(crate::types::CancelKind::User, None);
            assert_eq!(
                endpoint.process_packet_batch(&cx, packets).await,
                Err(ManagedEndpointError::Cancelled)
            );
            assert_eq!(endpoint.pending_incoming.len(), 2);
            assert_eq!(endpoint.pending_incoming[0].packet.receive_time, early_time);
            assert_eq!(endpoint.pending_incoming[1].packet.receive_time, mapped);
            assert_eq!(
                endpoint.pending_incoming[1].packet.data,
                b"fresh kernel input"
            );
            clock.advance(20_000_000_000);
            assert_eq!(
                endpoint.process_packet_batch(&cx, Vec::new()).await,
                Err(ManagedEndpointError::Cancelled)
            );
            assert_eq!(endpoint.pending_incoming[0].packet.receive_time, early_time);
            assert_eq!(endpoint.pending_incoming[1].packet.receive_time, mapped);
            assert!(
                endpoint
                    .pending_incoming
                    .iter()
                    .all(|packet| !packet.needs_clock_stamp)
            );
            assert_eq!(
                endpoint.shutdown(&cx).await,
                Err(ManagedEndpointError::Cancelled)
            );
            assert!(endpoint.pending_incoming.is_empty());
        }));
    }

    #[test]
    fn simultaneous_ready_io_and_due_timer_cancel_before_consuming_owned_suffix() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let io_driver = owner.io_driver_handle().unwrap();
            let registrations = io_driver.waker_count();
            let (cx, clock, driver, mut endpoint, peer, _) = selection_fixture(&owner).await;
            let deadline = endpoint.connection_router.next_timer_deadline().unwrap();
            let advance = u64::try_from(
                deadline
                    .duration_since(endpoint.timer_scheduler.now(&cx).unwrap())
                    .as_nanos(),
            )
            .unwrap();
            assert!(advance > 0);
            let metrics = endpoint.udp_endpoint.metrics();
            let wake = Arc::new(SelectionWake::default());
            let waker = std::task::Waker::from(wake.clone());
            let endpoint_addr = endpoint.local_addr();
            {
                let mut run = std::pin::pin!(endpoint.run_event_loop(&cx));
                assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                assert_eq!(wake.0.load(Ordering::SeqCst), 0, "idle loop must genuinely park");
                assert_eq!(driver.pending_count(), 1);
                assert_eq!(io_driver.waker_count(), registrations + 1);
                let before = wake.0.load(Ordering::SeqCst);
                assert_eq!(peer.send_to(b"invalid QUIC", endpoint_addr).unwrap(), 12);
                witness_selection_io_wake(&owner, &wake, before);
                // Do not repoll before observing the real wake. Drop this parked
                // future solely to seed output through the retained endpoint.
            }
            assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 0);
            assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 0);
            assert_eq!(endpoint.timer_scheduler.current_deadline(), Some(deadline));
            let queue_cid = ConnectionId::new(&[9; 8]).unwrap();
            for index in 0..3u8 {
                endpoint.queue_connection_packets(
                    queue_cid,
                    [OutgoingPacket {
                        dst_addr: peer.local_addr().unwrap(),
                        data: vec![index],
                        send_time: None,
                    }],
                );
            }
            {
                let mut run = std::pin::pin!(endpoint.run_event_loop(&cx));
                // Restart the same owner; one writable packet commits before
                // yield, leaving an exact suffix and unread input ready.
                assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 1);
                assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 0);
                let before_timer = wake.0.load(Ordering::SeqCst);
                clock.advance(advance);
                assert_eq!(driver.process_timers(), 1);
                assert!(wake.0.load(Ordering::SeqCst) > before_timer, "due timer must wake the retained loop");
                let before_cancel = wake.0.load(Ordering::SeqCst);
                cx.cancel_with(crate::types::CancelKind::User, None);
                assert!(wake.0.load(Ordering::SeqCst) > before_cancel, "cancellation must wake its current registered waiter");
                assert_eq!(
                    run.as_mut().poll(&mut std::task::Context::from_waker(&waker)),
                    Poll::Ready(Err(ManagedEndpointError::Cancelled))
                );
            }
            assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 1);
            assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 0);
            assert_eq!(endpoint.pending_outgoing.len(), 2);
            for (packet, index) in endpoint.pending_outgoing.iter().zip(1..3u8) {
                assert_eq!(packet.connection_id, queue_cid);
                assert_eq!(packet.packet.data, vec![index]);
                assert_eq!(packet.packet.dst_addr, peer.local_addr().unwrap());
            }
            assert_eq!(driver.pending_count(), 0);
            assert!(!endpoint.timer_scheduler.has_pending_timer());
            let mut bytes = [0u8; 1_200];
            assert_eq!(peer.recv_from(&mut bytes).unwrap(), (1, endpoint_addr));
            assert_eq!(bytes[0], 0);
            assert_eq!(peer.recv_from(&mut bytes).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            assert_eq!(endpoint.shutdown(&cx).await, Err(ManagedEndpointError::Cancelled));
            assert!(endpoint.pending_outgoing.is_empty());
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert_eq!(driver.pending_count(), 0);
            assert_eq!(io_driver.waker_count(), registrations);
            println!("managed_selection_cancel bead=asupersync-bi2462.75 fixture=virtual37_native_udp parked_read_wake=true timer_firings=1 sent_prefix=1 retained_suffix=2 received_before_cancel=0 registrations_after_cleanup={registrations} outcome=cancelled");
        }));
    }

    #[test]
    fn continuous_ready_ingress_cannot_starve_due_protected_pto_output() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let io_driver = owner.io_driver_handle().unwrap();
            let registrations = io_driver.waker_count();
            let (cx, clock, driver, mut endpoint, peer, cid) = selection_fixture(&owner).await;
            let mut verifier = selection_packet_protection(&owner).await;
            let endpoint_addr = endpoint.local_addr();
            let deadline = endpoint.connection_router.next_timer_deadline().unwrap();
            let advance = u64::try_from(
                deadline
                    .duration_since(endpoint.timer_scheduler.now(&cx).unwrap())
                    .as_nanos(),
            )
            .unwrap();
            assert!(advance > 0);
            let metrics = endpoint.udp_endpoint.metrics();
            let wake = Arc::new(SelectionWake::default());
            let waker = std::task::Waker::from(wake.clone());
            {
                let mut run = std::pin::pin!(endpoint.run_event_loop(&cx));
                assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                assert_eq!(wake.0.load(Ordering::SeqCst), 0, "idle loop must genuinely park");
                assert_eq!(driver.pending_count(), 1);
                assert_eq!(io_driver.waker_count(), registrations + 1);
                let mut before = wake.0.load(Ordering::SeqCst);
                for _ in 0..32 {
                    assert_eq!(peer.send_to(b"invalid QUIC", endpoint_addr).unwrap(), 12);
                }
                witness_selection_io_wake(&owner, &wake, before);
                // Four real read batches precede the deadline. Every later
                // turn still has queued input: at most eight of 32 are read.
                for received in 1..=4 {
                    assert!(wake.0.load(Ordering::SeqCst) > before, "ready ingress/cooperative turn must wake before repoll");
                    before = wake.0.load(Ordering::SeqCst);
                    assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                    assert_eq!(metrics.packets_received.load(Ordering::Relaxed), received);
                    assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 0);
                }
                let before_timer = wake.0.load(Ordering::SeqCst);
                clock.advance(advance);
                assert_eq!(driver.process_timers(), 1);
                assert!(wake.0.load(Ordering::SeqCst) > before_timer, "actual timer registration must wake the loop");
                before = wake.0.load(Ordering::SeqCst);
                assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 4, "due PTO must beat already-readable input");
                assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 0);
                assert!(wake.0.load(Ordering::SeqCst) > before);
                before = wake.0.load(Ordering::SeqCst);
                assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 1, "PTO output must reach actual UDP while ingress remains ready");
                assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 4);
                for received in 5..=8 {
                    assert!(wake.0.load(Ordering::SeqCst) > before);
                    before = wake.0.load(Ordering::SeqCst);
                    assert!(run.as_mut().poll(&mut std::task::Context::from_waker(&waker)).is_pending());
                    assert_eq!(metrics.packets_received.load(Ordering::Relaxed), received);
                    assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 1);
                }
                let before_cancel = wake.0.load(Ordering::SeqCst);
                cx.cancel_with(crate::types::CancelKind::User, None);
                assert!(wake.0.load(Ordering::SeqCst) > before_cancel);
                assert_eq!(
                    run.as_mut().poll(&mut std::task::Context::from_waker(&waker)),
                    Poll::Ready(Err(ManagedEndpointError::Cancelled))
                );
            }
            assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 8);
            assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 1);
            assert!(endpoint.pending_outgoing.is_empty());
            assert!(endpoint.connection_router.next_timer_deadline().unwrap() > deadline);
            assert_eq!(driver.now(), crate::Time::from_nanos(37_000_000_000 + advance));
            assert_eq!(driver.pending_count(), 0);
            let mut bytes = [0u8; 1_200];
            let (length, source) = peer.recv_from(&mut bytes).unwrap();
            assert_eq!(source, endpoint_addr);
            let crate::net::quic_core::ProtectedHeaderPrefix::Short { dst_cid, .. } =
                crate::net::quic_core::ProtectedHeaderPrefix::decode(&bytes[..length], 8).unwrap()
            else {
                panic!("due managed PTO must emit an actual protected short packet")
            };
            assert_eq!(dst_cid, cid);
            let unprotected = crate::net::quic_native::connection_manager::unprotect_1rtt_packet(
                &owner,
                cid,
                &mut verifier,
                &bytes[..length],
            )
            .await
            .unwrap();
            assert_eq!(unprotected.header.dst_cid, cid);
            assert_eq!(unprotected.header.packet_number, 1);
            let plaintext = unprotected.plaintext;
            let mut expected = crate::bytes::BytesMut::new();
            crate::net::atp::protocol::quic_frames::QuicFrame::Ping.encode(&mut expected).unwrap();
            assert_eq!(plaintext, expected.as_ref());
            assert_eq!(peer.recv_from(&mut bytes).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            assert_eq!(endpoint.shutdown(&cx).await, Err(ManagedEndpointError::Cancelled));
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert_eq!(io_driver.waker_count(), registrations);
            assert_eq!(driver.pending_count(), 0);
            println!("managed_selection_pto bead=asupersync-bi2462.75 fixture=virtual37_native_udp input_sent=32 input_before_due=4 input_after_probe=8 protected_ping_packets=1 protected_bytes={length} timer_firings=1 virtual_advance_ns={advance} registrations_after_cleanup={registrations} outcome=pass no_authenticated_handshake_claim=true");
        }));
    }

    #[test]
    fn native_idle_loop_parks_and_acknowledges_cancellation_without_packets() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native worker context");
            let parked = Arc::new(AtomicBool::new(false));
            let parked_child = parked.clone();
            let mut child = cx
                .spawn(move |child_cx| async move {
                    let mut endpoint = ManagedQuicEndpoint::bind(
                        &child_cx,
                        "127.0.0.1:0".parse().unwrap(),
                        ManagedEndpointConfig::default(),
                    )
                    .await
                    .unwrap();
                    let result = {
                        let mut run = std::pin::pin!(endpoint.run_event_loop(&child_cx));
                        poll_fn(|task_cx| {
                            let poll = run.as_mut().poll(task_cx);
                            if poll.is_pending() {
                                parked_child.store(true, Ordering::SeqCst);
                            }
                            poll
                        })
                        .await
                    };
                    assert_eq!(
                        endpoint
                            .udp_endpoint
                            .metrics()
                            .packets_received
                            .load(Ordering::Relaxed),
                        0
                    );
                    assert!(!endpoint.timer_scheduler.has_pending_timer());
                    assert!(endpoint.pending_outgoing.is_empty());
                    result
                })
                .unwrap();
            for _ in 0..512 {
                if parked.load(Ordering::SeqCst) {
                    break;
                }
                crate::runtime::yield_now().await;
            }
            assert!(
                parked.load(Ordering::SeqCst),
                "native UDP receive must park before cancellation"
            );
            child.abort();
            let result = crate::time::timeout(cx.now(), Duration::from_secs(5), child.join(&cx))
                .await
                .unwrap();
            assert_eq!(result.unwrap(), Err(ManagedEndpointError::Cancelled));
        }));
    }

    #[test]
    fn native_loop_sends_healthy_peer_after_bad_destination_and_receives_during_load() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native worker context");
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_nonblocking(true).unwrap();
            let peer_addr = peer.local_addr().unwrap();
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
            let mut child = cx
                .spawn(move |child_cx| async move {
                    let config = ManagedEndpointConfig {
                        packet_batch_size: 4,
                        ..ManagedEndpointConfig::default()
                    };
                    let mut endpoint = ManagedQuicEndpoint::bind(
                        &child_cx,
                        "127.0.0.1:0".parse().unwrap(),
                        config,
                    )
                    .await
                    .unwrap();
                    endpoint.queue_connection_packets(
                        ConnectionId::default(),
                        [OutgoingPacket {
                            dst_addr: "127.0.0.1:0".parse().unwrap(),
                            data: vec![0xff],
                            send_time: None,
                        }],
                    );
                    for index in 0..65u8 {
                        endpoint.queue_connection_packets(
                            ConnectionId::default(),
                            [OutgoingPacket {
                                dst_addr: peer_addr,
                                data: vec![index],
                                send_time: None,
                            }],
                        );
                    }
                    let metrics = endpoint.udp_endpoint.metrics();
                    ready_tx.send((endpoint.local_addr(), metrics)).unwrap();
                    let result = endpoint.run_event_loop(&child_cx).await;
                    assert!(
                        endpoint.pending_outgoing.is_empty(),
                        "all permitted output must reach the socket before cancellation"
                    );
                    result
                })
                .unwrap();
            let mut ready = None;
            for _ in 0..512 {
                if let Ok(value) = ready_rx.try_recv() {
                    ready = Some(value);
                    break;
                }
                crate::runtime::yield_now().await;
            }
            let (endpoint_addr, metrics) = ready.expect("endpoint started on native worker");
            let mut observed = Vec::new();
            let mut ingress_with_multiple_output_batches_pending = false;
            let mut buffer = [0u8; 16];
            for _ in 0..2048 {
                // Keep ingress readable while checking both egress and scheduler progress.
                for _ in 0..8 {
                    peer.send_to(b"invalid QUIC", endpoint_addr).unwrap();
                }
                loop {
                    match peer.recv_from(&mut buffer) {
                        Ok((length, source)) => {
                            assert_eq!(source, endpoint_addr);
                            assert_eq!(length, 1);
                            observed.push(buffer[0]);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("native receive failed: {error}"),
                    }
                }
                ingress_with_multiple_output_batches_pending |=
                    metrics.packets_received.load(Ordering::Relaxed) > 0
                        && metrics.packets_sent.load(Ordering::Relaxed) <= 60;
                if observed.len() == 65 && metrics.packets_received.load(Ordering::Relaxed) > 0 {
                    break;
                }
                crate::runtime::yield_now().await;
            }
            assert_eq!(observed, (0..65u8).collect::<Vec<_>>());
            assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 65);
            assert!(
                metrics.send_errors.load(Ordering::Relaxed) > 0,
                "planted destination failure was reached"
            );
            assert!(metrics.packets_received.load(Ordering::Relaxed) > 0);
            assert!(
                ingress_with_multiple_output_batches_pending,
                "receives must progress before the output queue falls below one batch"
            );
            child.abort();
            let result = crate::time::timeout(cx.now(), Duration::from_secs(5), child.join(&cx))
                .await
                .unwrap();
            assert_eq!(result.unwrap(), Err(ManagedEndpointError::Cancelled));
        }));
    }

    #[test]
    fn send_errors_blame_a_destination_only_when_the_os_reported_them() {
        use std::io::{Error, ErrorKind};
        // The endpoint's own size check shares the kind of the OS's EINVAL for
        // sending to port 0, but only the latter is the destination's fault.
        #[cfg(unix)]
        assert!(send_error_blames_destination(&Error::from_raw_os_error(
            libc::EINVAL
        )));
        assert!(!send_error_blames_destination(&Error::new(
            ErrorKind::InvalidInput,
            "packet size 5 exceeds endpoint limit 4"
        )));
        assert!(send_error_is_resource_shortage(&Error::from(
            ErrorKind::OutOfMemory
        )));
        #[cfg(unix)]
        {
            let shortage = Error::from_raw_os_error(libc::ENOBUFS);
            assert!(send_error_is_resource_shortage(&shortage));
            assert!(!send_error_blames_destination(&shortage));
            let fatal = Error::from_raw_os_error(libc::EBADF);
            assert!(!send_error_is_resource_shortage(&fatal));
            assert!(!send_error_blames_destination(&fatal));
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_loop_backs_off_from_send_buffer_shortage_and_delivers_every_packet() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native worker context");
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_nonblocking(true).unwrap();
            let peer_addr = peer.local_addr().unwrap();
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
            let started = Instant::now();
            let mut child = cx
                .spawn(move |child_cx| async move {
                    let mut endpoint = ManagedQuicEndpoint::bind(
                        &child_cx,
                        "127.0.0.1:0".parse().unwrap(),
                        ManagedEndpointConfig::default(),
                    )
                    .await
                    .unwrap();
                    for index in 0..8u8 {
                        endpoint.queue_connection_packets(
                            ConnectionId::default(),
                            [OutgoingPacket {
                                dst_addr: peer_addr,
                                data: vec![index],
                                send_time: None,
                            }],
                        );
                    }
                    // Five consecutive shortages wait 2 + 4 + 8 + 16 + 32 ms.
                    endpoint.udp_endpoint.inject_send_errors([
                        std::io::Error::from_raw_os_error(libc::ENOBUFS),
                        std::io::Error::from_raw_os_error(libc::ENOBUFS),
                        std::io::Error::from(std::io::ErrorKind::OutOfMemory),
                        std::io::Error::from_raw_os_error(libc::ENOBUFS),
                        std::io::Error::from_raw_os_error(libc::ENOBUFS),
                    ]);
                    ready_tx.send(endpoint.udp_endpoint.metrics()).unwrap();
                    let mut polls = 0_usize;
                    let result = {
                        let mut run = std::pin::pin!(endpoint.run_event_loop(&child_cx));
                        poll_fn(|task_cx| {
                            polls += 1;
                            run.as_mut().poll(task_cx)
                        })
                        .await
                    };
                    assert!(endpoint.pending_outgoing.is_empty());
                    assert_eq!(endpoint.send_backoff_until, None);
                    assert_eq!(endpoint.send_backoff_streak, 0);
                    (result, polls)
                })
                .unwrap();
            let mut metrics = None;
            for _ in 0..512 {
                if let Ok(value) = ready_rx.try_recv() {
                    metrics = Some(value);
                    break;
                }
                crate::runtime::yield_now().await;
            }
            let metrics = metrics.expect("endpoint started on native worker");
            let mut observed = Vec::new();
            let mut buffer = [0u8; 16];
            for _ in 0..5_000 {
                loop {
                    match peer.recv_from(&mut buffer) {
                        Ok((length, _)) => {
                            assert_eq!(length, 1);
                            observed.push(buffer[0]);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("native receive failed: {error}"),
                    }
                }
                if observed.len() == 8 {
                    break;
                }
                crate::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
            let elapsed = started.elapsed();
            assert_eq!(observed, (0..8u8).collect::<Vec<_>>());
            assert_eq!(metrics.send_errors.load(Ordering::Relaxed), 5);
            assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 8);
            assert!(
                elapsed >= Duration::from_millis(40),
                "five shortages must wait out a capped backoff, not retry at once: {elapsed:?}"
            );
            child.abort();
            let joined = crate::time::timeout(cx.now(), Duration::from_secs(5), child.join(&cx))
                .await
                .unwrap();
            let (result, polls) = joined.unwrap();
            assert_eq!(result, Err(ManagedEndpointError::Cancelled));
            assert!(
                polls <= 64,
                "a backoff must park the loop, not spin: {polls} polls"
            );
        }));
    }

    #[test]
    fn native_loop_drops_only_an_oversized_datagram_and_keeps_its_peer() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native worker context");
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_nonblocking(true).unwrap();
            let peer_addr = peer.local_addr().unwrap();
            let mut endpoint = ManagedQuicEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                ManagedEndpointConfig {
                    udp_config: QuicUdpEndpointConfig {
                        max_packet_size: 4,
                        ..QuicUdpEndpointConfig::default()
                    },
                    ..ManagedEndpointConfig::default()
                },
            )
            .await
            .unwrap();
            let ids = [
                ConnectionId::new(&[1]).unwrap(),
                ConnectionId::new(&[2]).unwrap(),
            ];
            for id in ids {
                endpoint
                    .create_connection_for_testing(&cx, id, peer_addr)
                    .await
                    .unwrap();
            }
            // Both connections share one peer address. Only the first built a
            // datagram above the socket limit.
            endpoint.queue_connection_packets(
                ids[0],
                [OutgoingPacket {
                    dst_addr: peer_addr,
                    data: vec![0; 5],
                    send_time: None,
                }],
            );
            endpoint.queue_connection_packets(
                ids[1],
                [OutgoingPacket {
                    dst_addr: peer_addr,
                    data: vec![7],
                    send_time: None,
                }],
            );
            {
                let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
                let mut drive = std::pin::pin!(endpoint.run_event_loop(&cx));
                assert!(drive.as_mut().poll(&mut task_cx).is_pending());
            }
            assert!(endpoint.pending_outgoing.is_empty());
            let mut buffer = [0u8; 16];
            let (length, source) = peer.recv_from(&mut buffer).unwrap();
            assert_eq!(source, endpoint.local_addr());
            assert_eq!(&buffer[..length], &[7]);
            assert_eq!(
                peer.recv_from(&mut buffer).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(endpoint.connection_stats().active_connections, 1);
            assert!(matches!(
                endpoint.take_connection(&cx, ids[0]),
                Err(ManagedEndpointError::ConnectionRouter(
                    ConnectionRouterError::ConnectionNotFound(id)
                )) if id == ids[0]
            ));
            assert_eq!(
                endpoint.take_connection(&cx, ids[1]).unwrap().connection_id,
                ids[1]
            );
            endpoint.shutdown(&cx).await.unwrap();
        }));
    }

    #[test]
    fn handoff_after_dropped_loop_retires_only_that_connections_unsent_packets() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native worker context");
            for take_next in [false, true] {
                let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                peer.set_nonblocking(true).unwrap();
                let peer_addr = peer.local_addr().unwrap();
                let mut endpoint = ManagedQuicEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    ManagedEndpointConfig::default(),
                )
                .await
                .unwrap();
                let ids = [
                    ConnectionId::new(&[1]).unwrap(),
                    ConnectionId::new(&[2]).unwrap(),
                ];
                for (index, id) in ids.into_iter().enumerate() {
                    endpoint
                        .create_connection_for_testing(&cx, id, peer_addr)
                        .await
                        .unwrap();
                    endpoint.queue_connection_packets(
                        id,
                        [OutgoingPacket {
                            dst_addr: peer_addr,
                            data: vec![u8::try_from(index).unwrap()],
                            send_time: None,
                        }],
                    );
                }
                // Force a real receive turn followed by a cooperative yield while
                // both packets are still locally owned, then drop the loop future.
                endpoint.prefer_send = false;
                peer.send_to(b"invalid QUIC", endpoint.local_addr())
                    .unwrap();
                {
                    let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
                    let mut drive = std::pin::pin!(endpoint.run_event_loop(&cx));
                    assert!(drive.as_mut().poll(&mut task_cx).is_pending());
                }
                assert_eq!(endpoint.pending_outgoing.len(), 2);
                assert_eq!(
                    endpoint
                        .udp_endpoint
                        .metrics()
                        .packets_received
                        .load(Ordering::Relaxed),
                    1
                );
                assert_eq!(
                    endpoint
                        .udp_endpoint
                        .metrics()
                        .packets_sent
                        .load(Ordering::Relaxed),
                    0
                );
                let accepted = if take_next {
                    endpoint.take_next_connection(&cx).unwrap().unwrap()
                } else {
                    endpoint.take_connection(&cx, ids[0]).unwrap()
                };
                assert_eq!(accepted.connection_id, ids[0]);
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                assert_eq!(endpoint.pending_outgoing[0].connection_id, ids[1]);
                {
                    let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
                    let mut drive = std::pin::pin!(endpoint.run_event_loop(&cx));
                    assert!(drive.as_mut().poll(&mut task_cx).is_pending());
                }
                assert!(endpoint.pending_outgoing.is_empty());
                let mut buffer = [0u8; 16];
                let (length, source) = peer.recv_from(&mut buffer).unwrap();
                assert_eq!(source, endpoint.local_addr());
                assert_eq!(&buffer[..length], &[1]);
                assert_eq!(
                    peer.recv_from(&mut buffer).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                endpoint.shutdown(&cx).await.unwrap();
            }
        }));
    }

    #[test]
    fn restart_sends_retained_timer_prefix_before_another_deadline() {
        use crate::net::atp::quic::AtpPacketProtection;
        use crate::net::quic_native::{
            PacketNumberSpace, PacketProtectionSpace, QuicHandshakeTranscript,
        };
        use crate::time::{TimerDriverHandle, VirtualClock};
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let clock = Arc::new(VirtualClock::starting_at(crate::Time::from_secs(37)));
            let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
            let cx = Cx::new_with_drivers(
                crate::types::RegionId::new_for_test(0, 1),
                crate::types::TaskId::new_for_test(0, 0),
                crate::types::Budget::INFINITE,
                None,
                owner.io_driver_handle(),
                None,
                Some(driver.clone()),
                None,
            );
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_nonblocking(true).unwrap();
            let peer_addr = peer.local_addr().unwrap();
            let mut endpoint = ManagedQuicEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                ManagedEndpointConfig {
                    packet_batch_size: 4,
                    ..ManagedEndpointConfig::default()
                },
            )
            .await
            .unwrap();
            endpoint.timer_scheduler.now(&cx).unwrap();
            // Recovery fixture only: real frame protection and real UDP, with
            // explicit test keys/state rather than a claimed TLS handshake.
            for index in 0..33u64 {
                let cid = ConnectionId::new(&index.to_be_bytes()).unwrap();
                endpoint
                    .create_connection_for_testing(&cx, cid, peer_addr)
                    .await
                    .unwrap();
                if index == 32 {
                    continue;
                } // Idle tail: no overdue timer on restart.
                let mut transcript = QuicHandshakeTranscript::new();
                transcript.record("client_initial", b"retained timer client");
                transcript.record("server_handshake", b"retained timer server");
                let mut protection = AtpPacketProtection::new_client(true).unwrap();
                protection
                    .derive_keys(
                        &cx,
                        PacketProtectionSpace::OneRtt,
                        &transcript,
                        b"retained timer unit fixture",
                    )
                    .await
                    .unwrap();
                endpoint
                    .connection_router
                    .install_packet_protection(&cx, cid, protection)
                    .unwrap();
                let connection = endpoint
                    .connection_router
                    .connection_mut_for_testing(&cx, cid)
                    .unwrap();
                connection.begin_handshake(&cx).unwrap();
                connection.on_handshake_keys_available(&cx).unwrap();
                connection.on_1rtt_keys_available(&cx).unwrap();
                connection.record_verified_server_identity();
                connection.on_handshake_confirmed(&cx).unwrap();
                connection
                    .on_packet_sent(
                        &cx,
                        PacketNumberSpace::ApplicationData,
                        1_200,
                        true,
                        true,
                        1_000,
                    )
                    .unwrap();
                endpoint
                    .connection_router
                    .refresh_connection_timer_for_testing(&cx, cid, 1_000)
                    .unwrap();
            }
            let deadline = endpoint.connection_router.next_timer_deadline().unwrap();
            endpoint.refresh_timer(&cx).await.unwrap();
            assert!(
                endpoint
                    .timer_scheduler
                    .poll_timer(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                    .is_pending()
            );
            clock.advance(
                u64::try_from(
                    deadline
                        .duration_since(endpoint.timer_scheduler.now(&cx).unwrap())
                        .as_nanos(),
                )
                .unwrap(),
            );
            assert_eq!(driver.process_timers(), 1);
            assert_eq!(
                endpoint
                    .timer_scheduler
                    .poll_timer(&mut std::task::Context::from_waker(std::task::Waker::noop())),
                Poll::Ready(Some(deadline))
            );
            {
                // This is the same timer branch awaited by the main loop. Drop
                // it at the cooperative yield with its committed prefix retained.
                let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
                let mut timer_turn = std::pin::pin!(endpoint.process_timer_events(&cx, deadline));
                assert!(timer_turn.as_mut().poll(&mut task_cx).is_pending());
            }
            assert!(endpoint.pending_outgoing.is_empty());
            let next = endpoint.connection_router.next_timer_deadline().unwrap();
            assert!(next > endpoint.timer_scheduler.now(&cx).unwrap());
            let metrics = endpoint.udp_endpoint.metrics();
            {
                let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
                let mut restarted = std::pin::pin!(endpoint.run_event_loop(&cx));
                for _ in 0..64 {
                    assert!(restarted.as_mut().poll(&mut task_cx).is_pending());
                    if metrics.packets_sent.load(Ordering::Relaxed) == 32 {
                        break;
                    }
                }
            }
            assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 32);
            assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 0);
            assert!(
                next > endpoint.timer_scheduler.now(&cx).unwrap(),
                "no second PTO was needed"
            );
            let mut observed = std::collections::HashSet::new();
            let mut payload = [0u8; 1_200];
            for _ in 0..32 {
                let (length, source) = peer.recv_from(&mut payload).unwrap();
                assert_eq!(source, endpoint.local_addr());
                let crate::net::quic_core::ProtectedHeaderPrefix::Short { dst_cid, .. } =
                    crate::net::quic_core::ProtectedHeaderPrefix::decode(&payload[..length], 8)
                        .unwrap()
                else {
                    panic!("actual protected short packet expected")
                };
                assert!(observed.insert(dst_cid));
                // The packet number is header-protected; unmask it with the
                // same deterministic fixture keys every connection installed.
                let mut transcript = QuicHandshakeTranscript::new();
                transcript.record("client_initial", b"retained timer client");
                transcript.record("server_handshake", b"retained timer server");
                let mut verifier = AtpPacketProtection::new_client(true).unwrap();
                verifier
                    .derive_keys(
                        &cx,
                        PacketProtectionSpace::OneRtt,
                        &transcript,
                        b"retained timer unit fixture",
                    )
                    .await
                    .unwrap();
                let unprotected =
                    crate::net::quic_native::connection_manager::unprotect_1rtt_packet(
                        &cx,
                        dst_cid,
                        &mut verifier,
                        &payload[..length],
                    )
                    .await
                    .unwrap();
                assert_eq!(unprotected.header.packet_number, 1);
            }
            assert_eq!(observed.len(), 32);
            assert_eq!(
                peer.recv_from(&mut payload).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            endpoint.shutdown(&cx).await.unwrap();
            assert_eq!(driver.pending_count(), 0);
        }));
    }

    #[test]
    fn shutdown_uses_supplied_context_when_ambient_context_is_cancelled() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, _, driver, mut endpoint, peer, _) = selection_fixture(&owner).await;
            let ambient = Cx::new(
                crate::types::RegionId::new_for_test(0, 2),
                crate::types::TaskId::new_for_test(0, 1),
                crate::types::Budget::INFINITE,
            );
            ambient.cancel_with(crate::types::CancelKind::User, None);
            let mut shutdown = Box::pin(endpoint.shutdown(&cx));
            let result = {
                let _current = Cx::set_current(Some(ambient));
                shutdown
                    .as_mut()
                    .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
            };
            assert!(matches!(result, Poll::Ready(Ok(()))));
            drop(shutdown);
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert_eq!(driver.pending_count(), 0);
            assert!(peer.recv_from(&mut [0_u8; 1_200]).unwrap().0 > 0);
        }));
    }

    #[test]
    fn shutdown_cleanup_retires_ownership_when_parked_future_is_dropped() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, _, driver, mut endpoint, peer, cid) = selection_fixture(&owner).await;
            let deadline = endpoint.timer_scheduler.now(&cx).unwrap() + Duration::from_secs(60);
            endpoint
                .timer_scheduler
                .schedule_timer(&cx, deadline)
                .await
                .unwrap();
            let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
            {
                let _current = Cx::set_current(Some(cx.clone()));
                assert!(
                    endpoint
                        .timer_scheduler
                        .poll_timer(&mut task_cx)
                        .is_pending()
                );
            }
            assert!(driver.pending_count() > 0);
            endpoint.queue_connection_packets(
                cid,
                [OutgoingPacket {
                    dst_addr: peer.local_addr().unwrap(),
                    data: vec![1],
                    send_time: None,
                }],
            );
            // Exercise the ownership guard at a deterministic suspension point;
            // this does not claim to force kernel UDP backpressure.
            let mut parked = Box::pin(async {
                let cleanup = ManagedShutdownCleanup(&mut endpoint);
                std::future::pending::<()>().await;
                drop(cleanup);
            });
            assert!(parked.as_mut().poll(&mut task_cx).is_pending());
            drop(parked);
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert!(endpoint.pending_outgoing.is_empty());
            assert!(endpoint.pending_incoming.is_empty());
            assert!(!endpoint.timer_scheduler.has_pending_timer());
            assert_eq!(driver.pending_count(), 0);
        }));
    }

    #[test]
    fn shutdown_sends_only_protected_close_and_releases_ownership() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, _, driver, mut endpoint, peer, cid) = selection_fixture(&owner).await;
            let address = endpoint.local_addr();
            endpoint
                .create_connection_for_testing(
                    &cx,
                    ConnectionId::new(b"idle").unwrap(),
                    peer.local_addr().unwrap(),
                )
                .await
                .unwrap();
            endpoint.queue_connection_packets(
                cid,
                [OutgoingPacket {
                    dst_addr: peer.local_addr().unwrap(),
                    data: b"stale application output".to_vec(),
                    send_time: None,
                }],
            );
            endpoint.shutdown(&cx).await.unwrap();
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert!(endpoint.pending_outgoing.is_empty());
            assert_eq!(driver.pending_count(), 0);
            let mut bytes = [0_u8; 1_200];
            let (length, from) = peer.recv_from(&mut bytes).unwrap();
            assert_eq!(from, address);
            let mut verifier = selection_packet_protection(&cx).await;
            let plaintext = crate::net::quic_native::connection_manager::unprotect_1rtt_packet(
                &cx,
                cid,
                &mut verifier,
                &bytes[..length],
            )
            .await
            .unwrap()
            .plaintext;
            let frames =
                crate::net::quic_native::NativeQuicConnection::decode_frames(&plaintext).unwrap();
            assert!(matches!(frames.as_slice(), [
                crate::net::atp::protocol::quic_frames::QuicFrame::ConnectionClose {
                    error_code, frame_type: None, reason_phrase,
                }
            ] if error_code.value() == 0 && reason_phrase.is_empty()));
            endpoint.shutdown(&cx).await.unwrap();
            assert_eq!(
                peer.recv_from(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }));
    }

    #[test]
    fn shutdown_send_failure_still_retires_connections_and_timer() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            let (cx, _, driver, mut endpoint, peer, _) = selection_fixture(&owner).await;
            endpoint.udp_endpoint = QuicUdpEndpoint::bind(
                &cx, "127.0.0.1:0".parse().unwrap(), QuicUdpEndpointConfig {
                    max_packet_size: 1,
                    ..QuicUdpEndpointConfig::default()
                },
            ).await.unwrap();
            assert!(matches!(endpoint.shutdown(&cx).await,
                Err(ManagedEndpointError::UdpEndpoint(message)) if message.contains("exceeds endpoint limit")));
            assert_eq!(endpoint.connection_stats().active_connections, 0);
            assert!(!endpoint.timer_scheduler.has_pending_timer());
            assert_eq!(driver.pending_count(), 0);
            let mut bytes = [0_u8; 1_200];
            assert_eq!(peer.recv_from(&mut bytes).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        }));
    }

    #[test]
    fn shutdown_is_silent_after_peer_close_or_cancellation() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().unwrap();
            for cancelled in [false, true] {
                let (cx, _, driver, mut endpoint, peer, cid) = selection_fixture(&owner).await;
                if cancelled {
                    cx.cancel_with(crate::types::CancelKind::User, None);
                } else {
                    endpoint
                        .connection_router
                        .connection_mut_for_testing(&cx, cid)
                        .unwrap()
                        .process_frame(
                            &cx,
                            &crate::net::atp::protocol::quic_frames::QuicFrame::ConnectionClose {
                                error_code: crate::net::atp::protocol::varint::VarInt::new(42)
                                    .unwrap(),
                                frame_type: None,
                                reason_phrase: crate::bytes::Bytes::new(),
                            },
                            crate::net::quic_native::PacketNumberSpace::ApplicationData,
                        )
                        .unwrap();
                }
                let result = endpoint.shutdown(&cx).await;
                if cancelled {
                    assert_eq!(result, Err(ManagedEndpointError::Cancelled));
                } else {
                    result.unwrap();
                }
                assert_eq!(endpoint.connection_stats().active_connections, 0);
                assert_eq!(driver.pending_count(), 0);
                let mut bytes = [0_u8; 1_200];
                assert_eq!(
                    peer.recv_from(&mut bytes).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
        }));
    }

    #[test]
    fn cancelled_shutdown_retires_queued_work_and_obsolete_timer_on_retained_endpoint() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native worker context");
            let mut endpoint = ManagedQuicEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                ManagedEndpointConfig::default(),
            )
            .await
            .unwrap();
            let deadline = endpoint.timer_scheduler.now(&cx).unwrap() + Duration::from_secs(60);
            endpoint
                .timer_scheduler
                .schedule_timer(&cx, deadline)
                .await
                .unwrap();
            assert!(
                endpoint
                    .timer_scheduler
                    .poll_timer(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                    .is_pending()
            );
            let driver = cx.timer_driver().unwrap();
            let armed = driver.pending_count();
            assert!(armed > 0);
            endpoint.refresh_timer(&cx).await.unwrap();
            assert_eq!(
                driver.pending_count(),
                armed - 1,
                "no connections means no timer"
            );
            endpoint.queue_connection_packets(
                ConnectionId::default(),
                [OutgoingPacket {
                    dst_addr: "127.0.0.1:9".parse().unwrap(),
                    data: vec![1],
                    send_time: None,
                }],
            );
            cx.cancel_with(crate::types::CancelKind::User, None);
            assert_eq!(
                endpoint.shutdown(&cx).await,
                Err(ManagedEndpointError::Cancelled)
            );
            assert!(endpoint.shutting_down);
            assert!(endpoint.pending_outgoing.is_empty());
            assert!(!endpoint.timer_scheduler.has_pending_timer());
            assert_eq!(endpoint.connection_stats().active_connections, 0);
        }));
    }

    #[test]
    fn test_managed_endpoint_bind() {
        run_test_with_cx(|cx| async move {
            let config = ManagedEndpointConfig::default();
            let endpoint = ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                .await
                .expect("bind should succeed");

            assert_ne!(endpoint.local_addr().port(), 0);
            assert_ne!(endpoint.endpoint_id(), 0);

            let stats = endpoint.connection_stats();
            assert_eq!(stats.active_connections, 0);
        });
    }

    #[test]
    fn test_managed_endpoint_config_validation() {
        run_test_with_cx(|cx| async move {
            // Test max_connections = 0
            let mut config = ManagedEndpointConfig::default();
            config.max_connections = 0;

            let result =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config).await;
            assert!(matches!(
                result,
                Err(ManagedEndpointError::InvalidConfig(_))
            ));

            // Test packet_batch_size = 0
            let mut config = ManagedEndpointConfig::default();
            config.packet_batch_size = 0;

            let result =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config).await;
            assert!(matches!(
                result,
                Err(ManagedEndpointError::InvalidConfig(_))
            ));
        });
    }

    #[test]
    fn test_endpoint_shutdown() {
        run_test_with_cx(|cx| async move {
            let config = ManagedEndpointConfig::default();
            let mut endpoint =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                    .await
                    .expect("bind should succeed");

            // Shutdown should complete without error
            endpoint
                .shutdown(&cx)
                .await
                .expect("shutdown should succeed");
            assert!(endpoint.shutting_down);
        });
    }

    #[test]
    fn test_managed_endpoint_take_connection_handoff() {
        run_test_with_cx(|cx| async move {
            let config = ManagedEndpointConfig::default();
            let mut endpoint =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                    .await
                    .expect("bind should succeed");
            let connection_id = ConnectionId::new(&[0x24, 0x00, 0x00, 0x01]).expect("cid");
            let peer_addr: SocketAddr = "127.0.0.1:5666".parse().unwrap();
            endpoint
                .connection_router
                .create_connection(&cx, connection_id, peer_addr, true)
                .await
                .expect("connection creation should succeed");

            let accepted = endpoint
                .take_connection(&cx, connection_id)
                .expect("endpoint should hand off connection");
            assert_eq!(accepted.connection_id, connection_id);
            assert_eq!(accepted.peer_addr, peer_addr);
            assert_eq!(endpoint.connection_stats().active_connections, 0);

            let err = endpoint
                .take_connection(&cx, connection_id)
                .expect_err("missing connection must fail closed");
            assert!(matches!(
                err,
                ManagedEndpointError::ConnectionRouter(
                    ConnectionRouterError::ConnectionNotFound(id)
                ) if id == connection_id
            ));
        });
    }

    #[test]
    fn test_managed_endpoint_take_next_connection_handoff_order() {
        run_test_with_cx(|cx| async move {
            let config = ManagedEndpointConfig::default();
            let mut endpoint =
                ManagedQuicEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                    .await
                    .expect("bind should succeed");
            let first = ConnectionId::new(&[0x01, 0x22, 0x00, 0x00]).expect("first cid");
            let second = ConnectionId::new(&[0x02, 0x22, 0x00, 0x00]).expect("second cid");
            let peer_addr: SocketAddr = "127.0.0.1:5667".parse().unwrap();

            for connection_id in [second, first] {
                endpoint
                    .connection_router
                    .create_connection(&cx, connection_id, peer_addr, true)
                    .await
                    .expect("connection creation should succeed");
            }

            let accepted = endpoint
                .take_next_connection(&cx)
                .expect("take should succeed")
                .expect("connection should exist");
            assert_eq!(accepted.connection_id, first);
            assert_eq!(endpoint.connection_stats().active_connections, 1);

            let accepted = endpoint
                .take_next_connection(&cx)
                .expect("take should succeed")
                .expect("connection should exist");
            assert_eq!(accepted.connection_id, second);
            assert_eq!(endpoint.connection_stats().active_connections, 0);

            assert!(
                endpoint
                    .take_next_connection(&cx)
                    .expect("empty take should succeed")
                    .is_none()
            );
        });
    }

    #[cfg(feature = "tls")]
    mod authenticated_accept_tests {
        use super::*;
        use crate::net::quic_core::PacketHeader;

        /// Encode a STREAM packet independently of the connection assembler.
        /// Packet protection still uses the real TLS-negotiated client keys.
        fn first_application_packet(
            driver: &mut QuicHandshakeDriver,
            destination: ConnectionId,
        ) -> Vec<u8> {
            use crate::net::quic_native::{
                PacketProtectionRequest, PacketProtectionSpace, QuicPacketProtectionProvider,
            };

            const REQUEST: &[u8] = b"coalesced first request";
            // STREAM + LEN + FIN, stream 0, one-byte length, payload. No shared
            // frame encoder can manufacture the receive oracle for this test.
            let mut plaintext = vec![0x0b, 0, u8::try_from(REQUEST.len()).unwrap()];
            plaintext.extend_from_slice(REQUEST);
            let mut packet = vec![0x43]; // fixed bit, four-byte packet number
            packet.extend_from_slice(destination.as_bytes());
            let number_offset = packet.len();
            packet.extend_from_slice(&0u32.to_be_bytes());
            let protected = driver
                .provider_mut()
                .protect_packet(PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: 0,
                    associated_data: &packet,
                    payload: &plaintext,
                })
                .unwrap();
            packet.extend_from_slice(&protected.ciphertext);
            packet.extend_from_slice(&protected.tag);
            let sample: [u8; 16] = packet[number_offset + 4..number_offset + 20]
                .try_into()
                .unwrap();
            let mask = driver
                .provider()
                .header_protection_mask(PacketProtectionSpace::OneRtt, &sample)
                .unwrap();
            packet[0] ^= mask.bytes[0] & 0x1f;
            for index in 0..4 {
                packet[number_offset + index] ^= mask.bytes[index + 1];
            }
            packet
        }

        #[test]
        fn managed_accept_delivers_coalesced_request_and_sends_final_ack_over_native_udp() {
            use super::super::super::handshake_driver::{
                client_config, server_config,
                tests::{CA_CERT_PEM, LEAF_CERT_PEM, leaf_key, parse_one_cert},
            };
            use crate::net::quic_core::TransportParameters;
            use crate::net::quic_native::StreamId;

            for case in ["valid", "bad_tag", "wrong_cid", "cancel"] {
                let runtime = crate::runtime::RuntimeBuilder::current_thread()
                    .with_reactor(crate::runtime::reactor::create_reactor().unwrap())
                    .build()
                    .unwrap();
                runtime.block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().unwrap();
                    let timer = cx.timer_driver().unwrap().clone();
                    let parameters = TransportParameters {
                        initial_max_streams_bidi: Some(4),
                        initial_max_data: Some(4096),
                        initial_max_stream_data_bidi_remote: Some(4096),
                        initial_max_stream_data_bidi_local: Some(4096),
                        ..TransportParameters::default()
                    };
                    let mut encoded = Vec::new();
                    parameters.encode(&mut encoded).unwrap();
                    let mut endpoint = ManagedQuicEndpoint::bind(
                        &cx,
                        "127.0.0.1:0".parse().unwrap(),
                        ManagedEndpointConfig {
                            is_server: true,
                            packet_batch_size: 1,
                            ..ManagedEndpointConfig::default()
                        },
                    )
                    .await
                    .unwrap();
                    endpoint
                        .configure_authenticated_server(
                            &cx,
                            server_config(
                                vec![parse_one_cert(LEAF_CERT_PEM)],
                                leaf_key(),
                                vec![b"atp/1".to_vec()],
                            )
                            .unwrap(),
                            encoded.clone(),
                            b"atp/1",
                        )
                        .unwrap();
                    let server_addr = endpoint.local_addr();
                    let client_cid = ConnectionId::new(&[0xd4; 8]).unwrap();
                    let initial_cid = ConnectionId::new(&[0xd5; 8]).unwrap();
                    let mut client = QuicHandshakeDriver::client(
                        client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![b"atp/1".to_vec()])
                            .unwrap(),
                        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                        encoded,
                    )
                    .unwrap();
                    client.install_initial_keys(initial_cid.as_bytes()).unwrap();
                    let mut peer = QuicUdpEndpoint::bind(
                        &cx,
                        "127.0.0.1:0".parse().unwrap(),
                        QuicUdpEndpointConfig::default(),
                    )
                    .await
                    .unwrap();
                    let client_exchange = async {
                        let segments = client.pump_outbound().unwrap();
                        assert_eq!(segments.len(), 1, "actual ClientHello flight");
                        let hello = client
                            .assemble_handshake_packet(&segments[0], initial_cid, client_cid, 0)
                            .unwrap();
                        let sent = peer
                            .send_batch(
                                &cx,
                                &[OutgoingPacket {
                                    dst_addr: server_addr,
                                    data: hello,
                                    send_time: None,
                                }],
                            )
                            .await
                            .unwrap();
                        assert_eq!(sent.packets_processed, 1);
                        assert!(sent.error.is_none());
                        let mut finished = Vec::new();
                        while !client.is_complete() {
                            for packet in peer.receive_batch(&cx, 8).await.unwrap() {
                                assert_eq!(packet.src_addr, server_addr);
                                client.recv_handshake_packet(&packet.data).unwrap();
                                finished.extend(client.pump_outbound().unwrap());
                            }
                        }
                        let finished: Vec<_> = finished
                            .into_iter()
                            .filter(|segment| segment.level == HandshakeLevel::Handshake)
                            .collect();
                        assert_eq!(finished.len(), 1, "actual client Finished flight");
                        let server_cid = client.peer_connection_id().unwrap();
                        // Deliberately leave a packet-number gap; the final ACK
                        // must acknowledge 7 only, never fabricate receipt of 0..6.
                        let mut datagram = client
                            .assemble_handshake_packet(&finished[0], server_cid, client_cid, 7)
                            .unwrap();
                        let destination = if case == "wrong_cid" {
                            initial_cid
                        } else {
                            server_cid
                        };
                        let mut application = first_application_packet(&mut client, destination);
                        if case == "bad_tag" {
                            *application.last_mut().unwrap() ^= 1;
                        }
                        datagram.extend_from_slice(&application);
                        assert!(
                            datagram.len() <= 1200,
                            "Finished and request share one UDP datagram"
                        );
                        let sent = peer
                            .send_batch(
                                &cx,
                                &[OutgoingPacket {
                                    dst_addr: server_addr,
                                    data: datagram,
                                    send_time: None,
                                }],
                            )
                            .await
                            .unwrap();
                        assert_eq!(sent.packets_processed, 1);
                        assert!(sent.error.is_none());
                        application
                    };
                    let server_exchange =
                        endpoint.run_event_loop_with_application(&cx, |_, endpoint, _| {
                            if endpoint
                                .pending_authenticated_accept
                                .iter()
                                .any(|pending| pending.driver.is_complete())
                                || !endpoint.authenticated_accept_result.is_empty()
                            {
                                Poll::Ready(Ok(()))
                            } else {
                                Poll::Pending
                            }
                        });
                    let (application, server_result) = crate::time::timeout(
                        cx.now(),
                        Duration::from_secs(8),
                        futures_lite::future::zip(client_exchange, server_exchange),
                    )
                    .await
                    .expect("native TLS admission reached client Finished");
                    server_result.unwrap();

                    let pending = endpoint
                        .pending_authenticated_accept
                        .front()
                        .expect("final ACK remains owned before send");
                    assert!(pending.driver.is_complete());
                    assert!(pending.final_ack_queued);
                    assert_eq!(pending.outstanding_packets, 1);
                    assert!(
                        endpoint.authenticated_accept_result.is_empty(),
                        "accept receipt must follow real ACK transmission"
                    );
                    assert_eq!(endpoint.connection_stats().active_connections, 0);
                    let server_cid = pending.local_cid;
                    let retained = pending.early.first().map(|packet| {
                        (packet.data.clone(), packet.receive_time, packet.transmit_time)
                    });
                    if case == "wrong_cid" {
                        assert!(retained.is_none());
                        assert_eq!(pending.early_bytes, 0);
                    } else {
                        assert_eq!(retained.as_ref().unwrap().0, application);
                        assert_eq!(pending.early_bytes, application.len());
                    }
                    let final_ack = endpoint
                        .pending_outgoing
                        .front()
                        .expect("protected final ACK queued for socket")
                        .packet
                        .data
                        .clone();
                    assert_eq!(pending.outstanding_bytes, final_ack.len());

                    // Drop a real managed driver at its cooperative Pending
                    // boundary before the socket gets another send turn. This
                    // is owner-retention proof, not claimed UDP backpressure.
                    let mut callback_calls = 0;
                    {
                        let mut run = std::pin::pin!(endpoint.run_event_loop_with_application(
                            &cx,
                            |_, _, _| {
                                callback_calls += 1;
                                Poll::<Result<(), ManagedEndpointError>>::Pending
                            }
                        ));
                        assert!(
                            run.as_mut()
                                .poll(&mut Context::from_waker(Waker::noop()))
                                .is_pending()
                        );
                    }
                    assert_eq!(callback_calls, 1);
                    let pending = endpoint.pending_authenticated_accept.front().unwrap();
                    assert_eq!(pending.outstanding_packets, 1);
                    assert_eq!(
                        endpoint.pending_outgoing.front().unwrap().packet.data,
                        final_ack
                    );
                    assert_eq!(
                        pending.early.first().map(|packet| (
                            packet.data.clone(),
                            packet.receive_time,
                            packet.transmit_time
                        )),
                        retained
                    );

                    if case == "cancel" {
                        let cancel = Cx::for_testing();
                        cancel.set_cancel_requested(true);
                        assert_eq!(
                            endpoint.run_event_loop(&cancel).await,
                            Err(ManagedEndpointError::Cancelled)
                        );
                        assert!(endpoint.pending_authenticated_accept.is_empty());
                        assert!(endpoint.pending_outgoing.is_empty());
                        assert!(endpoint.pending_incoming.is_empty());
                        assert_eq!(endpoint.connection_stats().active_connections, 0);
                        assert!(matches!(
                            endpoint.take_authenticated_accept_result_with_id(),
                            Some((id, Err(ManagedEndpointError::Cancelled))) if id == server_cid
                        ));
                    } else {
                        let mut accepted = None;
                        crate::time::timeout(
                            cx.now(),
                            Duration::from_secs(8),
                            endpoint.run_event_loop_with_application(&cx, |cx, endpoint, _| {
                                if let Some(result) = endpoint.take_authenticated_accept_result() {
                                    accepted = Some(result.unwrap());
                                }
                                if let Some(cid) = accepted
                                    && endpoint.pending_incoming.is_empty()
                                {
                                    assert_eq!(cid, server_cid);
                                    endpoint.with_connection_mut(cx, cid, |connection| {
                                        let received = connection.read_stream(cx, StreamId(0), 4096);
                                        if case == "valid" {
                                            assert_eq!(received.unwrap().as_ref(), b"coalesced first request");
                                            assert!(connection.is_stream_eof(StreamId(0)).unwrap());
                                            assert!(connection.read_stream(cx, StreamId(0), 4096).unwrap().is_empty());
                                        } else {
                                            assert!(matches!(received, Err(super::super::super::NativeQuicConnectionError::StreamTable(
                                                super::super::super::StreamTableError::UnknownStream(StreamId(0))
                                            ))));
                                        }
                                    }).unwrap();
                                    Poll::Ready(Ok(()))
                                } else {
                                    Poll::Pending
                                }
                            }),
                        )
                        .await
                        .expect("native route consumes the retained coalesced packet")
                        .unwrap();
                        let received = crate::time::timeout(
                            cx.now(),
                            Duration::from_secs(2),
                            peer.receive_batch(&cx, 1),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                        assert_eq!(received.len(), 1);
                        assert_eq!(
                            received[0].data, final_ack,
                            "socket transmits the retained protected ACK exactly"
                        );
                        let ProtectedHeaderPrefix::Long(prefix) =
                            ProtectedHeaderPrefix::decode(&received[0].data, 0).unwrap()
                        else {
                            panic!("final ACK must use Handshake keys");
                        };
                        let (header, plaintext) = client
                            .unprotect_long_header_packet(&prefix, &received[0].data)
                            .unwrap();
                        assert_eq!(header.packet_type, LongPacketType::Handshake);
                        assert_eq!(header.dst_cid, client_cid);
                        assert_eq!(header.src_cid, server_cid);
                        assert_eq!(
                            plaintext,
                            vec![0x02, 7, 0, 0, 0],
                            "independent ACK(7), delay=0, zero gaps, first range=0 wire oracle"
                        );
                    }
                    endpoint.shutdown(&cx).await.unwrap();
                    peer.shutdown(&cx).await.unwrap();
                    assert_eq!(endpoint.connection_stats().active_connections, 0);
                    assert!(endpoint.pending_outgoing.is_empty());
                    assert!(endpoint.pending_incoming.is_empty());
                    assert_eq!(timer.pending_count(), 0);
                }));
            }
        }

        #[test]
        fn managed_accept_early_ciphertext_budget_refuses_before_changing_retained_packets() {
            // Preparing an authenticated accept schedules QUIC timers, which
            // need a runtime Cx with a timer driver (the siblings' pattern).
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let cx = Cx::current().unwrap();
                let mut endpoint = ManagedQuicEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    ManagedEndpointConfig {
                        is_server: true,
                        ..ManagedEndpointConfig::default()
                    },
                )
                .await
                .unwrap();
                endpoint.authenticated_only = true;
                let peer = "127.0.0.1:9191".parse().unwrap();
                for (packet_bytes, packet_count) in [(32, ACCEPT_MAX_PACKETS), (4096, 512)] {
                    let mut pending = endpoint
                        .prepare_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            ConnectionId::new(&[0x21; 8]).unwrap(),
                            ConnectionId::new(&[0x22; 8]).unwrap(),
                            b"atp/1",
                        )
                        .unwrap();
                    let mut data = vec![0xa5; packet_bytes];
                    data[0] = 0x43;
                    data[1..9].copy_from_slice(pending.local_cid.as_bytes());
                    let packet = ReceivedPacket {
                        src_addr: peer,
                        data,
                        receive_time: Instant::now(),
                        transmit_time: None,
                    };
                    // This is supplemental queue-admission coverage. The
                    // preceding native test proves production TLS/UDP routing.
                    for _ in 0..packet_count {
                        pending.retain_early_packet(packet.clone()).unwrap();
                    }
                    let byte_count: usize = pending.early.iter().map(|packet| packet.data.len()).sum();
                    assert_eq!(pending.early_bytes, byte_count);
                    assert_eq!(byte_count, packet_count * packet_bytes);
                    assert_eq!(
                        pending.retain_early_packet(packet.clone()),
                        Err(accept_error("early application packet bound exhausted"))
                    );
                    assert_eq!(pending.early.len(), packet_count);
                    assert_eq!(pending.early_bytes, byte_count);
                    assert!(pending.early.iter().all(|retained| retained == &packet));
                }
                endpoint.shutdown(&cx).await.unwrap();
            }));
        }

        // The established route comes from selection_fixture's documented
        // recovery-state fixture. These tests prove pending-owner mechanics,
        // not a completed authenticated two-peer exchange or client identity.
        fn enable_admission_mechanics(endpoint: &mut ManagedQuicEndpoint) {
            endpoint.authenticated_only = true;
            endpoint.config.is_server = true;
            endpoint.config.udp_config.max_packet_size = 16_384;
        }

        fn server_policy(cancel_on_certificate: Option<Cx>) -> Arc<rustls::ServerConfig> {
            use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

            #[derive(Debug)]
            struct CancellingResolver {
                cx: Cx,
                inner: Arc<dyn rustls::server::ResolvesServerCert>,
            }

            impl rustls::server::ResolvesServerCert for CancellingResolver {
                fn resolve(
                    &self,
                    hello: rustls::server::ClientHello<'_>,
                ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                    self.cx.cancel_with(
                        crate::types::CancelKind::User,
                        Some("cancel inside actual TLS certificate resolution"),
                    );
                    self.inner.resolve(hello)
                }
            }

            let certs = CertificateDer::pem_reader_iter(&mut std::io::Cursor::new(include_bytes!(
                "../../../tests/fixtures/tls/server.crt"
            )))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let key = PrivateKeyDer::pem_reader_iter(&mut std::io::Cursor::new(include_bytes!(
                "../../../tests/fixtures/tls/server.key"
            )))
            .next()
            .transpose()
            .unwrap()
            .unwrap();
            let mut config = super::super::super::handshake_driver::server_config(
                certs,
                key,
                vec![b"atp/1".to_vec()],
            )
            .unwrap();
            if let Some(cx) = cancel_on_certificate {
                let config = Arc::get_mut(&mut config).unwrap();
                config.cert_resolver = Arc::new(CancellingResolver {
                    cx,
                    inner: Arc::clone(&config.cert_resolver),
                });
            }
            config
        }

        fn server_driver(cancel_on_certificate: Option<Cx>) -> QuicHandshakeDriver {
            QuicHandshakeDriver::server(server_policy(cancel_on_certificate), Vec::new()).unwrap()
        }

        fn initial_packet(peer: SocketAddr, initial: ConnectionId, now: Instant) -> ReceivedPacket {
            let config = super::super::super::handshake_driver::client_config(
                Vec::new(),
                vec![b"atp/1".to_vec()],
            )
            .unwrap();
            let mut client = QuicHandshakeDriver::client(
                config,
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                Vec::new(),
            )
            .unwrap();
            client.install_initial_keys(initial.as_bytes()).unwrap();
            let segments = client.pump_outbound().unwrap();
            assert_eq!(segments.len(), 1, "one actual ClientHello flight");
            let data = client
                .assemble_handshake_packet(
                    &segments[0],
                    initial,
                    ConnectionId::new(&[0x33; 8]).unwrap(),
                    0,
                )
                .unwrap();
            ReceivedPacket {
                src_addr: peer,
                data,
                receive_time: now,
                transmit_time: None,
            }
        }

        fn routed_packet(cid: ConnectionId, peer: SocketAddr, value: u8) -> RoutedOutgoingPacket {
            RoutedOutgoingPacket {
                connection_id: cid,
                packet: OutgoingPacket {
                    dst_addr: peer,
                    data: vec![value; 32],
                    send_time: None,
                },
                final_handshake_flight: false,
                ack_eliciting: false,
            }
        }

        fn short_packet(cid: ConnectionId, peer: SocketAddr, now: Instant) -> ReceivedPacket {
            let mut data = Vec::new();
            PacketHeader::Short(crate::net::quic_core::ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: cid,
                packet_number: 0,
                packet_number_len: 1,
            })
            .encode(&mut data)
            .unwrap();
            ReceivedPacket {
                src_addr: peer,
                data,
                receive_time: now,
                transmit_time: None,
            }
        }

        #[test]
        fn managed_accept_automatic_policy_preflight_and_malformed_initials_are_atomic() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, existing) =
                    selection_fixture(&Cx::current().unwrap()).await;
                endpoint.remove_connection(&cx, existing).unwrap();
                endpoint.config.is_server = true;
                let peer = peer.local_addr().unwrap();
                for (parameters, alpn) in [
                    (Vec::new(), b"absent".as_slice()),
                    (vec![0xff], b"atp/1".as_slice()),
                    (vec![0x02, 0], b"atp/1".as_slice()),
                    (vec![0x0d, 0], b"atp/1".as_slice()),
                    (vec![0x10, 0], b"atp/1".as_slice()),
                ] {
                    assert!(
                        endpoint
                            .configure_authenticated_server(
                                &cx,
                                server_policy(None),
                                parameters,
                                alpn,
                            )
                            .is_err()
                    );
                    assert!(!endpoint.authenticated_only);
                    assert!(endpoint.authenticated_server.is_none());
                }
                endpoint
                    .configure_authenticated_server(
                        &cx,
                        server_policy(None),
                        vec![0x00, 1, 9, 0x0f, 1, 8],
                        b"atp/1",
                    )
                    .unwrap();
                assert!(endpoint.authenticated_only);
                assert!(
                    endpoint
                        .configure_authenticated_server(
                            &cx,
                            server_policy(None),
                            Vec::new(),
                            b"absent",
                        )
                        .is_err()
                );
                assert_eq!(
                    endpoint
                        .authenticated_server
                        .as_ref()
                        .unwrap()
                        .required_alpn,
                    b"atp/1"
                );
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let initial = ConnectionId::new(&[0xe1; 8]).unwrap();
                let packet = initial_packet(peer, initial, now);
                let mut corrupt = packet.clone();
                *corrupt.data.last_mut().unwrap() ^= 1;
                let mut undersized = packet.clone();
                undersized.data.truncate(1199);
                let mut wrong_version = packet.clone();
                wrong_version.data[1..5].copy_from_slice(&2u32.to_be_bytes());
                for invalid in [
                    corrupt,
                    undersized,
                    wrong_version,
                    initial_packet(peer, ConnectionId::new(&[0xe2; 4]).unwrap(), now),
                ] {
                    assert!(
                        endpoint
                            .try_automatic_authenticated_accept(&cx, &invalid)
                            .unwrap()
                    );
                    assert!(endpoint.pending_authenticated_accept.is_empty());
                    assert!(endpoint.authenticated_accept_result.is_empty());
                    assert!(endpoint.pending_outgoing.is_empty());
                    assert_eq!(endpoint.connection_stats().active_connections, 0);
                }
                assert!(
                    endpoint
                        .try_automatic_authenticated_accept(&cx, &packet)
                        .unwrap()
                );
                assert_eq!(endpoint.pending_authenticated_accept.len(), 1);
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                let local = pending.local_cid;
                assert_eq!(local.len(), ConnectionId::MAX_LEN);
                assert_ne!(local, initial);
                assert_eq!(pending.peer, peer);
                assert_eq!(pending.received_packets, 1);
                assert!(
                    !pending.outbound.is_empty(),
                    "actual TLS flight was produced"
                );
                let parameters = crate::net::quic_core::TransportParameters::decode(
                    pending.driver.local_transport_parameters(),
                )
                .unwrap();
                for (id, expected) in [(0x00, initial), (0x0f, local)] {
                    assert_eq!(
                        parameters
                            .unknown
                            .iter()
                            .find(|p| p.id == id)
                            .unwrap()
                            .value,
                        expected.as_bytes(),
                        "each admitted CID replaces the static template value"
                    );
                }
                let mut wrong_peer = packet;
                wrong_peer.src_addr = "127.0.0.1:1".parse().unwrap();
                endpoint
                    .process_packet_batch(&cx, vec![wrong_peer])
                    .await
                    .unwrap();
                assert_eq!(
                    endpoint
                        .pending_authenticated_accept
                        .front()
                        .unwrap()
                        .received_packets,
                    1
                );
                assert_eq!(endpoint.stop_authenticated_accepts(), 1);
                assert_eq!(endpoint.stop_authenticated_accepts(), 0);
                assert_eq!(
                    endpoint.take_authenticated_accept_result_with_id(),
                    Some((local, Err(ManagedEndpointError::ShuttingDown)))
                );
                assert!(endpoint.pending_outgoing.is_empty());
                assert!(
                    endpoint.authenticated_only,
                    "closing admission never restores the plaintext path"
                );
                assert_eq!(
                    endpoint.configure_authenticated_server(
                        &cx,
                        server_policy(None),
                        Vec::new(),
                        b"atp/1",
                    ),
                    Err(ManagedEndpointError::ShuttingDown)
                );
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_automatic_cancellation_before_publication_retains_no_owner() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, existing) =
                    selection_fixture(&Cx::current().unwrap()).await;
                endpoint.remove_connection(&cx, existing).unwrap();
                endpoint.config.is_server = true;
                endpoint
                    .configure_authenticated_server(
                        &cx,
                        server_policy(Some(cx.clone())),
                        Vec::new(),
                        b"atp/1",
                    )
                    .unwrap();
                let packet = initial_packet(
                    peer.local_addr().unwrap(),
                    ConnectionId::new(&[0xe3; 8]).unwrap(),
                    endpoint.timer_scheduler.now(&cx).unwrap(),
                );
                assert_eq!(
                    endpoint.try_automatic_authenticated_accept(&cx, &packet),
                    Err(ManagedEndpointError::Cancelled)
                );
                assert!(endpoint.pending_authenticated_accept.is_empty());
                assert!(endpoint.authenticated_accept_result.is_empty());
                assert!(endpoint.pending_outgoing.is_empty());
                assert_eq!(endpoint.connection_stats().active_connections, 0);
                let _ = endpoint.shutdown(&cx).await;
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_segments_large_tls_flights_with_full_size_cids() {
            use super::super::super::handshake_driver::{
                client_config, server_config,
                tests::{CA_CERT_PEM, LEAF_CERT_PEM, leaf_key, parse_one_cert},
            };

            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, existing) =
                    selection_fixture(&Cx::current().unwrap()).await;
                endpoint.remove_connection(&cx, existing).unwrap();
                endpoint.config.is_server = true;
                endpoint.config.udp_config.max_packet_size = 1500;
                let mut parameters = crate::net::quic_core::TransportParameters::default();
                parameters
                    .unknown
                    .push(crate::net::quic_core::UnknownTransportParameter {
                        id: 0x173e,
                        value: vec![7; 4096],
                    });
                let mut encoded = Vec::new();
                parameters.encode(&mut encoded).unwrap();
                let tls = server_config(
                    vec![parse_one_cert(LEAF_CERT_PEM)],
                    leaf_key(),
                    vec![b"atp/1".to_vec()],
                )
                .unwrap();
                endpoint
                    .configure_authenticated_server(&cx, tls, encoded, b"atp/1")
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let peer_parameters = crate::net::quic_core::TransportParameters {
                    max_udp_payload_size: Some(1200),
                    ..crate::net::quic_core::TransportParameters::default()
                };
                let mut peer_encoded = Vec::new();
                peer_parameters.encode(&mut peer_encoded).unwrap();
                let mut client = QuicHandshakeDriver::client(
                    client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![b"atp/1".to_vec()])
                        .unwrap(),
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    peer_encoded,
                )
                .unwrap();
                let initial_cid = ConnectionId::new(&[0xe4; 20]).unwrap();
                let client_cid = ConnectionId::new(&[0xe5; 20]).unwrap();
                client.install_initial_keys(initial_cid.as_bytes()).unwrap();
                let segments = client.pump_outbound().unwrap();
                assert_eq!(segments.len(), 1);
                let packet = ReceivedPacket {
                    src_addr: peer.local_addr().unwrap(),
                    data: client
                        .assemble_handshake_packet(&segments[0], initial_cid, client_cid, 0)
                        .unwrap(),
                    receive_time: now,
                    transmit_time: None,
                };
                assert!(
                    endpoint
                        .try_automatic_authenticated_accept(&cx, &packet)
                        .unwrap()
                );
                let pending = endpoint
                    .pending_authenticated_accept
                    .front()
                    .expect("large valid TLS flight remains admitted");
                assert_eq!(pending.local_cid.len(), 20);
                assert!(
                    pending.last_flight.len() >= 5,
                    "TLS bytes split across bounded datagrams"
                );
                assert!(
                    pending
                        .last_flight
                        .iter()
                        .all(|packet| packet.data.len() <= 1200)
                );
                assert!(pending.outstanding_bytes > 4096);
                assert_eq!(
                    pending.outstanding_bytes,
                    pending
                        .last_flight
                        .iter()
                        .map(|packet| packet.data.len())
                        .sum::<usize>()
                );
                assert!(pending.outstanding_bytes <= ACCEPT_MAX_BYTES);
                // Real decryption and CRYPTO reassembly must reach the end of
                // the server's enlarged TLS flight without an offset gap.
                for packet in &pending.last_flight {
                    assert_eq!(
                        client.recv_handshake_packet(&packet.data).unwrap(),
                        pending.local_cid
                    );
                    let _ = client.pump_outbound().unwrap();
                }
                assert!(client.is_complete());
                assert!(client.one_rtt_keys_installed());
                let server_parameters = crate::net::quic_core::TransportParameters::decode(
                    client.peer_transport_parameters().unwrap(),
                )
                .unwrap();
                assert!(server_parameters.unknown.iter().any(|parameter| {
                    parameter.id == 0x173e && parameter.value == vec![7; 4096]
                }));
                endpoint.queue_accept_output();
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert!(
                    pending.socket_pending_bytes as u64 <= pending.authenticated_received_bytes * 3
                );
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_pto_resends_the_flight_under_new_packet_numbers() {
            use super::super::super::handshake_driver::{
                client_config, server_config,
                tests::{CA_CERT_PEM, LEAF_CERT_PEM, leaf_key, parse_one_cert},
            };

            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, existing) =
                    selection_fixture(&Cx::current().unwrap()).await;
                endpoint.remove_connection(&cx, existing).unwrap();
                endpoint.config.is_server = true;
                endpoint.config.udp_config.max_packet_size = 1500;
                endpoint.config.packet_batch_size = 1024;
                let mut parameters = Vec::new();
                crate::net::quic_core::TransportParameters::default()
                    .encode(&mut parameters)
                    .unwrap();
                let tls = server_config(
                    vec![parse_one_cert(LEAF_CERT_PEM)],
                    leaf_key(),
                    vec![b"atp/1".to_vec()],
                )
                .unwrap();
                endpoint
                    .configure_authenticated_server(&cx, tls, parameters, b"atp/1")
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let mut client = QuicHandshakeDriver::client(
                    client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![b"atp/1".to_vec()])
                        .unwrap(),
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    Vec::new(),
                )
                .unwrap();
                let initial_cid = ConnectionId::new(&[0xd6; 8]).unwrap();
                let client_cid = ConnectionId::new(&[0xd7; 8]).unwrap();
                client.install_initial_keys(initial_cid.as_bytes()).unwrap();
                let segments = client.pump_outbound().unwrap();
                let packet = ReceivedPacket {
                    src_addr: peer.local_addr().unwrap(),
                    data: client
                        .assemble_handshake_packet(&segments[0], initial_cid, client_cid, 0)
                        .unwrap(),
                    receive_time: now,
                    transmit_time: None,
                };
                assert!(
                    endpoint
                        .try_automatic_authenticated_accept(&cx, &packet)
                        .unwrap()
                );
                let first: Vec<Vec<u8>> = endpoint
                    .pending_authenticated_accept
                    .front()
                    .unwrap()
                    .last_flight
                    .iter()
                    .map(|packet| packet.data.clone())
                    .collect();
                assert!(!first.is_empty(), "actual TLS server flight");
                // The client processes the whole first flight, so only its
                // acknowledgment is missing when the server's PTO fires.
                for data in &first {
                    client.recv_handshake_packet(data).unwrap();
                    let _ = client.pump_outbound().unwrap();
                }
                assert!(client.is_complete());
                let levels = [HandshakeLevel::Initial, HandshakeLevel::Handshake];
                let seen = levels.map(|level| client.received_handshake_packet_numbers(level));
                // Byte credit is not under test: a validated address lets the
                // whole first flight reach the socket queue before the PTO.
                endpoint
                    .pending_authenticated_accept
                    .front_mut()
                    .unwrap()
                    .address_validated = true;
                for _ in 0..first.len() {
                    endpoint.queue_accept_output();
                    for packet in endpoint.pending_outgoing.drain(..) {
                        endpoint
                            .pending_authenticated_accept
                            .front_mut()
                            .unwrap()
                            .sent(packet.packet.data.len());
                    }
                }
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert!(pending.outbound.is_empty());
                assert_eq!(pending.outstanding_packets, 0);
                let due = pending.next_pto;
                assert!(!endpoint.advance_authenticated_accept(&cx, due));
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert_eq!(pending.flights, 2);
                let second: Vec<Vec<u8>> = pending
                    .outbound
                    .iter()
                    .map(|packet| packet.data.clone())
                    .collect();
                assert_eq!(second.len(), first.len());
                for (old, new) in first.iter().zip(&second) {
                    assert_eq!(old.len(), new.len(), "the same CRYPTO bytes");
                    assert_ne!(old, new, "a retransmission never reuses a packet number");
                }
                for data in &second {
                    client.recv_handshake_packet(data).unwrap();
                }
                for (level, before) in levels.into_iter().zip(seen) {
                    let after = client.received_handshake_packet_numbers(level);
                    let fresh: Vec<u64> = after
                        .iter()
                        .copied()
                        .filter(|number| !before.contains(number))
                        .collect();
                    assert_eq!(
                        fresh.len(),
                        before.len(),
                        "{level:?}: every resent packet is new to the peer"
                    );
                    assert!(
                        fresh
                            .iter()
                            .all(|number| before.iter().all(|old| number > old)),
                        "{level:?}: resent packet numbers only grow"
                    );
                }
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn retry_tokens_bind_the_peer_the_cids_the_key_and_a_lifetime() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let cx = Cx::current().unwrap();
                let mut endpoint = ManagedQuicEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    ManagedEndpointConfig {
                        is_server: true,
                        ..ManagedEndpointConfig::default()
                    },
                )
                .await
                .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                endpoint.retry_secret = RetrySecret([7; 32]);
                endpoint.retry_epoch = Some(now);
                let peer: SocketAddr = "192.0.2.7:4433".parse().unwrap();
                let original = ConnectionId::new(&[1; 8]).unwrap();
                let retry = ConnectionId::new(&[2; 20]).unwrap();
                let token = endpoint
                    .mint_retry_token(peer, original, retry, now)
                    .unwrap();
                let check = |endpoint: &ManagedQuicEndpoint, token: &[u8], peer, retry, at| {
                    endpoint.validate_retry_token(token, peer, retry, at)
                };
                assert_eq!(check(&endpoint, &token, peer, retry, now), Some(original));
                let last = now + RETRY_TOKEN_LIFETIME;
                assert_eq!(check(&endpoint, &token, peer, retry, last), Some(original));
                let late = last + Duration::from_secs(1);
                assert_eq!(check(&endpoint, &token, peer, retry, late), None, "expired");
                for other in ["192.0.2.7:4434", "192.0.2.8:4433", "[2001:db8::7]:4433"] {
                    let other: SocketAddr = other.parse().unwrap();
                    assert_eq!(check(&endpoint, &token, other, retry, now), None, "{other}");
                }
                assert_eq!(
                    check(&endpoint, &token, peer, original, now),
                    None,
                    "another CID"
                );
                for index in 0..token.len() {
                    let mut forged = token.clone();
                    forged[index] ^= 1;
                    assert_eq!(
                        check(&endpoint, &forged, peer, retry, now),
                        None,
                        "byte {index}"
                    );
                }
                let short = &token[..token.len() - 1];
                assert_eq!(check(&endpoint, short, peer, retry, now), None, "truncated");
                endpoint.retry_secret = RetrySecret([8; 32]);
                assert_eq!(
                    check(&endpoint, &token, peer, retry, now),
                    None,
                    "another key"
                );
            }));
        }

        /// With `packet_batch_size: 1`, one admission packet fills the batch. A
        /// Retry dropped there left the client waiting for its PTO. On a
        /// virtual clock that never advances, the handshake hung. Retries use
        /// a bounded slack beyond the batch instead.
        #[test]
        fn a_full_send_batch_does_not_drop_a_stateless_retry() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let cx = Cx::current().unwrap();
                let mut endpoint = ManagedQuicEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    ManagedEndpointConfig {
                        is_server: true,
                        packet_batch_size: 1,
                        ..ManagedEndpointConfig::default()
                    },
                )
                .await
                .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                endpoint.retry_secret = RetrySecret([7; 32]);
                endpoint.retry_epoch = Some(now);
                let peer: SocketAddr = "192.0.2.7:4433".parse().unwrap();
                let client = ConnectionId::new(&[3; 8]).unwrap();
                let original = ConnectionId::new(&[4; 8]).unwrap();
                endpoint.pending_outgoing.push_back(RoutedOutgoingPacket {
                    connection_id: ConnectionId::new(&[5; 8]).unwrap(),
                    packet: OutgoingPacket {
                        dst_addr: "192.0.2.9:4433".parse().unwrap(),
                        data: vec![0; 1200],
                        send_time: None,
                    },
                    final_handshake_flight: false,
                    ack_eliciting: true,
                });
                endpoint.queue_retry(&cx, client, original, peer, now);
                assert_eq!(endpoint.pending_outgoing.len(), 2, "the Retry is queued");
                let retry = &endpoint.pending_outgoing[1].packet;
                assert_eq!(retry.dst_addr, peer);
                assert!(matches!(
                    ProtectedHeaderPrefix::decode(&retry.data, 0),
                    Ok(ProtectedHeaderPrefix::Retry(_))
                ));
                for _ in 0..2 * RETRY_QUEUE_SLACK {
                    endpoint.queue_retry(&cx, client, original, peer, now);
                }
                assert_eq!(
                    endpoint.pending_outgoing.len(),
                    1 + RETRY_QUEUE_SLACK,
                    "a flood fills only the bounded Retry slack"
                );
            }));
        }

        #[test]
        fn managed_retry_lets_a_validated_client_displace_a_silent_spoofed_admission() {
            use super::super::super::handshake_driver::{
                client_config, client_handshake_over_udp, server_config,
                tests::{CA_CERT_PEM, LEAF_CERT_PEM, leaf_key, parse_one_cert},
            };

            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let cx = Cx::current().unwrap();
                // One admission slot, the default, and the default Retry policy.
                let mut server = ManagedQuicEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    ManagedEndpointConfig {
                        is_server: true,
                        ..ManagedEndpointConfig::default()
                    },
                )
                .await
                .unwrap();
                let mut parameters = Vec::new();
                crate::net::quic_core::TransportParameters::default()
                    .encode(&mut parameters)
                    .unwrap();
                let tls = server_config(
                    vec![parse_one_cert(LEAF_CERT_PEM)],
                    leaf_key(),
                    vec![b"atp/1".to_vec()],
                )
                .unwrap();
                server
                    .configure_authenticated_server(&cx, tls, parameters, b"atp/1")
                    .unwrap();
                let server_addr = server.local_addr();
                let client_driver = || {
                    QuicHandshakeDriver::client(
                        client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![b"atp/1".to_vec()])
                            .unwrap(),
                        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                        Vec::new(),
                    )
                    .unwrap()
                };
                // A real ClientHello from an address that never answers takes the
                // only slot first, as a spoofed Initial would.
                let spoofer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                let spoofed_initial = ConnectionId::new(&[0x51; 8]).unwrap();
                let mut spoofed = client_driver();
                spoofed
                    .install_initial_keys(spoofed_initial.as_bytes())
                    .unwrap();
                let segments = spoofed.pump_outbound().unwrap();
                let hello = spoofed
                    .assemble_handshake_packet(
                        &segments[0],
                        spoofed_initial,
                        ConnectionId::new(&[0x52; 8]).unwrap(),
                        0,
                    )
                    .unwrap();
                spoofer.send_to(&hello, server_addr).unwrap();

                let mut client_endpoint = QuicUdpEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    QuicUdpEndpointConfig::default(),
                )
                .await
                .unwrap();
                let mut client = client_driver();
                let (outcome, client_done, receipt) = {
                    let mut handshake = std::pin::pin!(client_handshake_over_udp(
                        &cx,
                        &mut client_endpoint,
                        server_addr,
                        &mut client,
                        ConnectionId::new(&[0x61; 8]).unwrap(),
                        ConnectionId::new(&[0x62; 8]).unwrap(),
                    ));
                    let mut client_done = None;
                    let mut receipt = None;
                    let outcome = crate::time::timeout(
                        cx.now(),
                        Duration::from_secs(10),
                        server.run_event_loop_with_application(&cx, |_, endpoint, task_cx| {
                            if client_done.is_none() {
                                if let Poll::Ready(result) = handshake.as_mut().poll(task_cx) {
                                    client_done = Some(result);
                                }
                            }
                            if receipt.is_none() {
                                receipt = endpoint.take_authenticated_accept_result();
                            }
                            if client_done.is_some() && receipt.is_some() {
                                Poll::Ready(Ok(()))
                            } else {
                                Poll::Pending
                            }
                        }),
                    )
                    .await;
                    (outcome, client_done, receipt)
                };
                assert!(
                    matches!(outcome, Ok(Ok(()))),
                    "the validated client must be admitted while the spoofed one holds the slot: {outcome:?}"
                );
                assert!(matches!(client_done, Some(Ok(_))), "{client_done:?}");
                assert!(matches!(receipt, Some(Ok(_))), "{receipt:?}");
                // The client completed only after checking both Retry parameters
                // (verify_completed_retry). The server advertised a Retry source.
                let server_parameters = crate::net::quic_core::TransportParameters::decode(
                    client.peer_transport_parameters().unwrap(),
                )
                .unwrap();
                assert!(server_parameters.unknown.iter().any(|parameter| parameter.id == 0x10));
                assert!(server.pending_authenticated_accept.is_empty(), "the spoofed admission was displaced");
                assert!(server.take_authenticated_accept_result().is_none(), "displacement publishes nothing");
                server.shutdown(&cx).await.unwrap();
            }));
        }

        /// br-asupersync-2eqmd2 M3: an automatic admission whose TLS refuses
        /// the client's ALPN sends CONNECTION_CLOSE with CRYPTO_ERROR, so the
        /// client's handshake ends at once instead of retransmitting for its
        /// whole flight budget (96 s).
        #[test]
        fn managed_alpn_refusal_closes_the_client_handshake() {
            use super::super::super::handshake_driver::{
                PEER_CRYPTO_ERROR_CLOSE_CODE, client_config, client_handshake_over_udp,
                server_config,
                tests::{CA_CERT_PEM, LEAF_CERT_PEM, leaf_key, parse_one_cert},
            };

            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let cx = Cx::current().unwrap();
                let mut server = ManagedQuicEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    ManagedEndpointConfig {
                        is_server: true,
                        ..ManagedEndpointConfig::default()
                    },
                )
                .await
                .unwrap();
                let mut parameters = Vec::new();
                crate::net::quic_core::TransportParameters::default()
                    .encode(&mut parameters)
                    .unwrap();
                let tls = server_config(
                    vec![parse_one_cert(LEAF_CERT_PEM)],
                    leaf_key(),
                    vec![b"atp/1".to_vec()],
                )
                .unwrap();
                server
                    .configure_authenticated_server(&cx, tls, parameters, b"atp/1")
                    .unwrap();
                let server_addr = server.local_addr();
                let mut client_endpoint = QuicUdpEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    QuicUdpEndpointConfig::default(),
                )
                .await
                .unwrap();
                let mut client = QuicHandshakeDriver::client(
                    client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![b"h3".to_vec()]).unwrap(),
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    Vec::new(),
                )
                .unwrap();
                let (outcome, client_done) = {
                    let mut handshake = std::pin::pin!(client_handshake_over_udp(
                        &cx,
                        &mut client_endpoint,
                        server_addr,
                        &mut client,
                        ConnectionId::new(&[0x71; 8]).unwrap(),
                        ConnectionId::new(&[0x72; 8]).unwrap(),
                    ));
                    let mut client_done = None;
                    let outcome = crate::time::timeout(
                        cx.now(),
                        Duration::from_secs(10),
                        server.run_event_loop_with_application(&cx, |_, _, task_cx| {
                            if let Poll::Ready(result) = handshake.as_mut().poll(task_cx) {
                                client_done = Some(result);
                                Poll::Ready(Ok(()))
                            } else {
                                Poll::Pending
                            }
                        }),
                    )
                    .await;
                    (outcome, client_done)
                };
                assert!(
                    matches!(outcome, Ok(Ok(()))),
                    "the client's handshake must end long before its flight budget: {outcome:?}"
                );
                let refused = client_done.unwrap().expect_err("no common ALPN");
                assert!(
                    matches!(
                        refused,
                        crate::net::quic_native::QuicTlsError::CryptoProviderFailure { code, .. }
                            if code == PEER_CRYPTO_ERROR_CLOSE_CODE
                    ),
                    "{refused:?}"
                );
                // TLS alert 120, no_application_protocol.
                assert_eq!(client.peer_close_error_code(), Some(0x0100 + 120));
                assert!(server.pending_authenticated_accept.is_empty());
                server.shutdown(&cx).await.unwrap();
            }));
        }

        #[test]
        fn managed_accept_server_rejects_encoded_retry_without_claiming_other_cids() {
            let initial = ConnectionId::new(&[0x91; 8]).unwrap();
            let local = ConnectionId::new(&[0x92; 8]).unwrap();
            let other = ConnectionId::new(&[0x93; 8]).unwrap();
            let peer: SocketAddr = "127.0.0.1:9123".parse().unwrap();
            let now = Instant::now();
            let mut retained = Vec::new();
            for destination in [initial, local, other] {
                let header = PacketHeader::Retry(crate::net::quic_core::RetryHeader {
                    version: 1,
                    dst_cid: destination,
                    src_cid: ConnectionId::new(&[0x94; 8]).unwrap(),
                    token: b"actual encoded Retry token".to_vec(),
                    integrity_tag: [0x95; 16],
                });
                let mut data = Vec::new();
                header.encode(&mut data).unwrap();
                let (decoded, consumed) = PacketHeader::decode(&data, 0).unwrap();
                assert_eq!(decoded, header);
                assert_eq!(consumed, data.len());
                let packet = ReceivedPacket {
                    src_addr: peer,
                    data,
                    receive_time: now,
                    transmit_time: None,
                };
                assert!(!PendingAuthenticatedAccept::packet_matches(
                    &packet, initial, local
                ));
                retained.push(packet);
            }
            let a = short_packet(other, peer, now);
            let b = short_packet(local, peer, now);
            assert!(!PendingAuthenticatedAccept::packet_matches(
                &a, initial, local
            ));
            assert!(PendingAuthenticatedAccept::packet_matches(
                &b, initial, local
            ));
            retained.push(a.clone());
            retained.push(b);
            retained.retain(|packet| {
                !PendingAuthenticatedAccept::packet_matches(packet, initial, local)
            });
            assert_eq!(
                retained.len(),
                4,
                "only the pending server's short packet was claimed"
            );
            assert_eq!(retained.last().unwrap().data, a.data);
            // Header classification is not Retry integrity verification or an
            // authenticated peer exchange; all unclaimed packets stay with the
            // established router and its own role/authentication checks.
        }

        #[test]
        fn managed_accept_preflight_receipt_and_packet_bounds_preserve_existing_owner() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                let initial = ConnectionId::new(&[9; 8]).unwrap();
                let original_socket = endpoint.local_addr();
                let original_deadline = endpoint.connection_router.next_timer_deadline();
                enable_admission_mechanics(&mut endpoint);
                for (initial, local, alpn) in [
                    (initial, b, b"".as_slice()),
                    (a, b, b"atp/1".as_slice()),
                    (initial, a, b"atp/1".as_slice()),
                    (
                        initial,
                        ConnectionId::new(&[7; 4]).unwrap(),
                        b"atp/1".as_slice(),
                    ),
                ] {
                    assert!(
                        endpoint
                            .begin_authenticated_accept(
                                &cx,
                                server_driver(None),
                                peer,
                                initial,
                                local,
                                alpn
                            )
                            .is_err()
                    );
                    assert!(endpoint.pending_authenticated_accept.is_empty());
                    assert!(endpoint.take_authenticated_accept_result().is_none());
                    assert_eq!(endpoint.connection_stats().active_connections, 1);
                }
                endpoint.config.max_connections = 1;
                assert_eq!(
                    endpoint.begin_authenticated_accept(
                        &cx,
                        server_driver(None),
                        peer,
                        initial,
                        b,
                        b"atp/1"
                    ),
                    Err(ManagedEndpointError::MaxConnectionsReached { limit: 1 })
                );
                endpoint.config.max_connections = 2;
                endpoint
                    .begin_authenticated_accept(
                        &cx,
                        server_driver(None),
                        peer,
                        initial,
                        b,
                        b"atp/1",
                    )
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let pending = endpoint.pending_authenticated_accept.front_mut().unwrap();
                let wrong_peer = "127.0.0.1:1".parse().unwrap();
                pending
                    .receive(short_packet(b, wrong_peer, now), 16_384, now)
                    .unwrap();
                assert_eq!(pending.received_packets, 0);
                let packet = routed_packet(b, peer, 1).packet;
                let full = vec![packet.clone(); ACCEPT_MAX_PACKETS];
                pending.queue_flight(&full).unwrap();
                let owned_bytes = pending.outstanding_bytes;
                assert!(pending.queue_flight(&[packet]).is_err());
                assert_eq!(pending.outbound.len(), ACCEPT_MAX_PACKETS);
                assert_eq!(pending.outstanding_bytes, owned_bytes);
                endpoint
                    .pending_outgoing
                    .push_back(routed_packet(a, peer, 7));
                endpoint.remove_connection(&cx, b).unwrap();
                assert!(endpoint.pending_authenticated_accept.is_empty());
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                assert_eq!(endpoint.pending_outgoing[0].connection_id, a);
                assert!(
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            initial,
                            b,
                            b"atp/1"
                        )
                        .is_err(),
                    "unconsumed terminal receipt must stay owned"
                );
                assert_eq!(
                    endpoint.take_authenticated_accept_result(),
                    Some(Err(ManagedEndpointError::Cancelled))
                );
                assert!(endpoint.take_authenticated_accept_result().is_none());
                assert_eq!(endpoint.local_addr(), original_socket);
                assert_eq!(
                    endpoint.connection_router.next_timer_deadline(),
                    original_deadline
                );
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_concurrent_capacity_and_cid_ownership_include_unread_receipts() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, established) =
                    selection_fixture(&Cx::current().unwrap()).await;
                enable_admission_mechanics(&mut endpoint);
                endpoint.config.max_connections = 4;
                assert!(endpoint.set_authenticated_accept_limit(0).is_err());
                assert!(endpoint.set_authenticated_accept_limit(5).is_err());
                endpoint.set_authenticated_accept_limit(3).unwrap();
                let peer = peer.local_addr().unwrap();
                let first = ConnectionId::new(&[0x81; 8]).unwrap();
                let second = ConnectionId::new(&[0x82; 8]).unwrap();
                let third = ConnectionId::new(&[0x83; 8]).unwrap();
                let first_initial = ConnectionId::new(&[0x91; 8]).unwrap();
                let second_initial = ConnectionId::new(&[0x92; 8]).unwrap();
                let third_initial = ConnectionId::new(&[0x93; 8]).unwrap();
                for (initial, local) in [(first_initial, first), (second_initial, second)] {
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            initial,
                            local,
                            b"atp/1",
                        )
                        .unwrap();
                }
                assert_eq!(endpoint.pending_authenticated_accept.len(), 2);
                assert!(endpoint.set_authenticated_accept_limit(4).is_err());
                for (initial, local) in [
                    (first_initial, third),
                    (first, third),
                    (third_initial, first_initial),
                    (third_initial, ConnectionId::new(&[0x81; 4]).unwrap()),
                    (third_initial, ConnectionId::new(&[0x81; 12]).unwrap()),
                ] {
                    assert!(
                        endpoint
                            .begin_authenticated_accept(
                                &cx,
                                server_driver(None),
                                peer,
                                initial,
                                local,
                                b"atp/1",
                            )
                            .is_err(),
                        "pending aliases and ambiguous short IDs remain reserved"
                    );
                    assert_eq!(endpoint.pending_authenticated_accept.len(), 2);
                }
                endpoint.remove_connection(&cx, first).unwrap();
                assert!(
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            first_initial,
                            first,
                            b"atp/1",
                        )
                        .is_err(),
                    "failure receipt keeps its CID reservation"
                );
                endpoint
                    .begin_authenticated_accept(
                        &cx,
                        server_driver(None),
                        peer,
                        third_initial,
                        third,
                        b"atp/1",
                    )
                    .unwrap();
                assert!(
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            ConnectionId::new(&[0x94; 8]).unwrap(),
                            ConnectionId::new(&[0x84; 8]).unwrap(),
                            b"atp/1",
                        )
                        .is_err(),
                    "two pending plus one unread receipt fill three slots"
                );
                assert_eq!(
                    endpoint.take_authenticated_accept_result_with_id(),
                    Some((first, Err(ManagedEndpointError::Cancelled)))
                );
                endpoint.config.max_connections = 3;
                assert_eq!(
                    endpoint.begin_authenticated_accept(
                        &cx,
                        server_driver(None),
                        peer,
                        first_initial,
                        first,
                        b"atp/1",
                    ),
                    Err(ManagedEndpointError::MaxConnectionsReached { limit: 3 }),
                    "pending handshakes reserve eventual connection capacity"
                );
                endpoint.remove_connection(&cx, second).unwrap();
                endpoint.remove_connection(&cx, third).unwrap();
                assert_eq!(
                    endpoint.take_authenticated_accept_result_with_id(),
                    Some((second, Err(ManagedEndpointError::Cancelled)))
                );
                assert_eq!(
                    endpoint.take_authenticated_accept_result(),
                    Some(Err(ManagedEndpointError::Cancelled))
                );
                assert!(
                    endpoint
                        .take_authenticated_accept_result_with_id()
                        .is_none()
                );
                endpoint.set_authenticated_accept_limit(2).unwrap();
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                assert!(
                    endpoint
                        .connection_router
                        .connection_mut_for_testing(&cx, established)
                        .is_ok()
                );
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_round_robin_skips_silent_and_credit_blocked_peers() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, established) =
                    selection_fixture(&Cx::current().unwrap()).await;
                enable_admission_mechanics(&mut endpoint);
                endpoint.set_authenticated_accept_limit(3).unwrap();
                let peer = peer.local_addr().unwrap();
                let silent = ConnectionId::new(&[0xa1; 8]).unwrap();
                let first = ConnectionId::new(&[0xa2; 8]).unwrap();
                let second = ConnectionId::new(&[0xa3; 8]).unwrap();
                for (value, local) in [(0xb1, silent), (0xb2, first), (0xb3, second)] {
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            ConnectionId::new(&[value; 8]).unwrap(),
                            local,
                            b"atp/1",
                        )
                        .unwrap();
                }
                // Queue mechanics only: live TLS/UDP progress is exercised by
                // quic_h3_live_udp, not inferred from these planted flights.
                for local in [first, second] {
                    let pending = endpoint
                        .pending_authenticated_accept
                        .iter_mut()
                        .find(|pending| pending.local_cid == local)
                        .unwrap();
                    pending.address_validated = true;
                    let packet = routed_packet(local, peer, 1).packet;
                    pending.queue_flight(&[packet.clone(), packet]).unwrap();
                }
                for expected in [first, second, first, second] {
                    endpoint.queue_accept_output();
                    assert_eq!(endpoint.pending_outgoing.len(), 1);
                    let packet = endpoint.pending_outgoing.pop_front().unwrap();
                    assert_eq!(packet.connection_id, expected);
                    endpoint
                        .pending_authenticated_accept
                        .iter_mut()
                        .find(|pending| pending.local_cid == expected)
                        .unwrap()
                        .sent(packet.packet.data.len());
                }
                for local in [first, second] {
                    let pending = endpoint
                        .pending_authenticated_accept
                        .iter_mut()
                        .find(|pending| pending.local_cid == local)
                        .unwrap();
                    pending
                        .queue_flight(&[routed_packet(local, peer, 2).packet])
                        .unwrap();
                    pending.address_validated = local == second;
                }
                endpoint.queue_accept_output();
                let packet = endpoint.pending_outgoing.pop_front().unwrap();
                assert_eq!(
                    packet.connection_id, second,
                    "blocked peer must not hold the send turn"
                );
                endpoint
                    .pending_authenticated_accept
                    .iter_mut()
                    .find(|pending| pending.local_cid == second)
                    .unwrap()
                    .sent(packet.packet.data.len());
                endpoint
                    .pending_outgoing
                    .push_back(routed_packet(established, peer, 7));
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                endpoint
                    .pending_authenticated_accept
                    .iter_mut()
                    .find(|pending| pending.local_cid == silent)
                    .unwrap()
                    .expires = now;
                assert!(endpoint.advance_authenticated_accept(&cx, now));
                assert_eq!(endpoint.pending_authenticated_accept.len(), 2);
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                assert_eq!(endpoint.pending_outgoing[0].connection_id, established);
                assert!(
                    matches!(endpoint.take_authenticated_accept_result_with_id(),
                    Some((cid, Err(ManagedEndpointError::InvalidConfig(reason))))
                    if cid == silent && reason.contains("deadline expired"))
                );
                for pending in &mut endpoint.pending_authenticated_accept {
                    pending.next_pto = now
                        + Duration::from_millis(if pending.local_cid == first { 20 } else { 10 });
                }
                let earliest = now + Duration::from_millis(10);
                let expected = endpoint
                    .connection_router
                    .next_timer_deadline()
                    .map_or(earliest, |established| established.min(earliest));
                endpoint.refresh_timer(&cx).await.unwrap();
                assert_eq!(
                    endpoint.timer_scheduler.current_deadline(),
                    Some(expected),
                    "the nearest of every admission and established deadline drives wakeup"
                );
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(
                    endpoint.authenticated_accept_result.len(),
                    2,
                    "shutdown retains one terminal receipt for each remaining owner"
                );
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_failed_peer_does_not_discard_another_real_initial() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, established) =
                    selection_fixture(&Cx::current().unwrap()).await;
                enable_admission_mechanics(&mut endpoint);
                endpoint.config.packet_batch_size = 2;
                endpoint.set_authenticated_accept_limit(2).unwrap();
                let peer = peer.local_addr().unwrap();
                let first = ConnectionId::new(&[0xc1; 8]).unwrap();
                let second = ConnectionId::new(&[0xc2; 8]).unwrap();
                let first_initial = ConnectionId::new(&[0xd1; 8]).unwrap();
                let second_initial = ConnectionId::new(&[0xd2; 8]).unwrap();
                for (initial, local) in [(first_initial, first), (second_initial, second)] {
                    endpoint
                        .begin_authenticated_accept(
                            &cx,
                            server_driver(None),
                            peer,
                            initial,
                            local,
                            b"atp/1",
                        )
                        .unwrap();
                }
                endpoint
                    .pending_authenticated_accept
                    .front_mut()
                    .unwrap()
                    .received_packets = ACCEPT_MAX_PACKETS;
                endpoint
                    .pending_outgoing
                    .push_back(routed_packet(established, peer, 7));
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                endpoint
                    .process_packet_batch(
                        &cx,
                        vec![
                            initial_packet(peer, first_initial, now),
                            initial_packet(peer, second_initial, now),
                        ],
                    )
                    .await
                    .unwrap();
                assert_eq!(endpoint.pending_authenticated_accept.len(), 1);
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert_eq!(pending.local_cid, second);
                assert_eq!(pending.received_packets, 1);
                assert!(
                    !pending.last_flight.is_empty(),
                    "second peer generated real TLS output"
                );
                assert_eq!(endpoint.pending_outgoing[0].connection_id, established);
                assert!(
                    matches!(endpoint.take_authenticated_accept_result_with_id(),
                    Some((cid, Err(ManagedEndpointError::InvalidConfig(reason))))
                    if cid == first && reason.contains("packet bound exhausted"))
                );
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        /// RFC 9000 §12.2: a datagram that fails authentication is discarded.
        /// Anyone who saw the cleartext Initial can spoof the client's
        /// address, so a corrupted copy of that Initial or a long header
        /// with a bogus Length must neither end the admission nor consume
        /// its accepted-packet bound; the real Initial still authenticates
        /// afterwards.
        #[test]
        fn managed_accept_discards_unauthenticated_datagrams_without_aborting() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, _timer, mut endpoint, peer, _a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                let initial = ConnectionId::new(&[9; 8]).unwrap();
                enable_admission_mechanics(&mut endpoint);
                endpoint.config.packet_batch_size = 1024;
                endpoint
                    .begin_authenticated_accept(
                        &cx,
                        server_driver(None),
                        peer,
                        initial,
                        b,
                        b"atp/1",
                    )
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let incoming = initial_packet(peer, initial, now);

                // A bit-flipped copy of the real Initial fails AEAD under the
                // live Initial keys.
                let mut corrupted = incoming.clone();
                let last = corrupted.data.len() - 1;
                corrupted.data[last] ^= 0x55;
                // A version-1 Initial whose Length runs past the datagram.
                let mut overrun = vec![0xC0, 0, 0, 0, 1, 8];
                overrun.extend_from_slice(&[9; 8]);
                overrun.push(0);
                overrun.push(0);
                overrun.extend_from_slice(&[0xBF, 0xFF, 0xFF, 0xFF]);
                overrun.extend_from_slice(&[0u8; 16]);
                let overrun = ReceivedPacket {
                    src_addr: peer,
                    data: overrun,
                    receive_time: now,
                    transmit_time: None,
                };
                {
                    let pending = endpoint.pending_authenticated_accept.front_mut().unwrap();
                    pending
                        .receive(corrupted, 16_384, now)
                        .expect("a corrupted datagram is discarded, not fatal");
                    pending
                        .receive(overrun, 16_384, now)
                        .expect("a length-overrun datagram is discarded, not fatal");
                    assert_eq!(pending.received_packets, 0);
                    assert_eq!(pending.authenticated_received_bytes, 0);
                }

                let initial_bytes = incoming.data.len() as u64;
                endpoint
                    .process_packet_batch(&cx, vec![incoming])
                    .await
                    .unwrap();
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert_eq!(pending.authenticated_received_bytes, initial_bytes);
                assert_eq!(pending.received_packets, 1);
                endpoint.shutdown(&cx).await.unwrap();
            }));
        }

        /// br-asupersync-1r3f5u L3 and T6 (RFC 9000 §8.1): only an
        /// authenticated Handshake packet validates the client's address.
        /// The server cannot open a Handshake packet before the ClientHello,
        /// so one that leads a datagram is skipped. The real Initial coalesced
        /// after it authenticates, but proves nothing about the address. The
        /// client's Finished, coalesced after an Initial, does prove it.
        #[test]
        fn managed_accept_validates_the_address_only_on_an_authenticated_handshake_packet() {
            use super::super::super::handshake_driver::{
                client_config, server_config,
                tests::{CA_CERT_PEM, LEAF_CERT_PEM, leaf_key, parse_one_cert},
            };

            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, _timer, mut endpoint, peer, _a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let local = ConnectionId::new(&[0xc1; 8]).unwrap();
                let initial = ConnectionId::new(&[0xc2; 8]).unwrap();
                let client_cid = ConnectionId::new(&[0xc3; 8]).unwrap();
                enable_admission_mechanics(&mut endpoint);
                let server = QuicHandshakeDriver::server(
                    server_config(
                        vec![parse_one_cert(LEAF_CERT_PEM)],
                        leaf_key(),
                        vec![b"atp/1".to_vec()],
                    )
                    .unwrap(),
                    Vec::new(),
                )
                .unwrap();
                endpoint
                    .begin_authenticated_accept(&cx, server, peer, initial, local, b"atp/1")
                    .unwrap();
                let mut client = QuicHandshakeDriver::client(
                    client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![b"atp/1".to_vec()])
                        .unwrap(),
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    Vec::new(),
                )
                .unwrap();
                client.install_initial_keys(initial.as_bytes()).unwrap();
                let hello = client.pump_outbound().unwrap();
                assert_eq!(hello.len(), 1, "one ClientHello segment");
                let first_initial = client
                    .assemble_handshake_packet(&hello[0], initial, client_cid, 0)
                    .unwrap();
                // The same CRYPTO bytes again under a new packet number, to
                // lead the datagram that carries the Finished.
                let second_initial = client
                    .assemble_handshake_packet_at(&hello[0], 0, local, client_cid, 1)
                    .unwrap();
                let mut skipped = Vec::new();
                PacketHeader::Long(crate::net::quic_core::LongHeader {
                    packet_type: LongPacketType::Handshake,
                    version: 1,
                    dst_cid: local,
                    src_cid: client_cid,
                    token: Vec::new(),
                    payload_length: 4 + 32 + 16,
                    packet_number: 0,
                    packet_number_len: 4,
                })
                .encode(&mut skipped)
                .unwrap();
                skipped.extend_from_slice(&[0x5a; 48]);
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let datagram = |data: Vec<u8>| ReceivedPacket {
                    src_addr: peer,
                    data,
                    receive_time: now,
                    transmit_time: None,
                };

                let pending = endpoint.pending_authenticated_accept.front_mut().unwrap();
                pending
                    .receive(datagram([skipped, first_initial].concat()), 16_384, now)
                    .expect("the coalesced Initial authenticates");
                assert_eq!(pending.received_packets, 1, "the ClientHello was processed");
                assert!(!pending.last_flight.is_empty(), "the server answered it");
                assert!(
                    !pending.address_validated,
                    "a Handshake packet that was skipped validates nothing"
                );

                let mut finished = Vec::new();
                for packet in &pending.last_flight {
                    client.recv_handshake_packet(&packet.data).unwrap();
                    finished.extend(
                        client
                            .pump_outbound()
                            .unwrap()
                            .into_iter()
                            .filter(|segment| segment.level == HandshakeLevel::Handshake),
                    );
                }
                assert!(client.is_complete());
                assert_eq!(finished.len(), 1, "the client's Finished");
                let finished = client
                    .assemble_handshake_packet(&finished[0], local, client_cid, 0)
                    .unwrap();
                pending
                    .receive(datagram([second_initial, finished].concat()), 16_384, now)
                    .expect("the coalesced Finished authenticates");
                assert!(
                    pending.address_validated,
                    "an authenticated Handshake packet after an Initial validates the address"
                );
                endpoint.shutdown(&cx).await.unwrap();
            }));
        }

        #[test]
        fn managed_accept_actual_initial_credit_bounds_queued_prefix_and_pto_replay() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                let initial = ConnectionId::new(&[9; 8]).unwrap();
                enable_admission_mechanics(&mut endpoint);
                endpoint.config.packet_batch_size = 1024;
                endpoint.begin_authenticated_accept(
                    &cx, server_driver(None), peer, initial, b, b"atp/1"
                ).unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let incoming = initial_packet(peer, initial, now);
                let initial_bytes = incoming.data.len() as u64;
                endpoint.process_packet_batch(&cx, vec![incoming.clone()]).await.unwrap();
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert_eq!(pending.authenticated_received_bytes, initial_bytes);
                assert!(!pending.address_validated);
                assert!(!pending.last_flight.is_empty(), "actual TLS server output");
                let flight_bytes: u64 = pending.last_flight.iter().map(|packet| packet.data.len() as u64).sum();
                let input_count = (flight_bytes * 2).div_ceil(initial_bytes * 3).max(1);
                assert!(input_count <= 16, "bounded real input funds two complete flights");
                for _ in 1..input_count {
                    endpoint.process_packet_batch(&cx, vec![incoming.clone()]).await.unwrap();
                }
                let received_bytes = initial_bytes * input_count;
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert_eq!(pending.authenticated_received_bytes, received_bytes);
                assert_eq!(pending.received_packets as u64, input_count);
                assert_eq!(pending.flights, 1, "duplicates grant byte credit without new TLS output");
                // Repeated real serialized flights spend the same finite input
                // credit. No extra receive, invented validation, or re-credit.
                let mut charged = 0usize;
                let mut pto_replays = 0usize;
                for _ in 0..ACCEPT_MAX_FLIGHTS {
                    while endpoint.pending_authenticated_accept.front().unwrap()
                        .outbound.front().is_some_and(|packet| endpoint
                            .pending_authenticated_accept.front().unwrap().can_queue(packet.data.len()))
                    {
                        endpoint.queue_accept_output();
                    }
                    let pending = endpoint.pending_authenticated_accept.front().unwrap();
                    assert!(pending.sent_bytes + pending.socket_pending_bytes as u64 <= received_bytes * 3);
                    let queued = endpoint.pending_outgoing.len();
                    endpoint.queue_accept_output();
                    assert_eq!(endpoint.pending_outgoing.len(), queued,
                        "a second queue pass cannot spend queued credit again");
                    for packet in endpoint.pending_outgoing.drain(..) {
                        assert_eq!(packet.connection_id, b);
                        charged += packet.packet.data.len();
                        endpoint.pending_authenticated_accept.front_mut().unwrap().sent(packet.packet.data.len());
                    }
                    let pending = endpoint.pending_authenticated_accept.front().unwrap();
                    if !pending.outbound.is_empty() {
                        let retained = pending.outbound.len();
                        let due = pending.next_pto;
                        assert!(!endpoint.advance_authenticated_accept(&cx, due));
                        assert_eq!(endpoint.pending_authenticated_accept.front().unwrap().outbound.len(), retained,
                            "credit-blocked flight must not duplicate on PTO");
                        break;
                    }
                    let due = pending.next_pto;
                    let before_flights = pending.flights;
                    assert!(!endpoint.advance_authenticated_accept(&cx, due));
                    let pending = endpoint.pending_authenticated_accept.front().unwrap();
                    assert_eq!(pending.flights, before_flights + 1);
                    assert!(!pending.outbound.is_empty(), "actual PTO enqueues retained TLS flight");
                    pto_replays += 1;
                }
                let pending = endpoint.pending_authenticated_accept.front().unwrap();
                assert!(!pending.outbound.is_empty(), "actual bounded credit becomes decisive");
                assert!(charged > 0, "the credit guard must admit a real positive prefix");
                assert!(pto_replays > 0, "at least one actual PTO replay must precede blocking");
                assert!(charged as u64 <= received_bytes * 3);
                assert_eq!(pending.sent_bytes, charged as u64);
                assert_eq!(pending.socket_pending_bytes, 0);
                endpoint.pending_outgoing.push_back(routed_packet(a, peer, 7));
                endpoint.queue_accept_output();
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                assert_eq!(endpoint.pending_outgoing[0].connection_id, a,
                    "blocked B never occupies the shared socket queue ahead of A");
                let expires = endpoint.pending_authenticated_accept.front().unwrap().expires;
                assert!(endpoint.advance_authenticated_accept(&cx, expires));
                assert!(matches!(endpoint.take_authenticated_accept_result(),
                    Some(Err(ManagedEndpointError::InvalidConfig(reason))) if reason.contains("deadline expired")));
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn managed_accept_tls_callback_cancellation_stops_at_one_packet_and_keeps_other_cid() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                let initial = ConnectionId::new(&[9; 8]).unwrap();
                enable_admission_mechanics(&mut endpoint);
                endpoint.config.packet_batch_size = 3;
                endpoint
                    .begin_authenticated_accept(
                        &cx,
                        server_driver(Some(cx.clone())),
                        peer,
                        initial,
                        b,
                        b"atp/1",
                    )
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let incoming = initial_packet(peer, initial, now);
                let retained_a = short_packet(a, peer, now);
                endpoint
                    .pending_outgoing
                    .push_back(routed_packet(a, peer, 7));
                assert_eq!(
                    endpoint
                        .process_packet_batch(
                            &cx,
                            vec![incoming.clone(), incoming, retained_a.clone()]
                        )
                        .await,
                    Err(ManagedEndpointError::Cancelled)
                );
                assert_eq!(
                    cx.cancel_reason().unwrap().message.as_deref(),
                    Some("cancel inside actual TLS certificate resolution")
                );
                assert_eq!(
                    endpoint
                        .pending_authenticated_accept
                        .front()
                        .unwrap()
                        .received_packets,
                    1
                );
                assert_eq!(
                    endpoint.pending_incoming.len(),
                    2,
                    "cancel must leave the second B datagram and A suffix unconsumed"
                );
                assert_eq!(
                    endpoint.run_event_loop(&cx).await,
                    Err(ManagedEndpointError::Cancelled)
                );
                assert_eq!(
                    endpoint.take_authenticated_accept_result(),
                    Some(Err(ManagedEndpointError::Cancelled))
                );
                assert_eq!(endpoint.pending_incoming.len(), 1);
                assert_eq!(endpoint.pending_incoming[0].packet.data, retained_a.data);
                assert_eq!(endpoint.pending_outgoing.len(), 1);
                assert_eq!(endpoint.pending_outgoing[0].connection_id, a);
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                assert_eq!(
                    accept_completion_error(
                        super::super::super::NativeQuicUdpConnectionError::Cancelled
                    ),
                    ManagedEndpointError::Cancelled
                );
                assert_eq!(
                    accept_router_error(ConnectionRouterError::Cancelled),
                    ManagedEndpointError::Cancelled
                );
                assert_eq!(
                    endpoint.shutdown(&cx).await,
                    Err(ManagedEndpointError::Cancelled)
                );
                assert!(endpoint.pending_outgoing.is_empty());
                assert!(endpoint.pending_incoming.is_empty());
                assert_eq!(timer.pending_count(), 0);
            }));
        }

        #[test]
        fn lifecycle_reaping_preserves_same_address_peer_queues_and_timer() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, _, mut endpoint, peer, a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                endpoint
                    .create_connection_for_testing(&cx, b, peer)
                    .await
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let survivor_deadline = endpoint.connection_router.next_timer_deadline();
                for cid in [a, b, a, b] {
                    endpoint.pending_outgoing.push_back(routed_packet(
                        cid,
                        peer,
                        cid.as_bytes()[0],
                    ));
                    endpoint.pending_incoming.push_back(ManagedIncomingPacket {
                        packet: short_packet(cid, peer, now),
                        needs_clock_stamp: false,
                    });
                }
                endpoint
                    .connection_router
                    .connection_mut_for_testing(&cx, b)
                    .unwrap()
                    .close_immediately(&cx, 0x19)
                    .unwrap();
                endpoint.process_timer_events(&cx, now).await.unwrap();
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                assert_eq!(
                    endpoint.connection_router.next_timer_deadline(),
                    survivor_deadline
                );
                assert_eq!(endpoint.pending_outgoing.len(), 2);
                assert!(
                    endpoint
                        .pending_outgoing
                        .iter()
                        .all(|packet| packet.connection_id == a)
                );
                assert_eq!(endpoint.pending_incoming.len(), 2);
                assert!(endpoint.pending_incoming.iter().all(|packet| {
                    endpoint
                        .connection_router
                        .retained_packet_connection_id(&packet.packet)
                        == Some(a)
                }));
                endpoint.shutdown(&cx).await.unwrap();
            }));
        }

        #[test]
        fn managed_remove_connection_preserves_same_address_peer_queues_and_timer() {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(runtime.handle().spawn(async {
                let (cx, _, timer, mut endpoint, peer, a) =
                    selection_fixture(&Cx::current().unwrap()).await;
                let peer = peer.local_addr().unwrap();
                let b = ConnectionId::new(&[8; 8]).unwrap();
                endpoint
                    .create_connection_for_testing(&cx, b, peer)
                    .await
                    .unwrap();
                let now = endpoint.timer_scheduler.now(&cx).unwrap();
                let deadline = endpoint.connection_router.next_timer_deadline();
                for cid in [a, b, a, b] {
                    endpoint.pending_outgoing.push_back(routed_packet(
                        cid,
                        peer,
                        cid.as_bytes()[0],
                    ));
                    endpoint.pending_incoming.push_back(ManagedIncomingPacket {
                        packet: short_packet(cid, peer, now),
                        needs_clock_stamp: false,
                    });
                }
                endpoint.remove_connection(&cx, b).unwrap();
                assert_eq!(endpoint.connection_stats().active_connections, 1);
                assert_eq!(endpoint.connection_router.next_timer_deadline(), deadline);
                assert_eq!(endpoint.pending_outgoing.len(), 2);
                assert!(
                    endpoint.pending_outgoing.iter().all(
                        |packet| packet.connection_id == a && packet.packet.data == vec![7; 32]
                    )
                );
                assert_eq!(endpoint.pending_incoming.len(), 2);
                assert!(endpoint.pending_incoming.iter().all(|packet| {
                    endpoint
                        .connection_router
                        .retained_packet_connection_id(&packet.packet)
                        == Some(a)
                }));
                assert_eq!(
                    endpoint.remove_connection(&cx, b),
                    Err(ManagedEndpointError::ConnectionRouter(
                        ConnectionRouterError::ConnectionNotFound(b)
                    ))
                );
                endpoint.remove_connection(&cx, a).unwrap();
                assert_eq!(endpoint.connection_stats().active_connections, 0);
                assert!(endpoint.pending_outgoing.is_empty());
                assert!(endpoint.pending_incoming.is_empty());
                endpoint.shutdown(&cx).await.unwrap();
                assert_eq!(timer.pending_count(), 0);
            }));
        }
    }
