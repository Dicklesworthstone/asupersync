    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use parking_lot::Mutex;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn lamport_raw(time: &LogicalTime) -> u64 {
        match time {
            LogicalTime::Lamport(time) => time.raw(),
            other => panic!("expected Lamport logical time, got {other:?}"),
        }
    }

    fn test_request_fingerprint(name: &str) -> IdempotencyRequestFingerprint {
        IdempotencyRequestFingerprint::new(ComputationName::new(name), RemoteInput::empty())
    }

    fn deadline_wire_fixture(
        version: RemoteProtocolVersion,
        budget: Option<Budget>,
    ) -> (RemotePeerHello, SpawnRequest) {
        let origin = NodeId::new("wire-peer");
        let hello = RemotePeerHello::new(
            origin.clone(),
            version,
            ComputationRegistryFingerprint::from_bytes([7; 32]),
        );
        let request = SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(7),
            computation: ComputationName::new("proof.echo"),
            input: RemoteInput::new(vec![1, 2, 3]),
            lease: Duration::new(5, 6),
            idempotency_key: IdempotencyKey::from_raw((1_u128 << 64) | 2),
            budget,
            origin_node: origin,
            origin_region: RegionId::new_for_test(13, 14),
            origin_task: TaskId::new_for_test(15, 16),
        };
        (hello, request)
    }

    #[test]
    fn timed_wire_constructor_preserves_v1_v2_v3_exact_bytes() {
        // br-asupersync-remote-service-audit-pjrlqa: choosing the new clock-aware
        // constructor must not reinterpret a shipped protocol's absolute time.
        const TAIL: &str = concat!(
            ",\"registry_fingerprint\":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,",
            "7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7]},",
            "\"remote_task_id\":7,\"computation\":\"proof.echo\",\"input\":[1,2,3],",
            "\"lease_secs\":5,\"lease_subsec_nanos\":6,",
            "\"idempotency_key_high\":1,\"idempotency_key_low\":2,",
            "\"budget\":{\"deadline_nanos\":9,\"poll_quota\":10,\"cost_quota\":11,\"priority\":12},",
            "\"origin_region\":{\"kind\":\"RegionId\",\"index\":13,\"generation\":14},",
            "\"origin_task\":{\"kind\":\"TaskId\",\"index\":15,\"generation\":16}}"
        );
        for version in [
            RemoteProtocolVersion::V1,
            RemoteProtocolVersion::V2,
            RemoteProtocolVersion::V3,
        ] {
            let budget = Budget {
                deadline: Some(Time::from_nanos(9)),
                poll_quota: 10,
                cost_quota: Some(11),
                priority: 12,
            };
            let (hello, request) = deadline_wire_fixture(version, Some(budget));
            let wire = RemoteServiceWireRequest::from_spawn_request_at(
                hello.clone(),
                &request,
                Time::from_secs(1_000),
            )
            .expect("legacy construction retains its original encoding");
            let legacy = RemoteServiceWireRequest::from_spawn_request(hello, &request).unwrap();
            let golden = format!(
                "{{\"hello\":{{\"peer_node\":\"wire-peer\",\"protocol_version\":{{\"major\":{},\"minor\":0}}{TAIL}",
                version.major(),
            );
            assert_eq!(serde_json::to_string(&wire).unwrap(), golden);
            assert_eq!(wire, legacy);
            let decoded: RemoteServiceWireRequest = serde_json::from_str(&golden).unwrap();
            assert_eq!(decoded, wire);
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn relative_wire_deadline_rebases_across_independent_process_clocks() {
        // The server's epoch can precede or follow the origin's by any amount.
        // Every example still grants exactly five seconds on the server clock.
        for (origin_now, origin_deadline, receiver_now, expected_deadline) in [
            (5, 10, 1_000, 1_005),
            (1_000, 1_005, 5, 10),
            (0, 5, 0, 5),
        ] {
            let budget = Budget {
                deadline: Some(Time::from_secs(origin_deadline)),
                poll_quota: 10,
                cost_quota: Some(11),
                priority: 12,
            };
            let (hello, request) = deadline_wire_fixture(RemoteProtocolVersion::V4, Some(budget));
            let wire = RemoteServiceWireRequest::from_spawn_request_at(
                hello,
                &request,
                Time::from_secs(origin_now),
            )
            .unwrap();
            assert_eq!(wire.budget.unwrap().deadline_nanos, Some(5_000_000_000));
            // Exercise the wire round trip: local-only metadata cannot carry
            // the clock correction to the receiving process.
            let encoded = serde_json::to_vec(&wire).unwrap();
            let decoded: RemoteServiceWireRequest = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded, wire);
            let admitted = decoded
                .into_spawn_request_at(Time::from_secs(receiver_now))
                .unwrap();
            let translated = admitted.budget.unwrap();
            assert_eq!(translated.deadline, Some(Time::from_secs(expected_deadline)));
            assert_eq!(translated.poll_quota, budget.poll_quota);
            assert_eq!(translated.cost_quota, budget.cost_quota);
            assert_eq!(translated.priority, budget.priority);
            assert_eq!(admitted.input, request.input);
            assert_eq!(admitted.origin_node, request.origin_node);
            assert_eq!(admitted.origin_region, request.origin_region);
            assert_eq!(admitted.origin_task, request.origin_task);
            assert_eq!(admitted.idempotency_key, request.idempotency_key);
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn relative_wire_deadline_keeps_expiry_distinct_from_no_deadline() {
        let receiver_now = Time::from_secs(1_000);
        for deadline in [Time::ZERO, Time::from_secs(4), Time::from_secs(5)] {
            let budget = Budget::INFINITE.with_deadline(deadline);
            let (hello, request) = deadline_wire_fixture(RemoteProtocolVersion::V4, Some(budget));
            let wire = RemoteServiceWireRequest::from_spawn_request_at(
                hello,
                &request,
                Time::from_secs(5),
            )
            .unwrap();
            assert_eq!(wire.budget.unwrap().deadline_nanos, Some(0));
            assert_eq!(
                wire.into_spawn_request_at(receiver_now)
                    .unwrap()
                    .budget
                    .unwrap()
                    .deadline,
                Some(receiver_now),
                "an expired remote budget must not become infinite",
            );
        }
        for budget in [None, Some(Budget::INFINITE.with_poll_quota(17))] {
            let (hello, request) = deadline_wire_fixture(RemoteProtocolVersion::V4, budget);
            let timed = RemoteServiceWireRequest::from_spawn_request_at(
                hello.clone(),
                &request,
                Time::MAX,
            )
            .unwrap();
            let untimed = RemoteServiceWireRequest::from_spawn_request(hello, &request).unwrap();
            assert_eq!(
                timed, untimed,
                "an infinite deadline needs no clock conversion"
            );
            assert_eq!(
                timed.into_spawn_request_at(receiver_now).unwrap().budget,
                budget
            );
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn relative_wire_deadline_saturates_without_wrapping_or_relaxing_parent() {
        let (hello, request) = deadline_wire_fixture(
            RemoteProtocolVersion::V4,
            Some(Budget::INFINITE.with_deadline(Time::MAX)),
        );
        let wire =
            RemoteServiceWireRequest::from_spawn_request_at(hello, &request, Time::ZERO).unwrap();
        assert_eq!(wire.budget.unwrap().deadline_nanos, Some(u64::MAX));
        let requested = wire
            .into_spawn_request_at(Time::from_nanos(u64::MAX - 1))
            .unwrap()
            .budget
            .unwrap();
        assert_eq!(requested.deadline, Some(Time::MAX), "addition must saturate");
        let parent = Budget::INFINITE
            .with_deadline(Time::from_secs(2))
            .with_poll_quota(3);
        let effective = requested.combine(parent);
        assert_eq!(effective.deadline, parent.deadline);
        assert_eq!(effective.poll_quota, 3);
    }

    #[test]
    fn finite_relative_wire_deadline_requires_an_explicit_origin_clock() {
        let (hello, request) = deadline_wire_fixture(
            RemoteProtocolVersion::V4,
            Some(Budget::INFINITE.with_deadline(Time::from_secs(10))),
        );
        assert!(RemoteServiceWireRequest::from_spawn_request(hello.clone(), &request).is_err());
        let timed = RemoteServiceWireRequest::from_spawn_request_at(
            hello,
            &request,
            Time::from_secs(5),
        )
        .expect("the additive constructor supplies the missing clock");
        assert_eq!(timed.budget.unwrap().deadline_nanos, Some(5_000_000_000));
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn relative_origin_deadline_ignores_ambient_cancellation_and_expires_before_dispatch() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(5)));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(13, 14),
            TaskId::new_for_test(15, 16),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let (hello, request) = deadline_wire_fixture(
            RemoteProtocolVersion::V4,
            Some(Budget::INFINITE.with_deadline(Time::from_secs(10))),
        );
        let wire =
            RemoteServiceWireRequest::from_spawn_request_at(hello, &request, cx.now()).unwrap();
        let origin = RemoteRequestOrigin::new(&cx, &request);
        assert!(!origin.is_cancelled());

        // Polling under a different, already-cancelled context must not turn
        // that context's User cancellation into an origin Deadline result.
        let ambient = Cx::for_testing();
        ambient.cancel_with(CancelKind::User, Some("unrelated poller cancelled"));
        let _current = Cx::set_current(Some(ambient));
        let mut cancellation = Box::pin(origin.cancellation());
        let mut task_cx = Context::from_waker(Waker::noop());
        assert!(cancellation.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(timer.pending_count(), 1);

        clock.advance_to(Time::from_secs(10));
        assert_eq!(timer.process_timers(), 1);
        let Poll::Ready(reason) = cancellation.as_mut().poll(&mut task_cx) else {
            panic!("the actual origin deadline must wake cancellation");
        };
        assert_eq!(reason.kind(), CancelKind::Deadline);
        assert!(origin.is_cancelled());
        assert_eq!(
            origin.cancellation_reason().unwrap().kind(),
            CancelKind::Deadline
        );
        assert_eq!(
            origin.request_at_dispatch(&wire).budget.unwrap().deadline_nanos,
            Some(0),
            "a delayed publication cannot refresh the expired budget"
        );
        assert_eq!(timer.pending_count(), 0);
        assert!(!cx.is_cancel_requested(), "the remote budget is independent");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn peer_exchange_credits_bound_each_configured_identity_and_release_once() {
        let mut policy = RemotePeerAdmissionPolicy::new(
            RemoteProtocolVersion::V3,
            ComputationSchemaRegistry::new(),
        );
        let a = NodeId::new("peer-a");
        let b = NodeId::new("peer-b");
        for peer in [&a, &b] {
            policy.grant_peer(peer.clone(), std::iter::empty::<&str>()).unwrap();
        }
        for limit in [0, 1, 3] {
            let admission = RemoteServicePeerAdmission::new(&policy, limit);
            let mut held = Vec::new();
            for expected in 1..=limit {
                held.push(admission.try_acquire(&a).expect("capacity available"));
                assert_eq!(admission.active(&a), Some(expected));
            }
            assert!(admission.try_acquire(&a).is_none(), "capacity is exact");
            let other_peer = admission.try_acquire(&b);
            assert_eq!(other_peer.is_some(), limit != 0);
            assert_eq!(admission.active(&b), Some(usize::from(limit != 0)));
            for index in 0..32 {
                let unknown = NodeId::new(format!("not-granted-{index}"));
                assert!(admission.try_acquire(&unknown).is_none());
                assert_eq!(admission.active(&unknown), None);
            }
            assert_eq!(admission.active.len(), 2, "requests cannot grow the identity map");

            let retained_cleanup = held.last().map(Arc::clone);
            drop(held);
            assert_eq!(admission.active(&a), Some(usize::from(limit != 0)));
            drop(retained_cleanup);
            drop(other_peer);
            assert_eq!(admission.active(&a), Some(0));
            assert_eq!(admission.active(&b), Some(0));
            assert_eq!(admission.active.len(), 2);
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn peer_exchange_credit_unwind_releases_only_after_the_last_owner() {
        let peer = NodeId::new("peer");
        let mut policy = RemotePeerAdmissionPolicy::new(
            RemoteProtocolVersion::V3,
            ComputationSchemaRegistry::new(),
        );
        policy.grant_peer(peer.clone(), std::iter::empty::<&str>()).unwrap();
        let admission = RemoteServicePeerAdmission::new(&policy, 1);
        let transport = admission.try_acquire(&peer).unwrap();
        let region = Arc::clone(&transport);
        let unwound = std::panic::catch_unwind(move || {
            let _transport = transport;
            panic!("exchange interrupted during publication");
        });
        assert!(unwound.is_err());
        assert_eq!(admission.active(&peer), Some(1));
        assert!(admission.try_acquire(&peer).is_none());
        drop(region);
        assert_eq!(admission.active(&peer), Some(0));
        let next = admission.try_acquire(&peer).expect("cleanup returned the credit");
        drop(next);
        assert_eq!(admission.active(&peer), Some(0));
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn accept_resource_exhaustion_retries_out_of_memory() {
        assert!(remote_service_transient_accept_error(&io::Error::from(
            io::ErrorKind::OutOfMemory
        )));
    }

    #[cfg(all(feature = "remote-service", unix))]
    #[test]
    fn remote_computation_service_file_config_decodes_max_connections_per_ip() {
        let toml_str = r#"
schema_version = 2
protocol = "3.0"
listen = "127.0.0.1:9099"
listen_scope = "loopback_only"
server_certificate_chain = "server.crt"
server_private_key = "server.key"
client_ca_bundle = "ca.crt"
max_frame_bytes = 1048576
max_connections = 128
max_connections_per_ip = 16
tls_handshake_timeout_ms = 5000
initial_frame_timeout_ms = 5000
drain_timeout_ms = 10000
idempotency_retention_ms = 60000
max_idempotency_records_per_peer = 1024
peers = []
"#;
        let config: RemoteComputationServiceFileConfig =
            toml::from_str(toml_str).expect("decode toml with max_connections_per_ip");
        assert_eq!(config.max_connections_per_ip, Some(16));

        let toml_str_default = r#"
schema_version = 2
protocol = "3.0"
listen = "127.0.0.1:9099"
listen_scope = "loopback_only"
server_certificate_chain = "server.crt"
server_private_key = "server.key"
client_ca_bundle = "ca.crt"
max_frame_bytes = 1048576
max_connections = 128
tls_handshake_timeout_ms = 5000
initial_frame_timeout_ms = 5000
drain_timeout_ms = 10000
idempotency_retention_ms = 60000
max_idempotency_records_per_peer = 1024
peers = []
"#;
        let config_default: RemoteComputationServiceFileConfig =
            toml::from_str(toml_str_default).expect("decode toml without max_connections_per_ip");
        assert_eq!(config_default.max_connections_per_ip, None);
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32"), any(unix, windows)))]
    #[test]
    fn accept_resource_exhaustion_retries_native_errors() {
        #[cfg(unix)]
        let codes = [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM];
        #[cfg(windows)]
        let codes = {
            use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
            [WSAEMFILE, WSAENOBUFS]
        };

        for code in codes {
            let error = io::Error::from_raw_os_error(code);
            assert!(
                remote_service_transient_accept_error(&error),
                "resource exhaustion must keep the remote listener alive: {error:?}"
            );
        }
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32"), any(unix, windows)))]
    #[test]
    fn accept_resource_exhaustion_preserves_native_fatal_errors() {
        #[cfg(unix)]
        let codes = [libc::EBADF, libc::ENOTSOCK, libc::EINVAL, libc::EACCES];
        #[cfg(windows)]
        let codes = {
            use windows_sys::Win32::Networking::WinSock::{WSAEACCES, WSAEINVAL, WSAENOTSOCK};
            [WSAENOTSOCK, WSAEINVAL, WSAEACCES]
        };

        for code in codes {
            let error = io::Error::from_raw_os_error(code);
            assert!(
                !remote_service_transient_accept_error(&error),
                "permanent accept errors must still terminate the listener: {error:?}"
            );
        }
        for kind in [io::ErrorKind::TimedOut, io::ErrorKind::ConnectionRefused] {
            assert!(
                !remote_service_transient_accept_error(&io::Error::from(kind)),
                "preserve the remote listener's existing policy for {kind:?}"
            );
        }
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn accept_resource_exhaustion_backoff_uses_timer_and_allows_termination() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        #[derive(Clone, Copy)]
        enum Finish {
            Deadline,
            ForceClose,
            Cancel,
        }

        for (streak, delay_ms, finish) in [
            (1, 2, Finish::Deadline),
            (16, 2, Finish::Deadline),
            (17, 4, Finish::Deadline),
            (u32::MAX, 64, Finish::Deadline),
            (u32::MAX, 64, Finish::ForceClose),
            (u32::MAX, 64, Finish::Cancel),
        ] {
            let clock = Arc::new(VirtualClock::new());
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let cx = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(0, 1),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            );
            let _current = Cx::set_current(Some(cx.clone()));
            let shutdown = ShutdownSignal::new();
            let mut backoff = Box::pin(remote_service_accept_backoff(&cx, &shutdown, streak));
            let mut task_cx = Context::from_waker(Waker::noop());
            let deadline = Time::from_nanos(delay_ms * 1_000_000);

            assert!(backoff.as_mut().poll(&mut task_cx).is_pending());
            assert_eq!(timer.pending_count(), 1);
            assert_eq!(timer.next_deadline(), Some(deadline));
            for _ in 0..4 {
                assert!(backoff.as_mut().poll(&mut task_cx).is_pending());
            }
            assert_eq!(timer.pending_count(), 1, "re-polling must retain one timer");

            let expected = match finish {
                Finish::Deadline => {
                    clock.advance_to(Time::from_nanos(deadline.as_nanos() - 1));
                    assert!(backoff.as_mut().poll(&mut task_cx).is_pending());
                    clock.advance_to(deadline);
                    assert_eq!(timer.process_timers(), 1);
                    true
                }
                Finish::ForceClose => {
                    assert!(shutdown.begin_drain(Duration::ZERO));
                    assert!(shutdown.begin_force_close());
                    false
                }
                Finish::Cancel => {
                    cx.cancel_with(CancelKind::User, Some("accept backoff test"));
                    false
                }
            };
            assert_eq!(backoff.as_mut().poll(&mut task_cx), Poll::Ready(expected));
            assert_eq!(
                timer.pending_count(),
                0,
                "completed waits retire their timer"
            );
            drop(backoff);
            assert_eq!(timer.pending_count(), 0);
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn remote_service_protocol_classifier_is_explicit_and_fail_closed() {
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::V1),
            RemoteServiceProtocolKind::V1OneShot
        );
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::V2),
            RemoteServiceProtocolKind::V2Idempotent
        );
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::V3),
            RemoteServiceProtocolKind::V3Session
        );
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::V4),
            RemoteServiceProtocolKind::V3Session
        );
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::new(2, 1)),
            RemoteServiceProtocolKind::Unsupported
        );
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::new(4, 1)),
            RemoteServiceProtocolKind::Unsupported
        );
        assert_eq!(
            remote_service_protocol_kind(RemoteProtocolVersion::new(5, 0)),
            RemoteServiceProtocolKind::Unsupported
        );
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn remote_service_v3_renewal_sequence_never_wraps() {
        assert_eq!(remote_service_v3_next_renewal_id(None), Some(1));
        assert_eq!(remote_service_v3_next_renewal_id(Some(1)), Some(2));
        assert_eq!(
            remote_service_v3_next_renewal_id(Some(u64::MAX - 1)),
            Some(u64::MAX)
        );
        assert_eq!(remote_service_v3_next_renewal_id(Some(u64::MAX)), None);
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn remote_service_lease_expiry_wins_at_exact_boundary() {
        let expires_at = Time::from_nanos(50);
        assert!(!remote_service_lease_expired(
            Time::from_nanos(49),
            expires_at
        ));
        assert!(remote_service_lease_expired(expires_at, expires_at));
        assert!(remote_service_lease_expired(
            Time::from_nanos(51),
            expires_at
        ));
    }

    #[test]
    fn node_id_basics() {
        let node = NodeId::new("worker-1");
        assert_eq!(node.as_str(), "worker-1");
        assert_eq!(format!("{node}"), "Node(worker-1)");

        let node2 = NodeId::new("worker-1");
        assert_eq!(node, node2);

        let node3 = NodeId::new("worker-2");
        assert_ne!(node, node3);
    }

    #[test]
    fn computation_name_basics() {
        let name = ComputationName::new("encode_block");
        assert_eq!(name.as_str(), "encode_block");
        assert_eq!(format!("{name}"), "encode_block");

        let name2 = ComputationName::new("encode_block");
        assert_eq!(name, name2);
    }

    #[test]
    fn remote_input_basics() {
        let input = RemoteInput::new(vec![1, 2, 3]);
        assert_eq!(input.data(), &[1, 2, 3]);
        assert_eq!(input.len(), 3);
        assert!(!input.is_empty());

        let empty = RemoteInput::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let owned = input.into_data();
        assert_eq!(owned, vec![1, 2, 3]);
    }

    #[test]
    fn remote_cap_defaults() {
        let cap = RemoteCap::new();
        assert_eq!(cap.default_lease(), Duration::from_secs(30));
        assert!(cap.remote_budget().is_none());
        assert_eq!(cap.local_node().as_str(), "local");
        assert_eq!(cap.phase0_simulation(), &Phase0SimulationConfig::default());
    }

    #[test]
    fn remote_cap_builder() {
        let cap = RemoteCap::new()
            .with_default_lease(Duration::from_secs(60))
            .with_remote_budget(Budget::INFINITE)
            .with_local_node(NodeId::new("origin-a"))
            .with_phase0_failure(Phase0RemoteFailure::NodeDown)
            .with_phase0_timeout(Duration::from_secs(2));
        assert_eq!(cap.default_lease(), Duration::from_secs(60));
        assert!(cap.remote_budget().is_some());
        assert_eq!(cap.local_node().as_str(), "origin-a");
        assert_eq!(
            cap.phase0_simulation().failure,
            Phase0RemoteFailure::NodeDown
        );
        assert_eq!(cap.phase0_simulation().timeout, Duration::from_secs(2));
    }

    #[derive(Debug, Default)]
    struct CaptureRuntime {
        sent: Mutex<Vec<(NodeId, MessageEnvelope<RemoteMessage>)>>,
    }

    impl RemoteRuntime for CaptureRuntime {
        fn send_message(
            &self,
            destination: &NodeId,
            envelope: MessageEnvelope<RemoteMessage>,
        ) -> Result<(), RemoteError> {
            self.sent.lock().push((destination.clone(), envelope));
            Ok(())
        }

        fn register_task(
            &self,
            _task_id: RemoteTaskId,
            _tx: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
        ) {
            // Intentionally dropped in this capture runtime.
        }

        fn clear_task_state(&self, _task_id: RemoteTaskId) {
            // No state to clear in capture runtime.
        }

        fn unregister_task(&self, _task_id: RemoteTaskId) {
            // No registration state to clean up in capture runtime.
        }
    }

    #[derive(Debug, Default)]
    struct FailingSendRuntime {
        registered: Mutex<Vec<RemoteTaskId>>,
        unregistered: Mutex<Vec<RemoteTaskId>>,
    }

    impl RemoteRuntime for FailingSendRuntime {
        fn send_message(
            &self,
            _destination: &NodeId,
            _envelope: MessageEnvelope<RemoteMessage>,
        ) -> Result<(), RemoteError> {
            Err(RemoteError::TransportError("simulated send failure".into()))
        }

        fn register_task(
            &self,
            task_id: RemoteTaskId,
            _tx: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
        ) {
            self.registered.lock().push(task_id);
        }

        fn clear_task_state(&self, _task_id: RemoteTaskId) {
            // No persistent state to clear in failing send runtime.
        }

        fn unregister_task(&self, task_id: RemoteTaskId) {
            self.unregistered.lock().push(task_id);
        }
    }

    #[derive(Debug, Default)]
    struct LifecycleRuntime {
        sent: Mutex<Vec<(NodeId, MessageEnvelope<RemoteMessage>)>>,
        pending: Mutex<BTreeMap<RemoteTaskId, oneshot::Sender<Result<RemoteOutcome, RemoteError>>>>,
        states: Mutex<BTreeMap<RemoteTaskId, RemoteTaskState>>,
    }

    impl LifecycleRuntime {
        fn mark_state(&self, task_id: RemoteTaskId, state: RemoteTaskState) {
            self.states.lock().insert(task_id, state);
        }

        fn close_sender_preserving_state(&self, task_id: RemoteTaskId) {
            self.pending.lock().remove(&task_id);
        }

        fn deliver(
            &self,
            _cx: &Cx,
            task_id: RemoteTaskId,
            result: Result<RemoteOutcome, RemoteError>,
        ) {
            let state = match &result {
                Ok(RemoteOutcome::Success(_)) => RemoteTaskState::Completed,
                Ok(RemoteOutcome::Cancelled(_)) | Err(RemoteError::Cancelled(_)) => {
                    RemoteTaskState::Cancelled
                }
                Err(RemoteError::LeaseExpired) => RemoteTaskState::LeaseExpired,
                Ok(RemoteOutcome::Failed(_) | RemoteOutcome::Panicked(_)) | Err(_) => {
                    RemoteTaskState::Failed
                }
            };
            self.states.lock().insert(task_id, state);
            let tx = self
                .pending
                .lock()
                .remove(&task_id)
                .expect("pending remote task");
            if tx.send_blocking(result).is_err() {
                self.states.lock().remove(&task_id);
            }
        }

        fn sent_messages(&self) -> Vec<(NodeId, MessageEnvelope<RemoteMessage>)> {
            self.sent.lock().clone()
        }

        fn pending_count(&self) -> usize {
            self.pending.lock().len()
        }

        fn state_count(&self) -> usize {
            self.states.lock().len()
        }
    }

    fn last_remote_message(runtime: &LifecycleRuntime) -> RemoteMessage {
        runtime
            .sent_messages()
            .last()
            .expect("expected a sent remote message")
            .1
            .payload
            .clone()
    }

    fn last_spawn_request(runtime: &LifecycleRuntime) -> SpawnRequest {
        match last_remote_message(runtime) {
            RemoteMessage::SpawnRequest(request) => request,
            other => panic!("expected SpawnRequest, got {other:?}"),
        }
    }

    fn last_cancel_request(runtime: &LifecycleRuntime) -> CancelRequest {
        match last_remote_message(runtime) {
            RemoteMessage::CancelRequest(request) => request,
            other => panic!("expected CancelRequest, got {other:?}"),
        }
    }

    fn assert_runtime_drained(runtime: &LifecycleRuntime) {
        assert_eq!(runtime.pending_count(), 0, "pending remote result senders");
        assert_eq!(runtime.state_count(), 0, "tracked remote lifecycle states");
    }

    fn trace_messages(trace: &crate::trace::TraceBufferHandle) -> Vec<String> {
        trace
            .snapshot()
            .into_iter()
            .filter_map(|event| match event.data {
                crate::trace::TraceData::Message(message) => Some(message),
                _ => None,
            })
            .collect()
    }

    impl RemoteRuntime for LifecycleRuntime {
        fn send_message(
            &self,
            destination: &NodeId,
            envelope: MessageEnvelope<RemoteMessage>,
        ) -> Result<(), RemoteError> {
            self.sent.lock().push((destination.clone(), envelope));
            Ok(())
        }

        fn register_task(
            &self,
            task_id: RemoteTaskId,
            tx: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
        ) {
            self.pending.lock().insert(task_id, tx);
            self.states.lock().insert(task_id, RemoteTaskState::Pending);
        }

        fn observe_task_state(&self, task_id: RemoteTaskId) -> Option<RemoteTaskState> {
            self.states.lock().get(&task_id).copied()
        }

        fn clear_task_state(&self, task_id: RemoteTaskId) {
            self.pending.lock().remove(&task_id);
            self.states.lock().remove(&task_id);
        }

        fn unregister_task(&self, task_id: RemoteTaskId) {
            self.pending.lock().remove(&task_id);
            self.states.lock().remove(&task_id);
        }
    }

    fn fast_phase0_cap() -> RemoteCap {
        RemoteCap::new().with_phase0_failure(Phase0RemoteFailure::NodeUnreachable)
    }

    fn timeout_phase0_cap() -> RemoteCap {
        RemoteCap::new().with_phase0_failure(Phase0RemoteFailure::Timeout)
    }

    #[test]
    fn spawn_remote_uses_cap_local_node_for_origin() {
        let runtime = Arc::new(CaptureRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let (destination, envelope) = {
            let sent = runtime.sent.lock();
            assert_eq!(sent.len(), 1);
            sent[0].clone()
        };
        assert_eq!(destination.as_str(), "worker-1");
        assert_eq!(envelope.sender.as_str(), "origin-a");
        assert!(lamport_raw(&envelope.sender_time) > 0);
        match &envelope.payload {
            RemoteMessage::SpawnRequest(req) => {
                assert_eq!(req.remote_task_id, handle.remote_task_id());
                assert_eq!(req.origin_node.as_str(), "origin-a");
            }
            other => unreachable!("expected SpawnRequest, got {other:?}"),
        }
    }

    #[test]
    fn remote_handle_abort_with_attached_runtime_sends_cancel_request() {
        let runtime = Arc::new(CaptureRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        handle.abort(&cx);

        let (destination, envelope, spawn_time) = {
            let sent = runtime.sent.lock();
            assert_eq!(sent.len(), 2);
            (
                sent[1].0.clone(),
                sent[1].1.clone(),
                lamport_raw(&sent[0].1.sender_time),
            )
        };
        assert_eq!(destination.as_str(), "worker-1");
        assert_eq!(envelope.sender.as_str(), "origin-a");
        assert!(lamport_raw(&envelope.sender_time) > spawn_time);
        match &envelope.payload {
            RemoteMessage::CancelRequest(req) => {
                assert_eq!(req.remote_task_id, handle.remote_task_id());
                assert_eq!(req.origin_node.as_str(), "origin-a");
                assert_eq!(req.reason, CancelReason::user("remote handle abort"));
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
    }

    #[test]
    fn remote_handle_abort_uses_handle_origin_even_with_different_caller_cap() {
        let runtime = Arc::new(CaptureRuntime::default());
        let spawn_cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let spawn_cx: Cx = Cx::for_testing_with_remote(spawn_cap);

        let handle = spawn_remote(
            &spawn_cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let abort_cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-b"))
            .with_runtime(runtime.clone());
        let abort_cx: Cx = Cx::for_testing_with_remote(abort_cap);
        let expected_reason = CancelReason::deadline();
        abort_cx.set_cancel_reason(expected_reason.clone());

        handle.abort(&abort_cx);

        let (destination, envelope, spawn_time) = {
            let sent = runtime.sent.lock();
            assert_eq!(sent.len(), 2);
            (
                sent[1].0.clone(),
                sent[1].1.clone(),
                lamport_raw(&sent[0].1.sender_time),
            )
        };
        assert_eq!(destination.as_str(), "worker-1");
        assert_eq!(envelope.sender.as_str(), "origin-a");
        assert!(lamport_raw(&envelope.sender_time) > spawn_time);
        match &envelope.payload {
            RemoteMessage::CancelRequest(req) => {
                assert_eq!(req.remote_task_id, handle.remote_task_id());
                assert_eq!(req.origin_node.as_str(), "origin-a");
                assert_eq!(req.reason, expected_reason);
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
    }

    #[test]
    fn spawn_remote_send_failure_unregisters_pending_task() {
        let runtime = Arc::new(FailingSendRuntime::default());
        let cap = RemoteCap::new().with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let err = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect_err("spawn_remote should fail when send_message fails");
        match err {
            RemoteError::TransportError(msg) => {
                assert!(msg.contains("simulated send failure"));
            }
            other => unreachable!("expected TransportError, got {other:?}"),
        }

        let registered = runtime.registered.lock().clone();
        let unregistered = runtime.unregistered.lock().clone();

        assert_eq!(registered.len(), 1);
        assert_eq!(unregistered, registered);
    }

    #[test]
    fn remote_task_id_uniqueness() {
        let id1 = RemoteTaskId::next();
        let id2 = RemoteTaskId::next();
        assert_ne!(id1, id2);
        assert!(id2.raw() > id1.raw());
    }

    #[test]
    fn remote_task_state_display() {
        assert_eq!(format!("{}", RemoteTaskState::Pending), "Pending");
        assert_eq!(format!("{}", RemoteTaskState::Running), "Running");
        assert_eq!(format!("{}", RemoteTaskState::Completed), "Completed");
        assert_eq!(format!("{}", RemoteTaskState::LeaseExpired), "LeaseExpired");
    }

    #[test]
    fn remote_error_display() {
        let err = RemoteError::NoCapability;
        assert_eq!(format!("{err}"), "remote capability not available");

        let err = RemoteError::NodeUnreachable("worker-9".into());
        assert!(format!("{err}").contains("worker-9"));

        let err = RemoteError::NodeDown("worker-9".into());
        assert!(format!("{err}").contains("worker-9"));

        let err = RemoteError::UnknownComputation("bad_fn".into());
        assert!(format!("{err}").contains("bad_fn"));
    }

    #[test]
    fn spawn_remote_without_cap_fails() {
        let cx: Cx = Cx::for_testing();
        assert!(!cx.has_remote());

        let result = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode"),
            RemoteInput::empty(),
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), RemoteError::NoCapability);
    }

    #[test]
    fn spawn_remote_with_cap_succeeds() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        assert!(cx.has_remote());

        let result = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![42]),
        );
        assert!(result.is_ok());

        let handle = result.unwrap();
        assert_eq!(handle.node().as_str(), "worker-1");
        assert_eq!(handle.computation().as_str(), "encode_block");
        assert_eq!(handle.state(), RemoteTaskState::Failed);
        assert!(handle.is_finished());
        assert_eq!(handle.lease(), Duration::from_secs(30));
        assert!(handle.local_task_id().is_none());
    }

    #[test]
    fn remote_handle_debug() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        let handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("compute"),
            RemoteInput::empty(),
        )
        .unwrap();

        let debug = format!("{handle:?}");
        assert!(debug.contains("RemoteHandle"));
        assert!(debug.contains("n1"));
        assert!(debug.contains("compute"));
    }

    #[test]
    fn remote_handle_phase0_fallback_finishes_immediately() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        let handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("add"),
            RemoteInput::empty(),
        )
        .unwrap();

        assert!(handle.is_finished());
        assert_eq!(handle.state(), RemoteTaskState::Failed);
    }

    #[test]
    fn remote_handle_try_join_phase0_fallback_returns_configured_error() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("work"),
            RemoteInput::empty(),
        )
        .unwrap();

        let err = handle
            .try_join()
            .expect_err("phase-0 fallback should fail explicitly");
        assert!(matches!(err, RemoteError::NodeUnreachable(_)));
        assert_eq!(handle.state(), RemoteTaskState::Failed);
    }

    #[test]
    fn phase0_fallback_publication_is_independent_of_caller_cancellation() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        cx.cancel_with(
            crate::types::CancelKind::User,
            Some("cancel before remote fallback"),
        );

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("cancelled-caller-fallback"),
            RemoteInput::empty(),
        )
        .expect("terminal fallback publication must not be cancelled by its caller Cx");

        let err = handle
            .try_join()
            .expect_err("the configured phase-0 failure must remain observable");
        assert!(matches!(err, RemoteError::NodeUnreachable(_)));
        assert_eq!(handle.state(), RemoteTaskState::Failed);
    }

    #[test]
    fn remote_handle_join_updates_terminal_state() {
        let cap = RemoteCap::new().with_phase0_simulation(Phase0SimulationConfig {
            failure: Phase0RemoteFailure::NodeDown,
            retry: Phase0RetryPolicy {
                max_attempts: 2,
                initial_backoff: Duration::from_millis(2),
                max_backoff: Duration::from_millis(2),
            },
            timeout: Duration::from_millis(20),
        });
        let cx: Cx = Cx::for_testing_with_remote(cap);
        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("join-state"),
            RemoteInput::empty(),
        )
        .expect("spawn");

        assert_eq!(handle.state(), RemoteTaskState::Failed);
        let result = futures_lite::future::block_on(handle.join(&cx));
        assert!(matches!(result, Outcome::Err(RemoteError::NodeDown(_))));
        assert_eq!(handle.state(), RemoteTaskState::Failed);
        assert!(handle.is_finished());
    }

    #[test]
    fn remote_handle_try_join_updates_terminal_state() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("try-join-state"),
            RemoteInput::empty(),
        )
        .expect("spawn");

        let err = handle
            .try_join()
            .expect_err("phase-0 fallback should fail explicitly");
        assert!(matches!(err, RemoteError::NodeUnreachable(_)));
        assert_eq!(handle.state(), RemoteTaskState::Failed);
    }

    #[test]
    fn remote_handle_phase0_timeout_maps_to_cancelled_state() {
        let cx: Cx = Cx::for_testing_with_remote(timeout_phase0_cap());
        let mut handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("timeout-state"),
            RemoteInput::empty(),
        )
        .expect("spawn");

        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
        let result = futures_lite::future::block_on(handle.join(&cx));
        assert!(matches!(
            result,
            Outcome::Err(RemoteError::Cancelled(reason))
                if reason.kind == crate::types::CancelKind::Timeout
        ));
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
    }

    #[test]
    fn remote_handle_state_observes_runtime_lifecycle() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        assert_eq!(handle.state(), RemoteTaskState::Pending);

        runtime.mark_state(handle.remote_task_id(), RemoteTaskState::Running);
        assert_eq!(handle.state(), RemoteTaskState::Running);

        runtime.deliver(
            &cx,
            handle.remote_task_id(),
            Ok(RemoteOutcome::Success(vec![9, 9, 9])),
        );
        assert_eq!(handle.state(), RemoteTaskState::Completed);

        let outcome = handle.try_join().expect("result").expect("outcome");
        assert!(matches!(outcome, RemoteOutcome::Success(_)));
        assert!(
            runtime
                .observe_task_state(handle.remote_task_id())
                .is_none()
        );
    }

    #[test]
    fn remote_handle_close_skips_cancel_when_runtime_result_is_already_buffered() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        runtime.mark_state(handle.remote_task_id(), RemoteTaskState::Running);
        runtime.deliver(
            &cx,
            handle.remote_task_id(),
            Ok(RemoteOutcome::Cancelled(CancelReason::user(
                "closed remotely",
            ))),
        );
        runtime.mark_state(handle.remote_task_id(), RemoteTaskState::Running);

        let outcome = futures_lite::future::block_on(handle.close(&cx)).expect("close");
        assert!(matches!(outcome, RemoteOutcome::Cancelled(_)));
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
        assert!(
            runtime
                .observe_task_state(handle.remote_task_id())
                .is_none()
        );

        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "ready terminal result should not trigger a late cancel"
        );
    }

    #[test]
    fn remote_handle_close_ignores_caller_cancellation_until_terminal_result_arrives() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);
        cx.set_cancel_reason(CancelReason::deadline());

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let outcome = {
            let mut close = std::pin::pin!(handle.close(&cx));

            assert!(matches!(
                std::future::Future::poll(close.as_mut(), &mut task_cx),
                Poll::Pending
            ));
            assert_eq!(
                runtime.observe_task_state(remote_task_id),
                Some(RemoteTaskState::Running)
            );

            runtime.deliver(
                &cx,
                remote_task_id,
                Ok(RemoteOutcome::Cancelled(CancelReason::user(
                    "closed remotely",
                ))),
            );

            match std::future::Future::poll(close.as_mut(), &mut task_cx) {
                Poll::Ready(outcome) => outcome,
                Poll::Pending => panic!("close should drain terminal result"),
            }
        };
        assert!(matches!(
            outcome,
            Outcome::Ok(RemoteOutcome::Cancelled(reason))
                if reason == CancelReason::user("closed remotely")
        ));
        assert!(runtime.observe_task_state(remote_task_id).is_none());

        let sent = runtime.sent_messages();
        assert_eq!(sent.len(), 2);
        assert!(lamport_raw(&sent[1].1.sender_time) > lamport_raw(&sent[0].1.sender_time));
        match &sent[1].1.payload {
            RemoteMessage::CancelRequest(cancel) => {
                assert_eq!(cancel.remote_task_id, remote_task_id);
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
    }

    #[test]
    fn remote_handle_close_with_plain_context_still_requests_cancel_when_runtime_attached() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let spawn_cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let spawn_cx: Cx = Cx::for_testing_with_remote(spawn_cap);
        let close_cx: Cx = Cx::for_testing();
        let expected_reason = CancelReason::deadline();
        close_cx.set_cancel_reason(expected_reason.clone());

        let mut handle = spawn_remote(
            &spawn_cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let outcome = {
            let mut close = std::pin::pin!(handle.close(&close_cx));

            assert!(matches!(
                std::future::Future::poll(close.as_mut(), &mut task_cx),
                Poll::Pending
            ));

            let sent = runtime.sent_messages();
            assert_eq!(sent.len(), 2);
            match &sent[1].1.payload {
                RemoteMessage::CancelRequest(cancel) => {
                    assert_eq!(cancel.remote_task_id, remote_task_id);
                    assert_eq!(cancel.origin_node.as_str(), "origin-a");
                    assert_eq!(cancel.reason, expected_reason);
                }
                other => unreachable!("expected CancelRequest, got {other:?}"),
            }

            runtime.deliver(
                &spawn_cx,
                remote_task_id,
                Ok(RemoteOutcome::Cancelled(CancelReason::user(
                    "closed remotely",
                ))),
            );

            match std::future::Future::poll(close.as_mut(), &mut task_cx) {
                Poll::Ready(outcome) => outcome,
                Poll::Pending => panic!("close should drain terminal result"),
            }
        };

        assert!(matches!(
            outcome,
            Outcome::Ok(RemoteOutcome::Cancelled(reason))
                if reason == CancelReason::user("closed remotely")
        ));
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
        assert!(runtime.observe_task_state(remote_task_id).is_none());
    }

    #[test]
    fn remote_handle_join_closed_channel_preserves_runtime_lease_expired_state() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::LeaseExpired);
        runtime.close_sender_preserving_state(remote_task_id);

        let err = futures_lite::future::block_on(handle.join(&cx))
            .expect_err("closed channel should surface the observed lease-expired state");
        assert_eq!(err, RemoteError::LeaseExpired);
        assert_eq!(handle.state(), RemoteTaskState::LeaseExpired);
        assert!(runtime.observe_task_state(remote_task_id).is_none());
    }

    #[test]
    fn remote_handle_join_closed_channel_reports_transport_error_for_failed_state() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Failed);
        runtime.close_sender_preserving_state(remote_task_id);

        let err = futures_lite::future::block_on(handle.join(&cx))
            .expect_err("closed terminal failed channel should surface a transport error");
        assert!(matches!(
            err,
            RemoteError::TransportError(msg) if msg.contains("Failed")
        ));
        assert_eq!(handle.state(), RemoteTaskState::Failed);
        assert!(runtime.observe_task_state(remote_task_id).is_none());
    }

    #[test]
    fn remote_handle_try_join_closed_channel_reports_transport_error_for_completed_state() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Completed);
        runtime.close_sender_preserving_state(remote_task_id);

        let err = handle
            .try_join()
            .expect_err("closed terminal completed channel should surface a transport error");
        assert!(matches!(
            err,
            RemoteError::TransportError(msg) if msg.contains("Completed")
        ));
        assert_eq!(handle.state(), RemoteTaskState::Completed);
        assert!(runtime.observe_task_state(remote_task_id).is_none());
    }

    #[test]
    fn remote_handle_close_closed_channel_still_requests_cancel_for_live_runtime_task() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);
        runtime.close_sender_preserving_state(remote_task_id);

        let err = futures_lite::future::block_on(handle.close(&cx))
            .expect_err("closed live channel should still fail the close");
        assert_eq!(err, RemoteError::Cancelled(RemoteHandle::closed_reason()));
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
        assert!(runtime.observe_task_state(remote_task_id).is_none());

        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            2,
            "close should still send a best-effort cancel when the runtime still observes a live remote task"
        );
        match &sent[1].1.payload {
            RemoteMessage::CancelRequest(cancel) => {
                assert_eq!(cancel.remote_task_id, remote_task_id);
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
    }

    #[test]
    fn remote_handle_drop_cancels_live_runtime_task_but_preserves_runtime_state() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let remote_task_id = {
            let handle = spawn_remote(
                &cx,
                NodeId::new("worker-1"),
                ComputationName::new("encode_block"),
                RemoteInput::new(vec![1, 2, 3]),
            )
            .expect("spawn_remote should succeed");

            let remote_task_id = handle.remote_task_id();
            runtime.mark_state(remote_task_id, RemoteTaskState::Running);
            remote_task_id
        };

        assert_eq!(
            runtime.observe_task_state(remote_task_id),
            Some(RemoteTaskState::Running),
            "dropping a live handle must preserve runtime bookkeeping until the remote lifecycle finishes"
        );
        let sent = runtime.sent_messages();
        assert_eq!(sent.len(), 2, "spawn + best-effort drop cancel");
        assert!(lamport_raw(&sent[1].1.sender_time) > lamport_raw(&sent[0].1.sender_time));
        match &sent[1].1.payload {
            RemoteMessage::CancelRequest(cancel) => {
                assert_eq!(cancel.remote_task_id, remote_task_id);
                assert_eq!(cancel.reason, CancelReason::user("remote handle dropped"));
                assert_eq!(cancel.origin_node.as_str(), "origin-a");
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
    }

    #[test]
    fn remote_handle_drop_clears_runtime_state_after_terminal_result_is_observed() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let remote_task_id = {
            let handle = spawn_remote(
                &cx,
                NodeId::new("worker-1"),
                ComputationName::new("encode_block"),
                RemoteInput::new(vec![1, 2, 3]),
            )
            .expect("spawn_remote should succeed");

            let remote_task_id = handle.remote_task_id();
            runtime.deliver(
                &cx,
                remote_task_id,
                Ok(RemoteOutcome::Success(vec![7, 8, 9])),
            );
            remote_task_id
        };

        assert!(
            runtime.observe_task_state(remote_task_id).is_none(),
            "dropping a handle after the runtime observes a terminal result should clear bookkeeping"
        );
        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "terminal drop should not send an extra cancel"
        );
    }

    #[test]
    fn remote_handle_abort_skips_cancel_when_terminal_result_is_already_buffered() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.deliver(
            &cx,
            remote_task_id,
            Ok(RemoteOutcome::Success(vec![7, 8, 9])),
        );
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);

        handle.abort(&cx);

        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "buffered terminal result should suppress late cancel"
        );

        let outcome = handle.try_join().expect("result").expect("outcome");
        assert!(matches!(outcome, RemoteOutcome::Success(_)));
        assert_eq!(handle.state(), RemoteTaskState::Completed);
    }

    #[test]
    fn remote_handle_drop_skips_cancel_when_terminal_result_is_buffered_but_state_is_stale() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let remote_task_id = {
            let handle = spawn_remote(
                &cx,
                NodeId::new("worker-1"),
                ComputationName::new("encode_block"),
                RemoteInput::new(vec![1, 2, 3]),
            )
            .expect("spawn_remote should succeed");

            let remote_task_id = handle.remote_task_id();
            runtime.deliver(
                &cx,
                remote_task_id,
                Ok(RemoteOutcome::Success(vec![7, 8, 9])),
            );
            runtime.mark_state(remote_task_id, RemoteTaskState::Running);
            remote_task_id
        };

        assert!(
            runtime.observe_task_state(remote_task_id).is_none(),
            "dropping with a buffered terminal result should clear runtime bookkeeping even if observed state was stale"
        );
        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "stale running state must not trigger a late drop cancel"
        );
    }

    #[test]
    fn remote_handle_drop_preserves_terminal_runtime_state_until_sender_settles() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let remote_task_id = {
            let handle = spawn_remote(
                &cx,
                NodeId::new("worker-1"),
                ComputationName::new("encode_block"),
                RemoteInput::new(vec![1, 2, 3]),
            )
            .expect("spawn_remote should succeed");

            let remote_task_id = handle.remote_task_id();
            runtime.mark_state(remote_task_id, RemoteTaskState::Completed);
            remote_task_id
        };

        assert_eq!(
            runtime.observe_task_state(remote_task_id),
            Some(RemoteTaskState::Completed),
            "dropping after the runtime observes a terminal state must preserve bookkeeping until the terminal sender settles"
        );

        runtime.deliver(
            &cx,
            remote_task_id,
            Ok(RemoteOutcome::Success(vec![7, 8, 9])),
        );

        assert!(
            runtime.observe_task_state(remote_task_id).is_none(),
            "once the terminal sender settles into a dropped receiver, runtime bookkeeping should clear"
        );
        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "terminal drop should not emit a late cancel while waiting for sender cleanup"
        );
    }

    #[test]
    fn remote_handle_abort_closed_channel_still_requests_cancel_for_live_runtime_task() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);
        runtime.close_sender_preserving_state(remote_task_id);

        handle.abort(&cx);

        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            2,
            "explicit abort should still fence a live remote task even if the result sender already disappeared"
        );
        match &sent[1].1.payload {
            RemoteMessage::CancelRequest(cancel) => {
                assert_eq!(cancel.remote_task_id, remote_task_id);
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
        assert_eq!(
            runtime.observe_task_state(remote_task_id),
            Some(RemoteTaskState::Running)
        );
    }

    #[test]
    fn remote_handle_is_finished_stays_false_for_closed_channel_while_runtime_task_is_live() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        let remote_task_id = handle.remote_task_id();
        runtime.mark_state(remote_task_id, RemoteTaskState::Running);
        runtime.close_sender_preserving_state(remote_task_id);

        assert!(
            !handle.is_finished(),
            "closed result channel without a buffered terminal result must not look finished"
        );
        assert_eq!(handle.state(), RemoteTaskState::Running);

        let err = futures_lite::future::block_on(handle.close(&cx))
            .expect_err("closed live channel should still fail the close");
        assert_eq!(err, RemoteError::Cancelled(RemoteHandle::closed_reason()));
        assert!(
            handle.is_finished(),
            "close should transition the handle to a terminal state"
        );
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
        assert!(runtime.observe_task_state(remote_task_id).is_none());
    }

    #[test]
    fn remote_handle_drop_closed_channel_still_requests_cancel_for_live_runtime_task() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let remote_task_id = {
            let handle = spawn_remote(
                &cx,
                NodeId::new("worker-1"),
                ComputationName::new("encode_block"),
                RemoteInput::new(vec![1, 2, 3]),
            )
            .expect("spawn_remote should succeed");

            let remote_task_id = handle.remote_task_id();
            runtime.mark_state(remote_task_id, RemoteTaskState::Running);
            runtime.close_sender_preserving_state(remote_task_id);
            remote_task_id
        };

        let sent = runtime.sent_messages();
        assert_eq!(
            sent.len(),
            2,
            "dropping a live handle must still request cancel even if the result sender already disappeared"
        );
        match &sent[1].1.payload {
            RemoteMessage::CancelRequest(cancel) => {
                assert_eq!(cancel.remote_task_id, remote_task_id);
            }
            other => unreachable!("expected CancelRequest, got {other:?}"),
        }
        assert_eq!(
            runtime.observe_task_state(remote_task_id),
            Some(RemoteTaskState::Running)
        );
    }

    #[test]
    fn remote_handle_runtime_rejection_fails_closed() {
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let mut handle = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should succeed");

        runtime.deliver(
            &cx,
            handle.remote_task_id(),
            Err(RemoteError::SpawnRejected(
                SpawnRejectReason::CapacityExceeded,
            )),
        );

        assert_eq!(handle.state(), RemoteTaskState::Failed);
        let err = handle
            .try_join()
            .expect_err("runtime rejection should surface as terminal error");
        assert_eq!(
            err,
            RemoteError::SpawnRejected(SpawnRejectReason::CapacityExceeded)
        );
        assert!(
            runtime
                .observe_task_state(handle.remote_task_id())
                .is_none()
        );
    }

    #[test]
    fn remote_handle_try_join_maps_cancelled_outcome_state() {
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = oneshot::channel::<Result<RemoteOutcome, RemoteError>>();
        tx.send(
            &cx,
            Ok(RemoteOutcome::Cancelled(CancelReason::user(
                "cancelled remotely",
            ))),
        )
        .expect("send outcome");

        let mut handle = RemoteHandle {
            remote_task_id: RemoteTaskId::next(),
            local_task_id: None,
            origin_node: NodeId::new("origin"),
            node: NodeId::new("n1"),
            computation: ComputationName::new("compute"),
            owner_region: cx.region_id(),
            runtime: None,
            receiver: rx,
            sender_clock: cx.logical_clock_handle(),
            lease: Duration::from_secs(30),
            state: RemoteTaskState::Pending,
            completed: false,
        };

        let result = handle.try_join().expect("result").expect("outcome");
        assert!(matches!(result, RemoteOutcome::Cancelled(_)));
        assert_eq!(handle.state(), RemoteTaskState::Cancelled);
    }

    #[test]
    fn remote_handle_try_join_fails_closed_after_completion() {
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = oneshot::channel::<Result<RemoteOutcome, RemoteError>>();
        tx.send(&cx, Ok(RemoteOutcome::Success(Vec::new())))
            .expect("send outcome");

        let mut handle = RemoteHandle {
            remote_task_id: RemoteTaskId::next(),
            local_task_id: None,
            origin_node: NodeId::new("origin"),
            node: NodeId::new("n1"),
            computation: ComputationName::new("compute"),
            owner_region: cx.region_id(),
            runtime: None,
            receiver: rx,
            sender_clock: cx.logical_clock_handle(),
            lease: Duration::from_secs(30),
            state: RemoteTaskState::Pending,
            completed: false,
        };

        let first = handle.try_join().expect("result").expect("outcome");
        assert!(matches!(first, RemoteOutcome::Success(_)));
        assert_eq!(handle.state(), RemoteTaskState::Completed);

        let second = handle.try_join();
        assert!(matches!(second, Err(RemoteError::PolledAfterCompletion)));
    }

    #[test]
    fn remote_handle_join_fails_closed_after_completion() {
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = oneshot::channel::<Result<RemoteOutcome, RemoteError>>();
        tx.send(&cx, Ok(RemoteOutcome::Success(Vec::new())))
            .expect("send outcome");

        let mut handle = RemoteHandle {
            remote_task_id: RemoteTaskId::next(),
            local_task_id: None,
            origin_node: NodeId::new("origin"),
            node: NodeId::new("n1"),
            computation: ComputationName::new("compute"),
            owner_region: cx.region_id(),
            runtime: None,
            receiver: rx,
            sender_clock: cx.logical_clock_handle(),
            lease: Duration::from_secs(30),
            state: RemoteTaskState::Pending,
            completed: false,
        };

        let first = futures_lite::future::block_on(handle.join(&cx)).expect("first join");
        assert!(matches!(first, RemoteOutcome::Success(_)));
        assert_eq!(handle.state(), RemoteTaskState::Completed);

        let second = futures_lite::future::block_on(handle.join(&cx));
        assert!(matches!(
            second,
            Outcome::Err(RemoteError::PolledAfterCompletion)
        ));
    }

    #[test]
    fn remote_handle_join_uses_caller_cancel_reason_for_cancelled_wait() {
        let cx: Cx = Cx::for_testing();
        let (_tx, rx) = oneshot::channel::<Result<RemoteOutcome, RemoteError>>();
        let expected = CancelReason::deadline();
        cx.set_cancel_reason(expected.clone());

        let mut handle = RemoteHandle {
            remote_task_id: RemoteTaskId::next(),
            local_task_id: None,
            origin_node: NodeId::new("origin"),
            node: NodeId::new("n1"),
            computation: ComputationName::new("compute"),
            owner_region: cx.region_id(),
            runtime: None,
            receiver: rx,
            sender_clock: cx.logical_clock_handle(),
            lease: Duration::from_secs(30),
            state: RemoteTaskState::Running,
            completed: false,
        };

        let result = futures_lite::future::block_on(handle.join(&cx));
        assert!(matches!(
            result,
            Outcome::Err(RemoteError::Cancelled(reason)) if reason == expected
        ));
        assert_eq!(handle.state(), RemoteTaskState::Running);
        assert!(matches!(handle.try_join(), Ok(None)));
    }

    #[test]
    fn remote_handle_abort_without_attached_runtime_is_noop() {
        let cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        let handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("long_task"),
            RemoteInput::empty(),
        )
        .unwrap();

        handle.abort(&cx);
    }

    #[test]
    fn remote_cap_custom_lease_propagates() {
        let cap = fast_phase0_cap().with_default_lease(Duration::from_secs(120));
        let cx: Cx = Cx::for_testing_with_remote(cap);

        let handle = spawn_remote(
            &cx,
            NodeId::new("n1"),
            ComputationName::new("slow"),
            RemoteInput::empty(),
        )
        .unwrap();

        assert_eq!(handle.lease(), Duration::from_secs(120));
    }

    #[test]
    fn remote_virtual_lifecycle_proof_exercises_runtime_transport_and_protocol() {
        let trace = crate::trace::TraceBufferHandle::new(96);
        let runtime = Arc::new(LifecycleRuntime::default());
        let cap = RemoteCap::new()
            .with_local_node(NodeId::new("origin-a"))
            .with_runtime(runtime.clone());
        let cx: Cx = Cx::for_testing_with_remote(cap);
        cx.set_trace_buffer(trace.clone());

        let mut success = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("encode_block"),
            RemoteInput::new(vec![1, 2, 3]),
        )
        .expect("spawn_remote should enqueue a virtual transport request");
        let success_req = last_spawn_request(runtime.as_ref());
        let success_id = success.remote_task_id();
        let success_ack = test_ack_accepted(success_id);
        let origin = OriginSession::<OriginInit>::new(success_id)
            .send_spawn(&success_req)
            .expect("origin sends spawn");
        let remote = RemoteSession::<RemoteInit>::new(success_id)
            .recv_spawn(&success_req)
            .expect("remote receives spawn");
        let origin = match origin
            .recv_spawn_ack(&success_ack)
            .expect("origin receives accepted ack")
        {
            OriginAckOutcome::Accepted(session) => session,
            OriginAckOutcome::Rejected(_) => panic!("accepted ack must not reject"),
        };
        let remote = remote
            .send_ack_accepted(&success_ack)
            .expect("remote sends accepted ack");
        runtime.mark_state(success_id, RemoteTaskState::Running);

        let mut lease = Lease::new(
            test_obligation_id(),
            cx.region_id(),
            cx.task_id(),
            success_req.lease,
            Time::from_nanos(1_000_000_000),
        );
        assert!(lease.is_active(Time::from_nanos(1_000_000_000)));

        let renewal = LeaseRenewal {
            remote_task_id: success_id,
            new_lease: Duration::from_secs(15),
            current_state: RemoteTaskState::Running,
            node: NodeId::new("worker-1"),
        };
        let origin = origin
            .recv_lease_renewal(&renewal)
            .expect("origin accepts lease renewal");
        let remote = remote
            .send_lease_renewal(&renewal)
            .expect("remote sends lease renewal");
        lease
            .renew(renewal.new_lease, Time::from_secs(10))
            .expect("lease renewal extends liveness obligation");
        assert_eq!(lease.renewal_count(), 1);

        let success_result = ResultDelivery {
            remote_task_id: success_id,
            outcome: RemoteOutcome::Success(vec![9, 9, 9]),
            execution_time: Duration::from_millis(7),
        };
        let _remote_done = remote
            .send_result(&success_result)
            .expect("remote sends terminal result");
        let _origin_done = origin
            .recv_result(&success_result)
            .expect("origin receives terminal result");
        lease
            .release(Time::from_secs(11))
            .expect("terminal result releases lease");
        assert!(lease.is_released());
        runtime.deliver(&cx, success_id, Ok(success_result.outcome.clone()));

        let outcome = futures_lite::future::block_on(success.join(&cx))
            .expect("success result reaches origin handle");
        assert!(matches!(outcome, RemoteOutcome::Success(bytes) if bytes == vec![9, 9, 9]));
        assert_runtime_drained(runtime.as_ref());

        let mut cancelled_before_ack = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("pre_ack_cancel"),
            RemoteInput::new(vec![4]),
        )
        .expect("spawn before-ack cancel scenario");
        let cancel_before_req = last_spawn_request(runtime.as_ref());
        let cancel_before_id = cancelled_before_ack.remote_task_id();
        cancelled_before_ack.abort(&cx);
        let cancel_before = last_cancel_request(runtime.as_ref());
        let origin = OriginSession::<OriginInit>::new(cancel_before_id)
            .send_spawn(&cancel_before_req)
            .expect("origin sends spawn")
            .send_cancel(&cancel_before)
            .expect("origin sends cancel before ack");
        let remote = RemoteSession::<RemoteInit>::new(cancel_before_id)
            .recv_spawn(&cancel_before_req)
            .expect("remote receives spawn")
            .recv_cancel(&cancel_before)
            .expect("remote receives cancel before ack");
        let ack = test_ack_accepted(cancel_before_id);
        let origin = match origin
            .recv_spawn_ack(&ack)
            .expect("late ack after cancel is handled")
        {
            OriginCancelAckOutcome::Accepted(session) => session,
            OriginCancelAckOutcome::Rejected(_) => panic!("accepted late ack must not reject"),
        };
        let remote = remote
            .send_ack_accepted(&ack)
            .expect("remote accepts while cancel is pending");
        let result = ResultDelivery {
            remote_task_id: cancel_before_id,
            outcome: RemoteOutcome::Cancelled(CancelReason::user("cancelled before ack")),
            execution_time: Duration::from_millis(1),
        };
        let _remote_done = remote.send_result(&result).expect("remote drains cancel");
        let _origin_done = origin.recv_result(&result).expect("origin drains cancel");
        runtime.deliver(&cx, cancel_before_id, Ok(result.outcome.clone()));
        let outcome = futures_lite::future::block_on(cancelled_before_ack.join(&cx))
            .expect("cancelled result reaches origin handle");
        assert!(
            matches!(outcome, RemoteOutcome::Cancelled(reason) if reason == CancelReason::user("cancelled before ack"))
        );
        assert_runtime_drained(runtime.as_ref());

        let mut cancelled_running = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("running_cancel"),
            RemoteInput::new(vec![5]),
        )
        .expect("spawn running-cancel scenario");
        let running_req = last_spawn_request(runtime.as_ref());
        let running_id = cancelled_running.remote_task_id();
        let ack = test_ack_accepted(running_id);
        let origin = OriginSession::<OriginInit>::new(running_id)
            .send_spawn(&running_req)
            .expect("origin sends spawn");
        let remote = RemoteSession::<RemoteInit>::new(running_id)
            .recv_spawn(&running_req)
            .expect("remote receives spawn");
        let origin = match origin.recv_spawn_ack(&ack).expect("accepted ack") {
            OriginAckOutcome::Accepted(session) => session,
            OriginAckOutcome::Rejected(_) => panic!("accepted ack must not reject"),
        };
        let remote = remote.send_ack_accepted(&ack).expect("remote accepts");
        runtime.mark_state(running_id, RemoteTaskState::Running);
        let renewal = LeaseRenewal {
            remote_task_id: running_id,
            new_lease: Duration::from_secs(10),
            current_state: RemoteTaskState::Running,
            node: NodeId::new("worker-1"),
        };
        let origin = origin
            .recv_lease_renewal(&renewal)
            .expect("origin accepts running renewal");
        let remote = remote
            .send_lease_renewal(&renewal)
            .expect("remote sends running renewal");
        cancelled_running.abort(&cx);
        let cancel = last_cancel_request(runtime.as_ref());
        let origin = origin.send_cancel(&cancel).expect("origin sends cancel");
        let remote = remote.recv_cancel(&cancel).expect("remote receives cancel");
        let origin = origin
            .recv_lease_renewal(&renewal)
            .expect("origin accepts renewal while draining cancel");
        let remote = remote
            .send_lease_renewal(&renewal)
            .expect("remote renews while draining cancel");
        let result = ResultDelivery {
            remote_task_id: running_id,
            outcome: RemoteOutcome::Cancelled(CancelReason::user("cancelled while running")),
            execution_time: Duration::from_millis(3),
        };
        let _remote_done = remote
            .send_result(&result)
            .expect("remote sends cancel result");
        let _origin_done = origin
            .recv_result(&result)
            .expect("origin receives cancel result");
        runtime.deliver(&cx, running_id, Ok(result.outcome.clone()));
        let outcome = futures_lite::future::block_on(cancelled_running.join(&cx))
            .expect("running cancel reaches origin handle");
        assert!(
            matches!(outcome, RemoteOutcome::Cancelled(reason) if reason == CancelReason::user("cancelled while running"))
        );
        assert_runtime_drained(runtime.as_ref());

        let mut expired = spawn_remote(
            &cx,
            NodeId::new("worker-1"),
            ComputationName::new("lease_expiry"),
            RemoteInput::new(vec![6]),
        )
        .expect("spawn lease-expiry scenario");
        let expired_req = last_spawn_request(runtime.as_ref());
        let expired_id = expired.remote_task_id();
        let ack = test_ack_accepted(expired_id);
        let origin = OriginSession::<OriginInit>::new(expired_id)
            .send_spawn(&expired_req)
            .expect("origin sends spawn");
        let origin = match origin.recv_spawn_ack(&ack).expect("accepted ack") {
            OriginAckOutcome::Accepted(session) => session,
            OriginAckOutcome::Rejected(_) => panic!("accepted ack must not reject"),
        };
        let expired_cancel = CancelRequest {
            remote_task_id: expired_id,
            reason: CancelReason::deadline(),
            origin_node: NodeId::new("origin-a"),
        };
        let origin = origin
            .lease_expired()
            .send_cancel(&expired_cancel)
            .expect("lease expiry can request remote cleanup");
        let late_result = ResultDelivery {
            remote_task_id: expired_id,
            outcome: RemoteOutcome::Success(vec![1]),
            execution_time: Duration::from_millis(9),
        };
        let _origin_done = origin
            .recv_result(&late_result)
            .expect("late terminal result remains correlated");
        runtime.mark_state(expired_id, RemoteTaskState::LeaseExpired);
        runtime.close_sender_preserving_state(expired_id);
        let err = futures_lite::future::block_on(expired.join(&cx))
            .expect_err("closed lease-expired runtime state surfaces lease error");
        assert_eq!(err, RemoteError::LeaseExpired);
        assert_runtime_drained(runtime.as_ref());

        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let success_fingerprint = IdempotencyRequestFingerprint::from_spawn_request(&success_req);
        assert!(matches!(
            store.check(
                &success_req.idempotency_key,
                &success_fingerprint,
                Time::from_nanos(1_000_000_000)
            ),
            DedupDecision::New
        ));
        assert!(store.record(
            success_req.idempotency_key,
            success_id,
            success_fingerprint.clone(),
            Time::from_nanos(1_000_000_000),
        ));
        assert!(store.complete(
            &success_req.idempotency_key,
            success_id,
            RemoteOutcome::Success(vec![9, 9, 9]),
            Time::from_secs(1),
        ));
        match store.check(
            &success_req.idempotency_key,
            &success_fingerprint,
            Time::from_secs(1),
        ) {
            DedupDecision::Duplicate(record) => {
                assert_eq!(record.remote_task_id, success_id);
                assert!(
                    matches!(record.outcome, Some(RemoteOutcome::Success(bytes)) if bytes == vec![9, 9, 9])
                );
            }
            other => panic!("expected duplicate decision, got {other:?}"),
        }
        let conflict_fingerprint = IdempotencyRequestFingerprint::new(
            success_req.computation.clone(),
            RemoteInput::new(vec![0xff]),
        );
        assert!(matches!(
            store.check(
                &success_req.idempotency_key,
                &conflict_fingerprint,
                Time::from_secs(1),
            ),
            DedupDecision::Conflict
        ));

        let failing = Arc::new(FailingSendRuntime::default());
        let failing_cx: Cx =
            Cx::for_testing_with_remote(RemoteCap::new().with_runtime(failing.clone()));
        let err = spawn_remote(
            &failing_cx,
            NodeId::new("worker-1"),
            ComputationName::new("transport_failure"),
            RemoteInput::empty(),
        )
        .expect_err("send failure should fail spawn");
        assert!(
            matches!(err, RemoteError::TransportError(message) if message.contains("simulated send failure"))
        );
        let registered = failing.registered.lock().clone();
        assert_eq!(registered.len(), 1);
        assert_eq!(failing.unregistered.lock().clone(), registered);

        let fallback_cx: Cx = Cx::for_testing_with_remote(fast_phase0_cap());
        let mut fallback = spawn_remote(
            &fallback_cx,
            NodeId::new("missing-worker"),
            ComputationName::new("fallback"),
            RemoteInput::empty(),
        )
        .expect("phase-0 fallback creates a terminal handle");
        let err = fallback
            .try_join()
            .expect_err("phase-0 fallback surfaces configured error");
        assert!(matches!(err, RemoteError::NodeUnreachable(node) if node == "missing-worker"));

        let messages = trace_messages(&trace);
        for expected in [
            trace_events::SPAWN_REQUEST_CREATED,
            trace_events::SPAWN_REQUEST_SENT,
            trace_events::CANCEL_SENT,
            trace_events::RESULT_DELIVERED,
            trace_events::LEASE_EXPIRED,
        ] {
            assert!(
                messages.iter().any(|message| message == expected),
                "missing trace event {expected}; messages={messages:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Remote protocol contract tests
    // -----------------------------------------------------------------------

    #[test]
    fn idempotency_key_generate() {
        let cx: Cx = Cx::for_testing();
        let k1 = IdempotencyKey::generate(&cx);
        let k2 = IdempotencyKey::generate(&cx);
        // Keys should be unique (with overwhelming probability)
        assert_ne!(k1, k2);
        assert_ne!(k1.raw(), 0);
    }

    #[test]
    fn idempotency_key_from_raw() {
        let key = IdempotencyKey::from_raw(0xDEAD_BEEF);
        assert_eq!(key.raw(), 0xDEAD_BEEF);
        let display = format!("{key}");
        assert!(display.starts_with("IK-"));
        assert!(display.contains("deadbeef"));
    }

    #[test]
    fn spawn_request_construction() {
        let cx: Cx = Cx::for_testing();
        let req = SpawnRequest {
            remote_task_id: RemoteTaskId::next(),
            computation: ComputationName::new("encode_block"),
            input: RemoteInput::new(vec![1, 2, 3]),
            lease: Duration::from_secs(60),
            idempotency_key: IdempotencyKey::generate(&cx),
            budget: None,
            origin_node: NodeId::new("origin-1"),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        };

        assert_eq!(req.computation.as_str(), "encode_block");
        assert_eq!(req.input.len(), 3);
        assert_eq!(req.lease, Duration::from_secs(60));
        assert_eq!(req.origin_node.as_str(), "origin-1");
    }

    #[test]
    fn spawn_ack_accepted() {
        let ack = SpawnAck {
            remote_task_id: RemoteTaskId::next(),
            status: SpawnAckStatus::Accepted,
            assigned_node: NodeId::new("worker-3"),
        };
        assert_eq!(ack.status, SpawnAckStatus::Accepted);
        assert_eq!(ack.assigned_node.as_str(), "worker-3");
    }

    #[test]
    fn spawn_ack_rejected() {
        let ack = SpawnAck {
            remote_task_id: RemoteTaskId::next(),
            status: SpawnAckStatus::Rejected(SpawnRejectReason::CapacityExceeded),
            assigned_node: NodeId::new("worker-1"),
        };
        assert_eq!(
            ack.status,
            SpawnAckStatus::Rejected(SpawnRejectReason::CapacityExceeded)
        );
    }

    #[test]
    fn spawn_reject_reason_display() {
        assert_eq!(
            format!("{}", SpawnRejectReason::UnknownComputation),
            "unknown computation"
        );
        assert_eq!(
            format!("{}", SpawnRejectReason::CapacityExceeded),
            "capacity exceeded"
        );
        assert_eq!(
            format!("{}", SpawnRejectReason::NodeShuttingDown),
            "node shutting down"
        );
        assert!(
            format!("{}", SpawnRejectReason::InvalidInput("bad data".into())).contains("bad data")
        );
        assert_eq!(
            format!("{}", SpawnRejectReason::IdempotencyConflict),
            "idempotency conflict"
        );
    }

    #[test]
    fn cancel_request_construction() {
        let req = CancelRequest {
            remote_task_id: RemoteTaskId::next(),
            reason: CancelReason::user("user abort"),
            origin_node: NodeId::new("origin-1"),
        };
        assert_eq!(req.origin_node.as_str(), "origin-1");
    }

    #[test]
    fn result_delivery_success() {
        let delivery = ResultDelivery {
            remote_task_id: RemoteTaskId::next(),
            outcome: RemoteOutcome::Success(vec![42]),
            execution_time: Duration::from_millis(150),
        };
        assert!(delivery.outcome.is_success());
        assert_eq!(delivery.outcome.severity(), crate::types::Severity::Ok);
        assert_eq!(delivery.execution_time, Duration::from_millis(150));
    }

    #[test]
    fn result_delivery_failure() {
        let delivery = ResultDelivery {
            remote_task_id: RemoteTaskId::next(),
            outcome: RemoteOutcome::Failed("out of memory".into()),
            execution_time: Duration::from_secs(5),
        };
        assert!(!delivery.outcome.is_success());
        assert_eq!(delivery.outcome.severity(), crate::types::Severity::Err);
    }

    #[test]
    fn remote_outcome_display() {
        assert_eq!(format!("{}", RemoteOutcome::Success(vec![])), "Success");
        assert!(format!("{}", RemoteOutcome::Failed("oops".into())).contains("oops"));
        assert!(
            format!("{}", RemoteOutcome::Cancelled(CancelReason::user("done")))
                .contains("Cancelled")
        );
        assert!(format!("{}", RemoteOutcome::Panicked("boom".into())).contains("boom"));
    }

    #[test]
    fn lease_renewal_construction() {
        let renewal = LeaseRenewal {
            remote_task_id: RemoteTaskId::next(),
            new_lease: Duration::from_secs(30),
            current_state: RemoteTaskState::Running,
            node: NodeId::new("worker-1"),
        };
        assert_eq!(renewal.new_lease, Duration::from_secs(30));
        assert_eq!(renewal.current_state, RemoteTaskState::Running);
    }

    #[test]
    fn remote_message_task_id_dispatch() {
        let rtid = RemoteTaskId::next();
        let cx: Cx = Cx::for_testing();

        let spawn_msg = RemoteMessage::SpawnRequest(SpawnRequest {
            remote_task_id: rtid,
            computation: ComputationName::new("test"),
            input: RemoteInput::empty(),
            lease: Duration::from_secs(30),
            idempotency_key: IdempotencyKey::generate(&cx),
            budget: None,
            origin_node: NodeId::new("n1"),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        });
        assert_eq!(spawn_msg.remote_task_id(), rtid);

        let ack_msg = RemoteMessage::SpawnAck(SpawnAck {
            remote_task_id: rtid,
            status: SpawnAckStatus::Accepted,
            assigned_node: NodeId::new("n2"),
        });
        assert_eq!(ack_msg.remote_task_id(), rtid);

        let cancel_msg = RemoteMessage::CancelRequest(CancelRequest {
            remote_task_id: rtid,
            reason: CancelReason::user("test"),
            origin_node: NodeId::new("n1"),
        });
        assert_eq!(cancel_msg.remote_task_id(), rtid);

        let result_msg = RemoteMessage::ResultDelivery(ResultDelivery {
            remote_task_id: rtid,
            outcome: RemoteOutcome::Success(vec![]),
            execution_time: Duration::ZERO,
        });
        assert_eq!(result_msg.remote_task_id(), rtid);

        let renewal_msg = RemoteMessage::LeaseRenewal(LeaseRenewal {
            remote_task_id: rtid,
            new_lease: Duration::from_secs(30),
            current_state: RemoteTaskState::Running,
            node: NodeId::new("n2"),
        });
        assert_eq!(renewal_msg.remote_task_id(), rtid);
    }

    fn test_spawn_request(cx: &Cx, remote_task_id: RemoteTaskId) -> SpawnRequest {
        SpawnRequest {
            remote_task_id,
            computation: ComputationName::new("compute"),
            input: RemoteInput::empty(),
            lease: Duration::from_secs(30),
            idempotency_key: IdempotencyKey::generate(cx),
            budget: None,
            origin_node: NodeId::new("origin-1"),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        }
    }

    fn test_ack_accepted(remote_task_id: RemoteTaskId) -> SpawnAck {
        SpawnAck {
            remote_task_id,
            status: SpawnAckStatus::Accepted,
            assigned_node: NodeId::new("worker-1"),
        }
    }

    fn test_ack_rejected(remote_task_id: RemoteTaskId) -> SpawnAck {
        SpawnAck {
            remote_task_id,
            status: SpawnAckStatus::Rejected(SpawnRejectReason::CapacityExceeded),
            assigned_node: NodeId::new("worker-1"),
        }
    }

    fn test_cancel(remote_task_id: RemoteTaskId) -> CancelRequest {
        CancelRequest {
            remote_task_id,
            reason: CancelReason::user("cancel"),
            origin_node: NodeId::new("origin-1"),
        }
    }

    fn test_result(remote_task_id: RemoteTaskId, outcome: RemoteOutcome) -> ResultDelivery {
        ResultDelivery {
            remote_task_id,
            outcome,
            execution_time: Duration::ZERO,
        }
    }

    fn test_renewal(remote_task_id: RemoteTaskId) -> LeaseRenewal {
        LeaseRenewal {
            remote_task_id,
            new_lease: Duration::from_secs(10),
            current_state: RemoteTaskState::Running,
            node: NodeId::new("worker-1"),
        }
    }

    #[test]
    fn origin_session_cancel_flow() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let origin = OriginSession::<OriginInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let origin = origin.send_spawn(&req).unwrap();
        let ack = test_ack_accepted(rtid);
        let outcome = origin.recv_spawn_ack(&ack).unwrap();
        assert!(matches!(outcome, OriginAckOutcome::Accepted(_)));
        let origin = match outcome {
            OriginAckOutcome::Accepted(session) => session,
            OriginAckOutcome::Rejected(_) => return,
        };
        let origin = origin.recv_lease_renewal(&test_renewal(rtid)).unwrap();
        let origin = origin.send_cancel(&test_cancel(rtid)).unwrap();
        let result = test_result(
            rtid,
            RemoteOutcome::Cancelled(CancelReason::user("cancelled")),
        );
        let origin = origin.recv_result(&result).unwrap();
        assert_eq!(origin.remote_task_id(), rtid);
    }

    #[test]
    fn origin_session_cancel_before_ack_then_late_accept_flow() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let origin = OriginSession::<OriginInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let origin = origin.send_spawn(&req).unwrap();
        let origin = origin.send_cancel(&test_cancel(rtid)).unwrap();
        let ack = test_ack_accepted(rtid);
        let outcome = origin.recv_spawn_ack(&ack).unwrap();
        assert!(matches!(outcome, OriginCancelAckOutcome::Accepted(_)));
        let origin = match outcome {
            OriginCancelAckOutcome::Accepted(session) => session,
            OriginCancelAckOutcome::Rejected(_) => return,
        };
        let result = test_result(
            rtid,
            RemoteOutcome::Cancelled(CancelReason::user("cancelled")),
        );
        let origin = origin.recv_result(&result).unwrap();
        assert_eq!(origin.remote_task_id(), rtid);
    }

    #[test]
    fn origin_session_cancel_before_ack_then_late_reject_flow() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let origin = OriginSession::<OriginInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let origin = origin.send_spawn(&req).unwrap();
        let origin = origin.send_cancel(&test_cancel(rtid)).unwrap();
        let ack = test_ack_rejected(rtid);
        let outcome = origin.recv_spawn_ack(&ack).unwrap();
        assert!(matches!(outcome, OriginCancelAckOutcome::Rejected(_)));
        if let OriginCancelAckOutcome::Rejected(session) = outcome {
            assert_eq!(session.remote_task_id(), rtid);
        }
    }

    #[test]
    fn origin_session_reject_flow() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let origin = OriginSession::<OriginInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let origin = origin.send_spawn(&req).unwrap();
        let ack = test_ack_rejected(rtid);
        let outcome = origin.recv_spawn_ack(&ack).unwrap();
        assert!(matches!(outcome, OriginAckOutcome::Rejected(_)));
        if let OriginAckOutcome::Rejected(session) = outcome {
            assert_eq!(session.remote_task_id(), rtid);
        }
    }

    #[test]
    fn remote_session_cancel_before_ack_flow() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let remote = RemoteSession::<RemoteInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let remote = remote.recv_spawn(&req).unwrap();
        let remote = remote.recv_cancel(&test_cancel(rtid)).unwrap();
        let remote = remote.send_ack_accepted(&test_ack_accepted(rtid)).unwrap();
        let result = test_result(rtid, RemoteOutcome::Cancelled(CancelReason::user("done")));
        let remote = remote.send_result(&result).unwrap();
        assert_eq!(remote.remote_task_id(), rtid);
    }

    #[test]
    fn remote_session_cancelled_running_flow_allows_renewal_before_result() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let remote = RemoteSession::<RemoteInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let remote = remote.recv_spawn(&req).unwrap();
        let remote = remote.send_ack_accepted(&test_ack_accepted(rtid)).unwrap();
        let remote = remote.recv_cancel(&test_cancel(rtid)).unwrap();
        let remote = remote.send_lease_renewal(&test_renewal(rtid)).unwrap();
        let result = test_result(rtid, RemoteOutcome::Cancelled(CancelReason::user("done")));
        let remote = remote.send_result(&result).unwrap();
        assert_eq!(remote.remote_task_id(), rtid);
    }

    #[test]
    fn protocol_id_mismatch_is_error() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let origin = OriginSession::<OriginInit>::new(rtid);
        let req = test_spawn_request(&cx, RemoteTaskId::next());
        let err = origin.send_spawn(&req).unwrap_err();
        assert!(matches!(
            err,
            RemoteProtocolError::RemoteTaskIdMismatch { .. }
        ));
    }

    #[test]
    fn protocol_ack_status_mismatch_is_error() {
        let cx: Cx = Cx::for_testing();
        let rtid = RemoteTaskId::next();
        let remote = RemoteSession::<RemoteInit>::new(rtid);
        let req = test_spawn_request(&cx, rtid);
        let remote = remote.recv_spawn(&req).unwrap();
        let ack = test_ack_rejected(rtid);
        let err = remote.send_ack_accepted(&ack).unwrap_err();
        assert!(matches!(
            err,
            RemoteProtocolError::UnexpectedAckStatus { .. }
        ));
    }

    #[test]
    fn trace_event_names_are_namespaced() {
        // Verify all trace events follow the "remote::" namespace convention.
        assert!(trace_events::SPAWN_REQUEST_CREATED.starts_with("remote::"));
        assert!(trace_events::SPAWN_REQUEST_SENT.starts_with("remote::"));
        assert!(trace_events::SPAWN_ACK_RECEIVED.starts_with("remote::"));
        assert!(trace_events::SPAWN_REJECTED.starts_with("remote::"));
        assert!(trace_events::CANCEL_SENT.starts_with("remote::"));
        assert!(trace_events::CANCEL_RECEIVED.starts_with("remote::"));
        assert!(trace_events::RESULT_DELIVERED.starts_with("remote::"));
        assert!(trace_events::LEASE_RENEWAL_SENT.starts_with("remote::"));
        assert!(trace_events::LEASE_RENEWAL_RECEIVED.starts_with("remote::"));
        assert!(trace_events::LEASE_EXPIRED.starts_with("remote::"));
    }

    // -----------------------------------------------------------------------
    // Lease tests (tmh.2.1)
    // -----------------------------------------------------------------------

    fn test_obligation_id() -> ObligationId {
        ObligationId::new_for_test(0, 0)
    }

    fn test_region_id() -> RegionId {
        RegionId::new_for_test(0, 1)
    }

    fn test_task_id() -> TaskId {
        TaskId::new_for_test(0, 0)
    }

    #[test]
    fn lease_creation() {
        let now = Time::from_secs(10);
        let lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );
        assert!(lease.is_active(now));
        assert!(!lease.is_expired(now));
        assert!(!lease.is_released());
        assert_eq!(lease.renewal_count(), 0);
        assert_eq!(lease.initial_duration(), Duration::from_secs(30));
        assert_eq!(lease.expires_at(), Time::from_secs(40));
    }

    #[test]
    fn lease_remaining_time() {
        let now = Time::from_secs(10);
        let lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );
        let remaining = lease.remaining(Time::from_secs(20));
        assert_eq!(remaining, Duration::from_secs(20));

        // At expiry: zero remaining
        let remaining = lease.remaining(Time::from_secs(40));
        assert_eq!(remaining, Duration::ZERO);

        // Past expiry: zero remaining
        let remaining = lease.remaining(Time::from_secs(50));
        assert_eq!(remaining, Duration::ZERO);
    }

    #[test]
    fn lease_expiry_detection() {
        let now = Time::from_secs(10);
        let lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        // Before expiry
        assert!(!lease.is_expired(Time::from_secs(39)));
        assert!(lease.is_active(Time::from_secs(39)));

        // At expiry boundary
        assert!(lease.is_expired(Time::from_secs(40)));
        assert!(!lease.is_active(Time::from_secs(40)));

        // After expiry
        assert!(lease.is_expired(Time::from_secs(50)));
    }

    #[test]
    fn lease_renew_extends_expiry() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        // Renew at t=25 for another 30s
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(25));
        assert!(result.is_ok());
        assert_eq!(lease.expires_at(), Time::from_secs(55));
        assert_eq!(lease.renewal_count(), 1);

        // Renew again at t=50
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(50));
        assert!(result.is_ok());
        assert_eq!(lease.expires_at(), Time::from_secs(80));
        assert_eq!(lease.renewal_count(), 2);
    }

    #[test]
    fn lease_renew_after_expiry_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        // Try to renew after expiry
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(50));
        assert_eq!(result, Err(LeaseError::Expired));
        assert_eq!(lease.state(), LeaseState::Expired);
    }

    #[test]
    fn lease_release() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        let result = lease.release(Time::from_secs(20));
        assert!(result.is_ok());
        assert!(lease.is_released());
        assert_eq!(lease.state(), LeaseState::Released);
    }

    #[test]
    fn lease_remaining_after_release_is_zero_even_before_original_expiry() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        lease.release(Time::from_secs(20)).unwrap();

        assert_eq!(lease.remaining(Time::from_secs(20)), Duration::ZERO);
        assert_eq!(lease.remaining(Time::from_secs(25)), Duration::ZERO);
    }

    #[test]
    fn lease_double_release_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        lease.release(Time::from_secs(20)).unwrap();
        let result = lease.release(Time::from_secs(25));
        assert_eq!(result, Err(LeaseError::Released));
    }

    #[test]
    fn lease_renew_after_release_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        lease.release(Time::from_secs(20)).unwrap();
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(25));
        assert_eq!(result, Err(LeaseError::Released));
    }

    #[test]
    fn lease_mark_expired() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        let result = lease.mark_expired();
        assert!(result.is_ok());
        assert_eq!(lease.state(), LeaseState::Expired);

        // Idempotent
        let result = lease.mark_expired();
        assert!(result.is_ok());
    }

    #[test]
    fn lease_remaining_after_mark_expired_is_zero_before_wall_clock_expiry() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        lease.mark_expired().unwrap();

        assert_eq!(lease.remaining(Time::from_secs(15)), Duration::ZERO);
        assert_eq!(lease.remaining(Time::from_secs(39)), Duration::ZERO);
    }

    #[test]
    fn lease_mark_expired_after_release_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        lease.release(Time::from_secs(20)).unwrap();
        let result = lease.mark_expired();
        assert_eq!(result, Err(LeaseError::Released));
    }

    #[test]
    fn lease_state_display() {
        assert_eq!(format!("{}", LeaseState::Active), "Active");
        assert_eq!(format!("{}", LeaseState::Released), "Released");
        assert_eq!(format!("{}", LeaseState::Expired), "Expired");
    }

    #[test]
    fn lease_error_display() {
        assert_eq!(format!("{}", LeaseError::Expired), "lease expired");
        assert_eq!(
            format!("{}", LeaseError::Released),
            "lease already released"
        );
        assert!(format!("{}", LeaseError::CreationFailed("full".into())).contains("full"));
    }

    // -----------------------------------------------------------------------
    // Idempotency store tests (tmh.2.2)
    // -----------------------------------------------------------------------

    #[test]
    fn idempotency_store_new_request() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        assert!(store.is_empty());

        let key = IdempotencyKey::from_raw(1);
        let request = test_request_fingerprint("encode");
        let decision = store.check(&key, &request, Time::from_secs(10));
        assert!(matches!(decision, DedupDecision::New));

        let inserted = store.record(key, RemoteTaskId::next(), request, Time::from_secs(10));
        assert!(inserted);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn idempotency_store_in_flight_record_survives_insertion_ttl() {
        let mut store = IdempotencyStore::new(Duration::from_secs(60));
        let key = IdempotencyKey::from_raw(2);
        let canonical_task = RemoteTaskId::from_raw(11);
        let request = test_request_fingerprint("long-running");

        assert!(matches!(
            store.check_and_record(key, canonical_task, request.clone(), Time::from_secs(10)),
            DedupDecision::New
        ));

        assert_eq!(store.evict_expired(Time::from_secs(10_000)), 0);
        assert!(matches!(
            store.check(&key, &request, Time::from_secs(10_000)),
            DedupDecision::Duplicate(record)
                if record.remote_task_id == canonical_task
                    && record.outcome.is_none()
                    && record.expires_at.is_none()
        ));
        assert!(matches!(
            store.check(
                &key,
                &test_request_fingerprint("different-work"),
                Time::from_secs(10_000),
            ),
            DedupDecision::Conflict
        ));
    }

    #[test]
    fn idempotency_store_atomic_admission_fences_replaced_record_generation() {
        let mut store = IdempotencyStore::new(Duration::from_secs(60));
        let key = IdempotencyKey::from_raw(3);
        let request = test_request_fingerprint("reusable");
        let old_task = RemoteTaskId::from_raw(21);
        let new_task = RemoteTaskId::from_raw(22);

        assert!(matches!(
            store.check_and_record(key, old_task, request.clone(), Time::from_secs(10)),
            DedupDecision::New
        ));
        assert!(store.complete(
            &key,
            old_task,
            RemoteOutcome::Success(vec![1]),
            Time::from_secs(20),
        ));

        assert!(matches!(
            store.check_and_record(key, new_task, request.clone(), Time::from_secs(80)),
            DedupDecision::New
        ));
        assert_eq!(store.len(), 1);
        assert!(matches!(
            store.check(&key, &request, Time::from_secs(81)),
            DedupDecision::Duplicate(record)
                if record.remote_task_id == new_task
                    && record.outcome.is_none()
                    && record.expires_at.is_none()
        ));
        assert!(!store.complete(
            &key,
            old_task,
            RemoteOutcome::Failed("stale completion".into()),
            Time::from_secs(82),
        ));
        assert!(matches!(
            store.check(&key, &request, Time::from_secs(82)),
            DedupDecision::Duplicate(record)
                if record.remote_task_id == new_task
                    && record.outcome.is_none()
                    && record.expires_at.is_none()
        ));
        assert!(store.complete(
            &key,
            new_task,
            RemoteOutcome::Success(vec![2]),
            Time::from_secs(83),
        ));
        assert!(matches!(
            store.check(&key, &request, Time::from_secs(84)),
            DedupDecision::Duplicate(record)
                if record.remote_task_id == new_task
                    && matches!(record.outcome, Some(RemoteOutcome::Success(ref bytes)) if bytes.as_slice() == [2])
                    && record.expires_at == Some(Time::from_secs(143))
        ));
    }

    #[test]
    fn idempotency_store_duplicate_detection() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(42);
        let request = test_request_fingerprint("encode");

        store.record(
            key,
            RemoteTaskId::next(),
            request.clone(),
            Time::from_secs(10),
        );

        // Same key, same computation → Duplicate
        let decision = store.check(&key, &request, Time::from_secs(20));
        assert!(matches!(decision, DedupDecision::Duplicate(_)));

        // Trying to record again returns false
        let inserted = store.record(key, RemoteTaskId::next(), request, Time::from_secs(20));
        assert!(!inserted);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn idempotency_store_conflict_detection() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(42);

        store.record(
            key,
            RemoteTaskId::next(),
            test_request_fingerprint("encode"),
            Time::from_secs(10),
        );

        // Same key, DIFFERENT computation → Conflict
        let decision = store.check(
            &key,
            &test_request_fingerprint("decode"),
            Time::from_secs(20),
        );
        assert!(matches!(decision, DedupDecision::Conflict));
    }

    #[test]
    fn idempotency_store_complete_outcome() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(99);
        let task_id = RemoteTaskId::next();

        store.record(
            key,
            task_id,
            test_request_fingerprint("work"),
            Time::from_secs(10),
        );

        // Complete with success
        let updated = store.complete(
            &key,
            task_id,
            RemoteOutcome::Success(vec![1, 2, 3]),
            Time::from_secs(15),
        );
        assert!(updated);

        // Check returns duplicate with outcome
        let decision = store.check(&key, &test_request_fingerprint("work"), Time::from_secs(20));
        assert!(matches!(decision, DedupDecision::Duplicate(_)));
        if let DedupDecision::Duplicate(record) = decision {
            assert!(record.outcome.is_some());
            assert!(record.outcome.unwrap().is_success());
        }
    }

    #[test]
    fn idempotency_store_complete_unknown_key() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(999);

        // Complete on unknown key returns false
        let updated = store.complete(
            &key,
            RemoteTaskId::from_raw(1),
            RemoteOutcome::Failed("oops".into()),
            Time::from_secs(10),
        );
        assert!(!updated);
    }

    #[test]
    fn idempotency_store_eviction() {
        let mut store = IdempotencyStore::new(Duration::from_secs(60));
        let completed_key = IdempotencyKey::from_raw(1);
        let in_flight_key = IdempotencyKey::from_raw(2);
        let completed_task = RemoteTaskId::next();

        // Completion at t=20 establishes the terminal deadline at t=80.
        store.record(
            completed_key,
            completed_task,
            test_request_fingerprint("a"),
            Time::from_secs(10),
        );
        assert!(store.complete(
            &completed_key,
            completed_task,
            RemoteOutcome::Success(vec![]),
            Time::from_secs(20),
        ));

        // This second operation remains in flight and therefore has no
        // eviction deadline.
        store.record(
            in_flight_key,
            RemoteTaskId::next(),
            test_request_fingerprint("b"),
            Time::from_secs(50),
        );
        assert_eq!(store.len(), 2);

        assert_eq!(store.evict_expired(Time::from_secs(79)), 0);

        // The terminal record expires at the boundary; the in-flight record
        // remains resident.
        let evicted = store.evict_expired(Time::from_secs(80));
        assert_eq!(evicted, 1);
        assert_eq!(store.len(), 1);

        let decision = store.check(
            &in_flight_key,
            &test_request_fingerprint("b"),
            Time::from_secs(10_000),
        );
        assert!(matches!(decision, DedupDecision::Duplicate(_)));

        let decision = store.check(
            &completed_key,
            &test_request_fingerprint("a"),
            Time::from_secs(80),
        );
        assert!(matches!(decision, DedupDecision::New));
    }

    #[test]
    fn idempotency_store_check_treats_expired_records_as_new() {
        let mut store = IdempotencyStore::new(Duration::from_secs(60));
        let key = IdempotencyKey::from_raw(3);
        let task_id = RemoteTaskId::next();
        store.record(
            key,
            task_id,
            test_request_fingerprint("encode"),
            Time::from_secs(10),
        );
        assert!(store.complete(
            &key,
            task_id,
            RemoteOutcome::Success(vec![]),
            Time::from_secs(20),
        ));

        let decision = store.check(
            &key,
            &test_request_fingerprint("decode"),
            Time::from_secs(80),
        );
        assert!(
            matches!(decision, DedupDecision::New),
            "expired keys must not survive as stale conflicts"
        );
        assert!(store.is_empty(), "expired entry should be removed lazily");
    }

    #[test]
    fn idempotency_store_debug() {
        let store = IdempotencyStore::new(Duration::from_secs(60));
        let debug = format!("{store:?}");
        assert!(debug.contains("IdempotencyStore"));
        assert!(debug.contains("entries"));
    }

    // -----------------------------------------------------------------------
    // Saga tests (tmh.2.3)
    // -----------------------------------------------------------------------

    #[cfg(feature = "tls")]
    #[test]
    fn remote_service_reservation_fences_delayed_commit_and_drop_after_key_reuse() {
        let cx = Cx::for_testing();
        let peer = NodeId::new("reusing-peer");
        let request = test_spawn_request(&cx, RemoteTaskId::from_raw(900));
        let state = RemoteServiceIdempotency::new(Duration::from_secs(10), 1);
        assert!(matches!(
            state.admit(&peer, &request, Time::from_secs(100)),
            RemoteServiceIdempotencyAdmission::Execute
        ));
        let old = state.protect_in_flight(&cx, &peer, &request, 4096, false);
        let delayed = RemoteServiceTerminalCommit::Outcome {
            peer: peer.clone(), key: request.idempotency_key,
            canonical_task_id: request.remote_task_id,
            outcome: RemoteOutcome::Success(vec![9]),
        }.with_reservation(Some(Arc::clone(&old)));
        assert!(state.complete_outcome(
            &peer, request.idempotency_key, request.remote_task_id,
            RemoteOutcome::Success(vec![1]), Time::from_secs(100),
        ));
        assert!(matches!(
            state.admit(&peer, &request, Time::from_secs(110)),
            RemoteServiceIdempotencyAdmission::Execute
        ));
        assert!(!delayed.complete(&state, Time::from_secs(111)),
            "a reused task ID does not revive the old reservation");
        drop(old);
        assert!(matches!(
            state.admit(&peer, &request, Time::from_secs(112)),
            RemoteServiceIdempotencyAdmission::InFlight
        ));
        assert!(state.complete_outcome(
            &peer, request.idempotency_key, request.remote_task_id,
            RemoteOutcome::Success(vec![2]), Time::from_secs(112),
        ));
        assert!(matches!(
            state.admit(&peer, &request, Time::from_secs(113)),
            RemoteServiceIdempotencyAdmission::CachedOutcome(RemoteOutcome::Success(bytes))
                if bytes == vec![2]
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn remote_service_abandoned_result_keeps_wire_limit_and_terminal_retention() {
        let cx = Cx::for_testing();
        let peer = NodeId::new("large-result-peer");
        let request = test_spawn_request(&cx, RemoteTaskId::from_raw(901));
        let state = RemoteServiceIdempotency::new(Duration::from_secs(10), 1);
        let admitted_at = remote_service_idempotency_now(&cx);
        assert!(matches!(
            state.admit(&peer, &request, admitted_at),
            RemoteServiceIdempotencyAdmission::Execute
        ));
        let guard = state.protect_in_flight(&cx, &peer, &request, 512, true);
        guard.set_task(RemoteServiceRetainedTask::Terminal(Ok(Ok(
            RemoteOutcome::Success(vec![7; 8192]),
        ))));
        drop(guard);
        assert!(matches!(
            state.admit(&peer, &request, remote_service_idempotency_now(&cx)),
            RemoteServiceIdempotencyAdmission::CachedExecutionRejection(message)
                if message.contains("wire frame limit")
        ));
        let mut inner = state.inner.lock();
        let expiry = inner.peers[&peer].store.entries[&request.idempotency_key]
            .expires_at.expect("abandonment starts terminal retention");
        assert!(expiry >= admitted_at + Duration::from_secs(10));
        assert_eq!(inner.evict_expired(expiry), None);
        assert!(inner.peers.is_empty(), "quiet abandoned requests are reclaimable");
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn remote_service_native_unstarted_reservation_finalizer_does_not_wait_for_a_task() {
        for workers in [1, 2] {
            let runtime = if workers == 1 {
                crate::runtime::RuntimeBuilder::current_thread().build().unwrap()
            } else {
                crate::runtime::RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap()
            };
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let peer = NodeId::new("unstarted-peer");
                let request = test_spawn_request(&cx, RemoteTaskId::from_raw(902));
                let state = RemoteServiceIdempotency::new(Duration::from_secs(10), 1);
                assert!(matches!(
                    state.admit(&peer, &request, cx.now()),
                    RemoteServiceIdempotencyAdmission::Execute
                ));
                let guard = state.protect_in_flight(&cx, &peer, &request, 4096, false);
                let child = remote_service_open_child(
                    &cx, ChildRegionSpec::inherit(), None, Some(&guard),
                ).await.unwrap();
                crate::time::timeout(cx.now(), Duration::from_secs(3), child.close())
                    .await.expect("no-task close must not await a nonexistent join")
                    .unwrap();
                drop(guard);
                assert!(matches!(
                    state.admit(&peer, &request, cx.now()),
                    RemoteServiceIdempotencyAdmission::CachedExecutionRejection(_)
                ));
            });
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn remote_service_native_abandoned_exchange_waits_for_descendants_and_preserves_result() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use crate::distributed::{HasSchema, SchemaDescriptor};

        struct Payload;
        impl HasSchema for Payload {
            fn schema() -> SchemaDescriptor {
                SchemaDescriptor::primitive("remote-reservation.native.bytes.v1")
            }
        }
        #[derive(Default)]
        struct Witness {
            parked: AtomicBool,
            handler_parked: AtomicBool,
            cancelled: AtomicBool,
            release: AtomicBool,
            retired: AtomicBool,
            factories: AtomicUsize,
            changed: crate::sync::Notify,
        }
        struct Release(Arc<Witness>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.release.store(true, Ordering::Release);
                self.0.changed.notify_waiters();
            }
        }

        for workers in [1, 2] {
            for finish_before_abort in [false, true] {
                let runtime = if workers == 1 {
                    crate::runtime::RuntimeBuilder::current_thread().build().unwrap()
                } else {
                    crate::runtime::RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap()
                };
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let witness = Arc::new(Witness::default());
                    let release = Release(Arc::clone(&witness));
                    let mut registry = RemoteComputationRegistry::new();
                    let seen = Arc::clone(&witness);
                    registry.register::<Payload, Payload, _, _>("compute", move |body, _| {
                        let seen = Arc::clone(&seen);
                        seen.factories.fetch_add(1, Ordering::SeqCst);
                        async move {
                            let descendant = Arc::clone(&seen);
                            let _task = body.spawn(move |child| async move {
                                let mut cancel = std::pin::pin!(child.cancelled());
                                std::future::poll_fn(|task| {
                                    let poll = cancel.as_mut().poll(task);
                                    if poll.is_pending() && !descendant.parked.swap(true, Ordering::AcqRel) {
                                        descendant.changed.notify_waiters();
                                    }
                                    poll
                                }).await;
                                assert!(child.checkpoint().is_err());
                                descendant.cancelled.store(true, Ordering::Release);
                                descendant.changed.notify_waiters();
                                descendant.changed.wait_until(|| descendant.release.load(Ordering::Acquire)).await;
                                descendant.retired.store(true, Ordering::Release);
                                descendant.changed.notify_waiters();
                            }).unwrap();
                            seen.changed.wait_until(|| seen.parked.load(Ordering::Acquire)).await;
                            if !finish_before_abort {
                                let mut cancel = std::pin::pin!(body.cancelled());
                                std::future::poll_fn(|task| {
                                    let poll = cancel.as_mut().poll(task);
                                    if poll.is_pending() && !seen.handler_parked.swap(true, Ordering::AcqRel) {
                                        seen.changed.notify_waiters();
                                    }
                                    poll
                                }).await;
                                assert!(body.checkpoint().is_err());
                            }
                            Ok(RemoteOutcome::Success(vec![42]))
                        }
                    }).unwrap();
                    registry.register::<Payload, Payload, _, _>("echo", |_, _| async {
                        Ok(RemoteOutcome::Success(vec![99]))
                    }).unwrap();
                    let peer = NodeId::new("abandoned-peer");
                    let other_peer = NodeId::new("live-peer");
                    let mut policy = RemotePeerAdmissionPolicy::new(
                        RemoteProtocolVersion::V2, registry.schema_registry().clone(),
                    );
                    for node in [&peer, &other_peer] {
                        policy.grant_peer(node.clone(), ["compute", "echo"]).unwrap();
                    }
                    let session = policy.admit(&policy.hello_for(peer.clone())).unwrap();
                    let other_session = policy.admit(&policy.hello_for(other_peer.clone())).unwrap();
                    let request = test_spawn_request(&cx, RemoteTaskId::from_raw(903));
                    let state = RemoteServiceIdempotency::new(Duration::from_secs(10), 1);
                    let connection_state = state.clone();
                    let connection_request = request.clone();
                    let connection_registry = registry.clone();
                    let mut connection = cx.spawn(move |connection_cx| async move {
                        let shutdown = ShutdownSignal::new();
                        race_remote_service_termination(&connection_cx, &shutdown, async {
                            let (response, commit) = remote_service_dispatch_with_idempotency(
                                &connection_cx, &session, &connection_registry, connection_request,
                                Some(&connection_state), RemoteServiceExecutionMode::LeaseBound,
                                None, 4096,
                            ).await;
                            if let Some(commit) = commit {
                                assert!(commit.complete(&connection_state, connection_cx.now()));
                            }
                            response
                        }).await
                    }).unwrap();
                    crate::time::timeout(cx.now(), Duration::from_secs(3),
                        witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire)
                            && if finish_before_abort {
                                // Only the dispatcher's close can cancel this
                                // descendant before the connection abort. It
                                // closes only after the native join observed
                                // the published result and retirement barrier.
                                witness.cancelled.load(Ordering::Acquire)
                            } else {
                                witness.handler_parked.load(Ordering::Acquire)
                            }),
                    ).await.expect("handler publication or cancellation wait is established");
                    connection.abort();
                    let stopped = crate::time::timeout(cx.now(), Duration::from_secs(3), connection.join(&cx))
                        .await.expect("connection cancellation wakes the parked exchange")
                        .expect("acknowledged connection cancellation preserves its result");
                    assert!(stopped.is_none(), "termination drops the exchange before publication");
                    crate::time::timeout(cx.now(), Duration::from_secs(3),
                        witness.changed.wait_until(|| witness.cancelled.load(Ordering::Acquire)),
                    ).await.expect("descendant cancellation is observed");
                    assert!(!witness.retired.load(Ordering::Acquire));
                    {
                        let mut inner = state.inner.lock();
                        assert_eq!(inner.evict_expired(Time::MAX), None);
                        let record = &inner.peers[&peer].store.entries[&request.idempotency_key];
                        assert!(record.outcome.is_none() && record.expires_at.is_none(),
                            "cleanup owns the key until quiescence");
                    }
                    assert!(matches!(
                        state.admit(&peer, &request, cx.now()),
                        RemoteServiceIdempotencyAdmission::InFlight
                    ));
                    let mut different = request.clone();
                    different.idempotency_key = IdempotencyKey::from_raw(904);
                    assert!(matches!(
                        state.admit(&peer, &different, cx.now()),
                        RemoteServiceIdempotencyAdmission::Capacity
                    ));
                    let mut echo = different;
                    echo.computation = ComputationName::new("echo");
                    let (response, commit) = crate::time::timeout(cx.now(), Duration::from_secs(3),
                        remote_service_dispatch_with_idempotency(
                            &cx, &other_session, &registry, echo,
                            Some(&state), RemoteServiceExecutionMode::LeaseBound, None, 4096,
                        ),
                    ).await.expect("another peer remains live during cleanup");
                    assert!(matches!(response, RemoteServiceWireResponse::Outcome {
                        outcome: RemoteServiceWireOutcome::Success(bytes), ..
                    } if bytes == vec![99]));
                    assert!(commit.unwrap().complete(&state, cx.now()));
                    // Retire the unrelated peer's terminal entry so the next
                    // expiry notification belongs to the abandoned operation.
                    // Its still-live key must survive even this maximal sweep.
                    state.inner.lock().evict_expired(Time::MAX);
                    assert!(matches!(
                        state.admit(&peer, &request, cx.now()),
                        RemoteServiceIdempotencyAdmission::InFlight
                    ));
                    let released_at = cx.now();
                    drop(release);
                    crate::time::timeout(cx.now(), Duration::from_secs(3), async {
                        loop {
                            let changed = state.expiry_changed.notified();
                            if state.inner.lock().peers[&peer].store.entries[&request.idempotency_key]
                                .outcome.is_some() { break; }
                            changed.await;
                        }
                    }).await.expect("quiescence settles the abandoned key");
                    assert!(witness.retired.load(Ordering::Acquire));
                    assert_eq!(witness.factories.load(Ordering::SeqCst), 1);
                    assert!(matches!(
                        state.admit(&peer, &request, cx.now()),
                        RemoteServiceIdempotencyAdmission::CachedOutcome(RemoteOutcome::Success(bytes))
                            if bytes == vec![42]
                    ));
                    let expiry = state.inner.lock().peers[&peer].store.entries[&request.idempotency_key]
                        .expires_at.unwrap();
                    assert!(expiry >= released_at + Duration::from_secs(10),
                        "retention starts after cleanup, not at connection abort");
                });
                assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
            }
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn remote_service_idempotency_frees_an_idle_peers_expired_records() {
        let cx = Cx::for_testing();
        let retention = Duration::from_secs(10);
        let state = RemoteServiceIdempotency::new(retention, 16);
        let (quiet, active) = (NodeId::new("quiet-peer"), NodeId::new("active-peer"));
        let start = Time::from_secs(100);
        for raw in 1..=3 {
            let request = test_spawn_request(&cx, RemoteTaskId::from_raw(raw));
            assert!(matches!(
                state.admit(&quiet, &request, start),
                RemoteServiceIdempotencyAdmission::Execute
            ));
            assert!(state.complete_outcome(
                &quiet,
                request.idempotency_key,
                request.remote_task_id,
                RemoteOutcome::Success(vec![0; 1024]),
                start,
            ));
        }
        assert_eq!(state.inner.lock().peers[&quiet].store.len(), 3);

        // Only another peer is admitted once the quiet peer's records expired.
        let later = start + retention + Duration::from_secs(1);
        let request = test_spawn_request(&cx, RemoteTaskId::from_raw(9));
        assert!(matches!(
            state.admit(&active, &request, later),
            RemoteServiceIdempotencyAdmission::Execute
        ));
        let inner = state.inner.lock();
        assert!(
            !inner.peers.contains_key(&quiet),
            "an idle peer's expired records must be freed"
        );
        assert_eq!(inner.peers[&active].store.len(), 1);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn remote_service_idempotency_expiry_refresh_preserves_generation_and_rejection() {
        let cx = Cx::for_testing();
        let state = RemoteServiceIdempotency::new(Duration::from_secs(10), 16);
        let peer = NodeId::new("refreshed-peer");
        let mut request = test_spawn_request(&cx, RemoteTaskId::from_raw(301));
        assert!(matches!(
            state.admit(&peer, &request, Time::from_secs(100)),
            RemoteServiceIdempotencyAdmission::Execute
        ));
        assert!(state.complete_execution_rejection(
            &peer,
            request.idempotency_key,
            request.remote_task_id,
            "rejected".to_owned(),
            Time::from_secs(100),
        ));
        // A repeated completion refreshes outcome retention, while an existing
        // execution rejection still expires at its own original deadline.
        for now in 101..=105 {
            assert!(state.complete_outcome(
                &peer,
                request.idempotency_key,
                request.remote_task_id,
                RemoteOutcome::Success(vec![1]),
                Time::from_secs(now),
            ));
            assert_eq!(state.inner.lock().expiries.len(), 1);
        }
        {
            let mut inner = state.inner.lock();
            assert_eq!(
                inner.evict_expired(Time::from_secs(110)),
                Some(Time::from_secs(115))
            );
            assert!(inner.peers[&peer].execution_rejections.is_empty());
            assert_eq!(inner.peers[&peer].store.len(), 1);
            assert_eq!(inner.expiries.len(), 1);
        }
        assert!(matches!(
            state.admit(&peer, &request, Time::from_secs(114)),
            RemoteServiceIdempotencyAdmission::CachedOutcome(RemoteOutcome::Success(bytes))
                if bytes == vec![1]
        ));

        let previous_task = request.remote_task_id;
        request.remote_task_id = RemoteTaskId::from_raw(302);
        assert!(matches!(
            state.admit(&peer, &request, Time::from_secs(115)),
            RemoteServiceIdempotencyAdmission::Execute
        ));
        assert!(!state.complete_outcome(
            &peer,
            request.idempotency_key,
            previous_task,
            RemoteOutcome::Success(vec![2]),
            Time::from_secs(116),
        ));
        let mut inner = state.inner.lock();
        assert_eq!(inner.evict_expired(Time::from_secs(10_000)), None);
        assert!(inner.expiries.is_empty());
        let record = &inner.peers[&peer].store.entries[&request.idempotency_key];
        assert_eq!(record.remote_task_id, request.remote_task_id);
        assert!(record.outcome.is_none());
        assert!(record.expires_at.is_none());
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn remote_service_idle_expiry_uses_service_clock_and_preserves_live_records() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use std::sync::atomic::AtomicUsize;
        use std::task::Wake;

        #[derive(Default)]
        struct WakeCount(AtomicUsize);
        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let clock = Arc::new(VirtualClock::new());
        clock.advance_to(Time::from_secs(100));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 1),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        // A different ambient clock must neither expire the service's records
        // early nor steal registration of its timer.
        let ambient_clock = Arc::new(VirtualClock::new());
        ambient_clock.advance_to(Time::from_secs(10_000));
        let ambient_timer = TimerDriverHandle::with_virtual_clock(ambient_clock);
        let ambient = Cx::new_with_drivers(
            RegionId::new_for_test(1, 1),
            TaskId::new_for_test(1, 1),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(ambient_timer.clone()),
            None,
        );
        let _current = Cx::set_current(Some(ambient));
        let state = RemoteServiceIdempotency::new(Duration::from_secs(10), 16);
        let quiet = NodeId::new("expired-peer");
        let live = NodeId::new("live-peer");
        let completed = test_spawn_request(&cx, RemoteTaskId::from_raw(101));
        let rejected = test_spawn_request(&cx, RemoteTaskId::from_raw(102));
        let in_flight = test_spawn_request(&cx, RemoteTaskId::from_raw(103));
        let retained = test_spawn_request(&cx, RemoteTaskId::from_raw(104));
        for (peer, request) in [
            (&quiet, &completed),
            (&quiet, &rejected),
            (&live, &in_flight),
            (&live, &retained),
        ] {
            assert!(matches!(
                state.admit(peer, request, cx.now()),
                RemoteServiceIdempotencyAdmission::Execute
            ));
        }

        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task_cx = Context::from_waker(&waker);
        let mut maintenance = Box::pin(state.maintain_expiry(&cx));
        assert!(maintenance.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(state.expiry_changed.waiter_count(), 1);
        assert_eq!(timer.pending_count(), 0, "in-flight work has no expiry");
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

        let first_completed_at = cx.now();
        clock.advance_to(Time::from_secs(105));
        assert!(state.complete_outcome(
            &live,
            retained.idempotency_key,
            retained.remote_task_id,
            RemoteOutcome::Success(vec![8; 4096]),
            cx.now(),
        ));
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert!(maintenance.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(timer.next_deadline(), Some(Time::from_secs(115)));

        // Another connection sampled its completion time before contending
        // for the cache lock. Publishing it must advance the parked deadline.
        assert!(state.complete_outcome(
            &quiet,
            completed.idempotency_key,
            completed.remote_task_id,
            RemoteOutcome::Success(vec![7; 4096]),
            first_completed_at,
        ));
        assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
        assert!(state.complete_execution_rejection(
            &quiet,
            rejected.idempotency_key,
            rejected.remote_task_id,
            "execution rejected".to_owned(),
            first_completed_at,
        ));
        assert!(maintenance.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(timer.next_deadline(), Some(Time::from_secs(110)));
        assert_eq!(ambient_timer.pending_count(), 0);

        for _ in 0..4 {
            assert!(maintenance.as_mut().poll(&mut task_cx).is_pending());
        }
        assert_eq!(timer.pending_count(), 1, "retain exactly one expiry timer");
        assert_eq!(timer.next_deadline(), Some(Time::from_secs(110)));
        assert_eq!(wakes.0.load(Ordering::SeqCst), 2, "no idle self-waking");

        clock.advance_to(Time::from_secs(109));
        assert_eq!(timer.process_timers(), 0);
        assert!(maintenance.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(state.inner.lock().peers[&quiet].store.len(), 2);

        // Expire without admitting any more requests, on either peer.
        clock.advance_to(Time::from_secs(110));
        assert_eq!(timer.process_timers(), 1);
        assert!(maintenance.as_mut().poll(&mut task_cx).is_pending());
        {
            let inner = state.inner.lock();
            assert!(!inner.peers.contains_key(&quiet));
            assert_eq!(inner.peers[&live].store.len(), 2);
            assert!(
                inner.peers[&live].store.entries[&in_flight.idempotency_key]
                    .outcome
                    .is_none()
            );
            assert!(
                inner.peers[&live].store.entries[&retained.idempotency_key]
                    .outcome
                    .is_some()
            );
        }
        assert_eq!(timer.next_deadline(), Some(Time::from_secs(115)));

        clock.advance_to(Time::from_secs(115));
        assert_eq!(timer.process_timers(), 1);
        assert!(maintenance.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(state.inner.lock().peers[&live].store.len(), 1);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(ambient_timer.pending_count(), 0);

        // Listener shutdown drops this future before the next expiry, retiring
        // the outstanding registration without evicting a retained outcome.
        assert!(state.complete_outcome(
            &live,
            in_flight.idempotency_key,
            in_flight.remote_task_id,
            RemoteOutcome::Success(vec![]),
            cx.now(),
        ));
        assert!(maintenance.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(timer.next_deadline(), Some(Time::from_secs(125)));
        drop(maintenance);
        assert_eq!(state.expiry_changed.waiter_count(), 0);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(state.inner.lock().peers[&live].store.len(), 1);
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn remote_service_driverless_idle_expiry_keeps_wall_clock_under_foreign_context() {
        use crate::time::{TimerDriverHandle, VirtualClock, raw_wall_now};

        let owner = Cx::for_testing();
        assert!(owner.timer_driver().is_none());
        let ambient_clock = Arc::new(VirtualClock::new());
        ambient_clock.advance_to(Time::MAX);
        let ambient_timer = TimerDriverHandle::with_virtual_clock(ambient_clock);
        let ambient = Cx::new_with_drivers(
            RegionId::new_for_test(1, 1),
            TaskId::new_for_test(1, 1),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(ambient_timer.clone()),
            None,
        );
        let _current = Cx::set_current(Some(ambient));
        // Cx's driverless convenience clock can follow the ambient driver;
        // cache timestamps and maintenance must consistently select raw wall
        // time to match the explicitly wall-bound expiry timer.
        assert_eq!(owner.now(), Time::MAX);
        let before = raw_wall_now();
        let now = remote_service_idempotency_now(&owner);
        assert!(before <= now && now <= raw_wall_now());

        let retention = Duration::from_secs(3600);
        let state = RemoteServiceIdempotency::new(retention, 16);
        let peer = NodeId::new("driverless-peer");
        let request = test_spawn_request(&owner, RemoteTaskId::from_raw(401));
        assert!(matches!(
            state.admit(&peer, &request, now),
            RemoteServiceIdempotencyAdmission::Execute
        ));
        assert!(state.complete_outcome(
            &peer,
            request.idempotency_key,
            request.remote_task_id,
            RemoteOutcome::Success(vec![1; 1024]),
            now,
        ));

        let mut maintenance = Box::pin(state.maintain_expiry(&owner));
        let mut task_cx = Context::from_waker(Waker::noop());
        for _ in 0..3 {
            assert!(maintenance.as_mut().poll(&mut task_cx).is_pending());
        }
        let inner = state.inner.lock();
        assert_eq!(inner.peers[&peer].store.len(), 1);
        assert_eq!(inner.next_expiry(), Some(now + retention));
        drop(inner);
        assert_eq!(ambient_timer.pending_count(), 0);
        assert_eq!(state.expiry_changed.waiter_count(), 1);
        drop(maintenance);
        assert_eq!(state.expiry_changed.waiter_count(), 0);
    }

    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn remote_service_native_idle_listener_evicts_without_connections() {
        use crate::runtime::RuntimeBuilder;
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::tls::{CertificateChain, PrivateKey};

        let clock = Arc::new(VirtualClock::new());
        clock.advance_to(Time::from_secs(100));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .with_timer_driver(timer.clone())
            .build()
            .expect("native service runtime");
        let chain = CertificateChain::from_pem(include_bytes!("../tests/fixtures/tls/server.crt"))
            .expect("fixture certificate");
        let key = PrivateKey::from_pem(include_bytes!("../tests/fixtures/tls/server.key"))
            .expect("fixture private key");
        let acceptor = TlsAcceptor::builder(chain, key)
            .disable_strict_cert_validation()
            .build()
            .expect("fixture acceptor");
        let service = runtime
            .block_on(RemoteComputationService::bind(
                "127.0.0.1:0",
                acceptor,
                RemotePeerAdmissionPolicy::new(
                    RemoteProtocolVersion::V3,
                    ComputationSchemaRegistry::new(),
                ),
                RemoteComputationRegistry::new(),
                RemoteComputationServiceConfig::new()
                    .with_idempotency_retention(Duration::from_secs(10)),
            ))
            .expect("bind idle listener");
        let operator = service.handle();
        let state = Arc::clone(&service.idempotency);
        let peer = NodeId::new("quiet-native-peer");
        let request = test_spawn_request(&Cx::for_testing(), RemoteTaskId::from_raw(201));
        assert!(matches!(
            state.admit(&peer, &request, timer.now()),
            RemoteServiceIdempotencyAdmission::Execute
        ));

        let (parked_tx, parked_rx) = std::sync::mpsc::sync_channel(1);
        let (armed_tx, armed_rx) = std::sync::mpsc::sync_channel(1);
        let (expired_tx, expired_rx) = std::sync::mpsc::sync_channel(1);
        let controller_state = Arc::clone(&state);
        let controller_timer = timer.clone();
        let controller_operator = operator.clone();
        let controller = std::thread::spawn(move || {
            // A failed witness must still release block_on and join the native
            // runtime, so regressions fail within the bounded channel waits.
            struct StopService(RemoteComputationServiceHandle);
            impl Drop for StopService {
                fn drop(&mut self) {
                    self.0.force_close();
                }
            }
            let _stop = StopService(controller_operator);
            let limit = Duration::from_secs(5);
            parked_rx
                .recv_timeout(limit)
                .expect("listener parked without clients");
            assert_eq!(controller_timer.pending_count(), 0);
            assert!(controller_state.complete_outcome(
                &peer,
                request.idempotency_key,
                request.remote_task_id,
                RemoteOutcome::Success(vec![42; 64 * 1024]),
                controller_timer.now(),
            ));
            armed_rx
                .recv_timeout(limit)
                .expect("completion wakes idle listener and arms expiry");
            assert_eq!(controller_state.inner.lock().peers[&peer].store.len(), 1);
            clock.advance_to(Time::from_secs(110));
            let _ = controller_timer.process_timers();
            expired_rx
                .recv_timeout(limit)
                .expect("timer alone releases cached outcome");
        });

        let report = runtime
            .block_on(async {
                let cx = Cx::current().expect("native service context");
                let mut run = Box::pin(service.run(&cx));
                let mut parked_tx = Some(parked_tx);
                let mut armed_tx = Some(armed_tx);
                let mut expired_tx = Some(expired_tx);
                std::future::poll_fn(|task_cx| {
                    let result = run.as_mut().poll(task_cx);
                    if result.is_pending() {
                        if state.expiry_changed.waiter_count() == 1
                            && let Some(tx) = parked_tx.take()
                        {
                            tx.send(()).expect("publish parked listener witness");
                        }
                        if timer.next_deadline() == Some(Time::from_secs(110))
                            && let Some(tx) = armed_tx.take()
                        {
                            tx.send(()).expect("publish expiry timer witness");
                        }
                        if state.inner.lock().peers.is_empty()
                            && let Some(tx) = expired_tx.take()
                        {
                            tx.send(()).expect("publish idle cache eviction");
                        }
                    }
                    result
                })
                .await
            })
            .expect("idle listener shuts down cleanly");
        controller.join().expect("expiry controller completes");
        assert_eq!(report.accepted_connections(), 0);
        assert_eq!(report.completed_connections(), 0);
        assert_eq!(report.failed_connections(), 0);
        assert_eq!(operator.active_connections(), 0);
        assert_eq!(operator.shutdown_signal().phase(), ShutdownPhase::Stopped);
        assert!(state.inner.lock().peers.is_empty());
        assert_eq!(state.expiry_changed.waiter_count(), 0);
        assert_eq!(timer.pending_count(), 0);
    }

    #[test]
    fn saga_successful_completion() {
        let mut saga = Saga::new();
        assert_eq!(saga.state(), SagaState::Running);
        assert_eq!(saga.completed_steps(), 0);

        let r1: Result<String, _> = saga.step(
            "create resource",
            || Ok("resource-1".to_string()),
            || "deleted resource-1".to_string(),
        );
        assert!(r1.is_ok());
        assert_eq!(r1.unwrap(), "resource-1");
        assert_eq!(saga.completed_steps(), 1);

        let r2: Result<(), _> = saga.step("configure", || Ok(()), || "reset config".to_string());
        assert!(r2.is_ok());
        assert_eq!(saga.completed_steps(), 2);

        saga.complete();
        assert_eq!(saga.state(), SagaState::Completed);
        assert!(saga.compensation_results().is_empty());
    }

    #[test]
    fn saga_step_failure_runs_compensations_reverse() {
        use std::sync::Arc;

        let order = Arc::new(Mutex::new(Vec::new()));

        let o1 = Arc::clone(&order);
        let mut saga = Saga::new();

        saga.step(
            "step-0",
            || Ok(()),
            move || {
                o1.lock().push(0);
                "comp-0".to_string()
            },
        )
        .unwrap();

        let o2 = Arc::clone(&order);
        saga.step(
            "step-1",
            || Ok(()),
            move || {
                o2.lock().push(1);
                "comp-1".to_string()
            },
        )
        .unwrap();

        let o3 = Arc::clone(&order);
        // Step 2 fails
        let result: Result<(), SagaStepError> = saga.step(
            "step-2",
            || Err("boom".to_string()),
            move || {
                o3.lock().push(2);
                "comp-2".to_string()
            },
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.step, 2);
        assert!(err.message.contains("boom"));

        // Saga should be aborted
        assert_eq!(saga.state(), SagaState::Aborted);

        // Compensations should have run in reverse: step-1, step-0
        // (step-2 never succeeded, so no compensation for it)
        let comps = saga.compensation_results();
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0].step, 1); // step-1 first (reverse order)
        assert_eq!(comps[1].step, 0); // step-0 second

        // Verify execution order: 1 then 0 (reverse)
        let executed = order.lock().clone();
        assert_eq!(executed, vec![1, 0]);
    }

    #[test]
    fn saga_explicit_abort() {
        use std::sync::Arc;

        let compensated = Arc::new(Mutex::new(Vec::new()));
        let mut saga = Saga::new();

        let c1 = Arc::clone(&compensated);
        saga.step(
            "step-0",
            || Ok(()),
            move || {
                c1.lock().push("step-0");
                "undid step-0".to_string()
            },
        )
        .unwrap();

        let c2 = Arc::clone(&compensated);
        saga.step(
            "step-1",
            || Ok(()),
            move || {
                c2.lock().push("step-1");
                "undid step-1".to_string()
            },
        )
        .unwrap();

        // Explicitly abort (e.g., due to cancellation)
        saga.abort();
        assert_eq!(saga.state(), SagaState::Aborted);

        let comps = saga.compensation_results();
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0].description, "step-1"); // reverse order
        assert_eq!(comps[1].description, "step-0");

        let executed = compensated.lock().clone();
        assert_eq!(executed, vec!["step-1", "step-0"]);
    }

    #[test]
    fn saga_first_step_failure_no_compensations() {
        let mut saga = Saga::new();

        // First step fails — nothing to compensate
        let result: Result<(), _> = saga.step("fail-step", || Err("bad".to_string()), String::new);
        assert!(result.is_err());
        assert_eq!(saga.state(), SagaState::Aborted);
        assert!(saga.compensation_results().is_empty());
    }

    #[test]
    fn saga_drop_during_unwind_skips_compensation_side_effects() {
        use std::panic::{self, AssertUnwindSafe};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let compensated = Arc::new(AtomicBool::new(false));
        let compensation_ran = Arc::clone(&compensated);

        let unwind = panic::catch_unwind(AssertUnwindSafe(move || {
            let mut saga = Saga::new();
            saga.step(
                "step-0",
                || Ok(()),
                move || {
                    compensation_ran.store(true, Ordering::SeqCst);
                    "comp-0".to_string()
                },
            )
            .unwrap();

            panic!("outer panic");
        }));

        assert!(unwind.is_err());
        assert!(
            !compensated.load(Ordering::SeqCst),
            "drop during unwind must not run compensation closures"
        );
    }

    #[test]
    fn saga_drop_during_unwind_with_panicking_compensation_preserves_process() {
        const CHILD_ENV: &str = "ASUPERSYNC_SAGA_UNWIND_CHILD";
        const TEST_NAME: &str =
            "remote::tests::saga_drop_during_unwind_with_panicking_compensation_preserves_process";

        if std::env::var_os(CHILD_ENV).is_some() {
            let mut saga = Saga::new();
            saga.step(
                "step-0",
                || Ok(()),
                || -> String { panic!("compensation panic during unwind") },
            )
            .unwrap();

            panic!("outer panic");
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .output()
            .expect("spawn child test binary");

        assert_eq!(
            output.status.code(),
            Some(101),
            "child should fail from the original panic without aborting the process: {:?}",
            output.status
        );
    }

    #[test]
    fn saga_state_display() {
        assert_eq!(format!("{}", SagaState::Running), "Running");
        assert_eq!(format!("{}", SagaState::Completed), "Completed");
        assert_eq!(format!("{}", SagaState::Compensating), "Compensating");
        assert_eq!(format!("{}", SagaState::Aborted), "Aborted");
    }

    #[test]
    fn saga_step_error_display() {
        let err = SagaStepError {
            step: 3,
            description: "deploy".to_string(),
            message: "timeout".to_string(),
        };
        let text = format!("{err}");
        assert!(text.contains('3'));
        assert!(text.contains("deploy"));
        assert!(text.contains("timeout"));
    }

    #[test]
    fn saga_debug() {
        let saga = Saga::new();
        let debug = format!("{saga:?}");
        assert!(debug.contains("Saga"));
        assert!(debug.contains("Running"));
    }

    #[test]
    fn saga_default_trait() {
        let saga = Saga::default();
        assert_eq!(saga.state(), SagaState::Running);
    }

    // -----------------------------------------------------------------------
    // Invariant tests — lease boundary conditions (B6: asupersync-3narc.2.6)
    // -----------------------------------------------------------------------

    /// Invariant: renewing a lease at exactly `now == expires_at` must fail
    /// with `LeaseError::Expired`, because `is_expired` uses `>=`.
    #[test]
    fn lease_renew_at_exact_expiry_boundary_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );
        // expires_at == 40; renew at exactly 40
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(40));
        assert_eq!(result, Err(LeaseError::Expired));
        assert_eq!(lease.state(), LeaseState::Expired);
        // Once expired by renew, subsequent renew must also fail
        let result2 = lease.renew(Duration::from_secs(30), Time::from_secs(35));
        assert_eq!(result2, Err(LeaseError::Expired));
    }

    /// Invariant: releasing a lease at or after `expires_at` must fail with
    /// `LeaseError::Expired` and transition the lease into `Expired`.
    #[test]
    fn lease_release_at_exact_expiry_boundary_fails() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );

        let result = lease.release(Time::from_secs(40));
        assert_eq!(result, Err(LeaseError::Expired));
        assert_eq!(lease.state(), LeaseState::Expired);
        assert!(lease.is_expired(Time::from_secs(40)));
        assert!(!lease.is_released());
    }

    /// Invariant: a zero-duration lease is immediately expired at its creation time,
    /// since `expires_at = now + Duration::ZERO = now` and `is_expired` uses `>=`.
    #[test]
    fn lease_zero_duration_immediately_expired() {
        let now = Time::from_secs(100);
        let lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::ZERO,
            now,
        );
        assert!(
            lease.is_expired(now),
            "zero-duration lease must be expired at creation time"
        );
        assert!(
            !lease.is_active(now),
            "zero-duration lease must not be active at creation time"
        );
        assert_eq!(lease.remaining(now), Duration::ZERO);
    }

    /// Invariant: `is_active` and `is_expired` are complementary for Active-state leases.
    /// For any time `t`, exactly one of `is_active(t)` or `is_expired(t)` is true
    /// when the lease state is Active.
    #[test]
    fn lease_active_and_expired_are_complementary() {
        let now = Time::from_secs(10);
        let lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );
        // Test several time points: before, at, and after expiry
        for t in [0, 5, 10, 20, 39, 40, 41, 100] {
            let time = Time::from_secs(t);
            let active = lease.is_active(time);
            let expired = lease.is_expired(time);
            assert!(
                active != expired,
                "at t={t}: is_active={active}, is_expired={expired} — must be complementary"
            );
        }
    }

    /// Invariant: releasing then trying to renew gives Released, not Expired.
    /// The state transition Release takes precedence in error reporting.
    #[test]
    fn lease_release_then_renew_gives_released_error() {
        let now = Time::from_secs(10);
        let mut lease = Lease::new(
            test_obligation_id(),
            test_region_id(),
            test_task_id(),
            Duration::from_secs(30),
            now,
        );
        lease.release(Time::from_secs(15)).unwrap();
        let result = lease.renew(Duration::from_secs(30), Time::from_secs(15));
        assert_eq!(result, Err(LeaseError::Released));
    }

    // -----------------------------------------------------------------------
    // Invariant tests — idempotency store (B6: asupersync-3narc.2.6)
    // -----------------------------------------------------------------------

    /// Invariant: eviction removes completed entries too, not just pending ones.
    /// Completion status does not exempt an entry from TTL-based eviction.
    #[test]
    fn idempotency_store_evicts_completed_entries_on_ttl() {
        let mut store = IdempotencyStore::new(Duration::from_secs(60));
        let key = IdempotencyKey::from_raw(1);
        let request = test_request_fingerprint("work");
        let task_id = RemoteTaskId::next();

        // Record at t=10, then complete at t=20 (expires at t=80).
        store.record(key, task_id, request.clone(), Time::from_secs(10));
        // Complete with success
        store.complete(
            &key,
            task_id,
            RemoteOutcome::Success(vec![42]),
            Time::from_secs(20),
        );
        assert_eq!(store.len(), 1);

        // Evict at t=80 — should remove the completed entry
        let evicted = store.evict_expired(Time::from_secs(80));
        assert_eq!(evicted, 1);
        assert!(store.is_empty());

        // Re-check: the key should be New again
        let decision = store.check(&key, &request, Time::from_secs(80));
        assert!(matches!(decision, DedupDecision::New));
    }

    /// Invariant: checking a completed entry with a Failed outcome still returns
    /// Duplicate (not New), and the cached outcome is available.
    #[test]
    fn idempotency_store_check_after_failed_returns_duplicate_with_outcome() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(77);
        let request = test_request_fingerprint("fragile_op");
        let task_id = RemoteTaskId::next();

        store.record(key, task_id, request.clone(), Time::from_secs(10));
        store.complete(
            &key,
            task_id,
            RemoteOutcome::Failed("disk full".into()),
            Time::from_secs(15),
        );

        let decision = store.check(&key, &request, Time::from_secs(20));
        assert!(
            matches!(
                decision,
                DedupDecision::Duplicate(record)
                    if record.outcome.as_ref().is_some_and(|outcome| {
                        !outcome.is_success()
                            && matches!(
                                outcome,
                                RemoteOutcome::Failed(msg) if msg.contains("disk full")
                            )
                    })
            ),
            "expected Duplicate with failed outcome recorded"
        );
    }

    /// Invariant: completing the same key twice overwrites the outcome.
    /// The last `complete()` call wins.
    #[test]
    fn idempotency_store_complete_overwrites_outcome() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(88);
        let request = test_request_fingerprint("retry_op");
        let task_id = RemoteTaskId::next();

        store.record(key, task_id, request.clone(), Time::from_secs(10));

        // First complete: Failed
        store.complete(
            &key,
            task_id,
            RemoteOutcome::Failed("transient".into()),
            Time::from_secs(15),
        );
        // Second complete: Success (overwrites)
        store.complete(
            &key,
            task_id,
            RemoteOutcome::Success(vec![1, 2, 3]),
            Time::from_secs(18),
        );

        let decision = store.check(&key, &request, Time::from_secs(20));
        assert!(
            matches!(
                decision,
                DedupDecision::Duplicate(record)
                    if record
                        .outcome
                        .as_ref()
                        .is_some_and(RemoteOutcome::is_success)
            ),
            "expected Duplicate with the latest successful outcome"
        );
    }

    #[test]
    fn idempotency_store_same_computation_different_input_conflicts() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(0xfeed);
        let base = IdempotencyRequestFingerprint::new(
            ComputationName::new("encode"),
            RemoteInput::new(vec![1, 2, 3]),
        );
        let mut changed_input = base.clone();
        changed_input.input = RemoteInput::new(vec![9, 9, 9]);

        store.record(key, RemoteTaskId::next(), base, Time::from_secs(10));

        let decision = store.check(&key, &changed_input, Time::from_secs(20));
        assert!(
            matches!(decision, DedupDecision::Conflict),
            "same key + same computation but different payload must conflict"
        );
    }

    #[test]
    fn idempotency_store_retry_metadata_does_not_trigger_conflict() {
        let mut store = IdempotencyStore::new(Duration::from_secs(300));
        let key = IdempotencyKey::from_raw(0xbeef);
        let base = SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(7),
            computation: ComputationName::new("encode"),
            input: RemoteInput::new(vec![1, 2, 3]),
            lease: Duration::from_secs(30),
            idempotency_key: key,
            budget: Some(Budget::MINIMAL),
            origin_node: NodeId::new("origin-a"),
            origin_region: RegionId::new_for_test(1, 1),
            origin_task: TaskId::new_for_test(1, 1),
        };
        let retry = SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(99),
            lease: Duration::from_secs(120),
            budget: Some(Budget::INFINITE),
            origin_node: NodeId::new("origin-b"),
            origin_region: RegionId::new_for_test(2, 2),
            origin_task: TaskId::new_for_test(2, 2),
            ..base.clone()
        };

        let recorded = IdempotencyRequestFingerprint::from_spawn_request(&base);
        assert!(store.record(
            key,
            base.remote_task_id,
            recorded.clone(),
            Time::from_secs(10),
        ));

        let decision = store.check(
            &key,
            &IdempotencyRequestFingerprint::from_spawn_request(&retry),
            Time::from_secs(20),
        );
        assert!(
            matches!(decision, DedupDecision::Duplicate(record) if record.request == recorded),
            "retries must deduplicate on logical operation, not lease/budget/origin metadata"
        );
    }

    // -----------------------------------------------------------------------
    // Invariant tests — saga (B6: asupersync-3narc.2.6)
    // -----------------------------------------------------------------------

    /// Invariant: calling `step()` after `complete()` must panic.
    /// A completed saga must not accept new steps.
    #[test]
    #[should_panic(expected = "not Running")]
    fn saga_step_after_complete_panics() {
        let mut saga = Saga::new();
        saga.step("step-0", || Ok(()), || "comp-0".to_string())
            .unwrap();
        saga.complete();
        assert_eq!(saga.state(), SagaState::Completed);

        // This must panic
        let _: Result<(), _> = saga.step("step-1", || Ok(()), || "comp-1".to_string());
    }

    /// Invariant: calling `step()` after `abort()` must panic.
    /// An aborted saga must not accept new steps.
    #[test]
    #[should_panic(expected = "not Running")]
    fn saga_step_after_abort_panics() {
        let mut saga = Saga::new();
        saga.step("step-0", || Ok(()), || "comp-0".to_string())
            .unwrap();
        saga.abort();
        assert_eq!(saga.state(), SagaState::Aborted);

        // This must panic
        let _: Result<(), _> = saga.step("step-1", || Ok(()), || "comp-1".to_string());
    }

    /// Invariant: calling `complete()` after `abort()` must panic.
    #[test]
    #[should_panic(expected = "Running")]
    fn saga_complete_after_abort_panics() {
        let mut saga = Saga::new();
        saga.step("step-0", || Ok(()), || "comp-0".to_string())
            .unwrap();
        saga.abort();
        saga.complete(); // must panic
    }

    /// Invariant: calling `abort()` after `complete()` must panic.
    #[test]
    #[should_panic(expected = "Running")]
    fn saga_abort_after_complete_panics() {
        let mut saga = Saga::new();
        saga.step("step-0", || Ok(()), || "comp-0".to_string())
            .unwrap();
        saga.complete();
        saga.abort(); // must panic
    }

    /// Invariant: an empty saga can be completed without any steps.
    #[test]
    fn saga_empty_complete_is_valid() {
        let mut saga = Saga::new();
        assert_eq!(saga.completed_steps(), 0);
        saga.complete();
        assert_eq!(saga.state(), SagaState::Completed);
        assert!(saga.compensation_results().is_empty());
    }

    /// Invariant: an empty saga can be aborted (no compensations to run).
    #[test]
    fn saga_empty_abort_is_valid() {
        let mut saga = Saga::new();
        saga.abort();
        assert_eq!(saga.state(), SagaState::Aborted);
        assert!(saga.compensation_results().is_empty());
    }

    // --- wave 75 trait coverage ---

    #[test]
    fn remote_task_id_debug_clone_copy_eq_ord_hash() {
        use std::collections::HashSet;
        let a = RemoteTaskId::from_raw(42);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, RemoteTaskId::from_raw(99));
        assert!(a < RemoteTaskId::from_raw(100));
        let dbg = format!("{a:?}");
        assert!(dbg.contains("42"));
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn idempotency_key_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let k = IdempotencyKey::from_raw(12345);
        let k2 = k; // Copy
        let k3 = k;
        assert_eq!(k, k2);
        assert_eq!(k, k3);
        assert_ne!(k, IdempotencyKey::from_raw(99999));
        let dbg = format!("{k:?}");
        assert!(dbg.contains("12345"));
        let mut set = HashSet::new();
        set.insert(k);
        assert!(set.contains(&k2));
    }

    #[test]
    fn lease_state_debug_clone_copy_eq() {
        let s = LeaseState::Active;
        let s2 = s; // Copy
        let s3 = s;
        assert_eq!(s, s2);
        assert_eq!(s, s3);
        assert_ne!(s, LeaseState::Released);
        assert_ne!(s, LeaseState::Expired);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Active"));
    }

    #[test]
    fn saga_state_debug_clone_copy_eq() {
        let s = SagaState::Running;
        let s2 = s; // Copy
        let s3 = s;
        assert_eq!(s, s2);
        assert_eq!(s, s3);
        assert_ne!(s, SagaState::Completed);
        assert_ne!(s, SagaState::Compensating);
        assert_ne!(s, SagaState::Aborted);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Running"));
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn remote_task_state_debug_clone_eq() {
        let s = RemoteTaskState::Pending;
        let s2 = s.clone();
        assert_eq!(s, s2);
        assert_ne!(s, RemoteTaskState::Running);
        assert_ne!(s, RemoteTaskState::Completed);
        assert_ne!(s, RemoteTaskState::Failed);
        assert_ne!(s, RemoteTaskState::Cancelled);
        assert_ne!(s, RemoteTaskState::LeaseExpired);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Pending"));
    }

    #[test]
    fn remote_error_debug_clone_eq() {
        let e = RemoteError::NoCapability;
        let e2 = e.clone();
        assert_eq!(e, e2);
        assert_ne!(e, RemoteError::LeaseExpired);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("NoCapability"));
    }

    /// asupersync-bi2462.77: a second drain request reached a driver whose
    /// graceful Cancel exchange was in flight and cancelled its Cx. The
    /// server's Cancelled outcome was then lost to a local `Err(Cancelled)`.
    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[test]
    fn native_cancel_request_interrupts_renewal_but_not_graceful_cancel_exchange() {
        let shared = NativeRemoteShared {
            max_in_flight: 4,
            drain_timeout: Duration::from_secs(1),
            automatic_lease_renewal: false,
            state: Mutex::new(NativeRemoteState::new()),
            retirement_notify: None,
        };
        for (raw, cancel_exchange) in [(1_u64, true), (2, false)] {
            let task_id = RemoteTaskId::from_raw(raw);
            let (result, _result_rx) = oneshot::channel();
            shared.register(task_id, result);
            let _wake = shared.admit(task_id).unwrap();
            let driver_cx = Cx::for_testing();
            shared.attach_driver_cx(task_id, driver_cx.clone());
            shared.set_running(task_id);
            let control = shared.control(task_id).unwrap();

            if cancel_exchange {
                shared
                    .request_cancel(task_id, CancelReason::shutdown())
                    .unwrap();
                assert!(!driver_cx.is_cancel_requested());
                assert!(shared.begin_control_exchange(task_id, &control).is_some());
                shared
                    .request_cancel(task_id, CancelReason::shutdown())
                    .unwrap();
                assert!(
                    !driver_cx.is_cancel_requested(),
                    "a repeated drain must not interrupt the graceful Cancel exchange"
                );
            } else {
                assert!(shared.begin_control_exchange(task_id, &control).is_none());
                shared
                    .request_cancel(task_id, CancelReason::shutdown())
                    .unwrap();
                assert!(
                    driver_cx.is_cancel_requested(),
                    "a cancellation racing a renewal still wakes the driver"
                );
            }
        }
    }

    /// A V3 peer that replays scripted event frames and discards the client's
    /// writes.
    #[cfg(feature = "tls")]
    struct ScriptedV3Peer {
        frames: std::io::Cursor<Vec<u8>>,
    }

    #[cfg(feature = "tls")]
    impl ScriptedV3Peer {
        fn new(events: &[RemoteServiceSessionEvent]) -> Self {
            let mut frames = Vec::new();
            for event in events {
                let body = serde_json::to_vec(event).expect("scripted event should encode");
                let len = u32::try_from(body.len()).expect("scripted frame length fits u32");
                frames.extend_from_slice(&len.to_be_bytes());
                frames.extend_from_slice(&body);
            }
            Self {
                frames: std::io::Cursor::new(frames),
            }
        }
    }

    #[cfg(feature = "tls")]
    impl AsyncRead for ScriptedV3Peer {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.frames).poll_read(cx, buf)
        }
    }

    #[cfg(feature = "tls")]
    impl AsyncWrite for ScriptedV3Peer {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Starts a V3 session against a scripted peer and renews for `requested`;
    /// the peer acknowledges the renewal with `granted`.
    #[cfg(feature = "tls")]
    fn renew_against_a_peer_granting(
        requested: Duration,
        granted: Duration,
    ) -> Result<RemoteServiceSessionEvent, RemoteServiceSessionError> {
        const TASK: u64 = 0x27c;
        let hello = RemotePeerAdmissionPolicy::new(
            RemoteProtocolVersion::V3,
            ComputationSchemaRegistry::new(),
        )
        .hello_for(NodeId::new("r27c-origin"));
        let cx = Cx::for_testing();
        let request = RemoteServiceWireRequest::from_spawn_request(
            hello.clone(),
            &SpawnRequest {
                remote_task_id: RemoteTaskId::from_raw(TASK),
                computation: ComputationName::new("proof.r27c"),
                input: RemoteInput::new(Vec::new()),
                lease: requested,
                idempotency_key: IdempotencyKey::from_raw(0x27c),
                budget: None,
                origin_node: hello.peer_node().clone(),
                origin_region: cx.region_id(),
                origin_task: cx.task_id(),
            },
        )
        .expect("the request identity should agree with its hello");
        let peer = ScriptedV3Peer::new(&[
            RemoteServiceSessionEvent::Accepted {
                remote_task_id: TASK,
            },
            RemoteServiceSessionEvent::LeaseRenewed {
                remote_task_id: TASK,
                renewal_id: 1,
                lease_secs: granted.as_secs(),
                lease_subsec_nanos: granted.subsec_nanos(),
            },
        ]);
        let start = crate::util::future::block_on(RemoteComputationSession::start(
            &cx,
            peer,
            &request,
            RemoteServiceWireLimits::default(),
        ))
        .expect("the scripted peer accepts the session");
        let RemoteComputationSessionStart::Running(mut session) = start else {
            panic!("the scripted peer accepted, so the session is running");
        };
        crate::util::future::block_on(session.renew_lease(&cx, requested))
    }

    #[cfg(feature = "tls")]
    #[test]
    fn renewal_accepts_a_capped_grant_and_rejects_a_zero_or_longer_one() {
        // R27c: a server may cap a renewal (its enforced cap is 24 h), so the
        // client accepts any non-zero grant no longer than it asked for and
        // returns it. A zero or a longer grant is a protocol violation.
        let requested = Duration::from_secs(48 * 3600);
        for granted in [requested, Duration::from_secs(86_400)] {
            let event = renew_against_a_peer_granting(requested, granted)
                .expect("an equal or capped grant is accepted");
            assert!(matches!(
                event,
                RemoteServiceSessionEvent::LeaseRenewed { lease_secs, lease_subsec_nanos, .. }
                    if Duration::new(lease_secs, lease_subsec_nanos) == granted
            ));
        }
        for granted in [Duration::ZERO, requested + Duration::from_nanos(1)] {
            assert!(matches!(
                renew_against_a_peer_granting(requested, granted),
                Err(RemoteServiceSessionError::RenewalLeaseMismatch { expected, actual })
                    if expected == requested && actual == granted
            ));
        }
    }
