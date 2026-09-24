use super::*;

#[test]
fn borrowed_preflight_matches_existing_strict_wire_bytes() {
    let cx = Cx::for_testing();
    let registry = ComputationSchemaRegistry::new();
    let hello = RemotePeerHello::new(
        NodeId::new("origin\n\"雪"),
        RemoteProtocolVersion::V3,
        registry.fingerprint(),
    );
    let input = (0_u8..=255).collect::<Vec<_>>();
    let request = SpawnRequest {
        remote_task_id: RemoteTaskId::from_raw(u64::MAX),
        computation: ComputationName::new("escaped\n\"computation"),
        input: RemoteInput::new(input.clone()),
        lease: Duration::new(u64::MAX, 999_999_999),
        idempotency_key: IdempotencyKey::from_raw(u128::MAX),
        budget: Some(cx.budget()),
        origin_node: hello.peer_node().clone(),
        origin_region: cx.region_id(),
        origin_task: cx.task_id(),
    };
    let wire = RemoteServiceWireRequest::from_spawn_request(hello.clone(), &request).unwrap();
    let borrowed = BorrowedRequest {
        hello: &hello,
        remote_task_id: u64::MAX,
        computation: request.computation.as_str(),
        input: &input,
        lease_secs: u64::MAX,
        lease_subsec_nanos: 999_999_999,
        idempotency_key_high: u64::MAX,
        idempotency_key_low: u64::MAX,
        budget: request.budget.map(Into::into),
        origin_region: cx.region_id(),
        origin_task: cx.task_id(),
    };
    let expected = serde_json::to_vec(&wire).unwrap();
    assert_eq!(serde_json::to_vec(&borrowed).unwrap(), expected);
    assert_eq!(
        count_frame(&borrowed, expected.len()).unwrap(),
        expected.len()
    );
    assert!(count_frame(&borrowed, expected.len() - 1).is_err());
    assert!(count_frame(&borrowed, 0).is_err());
    eprintln!(
        "{}",
        serde_json::json!({"bead":"asupersync-bi2462.77", "case":"strict_wire_preflight",
        "encoded_bytes":expected.len(), "exact_limit":"accepted", "one_below":"refused"})
    );
}

#[test]
fn admission_credit_waits_for_every_buffer_owner() {
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let peer = NodeId::new("pinned-test-peer");
        let executor = RemoteExecutor::new_queued(
            RemoteAdmissionLimits {
                max_peers: 1,
                max_in_flight: 1,
                max_input_bytes: 1024,
            },
            [(
                peer.clone(),
                RemotePeerLimits {
                    max_in_flight: 1,
                    max_input_bytes: 1024,
                    max_request_bytes: 1024,
                },
            )],
            RemoteQueueLimits {
                max_waiters: 1,
                max_input_bytes: 1024,
                max_waiters_per_peer: 1,
                max_input_bytes_per_peer: 1024,
            },
        )
        .unwrap();
        let reservation = executor
            .reserve(&cx, &peer, 1024, Duration::from_secs(1))
            .await
            .unwrap();
        let credit = Arc::new(NativeRemoteCredit {
            _reservation: reservation,
        });
        let receiver_owner = Arc::clone(&credit);
        let driver_owner = credit;
        drop(receiver_owner);
        assert_eq!(
            executor.usage().in_flight,
            1,
            "dropping a live handle cannot release its driver's credit"
        );
        drop(driver_owner);
        assert_eq!(executor.usage().in_flight, 0);
        assert_eq!(executor.usage().input_bytes, 0);

        let credit = Arc::new(NativeRemoteCredit {
            _reservation: executor
                .reserve(&cx, &peer, 1024, Duration::from_secs(1))
                .await
                .unwrap(),
        });
        let unread_result = Arc::clone(&credit);
        drop(credit);
        assert_eq!(
            executor.usage().input_bytes,
            1024,
            "an unread terminal result retains admission"
        );
        drop(unread_result);
        assert_eq!(executor.usage().input_bytes, 0);
    });
}

#[test]
fn discarded_factory_and_unpolled_driver_retire_native_admission() {
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let peer = NodeId::new("peer");
        let executor = RemoteExecutor::new_queued(
            RemoteAdmissionLimits { max_peers: 1, max_in_flight: 1, max_input_bytes: 1024 },
            [(peer.clone(), RemotePeerLimits { max_in_flight: 1, max_input_bytes: 1024, max_request_bytes: 1024 })],
            RemoteQueueLimits { max_waiters: 1, max_input_bytes: 1024, max_waiters_per_peer: 1, max_input_bytes_per_peer: 1024 },
        ).unwrap();
        let cert = crate::tls::Certificate::from_pem(include_bytes!("../../../tests/fixtures/tls/server.crt")).unwrap().remove(0);
        let client = RemoteComputationClient::new("127.0.0.1:1".parse().unwrap(), "localhost",
            crate::tls::TlsConnectorBuilder::new().add_root_certificate(&cert).build().unwrap(),
            RemoteComputationClientConfig::new()).unwrap();
        for construct_future in [false, true] {
            let shared = Arc::new(NativeRemoteShared { max_in_flight: 1, drain_timeout: Duration::from_secs(1),
                automatic_lease_renewal: true, state: Mutex::new(NativeRemoteState::new()), retirement_notify: None });
            let task = RemoteTaskId::next();
            let (sender, mut receiver) = oneshot::channel();
            shared.register(task, sender);
            let control_receiver = shared.admit(task).unwrap();
            let guard = NativeRemoteDriverGuard::new(Arc::clone(&shared), task);
            let registry = ComputationSchemaRegistry::new();
            let request = SpawnRequest { remote_task_id: task, computation: ComputationName::new("echo"),
                input: RemoteInput::new(vec![1, 2, 3]), lease: Duration::from_secs(1), idempotency_key: IdempotencyKey::from_raw(1),
                budget: None, origin_node: NodeId::new("origin"), origin_region: cx.region_id(), origin_task: cx.task_id() };
            let credit = Arc::new(NativeRemoteCredit { _reservation: executor.reserve(&cx, &peer, 1024,
                Duration::from_secs(1)).await.unwrap() });
            let publication = NativeRemotePublishedRequest {
                wire: RemoteServiceWireRequest::from_spawn_request(RemotePeerHello::new(NodeId::new("origin"),
                    RemoteProtocolVersion::V3, registry.fingerprint()), &request).unwrap(),
                client: client.clone(), control: shared.control(task).unwrap(), control_receiver,
                guard, _admission: Some(credit),
            };
            assert_eq!(shared.state.lock().active.len(), 1);
            assert_eq!(executor.usage().in_flight, 1);
            let factory = move || async move { drop(publication); };
            if construct_future { drop(factory()); } else { drop(factory); }
            assert!(shared.state.lock().active.is_empty());
            assert_eq!(executor.usage().in_flight, 0);
            assert!(matches!(receiver.try_recv(), Ok(Err(RemoteError::TransportError(message)))
                if message == "native remote driver ended before terminal publication"));
            assert!(shared.state.lock().tasks[&task].driver_cx.is_none());
            eprintln!("{}", serde_json::json!({"bead":"asupersync-bi2462.77", "case":"unpolled_publication_drop",
                "constructed_future":construct_future, "active":shared.state.lock().active.len(),
                "charged_bytes":executor.usage().input_bytes, "terminal":"TransportError"}));
        }
    });
}
