    use super::*;
    use crate::distributed::ComputationSchemaRegistry;
    use crate::remote::{NodeId, RemoteProtocolVersion};
    use crate::time::{TimerDriver, TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId, Time};
    use crate::util::ArenaIndex;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    fn transport(cx: Cx) -> RemoteSymbolTransport {
        RemoteSymbolTransport {
            cx, hello: RemotePeerHello::new(NodeId::new("origin"), RemoteProtocolVersion::V1,
                ComputationSchemaRegistry::new().fingerprint()),
            routes: Arc::new(BTreeMap::new()), auth_key: Arc::new(AuthKey::from_seed(42)),
            limits: SymbolBatchLimits { max_encoded_bytes: 4096, max_symbols: 16, max_payload_bytes: 2048, max_decoded_bytes: 8192 },
            admission: Arc::new(super::super::admission::Admission::new(1)), chunk_bytes: Some(128),
        }
    }

    fn timed_cx(id: u32, budget: Budget, timer: TimerDriverHandle) -> Cx {
        Cx::new_with_drivers(RegionId::from_arena(ArenaIndex::new(id, 0)),
            TaskId::from_arena(ArenaIndex::new(id, 0)), budget, None, None, None, Some(timer), None)
    }

    fn routed_transport(cx: Cx) -> RemoteSymbolTransport {
        let mut transport = transport(cx);
        let certificate = crate::tls::Certificate::from_pem(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls/server.crt",
        ))).unwrap().remove(0);
        let client = RemoteComputationClient::new(
            "127.0.0.1:9".parse().unwrap(), "localhost",
            crate::tls::TlsConnectorBuilder::new().add_root_certificate(&certificate).build().unwrap(),
            crate::remote::RemoteComputationClientConfig::new(),
        ).unwrap();
        transport.routes = Arc::new(BTreeMap::from([("replica".to_owned(), client)]));
        transport
    }

    fn encoded_upload() -> EncodedSymbolBatch {
        let security = crate::security::SecurityContext::new(AuthKey::from_seed(42));
        let symbol = crate::types::symbol::Symbol::new_for_test(71, 0, 0, b"retained upload bytes");
        encode_symbol_batch(&[security.sign_symbol(&symbol)], transport(Cx::for_testing()).limits).unwrap()
    }

    #[test]
    fn upload_identity_binds_canonical_metadata_without_retaining_payload() {
        let transport = routed_transport(Cx::for_testing());
        let batch = encoded_upload();
        let key = batch.key();
        let length = batch.as_ref().len();
        let identity = transport.chunked_upload_identity("replica", &batch, 17).unwrap();
        drop(batch);
        assert_eq!(identity.origin(), transport.hello.peer_node());
        assert_eq!(identity.replica(), "replica");
        assert_eq!(identity.key(), key);
        assert_eq!(identity.attempt(), 17);
        assert_eq!(identity.encoded_bytes(), length);
        assert_eq!(identity.symbol_count(), 1);
        assert_eq!(identity, identity.clone());
        assert_eq!(transport.in_flight(), 0);
    }

    #[test]
    fn explicit_abort_refuses_wrong_transport_origin_route_and_bounds_before_io() {
        let mut transport = routed_transport(Cx::for_testing());
        let batch = encoded_upload();
        let identity = transport.chunked_upload_identity("replica", &batch, 17).unwrap();
        let poll_abort = |transport: &RemoteSymbolTransport, identity: &SymbolUploadIdentity| {
            let mut operation = Box::pin(transport.abort_symbol_upload(identity));
            operation.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        };
        transport.chunk_bytes = None;
        assert!(matches!(transport.chunked_upload_identity("replica", &batch, 17), Err(RemoteSymbolError::Configuration)));
        assert!(matches!(poll_abort(&transport, &identity), Poll::Ready(Err(RemoteSymbolError::Configuration))));
        transport.chunk_bytes = Some(128);
        let mut foreign = identity.clone();
        foreign.origin = NodeId::new("different-origin");
        assert!(matches!(poll_abort(&transport, &foreign), Poll::Ready(Err(RemoteSymbolError::Configuration))));
        let mut unconfigured = identity.clone();
        unconfigured.replica = "missing".to_owned();
        assert!(matches!(transport.chunked_upload_identity("missing", &batch, 17), Err(RemoteSymbolError::UnknownReplica)));
        assert!(matches!(poll_abort(&transport, &unconfigured), Poll::Ready(Err(RemoteSymbolError::UnknownReplica))));
        transport.limits.max_encoded_bytes = batch.as_ref().len() - 1;
        assert!(matches!(transport.chunked_upload_identity("replica", &batch, 17), Err(RemoteSymbolError::Batch(SymbolStoreError::Limit(_)))));
        assert!(matches!(poll_abort(&transport, &identity), Poll::Ready(Err(RemoteSymbolError::Batch(SymbolStoreError::Limit(_))))));
        transport.limits.max_encoded_bytes = batch.as_ref().len();
        transport.limits.max_symbols = 0;
        assert!(matches!(poll_abort(&transport, &identity), Poll::Ready(Err(RemoteSymbolError::Batch(SymbolStoreError::Limit(_))))));
        assert_eq!(transport.in_flight(), 0);
    }

    #[test]
    fn explicit_abort_honors_cancelled_owner_and_admission_before_io() {
        let owner = Cx::for_testing();
        let mut transport = routed_transport(owner.clone());
        let batch = encoded_upload();
        let identity = transport.chunked_upload_identity("replica", &batch, 17).unwrap();
        transport.admission = Arc::new(super::super::admission::Admission::new(0));
        {
            let mut operation = Box::pin(transport.abort_symbol_upload(&identity));
            assert!(matches!(operation.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(RemoteSymbolError::Admission))));
        }
        owner.set_cancel_requested(true);
        let recreated = transport.chunked_upload_identity("replica", &batch, 17).unwrap();
        assert_eq!(recreated, identity, "describing metadata does not revive the cancelled owner");
        let mut operation = Box::pin(transport.abort_symbol_upload(&identity));
        assert!(matches!(operation.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(RemoteSymbolError::Cancelled))));
        assert_eq!(transport.in_flight(), 0);
    }

    #[test]
    fn explicit_abort_honors_owner_deadline_and_requires_its_timer_before_io() {
        let batch = encoded_upload();
        let missing_timer = routed_transport(Cx::for_testing_with_budget(
            Budget::INFINITE.with_deadline(Time::from_nanos(u64::MAX))));
        let identity = missing_timer.chunked_upload_identity("replica", &batch, 17).unwrap();
        {
            let mut operation = Box::pin(missing_timer.abort_symbol_upload(&identity));
            assert!(matches!(operation.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(RemoteSymbolError::Configuration))));
        }
        assert_eq!(missing_timer.in_flight(), 0);
        let clock = Arc::new(VirtualClock::new());
        clock.advance(100);
        let expired = routed_transport(timed_cx(1,
            Budget::INFINITE.with_deadline(Time::from_nanos(100)),
            TimerDriverHandle::with_virtual_clock(clock)));
        let mut operation = Box::pin(expired.abort_symbol_upload(&identity));
        assert!(matches!(operation.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(RemoteSymbolError::Deadline))));
        assert_eq!(expired.in_flight(), 0);
    }

    #[test]
    fn abort_acknowledgement_requires_exact_identity_and_zero_retained_progress() {
        let batch = encoded_upload();
        let upload = Upload { key: batch.key(), attempt: 17, total: batch.as_ref().len(), count: batch.symbol_count() };
        // Independent existing wire fixture: magic/version, object/digest,
        // attempt/length/count, accepted offset and nonzero chunk limit.
        let mut response = b"ASUPPRG\0".to_vec();
        response.extend_from_slice(&1_u32.to_le_bytes());
        response.extend_from_slice(&upload.key.object_id.as_u128().to_le_bytes());
        response.extend_from_slice(&upload.key.digest);
        response.extend_from_slice(&upload.attempt.to_le_bytes());
        response.extend_from_slice(&(upload.total as u64).to_le_bytes());
        response.extend_from_slice(&upload.count.to_le_bytes());
        response.extend_from_slice(&0_u64.to_le_bytes());
        response.extend_from_slice(&128_u32.to_le_bytes());
        assert_eq!(response.len(), 92);
        assert_eq!(validate_abort_progress(&response, upload), Ok(()));
        for index in [12, 28, 60, 68, 76] {
            let mut wrong = response.clone();
            wrong[index] ^= 1;
            assert_eq!(validate_abort_progress(&wrong, upload), Err(SymbolStoreError::Identity),
                "wrong identity component at byte {index} cannot acknowledge cleanup");
        }
        let mut retained = response.clone();
        retained[80] = 1;
        assert_eq!(validate_abort_progress(&retained, upload), Err(SymbolStoreError::Identity));
        let mut malformed = response.clone();
        malformed[88..92].fill(0);
        assert_eq!(validate_abort_progress(&malformed, upload), Err(SymbolStoreError::Format));
        malformed = response.clone();
        malformed.push(0);
        assert_eq!(validate_abort_progress(&malformed, upload), Err(SymbolStoreError::Format));
        assert_eq!(validate_abort_progress(&response[..91], upload), Err(SymbolStoreError::Format));
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }


    #[test]
    fn explicit_attempt_refuses_whole_batch_transport_before_route_or_admission() {
        let mut transport = transport(Cx::for_testing());
        transport.chunk_bytes = None;
        let mut sending = Box::pin(transport.send_symbols_with_attempt("missing", Vec::new(), 17));
        let result = sending.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(matches!(result, Poll::Ready(Err(RemoteSymbolError::Configuration))));
        assert_eq!(transport.in_flight(), 0);
    }

    #[test]
    fn whole_transfer_timer_and_inner_polls_use_owner_despite_foreign_ambient_clock() {
        let clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(Arc::clone(&clock)));
        let owner = timed_cx(1, Budget::INFINITE.with_deadline(Time::from_nanos(100)),
            TimerDriverHandle::new(Arc::clone(&driver)));
        let foreign_clock = Arc::new(VirtualClock::new());
        foreign_clock.advance(1000);
        let foreign = timed_cx(2, Budget::INFINITE, TimerDriverHandle::with_virtual_clock(foreign_clock));
        let transport = transport(owner.clone());
        let polls = AtomicUsize::new(0);
        let inner = poll_fn(|_| {
            assert_eq!(Cx::current().unwrap().task_id(), owner.task_id());
            polls.fetch_add(1, Ordering::SeqCst);
            Poll::Pending::<Result<(), RemoteSymbolError>>
        });
        let wake = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut task = Context::from_waker(&waker);
        let mut operation = Box::pin(transport.with_owner_deadline(inner));
        let _foreign = Cx::set_current(Some(foreign.clone()));
        assert!(operation.as_mut().poll(&mut task).is_pending(), "foreign clock must not expire the owner");
        assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        clock.advance(100);
        driver.process_timers();
        assert!(wake.0.load(Ordering::SeqCst) > 0, "owner timer must wake the parked operation");
        assert!(matches!(operation.as_mut().poll(&mut task), Poll::Ready(Err(RemoteSymbolError::Deadline))));
        assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
    }

    #[test]
    fn declared_owner_deadline_without_owner_timer_refuses_before_inner_dispatch() {
        let owner = Cx::for_testing_with_budget(Budget::INFINITE.with_deadline(Time::from_nanos(u64::MAX)));
        let transport = transport(owner);
        let dispatched = AtomicBool::new(false);
        let mut operation = Box::pin(transport.with_owner_deadline(async {
            dispatched.store(true, Ordering::SeqCst);
            Ok(())
        }));
        assert!(matches!(operation.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(RemoteSymbolError::Configuration))));
        assert!(!dispatched.load(Ordering::SeqCst));
    }
