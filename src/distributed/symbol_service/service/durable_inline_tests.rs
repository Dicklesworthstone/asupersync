    use super::*;

    #[test]
    fn one_registration_refuses_saturation_and_reuses_only_released_credit() {
        let gate = Arc::new(AtomicBool::new(false));
        let handle = DurableSymbolServiceHandle(Arc::clone(&gate));
        let credit = Credit::acquire(&gate).unwrap();
        assert!(handle.in_flight());
        assert!(Credit::acquire(&gate).is_none());
        drop(credit);
        assert!(!handle.in_flight());
        assert!(Credit::acquire(&gate).is_some());
    }

    #[test]
    fn unwinding_releases_owned_service_admission() {
        let gate = Arc::new(AtomicBool::new(false));
        let result = std::panic::catch_unwind(|| {
            let _credit = Credit::acquire(&gate).unwrap();
            panic!("worker sentinel");
        });
        assert!(result.is_err());
        assert!(!gate.load(Ordering::Acquire));
    }

    #[cfg(unix)]
    mod native {
        use super::*;
        use crate::distributed::symbol_service::durable::DurableSymbolLimits;
        use crate::distributed::remote_owned::{
            RemoteAdmissionLimits, RemoteAdmissionUsage, RemotePeerLimits, RemoteQueueLimits,
            RemoteQueueUsage,
        };
        use crate::distributed::symbol_service::service::{
            fetch_request, put_request, validate_receipt,
        };
        use crate::distributed::symbol_service::{
            EncodedSymbolBatch, SymbolBatchLimits, SymbolStoreLimits, encode_symbol_batch,
        };
        use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
        use crate::remote::{
            ComputationName, IdempotencyKey, RemoteComputationDispatchError, RemoteInput,
            RemotePeerAdmissionPolicy, RemoteProtocolVersion, RemoteTaskId, SpawnRequest,
        };
        use crate::security::{AuthKey, SecurityContext};
        use crate::types::CancelReason;
        use crate::types::symbol::Symbol;
        use std::fs::{File, OpenOptions};
        use std::future::{Future, poll_fn};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        use std::path::PathBuf;
        use crate::sync::atomic::AtomicU64;
        use std::task::Poll;
        use std::time::{Duration, Instant};

        fn limits() -> DurableSymbolLimits {
            DurableSymbolLimits {
                batch: SymbolBatchLimits { max_encoded_bytes: 4096, max_symbols: 8,
                    max_payload_bytes: 2048, max_decoded_bytes: 8192 },
                store: SymbolStoreLimits { max_batches: 1, max_bytes: 4096,
                    max_batches_per_peer: 1, max_bytes_per_peer: 4096 },
                max_journal_bytes: 8192,
            }
        }

        fn linked_store() -> (PathBuf, Arc<DurableSymbolReplicaStore>) {
            linked_store_with_limits(limits())
        }

        fn linked_store_with_limits(bounds: DurableSymbolLimits) -> (PathBuf, Arc<DurableSymbolReplicaStore>) {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let parent = std::env::temp_dir();
            loop {
                let path = parent.join(format!("asupersync-durable-handler-{}-{}",
                    std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
                match OpenOptions::new().create_new(true).read(true).write(true).mode(0o600).open(&path) {
                    Ok(file) => {
                        file.sync_all().unwrap();
                        File::open(&parent).unwrap().sync_all().unwrap();
                        let store = DurableSymbolReplicaStore::create(file, "replica",
                            AuthKey::from_seed(42), AuthKey::from_seed(99), bounds).unwrap();
                        return (path, Arc::new(store));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("linked durable handler fixture: {error}"),
                }
            }
        }

        fn batch() -> EncodedSymbolBatch {
            let security = SecurityContext::new(AuthKey::from_seed(42));
            let symbols = (0..3).map(|esi| security.sign_symbol(
                &Symbol::new_for_test(731, 0, esi, &[esi as u8; 128]),
            )).collect::<Vec<_>>();
            encode_symbol_batch(&symbols, limits().batch).unwrap()
        }

        fn runtime(workers: usize) -> Runtime {
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::multi_thread().worker_threads(workers) };
            builder.blocking_threads(1, 1).build().unwrap()
        }

        fn assert_drained(runtime: &Runtime) {
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert_eq!(report.live_tasks, 0);
            assert_eq!(report.live_regions, 0);
            assert_eq!(report.pending_obligations, 0);
            assert_eq!(report.pending_spawns, 0);
            assert_eq!(report.queued_finalizers, 0);
            assert!(!report.has_pending_obligation_posts);
        }

        struct ReleasePoolWorker(Option<std::sync::mpsc::Sender<()>>);

        impl ReleasePoolWorker {
            fn release(&mut self) {
                if let Some(release) = self.0.take() {
                    let _ = release.send(());
                }
            }
        }

        impl Drop for ReleasePoolWorker {
            fn drop(&mut self) { self.release(); }
        }

        fn service_admission() -> RemoteServiceAdmission {
            RemoteServiceAdmission::new_queued(
                RemoteAdmissionLimits { max_peers: 2, max_in_flight: 1, max_input_bytes: 8192 },
                ["a", "b"].map(|peer| (NodeId::new(peer), RemotePeerLimits {
                    max_in_flight: 1, max_input_bytes: 8192, max_request_bytes: 8192,
                })),
                RemoteQueueLimits { max_waiters: 2, max_input_bytes: 16384,
                    max_waiters_per_peer: 1, max_input_bytes_per_peer: 8192 },
            ).unwrap()
        }

        // Tests the admitted registry and actual native worker seam. Certificate
        // binding is exercised independently by tests/symbol_service_native.rs.
        async fn registered(
            cx: &Cx, registry: &RemoteComputationRegistry, name: &str,
            peer: &str, origin: &str, input: &[u8],
        ) -> Result<RemoteOutcome, RemoteComputationDispatchError> {
            let mut policy = RemotePeerAdmissionPolicy::new(
                RemoteProtocolVersion::V1, registry.schema_registry().clone());
            let peer = NodeId::new(peer);
            policy.grant_peer(peer.clone(), [name]).unwrap();
            let session = policy.admit(&policy.hello_for(peer)).unwrap();
            let task = RemoteTaskId::next();
            registry.dispatch(cx, &session, SpawnRequest {
                remote_task_id: task, computation: ComputationName::new(name),
                input: RemoteInput::new(input.to_vec()), lease: Duration::from_secs(10),
                idempotency_key: IdempotencyKey::from_raw(u128::from(task.raw())), budget: None,
                origin_node: NodeId::new(origin), origin_region: cx.region_id(), origin_task: cx.task_id(),
            }).await
        }

        #[test]
        fn admitted_durable_queue_is_peer_bounded_and_cancellation_releases_only_waiting_credit() {
            for workers in [1, 2] {
                let mut bounds = limits();
                bounds.store.max_batches = 2;
                bounds.store.max_bytes = 8192;
                bounds.max_journal_bytes = 16384;
                let (_path, store) = linked_store_with_limits(bounds);
                let admission = service_admission();
                let mut registry = RemoteComputationRegistry::new();
                let handle = register_durable_symbol_service_with_admission(&mut registry,
                    Arc::clone(&store), &admission, ChildRegionSpec::inherit(),
                    Some(Duration::from_secs(5))).unwrap();
                let mut ordinary = RemoteComputationRegistry::new();
                register_durable_symbol_service(&mut ordinary, Arc::clone(&store)).unwrap();
                assert_eq!(registry.schema_registry().fingerprint(), ordinary.schema_registry().fingerprint());
                let batch = batch();
                let input = put_request("replica", batch.as_ref()).unwrap();
                let runtime = runtime(workers);
                let pool = runtime.blocking_handle().unwrap();
                let (entered, parked) = std::sync::mpsc::channel();
                let (release, hold) = std::sync::mpsc::channel();
                let mut release = ReleasePoolWorker(Some(release));
                let occupying = pool.spawn(move || {
                    entered.send(()).unwrap();
                    hold.recv_timeout(Duration::from_secs(15)).unwrap();
                });
                parked.recv_timeout(Duration::from_secs(5)).expect("real pool worker is occupied");
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    crate::time::timeout(cx.now(), Duration::from_secs(10), async {
                        let oversized = registered(&cx, &registry, SYMBOL_SERVICE_COMPUTATION,
                            "a", "b", &vec![0; 8193]).await.unwrap();
                        assert!(matches!(oversized, RemoteOutcome::Failed(message)
                            if message == "remote service admission refused: remote request payload exceeds its admission limit"));
                        assert!(!handle.in_flight());
                        let start = |peer: &'static str, origin: &'static str| {
                            let registry = registry.clone();
                            let input = input.clone();
                            cx.spawn(move |body| async move {
                                registered(&body, &registry, SYMBOL_SERVICE_COMPUTATION,
                                    peer, origin, &input).await
                            }).unwrap()
                        };
                        let mut first = start("a", "b");
                        while pool.pending_count() != 1 { yield_now().await; }
                        assert!(handle.in_flight());
                        assert!(!first.is_finished());
                        assert_eq!(admission.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: input.len() });
                        assert_eq!(admission.peer_usage(&NodeId::new("a")).unwrap().in_flight, 1);
                        assert_eq!(admission.peer_usage(&NodeId::new("b")).unwrap().in_flight, 0);
                        let mut expiring = RemoteComputationRegistry::new();
                        let expired_handle = register_durable_symbol_service_with_admission(&mut expiring,
                            Arc::clone(&store), &admission, ChildRegionSpec::inherit(),
                            Some(Duration::from_millis(1))).unwrap();
                        let expired = registered(&cx, &expiring, SYMBOL_SERVICE_COMPUTATION,
                            "b", "a", &input).await.unwrap();
                        assert!(matches!(expired, RemoteOutcome::Failed(message)
                            if message == "remote service admission refused: remote reservation deadline reached"));
                        assert!(!expired_handle.in_flight());
                        assert_eq!(admission.queue_usage(), RemoteQueueUsage::default());
                        assert_eq!(pool.pending_count(), 1);
                        let mut cancelled = start("a", "b");
                        while admission.queue_usage().waiters != 1 { yield_now().await; }
                        assert!(!cancelled.is_finished(), "the second request is parked in admission");
                        assert_eq!(pool.pending_count(), 1, "waiting must not submit another disk job");
                        let refused = registered(&cx, &registry, SYMBOL_SERVICE_COMPUTATION,
                            "a", "b", &input).await.unwrap();
                        assert!(matches!(refused, RemoteOutcome::Failed(message)
                            if message == "remote service admission refused: remote wait queue limit reached: peer waiters"));
                        let mut other = start("b", "a");
                        while admission.queue_usage().waiters != 2 { yield_now().await; }
                        assert_eq!(admission.peer_queue_usage(&NodeId::new("b")).unwrap().waiters, 1);
                        assert_eq!(admission.queue_usage().input_bytes, 2 * input.len());
                        let reason = CancelReason::user("cancel queued symbol request");
                        cancelled.abort_with_reason(reason.clone());
                        let outcome = cancelled.join(&cx).await.expect("queued invocation task")
                            .expect("queued registry outcome");
                        assert!(matches!(outcome, RemoteOutcome::Cancelled(actual) if actual == reason));
                        assert_eq!(admission.peer_queue_usage(&NodeId::new("a")).unwrap(), RemoteQueueUsage::default());
                        assert_eq!(admission.queue_usage(), RemoteQueueUsage { waiters: 1, input_bytes: input.len() });
                        assert_eq!(admission.usage().in_flight, 1);
                        assert_eq!(pool.pending_count(), 1);
                        assert_eq!(store.stats().batches, 0);
                        release.release();
                        for task in [&mut first, &mut other] {
                            let outcome = task.join(&cx).await.expect("admitted request task")
                                .expect("admitted registry outcome");
                            let RemoteOutcome::Success(bytes) = outcome else { panic!("admitted PUT must commit"); };
                            validate_receipt(&bytes, "replica", batch.key(), batch.symbol_count()).unwrap();
                        }
                        assert_eq!(store.stats().batches, 2, "both authenticated peers make progress");
                        assert!(!handle.in_flight());
                        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
                        assert_eq!(admission.queue_usage(), RemoteQueueUsage::default());
                        let outcome = registered(&cx, &registry, SYMBOL_SERVICE_COMPUTATION, "b", "a",
                            &fetch_request("replica", batch.key()).unwrap()).await.unwrap();
                        assert!(matches!(outcome, RemoteOutcome::Success(bytes) if bytes == batch.as_ref()));
                        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
                    }).await.expect("native symbol admission queue watchdog");
                });
                assert!(occupying.wait_timeout(Duration::from_secs(1)));
                assert_drained(&runtime);
                assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
            }
        }

        #[test]
        fn dropped_admitted_durable_dispatch_retains_quota_until_real_worker_retirement() {
            for workers in [1, 2] {
                let (_path, store) = linked_store();
                let admission = service_admission();
                let mut registry = RemoteComputationRegistry::new();
                let handle = register_durable_symbol_service_with_admission(&mut registry,
                    Arc::clone(&store), &admission, ChildRegionSpec::inherit(), None).unwrap();
                let batch = batch();
                let input = put_request("replica", batch.as_ref()).unwrap();
                let runtime = runtime(workers);
                let pool = runtime.blocking_handle().unwrap();
                let (entered, parked) = std::sync::mpsc::channel();
                let (release, hold) = std::sync::mpsc::channel();
                let mut release = ReleasePoolWorker(Some(release));
                let occupying = pool.spawn(move || {
                    entered.send(()).unwrap();
                    hold.recv_timeout(Duration::from_secs(15)).unwrap();
                });
                parked.recv_timeout(Duration::from_secs(5)).expect("real pool worker is occupied");
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    crate::time::timeout(cx.now(), Duration::from_secs(10), async {
                        let mut pending = Box::pin(registered(&cx, &registry,
                            SYMBOL_SERVICE_COMPUTATION, "a", "b", &input));
                        poll_fn(|poll_cx| {
                            assert!(pending.as_mut().poll(poll_cx).is_pending());
                            if pool.pending_count() == 1 { Poll::Ready(()) }
                            else { poll_cx.waker().wake_by_ref(); Poll::Pending }
                        }).await;
                        assert!(handle.in_flight());
                        drop(pending);
                        assert_eq!(admission.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: input.len() });
                        assert!(handle.in_flight());
                    }).await.expect("native symbol admission parked-worker watchdog");
                });
                let blocked = runtime.shutdown_drained(Duration::from_millis(20));
                assert_eq!(blocked.outcome, RootDrainOutcome::TimedOut, "{blocked:?}");
                assert!(blocked.live_tasks > 0);
                assert_eq!(admission.usage().in_flight, 1);
                assert!(handle.in_flight());
                assert_eq!(store.stats().batches, 0);
                release.release();
                assert!(occupying.wait_timeout(Duration::from_secs(1)));
                assert_drained(&runtime);
                assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
                assert!(!handle.in_flight());
                assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
                assert_eq!(admission.queue_usage(), RemoteQueueUsage::default());
                assert_eq!(store.stats().batches, 0, "cancelled queued disk work must not execute");
                // The same registered handler and budget remain reusable by a
                // healthy runtime after the cancelled owner has really drained.
                let healthy = self::runtime(workers);
                healthy.block_on(async {
                    let cx = Cx::current().unwrap();
                    let outcome = registered(&cx, &registry, SYMBOL_SERVICE_COMPUTATION,
                        "b", "a", &input).await.unwrap();
                    let RemoteOutcome::Success(bytes) = outcome else { panic!("retired quota must be reusable"); };
                    validate_receipt(&bytes, "replica", batch.key(), batch.symbol_count()).unwrap();
                });
                assert_eq!(store.stats().batches, 1);
                assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
                assert_drained(&healthy);
                assert!(healthy.shutdown_timeout(Duration::from_secs(5)));
            }
        }

        #[test]
        fn admitted_durable_chunked_upload_commits_and_shares_admission_with_whole_frame_fetch() {
            use crate::distributed::symbol_service::{
                DurableChunkedSymbolService, SymbolChunkedLimits,
                register_durable_chunked_symbol_service,
                register_durable_chunked_symbol_service_with_admission,
            };
            use crate::distributed::symbol_service::service::chunked::{
                BEGIN, CHUNK, COMMIT, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
                Upload, read_progress, request, upload_body,
            };
            for workers in [1, 2] {
                let (_path, store) = linked_store();
                let service = Arc::new(DurableChunkedSymbolService::new(Arc::clone(&store),
                    SymbolChunkedLimits::new(128, 1, 4096, 1, 4096, Duration::from_secs(60)).unwrap()));
                let admission = service_admission();
                let mut registry = RemoteComputationRegistry::new();
                register_durable_symbol_service_with_admission(&mut registry, Arc::clone(&store),
                    &admission, ChildRegionSpec::inherit(), Some(Duration::from_secs(5))).unwrap();
                register_durable_chunked_symbol_service_with_admission(&mut registry, Arc::clone(&service),
                    &admission, ChildRegionSpec::inherit(), Some(Duration::from_secs(5))).unwrap();
                let mut ordinary = RemoteComputationRegistry::new();
                register_durable_symbol_service(&mut ordinary, Arc::clone(&store)).unwrap();
                register_durable_chunked_symbol_service(&mut ordinary, Arc::clone(&service)).unwrap();
                assert_eq!(registry.schema_registry().fingerprint(), ordinary.schema_registry().fingerprint());
                let batch = batch();
                let upload = Upload { key: batch.key(), attempt: 77,
                    total: batch.as_ref().len(), count: batch.symbol_count() };
                let begin = request(BEGIN, "replica", &upload_body(upload)).unwrap();
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    crate::time::timeout(cx.now(), Duration::from_secs(10), async {
                        let refused = registered(&cx, &registry, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
                            "unconfigured", "a", &begin).await.unwrap();
                        assert!(matches!(refused, RemoteOutcome::Failed(message)
                            if message == "remote service admission refused: remote admission peer is not configured"));
                        assert!(!service.in_flight());
                        assert_eq!(service.stats().uploads, 0);
                        let outcome = registered(&cx, &registry, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
                            "a", "b", &begin).await.unwrap();
                        let RemoteOutcome::Success(bytes) = outcome else { panic!("admitted BEGIN must stage"); };
                        assert_eq!(read_progress(&bytes, upload).unwrap(), (0, 128));
                        for (index, piece) in batch.as_ref().chunks(128).enumerate() {
                            let mut body = upload_body(upload);
                            body.extend_from_slice(&((index * 128) as u64).to_le_bytes());
                            body.extend_from_slice(piece);
                            let outcome = registered(&cx, &registry, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
                                "a", "b", &request(CHUNK, "replica", &body).unwrap()).await.unwrap();
                            let RemoteOutcome::Success(bytes) = outcome else { panic!("admitted CHUNK must progress"); };
                            assert_eq!(read_progress(&bytes, upload).unwrap().0, index * 128 + piece.len());
                            assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
                        }
                        let outcome = registered(&cx, &registry, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
                            "a", "b", &request(COMMIT, "replica", &upload_body(upload)).unwrap()).await.unwrap();
                        let RemoteOutcome::Success(bytes) = outcome else { panic!("admitted COMMIT must persist"); };
                        validate_receipt(&bytes[8..], "replica", batch.key(), batch.symbol_count()).unwrap();
                        assert_eq!(store.stats().batches, 1);
                        assert_eq!(service.stats().uploads, 0);
                        assert!(!service.in_flight());
                        let fetch = fetch_request("replica", batch.key()).unwrap();
                        let outcome = registered(&cx, &registry, SYMBOL_SERVICE_COMPUTATION,
                            "a", "b", &fetch).await.unwrap();
                        assert!(matches!(outcome, RemoteOutcome::Success(bytes) if bytes == batch.as_ref()));
                        assert!(admission.close_admission());
                        for (name, input) in [(SYMBOL_SERVICE_COMPUTATION, &fetch),
                            (SYMBOL_CHUNKED_SERVICE_COMPUTATION, &begin)] {
                            let outcome = registered(&cx, &registry, name, "a", "b", input).await.unwrap();
                            assert!(matches!(outcome, RemoteOutcome::Failed(message)
                                if message == "remote service admission refused: remote executor admission is closed"));
                        }
                        assert_eq!(store.stats().batches, 1);
                        assert_eq!(service.stats().uploads, 0);
                        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
                        assert_eq!(admission.queue_usage(), RemoteQueueUsage::default());
                    }).await.expect("native admitted durable chunked workflow watchdog");
                });
                assert_drained(&runtime);
                assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
            }
        }

        #[test]
        #[allow(clippy::too_many_lines)]
        fn spawned_whole_frame_put_and_get_preserve_completed_results_after_cancellation() {
            // p2gmw0 L2: the local task boundary. Listener lease/V3 cancellation
            // retains its separate policy and does not promise this receipt.
            for workers in [1, 2] {
                for get in [false, true] {
                    let (path, store) = linked_store();
                    let peer = NodeId::new("origin");
                    let batch = batch();
                    if get { store.put(&peer, batch.as_ref()).unwrap(); }
                    let before = store.committed_bytes();
                    let input = if get { fetch_request("replica", batch.key()).unwrap() }
                        else { put_request("replica", batch.as_ref()).unwrap() };
                    let gate = Arc::new(AtomicBool::new(false));
                    let handle = DurableSymbolServiceHandle(Arc::clone(&gate));
                    let runtime = runtime(workers);
                    let pool = runtime.blocking_handle().unwrap();
                    let (entered, parked) = std::sync::mpsc::channel();
                    let (release, hold) = std::sync::mpsc::channel();
                    let mut release = ReleasePoolWorker(Some(release));
                    let occupying = pool.spawn(move || {
                        entered.send(()).unwrap();
                        hold.recv_timeout(Duration::from_secs(15)).unwrap();
                    });
                    parked.recv_timeout(Duration::from_secs(5))
                        .expect("real blocking worker is occupied");

                    runtime.block_on(async {
                        let cx = Cx::current().unwrap();
                        let workflow = async {
                            let task_store = Arc::clone(&store);
                            let task_gate = Arc::clone(&gate);
                            let task_peer = peer.clone();
                            let (parked, mut parked_rx) = crate::channel::oneshot::channel();
                            let (resume, mut resume_rx) = crate::channel::oneshot::channel();
                            let mut task = cx.spawn(move |body| async move {
                                let mut handler = Box::pin(dispatch(&body, task_store,
                                    task_gate, &task_peer, &input));
                                let mut parked = Some(parked);
                                let mut resumed = false;
                                poll_fn(|poll_cx| {
                                    // Pause the real caller after its first
                                    // Pending, so worker completion cannot let
                                    // the ordinary task publish before abort.
                                    if parked.is_none() && !resumed {
                                        match resume_rx.poll_recv_uninterruptible(poll_cx) {
                                            Poll::Pending => return Poll::Pending,
                                            Poll::Ready(result) => {
                                                result.unwrap();
                                                resumed = true;
                                            }
                                        }
                                    }
                                    let poll = handler.as_mut().poll(poll_cx);
                                    if poll.is_pending() && let Some(parked) = parked.take() {
                                        parked.send_blocking(body.clone()).unwrap();
                                    }
                                    // No checkpoint in this witness: the
                                    // dispatch boundary must acknowledge it.
                                    poll
                                }).await
                            }).unwrap();
                            let body: Cx = parked_rx.recv(&cx).await.unwrap();
                            while pool.pending_count() != 1 { yield_now().await; }
                            assert!(handle.in_flight());
                            assert!(!task.is_finished());
                            release.release();
                            while handle.in_flight() { yield_now().await; }
                            assert_eq!(store.stats().batches, 1);
                            assert!(!task.is_finished(), "the caller still owns its parked handler");
                            task.abort_with_reason(CancelReason::user("late whole-frame receipt"));
                            // Abort may be published by a later scheduler
                            // turn. Observation does not acknowledge it.
                            body.cancelled().await;
                            assert!(body.is_cancel_requested());
                            resume.send(&cx, ()).unwrap();
                            let outcome = task.join(&cx).await
                                .expect("ordinary task completion must retain the durable result");
                            let RemoteOutcome::Success(bytes) = outcome else {
                                panic!("completed PUT/GET must preserve its exact terminal outcome");
                            };
                            if get {
                                assert_eq!(bytes, batch.as_ref());
                            } else {
                                validate_receipt(&bytes, "replica", batch.key(), batch.symbol_count()).unwrap();
                            }
                            assert!(!handle.in_flight());
                        };
                        crate::time::timeout(cx.now(), Duration::from_secs(10), workflow)
                            .await.expect("spawned whole-frame cancellation workflow");
                    });
                    assert!(occupying.wait_timeout(Duration::from_secs(1)));
                    assert_eq!(std::fs::metadata(&path).unwrap().len(), store.committed_bytes());
                    if get { assert_eq!(store.committed_bytes(), before); }
                    else { assert!(store.committed_bytes() > before); }
                    assert_drained(&runtime);
                    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
                }
            }
        }

        #[test]
        #[allow(clippy::too_many_lines)]
        fn dropped_whole_frame_handler_retains_region_and_journal_until_worker_retirement() {
            for workers in [1, 2] {
                let (path, store) = linked_store();
                let inode = std::fs::metadata(&path).unwrap();
                let before = store.committed_bytes();
                let owner = Arc::downgrade(&store);
                let gate = Arc::new(AtomicBool::new(false));
                let handle = DurableSymbolServiceHandle(Arc::clone(&gate));
                let batch = batch();
                let input = put_request("replica", batch.as_ref()).unwrap();
                let peer = NodeId::new("origin");
                let runtime = runtime(workers);
                let pool = runtime.blocking_handle().unwrap();
                let (entered, parked) = std::sync::mpsc::channel();
                let (release, hold) = std::sync::mpsc::channel();
                let occupying = runtime.spawn_blocking(move || {
                    entered.send(()).unwrap();
                    hold.recv_timeout(Duration::from_secs(15)).unwrap();
                }).unwrap();
                parked.recv_timeout(Duration::from_secs(5)).expect("real blocking worker is occupied");

                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let mut handler = Box::pin(dispatch(&cx, Arc::clone(&store),
                        Arc::clone(&gate), &peer, &input));
                    poll_fn(|poll_cx| {
                        assert!(handler.as_mut().poll(poll_cx).is_pending());
                        Poll::Ready(())
                    }).await;
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while pool.pending_count() != 1 {
                        assert!(Instant::now() < deadline, "PUT must reach the real pool queue");
                        yield_now().await;
                    }
                    drop(handler); // The registration calls this exact future.
                    assert!(handle.in_flight(), "dropping a handler cannot recycle its job credit");
                    assert_eq!(Arc::strong_count(&store), 2, "the queued job retains the journal");
                    let busy = dispatch(&cx, Arc::clone(&store), Arc::clone(&gate), &peer, &input).await;
                    assert!(matches!(busy, RemoteOutcome::Failed(message)
                        if message == "durable symbol service is busy"));
                    assert_eq!(store.stats().batches, 0);
                });
                drop(store); // Only the cancelled, still-queued job owns this file.
                let report = runtime.shutdown_drained(Duration::from_millis(20));
                assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
                assert!(report.live_tasks > 0, "the queued journal owner must retain its region task");
                assert!(handle.in_flight());
                assert_eq!(owner.strong_count(), 1);
                assert_eq!(std::fs::metadata(&path).unwrap().len(), before);
                let locked = OpenOptions::new().read(true).write(true).open(&path).unwrap();
                assert!(matches!(DurableSymbolReplicaStore::open(locked, "replica",
                    AuthKey::from_seed(42), AuthKey::from_seed(99), limits()),
                    Err(DurableSymbolError::Locked)));

                release.send(()).unwrap();
                assert_drained(&runtime);
                assert!(occupying.wait_timeout(Duration::from_secs(1)));
                assert!(!handle.in_flight());
                assert!(owner.upgrade().is_none(), "retirement must release the last file owner");
                assert_eq!(std::fs::metadata(&path).unwrap().len(), before,
                    "a cancelled queued PUT cannot append or publish a receipt");
                assert!(runtime.shutdown_timeout(Duration::from_secs(5)));

                // The same journal and released admission credit remain usable;
                // shutdown did not execute, repair or replace the cancelled PUT.
                let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
                let store = Arc::new(DurableSymbolReplicaStore::open(file, "replica",
                    AuthKey::from_seed(42), AuthKey::from_seed(99), limits()).unwrap());
                let retry_runtime = self::runtime(workers);
                retry_runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let outcome = dispatch(&cx, Arc::clone(&store), Arc::clone(&gate), &peer, &input).await;
                    let RemoteOutcome::Success(bytes) = outcome else { panic!("explicit retry must commit"); };
                    validate_receipt(&bytes, "replica", batch.key(), batch.symbol_count()).unwrap();
                    assert!(!handle.in_flight());
                    let fetch = fetch_request("replica", batch.key()).unwrap();
                    let outcome = dispatch(&cx, Arc::clone(&store), Arc::clone(&gate), &peer, &fetch).await;
                    let RemoteOutcome::Success(bytes) = outcome else { panic!("committed batch must be fetchable"); };
                    assert_eq!(bytes, batch.as_ref());
                });
                assert_eq!(store.stats().batches, 1);
                assert!(store.committed_bytes() > before);
                let after = std::fs::metadata(&path).unwrap();
                assert_eq!((after.dev(), after.ino()), (inode.dev(), inode.ino()));
                assert_drained(&retry_runtime);
                assert!(retry_runtime.shutdown_timeout(Duration::from_secs(5)));
            }
        }

        #[test]
        fn completed_whole_frame_put_and_get_survive_late_invocation_cancellation() {
            for workers in [1, 2] {
                for get in [false, true] {
                    let (path, store) = linked_store();
                    let gate = Arc::new(AtomicBool::new(false));
                    let handle = DurableSymbolServiceHandle(Arc::clone(&gate));
                    let peer = NodeId::new("origin");
                    let batch = batch();
                    if get { store.put(&peer, batch.as_ref()).unwrap(); }
                    let before = store.committed_bytes();
                    let input = if get { fetch_request("replica", batch.key()).unwrap() }
                        else { put_request("replica", batch.as_ref()).unwrap() };
                    let runtime = runtime(workers);
                    let pool = runtime.blocking_handle().unwrap();
                    let (entered, parked) = std::sync::mpsc::channel();
                    let (release, hold) = std::sync::mpsc::channel();
                    let occupying = runtime.spawn_blocking(move || {
                        entered.send(()).unwrap();
                        hold.recv_timeout(Duration::from_secs(15)).unwrap();
                    }).unwrap();
                    parked.recv_timeout(Duration::from_secs(5)).expect("real blocking worker is occupied");

                    runtime.block_on(async {
                        let cx = Cx::current().unwrap().derive_cancel_scope();
                        let mut handler = Box::pin(dispatch(&cx, Arc::clone(&store),
                            Arc::clone(&gate), &peer, &input));
                        poll_fn(|poll_cx| {
                            assert!(handler.as_mut().poll(poll_cx).is_pending());
                            Poll::Ready(())
                        }).await;
                        let deadline = Instant::now() + Duration::from_secs(5);
                        while pool.pending_count() != 1 {
                            assert!(Instant::now() < deadline, "request must enter the real pool queue");
                            yield_now().await;
                        }
                        assert!(handle.in_flight());
                        release.send(()).unwrap();
                        let deadline = Instant::now() + Duration::from_secs(5);
                        while handle.in_flight() {
                            assert!(Instant::now() < deadline, "the real journal job must finish");
                            yield_now().await;
                        }
                        // The handler has not been polled again: the exact
                        // result exists and its job retired before cancellation.
                        assert_eq!(store.stats().batches, 1);
                        cx.cancel_with_reason(CancelReason::user("late invocation cancellation"));
                        assert!(cx.is_cancel_requested());
                        let outcome = handler.await;
                        let RemoteOutcome::Success(bytes) = outcome else {
                            panic!("a completed durable transaction must retain its terminal result");
                        };
                        if get {
                            assert_eq!(bytes, batch.as_ref());
                        } else {
                            validate_receipt(&bytes, "replica", batch.key(), batch.symbol_count()).unwrap();
                        }
                        assert!(!handle.in_flight());
                    });
                    assert!(occupying.wait_timeout(Duration::from_secs(1)));
                    assert_eq!(std::fs::metadata(path).unwrap().len(), store.committed_bytes());
                    if get { assert_eq!(store.committed_bytes(), before); }
                    else { assert!(store.committed_bytes() > before); }
                    assert_drained(&runtime);
                    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
                }
            }
        }
    }
