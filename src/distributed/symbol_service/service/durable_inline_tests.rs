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
        use crate::distributed::symbol_service::service::{
            fetch_request, put_request, validate_receipt,
        };
        use crate::distributed::symbol_service::{
            EncodedSymbolBatch, SymbolBatchLimits, SymbolStoreLimits, encode_symbol_batch,
        };
        use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
        use crate::security::{AuthKey, SecurityContext};
        use crate::types::CancelReason;
        use crate::types::symbol::Symbol;
        use std::fs::{File, OpenOptions};
        use std::future::{Future, poll_fn};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        use std::path::PathBuf;
        use std::sync::atomic::AtomicU64;
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
                            AuthKey::from_seed(42), AuthKey::from_seed(99), limits()).unwrap();
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
