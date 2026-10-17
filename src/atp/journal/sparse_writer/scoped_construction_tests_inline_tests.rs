    use super::*;
    use crate::atp::journal::CommitPolicy;
    use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
    use crate::channel::oneshot;
    use crate::cx::ChildRegionSpec;
    use crate::runtime::{JoinError, RootDrainOutcome, Runtime, RuntimeBuilder, SpawnError, yield_now};
    use crate::types::CancelKind;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::task::Poll;
    use std::time::{Duration, Instant};

    fn runtime(workers: usize) -> Runtime {
        let builder = if workers == 1 {
            RuntimeBuilder::current_thread()
        } else {
            RuntimeBuilder::new().worker_threads(workers)
        };
        builder.blocking_threads(1, 2).build().unwrap()
    }

    fn drained(runtime: &Runtime) {
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_spawns, 0);
        assert_eq!(report.pending_obligations, 0);
    }

    fn manifest(content: &[u8]) -> (ObjectId, Arc<Manifest>) {
        let object = Object::file(content.to_vec());
        let id = object.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_root(object).unwrap();
        (id, Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap()))
    }

    #[test]
    fn public_constructor_to_publication_runs_on_both_native_schedulers() {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let directory = tempfile::tempdir().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                    for content in [b"".as_slice(), b"abcdefgh".as_slice()] {
                        let (id, manifest) = manifest(content);
                        let destination = directory.path().join(format!("{policy:?}-{}", content.len()));
                        let writer = ScopedSparseWriter::new(
                            &cx, id.clone(), destination.clone(),
                            SparseWriterConfig { enable_preallocation: false, commit_policy: policy, ..SparseWriterConfig::default() },
                        ).await.unwrap().unwrap();
                        assert!(!destination.exists());
                        assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().object_id, id);
                        assert!(writer.writer.lock_state().temp_file.is_none());
                        writer.set_expected_size(&cx, content.len() as u64).await.unwrap().unwrap();
                        if !content.is_empty() {
                            writer.write_chunk(&cx, 4, content[4..].to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                            writer.write_chunk(&cx, 0, content[..4].to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                        }
                        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
                        writer.verify_with_chunk_commitment(&cx, manifest, expected).await.unwrap().unwrap();
                        assert_eq!(writer.commit(&cx).await.unwrap().unwrap(), destination);
                        assert_eq!(std::fs::read(destination).unwrap(), content);
                    }
                }
                // Ordinary path-manager directories are not probe leaks.
                for entry in std::fs::read_dir(directory.path()).unwrap() {
                    assert!(!entry.unwrap().file_name().to_string_lossy().contains("_probe_"));
                }
            });
            drained(&runtime);
        }
    }

    #[test]
    fn unpolled_construction_is_send_and_has_no_effects() {
        fn assert_send<T: Send>(_: &T) {}
        let directory = tempfile::tempdir().unwrap();
        let (id, _) = manifest(b"");
        let cx = Cx::for_testing();
        let create = ScopedSparseWriter::new(&cx, id, directory.path().join("file"), SparseWriterConfig::default());
        assert_send(&create);
        drop(create);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn authority_cancellation_and_missing_runtime_refuse_before_construction() {
        let calls = Arc::new(AtomicUsize::new(0));
        for case in 0..3 {
            let cx = if case == 0 {
                let _restricted = Cx::for_testing().restrict::<crate::cx::NoCaps>().set_current_restricted();
                Cx::current().unwrap()
            } else {
                Cx::for_testing()
            };
            if case == 1 {
                cx.cancel_with(CancelKind::User, Some("before construction"));
            }
            let called = Arc::clone(&calls);
            let result = futures_lite::future::block_on(ScopedSparseWriter::create_with(&cx, move || {
                called.fetch_add(1, Ordering::SeqCst);
                panic!("refused constructor executed")
            }));
            match case {
                0 => assert!(matches!(result, Err(ScopedFsError::CapabilityDenied))),
                1 => assert!(matches!(result, Err(ScopedFsError::Checkpoint(_)))),
                2 => assert!(matches!(result, Err(ScopedFsError::Admission(SpawnError::RuntimeUnavailable)))),
                _ => unreachable!(),
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn constructor_domain_errors_and_worker_panics_remain_distinct() {
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let result = ScopedSparseWriter::create_with(&cx, || {
                Outcome::Err(SparseWriterError::PlatformDetection("probe failed".to_owned()))
            }).await;
            assert!(matches!(result, Ok(Outcome::Err(SparseWriterError::PlatformDetection(message))) if message == "probe failed"));
            let result = ScopedSparseWriter::create_with(&cx, || panic!("constructor panic")).await;
            assert!(matches!(result, Err(ScopedFsError::Join(JoinError::Panicked(_)))));
        });
        drained(&runtime);
    }

    #[cfg(unix)]
    #[test]
    fn real_probe_errors_keep_the_historical_domain_diagnostic() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("missing-parent").join("file");
        let (id, _) = manifest(b"");
        let expected = match SparseWriter::new_blocking(id.clone(), destination.clone(), SparseWriterConfig::default()) {
            Outcome::Err(SparseWriterError::PlatformDetection(error)) => error,
            _ => panic!("missing probe directory must fail"),
        };
        let runtime = runtime(1);
        runtime.block_on(async {
            let result = ScopedSparseWriter::new(&Cx::current().unwrap(), id, destination, SparseWriterConfig::default()).await;
            assert!(matches!(result, Ok(Outcome::Err(SparseWriterError::PlatformDetection(error))) if error == expected));
        });
        drained(&runtime);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn dropping_started_construction_drains_probes_and_destroys_abandoned_writer() {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let directory = tempfile::tempdir().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let child = region.cx();
                let expected_region = region.region_id();
                let caller_thread = std::thread::current().id();
                let (started, mut start) = oneshot::channel();
                let (release, wait) = mpsc::channel();
                let (retained, weak) = mpsc::channel();
                let destination = directory.path().join("file");
                let (id, _) = manifest(b"");
                let mut creating = Box::pin(ScopedSparseWriter::create_with(child, move || {
                    assert_ne!(std::thread::current().id(), caller_thread);
                    let ambient = Cx::current().unwrap();
                    assert_eq!(ambient.region_id(), expected_region);
                    started.send_blocking(ambient).unwrap();
                    wait.recv_timeout(Duration::from_secs(10)).unwrap();
                    let writer = SparseWriter::new_blocking(id, destination, SparseWriterConfig::default()).unwrap();
                    retained.send(Arc::downgrade(&writer.state)).unwrap();
                    Outcome::Ok(writer)
                }));
                poll_fn(|task| {
                    assert!(creating.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                let worker_cx = start.recv(&cx).await.unwrap();
                drop(creating);
                let deadline = Instant::now() + Duration::from_secs(5);
                while !worker_cx.is_cancel_requested() {
                    assert!(Instant::now() < deadline);
                    yield_now().await;
                }
                let mut closing = Box::pin(region.close());
                poll_fn(|task| {
                    assert!(closing.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
                release.send(()).unwrap();
                closing.await.unwrap();
                assert!(weak.try_recv().unwrap().upgrade().is_none(), "abandoned writer outlived region close");
                assert!(!directory.path().join("file").exists());
                // Started construction may create the path manager's directory;
                // dropping its wait is not rollback of those completed effects.
                for entry in std::fs::read_dir(directory.path()).unwrap() {
                    assert!(!entry.unwrap().file_name().to_string_lossy().contains("_probe_"));
                }
            });
            drained(&runtime);
        }
    }
