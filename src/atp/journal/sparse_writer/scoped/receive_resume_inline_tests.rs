    use super::*;
    use crate::atp::journal::{CommitPolicy, SparseWriterConfig, WriteOptions};
    use crate::atp::manifest::Manifest;
    use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
    use crate::atp::journal::{ScopedReceiveError, ScopedReceiveOptions};
    use crate::io::{AsyncReadExt, ReadBuf};
    use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
    use std::future::{Future, poll_fn};
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    fn runtime(workers: usize) -> Runtime {
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers) };
        builder.blocking_threads(1, 2).build().unwrap()
    }

    fn drained(runtime: &Runtime) {
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_spawns, 0);
        assert_eq!(report.pending_obligations, 0);
    }

    async fn prepared(cx: &Cx, path: PathBuf) -> (ScopedSparseWriter, Arc<Manifest>) {
        prepared_data(cx, path, b"abcdefgh", CommitPolicy::AtomicRename).await
    }

    async fn prepared_data(cx: &Cx, path: PathBuf, data: &[u8], policy: CommitPolicy)
        -> (ScopedSparseWriter, Arc<Manifest>)
    {
        let object = Object::file(data.to_vec());
        let id = object.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_root(object).unwrap();
        let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
        let writer = ScopedSparseWriter::new(cx, id, path, SparseWriterConfig {
            enable_preallocation: false,
            commit_policy: policy,
            ..SparseWriterConfig::default()
        }).await.unwrap().unwrap();
        writer.set_expected_size(cx, data.len() as u64).await.unwrap().unwrap();
        (writer, manifest)
    }

    #[test]
    fn public_offset_rehashes_exact_receipts_on_both_native_schedulers() {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let directory = tempfile::tempdir().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, _) = prepared(&cx, directory.path().join("file")).await;
                assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), 0);
                writer.write_chunk(&cx, 0, b"abcd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), 4);
                writer.write_chunk(&cx, 4, b"efgh".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), 8);
            });
            drained(&runtime);
        }
    }

    #[test]
    fn unreceipted_file_tail_is_not_advertised_as_received() {
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, _) = prepared(&cx, directory.path().join("file")).await;
            writer.write_chunk(&cx, 0, b"abcd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
            let staging = { writer.writer.lock_state().temp_path.clone().unwrap() };
            // Model a failed write that affected storage but returned no receipt.
            cx.scoped_fs().write(staging.clone(), b"abcdjunk".to_vec()).await.unwrap();
            assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), 4);
            assert_eq!(cx.scoped_fs().read(staging).await.unwrap(), b"abcdjunk");
        });
        drained(&runtime);
    }

    #[test]
    fn corrupted_prefix_revokes_prior_verification_and_prevents_commit() {
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("file");
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, destination.clone()).await;
            writer.write_chunk(&cx, 0, b"abcdefgh".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
            writer.verify(&cx, manifest).await.unwrap().unwrap();
            let staging = { writer.writer.lock_state().temp_path.clone().unwrap() };
            cx.scoped_fs().write(staging, b"Abcdefgh".to_vec()).await.unwrap();
            assert!(matches!(writer.checked_receive_offset(&cx).await,
                Ok(Outcome::Err(SparseWriterError::VerificationFailed(reason)))
                    if reason == "receive checkpoint chunk hash mismatch"));
            assert!(matches!(writer.commit(&cx).await, Ok(Outcome::Err(SparseWriterError::NotVerified))));
            assert!(!destination.exists());
        });
        drained(&runtime);
    }

    #[test]
    fn gaps_truncation_and_terminal_writers_cannot_supply_offsets() {
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for case in 0..4 {
                let (writer, manifest) = prepared(&cx, directory.path().join(format!("file-{case}"))).await;
                if case == 0 {
                    writer.write_chunk(&cx, 4, b"efgh".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                } else {
                    writer.write_chunk(&cx, 0, b"abcdefgh".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                }
                if case == 1 {
                    let staging = { writer.writer.lock_state().temp_path.clone().unwrap() };
                    cx.scoped_fs().write(staging, b"abc".to_vec()).await.unwrap();
                } else if case == 2 {
                    writer.verify_and_commit(&cx, manifest).await.unwrap().unwrap();
                } else if case == 3 {
                    writer.cancel(&cx).await.unwrap().unwrap();
                }
                let result = writer.checked_receive_offset(&cx).await.unwrap();
                if case < 2 {
                    assert!(matches!(result, Outcome::Err(SparseWriterError::VerificationFailed(_))));
                } else {
                    assert!(matches!(result, Outcome::Err(SparseWriterError::WriteFailed(_))));
                }
            }
        });
        drained(&runtime);
    }

    #[derive(Default)]
    struct Probe {
        polls: AtomicUsize,
        parked: AtomicBool,
        released: AtomicBool,
        waker: parking_lot::Mutex<Option<Waker>>,
    }

    impl Probe {
        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            let waker = { self.waker.lock().take() };
            if let Some(waker) = waker { waker.wake(); }
        }
    }

    struct Source {
        bytes: Vec<u8>,
        position: usize,
        fragment: usize,
        fail_at: Option<usize>,
        pause_at: Option<usize>,
        probe: Arc<Probe>,
    }

    fn source(bytes: &[u8], fail_at: Option<usize>) -> (Source, Arc<Probe>) {
        let probe = Arc::new(Probe::default());
        (Source { bytes: bytes.to_vec(), position: 0, fragment: 1, fail_at,
            pause_at: None, probe: Arc::clone(&probe) }, probe)
    }

    impl AsyncRead for Source {
        fn poll_read(self: Pin<&mut Self>, task: &mut Context<'_>, buf: &mut ReadBuf<'_>)
            -> Poll<io::Result<()>>
        {
            let this = self.get_mut();
            this.probe.polls.fetch_add(1, Ordering::SeqCst);
            if this.fail_at.is_some_and(|at| this.position >= at) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "disconnect")));
            }
            if this.pause_at.is_some_and(|at| this.position >= at)
                && !this.probe.released.load(Ordering::SeqCst)
            {
                *this.probe.waker.lock() = Some(task.waker().clone());
                this.probe.parked.store(true, Ordering::SeqCst);
                return Poll::Pending;
            }
            let mut n = buf.remaining().min(this.fragment).min(this.bytes.len() - this.position);
            if let Some(at) = this.fail_at { n = n.min(at.saturating_sub(this.position)); }
            if !this.probe.released.load(Ordering::SeqCst) {
                if let Some(at) = this.pause_at { n = n.min(at.saturating_sub(this.position)); }
            }
            buf.put_slice(&this.bytes[this.position..this.position + n]);
            this.position += n;
            Poll::Ready(Ok(()))
        }
    }

    fn options() -> ScopedReceiveOptions {
        ScopedReceiveOptions { max_bytes: 8, max_chunks: 8, chunk_size: 4 }
    }

    async fn reach_pause<R>(session: &mut ScopedReceive<R>, probe: &Probe) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !probe.parked.load(Ordering::SeqCst) {
            poll_fn(|task| {
                assert!(session.poll_wait(task).is_pending());
                Poll::Ready(())
            }).await;
            assert!(std::time::Instant::now() < deadline, "resumed source never parked");
            crate::runtime::yield_now().await;
        }
    }

    #[test]
    fn disconnected_receives_resume_only_the_unaccepted_suffix() {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let directory = tempfile::tempdir().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                    for failure in [0, 2, 4, 6] {
                        let path = directory.path().join(format!("{policy:?}-{failure}"));
                        let (writer, manifest) = prepared_data(&cx, path.clone(), b"abcdefgh", policy).await;
                        let (input, _) = source(b"abcdefgh", Some(failure));
                        let mut first = writer.receive_exact(&cx, input, Arc::clone(&manifest), options()).unwrap();
                        assert!(matches!(first.wait().await, Err(ScopedReceiveError::Source(error))
                            if error.kind() == io::ErrorKind::ConnectionReset));
                        assert!(!path.exists());
                        let offset = writer.checked_receive_offset(&cx).await.unwrap().unwrap();
                        assert_eq!(offset, (failure / 4 * 4) as u64);
                        drop(first);
                        let (input, _) = source(&b"abcdefghNEXT"[offset as usize..], None);
                        let mut resumed = writer.resume_exact_at(&cx, input, manifest, options(), offset).unwrap();
                        assert_eq!(resumed.accepted_bytes(), 0, "unvalidated offsets are not progress");
                        assert_eq!(resumed.wait().await.unwrap().unwrap(), path);
                        assert_eq!(resumed.accepted_bytes(), 8);
                        assert_eq!(cx.scoped_fs().read(path).await.unwrap(), b"abcdefgh");
                        let input = resumed.take_source().unwrap();
                        assert_eq!(input.position, 8 - offset as usize);
                        assert_eq!(&input.bytes[input.position..], b"NEXT");
                    }
                }
            });
            drained(&runtime);
        }
    }

    #[test]
    fn stale_offsets_changed_sizes_corruption_and_quotas_refuse_before_reading() {
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for case in 0..6 {
                let path = directory.path().join(format!("refused-{case}"));
                let (writer, manifest) = prepared(&cx, path.clone()).await;
                writer.write_chunk(&cx, 0, b"ab".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                writer.write_chunk(&cx, 2, b"cd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                let mut offset = writer.checked_receive_offset(&cx).await.unwrap().unwrap();
                let mut limits = options();
                match case {
                    0 => offset = 3,
                    1 => { writer.write_chunk(&cx, 4, vec![b'e'], WriteOptions::default()).await.unwrap().unwrap(); }
                    2 => { writer.set_expected_size(&cx, 9).await.unwrap().unwrap(); }
                    3 => {
                        let staging = { writer.writer.lock_state().temp_path.clone().unwrap() };
                        cx.scoped_fs().write(staging, b"Abcd".to_vec()).await.unwrap();
                    }
                    4 => limits.max_chunks = 2, // Two old receipts plus one suffix chunk need three.
                    5 => limits.max_bytes = 4, // The whole object, not just its suffix, must fit.
                    _ => unreachable!(),
                }
                let (input, probe) = source(b"efghNEXT", None);
                let mut receive = writer.resume_exact_at(&cx, input, manifest, limits, offset).unwrap();
                assert!(matches!(receive.wait().await, Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
                assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                assert_eq!(receive.accepted_bytes(), 0);
                assert!(!path.exists());
            }
        });
        drained(&runtime);
    }

    #[test]
    fn resume_overwrites_unreceipted_tail_and_counts_old_chunks_in_the_limit() {
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let path = directory.path().join("file");
            let (writer, manifest) = prepared(&cx, path.clone()).await;
            writer.write_chunk(&cx, 0, b"ab".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
            writer.write_chunk(&cx, 2, b"cd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
            let staging = { writer.writer.lock_state().temp_path.clone().unwrap() };
            cx.scoped_fs().write(staging, b"abcdjunk".to_vec()).await.unwrap();
            let offset = writer.checked_receive_offset(&cx).await.unwrap().unwrap();
            assert_eq!(offset, 4);
            let (input, _) = source(b"efghNEXT", None);
            let mut receive = writer.resume_exact_at(&cx, input, manifest,
                ScopedReceiveOptions { max_chunks: 3, ..options() }, offset).unwrap();
            receive.wait().await.unwrap().unwrap();
            assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().chunk_count, 3);
            assert_eq!(cx.scoped_fs().read(path).await.unwrap(), b"abcdefgh");
        });
        drained(&runtime);
    }

    #[test]
    fn complete_and_empty_prefixes_need_no_source_poll_but_still_authenticate() {
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for case in 0..3 {
                let data = if case == 0 { b"".as_slice() } else { b"abcdefgh".as_slice() };
                let path = directory.path().join(format!("complete-{case}"));
                let (writer, manifest) = prepared_data(&cx, path.clone(), data, CommitPolicy::AtomicRename).await;
                if case != 0 {
                    let bytes = if case == 2 { b"tampered" } else { b"abcdefgh" };
                    writer.write_chunk(&cx, 0, bytes.to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                }
                let offset = writer.checked_receive_offset(&cx).await.unwrap().unwrap();
                let (input, probe) = source(b"NEXT", None);
                let mut receive = writer.resume_exact_at(&cx, input, manifest, options(), offset).unwrap();
                let result = receive.wait().await;
                assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                if case == 2 {
                    assert!(matches!(result, Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
                    assert!(!path.exists(), "local receipts are not sender authentication");
                } else {
                    assert_eq!(result.unwrap().unwrap(), path);
                    assert_eq!(receive.take_source().unwrap().position, 0);
                    assert_eq!(cx.scoped_fs().read(path).await.unwrap(), data);
                }
            }
        });
        drained(&runtime);
    }

    #[test]
    fn resumed_preflight_never_reuses_earlier_verification() {
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let path = directory.path().join("file");
            let (writer, manifest) = prepared(&cx, path.clone()).await;
            writer.write_chunk(&cx, 0, b"abcdefgh".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
            writer.verify(&cx, Arc::clone(&manifest)).await.unwrap().unwrap();
            let (input, probe) = source(b"NEXT", None);
            let mut receive = writer.resume_exact_at_with_chunk_commitment(&cx, input, Arc::clone(&manifest), options(), 8,
                ManifestChunkCommitment::new([0; 32])).unwrap();
            assert!(matches!(receive.wait().await, Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            assert!(matches!(writer.commit(&cx).await, Ok(Outcome::Err(SparseWriterError::NotVerified))));
            assert!(!path.exists());

            // Witness the real successful preflight boundary as well: stopping
            // before its finalization must not expose the previous proof.
            writer.verify(&cx, Arc::clone(&manifest)).await.unwrap().unwrap();
            let expectation = Arc::clone(&manifest);
            assert_eq!(writer.run(&cx, move |core| {
                super::super::prepare_receive(core, &expectation, options(), None, Some(8))
            }).await.unwrap().unwrap(), 8);
            assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().verification_state,
                VerificationState::Pending);
            assert!(matches!(writer.commit(&cx).await, Ok(Outcome::Err(SparseWriterError::NotVerified))));
            let (input, probe) = source(b"NEXT", None);
            let mut receive = writer.resume_exact_at(&cx, input, manifest, options(), 8).unwrap();
            assert_eq!(receive.wait().await.unwrap().unwrap(), path);
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
        });
        drained(&runtime);
    }

    #[test]
    fn resumed_wait_retains_partial_source_bytes_and_excludes_competing_clones() {
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let path = directory.path().join("file");
            let (writer, manifest) = prepared(&cx, path.clone()).await;
            writer.write_chunk(&cx, 0, b"abcd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
            let (mut input, probe) = source(b"efghNEXT", None);
            input.pause_at = Some(2);
            let mut receive = writer.resume_exact_at(&cx, input, manifest, options(), 4).unwrap();
            reach_pause(&mut receive, &probe).await;
            assert_eq!(receive.accepted_bytes(), 4);
            let mut wait = Box::pin(receive.wait());
            poll_fn(|task| { assert!(wait.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            drop(wait);
            let mut competing = Box::pin(writer.set_expected_size(&cx, 9));
            poll_fn(|task| { assert!(competing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            assert_eq!(writer.admission.telemetry_snapshot(0).waiter_count, 1);
            cx.scoped_fs().write(directory.path().join("unrelated"), vec![1]).await.unwrap();
            probe.release();
            receive.wait().await.unwrap().unwrap();
            assert!(matches!(competing.await, Ok(Outcome::Err(SparseWriterError::WriteFailed(_)))));
            assert_eq!(receive.take_source().unwrap().position, 4);
            assert_eq!(cx.scoped_fs().read(path).await.unwrap(), b"abcdefgh");
        });
        drained(&runtime);
    }

    #[test]
    fn cancelled_suffix_can_restart_with_a_new_live_context() {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let directory = tempfile::tempdir().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let region = cx.open_child_region(crate::cx::ChildRegionSpec::inherit()).await.unwrap();
                let child = region.cx();
                let path = directory.path().join("file");
                let (writer, manifest) = prepared(&cx, path.clone()).await;
                writer.write_chunk(&cx, 0, b"abcd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                let (mut input, probe) = source(b"efghNEXT", None);
                input.pause_at = Some(2);
                let mut receive = writer.resume_exact_at(child, input, Arc::clone(&manifest), options(), 4).unwrap();
                reach_pause(&mut receive, &probe).await;
                child.cancel_with(crate::types::CancelKind::User, Some("resumed read cancelled"));
                let result = crate::time::timeout(cx.now(), Duration::from_secs(5), receive.wait()).await.unwrap();
                assert!(matches!(result, Err(ScopedReceiveError::Source(error)) if error.kind() == io::ErrorKind::Interrupted));
                assert_eq!(receive.accepted_bytes(), 4);
                drop(receive);
                region.close().await.unwrap();
                let offset = writer.checked_receive_offset(&cx).await.unwrap().unwrap();
                let (input, _) = source(b"efghNEXT", None);
                let mut resumed = writer.resume_exact_at(&cx, input, manifest, options(), offset).unwrap();
                resumed.wait().await.unwrap().unwrap();
                assert_eq!(cx.scoped_fs().read(path).await.unwrap(), b"abcdefgh");
            });
            drained(&runtime);
        }
    }

    #[test]
    fn chunk_only_resume_requires_the_independently_trusted_pin() {
        use crate::atp::manifest::{ChunkBoundary, ChunkStrategy, MerkleRoot};
        use crate::atp::object::{ManifestId, ObjectId};
        use sha2::{Digest, Sha256};
        let runtime = runtime(2);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let path = directory.path().join("pinned");
            let object = Object::file(b"abcdefgh".to_vec());
            let old_id = object.id.clone();
            let mut graph = ObjectGraph::new();
            graph.add_root(object).unwrap();
            let mut manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
            let id = ObjectId::manifest(ManifestId::from_manifest_bytes(b"resumed-file"));
            let mut object = manifest.objects.remove(&old_id).unwrap();
            object.id = id.clone();
            object.content_hash = None;
            object.chunk_boundaries = vec![ChunkBoundary {
                index: 0, byte_offset: 0, size_bytes: 8,
                content_hash: Sha256::digest(b"abcdefgh").into(),
                strategy: ChunkStrategy::FixedSize, metadata: None,
            }];
            manifest.objects.insert(id.clone(), object);
            manifest.roots = vec![id.clone()];
            manifest.merkle_root = MerkleRoot::from_manifest_components(
                &manifest.objects, &manifest.chunk_plan, &manifest.raptorq_layout,
                &manifest.compression_policy, &manifest.encryption_policy, &manifest.capability_policy,
                &manifest.transform_order, &manifest.transform_proof_policy, &manifest.repair_groups,
            );
            manifest.validate().unwrap();
            let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
            let manifest = Arc::new(manifest);
            let writer = ScopedSparseWriter::new(&cx, id, path.clone(), SparseWriterConfig {
                enable_preallocation: false, ..SparseWriterConfig::default()
            }).await.unwrap().unwrap();
            writer.set_expected_size(&cx, 8).await.unwrap().unwrap();
            writer.write_chunk(&cx, 0, b"abcd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
            for bad_pin in [None, Some(ManifestChunkCommitment::new([0; 32]))] {
                let (input, probe) = source(b"efghNEXT", None);
                let mut receive = match bad_pin {
                    None => writer.resume_exact_at(&cx, input, Arc::clone(&manifest), options(), 4),
                    Some(pin) => writer.resume_exact_at_with_chunk_commitment(
                        &cx, input, Arc::clone(&manifest), options(), 4, pin),
                }.unwrap();
                assert!(matches!(receive.wait().await, Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
                assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                assert!(!path.exists());
            }
            let (input, _) = source(b"efghNEXT", None);
            let mut receive = writer.resume_exact_at_with_chunk_commitment(
                &cx, input, manifest, options(), 4, expected).unwrap();
            receive.wait().await.unwrap().unwrap();
            assert_eq!(cx.scoped_fs().read(path).await.unwrap(), b"abcdefgh");
        });
        drained(&runtime);
    }

    struct WitnessedTcp {
        stream: crate::net::TcpStream,
        parked: Arc<AtomicBool>,
    }

    impl AsyncRead for WitnessedTcp {
        fn poll_read(self: Pin<&mut Self>, task: &mut Context<'_>, buf: &mut ReadBuf<'_>)
            -> Poll<io::Result<()>>
        {
            let this = self.get_mut();
            let result = Pin::new(&mut this.stream).poll_read(task, buf);
            if result.is_pending() { this.parked.store(true, Ordering::SeqCst); }
            result
        }
    }

    async fn socket_parked(session: &mut ScopedReceive<WitnessedTcp>, parked: &AtomicBool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !parked.load(Ordering::SeqCst) {
            poll_fn(|task| {
                assert!(session.poll_wait(task).is_pending());
                Poll::Ready(())
            }).await;
            assert!(std::time::Instant::now() < deadline, "TCP source never parked");
            crate::runtime::yield_now().await;
        }
    }

    #[test]
    fn truncated_tcp_connection_resumes_on_a_new_open_connection_without_replaying_prefix() {
        use std::io::Write;
        for workers in [1, 2] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let mut peer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (socket, _) = listener.accept().unwrap();
            let mut replacement = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (replacement_socket, _) = listener.accept().unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            replacement.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let runtime = runtime(workers);
            let directory = tempfile::tempdir().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let path = directory.path().join("file");
                let (writer, manifest) = prepared(&cx, path.clone()).await;
                let parked = Arc::new(AtomicBool::new(false));
                let input = WitnessedTcp { stream: crate::net::TcpStream::from_std(socket).unwrap(),
                    parked: Arc::clone(&parked) };
                let mut first = writer.receive_exact(&cx, input, Arc::clone(&manifest), options()).unwrap();
                socket_parked(&mut first, &parked).await;
                peer.write_all(b"abcdef").unwrap();
                peer.shutdown(std::net::Shutdown::Write).unwrap();
                let result = crate::time::timeout(cx.now(), Duration::from_secs(5), first.wait()).await.unwrap();
                assert!(matches!(result, Err(ScopedReceiveError::Source(error))
                    if error.kind() == io::ErrorKind::UnexpectedEof));
                // Graceful EOF emits its short last chunk, unlike an I/O error.
                assert_eq!(first.accepted_bytes(), 6);
                drop(first);
                assert!(!path.exists());
                let offset = writer.checked_receive_offset(&cx).await.unwrap().unwrap();
                assert_eq!(offset, 6);
                let parked = Arc::new(AtomicBool::new(false));
                let input = WitnessedTcp { stream: crate::net::TcpStream::from_std(replacement_socket).unwrap(),
                    parked: Arc::clone(&parked) };
                let mut resumed = writer.resume_exact_at(&cx, input, manifest, options(), offset).unwrap();
                socket_parked(&mut resumed, &parked).await;
                replacement.write_all(b"ghNEXT").unwrap(); // Deliberately stays open.
                let result = crate::time::timeout(cx.now(), Duration::from_secs(5), resumed.wait()).await.unwrap();
                assert_eq!(result.unwrap().unwrap(), path);
                assert_eq!(resumed.accepted_bytes(), 8);
                assert_eq!(cx.scoped_fs().read(path).await.unwrap(), b"abcdefgh");
                let mut input = resumed.take_source().unwrap();
                let mut next = [0; 4];
                crate::time::timeout(cx.now(), Duration::from_secs(5), input.read_exact(&mut next)).await.unwrap().unwrap();
                assert_eq!(&next, b"NEXT");
            });
            drained(&runtime);
        }
    }
