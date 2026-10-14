//! Native pool integration; gates witness executing work before cancellation.

use super::*;
use crate::atp::journal::CommitPolicy;
use crate::atp::journal::sparse_writer::{SparseWriterConfig, VerificationState};
use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
use crate::channel::oneshot;
use crate::cx::ChildRegionSpec;
use crate::runtime::{JoinError, RootDrainOutcome, Runtime, RuntimeBuilder, SpawnError, yield_now};
use crate::types::CancelKind;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::Poll;
use std::time::{Duration, Instant};

fn prepared(content: &[u8], policy: CommitPolicy) -> (tempfile::TempDir, PathBuf, Arc<Manifest>, ScopedSparseWriter) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("destination");
    let object = Object::file(content.to_vec());
    let object_id = object.id.clone();
    let mut graph = ObjectGraph::new();
    graph.add_root(object).unwrap();
    let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
    // Deliberately exercise adoption of the historical constructor outside the
    // runtime. This setup is not evidence for region-owned capability probes.
    let writer = futures_lite::future::block_on(SparseWriter::new(
        &Cx::for_testing(),
        object_id,
        &path,
        SparseWriterConfig { enable_preallocation: false, commit_policy: policy, ..SparseWriterConfig::default() },
    )).unwrap().into_scoped();
    (directory, path, manifest, writer)
}

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

#[test]
fn empty_and_out_of_order_files_use_the_real_verifier_and_publication_policies() {
    for workers in [1, 2] {
        for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
            for bytes in [b"".as_slice(), b"abcdefgh".as_slice()] {
                let (_directory, path, manifest, writer) = prepared(bytes, policy);
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    writer.set_expected_size(&cx, bytes.len() as u64).await.unwrap().unwrap();
                    if !bytes.is_empty() {
                        writer.write_chunk(&cx, 4, bytes[4..].to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                        assert!(!writer.is_complete(&cx).await.unwrap().unwrap());
                        writer.write_chunk(&cx, 0, bytes[..4].to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                    }
                    assert!(writer.is_complete(&cx).await.unwrap().unwrap());
                    let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
                    writer.verify_with_chunk_commitment(&cx, Arc::clone(&manifest), expected).await.unwrap().unwrap();
                    assert_eq!(writer.commit(&cx).await.unwrap().unwrap(), path);
                    assert_eq!(writer.commit(&cx).await.unwrap().unwrap(), path);
                    let stats = writer.get_stats(&cx).await.unwrap().unwrap();
                    assert_eq!(stats.total_bytes_written, bytes.len() as u64);
                    assert!(matches!(stats.verification_state, VerificationState::Verified { .. }));
                    assert_eq!(cx.scoped_fs().read(path.clone()).await.unwrap(), bytes);
                });
                drained(&runtime);
            }
        }
    }
}

#[test]
fn pin_and_writer_errors_remain_domain_outcomes_not_admission_failures() {
    let (_directory, path, manifest, writer) = prepared(b"data", CommitPolicy::AtomicRename);
    let runtime = runtime(2);
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        writer.set_expected_size(&cx, 4).await.unwrap().unwrap();
        writer.write_chunk(&cx, 0, b"data".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
        assert!(matches!(writer.write_chunk(&cx, 0, b"oops".to_vec(), WriteOptions::default()).await,
            Ok(Outcome::Err(SparseWriterError::OverlappingWrite { offset: 0, size: 4 }))));
        writer.verify(&cx, Arc::clone(&manifest)).await.unwrap().unwrap();
        assert!(matches!(writer.verify_with_chunk_commitment(&cx, manifest, ManifestChunkCommitment::new([0; 32])).await,
            Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
        assert!(matches!(writer.commit(&cx).await, Ok(Outcome::Err(SparseWriterError::NotVerified))));
        assert!(!path.exists());
        // Explicit cleanup has its own non-cancelled authority and keeps the
        // same terminal state machine; no implicit deletion occurs on failure.
        writer.cancel(&cx).await.unwrap().unwrap();
        writer.cancel(&cx).await.unwrap().unwrap();
        assert!(matches!(writer.write_chunk(&cx, 0, vec![0], WriteOptions::default()).await,
            Ok(Outcome::Err(SparseWriterError::WriteFailed(_)))));
    });
    drained(&runtime);
}

#[test]
fn no_runtime_and_attenuated_authority_never_dispatch_or_create_staging() {
    let (_directory, path, _manifest, writer) = prepared(b"data", CommitPolicy::AtomicRename);
    let absent = Cx::for_testing();
    assert!(matches!(futures_lite::future::block_on(writer.set_expected_size(&absent, 4)),
        Err(ScopedFsError::Admission(SpawnError::RuntimeUnavailable))));
    let denied = {
        let _guard = Cx::for_testing().restrict::<crate::cx::NoCaps>().set_current_restricted();
        Cx::current().unwrap()
    };
    assert!(matches!(futures_lite::future::block_on(writer.write_chunk(&denied, 0, b"data".to_vec(), WriteOptions::default())),
        Err(ScopedFsError::CapabilityDenied)));
    assert!(!path.exists());
    assert!(writer.writer.lock_state().temp_file.is_none());
    assert_eq!(writer.writer.lock_state().expected_size, None);
}

#[test]
fn a_precancelled_context_refuses_before_a_write_and_parent_cleanup_still_works() {
    let (_directory, _path, _manifest, writer) = prepared(b"data", CommitPolicy::AtomicRename);
    let runtime = runtime(1);
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        region.cx().cancel_with(CancelKind::User, Some("before sparse dispatch"));
        assert!(matches!(writer.write_chunk(region.cx(), 0, b"data".to_vec(), WriteOptions::default()).await,
            Err(ScopedFsError::Checkpoint(_))));
        assert!(writer.writer.lock_state().temp_file.is_none());
        region.close().await.unwrap();
        writer.cancel(&cx).await.unwrap().unwrap();
    });
    drained(&runtime);
}

#[test]
fn a_dropped_dispatch_wait_keeps_the_writer_and_region_alive_through_the_real_write() {
    for workers in [1, 2] {
        let (_directory, path, _manifest, writer) = prepared(b"data", CommitPolicy::AtomicRename);
        let runtime = runtime(workers);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            writer.set_expected_size(&cx, 4).await.unwrap().unwrap();
            let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let region_id = region.region_id();
            let (started, mut start) = oneshot::channel();
            let (finished, mut finish) = oneshot::channel();
            let (release, wait) = mpsc::channel();
            let owner = writer.clone();
            let weak = Arc::downgrade(&owner.writer);
            let mut work = Box::pin(owner.run(region.cx(), move |core| {
                let child = Cx::current().unwrap();
                assert_eq!(child.region_id(), region_id);
                started.send_blocking(child).unwrap();
                wait.recv_timeout(Duration::from_secs(10)).unwrap();
                // The production dispatcher encloses the actual core write.
                let result = core.write_chunk_blocking(0, b"data", WriteOptions::default());
                let staging = core.lock_state().temp_path.clone().unwrap();
                finished.send_blocking((staging, core.get_stats())).unwrap();
                result
            }));
            poll_fn(|task| { assert!(work.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            let child = start.recv(&cx).await.unwrap();
            drop(work);
            drop(owner);
            drop(writer);
            let deadline = Instant::now() + Duration::from_secs(5);
            while !child.is_cancel_requested() {
                assert!(Instant::now() < deadline, "drop must cancel the real pool child");
                yield_now().await;
            }
            assert!(weak.upgrade().is_some());
            let mut closing = Box::pin(region.close());
            poll_fn(|task| { assert!(closing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            assert!(!path.exists(), "no publication from a write");
            release.send(()).unwrap();
            closing.await.unwrap();
            assert!(weak.upgrade().is_none(), "the drained job must release its last writer owner");
            let (staging, stats) = finish.recv(&cx).await.unwrap();
            assert_eq!(stats.total_bytes_written, 4);
            assert_eq!(stats.chunk_count, 1);
            assert_eq!(cx.scoped_fs().read(staging).await.unwrap(), b"data");
        });
        drained(&runtime);
    }
}

#[test]
fn caller_cancellation_drains_and_preserves_a_late_core_result() {
    for workers in [1, 2] {
        let (_directory, _path, _manifest, writer) = prepared(b"data", CommitPolicy::AtomicRename);
        let runtime = runtime(workers);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            writer.set_expected_size(&cx, 4).await.unwrap().unwrap();
            let (started, mut start) = oneshot::channel();
            let (release, wait) = mpsc::channel();
            let returned = Arc::new(AtomicUsize::new(0));
            let finished = Arc::clone(&returned);
            let writer = writer.clone();
            let mut owner = cx.spawn(move |owner_cx| async move {
                let result = writer.run(&owner_cx, move |core| {
                    let child = Cx::current().unwrap();
                    started.send_blocking(child.clone()).unwrap();
                    wait.recv_timeout(Duration::from_secs(10)).unwrap();
                    assert_eq!(child.cancel_reason().unwrap().kind, CancelKind::User);
                    core.write_chunk_blocking(0, b"data", WriteOptions::default())
                }).await;
                finished.fetch_add(1, Ordering::SeqCst);
                result
            }).unwrap();
            let child = start.recv(&cx).await.unwrap();
            owner.abort();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !child.is_cancel_requested() {
                assert!(Instant::now() < deadline, "caller cancellation must reach pool child");
                yield_now().await;
            }
            assert_eq!(returned.load(Ordering::SeqCst), 0);
            assert!(matches!(owner.try_join(), Ok(None)));
            release.send(()).unwrap();
            match owner.join(&cx).await {
                Ok(Ok(Outcome::Ok(range))) => { assert_eq!(range.offset, 0); assert_eq!(range.size, 4); }
                other => panic!("late core result lost: {other:?}"),
            }
            assert_eq!(returned.load(Ordering::SeqCst), 1);
        });
        drained(&runtime);
    }
}

#[test]
fn pool_panics_keep_the_runtime_failure_shape() {
    let (_directory, _path, _manifest, writer) = prepared(b"", CommitPolicy::AtomicRename);
    let runtime = runtime(1);
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let result: ScopedWriterResult<()> = writer.run(&cx, |_| panic!("sparse dispatcher panic")).await;
        assert!(matches!(result, Err(ScopedFsError::Join(JoinError::Panicked(_)))));
    });
    drained(&runtime);
}

#[test]
fn public_operation_futures_are_send_and_unpolled_calls_do_not_dispatch() {
    fn assert_send<T: Send>(_: T) {}
    let (_directory, path, manifest, writer) = prepared(b"data", CommitPolicy::AtomicRename);
    let cx = Cx::for_testing();
    assert_send(writer.set_expected_size(&cx, 4));
    assert_send(writer.write_chunk(&cx, 0, b"data".to_vec(), WriteOptions::default()));
    assert_send(writer.verify(&cx, Arc::clone(&manifest)));
    assert_send(writer.verify_with_chunk_commitment(&cx, manifest, ManifestChunkCommitment::new([0; 32])));
    assert_send(writer.commit(&cx));
    assert_send(writer.cancel(&cx));
    assert_send(writer.get_stats(&cx));
    assert_send(writer.is_complete(&cx));
    assert!(writer.writer.lock_state().temp_file.is_none());
    assert!(!path.exists());
}
