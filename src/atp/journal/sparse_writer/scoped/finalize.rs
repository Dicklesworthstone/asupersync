//! Verification and publication as one admitted, region-owned operation.

use super::{Manifest, ManifestChunkCommitment, ScopedSparseWriter, ScopedWriterResult, SparseWriter, SparseWriterError};
use crate::cx::Cx;
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use crate::types::Outcome;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

impl ScopedSparseWriter {
    /// Verify the supplied trusted manifest and publish without a clone interleaving.
    ///
    /// Unlike separate `verify(...).await` and `commit(...).await` calls, this
    /// holds one FIFO admission slot and one blocking job across both stages.
    /// Every call performs fresh verification; it never relies on another
    /// caller's previously installed verification. Failed verification leaves
    /// staging available and does not start publication or its durability barrier.
    ///
    /// Once the job starts, cancellation requests drain, not rollback: successful
    /// verification may still be followed by publication after a cancellation
    /// request or dropped wait. The exact terminal outcome is preserved. Use
    /// separate methods when an application needs a decision point between
    /// verification and commit, and coordinate ownership of clones at that point.
    ///
    /// A successful finalization seals the writer. Calling this method again
    /// refuses rather than pretending to reverify a consumed staging inode; use
    /// [`Self::commit`] to retrieve the already committed path. A failed commit
    /// remains sealed with its existing uncertainty semantics. No protection
    /// against external filesystem mutation or pathname races is added, and
    /// `CopyAndVerify` retains its non-atomic visibility semantics.
    pub async fn verify_and_commit<Caps>(
        &self,
        cx: &Cx<Caps>,
        manifest: Arc<Manifest>,
    ) -> ScopedWriterResult<PathBuf>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.verify_publish_with(cx, manifest, None, |writer| {
            writer.commit_with_fsync(File::sync_all)
        }).await
    }

    /// Verify an independently trusted chunk commitment and publish in one job.
    ///
    /// The expected commitment must come from the trusted producer, not be
    /// computed from received untrusted metadata. This uses the same canonical
    /// identity, coverage, chunk and whole-file checks as pinned verification.
    /// A wrong pin cannot reach publication, even after an earlier successful
    /// verification. Admission, cancellation and retry semantics are those of
    /// [`Self::verify_and_commit`]; no legacy-root fallback is introduced.
    pub async fn verify_and_commit_with_chunk_commitment<Caps>(
        &self,
        cx: &Cx<Caps>,
        manifest: Arc<Manifest>,
        expected: ManifestChunkCommitment,
    ) -> ScopedWriterResult<PathBuf>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.verify_publish_with(cx, manifest, Some(expected), |writer| {
            writer.commit_with_fsync(File::sync_all)
        }).await
    }

    // One driver holds `run`'s owned permit across the real verifier and the
    // real publisher. The private continuation permits state-witnessed tests
    // between them and sync-failure injection through the canonical commit.
    // No public caller can replace verification or the publication operation.
    async fn verify_publish_with<Caps, F>(
        &self,
        cx: &Cx<Caps>,
        manifest: Arc<Manifest>,
        expected: Option<ManifestChunkCommitment>,
        publish: F,
    ) -> ScopedWriterResult<PathBuf>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce(&SparseWriter) -> Outcome<PathBuf, SparseWriterError> + Send + 'static,
    {
        self.run(cx, move |writer| {
            match writer.verify_inner(&manifest, expected.as_ref()) {
                Outcome::Ok(()) => publish(writer),
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => Outcome::Panicked(payload),
            }
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::journal::CommitPolicy;
    use crate::atp::journal::sparse_writer::{SparseWriterConfig, VerificationState, WriteOptions, WriterLifecycle};
    use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
    use crate::channel::oneshot;
    use crate::cx::ChildRegionSpec;
    use crate::fs::scoped::ScopedFsError;
    use crate::runtime::{JoinError, RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
    use crate::types::CancelKind;
    use std::future::{Future, poll_fn};
    use std::path::Path;
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

    async fn ready(
        cx: &Cx,
        path: &Path,
        content: &[u8],
        policy: CommitPolicy,
    ) -> (ScopedSparseWriter, Arc<Manifest>) {
        let object = Object::file(content.to_vec());
        let id = object.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_root(object).unwrap();
        let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
        let writer = ScopedSparseWriter::new(cx, id, path.to_owned(), SparseWriterConfig {
            enable_preallocation: false,
            commit_policy: policy,
            ..SparseWriterConfig::default()
        }).await.unwrap().unwrap();
        writer.set_expected_size(cx, content.len() as u64).await.unwrap().unwrap();
        if !content.is_empty() {
            writer.write_chunk(cx, 0, content.to_vec(), WriteOptions::default()).await.unwrap().unwrap();
        }
        (writer, manifest)
    }

    #[test]
    fn public_finalization_checks_every_policy_scheduler_and_pin_mode() {
        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                    for content in [b"".as_slice(), b"abcdefgh".as_slice()] {
                        for pinned in [false, true] {
                            let path = directory.path().join(format!("{policy:?}-{}-{pinned}", content.len()));
                            let (writer, manifest) = ready(&cx, &path, content, policy).await;
                            let result = if pinned {
                                let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
                                writer.verify_and_commit_with_chunk_commitment(&cx, manifest.clone(), expected).await
                            } else {
                                writer.verify_and_commit(&cx, manifest.clone()).await
                            };
                            assert_eq!(result.unwrap().unwrap(), path);
                            assert_eq!(std::fs::read(&path).unwrap(), content);
                            assert_eq!(writer.writer.lock_state().lifecycle, WriterLifecycle::Committed);
                            assert_eq!(writer.admission.available_permits(), 1);
                            assert_eq!(writer.commit(&cx).await.unwrap().unwrap(), path);
                            // A repeat cannot silently authenticate a different expectation.
                            assert!(matches!(writer.verify_and_commit(&cx, manifest).await,
                                Ok(Outcome::Err(SparseWriterError::WriteFailed(_)))));
                        }
                    }
                }
            });
            drained(&runtime);
        }
    }

    #[test]
    fn finalization_rechecks_bytes_after_an_earlier_successful_verification() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("destination");
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = ready(&cx, &path, b"abcdefgh", CommitPolicy::AtomicRename).await;
            writer.verify(&cx, manifest.clone()).await.unwrap().unwrap();
            let staging = writer.writer.lock_state().temp_path.clone().unwrap();
            cx.scoped_fs().write(staging.clone(), b"tampered".to_vec()).await.unwrap();
            assert!(matches!(writer.verify_and_commit(&cx, manifest).await,
                Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
            assert!(!path.exists());
            assert_eq!(std::fs::read(staging).unwrap(), b"tampered");
            assert!(matches!(writer.get_stats(&cx).await.unwrap().unwrap().verification_state,
                VerificationState::Failed { .. }));
            assert!(matches!(writer.commit(&cx).await, Ok(Outcome::Err(SparseWriterError::NotVerified))));
        });
        drained(&runtime);
    }

    #[test]
    fn pinned_chunk_only_objects_finalize_without_a_legacy_root_fallback() {
        use crate::atp::manifest::{ChunkBoundary, ChunkStrategy, MerkleRoot};
        use crate::atp::object::{ManifestId, ObjectId};
        use sha2::{Digest, Sha256};

        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for content in [b"".as_slice(), b"abcdefgh".as_slice()] {
                let object = Object::file(content.to_vec());
                let old_id = object.id.clone();
                let mut graph = ObjectGraph::new();
                graph.add_root(object).unwrap();
                let mut manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
                let id = ObjectId::manifest(ManifestId::from_manifest_bytes(b"finalization-test-object"));
                let mut record = manifest.objects.remove(&old_id).unwrap();
                record.id = id.clone();
                record.content_hash = None;
                record.chunk_boundaries = content.chunks(3).enumerate().map(|(index, bytes)| ChunkBoundary {
                    index: u32::try_from(index).unwrap(),
                    byte_offset: (index * 3) as u64,
                    size_bytes: bytes.len() as u64,
                    content_hash: Sha256::digest(bytes).into(),
                    strategy: ChunkStrategy::FixedSize,
                    metadata: None,
                }).collect();
                manifest.objects.insert(id.clone(), record);
                manifest.roots = vec![id.clone()];
                manifest.merkle_root = MerkleRoot::from_manifest_components(
                    &manifest.objects, &manifest.chunk_plan, &manifest.raptorq_layout,
                    &manifest.compression_policy, &manifest.encryption_policy,
                    &manifest.capability_policy, &manifest.transform_order,
                    &manifest.transform_proof_policy, &manifest.repair_groups,
                );
                manifest.validate().unwrap();
                let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
                let manifest = Arc::new(manifest);
                let path = directory.path().join(format!("chunk-only-{}", content.len()));
                let writer = ScopedSparseWriter::new(&cx, id, path.clone(), SparseWriterConfig {
                    enable_preallocation: false, ..SparseWriterConfig::default()
                }).await.unwrap().unwrap();
                writer.set_expected_size(&cx, content.len() as u64).await.unwrap().unwrap();
                if !content.is_empty() {
                    writer.write_chunk(&cx, 0, content.to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                }
                assert!(matches!(writer.verify_and_commit(&cx, manifest.clone()).await,
                    Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
                assert!(!path.exists());
                assert_eq!(writer.verify_and_commit_with_chunk_commitment(&cx, manifest, expected)
                    .await.unwrap().unwrap(), path);
                assert_eq!(std::fs::read(path).unwrap(), content);
            }
        });
        drained(&runtime);
    }

    #[test]
    fn refusal_never_invokes_publication_or_its_durability_barrier() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for case in 0..4 {
                let path = directory.path().join(format!("refusal-{case}"));
                let content = if case == 3 { b"".as_slice() } else { b"abcdefgh".as_slice() };
                let (writer, manifest) = ready(&cx, &path, content, CommitPolicy::AtomicRename).await;
                let expected = if case == 0 || case == 3 {
                    Some(ManifestChunkCommitment::new([0; 32]))
                } else { None };
                if case == 1 {
                    writer.set_expected_size(&cx, 9).await.unwrap().unwrap();
                } else if case == 2 {
                    let staging = writer.writer.lock_state().temp_path.clone().unwrap();
                    cx.scoped_fs().write(staging, b"tampered".to_vec()).await.unwrap();
                }
                let calls = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&calls);
                let result = writer.verify_publish_with(&cx, manifest, expected, move |core| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    core.commit_with_fsync(File::sync_all)
                }).await;
                assert!(matches!(result, Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert!(!path.exists());
                assert_eq!(writer.admission.available_permits(), 1);
                assert_eq!(writer.writer.lock_state().lifecycle, WriterLifecycle::Accepting);
                if case == 3 {
                    assert!(writer.writer.lock_state().temp_file.is_none());
                }
            }
        });
        drained(&runtime);
    }

    #[test]
    fn clone_mutations_wait_across_the_real_verification_publication_boundary() {
        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("destination");
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = ready(&cx, &path, b"abcdefgh", CommitPolicy::AtomicRename).await;
                let (verified, mut verification) = oneshot::channel();
                let (release, wait) = mpsc::channel();
                let mut finalizing = Box::pin(writer.verify_publish_with(&cx, manifest, None, move |core| {
                    assert!(matches!(core.get_stats().verification_state, VerificationState::Verified { .. }));
                    verified.send_blocking(()).unwrap();
                    wait.recv_timeout(Duration::from_secs(10)).unwrap();
                    core.commit_with_fsync(File::sync_all)
                }));
                poll_fn(|task| {
                    assert!(finalizing.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                verification.recv(&cx).await.unwrap();
                let clone = writer.clone();
                let mut resizing = Box::pin(clone.set_expected_size(&cx, 12));
                poll_fn(|task| {
                    assert!(resizing.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                assert_eq!(writer.admission.telemetry_snapshot(0).waiter_count, 1);
                assert_eq!(writer.writer.lock_state().expected_size, Some(8));
                // A competing clone must not consume the spare pool worker.
                let spare = crate::time::timeout(cx.now(), Duration::from_secs(3),
                    cx.scoped_fs().run_io(|_| Ok(37_u8))).await.unwrap().unwrap();
                assert_eq!(spare, 37);
                assert!(!path.exists());
                release.send(()).unwrap();
                assert_eq!(finalizing.await.unwrap().unwrap(), path);
                assert!(matches!(resizing.await, Ok(Outcome::Err(SparseWriterError::WriteFailed(_)))));
                assert_eq!(std::fs::read(&path).unwrap(), b"abcdefgh");
            });
            drained(&runtime);
        }
    }

    #[test]
    fn late_caller_cancellation_preserves_the_actual_final_publication() {
        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("destination");
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (writer, manifest) = ready(&cx, &path, b"abcdefgh", CommitPolicy::AtomicRename).await;
                let (verified, mut verification) = oneshot::channel();
                let (release, wait) = mpsc::channel();
                let owned = writer.clone();
                let mut task = cx.spawn(move |owner| async move {
                    owned.verify_publish_with(&owner, manifest, None, move |core| {
                        verified.send_blocking(Cx::current().unwrap()).unwrap();
                        wait.recv_timeout(Duration::from_secs(10)).unwrap();
                        core.commit_with_fsync(File::sync_all)
                    }).await
                }).unwrap();
                let worker = verification.recv(&cx).await.unwrap();
                task.abort();
                let deadline = Instant::now() + Duration::from_secs(5);
                while !worker.is_cancel_requested() {
                    assert!(Instant::now() < deadline, "owner cancellation did not reach the job");
                    yield_now().await;
                }
                assert!(matches!(task.try_join(), Ok(None)));
                assert_eq!(writer.admission.available_permits(), 0);
                assert!(!path.exists());
                release.send(()).unwrap();
                assert_eq!(task.join(&cx).await.unwrap().unwrap().unwrap(), path);
                assert_eq!(std::fs::read(&path).unwrap(), b"abcdefgh");
                assert_eq!(writer.admission.available_permits(), 1);
            });
            drained(&runtime);
        }
    }

    #[test]
    fn a_dropped_finalization_wait_keeps_its_region_and_admission_until_commit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("destination");
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = ready(&cx, &path, b"abcdefgh", CommitPolicy::AtomicRename).await;
            let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let child = region.cx();
            let (verified, mut verification) = oneshot::channel();
            let (release, wait) = mpsc::channel();
            let mut finalizing = Box::pin(writer.verify_publish_with(&child, manifest, None, move |core| {
                verified.send_blocking(()).unwrap();
                wait.recv_timeout(Duration::from_secs(10)).unwrap();
                core.commit_with_fsync(File::sync_all)
            }));
            poll_fn(|task| {
                assert!(finalizing.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            verification.recv(&cx).await.unwrap();
            drop(finalizing);
            let mut closing = Box::pin(region.close());
            poll_fn(|task| {
                assert!(closing.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            assert_eq!(writer.admission.available_permits(), 0);
            assert!(!path.exists());
            release.send(()).unwrap();
            closing.await.unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"abcdefgh");
            assert_eq!(writer.admission.available_permits(), 1);
            assert_eq!(writer.commit(&cx).await.unwrap().unwrap(), path);
        });
        drained(&runtime);
    }

    #[test]
    fn final_barrier_errors_and_panics_keep_unresolved_publication_sealed() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for panics in [false, true] {
                let path = directory.path().join(format!("failure-{panics}"));
                let (writer, manifest) = ready(&cx, &path, b"abcdefgh", CommitPolicy::AtomicRename).await;
                let result = writer.verify_publish_with(&cx, manifest.clone(), None, move |core| {
                    core.commit_with_fsync(|_| {
                        assert!(!panics, "injected final barrier panic");
                        Err(std::io::Error::other("injected final barrier failure"))
                    })
                }).await;
                if panics {
                    assert!(matches!(result, Err(ScopedFsError::Join(JoinError::Panicked(_)))));
                } else {
                    assert!(matches!(result, Ok(Outcome::Err(SparseWriterError::SyncFailed(error)))
                        if error == "injected final barrier failure"));
                }
                let state = writer.writer.lock_state();
                assert_eq!(state.lifecycle, WriterLifecycle::Committing);
                assert!(state.temp_file.is_some());
                assert_eq!(std::fs::read(state.temp_path.as_ref().unwrap()).unwrap(), b"abcdefgh");
                drop(state);
                assert!(!path.exists());
                assert_eq!(writer.admission.available_permits(), 1);
                assert!(matches!(writer.verify_and_commit(&cx, manifest).await,
                    Ok(Outcome::Err(SparseWriterError::WriteFailed(_)))));
                assert!(matches!(writer.commit(&cx).await, Ok(Outcome::Err(SparseWriterError::CommitFailed(_)))));
            }
        });
        drained(&runtime);
    }

    #[test]
    fn unpolled_and_precancelled_finalization_cannot_start_verification() {
        fn assert_send<T: Send>(_: &T) {}
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("destination");
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = ready(&cx, &path, b"abcdefgh", CommitPolicy::AtomicRename).await;
            let unpolled = writer.verify_and_commit(&cx, manifest.clone());
            assert_send(&unpolled);
            drop(unpolled);
            assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().verification_state, VerificationState::Pending);
            let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let child = region.cx();
            child.cancel_with(CancelKind::User, Some("before finalization"));
            let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
            assert!(matches!(writer.verify_and_commit_with_chunk_commitment(&child, manifest, expected).await,
                Err(ScopedFsError::Checkpoint(_))));
            assert_eq!(writer.admission.available_permits(), 1);
            assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().verification_state, VerificationState::Pending);
            assert!(!path.exists());
            region.close().await.unwrap();
        });
        drained(&runtime);
    }
}
