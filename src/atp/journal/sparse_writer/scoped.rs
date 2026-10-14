//! Sparse-file operations on the existing region-owned filesystem gateway.
//!
//! This is an execution adapter over `SparseWriter`, not another verifier,
//! journal, or publication state machine. Every operation uses `ScopedFs` and
//! therefore the runtime's drained blocking tasks. No call is polled on a pool
//! thread by a nested executor, and no inline or detached fallback is used.
//!
//! Each call is owned by its explicit context's region. Dropping the wait asks
//! the child to cancel; region close still waits for a running OS operation and
//! the destruction of abandoned results/captures. A started operation is not
//! preempted or rolled back. Its real `Outcome` survives caller cancellation.
//! Cancellation of a call does not implicitly discard the transfer's staging
//! file: request `cancel` with an authorized, non-cancelled cleanup context.
//!
//! `ScopedSparseWriter::new` includes destination-filesystem probes in the same
//! owned blocking gateway as subsequent operations. `into_scoped` also accepts
//! a writer prepared through the historical synchronous host-boundary API.
//! Existing path-race and publication-policy limitations remain unchanged.
//!
//! A single cancel-safe admission permit is shared by every clone. Contending
//! calls wait as futures before pool submission, instead of consuming workers
//! while blocked on this writer's synchronous operation lock. The permit moves
//! into the submitted closure: dropping its wait cannot release a running job's
//! slot before its core operation returns. This serializes core execution, not
//! subsequent runtime retirement or memory held by all awaiting callers.

use super::{
    ChunkRange, Manifest, ManifestChunkCommitment, SparseWriter, SparseWriterConfig, SparseWriterError,
    SparseWriterStats, WriteOptions,
};
use crate::atp::object::ObjectId;
use crate::cx::Cx;
use crate::cx::cap::{CapSetRuntimeMask, HasIo, HasSpawn};
use crate::fs::scoped::ScopedFsError;
use crate::sync::semaphore::OwnedAcquireFuture;
use crate::sync::{OwnedSemaphorePermit, Semaphore};
use crate::types::Outcome;
use std::fs::File;
use std::future::{Future, poll_fn};
use std::io;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;

/// Runtime admission/retirement and the writer's actual outcome are separate.
///
/// `Err` reports a `ScopedFs` authority, checkpoint, admission, or child failure.
/// `Ok(outcome)` preserves exactly what the running writer returned, including
/// a filesystem/verification error or a successful effect after cancellation.
/// Neither an outer nor an inner error is evidence that publication rolled back.
/// An unexpected internal-queue failure is `ScopedFsError::Io` with an
/// `AcquireError` source, not a filesystem operation. Context cancellation and
/// budget refusals while waiting remain `ScopedFsError::Checkpoint`.
pub type ScopedWriterResult<T> = Result<Outcome<T, SparseWriterError>, ScopedFsError>;

/// A shared sparse writer whose operations execute as region-owned pool jobs.
///
/// Clones refer to one writer and one serialized lifecycle. There is no raw
/// writer accessor and no borrowed file/data pointer crosses the pool boundary.
/// The adapter itself does not own a region: each operation requires an explicit
/// `Cx` with both I/O and spawn authority. A job retains the writer even after
/// all application handles and the borrowing wait have been dropped.
#[derive(Clone)]
pub struct ScopedSparseWriter {
    writer: Arc<SparseWriter>,
    admission: Arc<Semaphore>,
}

impl std::fmt::Debug for ScopedSparseWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not take the writer state lock on the caller's async thread.
        f.debug_struct("ScopedSparseWriter").finish_non_exhaustive()
    }
}

impl SparseWriter {
    /// Move this prepared writer behind the region-owned pool execution API.
    ///
    /// Adoption performs no filesystem work and does not change verification,
    /// written ranges, staging descriptors, or terminal state. The historical
    /// constructor's probes are not retroactively made region-owned.
    #[must_use]
    pub fn into_scoped(self) -> ScopedSparseWriter {
        ScopedSparseWriter {
            writer: Arc::new(self),
            admission: Arc::new(Semaphore::new(1)),
        }
    }
}

impl ScopedSparseWriter {
    /// Construct a writer entirely on the region-owned blocking pool.
    ///
    /// Destination-filesystem probes, their temporary files, and writer state
    /// construction all happen after I/O/spawn admission. No destination or
    /// staging file is published by construction. The path manager may create
    /// its quarantine directory. Existing probe policies and best-effort
    /// probe-file cleanup remain unchanged; cancellation does not roll them back.
    ///
    /// An unpolled call has no filesystem effects. Dropping a started wait
    /// requests cancellation; its region retains the job and destroys an
    /// abandoned writer before close completes. Running OS probes cannot be
    /// preempted. A completed writer returned after cancellation is still valid
    /// and can be used with another live, authorized context.
    pub async fn new<Caps>(
        cx: &Cx<Caps>,
        object_id: ObjectId,
        final_path: PathBuf,
        config: SparseWriterConfig,
    ) -> ScopedWriterResult<Self>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        Self::create_with(cx, move || SparseWriter::new_blocking(object_id, final_path, config)).await
    }

    // Keep constructor placement, domain mapping and abandoned-result ownership
    // on the real gateway; tests may gate this exact boundary without mocking it.
    async fn create_with<Caps, F>(cx: &Cx<Caps>, create: F) -> ScopedWriterResult<Self>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce() -> Outcome<SparseWriter, SparseWriterError> + Send + 'static,
    {
        cx.scoped_fs().run_io(move |_| {
            Ok(match create() {
                Outcome::Ok(writer) => Outcome::Ok(writer.into_scoped()),
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => Outcome::Panicked(payload),
            })
        }).await
    }

    // Acquire before submitting any pool job. Observe the explicitly supplied
    // context's cancellation even when it is not the currently polling task's
    // Cx. The semaphore owns FIFO/rollback; the explicit Cx owns checkpoints.
    async fn reserve<Caps>(&self, cx: &Cx<Caps>) -> Result<OwnedSemaphorePermit, ScopedFsError>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        if !cx.capabilities().io {
            return Err(ScopedFsError::CapabilityDenied);
        }
        cx.checkpoint().map_err(ScopedFsError::Checkpoint)?;
        let mut cancelled = pin!(cx.cancelled());
        // This is an internal execution gate, not an application obligation.
        // A child-region admission context need not be a live task holder.
        // Avoid minting a caller-held obligation before the real pool task is
        // admitted; that task, not this queue entry, owns filesystem work.
        let mut acquiring = pin!(OwnedAcquireFuture::new_uncancelable(
            Arc::clone(&self.admission), 1,
        ));
        poll_fn(|task| {
            // Register before checking so cancellation between checking and
            // queue registration cannot be lost. Checkpoint respects masking.
            let _ = cancelled.as_mut().poll(task);
            if !cx.capabilities().io {
                return std::task::Poll::Ready(Err(ScopedFsError::CapabilityDenied));
            }
            if let Err(error) = cx.checkpoint() {
                return std::task::Poll::Ready(Err(ScopedFsError::Checkpoint(error)));
            }
            acquiring.as_mut().poll(task).map(|result| {
                result.map_err(|error| ScopedFsError::Io(io::Error::other(error)))
            })
        }).await
    }

    // `ScopedFs` is the single authority/checkpoint/admission/cancel/drain
    // implementation. Wrapping the domain outcome in Ok deliberately does not
    // convert successful late effects into an artificial cancellation result.
    async fn run<Caps, F, T>(&self, cx: &Cx<Caps>, operation: F) -> ScopedWriterResult<T>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
        F: FnOnce(&SparseWriter) -> Outcome<T, SparseWriterError> + Send + 'static,
        T: Send + 'static,
    {
        let permit = self.reserve(cx).await?;
        let writer = Arc::clone(&self.writer);
        cx.scoped_fs().run_io(move |_| {
            // Hold through the operation itself, not merely the borrowing
            // await. Refusal, queued cancellation, panic and ordinary return
            // all restore capacity using the permit's existing RAII behavior.
            let _permit = permit;
            Ok(operation(&writer))
        }).await
    }

    /// Set the expected file length; any preallocation runs on the pool.
    pub async fn set_expected_size<Caps>(&self, cx: &Cx<Caps>, size: u64) -> ScopedWriterResult<()>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, move |writer| match writer.set_expected_size(size) {
            Ok(()) => Outcome::Ok(()),
            Err(error) => Outcome::Err(error),
        }).await
    }

    /// Write one owned chunk with the canonical range, hash, and fsync checks.
    ///
    /// Ownership of `data` moves into the job without a second payload copy.
    /// Dropping this wait need not undo a started write. Query actual ranges or
    /// statistics after its owning region drains instead of blindly resending.
    /// The caller chooses the allocation size; this method adds no size limit.
    pub async fn write_chunk<Caps>(
        &self,
        cx: &Cx<Caps>,
        offset: u64,
        data: Vec<u8>,
        options: WriteOptions,
    ) -> ScopedWriterResult<ChunkRange>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, move |writer| writer.write_chunk_blocking(offset, &data, options)).await
    }

    /// Verify against a trusted immutable manifest without blocking a scheduler.
    ///
    /// The manifest `Arc` avoids copying its object/chunk tables for each call.
    /// Legacy root-only chunk authentication remains refused by the core.
    pub async fn verify<Caps>(&self, cx: &Cx<Caps>, manifest: Arc<Manifest>) -> ScopedWriterResult<()>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, move |writer| writer.verify_inner(&manifest, None)).await
    }

    /// Verify every byte using an independently trusted chunk commitment.
    /// The same pinned verifier, identity checks and coverage checks are used.
    pub async fn verify_with_chunk_commitment<Caps>(
        &self,
        cx: &Cx<Caps>,
        manifest: Arc<Manifest>,
        expected: ManifestChunkCommitment,
    ) -> ScopedWriterResult<()>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, move |writer| writer.verify_inner(&manifest, Some(&expected))).await
    }

    /// Publish using the existing sealed lifecycle and final durability barriers.
    ///
    /// A started commit drains even if the caller is cancelled. Its exact result
    /// is preserved. An error may follow visibility; it never implies rollback.
    pub async fn commit<Caps>(&self, cx: &Cx<Caps>) -> ScopedWriterResult<PathBuf>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, |writer| writer.commit_with_fsync(File::sync_all)).await
    }

    /// Explicitly quarantine/clean up and permanently cancel an uncommitted writer.
    ///
    /// This is filesystem work, not a task-cancellation signal. Use a live,
    /// authorized cleanup context; an already-cancelled context refuses dispatch.
    /// A failed cleanup retains its evidence for retry. An unresolved publication
    /// cannot be discarded by this operation.
    pub async fn cancel<Caps>(&self, cx: &Cx<Caps>) -> ScopedWriterResult<()>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, SparseWriter::cancel_blocking).await
    }

    /// Observe progress on the pool, not by contending on an async worker.
    pub async fn get_stats<Caps>(&self, cx: &Cx<Caps>) -> ScopedWriterResult<SparseWriterStats>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, |writer| Outcome::Ok(writer.get_stats())).await
    }

    /// Observe whether all expected ranges are present without an async-thread lock.
    pub async fn is_complete<Caps>(&self, cx: &Cx<Caps>) -> ScopedWriterResult<bool>
    where
        Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
    {
        self.run(cx, |writer| Outcome::Ok(writer.is_complete())).await
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod construction_tests {
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
                let mut creating = Box::pin(ScopedSparseWriter::create_with(&child, move || {
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
}
