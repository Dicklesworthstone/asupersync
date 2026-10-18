//! Public automatic-checkpoint, restore and publication workflows.
//!
//! These tests use real native runtimes, journals and filesystem publication.
//! Fragmentation, source errors and parked-state probes are explicit test inputs.
//! No test claims power-loss simulation or changes a runtime proof gate.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::atp::journal::{
    FsyncPolicy, JournalCommitRequest, JournalPublication,
    JournalReceiveRequest, ScopedJournalReceive, ScopedReceiveError, ScopedReceiveOptions,
    SparseWriterConfig,
};
use asupersync::atp::journal::sparse_writer::{ScopedSparseWriter, SparseWriterError};
use asupersync::atp::manifest::Manifest;
use asupersync::atp::manifest_chunk_commitment::ManifestChunkCommitment;
use asupersync::cx::Cx;
use asupersync::fs::scoped::ScopedFsError;
use asupersync::io::{AsyncRead, AsyncReadExt};
use asupersync::types::Outcome;
use std::future::{Future, poll_fn};
use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::Poll;
use asupersync::atp::journal::{
    AppendJournal, CommitPolicy, JournalCheckpointRequest, JournalConfig,
    JournalRecord, JournalRestoreLimits, JournalRestoreRequest, TransferResumeStatus,
};
use asupersync::atp::object::{MetadataPolicy, Object, ObjectGraph};
use asupersync::io::ReadBuf;
use asupersync::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
use asupersync::security::{AuthKey, AuthenticationTag};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::{Context, Waker};
use std::time::Duration;

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::new().worker_threads(workers).with_sharded_state(true) };
    builder.blocking_threads(1, 2).build().unwrap()
}

fn drained(runtime: &Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

fn journal_config(base: &std::path::Path) -> JournalConfig {
    JournalConfig {
        base_dir: base.join("journal"), force_sync: false,
        max_journal_size: u64::MAX, max_generations: 0,
        recent_entries_limit: 1, ..JournalConfig::default()
    }
}

fn reopen(base: &std::path::Path) -> AppendJournal {
    AppendJournal::new(journal_config(base), AuthKey::from_seed(42)).unwrap()
}

fn request(journal: AppendJournal, manifest: Arc<Manifest>, interval: u64) -> JournalReceiveRequest {
    JournalReceiveRequest {
        commit: JournalCommitRequest {
            checkpoint: JournalCheckpointRequest {
                journal, transfer_id: "automatic".to_owned(), manifest,
                limits: JournalRestoreLimits { max_bytes: 64, max_chunks: 32, max_chunk_bytes: 4 },
                timestamp: 31,
            },
            expected_chunk_commitment: None,
        },
        options: ScopedReceiveOptions { max_bytes: 64, max_chunks: 32, chunk_size: 2 },
        checkpoint_bytes: interval,
        resume_offset: None,
    }
}

async fn prepared(
    cx: &Cx, base: &std::path::Path, data: &[u8], policy: CommitPolicy,
) -> (ScopedSparseWriter, Arc<Manifest>) {
    let object = Object::file(data.to_vec());
    let id = object.id.clone();
    let mut graph = ObjectGraph::new();
    graph.add_root(object).unwrap();
    let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
    let writer = ScopedSparseWriter::new(cx, id, base.join("destination"), SparseWriterConfig {
        enable_preallocation: false, fsync_policy: FsyncPolicy::BeforeCommit,
        commit_policy: policy, ..SparseWriterConfig::default()
    }).await.unwrap().unwrap();
    (writer, manifest)
}

#[derive(Default)]
struct Probe {
    consumed: AtomicUsize,
    polls: AtomicUsize,
    parked: AtomicBool,
    released: AtomicBool,
    waker: parking_lot::Mutex<Option<Waker>>,
}

struct Source {
    bytes: Vec<u8>, position: usize, fragment: usize,
    pause_at: Option<usize>, fail_at: Option<usize>, probe: Arc<Probe>,
}

impl Source {
    fn new(bytes: &[u8]) -> (Self, Arc<Probe>) {
        let probe = Arc::new(Probe::default());
        (Self {
            bytes: bytes.to_vec(), position: 0, fragment: 1,
            pause_at: None, fail_at: None, probe: Arc::clone(&probe),
        }, probe)
    }
}

impl AsyncRead for Source {
    fn poll_read(
        self: Pin<&mut Self>, task: &mut Context<'_>, buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.probe.polls.fetch_add(1, Ordering::SeqCst);
        if this.pause_at.is_some_and(|at| this.position >= at) {
            let retired = this.probe.waker.lock().replace(task.waker().clone());
            drop(retired);
            this.probe.parked.store(true, Ordering::SeqCst);
            if !this.probe.released.load(Ordering::SeqCst) { return Poll::Pending; }
        }
        if this.fail_at.is_some_and(|at| this.position >= at) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let mut count = this.fragment.min(buffer.remaining()).min(this.bytes.len() - this.position);
        if let Some(at) = this.pause_at.filter(|_| !this.probe.released.load(Ordering::SeqCst)) {
            count = count.min(at.saturating_sub(this.position));
        }
        if let Some(at) = this.fail_at { count = count.min(at.saturating_sub(this.position)); }
        buffer.put_slice(&this.bytes[this.position..this.position + count]);
        this.position += count;
        this.probe.consumed.store(this.position, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

fn release(probe: &Probe) {
    probe.released.store(true, Ordering::SeqCst);
    let wake = probe.waker.lock().take();
    if let Some(wake) = wake { wake.wake(); }
}

async fn park(cx: &Cx, receive: &mut ScopedJournalReceive<Source>, probe: &Probe) {
    let mut wait = Box::pin(receive.wait());
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), poll_fn(|task| {
        assert!(wait.as_mut().poll(task).is_pending(), "receive ended before source witness");
        if probe.parked.load(Ordering::SeqCst) { Poll::Ready(()) } else { Poll::Pending }
    })).await.expect("source did not reach its parked boundary");
    // This borrowing wait is intentionally dropped; the session keeps work.
}

#[test]
fn journaled_receive_publishes_and_reopens_without_consuming_following_protocol_bytes() {
    for workers in [1, 2] {
        for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
            for data in [b"".as_slice(), b"abcdefgh".as_slice()] {
                for interval in [1, 5, u64::MAX] {
                    let directory = tempfile::tempdir().unwrap();
                    let runtime = runtime(workers);
                    runtime.block_on(async {
                        let cx = Cx::current().unwrap();
                        let (writer, manifest) = prepared(&cx, directory.path(), data, policy).await;
                        let mut body = data.to_vec();
                        body.extend_from_slice(b"NEXT");
                        let (source, probe) = Source::new(&body);
                        let mut request = request(reopen(directory.path()), manifest, interval);
                        request.commit.expected_chunk_commitment = Some(
                            ManifestChunkCommitment::from_manifest(&request.commit.checkpoint.manifest).unwrap(),
                        );
                        let mut receiving = writer.receive_to_journal(&cx, source, request).unwrap();
                        assert!(receiving.last_checkpoint().is_none());
                        let report = receiving.wait().await.unwrap();
                        let path = directory.path().join("destination");
                        assert_eq!(report.outcome.unwrap().unwrap(), path);
                        assert_eq!(report.publication, Some(JournalPublication::Confirmed(path.clone())));
                        assert_eq!(probe.consumed.load(Ordering::SeqCst), data.len());
                        assert_eq!(receiving.accepted_bytes(), data.len() as u64);
                        assert_eq!(receiving.last_checkpoint().unwrap().summary.contiguous_prefix_bytes, data.len() as u64);
                        let mut source = receiving.take_source().unwrap();
                        let mut following = [0; 4];
                        source.read_exact(&mut following).await.unwrap();
                        assert_eq!(&following, b"NEXT");
                        assert!(receiving.take_source().is_none());
                        assert!(matches!(receiving.wait().await, Err(ScopedReceiveError::Completed)));
                        assert_eq!(std::fs::read(&path).unwrap(), data);
                        let mut journal = report.journal.unwrap();
                        let entries = journal.get_transfer_entries("automatic").unwrap();
                        assert_eq!(entries.len(), 3 * data.len().div_ceil(2) + 3);
                        assert!(matches!(entries[entries.len() - 2].record, JournalRecord::CommitIntent { .. }));
                        assert!(matches!(entries.last().unwrap().record, JournalRecord::CommitComplete { .. }));
                        journal.compact().unwrap();
                        drop(journal);
                        assert_eq!(reopen(directory.path()).get_resume_summary("automatic").unwrap().status,
                            TransferResumeStatus::Committed {
                                final_path: path.to_str().unwrap().to_owned(), committed_size: data.len() as u64,
                            });
                        accessible(&cx, &writer).await;
                    });
                    drained(&runtime);
                }
            }
        }
    }
}

#[test]
fn failed_source_returns_the_journal_and_durable_prefix_restores_into_suffix_receive() {
    for workers in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(workers);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::CopyAndVerify).await;
            let (mut source, probe) = Source::new(b"abcdefghNEXT");
            source.fail_at = Some(4);
            let mut receiving = writer.receive_to_journal(&cx, source,
                request(reopen(directory.path()), manifest.clone(), 4)).unwrap();
            let report = receiving.wait().await.unwrap();
            assert!(matches!(report.outcome, Err(ScopedReceiveError::Source(error))
                if error.kind() == io::ErrorKind::ConnectionReset));
            assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
            assert_eq!(probe.consumed.load(Ordering::SeqCst), 4);
            assert_eq!(receiving.accepted_bytes(), 4);
            assert!(receiving.take_source().is_none());
            let saved = receiving.last_checkpoint().unwrap();
            assert_eq!(saved.summary.contiguous_prefix_bytes, 4);
            let journal = report.journal.unwrap();
            assert_eq!(journal.get_resume_summary("automatic").unwrap().durable_bytes, 4);
            drop(journal);
            drop(writer);
            let restored = ScopedSparseWriter::restore_from_storage(&cx, JournalRestoreRequest {
                journal_config: journal_config(directory.path()), auth_key: AuthKey::from_seed(42),
                transfer_id: "automatic".to_owned(), source_path: saved.source_path.clone(),
                final_path: directory.path().join("restored"),
                writer_config: SparseWriterConfig { enable_preallocation: false, ..SparseWriterConfig::default() },
                limits: JournalRestoreLimits { max_bytes: 64, max_chunks: 32, max_chunk_bytes: 4 },
            }).await.unwrap().unwrap();
            let mut request = request(reopen(directory.path()), manifest, 3);
            request.resume_offset = Some(4);
            let mut resumed = restored.receive_to_journal(&cx, b"efghNEXT".as_slice(), request).unwrap();
            let report = resumed.wait().await.unwrap();
            assert_eq!(report.outcome.unwrap().unwrap(), directory.path().join("restored"));
            assert_eq!(resumed.take_source().unwrap(), b"NEXT");
            assert_eq!(std::fs::read(directory.path().join("restored")).unwrap(), b"abcdefgh");
            assert_eq!(std::fs::read(&saved.source_path).unwrap(), b"abcd");
            assert_ne!(resumed.last_checkpoint().unwrap().source_path, saved.source_path);
            assert_eq!(report.journal.unwrap().get_transfer_entries("automatic").unwrap().len(), 15);
        });
        drained(&runtime);
    }
}

#[test]
fn checkpoint_failure_keeps_actual_written_bytes_but_stops_the_next_source_poll() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime(2);
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
        let mut config = journal_config(directory.path());
        config.max_journal_size = 1;
        let journal = AppendJournal::new(config.clone(), AuthKey::from_seed(42)).unwrap();
        let (mut source, probe) = Source::new(b"abcdefgh");
        source.fragment = 2;
        source.pause_at = Some(0);
        let mut receiving = writer.receive_to_journal(&cx, source, request(journal, manifest, 2)).unwrap();
        park(&cx, &mut receiving, &probe).await;
        assert_eq!(receiving.last_checkpoint().unwrap().summary.durable_bytes, 0);
        assert!(config.base_dir.join("journal_gen_000001.dat").is_file());
        // Initial Offer rotated to generation 1. A real conflicting frontier
        // makes automatic rotation after the next append fail and fence it.
        cx.scoped_fs().write(config.base_dir.join("journal_gen_000002.dat"), vec![]).await.unwrap();
        release(&probe);
        let report = receiving.wait().await.unwrap();
        assert!(matches!(report.outcome, Ok(Outcome::Err(SparseWriterError::WriteFailed(message)))
            if message.contains("frontier")));
        assert_eq!(receiving.accepted_bytes(), 2);
        assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().total_bytes_written, 2);
        assert_eq!(receiving.last_checkpoint().unwrap().summary.durable_bytes, 0);
        assert_eq!(probe.consumed.load(Ordering::SeqCst), 2);
        assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
        let journal = report.journal.unwrap();
        assert!(journal.get_resume_summary("automatic").is_err());
        drop(journal);
        let reopened = AppendJournal::new(config, AuthKey::from_seed(42)).unwrap();
        assert_eq!(reopened.get_resume_summary("automatic").unwrap().durable_bytes, 0);
        assert!(!directory.path().join("destination").exists());
        accessible(&cx, &writer).await;
    });
    drained(&runtime);
}

#[test]
fn dropped_borrowing_wait_retains_the_checkpoint_and_excludes_competing_writer_clones() {
    for workers in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(workers);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
            let (mut source, probe) = Source::new(b"abcdefghNEXT");
            source.pause_at = Some(4);
            let mut receiving = writer.receive_to_journal(&cx, source,
                request(reopen(directory.path()), manifest, 2)).unwrap();
            park(&cx, &mut receiving, &probe).await;
            let snapshot = receiving.last_checkpoint().unwrap();
            assert_eq!(snapshot.summary.contiguous_prefix_bytes, 4);
            assert_eq!(receiving.accepted_bytes(), 4);
            assert!(!directory.path().join("destination").exists());
            let clone = writer.clone();
            let mut resizing = Box::pin(clone.set_expected_size(&cx, 9));
            poll_fn(|task| { assert!(resizing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            drop(resizing);
            release(&probe);
            let report = receiving.wait().await.unwrap();
            assert_eq!(report.outcome.unwrap().unwrap(), directory.path().join("destination"));
            assert_eq!(receiving.accepted_bytes(), 8);
            assert_eq!(receiving.last_checkpoint().unwrap().summary.contiguous_prefix_bytes, 8);
            assert_eq!(snapshot.summary.contiguous_prefix_bytes, 4, "snapshots are immutable observations");
            assert_eq!(report.journal.unwrap().get_transfer_entries("automatic").unwrap().len(), 15);
            assert_eq!(probe.consumed.load(Ordering::SeqCst), 8);
        });
        drained(&runtime);
    }
}

#[test]
fn invalid_history_pin_and_limits_refuse_before_source_or_staging() {
    for case in 0..7 {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
            let mut request = request(reopen(directory.path()), manifest, 2);
            match case {
                0 => request.commit.checkpoint.limits.max_bytes = 7,
                1 => request.commit.checkpoint.limits.max_chunks = 3,
                2 => request.commit.checkpoint.limits.max_chunk_bytes = 1,
                3 => request.commit.expected_chunk_commitment = Some(ManifestChunkCommitment::new([0; 32])),
                4 => { request.commit.checkpoint.journal.append(JournalRecord::Cancellation {
                    transfer_id: "automatic".to_owned(), reason: "stop".to_owned(), timestamp: 1,
                    auth_tag: AuthenticationTag::zero(),
                }).unwrap(); }
                5 => request.resume_offset = Some(9),
                6 => request.commit.checkpoint.transfer_id.clear(),
                _ => unreachable!(),
            }
            let sequence = request.commit.checkpoint.journal.get_stats().sequence;
            let (source, probe) = Source::new(b"abcdefgh");
            let mut receiving = writer.receive_to_journal(&cx, source, request).unwrap();
            let report = receiving.wait().await.unwrap();
            assert!(matches!(report.outcome, Ok(Outcome::Err(_))));
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            assert_eq!(report.journal.unwrap().get_stats().sequence, sequence);
            assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
            assert!(receiving.last_checkpoint().is_none());
            assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().chunk_count, 0);
            assert!(std::fs::read_dir(directory.path()).unwrap()
                .all(|entry| entry.unwrap().file_name().to_str() == Some("journal")));
            assert!(!directory.path().join("destination").exists());
        });
        drained(&runtime);
    }
}

#[test]
fn incremental_corruption_has_no_payload_checkpoint_or_publication() {
    use asupersync::atp::manifest::{ChunkBoundary, ChunkStrategy, MerkleRoot};
    use sha2::{Digest, Sha256};
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime(2);
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let (writer, mut manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
        let expected = Arc::make_mut(&mut manifest);
        expected.objects.values_mut().next().unwrap().chunk_boundaries = vec![ChunkBoundary {
            index: 0, byte_offset: 0, size_bytes: 2,
            content_hash: Sha256::digest(b"ab").into(), strategy: ChunkStrategy::FixedSize, metadata: None,
        }];
        expected.merkle_root = MerkleRoot::from_manifest_components(
            &expected.objects, &expected.chunk_plan, &expected.raptorq_layout,
            &expected.compression_policy, &expected.encryption_policy, &expected.capability_policy,
            &expected.transform_order, &expected.transform_proof_policy, &expected.repair_groups,
        );
        let (source, probe) = Source::new(b"XXcdefgh");
        let mut receiving = writer.receive_to_journal(&cx, source,
            request(reopen(directory.path()), manifest, 2)).unwrap();
        let report = receiving.wait().await.unwrap();
        assert!(matches!(report.outcome, Ok(Outcome::Err(SparseWriterError::VerificationFailed(message)))
            if message.contains("hash mismatch")));
        assert_eq!(probe.consumed.load(Ordering::SeqCst), 2);
        assert_eq!(receiving.accepted_bytes(), 0);
        assert_eq!(receiving.last_checkpoint().unwrap().summary.durable_bytes, 0);
        assert_eq!(report.journal.unwrap().get_transfer_entries("automatic").unwrap().len(), 1);
        assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
        assert!(!directory.path().join("destination").exists());
    });
    drained(&runtime);
}

#[test]
fn cancelled_and_unpolled_sessions_do_not_start_a_checkpoint() {
    fn assert_send<T: Send>(_: &T) {}
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime(1);
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let (writer, manifest) = prepared(&cx, directory.path(), b"data", CommitPolicy::AtomicRename).await;
        let unpolled = writer.receive_to_journal(&cx, b"data".as_slice(),
            request(reopen(directory.path()), manifest.clone(), 2)).unwrap();
        assert_send(&unpolled);
        drop(unpolled);
        assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().chunk_count, 0);
            assert!(std::fs::read_dir(directory.path()).unwrap()
                .all(|entry| entry.unwrap().file_name().to_str() == Some("journal")));
        let region = cx.open_child_region(asupersync::cx::ChildRegionSpec::inherit()).await.unwrap();
        let child = region.cx();
        child.cancel_with(asupersync::types::CancelKind::User, Some("before journal receive"));
        let (source, probe) = Source::new(b"data");
        let mut receiving = writer.receive_to_journal(child, source,
            request(reopen(directory.path()), manifest, 2)).unwrap();
        let report = receiving.wait().await.unwrap();
        assert!(matches!(report.outcome, Err(ScopedReceiveError::Gateway(ScopedFsError::Checkpoint(_)))));
        assert_eq!(report.journal.unwrap().get_stats().sequence, 0);
        assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
        assert!(receiving.last_checkpoint().is_none());
        assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().chunk_count, 0);
            assert!(std::fs::read_dir(directory.path()).unwrap()
                .all(|entry| entry.unwrap().file_name().to_str() == Some("journal")));
        accessible(&cx, &writer).await;
        region.close().await.unwrap();
    });
    drained(&runtime);
}

#[test]
fn truncated_source_distinguishes_written_tail_from_the_last_durable_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime(1);
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
        let mut receiving = writer.receive_to_journal(&cx, b"abc".as_slice(),
            request(reopen(directory.path()), manifest, 2)).unwrap();
        let report = receiving.wait().await.unwrap();
        assert!(matches!(report.outcome, Err(ScopedReceiveError::Source(error))
            if error.kind() == io::ErrorKind::UnexpectedEof));
        assert_eq!(receiving.accepted_bytes(), 3);
        let saved = receiving.last_checkpoint().unwrap();
        assert_eq!(saved.summary.contiguous_prefix_bytes, 2);
        assert_eq!(report.journal.unwrap().get_resume_summary("automatic").unwrap().durable_bytes, 2);
        assert_eq!(std::fs::read(&saved.source_path).unwrap(), b"abc");
        assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
        assert!(receiving.take_source().is_none());
        assert!(!directory.path().join("destination").exists());
    });
    drained(&runtime);
}

#[test]
fn failed_final_publication_retains_the_intent_and_never_returns_the_source() {
    for workers in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(workers);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let path = directory.path().join("destination");
            // A directory is a deterministic rename refusal, even as root.
            cx.scoped_fs().create_dir_all(path.clone()).await.unwrap();
            let (writer, manifest) = prepared(&cx, directory.path(), b"data", CommitPolicy::AtomicRename).await;
            let mut receiving = writer.receive_to_journal(&cx, b"dataNEXT".as_slice(),
                request(reopen(directory.path()), manifest, u64::MAX)).unwrap();
            let report = receiving.wait().await.unwrap();
            assert!(matches!(report.outcome, Ok(Outcome::Err(SparseWriterError::CommitFailed(_)))));
            assert_eq!(report.publication, Some(JournalPublication::Unconfirmed));
            let journal = report.journal.unwrap();
            assert_eq!(journal.get_resume_summary("automatic").unwrap().status,
                TransferResumeStatus::CommitIntentPending);
            assert!(!journal.get_transfer_entries("automatic").unwrap().iter()
                .any(|entry| matches!(entry.record, JournalRecord::CommitComplete { .. })));
            assert!(writer.set_expected_size(&cx, 4).await.unwrap().is_err());
            assert!(writer.cancel(&cx).await.unwrap().is_err());
            assert!(receiving.take_source().is_none());
            assert_eq!(receiving.accepted_bytes(), 4);
            assert_eq!(receiving.last_checkpoint().unwrap().summary.durable_bytes, 4);
            assert!(path.is_dir());
            accessible(&cx, &writer).await;
        });
        drained(&runtime);
    }
}

#[test]
fn cancellation_at_a_witnessed_parked_source_retains_the_checkpoint_and_journal() {
    for workers in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(workers);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (writer, manifest) = prepared(&cx, directory.path(), b"abcdefgh", CommitPolicy::AtomicRename).await;
            let region = cx.open_child_region(asupersync::cx::ChildRegionSpec::inherit()).await.unwrap();
            let child = region.cx();
            let (mut source, probe) = Source::new(b"abcdefgh");
            source.pause_at = Some(4);
            let mut receiving = writer.receive_to_journal(child, source,
                request(reopen(directory.path()), manifest, 2)).unwrap();
            park(&cx, &mut receiving, &probe).await;
            assert_eq!(receiving.last_checkpoint().unwrap().summary.contiguous_prefix_bytes, 4);
            child.cancel_with(asupersync::types::CancelKind::User, Some("parked journal source"));
            let report = receiving.wait().await.unwrap();
            assert!(matches!(report.outcome, Err(ScopedReceiveError::Source(error))
                if error.kind() == io::ErrorKind::Interrupted));
            assert_eq!(report.publication, Some(JournalPublication::NotAttempted));
            let summary = report.journal.unwrap().get_resume_summary("automatic").unwrap();
            assert_eq!(summary.status, TransferResumeStatus::Resumable);
            assert_eq!(summary.contiguous_prefix_bytes, 4);
            assert_eq!(receiving.accepted_bytes(), 4);
            assert_eq!(probe.consumed.load(Ordering::SeqCst), 4);
            accessible(&cx, &writer).await;
            assert!(!directory.path().join("destination").exists());
            region.close().await.unwrap();
        });
        drained(&runtime);
    }
}

async fn accessible(cx: &Cx, writer: &ScopedSparseWriter) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), writer.get_stats(cx))
        .await.expect("completed receive retained writer admission")
        .unwrap().unwrap();
}
