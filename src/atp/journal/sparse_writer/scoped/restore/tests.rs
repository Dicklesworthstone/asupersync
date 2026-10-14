use super::*;
use crate::atp::journal::{CommitPolicy, JournalConfig, ScopedReceiveOptions};
use crate::atp::journal::sparse_writer::VerificationState;
use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
use crate::io::{AsyncRead, AsyncReadExt, ReadBuf};
use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
use crate::security::{AuthKey, AuthenticationTag};
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::new().worker_threads(workers) };
    builder.blocking_threads(1, 2).build().unwrap()
}

fn drain(runtime: &Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

fn limits() -> JournalRestoreLimits {
    JournalRestoreLimits { max_bytes: 1024, max_chunks: 16, max_chunk_bytes: 8 }
}

fn config(policy: CommitPolicy) -> SparseWriterConfig {
    SparseWriterConfig {
        enable_preallocation: false,
        enable_quarantine: false,
        commit_policy: policy,
        ..SparseWriterConfig::default()
    }
}

fn setup(root: &Path, data: &[u8], ranges: &[(usize, usize)])
    -> (AppendJournal, Arc<Manifest>, PathBuf)
{
    let object = Object::file(data.to_vec());
    let id = object.id.clone();
    let mut graph = ObjectGraph::new();
    graph.add_root(object).unwrap();
    let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
    let journal_config = JournalConfig {
        base_dir: root.join("journal"), max_journal_size: u64::MAX,
        max_generations: 0, ..JournalConfig::default()
    };
    let mut journal = AppendJournal::new(journal_config.clone(), AuthKey::from_seed(42)).unwrap();
    journal.append(JournalRecord::Offer {
        transfer_id: "transfer".to_owned(), object_id: id,
        manifest_root: manifest.merkle_root.clone(), total_size: data.len() as u64,
        timestamp: 1, auth_tag: AuthenticationTag::zero(),
    }).unwrap();
    for &(start, end) in ranges {
        let hash: [u8; 32] = Sha256::digest(&data[start..end]).into();
        journal.append(JournalRecord::ChunkReceived {
            transfer_id: "transfer".to_owned(), chunk_offset: start as u64,
            chunk_size: (end - start) as u64, chunk_hash: hash,
            timestamp: 2, auth_tag: AuthenticationTag::zero(),
        }).unwrap();
        journal.append(JournalRecord::ChunkVerified {
            transfer_id: "transfer".to_owned(), chunk_offset: start as u64,
            chunk_size: (end - start) as u64, verified_hash: hash,
            timestamp: 3, auth_tag: AuthenticationTag::zero(),
        }).unwrap();
        journal.append(JournalRecord::ChunkWritten {
            transfer_id: "transfer".to_owned(), chunk_offset: start as u64,
            chunk_size: (end - start) as u64,
            // Must never be interpreted as filesystem authority by restoration.
            file_path: "/not-opened/from-journal".to_owned(),
            timestamp: 4, auth_tag: AuthenticationTag::zero(),
        }).unwrap();
    }
    journal.compact().unwrap();
    drop(journal);
    let reopened = AppendJournal::new(journal_config, AuthKey::from_seed(42)).unwrap();
    let source = root.join("old-payload");
    std::fs::write(&source, data).unwrap();
    (reopened, manifest, source)
}

struct Bytes(&'static [u8]);

impl AsyncRead for Bytes {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let count = this.0.len().min(buf.remaining()).min(2);
        buf.put_slice(&this.0[..count]);
        this.0 = &this.0[count..];
        Poll::Ready(Ok(()))
    }
}

#[test]
fn reopened_prefix_resumes_only_the_suffix_and_retains_next_frame() {
    for workers in [1, 2] {
        for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
            let root = tempfile::tempdir().unwrap();
            let (journal, manifest, source) = setup(root.path(), b"abcdefgh", &[(0, 3)]);
            // Unreceipted bytes are not imported, even though they exist locally.
            std::fs::write(&source, b"abcXXXXX").unwrap();
            let destination = root.path().join("final");
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let writer = ScopedSparseWriter::restore_from_journal(
                    &cx, Arc::new(journal), "transfer".to_owned(), File::open(&source).unwrap(),
                    destination.clone(), config(policy), limits(),
                ).await.unwrap().unwrap();
                assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), 3);
                let stats = writer.get_stats(&cx).await.unwrap().unwrap();
                assert_eq!(stats.total_bytes_written, 3);
                assert_eq!(stats.chunk_count, 1);
                assert_eq!(stats.verification_state, VerificationState::Pending);
                assert!(!destination.exists());
                assert_eq!(std::fs::read(&source).unwrap(), b"abcXXXXX");
                let mut receive = writer.resume_exact_at(
                    &cx, Bytes(b"defghNEXT"), manifest,
                    ScopedReceiveOptions { max_bytes: 8, max_chunks: 4, chunk_size: 3 }, 3,
                ).unwrap();
                assert_eq!(receive.wait().await.unwrap().unwrap(), destination);
                let mut next = receive.take_source().unwrap();
                let mut frame = [0; 4];
                next.read_exact(&mut frame).await.unwrap();
                assert_eq!(&frame, b"NEXT");
                assert_eq!(std::fs::read(&destination).unwrap(), b"abcdefgh");
                assert_eq!(std::fs::read(&source).unwrap(), b"abcXXXXX");
            });
            drain(&runtime);
        }
    }
}

#[test]
fn sparse_restoration_preserves_holes_and_uses_existing_out_of_order_finalization() {
    let root = tempfile::tempdir().unwrap();
    let (journal, manifest, source) = setup(root.path(), b"abcdefgh", &[(0, 2), (4, 8)]);
    let destination = root.path().join("final");
    let runtime = runtime(2);
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let writer = ScopedSparseWriter::restore_from_journal(
            &cx, Arc::new(journal), "transfer".to_owned(), File::open(&source).unwrap(),
            destination.clone(), config(CommitPolicy::AtomicRename), limits(),
        ).await.unwrap().unwrap();
        assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().total_bytes_written, 6);
        assert!(!writer.is_complete(&cx).await.unwrap().unwrap());
        assert!(matches!(writer.commit(&cx).await.unwrap(), Outcome::Err(SparseWriterError::IncompleteData)));
        writer.write_chunk(&cx, 2, b"cd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
        writer.verify_and_commit(&cx, manifest).await.unwrap().unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), b"abcdefgh");
        assert_eq!(std::fs::read(source).unwrap(), b"abcdefgh");
    });
    drain(&runtime);
}

#[test]
fn complete_and_empty_restores_never_inherit_commit_authorization() {
    for data in [b"abcdefgh".as_slice(), b"".as_slice()] {
        let root = tempfile::tempdir().unwrap();
        let ranges = if data.is_empty() { vec![] } else { vec![(0, 4), (4, 8)] };
        let (journal, manifest, source) = setup(root.path(), data, &ranges);
        let destination = root.path().join("final");
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let writer = ScopedSparseWriter::restore_from_journal(
                &cx, Arc::new(journal), "transfer".to_owned(), File::open(&source).unwrap(),
                destination.clone(), config(CommitPolicy::CopyAndVerify), limits(),
            ).await.unwrap().unwrap();
            assert!(writer.is_complete(&cx).await.unwrap().unwrap());
            assert!(matches!(writer.commit(&cx).await.unwrap(), Outcome::Err(SparseWriterError::NotVerified)));
            assert!(!destination.exists());
            writer.verify_and_commit(&cx, manifest).await.unwrap().unwrap();
            assert_eq!(std::fs::read(destination).unwrap(), data);
        });
        drain(&runtime);
    }
}

#[test]
fn corrupt_or_truncated_payload_cannot_be_restored_and_source_is_preserved() {
    for bytes in [b"abcdEFGH".as_slice(), b"abc".as_slice(), b"abcdefghi".as_slice()] {
        let root = tempfile::tempdir().unwrap();
        let (journal, _, source) = setup(root.path(), b"abcdefgh", &[(0, 4), (4, 8)]);
        std::fs::write(&source, bytes).unwrap();
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let result = ScopedSparseWriter::restore_from_journal(
                &cx, Arc::new(journal), "transfer".to_owned(), File::open(&source).unwrap(),
                root.path().join("final"), config(CommitPolicy::AtomicRename), limits(),
            ).await.unwrap();
            assert!(matches!(result, Outcome::Err(SparseWriterError::VerificationFailed(_))));
        });
        drain(&runtime);
        assert_eq!(std::fs::read(source).unwrap(), bytes);
        assert!(!root.path().join("final").exists());
        assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry.unwrap().file_name().to_string_lossy().ends_with(".tmp")
        }));
    }
}

#[test]
fn preflight_limits_and_offer_conflicts_have_no_writer_effects() {
    for case in 0..6 {
        let root = tempfile::tempdir().unwrap();
        let (mut journal, manifest, source) = setup(root.path(), b"abcdefgh", &[(0, 4)]);
        let mut bounds = limits();
        match case {
            0 => bounds.max_bytes = 7,
            1 => bounds.max_chunks = 0,
            2 => bounds.max_chunk_bytes = 3,
            3 => bounds.max_chunk_bytes = 0,
            4 | 5 => {
                journal.append(JournalRecord::Offer {
                    transfer_id: "transfer".to_owned(),
                    object_id: if case == 4 { Object::file(b"different".to_vec()).id }
                        else { manifest.roots[0].clone() },
                    manifest_root: if case == 5 { crate::atp::manifest::MerkleRoot::new([9; 32]) }
                        else { manifest.merkle_root.clone() },
                    total_size: 8, timestamp: 5, auth_tag: AuthenticationTag::zero(),
                }).unwrap();
            }
            _ => unreachable!(),
        }
        let runtime = runtime(1);
        runtime.block_on(async {
            let result = ScopedSparseWriter::restore_from_journal(
                &Cx::current().unwrap(), Arc::new(journal), "transfer".to_owned(),
                File::open(&source).unwrap(), root.path().join("final"),
                config(CommitPolicy::AtomicRename), bounds,
            ).await.unwrap();
            assert!(matches!(result, Outcome::Err(SparseWriterError::VerificationFailed(_))));
        });
        drain(&runtime);
        assert!(!root.path().join(".quarantine").exists());
        assert!(!root.path().join("final").exists());
        assert_eq!(std::fs::read(source).unwrap(), b"abcdefgh");
    }
}

#[test]
fn terminal_unknown_and_wrong_key_journals_refuse_before_copying() {
    for case in 0..6 {
        let root = tempfile::tempdir().unwrap();
        let (mut journal, manifest, source) = setup(root.path(), b"abcdefgh", &[(0, 4)]);
        let tag = AuthenticationTag::zero();
        let id = "transfer".to_owned();
        let record = match case {
            0 => Some(JournalRecord::Cancellation { transfer_id: id, reason: "stop".to_owned(), timestamp: 8, auth_tag: tag }),
            1 => Some(JournalRecord::Rollback { transfer_id: id, rollback_reason: "retry".to_owned(), checkpoint_sequence: 0, timestamp: 8, auth_tag: tag }),
            2 => Some(JournalRecord::CommitIntent { transfer_id: id, final_manifest_root: manifest.merkle_root.clone(), timestamp: 8, auth_tag: tag }),
            3 => Some(JournalRecord::CommitComplete { transfer_id: id, final_path: "already-finished".to_owned(), committed_size: 8, timestamp: 8, auth_tag: tag }),
            _ => None,
        };
        if let Some(record) = record { journal.append(record).unwrap(); }
        if case == 5 {
            drop(journal);
            journal = AppendJournal::new(JournalConfig {
                base_dir: root.path().join("journal"), ..JournalConfig::default()
            }, AuthKey::from_seed(43)).unwrap();
        }
        let runtime = runtime(1);
        runtime.block_on(async {
            let result = ScopedSparseWriter::restore_from_journal(
                &Cx::current().unwrap(), Arc::new(journal),
                if case == 4 { "unknown" } else { "transfer" }.to_owned(),
                File::open(&source).unwrap(), root.path().join("final"),
                config(CommitPolicy::AtomicRename), limits(),
            ).await.unwrap();
            assert!(matches!(result, Outcome::Err(SparseWriterError::VerificationFailed(_))));
        });
        drain(&runtime);
        assert!(!root.path().join(".quarantine").exists());
        assert!(!root.path().join("final").exists());
    }
}

#[test]
fn checkpoint_failure_cleans_only_new_staging_after_a_copied_prefix() {
    let root = tempfile::tempdir().unwrap();
    let (journal, _, source) = setup(root.path(), b"abcdefgh", &[(0, 4), (4, 8)]);
    let plan = restore_plan(&journal, "transfer", limits()).unwrap();
    let destination = root.path().join("final");
    let mut checks = 0;
    let result = restore_file(File::open(&source).unwrap(), destination.clone(),
        config(CommitPolicy::AtomicRename), plan, || {
            checks += 1;
            if checks == 6 {
                // The first receipt has been copied before the second begins.
                assert!(std::fs::read_dir(root.path()).unwrap().any(|entry| {
                    entry.unwrap().file_name().to_string_lossy().ends_with(".tmp")
                }));
                Err(io::Error::new(io::ErrorKind::Interrupted, "checkpoint witness"))
            } else { Ok(()) }
        });
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Interrupted));
    assert_eq!(checks, 6);
    assert_eq!(std::fs::read(source).unwrap(), b"abcdefgh");
    assert!(!destination.exists());
    assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| {
        !entry.unwrap().file_name().to_string_lossy().ends_with(".tmp")
    }));
}

#[test]
fn lazy_restore_is_send_and_does_not_create_a_writer() {
    fn assert_send<T: Send>(_: &T) {}
    let root = tempfile::tempdir().unwrap();
    let (journal, _, source) = setup(root.path(), b"abcdefgh", &[(0, 4)]);
    let cx = Cx::for_testing();
    let work = ScopedSparseWriter::restore_from_journal(
        &cx, Arc::new(journal), "transfer".to_owned(), File::open(&source).unwrap(),
        root.path().join("final"), config(CommitPolicy::AtomicRename), limits(),
    );
    assert_send(&work);
    drop(work);
    assert!(!root.path().join(".quarantine").exists());
    assert!(!root.path().join("final").exists());
    assert_eq!(std::fs::read(source).unwrap(), b"abcdefgh");
}
