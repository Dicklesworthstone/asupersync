//! Real-file restart journeys for the existing manifest sink and canonical writer.

use super::*;
use crate::atp::journal::CommitPolicy;
use crate::atp::manifest::{ChunkStrategy, MerkleRoot};
use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
use crate::io::AsyncWriteExt;
use crate::net::atp::sdk::native_auth::live::LiveStreamPrefix;
use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
use crate::security::{AuthKey, AuthenticationTag};
use std::future::poll_fn;
use std::time::Duration;

const TRANSFER: &str = "restore-live";
const DATA: &[u8] = b"abcdefghi";

struct RetainedFixture(PathBuf);

impl RetainedFixture {
    fn new() -> Self {
        Self(
            tempfile::Builder::new()
                .prefix("asupersync-manifest-restore-")
                .tempdir()
                .unwrap()
                .keep(),
        )
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new()
            .worker_threads(workers)
            .with_sharded_state(true)
    };
    builder.blocking_threads(1, 2).build().unwrap()
}

fn drained(runtime: Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0, "{report:?}");
    assert_eq!(report.live_regions, 0, "{report:?}");
    assert_eq!(report.pending_spawns, 0, "{report:?}");
    assert_eq!(report.pending_obligations, 0, "{report:?}");
    assert_eq!(report.queued_finalizers, 0, "{report:?}");
    assert!(!report.has_pending_obligation_posts, "{report:?}");
    assert!(runtime.is_quiescent());
    assert!(
        runtime.shutdown_timeout(Duration::from_secs(5)),
        "restore workers must retire"
    );
}

fn journal_config(base: &Path) -> JournalConfig {
    JournalConfig {
        base_dir: base.join("journal"),
        force_sync: false,
        max_journal_size: u64::MAX,
        ..JournalConfig::default()
    }
}

fn config(data: &[u8], destination: PathBuf, policy: CommitPolicy) -> ManifestFileSinkConfig {
    let object = Object::file(data.to_vec());
    let object_id = object.id.clone();
    let mut graph = ObjectGraph::new();
    graph.add_root(object).unwrap();
    ManifestFileSinkConfig {
        object_id,
        manifest: Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap()),
        expected_chunk_commitment: None,
        destination,
        writer: SparseWriterConfig {
            enable_preallocation: false,
            fsync_policy: FsyncPolicy::BeforeCommit,
            commit_policy: policy,
            ..SparseWriterConfig::default()
        },
        max_bytes: data.len() as u64,
        max_chunks: 100,
    }
}

fn pinned_hints(mut config: ManifestFileSinkConfig) -> ManifestFileSinkConfig {
    let manifest = Arc::make_mut(&mut config.manifest);
    manifest
        .objects
        .get_mut(&config.object_id)
        .unwrap()
        .chunk_boundaries = [(0, 2), (2, 8), (8, 9)]
        .into_iter()
        .enumerate()
        .map(|(index, (start, end))| ChunkBoundary {
            index: index as u32,
            byte_offset: start as u64,
            size_bytes: (end - start) as u64,
            content_hash: Sha256::digest(&DATA[start..end]).into(),
            strategy: ChunkStrategy::FixedSize,
            metadata: None,
        })
        .collect();
    manifest.merkle_root = MerkleRoot::from_manifest_components(
        &manifest.objects,
        &manifest.chunk_plan,
        &manifest.raptorq_layout,
        &manifest.compression_policy,
        &manifest.encryption_policy,
        &manifest.capability_policy,
        &manifest.transform_order,
        &manifest.transform_proof_policy,
        &manifest.repair_groups,
    );
    config.expected_chunk_commitment =
        Some(ManifestChunkCommitment::from_manifest(manifest).unwrap());
    config
}

fn restore_input(base: &Path, source_path: PathBuf) -> ManifestFileRestoreConfig {
    ManifestFileRestoreConfig {
        journal_config: journal_config(base),
        auth_key: AuthKey::from_seed(42),
        transfer_id: TRANSFER.to_owned(),
        source_path,
        timestamp: 82,
    }
}

fn receipt(data: &[u8]) -> LiveStreamReceipt {
    LiveStreamReceipt {
        prefix: LiveStreamPrefix {
            stream_nonce: [11; 32],
            epochs: u64::from(!data.is_empty()),
            bytes: data.len() as u64,
            chain: [12; 32],
        },
        source_sha256: Sha256::digest(data).into(),
    }
}

async fn commit(sink: &mut ManifestFileSink, data: &[u8]) -> io::Result<()> {
    let receipt = receipt(data);
    poll_fn(|task| Pin::new(&mut *sink).poll_commit(task, &receipt)).await
}

// This first runtime is completely drained and destroyed before the restoring
// runtime starts. The journal is compacted and closed, not handed over in memory.
fn checkpointed(
    base: &Path,
    config: &ManifestFileSinkConfig,
    prefix: &[u8],
    workers: usize,
) -> JournalCheckpoint {
    let runtime = runtime(workers);
    let saved = runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let mut sink = ManifestFileSink::new_journaled(
            &cx,
            config.clone(),
            ManifestFileJournalConfig {
                journal: AppendJournal::new(journal_config(base), AuthKey::from_seed(42)).unwrap(),
                transfer_id: TRANSFER.to_owned(),
                timestamp: 71,
            },
        )
        .await
        .unwrap();
        for bytes in prefix.chunks(3) {
            sink.write_all(bytes).await.unwrap();
        }
        sink.flush().await.unwrap();
        let saved = sink.journal_checkpoint().unwrap().clone();
        let mut journal = sink.release_journal().unwrap();
        drop(sink);
        cx.scoped_fs()
            .run_io(move |_| {
                journal.compact().unwrap();
                drop(journal);
                Ok(())
            })
            .await
            .unwrap();
        saved
    });
    drained(runtime);
    saved
}

fn journal_bytes(base: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut paths: Vec<_> = std::fs::read_dir(base.join("journal"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

fn empty_destination(base: &Path, config: &mut ManifestFileSinkConfig) -> PathBuf {
    let output = base.join("restore-output");
    std::fs::create_dir(&output).unwrap();
    config.destination = output.join("result");
    output
}

#[test]
fn restarted_manifest_sink_rebuilds_partial_chunk_hash_and_commits_durable_bytes() {
    for workers in [1, 2] {
        for policy in [
            CommitPolicy::AtomicRename,
            CommitPolicy::CopyAndVerify,
            CommitPolicy::LinkAndUnlink,
        ] {
            let directory = RetainedFixture::new();
            let path = directory.path().join("destination");
            let config = pinned_hints(config(DATA, path.clone(), policy));
            let saved = checkpointed(directory.path(), &config, &DATA[..5], workers);
            assert_eq!(saved.summary.durable_chunks.len(), 2);
            assert!(!path.exists());
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let mut sink = ManifestFileSink::restore_journaled(
                    &cx,
                    config,
                    restore_input(directory.path(), saved.source_path.clone()),
                )
                .await
                .unwrap();
                let restored = sink.journal_checkpoint().unwrap().clone();
                assert_ne!(restored.source_path, saved.source_path);
                assert_eq!(restored.summary.contiguous_prefix_bytes, 5);
                assert_eq!(
                    restored.summary.durable_chunks,
                    saved.summary.durable_chunks
                );
                assert_eq!(std::fs::read(&restored.source_path).unwrap(), &DATA[..5]);
                assert_eq!(sink.written_bytes(), 5);
                assert_eq!(sink.published_path(), None);
                assert_eq!(sink.journal_publication(), None);
                sink.write_all(&DATA[5..]).await.unwrap();
                sink.flush().await.unwrap();
                assert_eq!(sink.journal_checkpoint().unwrap().summary.durable_bytes, 9);
                commit(&mut sink, DATA).await.unwrap();
                assert_eq!(sink.published_path(), Some(path.as_path()));
                assert_eq!(
                    sink.journal_publication(),
                    Some(&JournalPublication::Confirmed(path.clone()))
                );
                assert_eq!(std::fs::read(&path).unwrap(), DATA);
                assert_eq!(std::fs::read(&saved.source_path).unwrap(), &DATA[..5]);
                let owner = sink.release_journal().unwrap();
                let reopen = journal_config(directory.path());
                let summary = cx
                    .scoped_fs()
                    .run_io(move |_| {
                        drop(owner);
                        let journal = AppendJournal::new(reopen, AuthKey::from_seed(42)).unwrap();
                        Ok(journal.get_resume_summary(TRANSFER).unwrap())
                    })
                    .await
                    .unwrap();
                assert_eq!(
                    summary.status,
                    TransferResumeStatus::Committed {
                        final_path: path.to_str().unwrap().to_owned(),
                        committed_size: 9,
                    }
                );
            });
            drained(runtime);
        }
    }
}

#[test]
fn empty_and_complete_receiving_checkpoints_still_require_explicit_final_commit() {
    for data in [b"".as_slice(), DATA] {
        let directory = RetainedFixture::new();
        let path = directory.path().join("destination");
        let config = config(data, path.clone(), CommitPolicy::AtomicRename);
        let saved = checkpointed(directory.path(), &config, data, 1);
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let mut sink = ManifestFileSink::restore_journaled(
                &cx,
                config,
                restore_input(directory.path(), saved.source_path.clone()),
            )
            .await
            .unwrap();
            assert_eq!(sink.written_bytes(), data.len() as u64);
            assert!(!path.exists());
            assert!(sink.journal_checkpoint().unwrap().source_path.is_file());
            commit(&mut sink, data).await.unwrap();
            assert_eq!(std::fs::read(path).unwrap(), data);
            assert_eq!(std::fs::read(saved.source_path).unwrap(), data);
        });
        drained(runtime);
    }
}

#[test]
fn restore_refuses_authority_identity_authentication_and_bounds_before_new_staging() {
    for case in 0..10 {
        let directory = RetainedFixture::new();
        let mut config = config(
            DATA,
            directory.path().join("initial"),
            CommitPolicy::AtomicRename,
        );
        let saved = checkpointed(directory.path(), &config, &DATA[..5], 1);
        let output = empty_destination(directory.path(), &mut config);
        let before = journal_bytes(directory.path());
        let mut restore = restore_input(directory.path(), saved.source_path.clone());
        match case {
            0 => {
                config = self::config(b"otherdata", config.destination, CommitPolicy::AtomicRename)
            }
            1 => config.object_id = Object::file(b"other".to_vec()).id,
            2 => config.expected_chunk_commitment = Some(ManifestChunkCommitment::new([0; 32])),
            3 => restore.auth_key = AuthKey::from_seed(99),
            4 => restore.transfer_id = "not-recorded".to_owned(),
            5 => config.writer.fsync_policy = FsyncPolicy::Never,
            6 => config.max_bytes = 8,
            7 => config.max_chunks = 1,
            8 => restore.journal_config.base_dir = directory.path().join("absent-journal"),
            9 => {
                // Same selected file and length, different independently valid graph root.
                let mut graph = ObjectGraph::new();
                graph.add_root(Object::file(DATA.to_vec())).unwrap();
                graph
                    .add_root(Object::file(b"another root".to_vec()))
                    .unwrap();
                config.manifest =
                    Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
            }
            _ => unreachable!(),
        }
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(
                ManifestFileSink::restore_journaled(&cx, config, restore)
                    .await
                    .is_err(),
                "case {case}"
            );
        });
        drained(runtime);
        assert_eq!(std::fs::read_dir(output).unwrap().count(), 0, "case {case}");
        assert!(!directory.path().join("absent-journal").exists());
        assert_eq!(std::fs::read(saved.source_path).unwrap(), &DATA[..5]);
        assert_eq!(journal_bytes(directory.path()), before);
    }
}

#[test]
fn corrupt_truncated_overlong_or_non_file_prefix_cannot_create_restored_staging() {
    for case in 0..5 {
        let directory = RetainedFixture::new();
        let mut config = config(
            DATA,
            directory.path().join("initial"),
            CommitPolicy::AtomicRename,
        );
        let saved = checkpointed(directory.path(), &config, &DATA[..5], 1);
        let output = empty_destination(directory.path(), &mut config);
        let before = journal_bytes(directory.path());
        let mut restore = restore_input(directory.path(), saved.source_path.clone());
        match case {
            0 => std::fs::write(&saved.source_path, b"wrong").unwrap(),
            1 => std::fs::write(&saved.source_path, b"abc").unwrap(),
            2 => std::fs::write(&saved.source_path, b"abcdefghij").unwrap(),
            3 => restore.source_path = directory.path().to_path_buf(),
            4 => restore.source_path = directory.path().join("missing-source"),
            _ => unreachable!(),
        }
        let retained = std::fs::read(&saved.source_path).unwrap();
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(
                ManifestFileSink::restore_journaled(&cx, config, restore)
                    .await
                    .is_err(),
                "case {case}"
            );
        });
        drained(runtime);
        assert_eq!(std::fs::read_dir(output).unwrap().count(), 0);
        assert_eq!(std::fs::read(saved.source_path).unwrap(), retained);
        assert_eq!(journal_bytes(directory.path()), before);
    }
}

#[test]
fn canonical_copy_rechecks_the_same_descriptor_after_preflight_mutation_or_name_swap() {
    for change_bytes in [true, false] {
        let directory = RetainedFixture::new();
        let config = pinned_hints(config(
            DATA,
            directory.path().join("destination"),
            CommitPolicy::AtomicRename,
        ));
        let saved = checkpointed(directory.path(), &config, &DATA[..5], 1);
        let before = journal_bytes(directory.path());
        let destination = config.destination.clone();
        let restore = restore_input(directory.path(), saved.source_path.clone());
        let moved = directory.path().join("original-prefix-moved");
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            // Both helpers are the exact production phases, including the same
            // scoped preflight and canonical receipt-copy implementation.
            let state = cx
                .scoped_fs()
                .run_io(move |child| {
                    prepare_restore(config, restore, || {
                        child
                            .checkpoint()
                            .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error))
                    })
                })
                .await
                .unwrap();
            if change_bytes {
                std::fs::write(&saved.source_path, b"WRONG").unwrap();
                assert!(
                    ManifestFileSink::restore_prepared(&cx, state)
                        .await
                        .is_err()
                );
                assert!(!destination.exists());
                assert_eq!(journal_bytes(directory.path()), before);
            } else {
                std::fs::rename(&saved.source_path, &moved).unwrap();
                std::fs::write(&saved.source_path, b"WRONG").unwrap();
                let mut sink = ManifestFileSink::restore_prepared(&cx, state)
                    .await
                    .unwrap();
                sink.write_all(&DATA[5..]).await.unwrap();
                commit(&mut sink, DATA).await.unwrap();
                assert_eq!(std::fs::read(&destination).unwrap(), DATA);
                assert_eq!(std::fs::read(&moved).unwrap(), &DATA[..5]);
            }
            assert_eq!(std::fs::read(&saved.source_path).unwrap(), b"WRONG");
        });
        drained(runtime);
    }
}

#[test]
fn restored_receipts_consume_the_original_budget_and_partial_hash_still_refuses_bad_suffix() {
    for bad_suffix in [false, true] {
        let directory = RetainedFixture::new();
        let mut config = pinned_hints(config(
            DATA,
            directory.path().join("destination"),
            CommitPolicy::AtomicRename,
        ));
        if !bad_suffix {
            config.max_chunks = 3;
        }
        let saved = checkpointed(directory.path(), &config, &DATA[..5], 1);
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let destination = config.destination.clone();
            let mut sink = ManifestFileSink::restore_journaled(
                &cx,
                config,
                restore_input(directory.path(), saved.source_path.clone()),
            )
            .await
            .unwrap();
            let new_path = sink.journal_checkpoint().unwrap().source_path.clone();
            if bad_suffix {
                assert!(sink.write_all(b"XYZ").await.is_err());
                assert_eq!(sink.written_bytes(), 5);
                assert_eq!(std::fs::read(new_path).unwrap(), &DATA[..5]);
            } else {
                assert_eq!(sink.write(b"f").await.unwrap(), 1);
                assert!(sink.write_all(b"ghi").await.is_err());
                assert_eq!(sink.written_bytes(), 6);
                assert_eq!(std::fs::read(new_path).unwrap(), &DATA[..6]);
            }
            assert!(commit(&mut sink, DATA).await.is_err());
            assert!(!destination.exists());
            assert_eq!(std::fs::read(&saved.source_path).unwrap(), &DATA[..5]);
        });
        drained(runtime);
    }
}

#[test]
fn terminal_or_unfinished_finalization_history_is_never_reopened_as_receiving() {
    for case in 0..4 {
        let directory = RetainedFixture::new();
        let mut config = config(
            DATA,
            directory.path().join("initial"),
            CommitPolicy::AtomicRename,
        );
        let saved = checkpointed(directory.path(), &config, &DATA[..5], 1);
        let mut journal =
            AppendJournal::new(journal_config(directory.path()), AuthKey::from_seed(42)).unwrap();
        let transfer_id = TRANSFER.to_owned();
        let auth_tag = AuthenticationTag::zero();
        let record = match case {
            0 => JournalRecord::CommitIntent {
                transfer_id,
                final_manifest_root: config.manifest.merkle_root.clone(),
                timestamp: 80,
                auth_tag,
            },
            1 => JournalRecord::CommitComplete {
                transfer_id,
                final_path: "diagnostic-only".to_owned(),
                committed_size: 9,
                timestamp: 80,
                auth_tag,
            },
            2 => JournalRecord::Cancellation {
                transfer_id,
                reason: "retained cancellation".to_owned(),
                timestamp: 80,
                auth_tag,
            },
            3 => JournalRecord::Rollback {
                transfer_id,
                rollback_reason: "retained rollback".to_owned(),
                checkpoint_sequence: 1,
                timestamp: 80,
                auth_tag,
            },
            _ => unreachable!(),
        };
        journal.append(record).unwrap();
        journal.flush().unwrap();
        drop(journal);
        let before = journal_bytes(directory.path());
        let output = empty_destination(directory.path(), &mut config);
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(
                ManifestFileSink::restore_journaled(
                    &cx,
                    config,
                    restore_input(directory.path(), saved.source_path.clone())
                )
                .await
                .is_err()
            );
        });
        drained(runtime);
        assert_eq!(std::fs::read_dir(output).unwrap().count(), 0);
        assert_eq!(std::fs::read(saved.source_path).unwrap(), &DATA[..5]);
        assert_eq!(journal_bytes(directory.path()), before);
    }
}

#[test]
fn noncontiguous_overlapping_or_incomplete_receipts_refuse_before_payload_open() {
    for case in 0..3 {
        let directory = RetainedFixture::new();
        let mut config = config(
            DATA,
            directory.path().join("initial"),
            CommitPolicy::AtomicRename,
        );
        let output = empty_destination(directory.path(), &mut config);
        let mut journal =
            AppendJournal::new(journal_config(directory.path()), AuthKey::from_seed(42)).unwrap();
        journal
            .append(JournalRecord::Offer {
                transfer_id: TRANSFER.to_owned(),
                object_id: config.object_id.clone(),
                manifest_root: config.manifest.merkle_root.clone(),
                total_size: 9,
                timestamp: 1,
                auth_tag: AuthenticationTag::zero(),
            })
            .unwrap();
        let ranges = if case == 0 {
            vec![(2, 5)]
        } else {
            vec![(0, 3), (2, 5)]
        };
        for (index, (start, end)) in ranges.into_iter().enumerate() {
            if case == 2 && index == 1 {
                break;
            }
            let hash = Sha256::digest(&DATA[start..end]).into();
            journal
                .append(JournalRecord::ChunkReceived {
                    transfer_id: TRANSFER.to_owned(),
                    chunk_offset: start as u64,
                    chunk_size: (end - start) as u64,
                    chunk_hash: hash,
                    timestamp: 2,
                    auth_tag: AuthenticationTag::zero(),
                })
                .unwrap();
            if case == 2 {
                // A torn checkpoint only persisted Received, not durable bytes.
                continue;
            }
            journal
                .append(JournalRecord::ChunkVerified {
                    transfer_id: TRANSFER.to_owned(),
                    chunk_offset: start as u64,
                    chunk_size: (end - start) as u64,
                    verified_hash: hash,
                    timestamp: 3,
                    auth_tag: AuthenticationTag::zero(),
                })
                .unwrap();
            journal
                .append(JournalRecord::ChunkWritten {
                    transfer_id: TRANSFER.to_owned(),
                    chunk_offset: start as u64,
                    chunk_size: (end - start) as u64,
                    file_path: "must-never-open".to_owned(),
                    timestamp: 4,
                    auth_tag: AuthenticationTag::zero(),
                })
                .unwrap();
        }
        journal.flush().unwrap();
        drop(journal);
        let before = journal_bytes(directory.path());
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let error = ManifestFileSink::restore_journaled(
                &cx,
                config,
                restore_input(directory.path(), directory.path().join("missing-source")),
            )
            .await
            .unwrap_err();
            assert!(
                error.to_string().contains("checkpoint")
                    || error.to_string().contains("overlap")
                    || error.to_string().contains("receipt"),
                "case {case}: {error}"
            );
        });
        drained(runtime);
        assert_eq!(std::fs::read_dir(output).unwrap().count(), 0);
        assert_eq!(journal_bytes(directory.path()), before);
    }
}
