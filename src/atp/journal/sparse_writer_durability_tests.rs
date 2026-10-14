//! Empty-object and terminal durability barrier regression tests.

use super::*;
use crate::atp::journal::FsyncPolicy;
use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
use futures_lite::future::block_on;
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

fn prepared_writer(
    content: &[u8],
    config: SparseWriterConfig,
) -> (Cx, SparseWriter, Manifest, PathBuf) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock")
        .as_nanos();
    let destination = std::env::temp_dir().join(format!(
        "asupersync_sparse_durability_{}_{}_{}",
        std::process::id(),
        nanos,
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    let cx = Cx::for_testing();
    let object = Object::file(content.to_vec());
    let object_id = object.id.clone();
    let mut graph = ObjectGraph::new();
    graph.add_root(object).expect("test graph");
    let manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).expect("test manifest");
    let writer = block_on(SparseWriter::new(&cx, object_id, &destination, config)).unwrap();
    writer.set_expected_size(content.len() as u64).unwrap();
    if !content.is_empty() {
        block_on(writer.write_chunk(&cx, 0, content, WriteOptions::default())).unwrap();
    }
    (cx, writer, manifest, destination)
}

#[test]
fn empty_objects_verify_and_commit_across_publication_and_sync_policies() {
    for commit_policy in [
        CommitPolicy::AtomicRename,
        CommitPolicy::CopyAndVerify,
        CommitPolicy::LinkAndUnlink,
    ] {
        for fsync_policy in [
            FsyncPolicy::Never,
            FsyncPolicy::EveryWrite,
            FsyncPolicy::VerifiedChunks,
            FsyncPolicy::BeforeCommit,
        ] {
            for enable_preallocation in [false, true] {
                let (cx, writer, manifest, destination) = prepared_writer(
                    b"",
                    SparseWriterConfig {
                        commit_policy,
                        fsync_policy,
                        enable_preallocation,
                        ..SparseWriterConfig::default()
                    },
                );
                assert!(writer.is_complete());
                assert!(writer.lock_state().temp_file.is_none());
                block_on(writer.verify(&cx, &manifest)).unwrap();
                let state = writer.lock_state();
                assert!(state.temp_file.is_some());
                assert!(state.written_chunks.is_empty());
                assert_eq!(state.temp_file.as_ref().unwrap().metadata().unwrap().len(), 0);
                drop(state);

                assert_eq!(block_on(writer.commit(&cx)).unwrap(), destination);
                assert_eq!(block_on(writer.commit(&cx)).unwrap(), destination);
                assert!(std::fs::read(&destination).unwrap().is_empty());
                assert_eq!(writer.get_stats().total_bytes_written, 0);
                assert_eq!(writer.get_stats().completion_ratio, 1.0);
            }
        }
    }
}

#[test]
fn every_durable_policy_runs_a_final_barrier_even_for_synced_chunks() {
    for fsync_policy in [
        FsyncPolicy::EveryWrite,
        FsyncPolicy::VerifiedChunks,
        FsyncPolicy::BeforeCommit,
    ] {
        let (cx, writer, manifest, destination) = prepared_writer(
            b"data",
            SparseWriterConfig {
                fsync_policy,
                enable_preallocation: false,
                ..SparseWriterConfig::default()
            },
        );
        block_on(writer.verify(&cx, &manifest)).unwrap();
        for chunk in writer.lock_state().written_chunks.values_mut() {
            chunk.synced = true;
        }
        let called = Cell::new(false);
        let result = writer.commit_with_fsync(|_| {
            called.set(true);
            Err(std::io::Error::other("injected terminal sync failure"))
        });
        assert!(called.get());
        assert!(matches!(result, Outcome::Err(SparseWriterError::SyncFailed(_))));
        assert!(!destination.exists());
        assert_eq!(writer.lock_state().lifecycle, WriterLifecycle::Committing);
        assert!(writer.lock_state().temp_file.is_some());
        assert!(matches!(block_on(writer.commit(&cx)), Outcome::Err(_)));
    }
}

#[test]
fn failed_barrier_does_not_mark_unsynced_chunks_as_durable() {
    let (cx, writer, manifest, _destination) = prepared_writer(
        b"data",
        SparseWriterConfig {
            fsync_policy: FsyncPolicy::BeforeCommit,
            enable_preallocation: false,
            ..SparseWriterConfig::default()
        },
    );
    block_on(writer.verify(&cx, &manifest)).unwrap();
    assert!(writer.lock_state().written_chunks.values().all(|chunk| !chunk.synced));
    assert!(matches!(
        writer.apply_fsync_policy_with(|_| Err(std::io::Error::other("injected sync failure"))),
        Outcome::Err(SparseWriterError::SyncFailed(_))
    ));
    assert!(writer.lock_state().written_chunks.values().all(|chunk| !chunk.synced));
    writer.apply_fsync_policy_with(File::sync_all).unwrap();
    assert!(writer.lock_state().written_chunks.values().all(|chunk| chunk.synced));
}

#[test]
fn never_policy_does_not_run_a_barrier_or_upgrade_chunk_evidence() {
    let (cx, writer, manifest, _destination) = prepared_writer(
        b"data",
        SparseWriterConfig {
            fsync_policy: FsyncPolicy::Never,
            enable_preallocation: false,
            ..SparseWriterConfig::default()
        },
    );
    block_on(writer.verify(&cx, &manifest)).unwrap();
    writer
        .apply_fsync_policy_with(|_| panic!("Never must not request a sync"))
        .unwrap();
    assert!(writer.lock_state().written_chunks.values().all(|chunk| !chunk.synced));
}

#[test]
fn absent_staging_descriptor_cannot_bypass_the_commit_barrier() {
    for fsync_policy in [
        FsyncPolicy::Never,
        FsyncPolicy::EveryWrite,
        FsyncPolicy::VerifiedChunks,
        FsyncPolicy::BeforeCommit,
    ] {
        let (cx, writer, manifest, destination) = prepared_writer(
            b"data",
            SparseWriterConfig {
                fsync_policy,
                enable_preallocation: false,
                ..SparseWriterConfig::default()
            },
        );
        block_on(writer.verify(&cx, &manifest)).unwrap();
        let staging = writer.lock_state().temp_path.clone().unwrap();
        let _retained_descriptor = writer.lock_state().temp_file.take().unwrap();
        assert!(matches!(
            block_on(writer.commit(&cx)),
            Outcome::Err(SparseWriterError::NoTempFile)
        ));
        assert_eq!(writer.lock_state().lifecycle, WriterLifecycle::Committing);
        assert!(!destination.exists());
        assert_eq!(std::fs::read(staging).unwrap(), b"data");
    }
}

#[test]
fn nonempty_objects_commit_across_publication_and_sync_policies() {
    let data = b"verified nonempty transfer with final inode barrier";
    for commit_policy in [
        CommitPolicy::AtomicRename,
        CommitPolicy::CopyAndVerify,
        CommitPolicy::LinkAndUnlink,
    ] {
        for fsync_policy in [
            FsyncPolicy::Never,
            FsyncPolicy::EveryWrite,
            FsyncPolicy::VerifiedChunks,
            FsyncPolicy::BeforeCommit,
        ] {
            let (cx, writer, manifest, destination) = prepared_writer(
                data,
                SparseWriterConfig {
                    commit_policy,
                    fsync_policy,
                    enable_preallocation: false,
                    ..SparseWriterConfig::default()
                },
            );
            block_on(writer.verify(&cx, &manifest)).unwrap();
            assert_eq!(block_on(writer.commit(&cx)).unwrap(), destination);
            assert_eq!(std::fs::read(destination).unwrap(), data);
            assert_eq!(writer.lock_state().lifecycle, WriterLifecycle::Committed);
        }
    }
}

#[test]
fn empty_objects_cannot_publish_after_a_failed_final_barrier() {
    for fsync_policy in [
        FsyncPolicy::EveryWrite,
        FsyncPolicy::VerifiedChunks,
        FsyncPolicy::BeforeCommit,
    ] {
        let (cx, writer, manifest, destination) = prepared_writer(
            b"",
            SparseWriterConfig {
                fsync_policy,
                enable_preallocation: false,
                ..SparseWriterConfig::default()
            },
        );
        block_on(writer.verify(&cx, &manifest)).unwrap();
        let called = Cell::new(false);
        assert!(matches!(
            writer.commit_with_fsync(|_| {
                called.set(true);
                Err(std::io::Error::other("injected empty inode sync failure"))
            }),
            Outcome::Err(SparseWriterError::SyncFailed(_))
        ));
        assert!(called.get());
        assert!(!destination.exists());
        let state = writer.lock_state();
        assert_eq!(state.lifecycle, WriterLifecycle::Committing);
        assert!(state.temp_path.as_ref().unwrap().is_file());
        assert_eq!(state.temp_file.as_ref().unwrap().metadata().unwrap().len(), 0);
    }
}
