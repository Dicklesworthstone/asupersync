//! Regression tests for stale verification and terminal writer reuse.

use super::*;
use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
use futures_lite::future::block_on;
use std::sync::atomic::{AtomicU64, Ordering};

fn unique_path(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "asupersync_sparse_lifecycle_{label}_{}_{}_{}",
        std::process::id(),
        nanos,
        NEXT.fetch_add(1, Ordering::Relaxed),
    ))
}

fn prepared_writer(content: &[u8], label: &str) -> (Cx, SparseWriter, Manifest, PathBuf) {
    let cx = Cx::for_testing();
    let object = Object::file(content.to_vec());
    let object_id = object.id.clone();
    let mut graph = ObjectGraph::new();
    graph.add_root(object).expect("test graph");
    let manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).expect("test manifest");
    let destination = unique_path(label);
    let writer = block_on(SparseWriter::new(
        &cx,
        object_id,
        &destination,
        SparseWriterConfig {
            enable_preallocation: false,
            enable_quarantine: false,
            ..SparseWriterConfig::default()
        },
    ))
    .unwrap();
    writer.set_expected_size(content.len() as u64).unwrap();
    block_on(writer.write_chunk(&cx, 0, content, WriteOptions::default())).unwrap();
    (cx, writer, manifest, destination)
}

#[test]
fn extending_verified_output_requires_new_verification() {
    let (cx, writer, manifest, destination) = prepared_writer(b"verified", "extend");
    block_on(writer.verify(&cx, &manifest)).unwrap();

    writer.set_expected_size(9).unwrap();
    assert_eq!(writer.get_stats().verification_state, VerificationState::Pending);
    block_on(writer.write_chunk(&cx, 8, b"!", WriteOptions::default())).unwrap();
    assert!(writer.is_complete());
    assert!(matches!(
        block_on(writer.commit(&cx)),
        Outcome::Err(SparseWriterError::NotVerified)
    ));
    assert!(!destination.exists());
    assert!(matches!(
        block_on(writer.verify(&cx, &manifest)),
        Outcome::Err(SparseWriterError::VerificationFailed(_))
    ));
}

#[test]
fn no_op_size_and_rejected_writes_preserve_verification() {
    let (cx, writer, manifest, destination) = prepared_writer(b"data", "rejected");
    block_on(writer.verify(&cx, &manifest)).unwrap();
    let verified = writer.get_stats().verification_state;

    writer.set_expected_size(4).unwrap();
    assert!(writer.set_expected_size(3).is_err());
    assert!(matches!(
        block_on(writer.write_chunk(&cx, 4, b"!", WriteOptions::default())),
        Outcome::Err(SparseWriterError::InvalidRange { .. })
    ));
    assert!(matches!(
        block_on(writer.write_chunk(&cx, 0, b"!", WriteOptions::default())),
        Outcome::Err(SparseWriterError::OverlappingWrite { .. })
    ));
    assert_eq!(writer.get_stats().verification_state, verified);
    assert_eq!(block_on(writer.commit(&cx)).unwrap(), destination);
    assert_eq!(std::fs::read(destination).unwrap(), b"data");
}

#[test]
fn committed_writer_cannot_recreate_staging_or_republish() {
    let (cx, writer, manifest, destination) = prepared_writer(b"data", "committed");
    block_on(writer.verify(&cx, &manifest)).unwrap();
    block_on(writer.commit(&cx)).unwrap();
    let before = writer.get_stats();

    assert!(writer.set_expected_size(8).is_err());
    assert!(matches!(
        block_on(writer.write_chunk(&cx, 0, b"evil", WriteOptions::default())),
        Outcome::Err(_)
    ));
    assert!(matches!(block_on(writer.verify(&cx, &manifest)), Outcome::Err(_)));
    assert!(matches!(block_on(writer.cancel(&cx)), Outcome::Err(_)));
    assert_eq!(block_on(writer.commit(&cx)).unwrap(), destination);
    let state = writer.lock_state();
    assert_eq!(state.lifecycle, WriterLifecycle::Committed);
    assert!(state.temp_file.is_none());
    assert!(state.temp_path.is_none());
    drop(state);
    assert_eq!(writer.get_stats().total_bytes_written, before.total_bytes_written);
    assert_eq!(std::fs::read(destination).unwrap(), b"data");
}

#[test]
fn cancellation_is_idempotent_and_cannot_resurrect_output() {
    let (cx, writer, manifest, destination) = prepared_writer(b"data", "cancelled");
    block_on(writer.verify(&cx, &manifest)).unwrap();
    block_on(writer.cancel(&cx)).unwrap();
    block_on(writer.cancel(&cx)).unwrap();

    assert!(writer.set_expected_size(8).is_err());
    assert!(matches!(
        block_on(writer.write_chunk(&cx, 0, b"evil", WriteOptions::default())),
        Outcome::Err(_)
    ));
    assert!(matches!(block_on(writer.verify(&cx, &manifest)), Outcome::Err(_)));
    assert!(matches!(block_on(writer.commit(&cx)), Outcome::Err(_)));
    let state = writer.lock_state();
    assert_eq!(state.lifecycle, WriterLifecycle::Cancelled);
    assert!(state.temp_file.is_none());
    assert!(state.temp_path.is_none());
    assert!(!destination.exists());
}

#[test]
fn failed_publication_keeps_evidence_and_refuses_blind_retry() {
    let (cx, writer, manifest, destination) = prepared_writer(b"data", "failed_commit");
    block_on(writer.verify(&cx, &manifest)).unwrap();
    let staging = writer.lock_state().temp_path.clone().unwrap();
    // A file cannot replace a directory. This fails the real publication step,
    // after the staging file's durability barrier has already completed.
    std::fs::create_dir(&destination).unwrap();
    assert!(matches!(block_on(writer.commit(&cx)), Outcome::Err(_)));
    assert_eq!(writer.lock_state().lifecycle, WriterLifecycle::Committing);
    assert_eq!(std::fs::read(&staging).unwrap(), b"data");

    assert!(writer.set_expected_size(8).is_err());
    assert!(matches!(
        block_on(writer.write_chunk(&cx, 0, b"evil", WriteOptions::default())),
        Outcome::Err(_)
    ));
    assert!(matches!(block_on(writer.verify(&cx, &manifest)), Outcome::Err(_)));
    assert!(matches!(block_on(writer.cancel(&cx)), Outcome::Err(_)));
    assert!(matches!(block_on(writer.commit(&cx)), Outcome::Err(_)));
    assert_eq!(std::fs::read(staging).unwrap(), b"data");
    assert!(destination.is_dir());
}

#[test]
fn concurrent_commits_observe_one_terminal_publication() {
    let (cx, writer, manifest, destination) = prepared_writer(b"data", "concurrent");
    block_on(writer.verify(&cx, &manifest)).unwrap();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            let cx = Cx::for_testing();
            barrier.wait();
            block_on(writer.commit(&cx))
        });
        let second = scope.spawn(|| {
            let cx = Cx::for_testing();
            barrier.wait();
            block_on(writer.commit(&cx))
        });
        assert_eq!(first.join().unwrap().unwrap(), destination);
        assert_eq!(second.join().unwrap().unwrap(), destination);
    });
    assert_eq!(std::fs::read(destination).unwrap(), b"data");
}

#[test]
fn failed_cancellation_cleanup_retains_ownership_for_retry() {
    let (cx, writer, _manifest, _destination) = prepared_writer(b"data", "cleanup_retry");
    let staging = writer.lock_state().temp_path.clone().unwrap();
    let not_a_file = unique_path("cleanup_failure");
    std::fs::create_dir(&not_a_file).unwrap();
    writer.lock_state().temp_path = Some(not_a_file.clone());

    assert!(matches!(block_on(writer.cancel(&cx)), Outcome::Err(_)));
    let state = writer.lock_state();
    assert_eq!(state.lifecycle, WriterLifecycle::Cancelling);
    assert_eq!(state.temp_path.as_ref(), Some(&not_a_file));
    assert!(state.temp_file.is_some());
    drop(state);
    assert!(writer.set_expected_size(8).is_err());

    // Restore the test-injected path fault; retry only the sealed cleanup.
    writer.lock_state().temp_path = Some(staging.clone());
    block_on(writer.cancel(&cx)).unwrap();
    assert_eq!(writer.lock_state().lifecycle, WriterLifecycle::Cancelled);
    assert!(!staging.exists());
}

#[test]
fn operation_serialization_preserves_send_futures() {
    fn assert_send<T: Send>(_: T) {}
    let (cx, writer, manifest, _destination) = prepared_writer(b"data", "send");
    // These futures are dropped unpolled. The compile-time bound catches a
    // parking_lot guard accidentally being held across a newly added await.
    assert_send(writer.write_chunk(&cx, 0, b"x", WriteOptions::default()));
    assert_send(writer.verify(&cx, &manifest));
    assert_send(writer.commit(&cx));
    assert_send(writer.cancel(&cx));
}
