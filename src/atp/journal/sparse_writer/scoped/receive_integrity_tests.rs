//! Ingestion behavior and direct-range hash controls.

use super::*;
use crate::atp::journal::CommitPolicy;
use crate::atp::journal::sparse_writer::VerificationState;
use crate::atp::manifest::{ChunkStrategy, MerkleRoot};
use crate::atp::object::{ManifestId, MetadataPolicy, Object, ObjectGraph};
use crate::io::ReadBuf;
use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::{Context, Waker};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Probe {
    consumed: AtomicUsize,
    polls: AtomicUsize,
    parked: AtomicBool,
    released: AtomicBool,
    wake: parking_lot::Mutex<Option<Waker>>,
}

struct Source {
    bytes: Vec<u8>,
    position: usize,
    fragment: usize,
    pause_at: Option<usize>,
    probe: Arc<Probe>,
}

impl Source {
    fn new(bytes: &[u8], fragment: usize) -> (Self, Arc<Probe>) {
        let probe = Arc::new(Probe::default());
        (Self {
            bytes: bytes.to_vec(), position: 0, fragment, pause_at: None,
            probe: Arc::clone(&probe),
        }, probe)
    }
}

impl AsyncRead for Source {
    fn poll_read(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.probe.polls.fetch_add(1, Ordering::SeqCst);
        let paused = !this.probe.released.load(Ordering::SeqCst);
        if paused && this.pause_at.is_some_and(|at| this.position >= at) {
            *this.probe.wake.lock() = Some(task.waker().clone());
            this.probe.parked.store(true, Ordering::SeqCst);
            return Poll::Pending;
        }
        let mut count = this.fragment.min(buf.remaining()).min(this.bytes.len() - this.position);
        if paused && let Some(at) = this.pause_at {
            count = count.min(at.saturating_sub(this.position));
        }
        buf.put_slice(&this.bytes[this.position..this.position + count]);
        this.position += count;
        this.probe.consumed.store(this.position, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

fn refresh(manifest: &mut Manifest) {
    manifest.merkle_root = MerkleRoot::from_manifest_components(
        &manifest.objects, &manifest.chunk_plan, &manifest.raptorq_layout,
        &manifest.compression_policy, &manifest.encryption_policy, &manifest.capability_policy,
        &manifest.transform_order, &manifest.transform_proof_policy, &manifest.repair_groups,
    );
    manifest.validate().unwrap();
}

fn fixture(bytes: &[u8], ranges: &[(usize, usize)], pinned_only: bool) -> (ObjectId, Arc<Manifest>) {
    let object = Object::file(bytes.to_vec());
    let old_id = object.id.clone();
    let mut graph = ObjectGraph::new();
    graph.add_root(object).unwrap();
    let mut manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
    let id = if pinned_only {
        ObjectId::manifest(ManifestId::from_manifest_bytes(b"incremental-receive-object"))
    } else {
        old_id.clone()
    };
    let mut record = manifest.objects.remove(&old_id).unwrap();
    record.id = id.clone();
    if pinned_only { record.content_hash = None; }
    record.chunk_boundaries = ranges.iter().enumerate().map(|(index, &(start, end))| ChunkBoundary {
        index: index as u32,
        byte_offset: start as u64,
        size_bytes: (end - start) as u64,
        content_hash: Sha256::digest(&bytes[start..end]).into(),
        strategy: ChunkStrategy::FixedSize,
        metadata: None,
    }).collect();
    manifest.objects.insert(id.clone(), record);
    manifest.roots = vec![id.clone()];
    refresh(&mut manifest);
    (id, Arc::new(manifest))
}

fn checker(id: ObjectId, manifest: Arc<Manifest>, length: u64) -> ReceiveIntegrity {
    ReceiveIntegrity::validate_ranges(&manifest.objects[&id].chunk_boundaries, length).unwrap();
    ReceiveIntegrity { manifest, object_id: id, length, offset: 0, origin: 0, next: 0, partial: None }
}

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

fn options(chunk_size: usize) -> ScopedReceiveOptions {
    ScopedReceiveOptions { max_bytes: 64, max_chunks: 64, chunk_size }
}

async fn writer(cx: &Cx, id: ObjectId, path: PathBuf, policy: CommitPolicy) -> ScopedSparseWriter {
    ScopedSparseWriter::new(cx, id, path, SparseWriterConfig {
        enable_preallocation: false, commit_policy: policy, ..SparseWriterConfig::default()
    }).await.unwrap().unwrap()
}

fn refusal(result: ScopedReceiveResult<PathBuf>) -> String {
    match result {
        Ok(Outcome::Err(SparseWriterError::VerificationFailed(reason))) => reason,
        other => panic!("wrong receive failure: {other:?}"),
    }
}

#[test]
fn canonical_reader_fragmentations_match_direct_range_hashes() {
    let original = b"abcdefghijkl";
    let layouts = [
        vec![], vec![(0, 12)], vec![(0, 4), (4, 8), (8, 12)],
        vec![(2, 5), (7, 11)], vec![(0, 0), (0, 4), (4, 4), (4, 12), (12, 12)],
    ];
    for ranges in layouts {
        for chunk_size in [1, 2, 3, 4, 7, 16] {
            for fragment in [1, 3, 64] {
                for mutation in 0..=original.len() {
                    let mut data = original.to_vec();
                    if mutation < data.len() { data[mutation] ^= 1; }
                    let (id, manifest) = fixture(original, &ranges, false);
                    let direct = manifest.objects[&id].chunk_boundaries.iter().all(|boundary| {
                        let from = boundary.byte_offset as usize;
                        let to = from + boundary.size_bytes as usize;
                        let actual: [u8; 32] = Sha256::digest(&data[from..to]).into();
                        actual == boundary.content_hash
                    });
                    let mut checking = checker(id, manifest, original.len() as u64);
                    let (source, _) = Source::new(&data, fragment);
                    let mut reader = StreamChunkReader::new(source, chunk_size).unwrap();
                    let incremental = futures_lite::future::block_on(async {
                        while let Some(chunk) = reader.next_chunk().await.unwrap() {
                            checking.check_chunk(&chunk)?;
                        }
                        checking.finish()
                    });
                    assert_eq!(incremental.is_ok(), direct,
                        "ranges={ranges:?} chunk_size={chunk_size} fragment={fragment} mutation={mutation}");
                }
            }
        }
    }
}

#[test]
fn bad_hint_ranges_and_empty_digests_refuse_before_source_or_staging() {
    let runtime = runtime(2);
    let directory = tempfile::tempdir().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        for case in 0..3 {
            let data = if case == 2 { b"".as_slice() } else { b"abcdefghijkl".as_slice() };
            let (id, mut expected) = fixture(data, &[(0, 0)], false);
            let boundary = &mut Arc::make_mut(&mut expected).objects.get_mut(&id).unwrap().chunk_boundaries[0];
            if case == 0 {
                boundary.byte_offset = 12;
                boundary.size_bytes = 1;
            } else {
                boundary.content_hash[0] ^= 1;
            }
            // These malformed hints passed the existing structural validator.
            refresh(Arc::make_mut(&mut expected));
            let path = directory.path().join(format!("refused-{case}"));
            let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
            let (source, probe) = Source::new(data, 1);
            let mut session = writer.receive_exact(&cx, source, expected, options(4)).unwrap();
            let reason = refusal(session.wait().await);
            assert!(reason.contains(if case == 0 { "exceeds receive length" } else { "hash mismatch" }));
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            assert!(writer.writer.lock_state().temp_file.is_none());
            assert_eq!(writer.admission.available_permits(), 1);
            assert!(!path.exists());
        }
    });
    drained(&runtime);
    let mut overflow = fixture(b"", &[(0, 0)], false).1.objects.values().next().unwrap().chunk_boundaries[0].clone();
    overflow.byte_offset = u64::MAX;
    overflow.size_bytes = 1;
    assert!(ReceiveIntegrity::validate_ranges(&[overflow], u64::MAX).is_err());
}

#[test]
fn corruption_stops_ingestion_at_the_completing_batch_before_it_is_written() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for first_end in [4, 6] {
                let (id, expected) = fixture(b"abcdefghijkl", &[(0, first_end), (first_end, 12)], false);
                let path = directory.path().join(format!("bad-{first_end}"));
                let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
                let (source, probe) = Source::new(b"Xbcdefghijkl", 1);
                let mut session = writer.receive_exact(&cx, source, expected, options(4)).unwrap();
                assert_eq!(refusal(session.wait().await), "manifest chunk 0 hash mismatch");
                let consumed = if first_end == 4 { 4 } else { 8 };
                assert_eq!(probe.consumed.load(Ordering::SeqCst), consumed);
                assert_eq!(session.accepted_bytes(), (consumed - 4) as u64);
                assert!(session.take_source().is_none());
                assert!(!path.exists());
                assert_eq!(writer.admission.available_permits(), 1);
                {
                    let state = writer.writer.lock_state();
                    assert_eq!(state.written_chunks.len(), usize::from(first_end != 4));
                    assert_eq!(state.verification_state, VerificationState::Failed {
                        reason: "manifest chunk 0 hash mismatch".to_owned(),
                    });
                    if first_end == 4 {
                        assert!(state.temp_file.is_none());
                    } else {
                        assert_eq!(std::fs::read(state.temp_path.as_ref().unwrap()).unwrap(), b"Xbcd");
                    }
                }
                writer.cancel(&cx).await.unwrap().unwrap();
            }
        });
        drained(&runtime);
    }
}

#[test]
fn uncovered_corruption_still_requires_final_whole_file_verification() {
    let runtime = runtime(1);
    let directory = tempfile::tempdir().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let (id, expected) = fixture(b"abcdefghijkl", &[(2, 5)], false);
        let path = directory.path().join("uncovered");
        let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
        let (source, probe) = Source::new(b"abcdefghXjkl", 3);
        let mut session = writer.receive_exact(&cx, source, expected, options(4)).unwrap();
        assert_eq!(refusal(session.wait().await), "manifest content hash mismatch");
        assert_eq!(probe.consumed.load(Ordering::SeqCst), 12);
        assert_eq!(session.accepted_bytes(), 12);
        assert!(!path.exists());
        writer.cancel(&cx).await.unwrap().unwrap();
    });
    drained(&runtime);
}

#[test]
fn pinned_chunk_only_files_keep_framing_with_unaligned_writes_and_all_policies() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                for chunk_size in [4, 5] {
                    let (id, expected) = fixture(b"abcdefghijkl", &[(0, 3), (3, 7), (7, 12)], true);
                    let pin = ManifestChunkCommitment::from_manifest(&expected).unwrap();
                    let path = directory.path().join(format!("{policy:?}-{chunk_size}"));
                    let writer = writer(&cx, id, path.clone(), policy).await;
                    let (source, probe) = Source::new(b"abcdefghijklNEXT", 3);
                    let mut session = writer.receive_exact_with_chunk_commitment(
                        &cx, source, expected, options(chunk_size), pin,
                    ).unwrap();
                    assert_eq!(session.wait().await.unwrap().unwrap(), path);
                    assert_eq!(std::fs::read(&path).unwrap(), b"abcdefghijkl");
                    assert_eq!(probe.consumed.load(Ordering::SeqCst), 12);
                    let source = session.take_source().unwrap();
                    assert_eq!(&source.bytes[source.position..], b"NEXT");
                }
            }
        });
        drained(&runtime);
    }
}

#[test]
fn abandoned_borrowing_wait_preserves_the_spanning_manifest_hash() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (id, expected) = fixture(b"abcdefghijkl", &[(0, 6), (6, 12)], false);
            let path = directory.path().join("resumed");
            let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
            let (mut source, probe) = Source::new(b"abcdefghijklNEXT", 1);
            source.pause_at = Some(5);
            let mut session = writer.receive_exact(&cx, source, expected, options(4)).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !probe.parked.load(Ordering::SeqCst) {
                poll_fn(|task| {
                    assert!(session.poll_wait(task).is_pending());
                    Poll::Ready(())
                }).await;
                assert!(Instant::now() < deadline, "partial manifest hash was never reached");
                yield_now().await;
            }
            assert_eq!(session.accepted_bytes(), 4);
            assert_eq!(probe.consumed.load(Ordering::SeqCst), 5);
            let mut wait = Box::pin(session.wait());
            poll_fn(|task| {
                assert!(wait.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            drop(wait);
            probe.released.store(true, Ordering::SeqCst);
            let wake = probe.wake.lock().take();
            if let Some(wake) = wake { wake.wake(); }
            assert_eq!(session.wait().await.unwrap().unwrap(), path);
            assert_eq!(std::fs::read(path).unwrap(), b"abcdefghijkl");
            assert_eq!(session.take_source().unwrap().position, 12);
        });
        drained(&runtime);
    }
}

#[test]
fn resumed_hashes_span_local_prefix_and_suffix_without_changing_framing() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let data = b"abcdefghijkl";
            let layouts = [vec![(0, 6), (6, 12)], vec![(2, 5), (7, 11)], vec![]];
            for (layout, ranges) in layouts.iter().enumerate() {
                for start in [0, 3, 4, 7, 12] {
                    for chunk_size in [3, 5] {
                        // The full layout is chunk-only and must use a trusted
                        // pin. Partial/absent hints still need the whole-file ID.
                        let (id, manifest) = fixture(data, ranges, layout == 0);
                        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
                        let path = directory.path().join(format!("resume-{layout}-{start}-{chunk_size}"));
                        let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
                        writer.set_expected_size(&cx, 12).await.unwrap().unwrap();
                        if start != 0 {
                            writer.write_chunk(&cx, 0, data[..start].to_vec(), WriteOptions::default())
                                .await.unwrap().unwrap();
                        }
                        assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), start as u64);
                        let mut suffix = data[start..].to_vec();
                        suffix.extend_from_slice(b"NEXT");
                        let (source, probe) = Source::new(&suffix, 1);
                        let mut session = writer.resume_exact_at_with_chunk_commitment(
                            &cx, source, manifest, options(chunk_size), start as u64, expected,
                        ).unwrap();
                        assert_eq!(session.wait().await.unwrap().unwrap(), path);
                        assert_eq!(probe.consumed.load(Ordering::SeqCst), 12 - start);
                        assert_eq!(session.accepted_bytes(), 12);
                        assert_eq!(std::fs::read(&path).unwrap(), data);
                        let source = session.take_source().unwrap();
                        assert_eq!(&source.bytes[source.position..], b"NEXT");
                    }
                }
            }
        });
        drained(&runtime);
    }
}

#[test]
fn self_consistent_but_unauthorized_prefix_refuses_before_replacement_reads() {
    let runtime = runtime(2);
    let directory = tempfile::tempdir().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        for start in [4, 12] {
            let (id, manifest) = fixture(b"abcdefghijkl", &[(0, 4), (4, 12)], true);
            let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
            let path = directory.path().join(format!("bad-prefix-{start}"));
            let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
            writer.set_expected_size(&cx, 12).await.unwrap().unwrap();
            writer.write_chunk(&cx, 0, b"Xbcdefghijkl"[..start].to_vec(), WriteOptions::default())
                .await.unwrap().unwrap();
            // This validates local receipt/storage agreement, not the sender's
            // manifest. The receive preflight must make that second comparison.
            assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), start as u64);
            let (source, probe) = Source::new(&b"abcdefghijklNEXT"[start..], 1);
            let mut session = writer.resume_exact_at_with_chunk_commitment(
                &cx, source, manifest, options(4), start as u64, expected,
            ).unwrap();
            assert_eq!(refusal(session.wait().await), "manifest chunk 0 hash mismatch");
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            assert_eq!(session.accepted_bytes(), 0);
            assert!(matches!(writer.writer.lock_state().verification_state, VerificationState::Failed { .. }));
            assert!(matches!(writer.commit(&cx).await, Ok(Outcome::Err(_))));
            assert_eq!(writer.admission.available_permits(), 1);
            assert!(!path.exists());
            writer.cancel(&cx).await.unwrap().unwrap();
        }
    });
    drained(&runtime);
}

#[test]
fn crossing_corruption_in_either_prefix_or_suffix_stops_before_suffix_write() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for corrupt_prefix in [false, true] {
                let (id, manifest) = fixture(b"abcdefghijkl", &[(0, 6), (6, 12)], true);
                let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
                let path = directory.path().join(format!("crossing-{corrupt_prefix}"));
                let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
                writer.set_expected_size(&cx, 12).await.unwrap().unwrap();
                let prefix = if corrupt_prefix { b"Xbcd" } else { b"abcd" };
                writer.write_chunk(&cx, 0, prefix.to_vec(), WriteOptions::default()).await.unwrap().unwrap();
                let suffix = if corrupt_prefix { b"efghijklNEXT" } else { b"eXghijklNEXT" };
                let (source, probe) = Source::new(suffix, 1);
                let mut session = writer.resume_exact_at_with_chunk_commitment(
                    &cx, source, manifest, options(4), 4, expected,
                ).unwrap();
                assert_eq!(refusal(session.wait().await), "manifest chunk 0 hash mismatch");
                assert_eq!(probe.consumed.load(Ordering::SeqCst), 4);
                assert_eq!(session.accepted_bytes(), 4);
                assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().total_bytes_written, 4);
                assert!(!path.exists());
                writer.cancel(&cx).await.unwrap().unwrap();
            }
        });
        drained(&runtime);
    }
}
