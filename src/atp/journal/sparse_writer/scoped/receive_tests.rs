//! Native file and socket workflows; borrowing waits retain the real operation.

use super::*;
use crate::atp::journal::CommitPolicy;
use crate::atp::manifest::{ChunkBoundary, ChunkStrategy, MerkleRoot};
use crate::atp::object::{ManifestId, MetadataPolicy, Object, ObjectGraph};
use crate::cx::ChildRegionSpec;
use crate::io::ReadBuf;
use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder, SpawnError, yield_now};
use crate::types::CancelKind;
use sha2::{Digest, Sha256};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::{Context, Waker};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Probe {
    polls: AtomicUsize,
    consumed: AtomicUsize,
    parked: AtomicBool,
    released: AtomicBool,
    dropped: AtomicBool,
    wake: parking_lot::Mutex<Option<Waker>>,
    accepted: parking_lot::Mutex<Option<Arc<AtomicU64>>>,
}

impl Probe {
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        let wake = self.wake.lock().take();
        if let Some(wake) = wake { wake.wake(); }
    }
}

struct Source {
    data: Vec<u8>,
    position: usize,
    fragment: usize,
    pause_at: Option<usize>,
    fail_at: Option<usize>,
    panic_at: Option<usize>,
    probe: Arc<Probe>,
}

impl Source {
    fn new(data: &[u8], fragment: usize) -> (Self, Arc<Probe>) {
        let probe = Arc::new(Probe::default());
        (Self {
            data: data.to_vec(), position: 0, fragment, pause_at: None, fail_at: None, panic_at: None,
            probe: Arc::clone(&probe),
        }, probe)
    }
}

impl Drop for Source {
    fn drop(&mut self) { self.probe.dropped.store(true, Ordering::SeqCst); }
}

impl AsyncRead for Source {
    fn poll_read(self: Pin<&mut Self>, task: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.probe.polls.fetch_add(1, Ordering::SeqCst);
        if this.panic_at.is_some_and(|at| this.position >= at) {
            panic!("source poll panic witness");
        }
        if this.pause_at.is_some_and(|at| this.position >= at) && !this.probe.released.load(Ordering::SeqCst) {
            *this.probe.wake.lock() = Some(task.waker().clone());
            this.probe.parked.store(true, Ordering::SeqCst);
            return Poll::Pending;
        }
        if this.fail_at.is_some_and(|at| this.position >= at) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "source failure witness")));
        }
        let mut count = this.fragment.min(buf.remaining()).min(this.data.len() - this.position);
        if !this.probe.released.load(Ordering::SeqCst) {
            if let Some(at) = this.pause_at { count = count.min(at.saturating_sub(this.position)); }
        }
        if let Some(at) = this.fail_at { count = count.min(at.saturating_sub(this.position)); }
        if let Some(at) = this.panic_at { count = count.min(at.saturating_sub(this.position)); }
        if let Some(accepted) = this.probe.accepted.lock().as_ref() {
            // Test sessions use four-byte chunks. No bytes of the next chunk
            // may be requested until the current write receipt was observed.
            assert!(this.position as u64 + count as u64 <= accepted.load(Ordering::Relaxed) + 4);
        }
        buf.put_slice(&this.data[this.position..this.position + count]);
        this.position += count;
        this.probe.consumed.store(this.position, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
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

fn manifest(data: &[u8]) -> (ObjectId, Arc<Manifest>) {
    let object = Object::file(data.to_vec());
    let id = object.id.clone();
    let mut graph = ObjectGraph::new();
    graph.add_root(object).unwrap();
    (id, Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap()))
}

fn refresh(manifest: &mut Manifest) {
    manifest.merkle_root = MerkleRoot::from_manifest_components(
        &manifest.objects, &manifest.chunk_plan, &manifest.raptorq_layout,
        &manifest.compression_policy, &manifest.encryption_policy, &manifest.capability_policy,
        &manifest.transform_order, &manifest.transform_proof_policy, &manifest.repair_groups,
    );
    manifest.validate().unwrap();
}

fn options() -> ScopedReceiveOptions {
    ScopedReceiveOptions { max_bytes: 64, max_chunks: 16, chunk_size: 4 }
}

async fn writer(cx: &Cx, id: ObjectId, path: PathBuf, policy: CommitPolicy) -> ScopedSparseWriter {
    ScopedSparseWriter::new(cx, id, path, SparseWriterConfig {
        enable_preallocation: false, commit_policy: policy, ..SparseWriterConfig::default()
    }).await.unwrap().unwrap()
}

async fn reach_pause<R>(session: &mut ScopedReceive<R>, probe: &Probe) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !probe.parked.load(Ordering::SeqCst) {
        poll_fn(|task| {
            assert!(session.poll_wait(task).is_pending(), "receive completed before pause witness");
            Poll::Ready(())
        }).await;
        assert!(Instant::now() < deadline, "source was never polled to its pause");
        yield_now().await;
    }
}

#[test]
fn exact_ingress_publishes_without_eof_and_returns_unconsumed_protocol_bytes() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for policy in [CommitPolicy::AtomicRename, CommitPolicy::CopyAndVerify, CommitPolicy::LinkAndUnlink] {
                for data in [b"".as_slice(), b"abcdefghij".as_slice()] {
                    for fragment in [1, 3, 64] {
                        let path = directory.path().join(format!("{policy:?}-{}-{fragment}", data.len()));
                        let (id, manifest) = manifest(data);
                        let writer = writer(&cx, id, path.clone(), policy).await;
                        let mut wire = data.to_vec(); wire.extend_from_slice(b"NEXT");
                        let (source, probe) = Source::new(&wire, fragment);
                        let mut session = writer.receive_exact(&cx, source, manifest, options()).unwrap();
                        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                        assert_eq!(session.wait().await.unwrap().unwrap(), path);
                        assert_eq!(session.accepted_bytes(), data.len() as u64);
                        assert_eq!(std::fs::read(&path).unwrap(), data);
                        let source = session.take_source().unwrap();
                        assert_eq!(&source.data[source.position..], b"NEXT");
                        if data.is_empty() { assert_eq!(probe.polls.load(Ordering::SeqCst), 0); }
                        assert!(session.take_source().is_none());
                        assert!(matches!(session.wait().await, Err(ScopedReceiveError::Completed)));
                    }
                }
            }
        });
        drained(&runtime);
    }
}

#[test]
fn dropped_borrowing_wait_resumes_the_same_partial_chunk_and_holds_clone_admission() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (id, manifest) = manifest(b"abcdefghij");
            let path = directory.path().join("file");
            let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
            let (mut source, probe) = Source::new(b"abcdefghijNEXT", 1);
            source.pause_at = Some(6); // One accepted chunk, two retained source bytes.
            let mut session = writer.receive_exact(&cx, source, manifest, options()).unwrap();
            *probe.accepted.lock() = Some(Arc::clone(&session.accepted));
            reach_pause(&mut session, &probe).await;
            assert_eq!(session.accepted_bytes(), 4);
            assert_eq!(probe.consumed.load(Ordering::SeqCst), 6);
            let mut wait = Box::pin(session.wait());
            poll_fn(|task| { assert!(wait.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            drop(wait);
            assert!(!probe.dropped.load(Ordering::SeqCst));
            let mut competing = Box::pin(writer.set_expected_size(&cx, 99));
            poll_fn(|task| { assert!(competing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            assert_eq!(writer.admission.telemetry_snapshot(1).waiter_count, 1);
            // The source wait holds no pool worker; unrelated I/O still runs.
            cx.scoped_fs().write(directory.path().join("other"), vec![9]).await.unwrap();
            probe.release();
            assert_eq!(session.wait().await.unwrap().unwrap(), path);
            assert!(matches!(competing.await, Ok(Outcome::Err(SparseWriterError::WriteFailed(_)))));
            assert_eq!(std::fs::read(&path).unwrap(), b"abcdefghij");
            assert_eq!(session.take_source().unwrap().position, 10);
        });
        drained(&runtime);
    }
}

#[test]
fn size_and_ledger_limits_and_wrong_pin_refuse_before_source_or_staging() {
    let runtime = runtime(2);
    let directory = tempfile::tempdir().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        for case in 0..4 {
            let (id, manifest) = manifest(b"abcdefghij");
            let path = directory.path().join(format!("refuse-{case}"));
            let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
            let (source, probe) = Source::new(b"abcdefghij", 10);
            let mut limits = options();
            if case == 0 { limits.max_bytes = 9; }
            if case == 1 { limits.max_chunks = 2; }
            if case == 2 { limits.max_chunks = 0; }
            let mut session = if case == 3 {
                writer.receive_exact_with_chunk_commitment(&cx, source, manifest, limits, ManifestChunkCommitment::new([0; 32]))
            } else { writer.receive_exact(&cx, source, manifest, limits) }.unwrap();
            assert!(matches!(session.wait().await, Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            assert!(probe.dropped.load(Ordering::SeqCst));
            assert!(writer.writer.lock_state().temp_file.is_none());
            assert!(!path.exists());
        }
    });
    drained(&runtime);
}

#[test]
fn unpolled_sessions_invalid_options_and_gateway_refusal_do_not_read() {
    fn assert_send<T: Send>(_: &T) {}
    let directory = tempfile::tempdir().unwrap();
    let (id, manifest) = manifest(b"data");
    let writer = SparseWriter::new_blocking(id, directory.path().join("file"), SparseWriterConfig::default()).unwrap().into_scoped();
    let cx = Cx::for_testing();
    for chunk_size in [0, 1_048_577] {
        let (source, probe) = Source::new(b"data", 1);
        let result = writer.receive_exact(&cx, source, Arc::clone(&manifest), ScopedReceiveOptions { chunk_size, ..options() });
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidInput));
        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
    }
    let (source, probe) = Source::new(b"data", 1);
    let session = writer.receive_exact(&cx, source, Arc::clone(&manifest), options()).unwrap();
    assert_send(&session); drop(session);
    assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
    for case in 0..3 {
        let cx = if case == 0 {
            let _restricted = Cx::for_testing().restrict::<crate::cx::NoCaps>().set_current_restricted();
            Cx::current().unwrap()
        } else { Cx::for_testing() };
        if case == 1 { cx.cancel_with(CancelKind::User, Some("before receive")); }
        let (source, probe) = Source::new(b"data", 1);
        let mut session = writer.receive_exact(&cx, source, Arc::clone(&manifest), options()).unwrap();
        let result = futures_lite::future::block_on(session.wait());
        match case {
            0 => assert!(matches!(result, Err(ScopedReceiveError::Gateway(ScopedFsError::CapabilityDenied)))),
            1 => assert!(matches!(result, Err(ScopedReceiveError::Gateway(ScopedFsError::Checkpoint(_))))),
            2 => assert!(matches!(result, Err(ScopedReceiveError::Gateway(ScopedFsError::Admission(SpawnError::RuntimeUnavailable))))),
            _ => unreachable!(),
        }
        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
        assert_eq!(writer.admission.available_permits(), 1);
    }
}

#[test]
fn truncation_source_errors_and_corrupt_content_never_publish() {
    let runtime = runtime(2);
    let directory = tempfile::tempdir().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        for case in 0..3 {
            let (id, manifest) = manifest(b"abcdefgh");
            let path = directory.path().join(format!("bad-{case}"));
            let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
            let payload: &[u8] = match case { 0 => b"abcde", 1 => b"abcdefgh", _ => b"abcdWXYZ" };
            let (mut source, probe) = Source::new(payload, 2);
            if case == 1 { source.fail_at = Some(4); }
            let mut session = writer.receive_exact(&cx, source, manifest, options()).unwrap();
            match session.wait().await {
                Err(ScopedReceiveError::Source(error)) if case == 0 => assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof),
                Err(ScopedReceiveError::Source(error)) if case == 1 => {
                    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                    assert_eq!(error.to_string(), "source failure witness");
                }
                Ok(Outcome::Err(SparseWriterError::VerificationFailed(_))) if case == 2 => {},
                other => panic!("wrong terminal result: {other:?}"),
            }
            assert!(!path.exists());
            assert!(session.take_source().is_none());
            assert!(probe.dropped.load(Ordering::SeqCst));
            assert_eq!(writer.admission.available_permits(), 1);
            writer.cancel(&cx).await.unwrap().unwrap();
        }
    });
    drained(&runtime);
}

#[test]
fn nonfresh_writer_is_refused_without_consuming_the_new_source() {
    let runtime = runtime(1);
    let directory = tempfile::tempdir().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let (id, manifest) = manifest(b"abcdefgh");
        let writer = writer(&cx, id, directory.path().join("file"), CommitPolicy::AtomicRename).await;
        writer.write_chunk(&cx, 0, b"abcd".to_vec(), WriteOptions::default()).await.unwrap().unwrap();
        let (source, probe) = Source::new(b"abcdefgh", 2);
        let mut session = writer.receive_exact(&cx, source, manifest, options()).unwrap();
        assert!(matches!(session.wait().await, Ok(Outcome::Err(SparseWriterError::WriteFailed(_)))));
        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
        assert_eq!(writer.get_stats(&cx).await.unwrap().unwrap().total_bytes_written, 4);
        writer.cancel(&cx).await.unwrap().unwrap();
    });
    drained(&runtime);
}

#[test]
fn pinned_chunk_only_ingress_uses_the_authorized_complete_ledger() {
    let runtime = runtime(2);
    let directory = tempfile::tempdir().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        for length in [0, 8] {
            let data = &b"abcdefgh"[..length];
            let (old_id, original) = manifest(data);
            let mut manifest = (*original).clone();
            let id = ObjectId::manifest(ManifestId::from_manifest_bytes(b"ingress-object"));
            let mut object = manifest.objects.remove(&old_id).unwrap();
            object.id = id.clone(); object.content_hash = None;
            if length != 0 {
                object.chunk_boundaries = vec![ChunkBoundary {
                    index: 0, byte_offset: 0, size_bytes: length as u64,
                    content_hash: Sha256::digest(data).into(), strategy: ChunkStrategy::FixedSize, metadata: None,
                }];
            }
            manifest.objects.insert(id.clone(), object); manifest.roots = vec![id.clone()]; refresh(&mut manifest);
            let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
            let manifest = Arc::new(manifest);
            let path = directory.path().join(format!("pinned-{length}"));
            let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
            let (source, probe) = Source::new(data, 1);
            let mut denied = writer.receive_exact(&cx, source, Arc::clone(&manifest), options()).unwrap();
            assert!(matches!(denied.wait().await, Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            let (source, _) = Source::new(data, 1);
            let mut session = writer.receive_exact_with_chunk_commitment(&cx, source, manifest, options(), expected).unwrap();
            assert_eq!(session.wait().await.unwrap().unwrap(), path);
            assert_eq!(std::fs::read(path).unwrap(), data);
        }
    });
    drained(&runtime);
}

#[test]
fn explicit_context_cancellation_wakes_a_parked_source_and_releases_admission() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let child = region.cx();
            let (id, manifest) = manifest(b"abcdefgh");
            let path = directory.path().join("file");
            let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
            let (mut source, probe) = Source::new(b"abcdefgh", 1); source.pause_at = Some(2);
            let mut session = writer.receive_exact(&child, source, manifest, options()).unwrap();
            reach_pause(&mut session, &probe).await;
            child.cancel_with(CancelKind::User, Some("parked receive"));
            let result = crate::time::timeout(cx.now(), Duration::from_secs(5), session.wait()).await.unwrap();
            assert!(matches!(result, Err(ScopedReceiveError::Source(error)) if error.kind() == io::ErrorKind::Interrupted));
            assert_eq!(probe.consumed.load(Ordering::SeqCst), 2);
            assert_eq!(writer.admission.available_permits(), 1);
            assert!(!path.exists());
            region.close().await.unwrap();
            writer.cancel(&cx).await.unwrap().unwrap();
        });
        drained(&runtime);
    }
}

struct WitnessedTcp {
    stream: crate::net::TcpStream,
    parked: Arc<AtomicBool>,
}

impl AsyncRead for WitnessedTcp {
    fn poll_read(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_read(task, buf);
        if result.is_pending() {
            this.parked.store(true, Ordering::SeqCst);
        }
        result
    }
}

#[test]
fn real_tcp_body_commits_while_peer_stays_open_and_next_frame_is_readable() {
    use std::io::Write;
    for workers in [1, 2] {
        // Connection setup is synchronous fixture work, not part of ingestion.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime(workers);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let path = directory.path().join("received");
            let (id, manifest) = manifest(b"abcdefghij");
            let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
            let parked = Arc::new(AtomicBool::new(false));
            let source = WitnessedTcp {
                stream: crate::net::TcpStream::from_std(socket).unwrap(),
                parked: Arc::clone(&parked),
            };
            let mut session = writer.receive_exact(&cx, source, manifest, options()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !parked.load(Ordering::SeqCst) {
                poll_fn(|task| {
                    assert!(session.poll_wait(task).is_pending());
                    Poll::Ready(())
                }).await;
                assert!(Instant::now() < deadline, "TCP read never registered Pending");
                yield_now().await;
            }
            assert!(!path.exists());
            // The peer neither closes nor half-closes. Waiting for source EOF
            // would fail the deadline rather than pass this framed-body test.
            peer.write_all(b"abcdefghijNEXT").unwrap();
            let result = crate::time::timeout(cx.now(), Duration::from_secs(5), session.wait())
                .await.unwrap().unwrap().unwrap();
            assert_eq!(result, path);
            assert_eq!(session.accepted_bytes(), 10);
            assert_eq!(std::fs::read(&path).unwrap(), b"abcdefghij");
            let mut source = session.take_source().unwrap();
            let mut next = [0; 4];
            crate::time::timeout(cx.now(), Duration::from_secs(5), source.read_exact(&mut next))
                .await.unwrap().unwrap();
            assert_eq!(&next, b"NEXT");
        });
        drained(&runtime);
    }
}

#[test]
fn dropping_the_receive_owner_releases_source_and_preserves_staging_for_cleanup() {
    let runtime = runtime(2);
    let directory = tempfile::tempdir().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let path = directory.path().join("file");
        let (id, manifest) = manifest(b"abcdefghij");
        let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
        let (mut source, probe) = Source::new(b"abcdefghij", 1);
        source.pause_at = Some(6);
        let mut session = writer.receive_exact(&cx, source, manifest, options()).unwrap();
        reach_pause(&mut session, &probe).await;
        assert_eq!(session.accepted_bytes(), 4);
        let staging = writer.writer.lock_state().temp_path.clone().unwrap();
        let mut competing = Box::pin(writer.get_stats(&cx));
        poll_fn(|task| {
            assert!(competing.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }).await;
        drop(session);
        assert!(probe.dropped.load(Ordering::SeqCst));
        assert_eq!(competing.await.unwrap().unwrap().total_bytes_written, 4);
        assert_eq!(std::fs::read(staging).unwrap(), b"abcd");
        assert!(!path.exists());
        writer.cancel(&cx).await.unwrap().unwrap();
    });
    drained(&runtime);
}

#[test]
fn source_poll_panic_cannot_be_replayed_by_another_borrowing_wait() {
    let runtime = runtime(1);
    let directory = tempfile::tempdir().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let path = directory.path().join("file");
        let (id, manifest) = manifest(b"abcdefgh");
        let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
        let (mut source, probe) = Source::new(b"abcdefgh", 1);
        source.panic_at = Some(2);
        let mut session = writer.receive_exact(&cx, source, manifest, options()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let panicked = poll_fn(|task| {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    assert!(session.poll_wait(task).is_pending());
                }));
                Poll::Ready(result)
            }).await;
            if let Err(payload) = panicked {
                let message = payload.downcast_ref::<&str>().copied()
                    .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
                assert_eq!(message, Some("source poll panic witness"));
                break;
            }
            assert!(Instant::now() < deadline, "source did not reach panic witness");
            yield_now().await;
        }
        let polls = probe.polls.load(Ordering::SeqCst);
        assert!(matches!(session.wait().await, Err(ScopedReceiveError::Poisoned)));
        assert_eq!(probe.polls.load(Ordering::SeqCst), polls);
        assert_eq!(probe.consumed.load(Ordering::SeqCst), 2);
        assert!(!path.exists());
        drop(session);
        assert!(probe.dropped.load(Ordering::SeqCst));
        assert_eq!(writer.admission.available_permits(), 1);
        writer.cancel(&cx).await.unwrap().unwrap();
    });
    drained(&runtime);
}

#[test]
fn dropped_pool_step_keeps_admission_until_its_actual_write_retires() {
    use crate::channel::oneshot;
    use std::sync::mpsc;
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let directory = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let child = region.cx();
            let path = directory.path().join("file");
            let (id, _) = manifest(b"data");
            let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
            writer.set_expected_size(&cx, 4).await.unwrap().unwrap();
            let permit = writer.reserve(&child).await.unwrap();
            let (started, mut start) = oneshot::channel();
            let (release, wait_release) = mpsc::channel();
            // Supplemental test of the exact helper used by ingress. The gate
            // is inside the real pool closure, before its real filesystem write.
            let mut step = Box::pin(writer.receive_step(&child, permit, move |core| {
                let worker = Cx::current().unwrap();
                started.send_blocking(worker).unwrap();
                wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
                core.write_chunk_blocking(0, b"data", WriteOptions::default())
            }));
            poll_fn(|task| {
                assert!(step.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            let worker = start.recv(&cx).await.unwrap();
            drop(step);
            let deadline = Instant::now() + Duration::from_secs(5);
            while !worker.is_cancel_requested() {
                assert!(Instant::now() < deadline, "abandonment did not reach the owned worker");
                yield_now().await;
            }
            let mut competing = Box::pin(writer.get_stats(&cx));
            poll_fn(|task| {
                assert!(competing.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            let mut closing = Box::pin(region.close());
            poll_fn(|task| {
                assert!(closing.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            assert_eq!(writer.admission.available_permits(), 0);
            assert!(writer.writer.lock_state().temp_file.is_none());
            release.send(()).unwrap();
            closing.await.unwrap();
            assert_eq!(competing.await.unwrap().unwrap().total_bytes_written, 4);
            let staging = writer.writer.lock_state().temp_path.clone().unwrap();
            assert_eq!(std::fs::read(staging).unwrap(), b"data");
            assert!(!path.exists());
            writer.cancel(&cx).await.unwrap().unwrap();
        });
        drained(&runtime);
    }
}

#[test]
fn missing_size_wrong_kind_and_identity_refuse_before_source_poll() {
    let runtime = runtime(2);
    let directory = tempfile::tempdir().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        for case in 0..3 {
            let (id, original) = manifest(b"data");
            let mut manifest = (*original).clone();
            let object = manifest.objects.get_mut(&id).unwrap();
            match case {
                0 => object.size_bytes = None,
                1 => object.kind = crate::atp::object::ObjectKind::StreamObject,
                2 => object.id = ObjectId::manifest(ManifestId::from_manifest_bytes(b"other")),
                _ => unreachable!(),
            }
            refresh(&mut manifest);
            let path = directory.path().join(format!("invalid-{case}"));
            let writer = writer(&cx, id, path.clone(), CommitPolicy::AtomicRename).await;
            let (source, probe) = Source::new(b"data", 1);
            let mut session = writer.receive_exact(&cx, source, Arc::new(manifest), options()).unwrap();
            assert!(matches!(session.wait().await,
                Ok(Outcome::Err(SparseWriterError::VerificationFailed(_)))));
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            assert!(writer.writer.lock_state().temp_file.is_none());
            assert!(!path.exists());
        }
    });
    drained(&runtime);
}
