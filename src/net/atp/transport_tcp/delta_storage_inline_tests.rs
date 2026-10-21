use super::*;
use crate::types::CancelKind;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn key(bytes: &[u8]) -> DeltaContentKey {
    DeltaContentKey {
        content_id_hex: ContentId::from_bytes(bytes).to_hex(),
        size_bytes: bytes.len() as u64,
    }
}

fn run(operation: impl Future<Output = ()> + Send + 'static) {
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("native runtime");
    runtime.block_on(runtime.handle().spawn(operation));
}

#[test]
fn cancellation_wakes_parked_storage_without_repolling_the_operation() {
    let cx = Cx::for_testing();
    let polls = AtomicUsize::new(0);
    let operation = poll_fn(|_| {
        polls.fetch_add(1, Ordering::SeqCst);
        Poll::<Result<(), TransportError>>::Pending
    });
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&count));
    let mut task = Context::from_waker(&waker);
    let mut wait = Box::pin(run_io(&cx, operation));
    assert!(wait.as_mut().poll(&mut task).is_pending());
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        wait.as_mut().poll(&mut task),
        Poll::Ready(Err(TransportError::Cancelled))
    ));
    assert_eq!(polls.load(Ordering::SeqCst), 1);
}

#[test]
fn cancelled_before_first_poll_does_not_start_storage_work() {
    let cx = Cx::for_testing();
    cx.cancel_fast(CancelKind::User);
    let mut started = false;
    let result = futures_lite::future::block_on(run_io(&cx, async {
        started = true;
        Ok(())
    }));
    assert!(matches!(result, Err(TransportError::Cancelled)));
    assert!(!started);
}

#[test]
fn restricted_caller_cannot_resume_using_a_stronger_saved_context() {
    let cx = Cx::for_testing();
    let denied = cx.restrict::<crate::cx::cap::None>();
    let polls = AtomicUsize::new(0);
    let operation = poll_fn(|_| {
        polls.fetch_add(1, Ordering::SeqCst);
        Poll::<Result<(), TransportError>>::Pending
    });
    let mut wait = Box::pin(run_io(&cx, operation));
    let mut task = Context::from_waker(Waker::noop());
    assert!(wait.as_mut().poll(&mut task).is_pending());
    {
        let _ambient = denied.set_current_restricted();
        let Poll::Ready(Err(TransportError::Io(error))) = wait.as_mut().poll(&mut task) else {
            panic!("restricted resume must refuse before polling storage");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }
    assert_eq!(polls.load(Ordering::SeqCst), 1);
}

#[test]
fn masked_cancellation_does_not_abort_or_self_wake_parked_storage() {
    let cx = Cx::for_testing();
    cx.cancel_fast(CancelKind::User);
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&count));
    let mut task = Context::from_waker(&waker);
    let mut wait = Box::pin(run_io(&cx, std::future::pending::<Result<(), TransportError>>()));
    cx.masked(|| {
        for _ in 0..4 {
            assert!(wait.as_mut().poll(&mut task).is_pending());
        }
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
    });
    assert!(matches!(
        wait.as_mut().poll(&mut task),
        Poll::Ready(Err(TransportError::Cancelled))
    ));
}

#[test]
fn abandoning_a_storage_wait_unregisters_its_cancellation_observer() {
    let cx = Cx::for_testing();
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let weak = Arc::downgrade(&count);
    let waker = Waker::from(count);
    let mut wait = Box::pin(run_io(&cx, std::future::pending::<Result<(), TransportError>>()));
    assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    drop(waker);
    assert!(weak.upgrade().is_some());
    drop(wait);
    assert!(weak.upgrade().is_none());
}

#[test]
fn native_spool_roundtrip_deduplicates_and_supports_reordered_reads() {
    run(async {
        let cx = Cx::current().expect("task context");
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("spool");
        let mut spool = DeltaChunkSpool::create(&cx, &path, 11).await.unwrap();
        let first = key(b"first");
        let second = key(b"second");
        spool.insert(&cx, first.clone(), b"first").await.unwrap();
        spool.insert(&cx, first.clone(), b"first").await.unwrap();
        spool.insert(&cx, second.clone(), b"second").await.unwrap();
        assert_eq!(spool.written, 11);
        assert_eq!(spool.offsets.len(), 2);
        let mut scratch = Vec::new();
        assert!(matches!(
            spool.read_verified(&cx, &first, &mut scratch).await,
            Err(TransportError::Frame(_))
        ));
        spool.seal(&cx).await.unwrap();
        spool.seal(&cx).await.unwrap();
        for (chunk, expected) in [(&second, b"second".as_slice()), (&first, b"first".as_slice())] {
            spool.read_verified(&cx, chunk, &mut scratch).await.unwrap();
            assert_eq!(scratch, expected);
        }
        assert!(matches!(
            spool.insert(&cx, first, b"first").await,
            Err(TransportError::Frame(_))
        ));
        drop(spool);
        assert_eq!(std::fs::read(path).unwrap(), b"firstsecond");
    });
}

#[test]
fn native_spool_limits_and_bad_hashes_refuse_before_mutating() {
    run(async {
        let cx = Cx::current().expect("task context");
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("spool");
        let mut spool = DeltaChunkSpool::create(&cx, &path, 3).await.unwrap();
        assert!(matches!(
            spool.insert(&cx, key(b"four"), b"four").await,
            Err(TransportError::TooLarge { size: 4, max: 3 })
        ));
        assert!(matches!(
            spool.insert(&cx, key(b"bad"), b"new").await,
            Err(TransportError::Integrity(_))
        ));
        assert_eq!(spool.phase, SpoolPhase::Writing);
        assert_eq!(spool.written, 0);
        assert!(spool.offsets.is_empty());
        spool.insert(&cx, key(b"yes"), b"yes").await.unwrap();
        spool.seal(&cx).await.unwrap();
        drop(spool);
        assert_eq!(std::fs::read(path).unwrap(), b"yes");
    });
}

#[test]
fn native_spool_corruption_poisoning_is_persistent() {
    run(async {
        let cx = Cx::current().expect("task context");
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("spool");
        let mut spool = DeltaChunkSpool::create(&cx, &path, 5).await.unwrap();
        let chunk = key(b"first");
        spool.insert(&cx, chunk.clone(), b"first").await.unwrap();
        spool.seal(&cx).await.unwrap();
        std::fs::write(&path, b"wrong").unwrap();
        let mut scratch = Vec::new();
        assert!(matches!(
            spool.read_verified(&cx, &chunk, &mut scratch).await,
            Err(TransportError::Integrity(_))
        ));
        assert_eq!(spool.phase, SpoolPhase::Failed);
        std::fs::write(&path, b"first").unwrap();
        assert!(matches!(
            spool.read_verified(&cx, &chunk, &mut scratch).await,
            Err(TransportError::Frame(_))
        ));
    });
}

#[test]
fn native_baseline_ranges_are_revalidated_after_source_changes() {
    run(async {
        let cx = Cx::current().expect("task context");
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("baseline");
        std::fs::write(&path, b"beforepayloadafter").unwrap();
        let source = BaselineChunk::new(Arc::new(path.clone()), 6);
        let mut scratch = Vec::new();
        let chunk = key(b"payload");
        source.read_verified(&cx, &chunk, &mut scratch).await.unwrap();
        assert_eq!(scratch, b"payload");
        std::fs::write(&path, b"beforePAYLOADafter").unwrap();
        assert!(matches!(
            source.read_verified(&cx, &chunk, &mut scratch).await,
            Err(TransportError::Integrity(_))
        ));
        std::fs::write(&path, b"beforepay").unwrap();
        assert!(matches!(
            source.read_verified(&cx, &chunk, &mut scratch).await,
            Err(TransportError::Source(_))
        ));
    });
}

#[test]
fn native_spool_creation_never_overwrites_an_existing_file() {
    run(async {
        let cx = Cx::current().expect("task context");
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("existing");
        std::fs::write(&path, b"sentinel").unwrap();
        assert!(matches!(
            DeltaChunkSpool::create(&cx, &path, 100).await,
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(std::fs::read(path).unwrap(), b"sentinel");
    });
}

#[cfg(feature = "test-internals")]
#[test]
fn native_pending_spool_io_cancels_before_the_started_syscall_is_released() {
    use crate::fs::FileCursorOperationProbe;
    use std::sync::mpsc;
    use std::time::Duration;

    struct ReleaseOnDrop(Arc<FileCursorOperationProbe>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release_first();
        }
    }

    // Both append and reconstruction must register independently of the file's
    // completion waker. The probe witnesses a real started blocking operation.
    for reading in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("spool");
        let probe = Arc::new(FileCursorOperationProbe::new());
        let release = ReleaseOnDrop(Arc::clone(&probe));
        let worker_probe = Arc::clone(&probe);
        let (context_tx, context_rx) = mpsc::channel::<Cx>();
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            run(async move {
                let cx = Cx::current().expect("task context");
                let mut spool = DeltaChunkSpool::create(&cx, &path, 5).await.unwrap();
                let chunk = key(b"first");
                if reading {
                    spool.insert(&cx, chunk.clone(), b"first").await.unwrap();
                    spool.seal(&cx).await.unwrap();
                }
                spool.file.install_cursor_operation_probe_for_test(worker_probe);
                context_tx.send(cx.clone()).unwrap();
                let outcome = if reading {
                    spool.read_verified(&cx, &chunk, &mut Vec::new()).await
                } else {
                    spool.insert(&cx, chunk, b"first").await
                };
                finished_tx.send((
                    matches!(outcome, Err(TransportError::Cancelled)),
                    spool.phase == SpoolPhase::Failed,
                )).unwrap();
            });
        });
        let cx = context_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(probe.wait_until_first_blocked(Duration::from_secs(10)));
        cx.cancel_fast(CancelKind::User);
        let completed_before_release = finished_rx.recv_timeout(Duration::from_secs(10));
        let acquisitions_before_release = probe.acquisition_count();
        drop(release);
        worker.join().unwrap();
        assert_eq!(completed_before_release.unwrap(), (true, true));
        assert_eq!(acquisitions_before_release, 1);
    }
}

struct FragmentedBaseline<'a> {
    bytes: &'a [u8],
    max_read: usize,
    interruptions: usize,
    calls: Arc<AtomicUsize>,
}

impl std::io::Read for FragmentedBaseline<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.interruptions > 0 {
            self.interruptions -= 1;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        let count = self.max_read.min(buffer.len()).min(self.bytes.len());
        buffer[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}

#[test]
fn baseline_batches_resume_short_reads_and_eintr_without_reallocating() {
    let expected: Vec<u8> = (0..193).map(|i| (i % 251) as u8).collect();
    let calls = Arc::new(AtomicUsize::new(0));
    let reader = FragmentedBaseline {
        bytes: &expected,
        max_read: 1,
        interruptions: 65,
        calls: Arc::clone(&calls),
    };
    let mut state = BaselineRead {
        reader: Some(reader),
        path: Arc::new(PathBuf::from("fragmented-baseline")),
        key: key(&expected),
        buffer: vec![0xa5; expected.len()],
        filled: 0,
    };
    let allocation = state.buffer.as_ptr();
    state = state.read_batch().unwrap();
    assert_eq!(state.filled, 0, "exhausting EINTR attempts is not EOF");
    assert_eq!(calls.load(Ordering::SeqCst), 64);
    assert!(state.reader.is_some());
    let mut jobs = 1;
    while state.reader.is_some() {
        let before = calls.load(Ordering::SeqCst);
        state = state.read_batch().unwrap();
        jobs += 1;
        assert!(calls.load(Ordering::SeqCst) - before <= 64);
        assert_eq!(state.buffer.as_ptr(), allocation);
        assert!(jobs < 10, "the scripted source must make progress");
    }
    assert_eq!(state.filled, expected.len());
    assert_eq!(state.buffer, expected);
    assert_eq!(calls.load(Ordering::SeqCst), 65 + expected.len());
}

#[test]
fn baseline_batch_stops_at_the_exact_range_without_an_eof_probe() {
    let mut reader = b"payload-trailing-content".as_slice();
    let state = BaselineRead {
        reader: Some(&mut reader),
        path: Arc::new(PathBuf::from("indexed-baseline")),
        key: key(b"payload"),
        buffer: vec![0; 7],
        filled: 0,
    }
    .read_batch()
    .unwrap();
    assert!(state.reader.is_none(), "the first job completes the range");
    assert_eq!(state.buffer, b"payload");
    drop(state);
    assert_eq!(reader, b"-trailing-content");
}

#[test]
fn baseline_batches_distinguish_truncation_content_drift_and_read_errors() {
    for bytes in [b"pay".as_slice(), b"PAYLOAD".as_slice()] {
        let state = BaselineRead {
            reader: Some(bytes),
            path: Arc::new(PathBuf::from("changed-baseline")),
            key: key(b"payload"),
            buffer: vec![0xa5; 7],
            filled: 0,
        };
        match state.read_batch() {
            Err(TransportError::Source(message)) if bytes.len() < 7 => {
                assert!(message.contains("changed-baseline"));
                assert!(message.contains("3 of 7"));
            }
            Err(TransportError::Integrity(_)) if bytes.len() == 7 => {}
            _ => panic!("partial or changed bytes must never be published as verified"),
        }
    }
    struct FailingRead(bool);
    impl std::io::Read for FailingRead {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.0 {
                return Err(std::io::Error::other("read-failure-sentinel"));
            }
            self.0 = true;
            buffer[0] = b'p';
            Ok(1)
        }
    }
    let result = BaselineRead {
        reader: Some(FailingRead(false)),
        path: Arc::new(PathBuf::from("failing-baseline")),
        key: key(b"payload"),
        buffer: vec![0xa5; 7],
        filled: 0,
    }
    .read_batch();
    assert!(matches!(result, Err(TransportError::Source(message))
        if message.contains("failing-baseline") && message.contains("read-failure-sentinel")));
}

#[test]
fn native_baseline_worker_reads_reuse_scratch_through_maximum_chunk_size() {
    run(async {
        let cx = Cx::current().unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("baseline");
        let maximum = usize::try_from(MAX_COMPRESSED_CHUNK_RAW).unwrap();
        let bytes: Vec<u8> = (0..maximum + 31).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &bytes).unwrap();
        let source = BaselineChunk::new(Arc::new(path), 17);
        let mut scratch = vec![0xa5; maximum];
        let allocation = scratch.as_ptr() as usize;
        for length in [1, 63, 64, 65, 128 * 1024, 256 * 1024, maximum] {
            let expected = &bytes[17..17 + length];
            source.read_verified(&cx, &key(expected), &mut scratch).await.unwrap();
            assert_eq!(scratch, expected);
            assert_eq!(scratch.as_ptr() as usize, allocation);
        }
    });
}

#[test]
fn native_baseline_preflight_refuses_before_taking_scratch_or_opening() {
    run(async {
        let cx = Cx::current().unwrap();
        let root = tempfile::tempdir().unwrap();
        let missing = Arc::new(root.path().join("never-created"));
        let source = BaselineChunk::new(Arc::clone(&missing), 0);
        let mut scratch = b"keep-scratch".to_vec();
        let mut invalid = key(b"payload");
        for size in [0, u64::from(MAX_COMPRESSED_CHUNK_RAW) + 1] {
            invalid.size_bytes = size;
            assert!(matches!(
                source.read_verified(&cx, &invalid, &mut scratch).await,
                Err(TransportError::Frame(_))
            ));
            assert_eq!(scratch, b"keep-scratch");
        }
        let overflow = BaselineChunk::new(Arc::clone(&missing), u64::MAX);
        assert!(matches!(
            overflow.read_verified(&cx, &key(b"payload"), &mut scratch).await,
            Err(TransportError::Frame(_))
        ));
        let denied = cx.restrict::<crate::cx::cap::None>();
        assert!(matches!(
            denied.with_ambient(source.read_verified(&cx, &key(b"payload"), &mut scratch)).await,
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
        ));
        let stopped = Cx::for_testing();
        stopped.cancel_fast(CancelKind::User);
        assert!(matches!(
            source.read_verified(&stopped, &key(b"payload"), &mut scratch).await,
            Err(TransportError::Cancelled)
        ));
        assert_eq!(scratch, b"keep-scratch");
        assert!(!missing.exists());
    });
}

#[test]
fn native_tcp_delta_reconstructs_baseline_ranges_and_spooled_changes() {
    use super::super::{TransferConfig, receive_once, send_path};
    use crate::runtime::RuntimeBuilder;
    use std::sync::mpsc;
    use std::time::Duration;

    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let source_dir = root_path.join("source");
    let destination = root_path.join("destination");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::create_dir_all(&destination).unwrap();
    let source = source_dir.join("payload");
    let received_path = destination.join("payload");
    let mut baseline = vec![1u8; 3 * 4096];
    baseline[4096..8192].fill(2);
    baseline[8192..].fill(3);
    let mut target = baseline.clone();
    target[4096..8192].fill(4);
    std::fs::write(&received_path, &baseline).unwrap();
    std::fs::write(&source, &target).unwrap();
    let config = TransferConfig {
        chunk_size: 4096,
        idle_timeout: Duration::from_secs(5),
        accept_timeout: Duration::from_secs(5),
        ..TransferConfig::default()
    };
    let receive_config = config.clone();
    let (address_tx, address_rx) = mpsc::channel();
    let receiver = std::thread::spawn(move || {
        let runtime = RuntimeBuilder::multi_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let listener = crate::net::TcpListener::bind("127.0.0.1:0").await?;
            address_tx.send(listener.local_addr()?).unwrap();
            receive_once(&cx, &listener, &destination, receive_config, "receiver").await
        }))
    });
    let address = address_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let runtime = RuntimeBuilder::multi_thread().build().unwrap();
    let sent = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().unwrap();
        send_path(&cx, address, &source, config, "sender").await
    }));
    // Join before asserting either protocol result so a failure does not
    // abandon the independent receiver thread.
    let received = receiver.join().unwrap();
    let sent = sent.expect("delta sender");
    let received = received.expect("delta receiver");
    assert_eq!(sent.bytes_sent, 4096, "only the changed middle chunk crosses TCP");
    assert_eq!(received.bytes_received, 4096);
    assert!(sent.receipt.committed && sent.receipt.sha_ok && sent.receipt.merkle_ok);
    assert!(received.committed);
    assert_eq!(std::fs::read(received_path).unwrap(), target);
}

#[test]
fn native_spool_reads_full_chunks_across_filesystem_poll_boundaries() {
    run(async {
        let cx = Cx::current().unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("spool");
        let size = usize::try_from(MAX_COMPRESSED_CHUNK_RAW).unwrap();
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let chunk = key(&payload);
        let mut spool = DeltaChunkSpool::create(&cx, &path, size as u64).await.unwrap();
        spool.insert(&cx, chunk.clone(), &payload).await.unwrap();
        spool.seal(&cx).await.unwrap();
        let mut scratch = vec![0xa5; size];
        let allocation = scratch.as_ptr() as usize;
        for _ in 0..2 {
            spool.read_verified(&cx, &chunk, &mut scratch).await.unwrap();
            assert_eq!(scratch, payload);
            assert_eq!(scratch.as_ptr() as usize, allocation);
            assert_eq!(spool.phase, SpoolPhase::Reading);
        }
    });
}

#[test]
fn native_short_spool_read_fails_without_authorizing_a_prefix() {
    run(async {
        let cx = Cx::current().unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("spool");
        let payload = vec![0x37; 256 * 1024 + 1];
        let chunk = key(&payload);
        let mut spool = DeltaChunkSpool::create(&cx, &path, chunk.size_bytes).await.unwrap();
        spool.insert(&cx, chunk.clone(), &payload).await.unwrap();
        spool.seal(&cx).await.unwrap();
        std::fs::OpenOptions::new().write(true).open(&path).unwrap()
            .set_len(128 * 1024 + 1).unwrap();
        let mut scratch = Vec::new();
        let error = spool.read_verified(&cx, &chunk, &mut scratch).await.unwrap_err();
        assert!(matches!(error,
            TransportError::Io(error) if error.kind() == std::io::ErrorKind::UnexpectedEof));
        assert_eq!(spool.phase, SpoolPhase::Failed);
        assert!(matches!(
            spool.read_verified(&cx, &chunk, &mut scratch).await,
            Err(TransportError::Frame(_))
        ));
    });
}

#[test]
fn native_baseline_type_admission_preserves_regular_hardlink_reuse() {
    run(async {
        let cx = Cx::current().unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("regular");
        let alias = root.path().join("hardlink");
        std::fs::write(&path, b"beforepayloadafter").unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        let mut scratch = vec![0xa5; 64];
        let allocation = scratch.as_ptr() as usize;
        for path in [path, alias] {
            let source = BaselineChunk::new(Arc::new(path), 6);
            source.read_verified(&cx, &key(b"payload"), &mut scratch).await.unwrap();
            assert_eq!(scratch, b"payload");
            assert_eq!(scratch.as_ptr() as usize, allocation);
        }
    });
}

#[test]
fn native_baseline_refuses_a_directory_replacing_an_indexed_file() {
    run(async {
        let cx = Cx::current().unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("baseline");
        let held = root.path().join("held");
        std::fs::write(&path, b"payload").unwrap();
        let source = BaselineChunk::new(Arc::new(path.clone()), 0);
        source.read_verified(&cx, &key(b"payload"), &mut Vec::new()).await.unwrap();
        std::fs::rename(&path, &held).unwrap();
        std::fs::create_dir(&path).unwrap();
        let error = source.read_verified(&cx, &key(b"payload"), &mut Vec::new()).await.unwrap_err();
        assert!(matches!(error, TransportError::Source(message)
            if message == format!("{}: delta baseline source must be a plain regular file", path.display())));
        assert_eq!(std::fs::read(&held).unwrap(), b"payload");
        assert!(path.is_dir());
    });
}

#[cfg(unix)]
#[test]
fn native_baseline_refuses_a_same_content_symlink_replacement() {
    run(async {
        let cx = Cx::current().unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("baseline");
        let held = root.path().join("held");
        std::fs::write(&path, b"beforepayloadafter").unwrap();
        let source = BaselineChunk::new(Arc::new(path.clone()), 6);
        source.read_verified(&cx, &key(b"payload"), &mut Vec::new()).await.unwrap();
        std::fs::rename(&path, &held).unwrap();
        std::os::unix::fs::symlink(&held, &path).unwrap();
        let mut scratch = Vec::new();
        let error = source.read_verified(&cx, &key(b"payload"), &mut scratch).await.unwrap_err();
        assert!(matches!(error, TransportError::Source(message)
            if message == format!("{}: delta baseline source must be a plain regular file", path.display())));
        assert!(scratch.is_empty(), "matching bytes behind a link must not be published");
        assert_eq!(std::fs::read_link(&path).unwrap(), held);
        assert_eq!(std::fs::read(&held).unwrap(), b"beforepayloadafter");
    });
}

#[cfg(unix)]
#[test]
fn baseline_native_open_refuses_symlink_substitution_after_the_path_check() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("baseline");
    let held = root.path().join("held");
    std::fs::write(&path, b"payload").unwrap();
    // Witness the exact pathname admission that precedes the production open,
    // then replace the leaf before exercising that native-open boundary.
    require_regular_baseline(&std::fs::symlink_metadata(&path).unwrap()).unwrap();
    std::fs::rename(&path, &held).unwrap();
    std::os::unix::fs::symlink(&held, &path).unwrap();
    let error = open_baseline_handle(&path).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
    assert_eq!(std::fs::read(&held).unwrap(), b"payload");
}

#[cfg(unix)]
#[test]
fn native_baseline_fifo_refusal_finishes_before_any_writer_is_opened() {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    use std::sync::mpsc;
    use std::time::Duration;

    // Both the complete public-to-this-module read and the native open after
    // a successful pathname check must refuse a FIFO without needing a writer.
    for after_path_check in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("baseline");
        let held = root.path().join("held");
        std::fs::write(&path, b"payload").unwrap();
        require_regular_baseline(&std::fs::symlink_metadata(&path).unwrap()).unwrap();
        let source = BaselineChunk::new(Arc::new(path.clone()), 0);
        std::fs::rename(&path, &held).unwrap();
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_fifo());
        let worker_path = path.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .blocking_threads(1, 1)
                .build()
                .unwrap();
            let outcome = runtime.block_on(runtime.handle().spawn(async move {
                if after_path_check {
                    crate::runtime::spawn_blocking(move || {
                        open_baseline_handle(&worker_path).map(drop).map_err(|error| {
                            TransportError::Source(format!("{}: {error}", worker_path.display()))
                        })
                    }).await
                } else {
                    let cx = Cx::current().unwrap();
                    source.read_verified(&cx, &key(b"payload"), &mut Vec::new()).await
                }
            }));
            done_tx.send(outcome).unwrap();
        });
        let first = done_rx.recv_timeout(Duration::from_secs(5));
        let finished_without_writer = first.is_ok();
        // A regressed blocking open must not strand the test's worker. Only
        // after the deadline, supply a reader/writer pair so it can return;
        // the missed pre-writer deadline still makes the test fail.
        let rescue = if finished_without_writer {
            None
        } else {
            let reader = std::fs::OpenOptions::new().read(true)
                .custom_flags(libc::O_NONBLOCK).open(&path).unwrap();
            let writer = std::fs::OpenOptions::new().write(true)
                .custom_flags(libc::O_NONBLOCK).open(&path).unwrap();
            Some((reader, writer))
        };
        let outcome = first.or_else(|_| done_rx.recv_timeout(Duration::from_secs(5)));
        let joined = worker.join();
        drop(rescue);
        assert!(joined.is_ok(), "native runtime worker must retire");
        assert!(finished_without_writer, "FIFO refusal required a peer writer");
        assert!(matches!(outcome.unwrap(), Err(TransportError::Source(message))
            if message == format!("{}: delta baseline source must be a plain regular file", path.display())));
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_fifo());
        assert_eq!(std::fs::read(&held).unwrap(), b"payload");
    }
}

#[cfg(unix)]
#[test]
fn native_baseline_refuses_a_device_even_when_its_bytes_would_match() {
    use std::os::unix::fs::FileTypeExt;

    run(async {
        let cx = Cx::current().unwrap();
        let path = PathBuf::from("/dev/zero");
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_char_device());
        let source = BaselineChunk::new(Arc::new(path.clone()), 0);
        let mut scratch = Vec::new();
        let error = source.read_verified(&cx, &key(&[0; 32]), &mut scratch).await.unwrap_err();
        assert!(matches!(error, TransportError::Source(message)
            if message == format!("{}: delta baseline source must be a plain regular file", path.display())));
        assert!(scratch.is_empty());
    });
}

#[cfg(unix)]
#[test]
fn native_tcp_delta_rejects_baseline_substitution_after_request_without_publication() {
    use super::super as tcp;
    use crate::runtime::RuntimeBuilder;
    use std::sync::mpsc;
    use std::time::Duration;

    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let destination = root_path.join("destination");
    std::fs::create_dir(&destination).unwrap();
    let received_path = destination.join("payload");
    let held_path = root_path.join("held-baseline");
    let source_path = root_path.join("source");
    let mut baseline = vec![1u8; 3 * 4096];
    baseline[4096..8192].fill(2);
    baseline[8192..].fill(3);
    let mut target = baseline.clone();
    target[4096..8192].fill(4);
    std::fs::write(&received_path, &baseline).unwrap();
    std::fs::write(&source_path, &target).unwrap();
    let config = tcp::TransferConfig {
        chunk_size: 4096,
        idle_timeout: Duration::from_secs(5),
        accept_timeout: Duration::from_secs(5),
        ..tcp::TransferConfig::default()
    };
    let receive_config = config.clone();
    let receiver_destination = destination.clone();
    let (address_tx, address_rx) = mpsc::channel();
    let receiver = std::thread::spawn(move || {
        let runtime = RuntimeBuilder::multi_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let listener = crate::net::TcpListener::bind("127.0.0.1:0").await?;
            address_tx.send(listener.local_addr()?).unwrap();
            tcp::receive_once(&cx, &listener, &receiver_destination, receive_config, "receiver").await
        }))
    });
    let address = match address_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(address) => address,
        Err(error) => {
            let result = receiver.join();
            panic!("receiver failed to publish its address: {error}; {result:?}");
        }
    };
    let switched_path = received_path.clone();
    let saved_path = held_path.clone();
    let runtime = RuntimeBuilder::multi_thread().build().unwrap();
    // A protocol peer, not a fake filesystem: use the real sender's hash and
    // chunk-manifest builders, then pause at the receiver's ObjectRequest.
    let peer = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().unwrap();
        let (size, content_id, content_sha256) =
            tcp::hash_file_streaming(&source_path, &mut vec![0; 4096]).await?;
        let digest = tcp::EntryDigest {
            rel_path: "payload".into(), size, content_id, content_sha256,
        };
        let content_root = tcp::flat_merkle_root_from_digests(&[digest]);
        let entries = [tcp::SourceEntry {
            rel_path: "payload".into(), abs_path: source_path,
        }];
        let delta = tcp::build_delta_manifest_from_entries(
            content_root.clone(), &entries, &[tcp::EntryMetadata::default()], 4096,
        ).await?;
        let manifest = tcp::TransferManifest {
            transfer_id: tcp::transfer_id_hex(&content_root, size, 1),
            root_name: "payload".into(), is_directory: false, total_bytes: size,
            merkle_root_hex: content_root, metadata_root_hex: None, directory_metadata: None,
            entries: vec![tcp::ManifestEntry {
                index: 0, rel_path: "payload".into(), size,
                sha256_hex: tcp::hex_encode(&content_sha256), metadata: None, members: Vec::new(),
            }],
            delta_manifest: Some(delta),
        };
        let stream = crate::net::TcpStream::connect(address).await?;
        let mut wire = tcp::FrameTransport::new(stream);
        let hello = tcp::json_frame(tcp::FrameType::Handshake, &tcp::Hello {
            protocol: tcp::ATP_TCP_PROTOCOL, role: "sender".into(), peer_id: "baseline-guard-test".into(),
        })?;
        tcp::with_transport_timeout(&cx, config.idle_timeout, "test hello", wire.send(&hello)).await?;
        let ack = tcp::with_transport_timeout(&cx, config.idle_timeout, "test ack", wire.recv()).await?;
        if ack.frame_type() != tcp::FrameType::HandshakeAck
            || !tcp::parse_json::<tcp::HelloAck>(&ack)?.accepted
        {
            return Err(TransportError::Frame("test peer handshake was not accepted".into()));
        }
        let frame = tcp::json_frame(tcp::FrameType::ObjectManifest, &manifest)?;
        tcp::with_transport_timeout(&cx, config.idle_timeout, "test manifest", wire.send(&frame)).await?;
        let frame = tcp::with_transport_timeout(&cx, config.idle_timeout, "test request", wire.recv()).await?;
        if frame.frame_type() != tcp::FrameType::ObjectRequest {
            return Err(TransportError::Frame("receiver did not emit ObjectRequest".into()));
        }
        let request: tcp::DeltaObjectRequest = tcp::parse_json(&frame)?;
        tcp::sender_validation::validate_request(&manifest, &request)?;
        if request.mode != tcp::DeltaWireMode::DeltaChunks
            || request.missing_bytes != 4096 || request.missing_chunks.len() != 1
            || request.missing_chunks[0].entry_offset != 4096
        {
            return Err(TransportError::Frame("fixture did not witness the indexed delta baseline".into()));
        }
        // Receiving this request proves the receiver finished indexing the
        // original regular file. Its unchanged ranges are now replaced by a
        // link to exactly the same bytes, so hashing alone cannot reject it.
        std::fs::rename(&switched_path, &saved_path)?;
        std::os::unix::fs::symlink(&saved_path, &switched_path)?;
        let frame = tcp::data_frame(0, 4096, &target[4096..8192])?;
        tcp::with_transport_timeout(&cx, config.idle_timeout, "test changed chunk", wire.send(&frame)).await?;
        let complete = tcp::Frame::empty(tcp::FrameType::ObjectComplete)
            .map_err(|error| TransportError::Frame(error.to_string()))?;
        tcp::with_transport_timeout(&cx, config.idle_timeout, "test complete", wire.send(&complete)).await?;
        match tcp::with_transport_timeout(&cx, config.idle_timeout, "test rejection", wire.recv()).await {
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(TransportError::Frame("rejected baseline produced a protocol success frame".into())),
        }
    }));
    let received = receiver.join().expect("receiver thread must retire");
    peer.expect("peer must witness the delta request and closed failure session");
    assert!(matches!(received, Err(TransportError::Source(message))
        if message == format!("{}: delta baseline source must be a plain regular file", received_path.display())));
    assert_eq!(std::fs::read_link(&received_path).unwrap(), held_path);
    assert_eq!(std::fs::read(&held_path).unwrap(), baseline);
    let entries: Vec<_> = std::fs::read_dir(&destination).unwrap()
        .map(|entry| entry.unwrap().file_name()).collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("payload")], "failed receive must reclaim its spool and staging");
}
