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
