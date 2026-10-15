//! Public region-owned filesystem operations on a real native blocking pool.
//! Gates, rather than sleeps, establish running work before cancellation/drop.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx, ScopedFsError};
use asupersync::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
use asupersync::types::CancelKind;
use std::future::{Future, poll_fn};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::Poll;
use std::time::{Duration, Instant};

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("scoped filesystem scenario must terminate");
    worker.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    };
    builder.blocking_threads(1, 1).build().unwrap()
}

fn drained(runtime: &Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

#[test]
fn real_file_workflow_and_io_errors_on_both_native_schedulers() {
    bounded(|| {
        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().to_owned();
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let fs = cx.scoped_fs();
                let nested = root.join("nested");
                fs.create_dir_all(nested.clone()).await.unwrap();
                let source = nested.join("source");
                let copy = nested.join("copy");
                let renamed = nested.join("renamed");
                let bytes = b"owned filesystem\n".to_vec();
                fs.write(source.clone(), bytes.clone()).await.unwrap();
                assert_eq!(fs.read(source.clone()).await.unwrap(), bytes);
                assert_eq!(fs.copy(source.clone(), copy.clone()).await.unwrap(), bytes.len() as u64);
                fs.rename(copy.clone(), renamed.clone()).await.unwrap();
                assert_eq!(fs.read_to_string(renamed.clone()).await.unwrap(), "owned filesystem\n");
                assert_eq!(fs.metadata(renamed).await.unwrap().len(), bytes.len() as u64);
                assert!(matches!(fs.read(copy).await,
                    Err(ScopedFsError::Io(error)) if error.kind() == io::ErrorKind::NotFound));
                fs.write(source.clone(), vec![0xff]).await.unwrap();
                assert!(matches!(fs.read_to_string(source).await,
                    Err(ScopedFsError::Io(error)) if error.kind() == io::ErrorKind::InvalidData));
            });
            drained(&runtime);
        }
    });
}

#[test]
fn dropping_a_running_call_keeps_its_region_open_until_io_finishes() {
    bounded(|| {
        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("late-write");
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let expected_region = region.region_id();
                let fs = region.cx().scoped_fs();
                let (started, mut start) = oneshot::channel();
                let (release, wait_release) = mpsc::channel();
                let target = path.clone();
                let mut work = Box::pin(fs.run_io(move |worker| {
                    assert_eq!(worker.region_id(), expected_region);
                    assert_eq!(Cx::current().unwrap().task_id(), worker.task_id());
                    started.send_blocking(worker).unwrap();
                    wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
                    // Model an OS call already in progress: cancellation does
                    // not undo an effect that finishes after the request.
                    std::fs::write(target, b"finished before close")
                }));
                poll_fn(|task| {
                    assert!(work.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                let worker_cx = start.recv(&cx).await.unwrap();
                drop(work);
                let deadline = Instant::now() + Duration::from_secs(5);
                while !worker_cx.is_cancel_requested() {
                    assert!(Instant::now() < deadline, "drop cancellation must reach the worker");
                    yield_now().await;
                }
                let mut closing = Box::pin(region.close());
                poll_fn(|task| {
                    assert!(closing.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                assert!(!path.exists(), "worker is still held before its write");
                release.send(()).unwrap();
                closing.await.unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), b"finished before close");
                // Closing one invocation must not close unrelated parent I/O.
                assert_eq!(cx.scoped_fs().read(path.clone()).await.unwrap(), b"finished before close");
            });
            drained(&runtime);
        }
    });
}

#[test]
fn caller_cancellation_reaches_the_worker_before_return_and_preserves_its_result() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let after_return = Arc::new(AtomicUsize::new(0));
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (started, mut start) = oneshot::channel();
                let (release, wait_release) = mpsc::channel();
                let observed = Arc::clone(&after_return);
                let mut owner = cx.spawn(move |owner_cx| async move {
                    let result = owner_cx.scoped_fs().run_io(move |worker| {
                        started.send_blocking(worker.clone()).unwrap();
                        wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
                        assert_eq!(worker.cancel_reason().unwrap().kind, CancelKind::User);
                        Ok(73_usize)
                    }).await;
                    observed.fetch_add(1, Ordering::SeqCst);
                    result
                }).unwrap();
                let worker_cx = start.recv(&cx).await.unwrap();
                owner.abort();
                let deadline = Instant::now() + Duration::from_secs(5);
                while !worker_cx.is_cancel_requested() {
                    assert!(Instant::now() < deadline, "caller cancellation was not forwarded");
                    yield_now().await;
                }
                assert_eq!(after_return.load(Ordering::SeqCst), 0, "caller must still be draining");
                assert!(matches!(owner.try_join(), Ok(None)));
                release.send(()).unwrap();
                assert!(matches!(owner.join(&cx).await, Ok(Ok(73))));
                assert_eq!(after_return.load(Ordering::SeqCst), 1);
            });
            drained(&runtime);
        }
    });
}

#[test]
fn an_already_cancelled_context_does_not_touch_the_filesystem() {
    bounded(|| {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("must-not-exist");
        let runtime = runtime(2);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let child = region.cx();
            child.cancel_with(CancelKind::User, Some("before filesystem dispatch"));
            let result = child.scoped_fs().write(path.clone(), vec![42]).await;
            assert!(matches!(result, Err(ScopedFsError::Checkpoint(_))));
            assert!(!path.exists());
            region.close().await.unwrap();
        });
        drained(&runtime);
    });
}

