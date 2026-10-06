use super::*;
use crate::channel::oneshot;
use crate::cx::ChildRegionSpec;
use crate::runtime::{JoinError, RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
use crate::types::CancelKind;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn files(path: &Path) -> Vec<std::ffi::OsString> {
    let mut names: Vec<_> = std::fs::read_dir(path).unwrap()
        .map(|entry| entry.unwrap().file_name()).collect();
    names.sort();
    names
}

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(45))
        .expect("scoped atomic scenario must retire all work");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn runtime(workers: usize, pool: bool) -> Runtime {
    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::new().worker_threads(workers) };
    let builder = if pool { builder.blocking_threads(1, 1) } else { builder };
    builder.build().unwrap()
}

fn drained(runtime: &Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

#[test]
fn staging_error_and_panic_close_the_file_before_discarding_it() {
    for panic in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        std::fs::write(&path, b"old").unwrap();
        let before = files(dir.path());
        let result = catch_unwind(AssertUnwindSafe(|| stage_with(
            &path, true, || Ok(()), |file| {
                file.write_all(b"partial")?;
                if panic { panic!("staging writer panic"); }
                Err(io::Error::other("writer refusal"))
            }, OperationProbeHook::default(),
        )));
        if panic {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().unwrap_err().to_string(), "writer refusal");
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        assert_eq!(files(dir.path()), before);
    }
}

#[test]
fn cancellation_at_every_staging_checkpoint_discards_without_publishing() {
    for stop in 1..=6 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        std::fs::write(&path, b"old").unwrap();
        let before = files(dir.path());
        let mut checkpoints = 0;
        let result = stage_with(&path, true, || {
            checkpoints += 1;
            if checkpoints == stop { Err(io::ErrorKind::Interrupted.into()) }
            else { Ok(()) }
        }, |file| file.write_all(b"new"), OperationProbeHook::default());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(checkpoints, stop);
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        assert_eq!(files(dir.path()), before);
    }
}

struct Fragmented {
    bytes: Vec<u8>,
    calls: usize,
    interrupted: bool,
}

impl Write for Fragmented {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.interrupted {
            self.interrupted = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let count = bytes.len().min(3);
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[test]
fn partial_writes_and_eintr_keep_checkpoints_and_complete_bytes() {
    let mut writer = Fragmented { bytes: Vec::new(), calls: 0, interrupted: true };
    let mut checks = 0;
    write_checkpointed(&mut writer, b"abcdefgh", || { checks += 1; Ok(()) }).unwrap();
    assert_eq!(writer.bytes, b"abcdefgh");
    assert_eq!(writer.calls, 4);
    assert_eq!(checks, writer.calls);
}

#[test]
fn cancelled_write_checkpoint_is_not_retried_as_eintr() {
    let mut writer = Fragmented { bytes: Vec::new(), calls: 0, interrupted: true };
    let mut checks = 0;
    let result = write_checkpointed(&mut writer, b"abcdefgh", || {
        checks += 1;
        if checks == 3 { Err(io::Error::new(io::ErrorKind::Interrupted, "stop")) }
        else { Ok(()) }
    });
    assert_eq!(result.unwrap_err().to_string(), "stop");
    assert_eq!(writer.calls, 2);
    assert_eq!(writer.bytes, b"abc");
}

#[test]
fn chunked_write_bounds_each_syscall_and_handles_zero_write() {
    struct Recorder { sizes: Vec<usize>, zero: bool }
    impl Write for Recorder {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.sizes.push(bytes.len());
            Ok(if self.zero { 0 } else { bytes.len() })
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    let mut writer = Recorder { sizes: Vec::new(), zero: false };
    write_checkpointed(&mut writer, &vec![0; 2 * WRITE_CHUNK_BYTES + 7], || Ok(())).unwrap();
    assert_eq!(writer.sizes, [WRITE_CHUNK_BYTES, WRITE_CHUNK_BYTES, 7]);
    writer.zero = true;
    assert_eq!(write_checkpointed(&mut writer, b"x", || Ok(())).unwrap_err().kind(),
        io::ErrorKind::WriteZero);
}

#[test]
fn native_writes_create_replace_and_empty_without_leftover_staging() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers, true);
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("target");
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let fs = cx.scoped_fs();
                for bytes in [b"old".to_vec(), vec![42; 3 * WRITE_CHUNK_BYTES + 7], Vec::new()] {
                    fs.write_atomic(target.clone(), bytes.clone()).await.unwrap();
                    assert_eq!(std::fs::read(&target).unwrap(), bytes);
                    assert_eq!(files(dir.path()), [std::ffi::OsString::from("target")]);
                }
                assert!(!cx.is_cancel_requested());
            });
            drained(&runtime);
        }
    });
}

#[test]
fn native_writer_uses_blocking_thread_child_context_and_preserves_failures() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers, true);
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("target");
            std::fs::write(&target, b"old").unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let async_thread = std::thread::current().id();
                let task = cx.task_id();
                let result = cx.scoped_fs().write_atomic_with(target.clone(), move |child, file| {
                    assert_ne!(std::thread::current().id(), async_thread);
                    assert_ne!(child.task_id(), task);
                    assert_eq!(Cx::current().unwrap().task_id(), child.task_id());
                    file.write_all(b"partial")?;
                    Err(io::Error::new(io::ErrorKind::PermissionDenied, "writer refused"))
                }).await;
                assert!(matches!(result, Err(ScopedFsError::Io(error))
                    if error.kind() == io::ErrorKind::PermissionDenied && error.to_string() == "writer refused"));
                let result = cx.scoped_fs().write_atomic_with(target.clone(), |_, file| {
                    file.write_all(b"partial")?;
                    panic!("scoped writer failed");
                }).await;
                assert!(matches!(result, Err(ScopedFsError::Join(JoinError::Panicked(_)))));
                assert_eq!(std::fs::read(&target).unwrap(), b"old");
                assert_eq!(files(dir.path()), [std::ffi::OsString::from("target")]);
            });
            drained(&runtime);
        }
    });
}

#[test]
fn native_owner_cancel_cannot_publish_a_writer_blocked_before_commit() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers, true);
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("target");
            std::fs::write(&target, b"old").unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let path = target.clone();
                let (started, mut observed) = oneshot::channel();
                let (release, released) = mpsc::channel();
                let mut owner = cx.spawn(move |owner| async move {
                    owner.scoped_fs().write_atomic_with(path, move |child, file| {
                        file.write_all(b"new")?;
                        started.send_blocking(child.clone()).unwrap();
                        released.recv_timeout(Duration::from_secs(8)).unwrap();
                        Ok(())
                    }).await
                }).unwrap();
                let worker = observed.recv(&cx).await.unwrap();
                assert_eq!(std::fs::read(&target).unwrap(), b"old");
                assert_eq!(files(dir.path()).len(), 2, "temporary is actually staged");
                owner.abort();
                let deadline = Instant::now() + Duration::from_secs(5);
                while !worker.is_cancel_requested() {
                    assert!(Instant::now() < deadline, "owner forwards cancellation to worker");
                    yield_now().await;
                }
                assert!(matches!(owner.try_join(), Ok(None)), "must wait for worker retirement");
                release.send(()).unwrap();
                let result = owner.join(&cx).await.unwrap();
                assert!(matches!(result, Err(ScopedFsError::Io(error))
                    if error.kind() == io::ErrorKind::Interrupted));
                assert_eq!(std::fs::read(&target).unwrap(), b"old");
                assert_eq!(files(dir.path()), [std::ffi::OsString::from("target")]);
                assert!(!cx.is_cancel_requested());
            });
            drained(&runtime);
        }
    });
}

#[test]
fn dropped_atomic_wait_keeps_worker_and_temporary_owned_until_region_close() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers, true);
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("target");
            std::fs::write(&target, b"old").unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let fs = region.cx().scoped_fs();
                let (started, mut observed) = oneshot::channel();
                let (release, released) = mpsc::channel();
                let mut write = Box::pin(fs.write_atomic_with(target.clone(), move |child, file| {
                    file.write_all(b"new")?;
                    started.send_blocking(child.clone()).unwrap();
                    released.recv_timeout(Duration::from_secs(8)).unwrap();
                    Ok(())
                }));
                poll_fn(|task| { assert!(write.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                let worker = observed.recv(&cx).await.unwrap();
                drop(write);
                assert!(worker.is_cancel_requested());
                let mut closing = Box::pin(region.close());
                poll_fn(|task| { assert!(closing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                assert_eq!(files(dir.path()).len(), 2);
                assert_eq!(std::fs::read(&target).unwrap(), b"old");
                release.send(()).unwrap();
                closing.await.unwrap();
                assert_eq!(files(dir.path()), [std::ffi::OsString::from("target")]);
                assert_eq!(std::fs::read(&target).unwrap(), b"old");
            });
            drained(&runtime);
        }
    });
}

#[test]
fn authority_cancellation_and_missing_pool_refuse_before_writer_runs() {
    bounded(|| {
        for pool in [false, true] {
            let runtime = runtime(1, pool);
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("must-not-exist");
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let restricted = {
                    let _guard = cx.restrict::<crate::cx::NoCaps>().set_current_restricted();
                    Cx::current().unwrap()
                };
                let result = restricted.scoped_fs().write_atomic_with(target.clone(), |_, _| {
                    panic!("refused writer must not run")
                }).await;
                assert!(matches!(result, Err(ScopedFsError::CapabilityDenied)));
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let child = region.cx();
                child.cancel_with(CancelKind::User, Some("before atomic write"));
                let result = child.scoped_fs().write_atomic(target.clone(), b"new".to_vec()).await;
                assert!(matches!(result, Err(ScopedFsError::Checkpoint(_))));
                region.close().await.unwrap();
                if !pool {
                    let result = cx.scoped_fs().write_atomic_with(target.clone(), |_, _| {
                        panic!("no inline fallback")
                    }).await;
                    assert!(matches!(result, Err(ScopedFsError::Admission(_))));
                }
                assert!(files(dir.path()).is_empty());
            });
            drained(&runtime);
        }
    });
}

#[test]
fn rename_failure_preserves_destination_and_discards_staging() {
    bounded(|| {
        let runtime = runtime(1, true);
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("directory");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("child"), b"keep").unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let result = cx.scoped_fs().write_atomic(target.clone(), b"new".to_vec()).await;
            assert!(matches!(result, Err(ScopedFsError::Io(_))));
            assert_eq!(std::fs::read(target.join("child")).unwrap(), b"keep");
            assert_eq!(files(dir.path()), [std::ffi::OsString::from("directory")]);
        });
        drained(&runtime);
    });
}

#[cfg(unix)]
#[test]
fn private_staging_preserves_target_permissions_without_rewriting_aliases() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    bounded(|| {
        let runtime = runtime(1, true);
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let alias = dir.path().join("alias");
        let link = dir.path().join("symlink");
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::hard_link(&target, &alias).unwrap();
        symlink(&target, &link).unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let fs = cx.scoped_fs();
            fs.write_atomic_with(target.clone(), |_, file| {
                assert_eq!(file.metadata()?.permissions().mode() & 0o077, 0);
                file.write_all(b"new")
            }).await.unwrap();
            assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o640);
            assert_eq!(std::fs::read(&alias).unwrap(), b"old");
            assert_eq!(std::fs::read(&link).unwrap(), b"new");
            fs.write_atomic(link.clone(), b"replacement".to_vec()).await.unwrap();
            assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
            assert_eq!(std::fs::read(&target).unwrap(), b"new");
            assert_eq!(std::fs::read(&link).unwrap(), b"replacement");
        });
        drained(&runtime);
    });
}
