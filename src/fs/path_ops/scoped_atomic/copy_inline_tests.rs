    use super::*;
    use crate::cx::{ChildRegionSpec, Cx};
    use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
    use crate::types::CancelKind;
    use std::io::Cursor;
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    use std::sync::mpsc;
    use std::time::Duration;

    fn files(path: &std::path::Path) -> Vec<std::ffi::OsString> {
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
            .expect("atomic copy must retire all work");
        worker.join().unwrap();
        if let Err(payload) = result { resume_unwind(payload); }
    }

    fn runtime(workers: usize) -> Runtime {
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers) };
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
    fn exact_empty_oversized_and_maximum_limits_do_not_return_truncated_success() {
        for limit in [0, 1, WRITE_CHUNK_BYTES, WRITE_CHUNK_BYTES + 1] {
            let bytes = vec![42; limit];
            let mut output = Vec::new();
            assert_eq!(copy_checkpointed(&mut Cursor::new(&bytes), &mut output,
                limit as u64, || Ok(())).unwrap(), limit as u64);
            assert_eq!(output, bytes);
            let mut oversized = Cursor::new(vec![42; limit + 2]);
            let result = copy_checkpointed(&mut oversized, &mut Vec::new(), limit as u64, || Ok(()));
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::FileTooLarge);
            assert_eq!(oversized.position(), limit as u64 + 1);
        }
        let mut output = Vec::new();
        assert_eq!(copy_checkpointed(&mut Cursor::new(b"small"), &mut output,
            u64::MAX, || Ok(())).unwrap(), 5);
        assert_eq!(output, b"small");
    }

    #[test]
    fn cancellation_between_read_and_write_does_not_copy_that_chunk() {
        let mut source = Cursor::new(b"not committed");
        let mut output = Vec::new();
        let mut checks = 0;
        let result = copy_checkpointed(&mut source, &mut output, u64::MAX, || {
            checks += 1;
            if checks == 2 { Err(io::ErrorKind::Interrupted.into()) } else { Ok(()) }
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(output.is_empty());
        assert_eq!(checks, 2);
    }

    #[test]
    fn interrupted_reads_do_not_retry_checkpoint_cancellation() {
        struct Interrupted(usize);
        impl Read for Interrupted {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                Err(io::ErrorKind::Interrupted.into())
            }
        }
        let mut source = Interrupted(0);
        let mut checks = 0;
        let result = copy_checkpointed(&mut source, &mut Vec::new(), u64::MAX, || {
            checks += 1;
            if checks == 3 { Err(io::ErrorKind::Interrupted.into()) } else { Ok(()) }
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(source.0, 2);
        assert_eq!(checks, 3);
    }

    #[test]
    fn source_growth_beyond_limit_discards_the_staged_copy() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("source");
        let target_path = dir.path().join("target");
        std::fs::write(&source_path, b"small").unwrap();
        std::fs::write(&target_path, b"old").unwrap();
        let before = files(dir.path());
        let result = stage_with(&target_path, true, || Ok(()), |target| {
            let mut source = File::open(&source_path)?;
            let mut checks = 0;
            copy_checkpointed(&mut source, target, 5, || {
                checks += 1;
                if checks == 3 {
                    File::options().append(true).open(&source_path)?.write_all(b"!")?;
                }
                Ok(())
            }).map(|_| ())
        }, OperationProbeHook::default());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(std::fs::read(&target_path).unwrap(), b"old");
        assert_eq!(files(dir.path()), before);
    }

    #[test]
    fn native_bounded_copy_replaces_only_after_complete_input() {
        bounded(|| {
            for workers in [1, 2] {
                let runtime = runtime(workers);
                let dir = tempfile::tempdir().unwrap();
                let from = dir.path().join("source");
                let to = dir.path().join("target");
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let fs = cx.scoped_fs();
                    for size in [0, 1, 3 * WRITE_CHUNK_BYTES + 7] {
                        let bytes = vec![42; size];
                        std::fs::write(&from, &bytes).unwrap();
                        std::fs::write(&to, b"previous").unwrap();
                        if size > 0 {
                            let result = fs.copy_atomic_bounded(from.clone(), to.clone(), size as u64 - 1).await;
                            assert!(matches!(result, Err(ScopedFsError::Io(error))
                                if error.kind() == io::ErrorKind::FileTooLarge));
                            assert_eq!(std::fs::read(&to).unwrap(), b"previous");
                        }
                        assert_eq!(fs.copy_atomic_bounded(from.clone(), to.clone(), size as u64)
                            .await.unwrap(), size as u64);
                        assert_eq!(std::fs::read(&to).unwrap(), bytes);
                        assert_eq!(std::fs::read(&from).unwrap(), bytes);
                        assert_eq!(files(dir.path()).len(), 2);
                    }
                    let before = std::fs::read(&to).unwrap();
                    let result = fs.copy_atomic_bounded(from.with_file_name("absent"), to.clone(), 100).await;
                    assert!(matches!(result, Err(ScopedFsError::Io(error))
                        if error.kind() == io::ErrorKind::NotFound));
                    assert_eq!(std::fs::read(&to).unwrap(), before);
                    assert_eq!(files(dir.path()).len(), 2);
                });
                drained(&runtime);
            }
        });
    }

    #[test]
    fn native_same_file_and_alias_copies_never_truncate_the_source() {
        bounded(|| {
            for workers in [1, 2] {
                let runtime = runtime(workers);
                let dir = tempfile::tempdir().unwrap();
                let from = dir.path().join("source");
                let alias = dir.path().join("alias");
                std::fs::write(&from, b"preserve source").unwrap();
                std::fs::hard_link(&from, &alias).unwrap();
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let fs = cx.scoped_fs();
                    assert_eq!(fs.copy_atomic_bounded(from.clone(), from.clone(), u64::MAX)
                        .await.unwrap(), 15);
                    assert_eq!(std::fs::read(&from).unwrap(), b"preserve source");
                    assert_eq!(fs.copy_atomic_bounded(from.clone(), alias.clone(), u64::MAX)
                        .await.unwrap(), 15);
                    assert_eq!(std::fs::read(&alias).unwrap(), b"preserve source");
                    let result = fs.copy_atomic_bounded(from.clone(), from.clone(), 1).await;
                    assert!(matches!(result, Err(ScopedFsError::Io(error))
                        if error.kind() == io::ErrorKind::FileTooLarge));
                    assert_eq!(std::fs::read(&from).unwrap(), b"preserve source");
                    assert_eq!(files(dir.path()).len(), 2);
                });
                drained(&runtime);
            }
        });
    }

    #[test]
    fn native_copy_refuses_cancelled_and_attenuated_owners_before_staging() {
        bounded(|| {
            let runtime = runtime(1);
            let dir = tempfile::tempdir().unwrap();
            let from = dir.path().join("source");
            let to = dir.path().join("target");
            std::fs::write(&from, b"new").unwrap();
            std::fs::write(&to, b"old").unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let child = region.cx();
                child.cancel_with(CancelKind::User, Some("before atomic copy"));
                let result = child.scoped_fs().copy_atomic_bounded(from.clone(), to.clone(), 3).await;
                assert!(matches!(result, Err(ScopedFsError::Checkpoint(_))));
                region.close().await.unwrap();
                let restricted = {
                    let _guard = cx.restrict::<crate::cx::NoCaps>().set_current_restricted();
                    Cx::current().unwrap()
                };
                let result = restricted.scoped_fs().copy_atomic_bounded(from.clone(), to.clone(), 3).await;
                assert!(matches!(result, Err(ScopedFsError::CapabilityDenied)));
                assert_eq!(std::fs::read(&to).unwrap(), b"old");
                assert_eq!(files(dir.path()).len(), 2);
            });
            drained(&runtime);
        });
    }
