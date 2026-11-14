//! Native recovery retains the publication job and never retries uncertain effects.

#![cfg(unix)]

use super::*;
use std::io::Write;
use std::path::Path;

const TORN_BYTES: &[u8] = &[0x19, 0x72, 0xa4];

fn torn_journal() -> (JournalFile, DurableRemoteJournal, u64) {
    let (file, mut journal) = JournalFile::create();
    let peer = NodeId::new(PEER);
    let completed = match journal
        .admit(&peer, IdempotencyKey::from_raw(1), INPUT, 1000)
        .unwrap()
    {
        DurableRemoteAdmission::Execute(permit) => permit,
        DurableRemoteAdmission::Replay(_) => panic!("new journal"),
    };
    journal
        .complete(completed, RemoteOutcome::Success(INPUT.to_vec()), 1000)
        .unwrap();
    let pending = match journal
        .admit(&peer, IdempotencyKey::from_raw(2), INPUT, 1000)
        .unwrap()
    {
        DurableRemoteAdmission::Execute(permit) => permit,
        DurableRemoteAdmission::Replay(_) => panic!("new key"),
    };
    drop(pending);
    let committed_bytes = journal.committed_bytes();
    assert_eq!(journal.records(), 3);
    drop(journal);

    let mut append = std::fs::OpenOptions::new()
        .append(true)
        .open(&file.path)
        .unwrap();
    append.write_all(TORN_BYTES).unwrap();
    append.sync_all().unwrap();
    drop(append);
    let journal = file.reopen().unwrap();
    assert_eq!(journal.status(), DurableRemoteJournalStatus::ReadOnlyTail);
    assert_eq!(journal.committed_bytes(), committed_bytes);
    (file, journal, committed_bytes)
}

fn replacement(file: &JournalFile) -> (PathBuf, File) {
    let path = file.path.with_file_name("recovery");
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    (path, handle)
}

fn publish(replacement: &Path, authoritative: &Path) -> io::Result<()> {
    std::fs::rename(replacement, authoritative)?;
    File::open(authoritative.parent().unwrap())?.sync_all()
}

#[test]
fn recovered_adapter_replays_results_preserves_uncertainty_and_admits_new_work() {
    for workers in [1, 2] {
        let (file, journal, committed_bytes) = torn_journal();
        let (replacement_path, replacement) = replacement(&file);
        let owner = Arc::new(DurableRemoteComputation::new(journal, || 1000));
        let runtime = native_runtime(workers, true);
        let publish_path = file.path.clone();
        let publications = Arc::new(AtomicUsize::new(0));
        let published = Arc::clone(&publications);
        run(&runtime, async {
            let cx = Cx::current().unwrap();
            assert!(matches!(
                owner
                    .call(&cx, invocation(&cx, 3), |_, _| async {
                        panic!("an incomplete journal cannot execute a new effect")
                    })
                    .await,
                Err(DurableRemoteError::NotWritable(
                    DurableRemoteJournalStatus::ReadOnlyTail
                ))
            ));
            let report = owner
                .recover_tail(&cx, replacement, move || {
                    publish(&replacement_path, &publish_path)?;
                    published.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(
                report.source_bytes,
                committed_bytes + TORN_BYTES.len() as u64
            );
            assert_eq!(report.committed_bytes, committed_bytes);
            assert_eq!(report.discarded_tail_bytes, TORN_BYTES.len() as u64);
            assert_eq!(report.records, 3);
            assert_eq!(report.retained_entries, 2);
            assert_eq!(publications.load(Ordering::SeqCst), 1);
            assert_eq!(records(&owner), 3, "recovery appends no new records");
            assert_eq!(
                owner.journal_status(),
                Some(DurableRemoteJournalStatus::Writable)
            );
            success(
                owner
                    .call(&cx, invocation(&cx, 1), |_, _| async {
                        panic!("the durable result must replay without execution")
                    })
                    .await
                    .unwrap(),
                INPUT,
            );
            assert!(matches!(
                owner
                    .call(&cx, invocation(&cx, 2), |_, _| async {
                        panic!("recovering storage never authorizes an uncertain effect")
                    })
                    .await,
                Err(DurableRemoteError::InDoubt)
            ));
            success(
                owner
                    .reconcile(&cx, invocation(&cx, 2), |_, _| async {
                        Some(RemoteOutcome::Success(INPUT.to_vec()))
                    })
                    .await
                    .unwrap(),
                INPUT,
            );
            success(
                owner
                    .call(&cx, invocation(&cx, 3), |_, _| async {
                        RemoteOutcome::Success(b"new effect".to_vec())
                    })
                    .await
                    .unwrap(),
                b"new effect",
            );
            assert_eq!(records(&owner), 6);
            assert!(!owner.in_flight());
        });
        drop(owner);
        drained(&runtime);
        let mut reopened = file.reopen().unwrap();
        assert_eq!(reopened.status(), DurableRemoteJournalStatus::Writable);
        assert_eq!(reopened.records(), 6);
        for key in [1, 2, 3] {
            match reopened
                .admit(
                    &NodeId::new(PEER),
                    IdempotencyKey::from_raw(key),
                    INPUT,
                    1000,
                )
                .unwrap()
            {
                DurableRemoteAdmission::Replay(outcome) => {
                    success(outcome, if key == 3 { b"new effect" } else { INPUT });
                }
                DurableRemoteAdmission::Execute(_) => {
                    panic!("reopen must replay every saved result")
                }
            }
        }
    }
}

#[test]
fn claimed_recovery_publication_survives_waiter_drop_or_late_cancellation() {
    for workers in [1, 2] {
        for abandon_waiter in [false, true] {
            let (file, journal, committed_bytes) = torn_journal();
            let (replacement_path, replacement) = replacement(&file);
            let clocks = Arc::new(AtomicUsize::new(0));
            let clock = Arc::clone(&clocks);
            let owner = Arc::new(DurableRemoteComputation::new(journal, move || {
                clock.fetch_add(1, Ordering::SeqCst);
                1000
            }));
            let runtime = native_runtime(workers, true);
            let gate = Arc::new(WorkerGate::default());
            let _release_on_unwind = ReleaseOnDrop(Arc::clone(&gate));
            let publications = Arc::new(AtomicUsize::new(0));
            let published = Arc::clone(&publications);
            let publication_gate = Arc::clone(&gate);
            let publish_path = file.path.clone();
            run(&runtime, async {
                let cx = Cx::current().unwrap();
                let region = cx
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let mut recovery =
                    Box::pin(owner.recover_tail(region.cx(), replacement, move || {
                        publication_gate.block();
                        publish(&replacement_path, &publish_path)?;
                        published.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }));
                let mut entered = Box::pin(gate.entered());
                poll_fn(|task| {
                    assert!(recovery.as_mut().poll(task).is_pending());
                    entered.as_mut().poll(task)
                })
                .await;
                assert!(owner.in_flight());
                assert_eq!(owner.journal_status(), None);
                assert!(matches!(file.reopen(), Err(DurableRemoteError::Locked)));
                assert!(matches!(
                    owner
                        .call(&cx, invocation(&cx, 1), |_, _| async {
                            panic!("recovery owns the exclusive journal slot")
                        })
                        .await,
                    Err(DurableRemoteError::Busy)
                ));
                assert_eq!(publications.load(Ordering::SeqCst), 0);
                if abandon_waiter {
                    drop(recovery);
                    let mut closing = Box::pin(region.close());
                    poll_fn(|task| {
                        assert!(closing.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    assert!(
                        owner.in_flight(),
                        "close retains the actual publication worker"
                    );
                    gate.release();
                    closing.await.unwrap();
                } else {
                    region
                        .cancel(CancelReason::user("late recovery cancellation"))
                        .unwrap();
                    gate.release();
                    let report = recovery
                        .await
                        .expect("published recovery receipt survives late cancellation");
                    assert_eq!(report.committed_bytes, committed_bytes);
                    assert_eq!(report.records, 3);
                    region.close().await.unwrap();
                }
                assert!(!owner.in_flight());
                assert_eq!(publications.load(Ordering::SeqCst), 1);
                assert_eq!(
                    owner.journal_status(),
                    Some(DurableRemoteJournalStatus::Writable)
                );
                assert_eq!(records(&owner), 3);
            });
            assert_eq!(
                clocks.load(Ordering::SeqCst),
                0,
                "prefix recovery does not retimestamp requests"
            );
            drop(owner);
            drained(&runtime);
            let reopened = file.reopen().unwrap();
            assert_eq!(reopened.status(), DurableRemoteJournalStatus::Writable);
            assert_eq!(reopened.committed_bytes(), committed_bytes);
        }
    }
}

#[test]
fn queued_recovery_cancellation_preserves_both_files_until_worker_retirement() {
    for workers in [1, 2] {
        let (file, journal, _) = torn_journal();
        let original = std::fs::read(&file.path).unwrap();
        let (replacement_path, replacement) = replacement(&file);
        let owner = Arc::new(DurableRemoteComputation::new(journal, || {
            panic!("recovering the authenticated prefix must not read a clock")
        }));
        let runtime = native_runtime(workers, true);
        let pool = runtime.blocking_handle().unwrap();
        let gate = Arc::new(WorkerGate::default());
        let _release_on_unwind = ReleaseOnDrop(Arc::clone(&gate));
        let blocking_gate = Arc::clone(&gate);
        let blocker = pool.spawn(move || blocking_gate.block());
        run(&runtime, async {
            let cx = Cx::current().unwrap();
            gate.entered().await;
            let region = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let mut recovery = Box::pin(owner.recover_tail(region.cx(), replacement, || {
                panic!("unclaimed cancelled recovery cannot publish")
            }));
            poll_fn(|task| {
                assert!(recovery.as_mut().poll(task).is_pending());
                if pool.pending_count() == 1 {
                    Poll::Ready(())
                } else {
                    task.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
            drop(recovery);
            assert!(owner.in_flight());
            let mut closing = Box::pin(region.close());
            poll_fn(|task| {
                assert!(closing.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            gate.release();
            closing.await.unwrap();
            assert!(!owner.in_flight());
            assert_eq!(
                owner.journal_status(),
                Some(DurableRemoteJournalStatus::ReadOnlyTail)
            );
        });
        assert!(blocker.wait_timeout(Duration::from_secs(5)));
        assert_eq!(std::fs::read(&file.path).unwrap(), original);
        assert_eq!(std::fs::metadata(&replacement_path).unwrap().len(), 0);
        drop(owner);
        assert_eq!(
            file.reopen().unwrap().status(),
            DurableRemoteJournalStatus::ReadOnlyTail
        );
        drained(&runtime);
    }
}

#[test]
fn recovery_refuses_missing_blocking_authority_or_already_cancelled_owner_before_io() {
    for blocking in [false, true] {
        let (file, journal, _) = torn_journal();
        let original = std::fs::read(&file.path).unwrap();
        let (replacement_path, replacement) = replacement(&file);
        let owner = Arc::new(DurableRemoteComputation::new(journal, || {
            panic!("refused recovery cannot read a clock")
        }));
        let runtime = native_runtime(1, blocking);
        run(&runtime, async {
            let cx = Cx::current().unwrap();
            let region = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            if blocking {
                region
                    .cancel(CancelReason::user("cancel before recovery admission"))
                    .unwrap();
            } else {
                assert!(region.cx().blocking_pool_handle().is_none());
            }
            assert!(matches!(
                owner
                    .recover_tail(region.cx(), replacement, || {
                        panic!("refused recovery cannot publish")
                    })
                    .await,
                Err(DurableRemoteError::Unavailable)
            ));
            assert!(!owner.in_flight());
            assert_eq!(
                owner.journal_status(),
                Some(DurableRemoteJournalStatus::ReadOnlyTail)
            );
            region.close().await.unwrap();
        });
        assert_eq!(std::fs::read(&file.path).unwrap(), original);
        assert_eq!(std::fs::metadata(&replacement_path).unwrap().len(), 0);
        drop(owner);
        drained(&runtime);
    }
}

struct PublicationDropGate {
    gate: Arc<WorkerGate>,
    retired: Arc<AtomicUsize>,
}

impl Drop for PublicationDropGate {
    fn drop(&mut self) {
        self.gate.block();
        self.retired.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn cancelled_replacement_jobs_retain_both_files_and_slot_through_callback_destruction() {
    for workers in [1, 2] {
        for recovering in [false, true] {
            let (file, journal) = if recovering {
                let (file, journal, _) = torn_journal();
                (file, journal)
            } else {
                JournalFile::create()
            };
            let expected_status = journal.status();
            let original = std::fs::read(&file.path).unwrap();
            let (replacement_path, replacement) = replacement(&file);
            // Cancellation can precede the worker's own lock acquisition.
            // A caller-owned lock witnesses that the supplied File remains
            // alive through destruction of the uninvoked callback's captures.
            replacement.try_lock().unwrap();
            let candidate_probe = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&replacement_path)
                .unwrap();
            let owner = Arc::new(DurableRemoteComputation::new(journal, || {
                panic!("a cancelled replacement job cannot sample the clock")
            }));
            let runtime = native_runtime(workers, true);
            let pool = runtime.blocking_handle().unwrap();
            let pool_gate = Arc::new(WorkerGate::default());
            let _release_pool = ReleaseOnDrop(Arc::clone(&pool_gate));
            let blocked_pool = Arc::clone(&pool_gate);
            let blocker = pool.spawn(move || blocked_pool.block());
            let drop_gate = Arc::new(WorkerGate::default());
            let _release_drop = ReleaseOnDrop(Arc::clone(&drop_gate));
            let retired = Arc::new(AtomicUsize::new(0));
            let probe = PublicationDropGate {
                gate: Arc::clone(&drop_gate),
                retired: Arc::clone(&retired),
            };
            let called = Arc::new(AtomicUsize::new(0));
            let callback_called = Arc::clone(&called);
            let callback = move || {
                callback_called.fetch_add(1, Ordering::SeqCst);
                drop(probe);
                Ok(())
            };
            run(&runtime, async {
                let cx = Cx::current().unwrap();
                pool_gate.entered().await;
                let region = cx
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let mut replacing = Box::pin(async {
                    if recovering {
                        owner
                            .recover_tail(region.cx(), replacement, callback)
                            .await
                            .map(|_| ())
                    } else {
                        owner
                            .compact(region.cx(), replacement, callback)
                            .await
                            .map(|_| ())
                    }
                });
                poll_fn(|task| {
                    assert!(replacing.as_mut().poll(task).is_pending());
                    if pool.pending_count() == 1 {
                        Poll::Ready(())
                    } else {
                        task.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                drop(replacing);
                let mut closing = Box::pin(region.close());
                poll_fn(|task| {
                    assert!(closing.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                pool_gate.release();
                drop_gate.entered().await;

                assert!(
                    owner.in_flight(),
                    "workers={workers} recovering={recovering}: callback Drop still owns the slot"
                );
                assert_eq!(owner.journal_status(), None);
                assert!(matches!(file.reopen(), Err(DurableRemoteError::Locked)));
                assert!(matches!(
                    candidate_probe.try_lock(),
                    Err(std::fs::TryLockError::WouldBlock)
                ));
                assert_eq!(called.load(Ordering::SeqCst), 0);
                assert_eq!(retired.load(Ordering::SeqCst), 0);
                poll_fn(|task| {
                    assert!(closing.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;

                drop_gate.release();
                closing.await.unwrap();
                assert_eq!(retired.load(Ordering::SeqCst), 1);
                assert_eq!(called.load(Ordering::SeqCst), 0);
                assert!(!owner.in_flight());
                assert_eq!(owner.journal_status(), Some(expected_status));
            });
            assert!(blocker.wait_timeout(Duration::from_secs(5)));
            assert_eq!(std::fs::read(&file.path).unwrap(), original);
            assert_eq!(std::fs::metadata(&replacement_path).unwrap().len(), 0);
            candidate_probe.try_lock().unwrap();
            drop(candidate_probe);
            drop(owner);
            drained(&runtime);
        }
    }
}
