//! Prepared undo covers failed or unobserved effects, not remote exactly-once.
//! Bead: asupersync-dist-otp-completeness-8y37kz.8 (local composition slice).

use super::*;

#[test]
fn prepared_steps_keep_typed_values_and_disarm_only_on_whole_saga_commit() {
    run_case(|cx| async move {
        let mut handle = cx
            .spawn_saga::<String, &'static str, &'static str, _>(
                BracketConfig::new(4),
                2,
                |_, mut saga| {
                    Box::pin(async move {
                        saga.step(
                            "ordinary successful effect",
                            |_| async { Outcome::<_, &'static str>::Ok(1_u8) },
                            no_compensation,
                        )
                        .await
                        .unwrap();
                        let phase = saga
                            .step_with_undo(
                                "prepared effect",
                                Cell::new(7_u8),
                                |_, undo| {
                                    Box::pin(async move {
                                        undo.set(9);
                                        Outcome::<_, &'static str>::Ok(String::from("acknowledged"))
                                    })
                                },
                                |_, _: Cell<u8>| async {
                                    panic!("whole-saga commit must disarm compensation");
                                },
                            )
                            .await
                            .unwrap();
                        assert!(phase.is_success());
                        let Outcome::Ok((key, value)) = phase.outcome else {
                            panic!("forward result");
                        };
                        assert_eq!(saga.get(&key).unwrap().get(), 9);
                        saga.get_mut(&key).unwrap().set(11);
                        Outcome::Ok(value)
                    })
                },
            )
            .unwrap();
        let report = handle.join().await.unwrap();
        assert!(report.is_success(), "{report:?}");
        assert!(matches!(&report.lifecycle.usage.unwrap().outcome,
            Outcome::Ok(value) if value == "acknowledged"));
        let resolution = report.resolution.unwrap();
        assert_eq!(resolution.decision, AsyncSagaDecision::Commit);
        assert!(resolution.compensations.is_none());
        assert_eq!(
            resolution.disposals.iter().map(|entry| entry.step).collect::<Vec<_>>(),
            [1, 0]
        );
    });
}

struct PreparedRetirementPanic<'a>(&'a mut u8);
impl Future for PreparedRetirementPanic<'_> {
    type Output = Outcome<u8, &'static str>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        *self.0 = 19;
        Poll::Ready(Outcome::Ok(21))
    }
}
impl Drop for PreparedRetirementPanic<'_> {
    fn drop(&mut self) {
        *self.0 = 23;
        panic!("prepared forward retirement");
    }
}

fn failing_forward(
    failure: u8,
    undo: &mut u8,
) -> BracketUseFuture<'_, u8, &'static str> {
    *undo = 7;
    if failure == 2 {
        *undo = 13;
        panic!("prepared forward factory");
    }
    if failure == 4 {
        return Box::pin(PreparedRetirementPanic(undo));
    }
    Box::pin(async move {
        *undo = 13;
        match failure {
            0 => Outcome::Err("acknowledgement lost"),
            1 => Outcome::Cancelled(CancelReason::user("uncertain remote effect")),
            3 => panic!("prepared forward poll"),
            _ => unreachable!(),
        }
    })
}

#[test]
fn prepared_failures_compensate_latest_state_before_older_effects() {
    for failure in 0_u8..5 {
        run_case(move |cx| async move {
            let log = Arc::new(Mutex::new(Vec::new()));
            let observed = Arc::clone(&log);
            let mut handle = cx
                .spawn_saga::<(), &'static str, &'static str, _>(
                    BracketConfig::new(8),
                    3,
                    move |_, mut saga| {
                        Box::pin(async move {
                            let oldest = Arc::clone(&observed);
                            saga.step(
                                "oldest",
                                |_| async { Outcome::<_, &'static str>::Ok(0_u8) },
                                move |_, undo| async move {
                                    oldest.lock().push(undo);
                                    Outcome::Ok(())
                                },
                            )
                            .await
                            .unwrap();
                            let newest = Arc::clone(&observed);
                            let phase = saga
                                .step_with_undo(
                                    "uncertain effect",
                                    1_u8,
                                    move |_, undo| failing_forward(failure, undo),
                                    move |_, undo| async move {
                                        newest.lock().push(undo);
                                        Outcome::Err("reconciliation refused")
                                    },
                                )
                                .await
                                .unwrap();
                            assert!(!phase.is_success());
                            if failure == 4 {
                                assert!(matches!(phase.outcome, Outcome::Ok((_, 21))));
                                assert_eq!(phase.retirement_panic.unwrap().message(),
                                    "prepared forward retirement");
                            }
                            assert_eq!(saga.abort_reason().unwrap().reason,
                                AsyncSagaAbortReason::FailedStep);
                            // A caught forward error cannot commit the earlier effects.
                            Outcome::Ok(())
                        })
                    },
                )
                .unwrap();
            let report = handle.join().await.unwrap();
            assert!(!report.committed());
            let resolution = report.resolution.unwrap();
            assert_eq!(resolution.steps[1].state, AsyncSagaStepState::Failed);
            let cleanup = resolution.compensations.unwrap();
            assert!(cleanup.complete);
            assert_eq!(cleanup.entries.iter().map(|entry| entry.index).collect::<Vec<_>>(), [1, 0]);
            assert!(matches!(cleanup.entries[0].phase.outcome,
                Outcome::Err("reconciliation refused")));
            assert!(cleanup.entries[1].phase.is_success());
            assert_eq!(*log.lock(), [if failure == 4 { 23 } else { 13 }, 0]);
        });
    }
}

#[test]
fn prepared_refusal_returns_both_original_owners_without_forward_effects() {
    run_case(|cx| async move {
        let mut handle = cx
            .spawn_saga::<(), &'static str, &'static str, _>(
                BracketConfig::new(4),
                0,
                |work_cx, mut saga| {
                    Box::pin(async move {
                        let marker = Arc::new(AtomicUsize::new(0));
                        let original = Arc::clone(&marker);
                        let captured = Arc::clone(&marker);
                        let error = saga
                            .step_with_undo(
                                "no capacity",
                                original,
                                |_, _| -> BracketUseFuture<'_, (), &'static str> {
                                    panic!("refused forward was invoked");
                                },
                                move |_, undo| async move {
                                    assert!(Arc::ptr_eq(&captured, &undo));
                                    undo.store(1, Ordering::SeqCst);
                                    Outcome::Ok(())
                                },
                            )
                            .await
                            .unwrap_err();
                        assert_eq!(error.error, ResourceStackError::Capacity { limit: 0 });
                        assert!(Arc::ptr_eq(&marker, &error.resource));
                        assert_eq!(marker.load(Ordering::SeqCst), 0);
                        // Both returned owners remain usable by the caller.
                        assert!(matches!((error.release)(work_cx, error.resource).await,
                            Outcome::Ok(())));
                        assert_eq!(marker.load(Ordering::SeqCst), 1);
                        Outcome::Ok(())
                    })
                },
            )
            .unwrap();
        let resolution = handle.join().await.unwrap().resolution.unwrap();
        assert_eq!(resolution.decision, AsyncSagaDecision::Rollback);
        assert!(resolution.steps.is_empty());
        assert!(resolution.compensations.unwrap().entries.is_empty());
    });
}

#[test]
fn prepared_token_is_compensated_when_cancellation_prevents_forward_start() {
    run_case(|cx| async move {
        let compensated = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&compensated);
        let mut handle = cx
            .spawn_saga::<(), &'static str, &'static str, _>(
                BracketConfig::new(4),
                1,
                move |work_cx, mut saga| {
                    Box::pin(async move {
                        work_cx.cancel_fast(CancelKind::User);
                        let phase = saga
                            .step_with_undo(
                                "cancelled before dispatch",
                                29_u8,
                                |_, _| -> BracketUseFuture<'_, (), &'static str> {
                                    panic!("cancelled forward was invoked");
                                },
                                move |_, undo| async move {
                                    observed.store(usize::from(undo), Ordering::SeqCst);
                                    Outcome::Ok(())
                                },
                            )
                            .await
                            .unwrap();
                        assert!(matches!(phase.outcome, Outcome::Cancelled(_)));
                        Outcome::Ok(())
                    })
                },
            )
            .unwrap();
        let report = handle.join().await.unwrap();
        assert!(!report.committed());
        assert!(report.resolution.unwrap().cleanup_succeeded());
        assert_eq!(compensated.load(Ordering::SeqCst), 29);
    });
}

struct PreparedDescendant(Arc<AtomicUsize>);
impl Drop for PreparedDescendant {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

async fn prepared_pending_case(cx: Cx, mode: u8) {
    let retired = Arc::new(AtomicUsize::new(0));
    let observed_retirement = Arc::clone(&retired);
    let log = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&log);
    let (parked, mut wait_parked) = oneshot::channel();
    let (undo_started, mut wait_undo) = oneshot::channel();
    let (finish_undo, mut undo_gate) = oneshot::channel();
    let (oldest_finished, mut wait_oldest) = oneshot::channel();
    let handle = cx
        .spawn_saga::<(), &'static str, &'static str, _>(
            BracketConfig::new(32),
            2,
            move |_, mut saga| {
                Box::pin(async move {
                    let oldest = Arc::clone(&observed);
                    saga.step(
                        "oldest effect",
                        |_| async { Outcome::<_, &'static str>::Ok(0_u8) },
                        move |_, undo| async move {
                            oldest.lock().push(undo);
                            oldest_finished.send_blocking(()).unwrap();
                            Outcome::Ok(())
                        },
                    )
                    .await
                    .unwrap();
                    let reached_pending = Arc::new(AtomicUsize::new(0));
                    let pending_witness = Arc::clone(&reached_pending);
                    let child_retired = Arc::clone(&observed_retirement);
                    let mut step = Box::pin(saga.step_with_undo(
                        "effect with an uncertain acknowledgement",
                        1_u8,
                        move |work_cx, undo| {
                            Box::pin(async move {
                                *undo = 7;
                                let (child_started, mut wait_child) = oneshot::channel();
                                let _child = work_cx.spawn(move |child_cx| async move {
                                    let _retirement = PreparedDescendant(child_retired);
                                    child_started.send_blocking(()).unwrap();
                                    child_cx.cancelled().await;
                                }).unwrap();
                                wait_child.recv(&work_cx).await.unwrap();
                                let mut cancellation = std::pin::pin!(work_cx.cancelled());
                                let mut parked = Some(parked);
                                poll_fn(|task| {
                                    let result = cancellation.as_mut().poll(task);
                                    if result.is_pending() {
                                        pending_witness.store(1, Ordering::SeqCst);
                                        if let Some(parked) = parked.take() {
                                            parked.send_blocking(()).unwrap();
                                        }
                                    }
                                    result
                                }).await;
                                *undo = 17;
                                Outcome::<(), &'static str>::Cancelled(
                                    work_cx.cancel_reason().unwrap())
                            })
                        },
                        move |_, undo| async move {
                            assert_eq!(observed_retirement.load(Ordering::SeqCst), 1,
                                "undo ran before the forward descendant retired");
                            observed.lock().push(undo);
                            undo_started.send_blocking(()).unwrap();
                            undo_gate.recv_uninterruptible().await.unwrap();
                            Outcome::Ok(())
                        },
                    ));
                    if mode == 0 {
                        poll_fn(|task| {
                            assert!(step.as_mut().poll(task).is_pending());
                            if reached_pending.load(Ordering::SeqCst) == 1 {
                                Poll::Ready(())
                            } else {
                                Poll::Pending
                            }
                        }).await;
                        drop(step);
                        assert_eq!(saga.abort_reason().unwrap().reason,
                            AsyncSagaAbortReason::IncompleteStep);
                    } else {
                        let phase = step.await.unwrap();
                        assert!(matches!(phase.outcome, Outcome::Cancelled(_)));
                    }
                    Outcome::Ok(())
                })
            },
        )
        .unwrap();
    let mut handle = Some(handle);
    wait_parked.recv(&cx).await.unwrap();
    if mode == 1 {
        handle.as_ref().unwrap().abort();
    } else if mode == 2 {
        drop(handle.take());
    }
    wait_undo.recv_uninterruptible().await.unwrap();
    let latest = if mode == 0 { 7 } else { 17 };
    assert_eq!(retired.load(Ordering::SeqCst), 1);
    assert_eq!(*log.lock(), [latest]);
    if let Some(handle) = &mut handle {
        let mut join = std::pin::pin!(handle.join());
        poll_fn(|task| {
            assert!(join.as_mut().poll(task).is_pending(),
                "saga returned before its pending compensation completed");
            Poll::Ready(())
        }).await;
    }
    finish_undo.send_blocking(()).unwrap();
    wait_oldest.recv_uninterruptible().await.unwrap();
    if let Some(mut handle) = handle {
        let report = handle.join().await.unwrap();
        assert!(!report.committed());
        let resolution = report.resolution.unwrap();
        assert!(resolution.cleanup_succeeded());
        assert_eq!(resolution.steps[1].state,
            if mode == 0 { AsyncSagaStepState::Pending } else { AsyncSagaStepState::Failed });
        assert_eq!(resolution.compensations.unwrap().entries.iter()
            .map(|entry| entry.index).collect::<Vec<_>>(), [1, 0]);
    }
    assert_eq!(*log.lock(), [latest, 0]);
}

#[test]
fn prepared_pending_steps_and_dropped_sagas_keep_undo_until_descendants_drain() {
    for mode in 0..3 {
        run_case(move |cx| prepared_pending_case(cx, mode));
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn native_prepared_pending_steps_and_dropped_sagas_keep_owned_undo() {
    super::native::bounded(|| {
        for multithread in [false, true] {
            for mode in 0..3 {
                let runtime = if multithread {
                    crate::runtime::RuntimeBuilder::new().worker_threads(2).build().unwrap()
                } else {
                    crate::runtime::RuntimeBuilder::current_thread().build().unwrap()
                };
                runtime.block_on(async move {
                    prepared_pending_case(Cx::current().unwrap(), mode).await;
                });
                assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(5)));
            }
        }
    });
}

#[test]
#[cfg(all(not(target_arch = "wasm32"), panic = "unwind"))]
fn unpolled_prepared_step_contains_panicking_capture_drops_during_outer_unwind() {
    const CHILD_ENV: &str = "ASUPERSYNC_PREPARED_SAGA_UNWIND_CHILD";
    const CHILD_PASS_EXIT: i32 = 78;
    if std::env::var_os(CHILD_ENV).is_none() {
        let (_, module) = module_path!().split_once("::").unwrap();
        let test = format!(
            "{module}::unpolled_prepared_step_contains_panicking_capture_drops_during_outer_unwind"
        );
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg(test).arg("--nocapture")
            .env(CHILD_ENV, "1").spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(CHILD_PASS_EXIT),
                    "unpolled prepared-step child failed: {status}");
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("unpolled prepared-step child exceeded 30 seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    struct Bomb(Arc<AtomicUsize>);
    impl Drop for Bomb {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("prepared step capture destructor");
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let mut saga = AsyncSaga::<&'static str>::new(1);
    let mut scope = AsyncSagaScope { cx: Cx::for_testing(), saga: &mut saga };
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let forward_capture = Bomb(Arc::clone(&drops));
        let compensation_capture = Bomb(Arc::clone(&drops));
        let _unpolled = scope.step_with_undo(
            "never admitted",
            Bomb(Arc::clone(&drops)),
            move |_, _| -> BracketUseFuture<'_, (), &'static str> {
                drop(forward_capture);
                panic!("unpolled forward factory");
            },
            move |_, undo| async move {
                drop(compensation_capture);
                drop(undo);
                Outcome::Ok(())
            },
        );
        panic!("original prepared-step owner panic");
    })).unwrap_err();
    assert_eq!(caught.downcast_ref::<&str>(), Some(&"original prepared-step owner panic"));
    assert_eq!(drops.load(Ordering::SeqCst), 3);
    assert!(scope.saga.steps().is_empty());

    struct PendingBomb<'a> {
        undo: &'a mut u8,
        drops: Arc<AtomicUsize>,
    }
    impl Future for PendingBomb<'_> {
        type Output = Outcome<(), &'static str>;
        fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            *self.undo = 41;
            Poll::Pending
        }
    }
    impl Drop for PendingBomb<'_> {
        fn drop(&mut self) {
            *self.undo = 43;
            self.drops.fetch_add(1, Ordering::SeqCst);
            panic!("active prepared forward destructor");
        }
    }
    let latest = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&latest);
    let forward_drops = Arc::clone(&drops);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut pending = Box::pin(scope.step_with_undo(
            "admitted before the owner unwinds",
            1_u8,
            move |_, undo| Box::pin(PendingBomb { undo, drops: forward_drops }),
            move |_, undo| async move {
                observed.store(usize::from(undo), Ordering::SeqCst);
                Outcome::Ok(())
            },
        ));
        assert!(pending.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        panic!("original active-step owner panic");
    })).unwrap_err();
    assert_eq!(caught.downcast_ref::<&str>(), Some(&"original active-step owner panic"));
    assert_eq!(drops.load(Ordering::SeqCst), 4);
    assert_eq!(scope.abort_reason().unwrap().reason, AsyncSagaAbortReason::IncompleteStep);
    // This standalone fixture started no descendant work; the only forward
    // future has been destroyed, so its undo can now be recovered safely.
    let cleanup_cx = Cx::for_testing();
    let mut cleanup = std::pin::pin!(scope.saga.compensate_after_quiescence(&cleanup_cx));
    let Poll::Ready(report) = cleanup.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
        panic!("immediate prepared compensation did not complete");
    };
    assert!(report.is_success());
    assert_eq!(latest.load(Ordering::SeqCst), 43);
    std::process::exit(CHILD_PASS_EXIT);
}
