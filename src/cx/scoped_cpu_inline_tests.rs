use super::*;
use crate::types::Budget;

/// G0: the lending property itself — children borrow run-local,
/// non-'static state (the exact thing task spawns cannot do).
#[test]
fn children_borrow_run_local_state() {
    let cx = Cx::for_testing();
    let cells: Vec<Mutex<u64>> = (0..4).map(|_| Mutex::new(0)).collect();
    let out = cx
        .scoped_cpu(4, |scope| {
            for (i, cell) in cells.iter().enumerate() {
                scope
                    .spawn(move |child| {
                        assert_eq!(child.child(), i);
                        child.checkpoint().expect("healthy scope");
                        *cell.lock().expect("cell") = (i as u64 + 1) * 10;
                    })
                    .expect("under cap");
            }
            scope.spawned()
        })
        .expect("scope completes");
    assert_eq!(out, 4);
    let values: Vec<u64> = cells.iter().map(|c| *c.lock().expect("cell")).collect();
    assert_eq!(values, vec![10, 20, 30, 40]);
}

/// Worker cap is a structured refusal, not a queue or a panic.
#[test]
fn worker_cap_refuses_structurally() {
    let cx = Cx::for_testing();
    let refused = cx
        .scoped_cpu(2, |scope| {
            scope.spawn(|_| {}).expect("first fits");
            scope.spawn(|_| {}).expect("second fits");
            match scope.spawn(|_| {}) {
                Err(ScopedCpuError::WorkerCapExceeded { cap }) => cap,
                other => panic!("expected cap refusal, got {other:?}"),
            }
        })
        .expect("scope completes");
    assert_eq!(refused, 2);
}

/// G4: one child panics -> first payload recorded, latch drains the
/// sibling at its next checkpoint, everything joins, structured
/// error out, and the Cx remains usable.
#[test]
fn child_panic_is_contained_and_drains_siblings() {
    let cx = Cx::for_testing();
    let err = cx
        .scoped_cpu(2, |scope| {
            scope
                .spawn(|child| {
                    // Drain loop: spin on checkpoint until the
                    // sibling's panic raises the latch.
                    while child.checkpoint().is_ok() {
                        std::hint::spin_loop();
                    }
                })
                .expect("under cap");
            scope
                .spawn(|_| panic!("deliberate test panic"))
                .expect("under cap");
        })
        .expect_err("panic must surface");
    match err {
        ScopedCpuError::ChildPanicked { child, message } => {
            assert_eq!(child, 1);
            assert!(message.contains("deliberate test panic"));
        }
        other => panic!("expected ChildPanicked, got {other:?}"),
    }
    // The scope is a region of the TASK; the task itself is intact.
    cx.checkpoint().expect("cx usable after contained panic");
}

/// G4: cancellation requested mid-run reaches children through
/// their checkpoints; they drain; scoped_cpu surfaces Cancelled at
/// exit after all joins.
#[test]
fn cancellation_propagates_to_children_and_surfaces() {
    let cx = Cx::for_testing();
    let err = cx
        .scoped_cpu(1, |scope| {
            scope
                .spawn(|child| {
                    // Request cancellation on the owning task from
                    // inside the worker, then observe it at the
                    // next checkpoint (bounded latency).
                    child.cx.set_cancel_requested(true);
                    assert!(child.is_cancel_requested());
                    child
                        .checkpoint()
                        .expect_err("checkpoint observes the request");
                })
                .expect("under cap");
        })
        .expect_err("exit checkpoint surfaces cancellation");
    assert!(matches!(err, ScopedCpuError::Cancelled(_)));
}

/// Entry refusal: an already-exhausted budget never starts work.
#[test]
fn exhausted_budget_refuses_at_entry() {
    let cx = Cx::for_testing_with_budget(Budget {
        poll_quota: 0,
        ..Budget::INFINITE
    });
    let spawned = AtomicUsize::new(0);
    let err = cx
        .scoped_cpu(4, |scope| {
            scope
                .spawn(|_| {
                    spawned.fetch_add(1, Ordering::SeqCst);
                })
                .ok();
        })
        .expect_err("zero poll quota refuses at entry");
    assert!(matches!(err, ScopedCpuError::Cancelled(_)));
    assert_eq!(spawned.load(Ordering::SeqCst), 0, "no work started");
}

/// A panic in the orchestrator closure must raise the scope latch so a
/// child looping until its next checkpoint drains instead of blocking the
/// implicit `std::thread::scope` join forever. Without the latch-on-panic,
/// this test would hang (and be caught as a CI timeout).
#[test]
fn orchestrator_panic_drains_looping_child_and_propagates() {
    let cx = Cx::for_testing();
    let child_saw_cancel = Arc::new(AtomicBool::new(false));
    let child_saw_cancel_for_closure = Arc::clone(&child_saw_cancel);

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = cx.scoped_cpu(2, |scope| {
            let flag = Arc::clone(&child_saw_cancel_for_closure);
            scope
                .spawn(move |child| {
                    // Documented worker pattern: loop until checkpoint errs.
                    while child.checkpoint().is_ok() {
                        std::hint::spin_loop();
                    }
                    flag.store(true, Ordering::SeqCst);
                })
                .expect("first child fits under cap");
            // Orchestrator panics after spawning the looping child.
            panic!("orchestrator boom");
        });
    }));

    assert!(
        outcome.is_err(),
        "orchestrator panic must propagate to the caller"
    );
    assert!(
        child_saw_cancel.load(Ordering::SeqCst),
        "looping child must observe the latch and drain (no hang)"
    );
}

#[test]
fn post_latch_spawn_is_refused_without_starting_worker_ne8jdw() {
    let cx = Cx::for_testing();
    let late_worker_ran = AtomicBool::new(false);

    let err = cx
        .scoped_cpu(2, |scope| {
            scope
                .spawn(|_| panic!("raise scope latch"))
                .expect("first child fits under cap");

            while !scope.latch.load(Ordering::Acquire) {
                std::thread::yield_now();
            }

            let late_spawn = scope.spawn(|_| {
                late_worker_ran.store(true, Ordering::SeqCst);
            });
            assert!(matches!(late_spawn, Err(ScopedCpuError::Cancelled(_))));
            assert_eq!(scope.spawned(), 1, "refused worker is not counted");
        })
        .expect_err("first child panic must surface after drain");

    assert!(matches!(
        err,
        ScopedCpuError::ChildPanicked { child: 0, .. }
    ));
    assert!(
        !late_worker_ran.load(Ordering::SeqCst),
        "post-latch worker body must never start"
    );
}

#[test]
fn cancelled_scope_refuses_new_worker_ne8jdw() {
    let cx = Cx::for_testing();
    let worker_ran = AtomicBool::new(false);

    let err = cx
        .scoped_cpu(1, |scope| {
            cx.set_cancel_requested(true);
            let spawn = scope.spawn(|_| {
                worker_ran.store(true, Ordering::SeqCst);
            });
            assert!(matches!(spawn, Err(ScopedCpuError::Cancelled(_))));
            assert_eq!(scope.spawned(), 0, "refused worker is not counted");
        })
        .expect_err("exit checkpoint must retain cancellation");

    assert!(matches!(err, ScopedCpuError::Cancelled(_)));
    assert!(
        !worker_ran.load(Ordering::SeqCst),
        "cancelled scope must not start newly submitted work"
    );
}

fn wait_for_admission_checkpoints(cx: &Cx, minimum: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while cx.checkpoint_state().checkpoint_count < minimum {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::yield_now();
    }
    true
}

/// A scope's drain must release its blocked spawn even while another scope
/// keeps all runtime-wide admission capacity. The owner itself stays healthy.
#[test]
fn draining_scope_refuses_waiter_before_unrelated_capacity_is_released() {
    let admission = Arc::new(ScopedCpuAdmission::new(1));
    let holder_latch = AtomicBool::new(false);
    let holder = admission
        .acquire(&Cx::for_testing(), &holder_latch)
        .expect("unrelated scope holds the only permit");
    let cx = Cx::for_testing();
    let latch = Arc::new(AtomicBool::new(false));
    let worker_ran = Arc::new(AtomicBool::new(false));

    std::thread::scope(|threads| {
        let scope = ScopedCpu {
            scope: threads,
            cx: cx.clone(),
            latch: Arc::clone(&latch),
            panic_box: Arc::new(Mutex::new(None)),
            spawned: Arc::new(AtomicUsize::new(0)),
            cap: 1,
            admission: Arc::clone(&admission),
        };
        let ran = Arc::clone(&worker_ran);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let waiter = threads.spawn(move || {
            let result = scope.spawn(move |_| ran.store(true, Ordering::Release));
            done_tx
                .send((result, scope.spawned()))
                .expect("report waiting spawn");
        });

        // One spawn checkpoint and two admission checkpoints prove that the
        // waiter passed the entry check and retried while capacity stayed full.
        let was_waiting = wait_for_admission_checkpoints(&cx, 3);
        admission.request_scope_drain(&latch);
        let stopped_while_full = done_rx.recv_timeout(Duration::from_secs(2));
        let occupied = *admission.in_use.lock().expect("admission accounting");

        // Release and join before asserting, so the old hanging behavior also
        // fails cleanly without stranding a test thread.
        drop(holder);
        waiter.join().expect("join waiting spawn");
        assert!(was_waiting, "spawn reached the capacity wait");
        let (result, spawned) = stopped_while_full
            .expect("scope drain must not wait for unrelated capacity release");
        assert!(matches!(result, Err(ScopedCpuError::Cancelled(_))));
        assert_eq!(spawned, 0, "refused reservation is returned");
        assert_eq!(occupied, 1, "the unrelated holder is still admitted");
    });

    assert!(!worker_ran.load(Ordering::Acquire));
    assert!(!cx.is_cancel_requested(), "scope drain does not cancel its owner");
    cx.checkpoint().expect("owner remains usable");
    assert_eq!(*admission.in_use.lock().expect("admission accounting"), 0);
}

/// A panic payload can own cleanup that waits for the blocked orchestrator.
/// The failed worker still owns its permit while that payload is being dropped.
#[test]
fn sibling_panic_releases_waiting_spawn_before_payload_cleanup() {
    struct BlockingPanicPayload {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl Drop for BlockingPanicPayload {
        fn drop(&mut self) {
            let _ = self.entered.send(());
            let _ = self.release.recv();
        }
    }

    let admission = Arc::new(ScopedCpuAdmission::new(1));
    let cx = Cx::for_testing();
    let panic_box = Arc::new(Mutex::new(None));
    let worker_ran = Arc::new(AtomicBool::new(false));
    let (panic_tx, panic_rx) = std::sync::mpsc::channel();
    let (cleanup_tx, cleanup_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();

    std::thread::scope(|threads| {
        let scope = ScopedCpu {
            scope: threads,
            cx: cx.clone(),
            latch: Arc::new(AtomicBool::new(false)),
            panic_box: Arc::clone(&panic_box),
            spawned: Arc::new(AtomicUsize::new(0)),
            cap: 2,
            admission: Arc::clone(&admission),
        };
        scope
            .spawn(move |_| {
                let _ = panic_rx.recv();
                std::panic::panic_any(BlockingPanicPayload {
                    entered: cleanup_tx,
                    release: release_rx,
                });
            })
            .expect("first worker occupies the runtime permit");
        let before_wait = cx.checkpoint_state().checkpoint_count;
        let ran = Arc::clone(&worker_ran);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let waiter = threads.spawn(move || {
            let result = scope.spawn(move |_| ran.store(true, Ordering::Release));
            done_tx
                .send((result, scope.spawned()))
                .expect("report waiting spawn");
        });

        let was_waiting = wait_for_admission_checkpoints(&cx, before_wait + 3);
        let _ = panic_tx.send(());
        let cleanup_entered = cleanup_rx.recv_timeout(Duration::from_secs(2));
        let stopped_during_cleanup = done_rx.recv_timeout(Duration::from_secs(2));
        let occupied = *admission.in_use.lock().expect("admission accounting");

        // Let the failed worker release its permit even when the regression
        // makes the waiting spawn miss the scope's panic/drain notification.
        let _ = release_tx.send(());
        waiter.join().expect("join waiting spawn");
        assert!(was_waiting, "second spawn waited before its sibling panicked");
        assert!(cleanup_entered.is_ok(), "panic payload entered cleanup");
        let (result, spawned) = stopped_during_cleanup
            .expect("sibling panic must release admission before payload cleanup finishes");
        assert!(matches!(result, Err(ScopedCpuError::Cancelled(_))));
        assert_eq!(spawned, 1, "only the failed worker was admitted");
        assert_eq!(occupied, 1, "panic payload still retains the worker permit");
    });

    assert_eq!(panic_box.lock().expect("first panic").as_ref().unwrap().0, 0);
    assert!(!worker_ran.load(Ordering::Acquire));
    assert!(!cx.is_cancel_requested());
    assert_eq!(*admission.in_use.lock().expect("admission accounting"), 0);
}

#[test]
fn scope_drain_refuses_admission_on_both_sides_of_capacity_release() {
    for release_before_drain in [false, true] {
        let admission = Arc::new(ScopedCpuAdmission::new(1));
        let cx = Cx::for_testing();
        let healthy = AtomicBool::new(false);
        let drained = AtomicBool::new(false);
        let mut holder = Some(admission.acquire(&cx, &healthy).expect("initial permit"));
        if release_before_drain {
            drop(holder.take());
        }
        admission.request_scope_drain(&drained);
        drop(holder);

        assert!(admission.acquire(&cx, &drained).is_err());
        assert_eq!(*admission.in_use.lock().expect("admission accounting"), 0);
        let fresh = admission
            .acquire(&cx, &healthy)
            .expect("draining one scope must not close shared admission");
        assert_eq!(*admission.in_use.lock().expect("admission accounting"), 1);
        drop(fresh);
        assert_eq!(*admission.in_use.lock().expect("admission accounting"), 0);
    }
}
