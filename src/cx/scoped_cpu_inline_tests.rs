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
