    #![allow(clippy::pedantic, clippy::nursery)]
    use super::*;
    use crate::channel::oneshot;
    use crate::lab::{LabConfig, LabRuntime};
    use std::cell::Cell;

    fn run_case<F, Fut>(factory: F)
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut lab = LabRuntime::new(LabConfig::new(0xde_9001).max_steps(16384));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
            factory(Cx::current().expect("registered test owner")).await;
        }).unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        join.try_join().unwrap().expect("dependency scenario completed");
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
        if lab.state.region(root).is_some() {
            let (tasks, wakes) = lab.state.cancel_request(root, &CancelReason::shutdown(), None).into_parts();
            assert!(tasks.is_empty());
            wakes.dispatch();
            lab.state.advance_region_state(root);
        }
        assert!(lab.state.region(root).is_none());
    }

    async fn parked<F: Future>(future: F, signal: oneshot::Sender<()>) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut signal = Some(signal);
        poll_fn(|task| {
            let result = future.as_mut().poll(task);
            if result.is_pending() {
                if let Some(signal) = signal.take() { signal.send_blocking(()).unwrap(); }
            }
            result
        }).await
    }

    #[test]
    fn detached_context_refuses_before_work_factory_invocation() {
        let cx = Cx::for_testing();
        let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
        let result = futures_lite::future::block_on(dependencies.run(
            &cx, DependencyScopeConfig::new(Budget::INFINITE),
            |_, _| -> std::future::Ready<Outcome<(), ()>> { panic!("not admitted") },
        ));
        assert!(matches!(result, Err(DependencyScopeError::Region(ChildRegionError::NoRuntimeGateway))));
    }

    #[test]
    fn successful_send_only_value_survives_task_join_and_region_close() {
        run_case(|cx| async move {
            let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
            let report = dependencies.run(&cx, DependencyScopeConfig::new(Budget::INFINITE),
                |body, snapshot| async move {
                    assert!(snapshot.is_empty());
                    assert_eq!(body.task_id(), Cx::current().unwrap().task_id());
                    crate::runtime::yield_now().await;
                    Outcome::<_, Cell<String>>::Ok(Cell::new(41))
                },
            ).await.unwrap();
            assert!(report.is_success());
            assert!(matches!(report.work, Some(Ok(Outcome::Ok(value))) if value.get() == 41));
        });
    }

    #[test]
    fn typed_application_failure_is_not_replaced_by_control_metadata() {
        run_case(|cx| async move {
            let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
            let report = dependencies.run(&cx, DependencyScopeConfig::new(Budget::INFINITE),
                |_, _| async { Outcome::<(), _>::Err(Cell::new(73u32)) },
            ).await.unwrap();
            assert!(!report.is_success());
            assert!(report.stop.is_none());
            assert!(report.close.is_ok());
            assert!(matches!(report.work, Some(Ok(Outcome::Err(error))) if error.get() == 73));
        });
    }

    #[test]
    fn work_factory_panic_still_reaches_the_region_close_barrier() {
        run_case(|cx| async move {
            let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
            let report = dependencies.run(&cx, DependencyScopeConfig::new(Budget::INFINITE),
                |_, _| -> std::future::Ready<Outcome<(), ()>> { panic!("dependent factory sentinel") },
            ).await.unwrap();
            assert!(report.invoked);
            assert!(report.close.is_ok());
            assert!(!report.is_success());
            assert!(matches!(report.work, Some(Err(JoinError::Panicked(ref payload)))
                if payload.message() == "dependent factory sentinel"));
        });
    }

    #[test]
    fn caller_abort_during_descendant_close_preserves_completed_work_result() {
        run_case(|cx| async move {
            let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
            let (release, mut gate) = oneshot::channel::<()>();
            let (cleanup_parked, mut witness) = oneshot::channel();
            let mut controller = cx.spawn(move |driver| async move {
                dependencies.run(&driver, DependencyScopeConfig::new(Budget::INFINITE),
                    move |body, _| async move {
                        let (started, mut started_rx) = oneshot::channel();
                        let descendant = body.spawn(move |child| async move {
                            parked(child.cancelled(), started).await;
                            assert!(child.checkpoint().is_err());
                            parked(poll_fn(|task| gate.poll_recv_uninterruptible(task)), cleanup_parked)
                                .await.unwrap();
                        }).unwrap();
                        started_rx.recv(&body).await.unwrap();
                        drop(descendant); // The region, not this handle, owns the child.
                        Outcome::<_, ()>::Ok(42)
                    },
                ).await.unwrap()
            }).unwrap();
            witness.recv(&cx).await.unwrap();
            controller.abort();
            release.send_blocking(()).unwrap();
            let report = controller.join(&cx).await.unwrap();
            assert!(report.cancellation.is_some());
            assert!(matches!(report.stop, Some(DependencyStop::Cancelled(_))));
            assert!(matches!(report.work, Some(Ok(Outcome::Ok(42)))));
            assert!(report.close.is_ok());
            assert!(!report.is_success());
        });
    }
