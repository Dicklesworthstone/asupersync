use super::*;
use crate::channel::oneshot;
use crate::sync::pl::Mutex;
use std::sync::atomic::AtomicBool;

fn worker_config(mode: ManagedRestartMode) -> DynamicWorkerConfig {
    DynamicWorkerConfig::new(
        mode,
        SupervisionConfig::new(3, std::time::Duration::from_secs(60))
            .with_restart_policy(RestartPolicy::OneForOne)
            .with_backoff(BackoffStrategy::None),
    )
}

async fn drop_pending_replacement(replacement: impl Future) {
    let mut replacement = std::pin::pin!(replacement);
    poll_fn(|task| {
        assert!(replacement.as_mut().poll(task).is_pending());
        Poll::Ready(())
    })
    .await;
}

async fn abandoned_replacement_admission_keeps_predecessor(cx: Cx, worker: bool, resume: bool) {
    let mut owner = cx
        .open_dynamic_supervisor(DynamicSupervisorConfig::new(1))
        .await
        .unwrap();
    let old = owner
        .start_child(
            "service",
            managed(
                |_: Cx, _: ManagedGeneration| async {
                    Outcome::Err(String::from("previous generation's exact error"))
                },
                ManagedRestartMode::Temporary,
            ),
        )
        .await
        .unwrap();
    // Complete the real controller and region without consuming their receipt.
    // The replacement's next Pending must then be its own region admission.
    owner.wait_child_terminal(&old).await.unwrap();
    owner.require_reusable(&old).unwrap();
    let before_admission = owner.generation;
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let factory = move |_: Cx, _: ManagedGeneration| {
        counted.fetch_add(1, Ordering::SeqCst);
        async { Outcome::<(), String>::Ok(()) }
    };
    // Lab and the native current-thread scheduler apply region commands only
    // after this task yields, so this witnesses a genuinely pending admission.
    if worker {
        drop_pending_replacement(owner.replace_worker(
            &old,
            worker_config(ManagedRestartMode::Temporary),
            factory,
        ))
        .await;
    } else {
        drop_pending_replacement(
            owner.replace_child(&old, managed(factory, ManagedRestartMode::Temporary)),
        )
        .await;
    }

    assert_eq!(owner.generation, before_admission + 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(owner.len(), 1);
    assert_eq!(owner.children()[0].id, old);
    assert_eq!(owner.children()[0].state, DynamicChildState::Draining);
    assert!(matches!(owner.child_result(&old), Ok(Some(Ok(_)))));
    assert!(matches!(
        owner.start_child("service", done()).await,
        Err(DynamicSupervisorError::DuplicateName)
    ));
    assert!(matches!(
        owner.start_child("other", done()).await,
        Err(DynamicSupervisorError::Capacity)
    ));

    let previous = if resume {
        let replaced = owner.replace_child(&old, done()).await.unwrap();
        let new = replaced.replacement.unwrap();
        assert_eq!(new.name(), old.name());
        assert!(new.generation() > before_admission + 1);
        assert_ne!(new.region_id(), old.region_id());
        assert!(matches!(
            owner.request_stop(&old),
            Err(DynamicSupervisorError::StaleChild)
        ));
        assert!(!owner.child(&new).unwrap().stop_requested);
        assert!(owner.wait_child(&new).await.unwrap().close.is_ok());
        replaced.previous
    } else {
        owner.wait_child(&old).await.unwrap()
    };
    assert_eq!(previous.id, old);
    assert!(previous.close.is_ok());
    let report = previous.supervisor.unwrap();
    assert_eq!((report.started, report.joined), (1, 1));
    assert!(matches!(
        &report.children[0].outcome,
        Outcome::Err(message) if message == "previous generation's exact error"
    ));
    assert!(owner.is_empty());
    assert!(owner.shutdown().await.close.is_ok());
}

#[test]
fn dropped_replacement_admission_retains_old_result_for_reap_or_retry() {
    for worker in [false, true] {
        for resume in [false, true] {
            run_case(move |cx| abandoned_replacement_admission_keeps_predecessor(cx, worker, resume));
        }
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn native_dropped_replacement_admission_retains_old_result_for_reap_or_retry() {
    for worker in [false, true] {
        for resume in [false, true] {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let cx = Cx::current().expect("native runtime installs an owner context");
                abandoned_replacement_admission_keeps_predecessor(cx, worker, resume).await;
            });
            assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(5)));
        }
    }
}

#[test]
fn replacement_preserves_identity_and_owner_refusal_precedence() {
    for sealed in [false, true] {
        run_case(move |cx| async move {
            let mut owner = cx
                .open_dynamic_supervisor(DynamicSupervisorConfig::new(1))
                .await
                .unwrap();
            let old = owner.start_child("service", done()).await.unwrap();
            owner.wait_child_terminal(&old).await.unwrap();
            let sequence = owner.generation;
            let mut stale = old.clone();
            stale.generation += 1;
            let mut invalid = worker_config(ManagedRestartMode::Temporary);
            invalid.supervision.storm_threshold = Some(f64::NAN);
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&calls);
            let factory = move |_: Cx, _: ManagedGeneration| {
                counted.fetch_add(1, Ordering::SeqCst);
                async { Outcome::<(), String>::Ok(()) }
            };
            assert!(matches!(
                owner
                    .replace_worker(&stale, invalid.clone(), factory.clone())
                    .await,
                Err(DynamicSupervisorError::StaleChild)
            ));
            assert_eq!(owner.len(), 1);
            assert!(!owner.child(&old).unwrap().stop_requested);
            if sealed {
                owner.begin_shutdown();
            }
            let replaced = owner.replace_worker(&old, invalid, factory).await.unwrap();
            if sealed {
                assert!(matches!(
                    replaced.replacement,
                    Err(DynamicSupervisorError::Closing)
                ));
            } else {
                assert!(matches!(
                    replaced.replacement,
                    Err(DynamicSupervisorError::WorkerConfiguration(
                        crate::supervision::ManagedSupervisorBindError::InvalidStormThreshold
                    ))
                ));
            }
            assert_eq!(replaced.previous.id, old);
            assert!(replaced.previous.close.is_ok());
            assert_eq!(owner.generation, sequence);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(owner.is_empty());
            assert!(owner.shutdown().await.close.is_ok());
        });
    }
}

#[test]
#[cfg(all(not(target_arch = "wasm32"), panic = "unwind"))]
fn unpolled_replacement_drop_preserves_outer_unwind() {
    const CHILD_ENV: &str = "ASUPERSYNC_UNPOLLED_REPLACEMENT_UNWIND_CHILD";
    const CHILD_PASS_EXIT: i32 = 77;
    if std::env::var_os(CHILD_ENV).is_none() {
        // The regression aborts instead of unwinding, so isolate it from the
        // rest of the test binary and bound a possible stalled child process.
        let (_, module) = module_path!().split_once("::").unwrap();
        let test = format!("{module}::unpolled_replacement_drop_preserves_outer_unwind");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(test)
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                // A zero-test subprocess exits zero; the distinct success code
                // also proves that the requested regression actually ran.
                assert_eq!(
                    status.code(),
                    Some(CHILD_PASS_EXIT),
                    "unpolled replacement child failed: {status}"
                );
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("unpolled replacement child exceeded 30 seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    struct PanickingFactory(Arc<AtomicUsize>);

    impl ManagedChildFactory<String> for PanickingFactory {
        fn start(&self, _: Cx, _: ManagedGeneration) -> crate::supervision::ManagedChildFuture<String> {
            panic!("unpolled replacement must never invoke its factory");
        }
    }

    impl Drop for PanickingFactory {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("replacement factory destructor");
        }
    }

    for worker in [false, true] {
        run_case(move |cx| async move {
            let mut owner = cx
                .open_dynamic_supervisor(DynamicSupervisorConfig::new(1))
                .await
                .unwrap();
            let old = owner.start_child("service", done()).await.unwrap();
            let drops = Arc::new(AtomicUsize::new(0));
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let factory = PanickingFactory(Arc::clone(&drops));
                if worker {
                    let _replacement = owner.replace_worker(
                        &old,
                        worker_config(ManagedRestartMode::Temporary),
                        factory,
                    );
                    panic!("original owner unwind");
                } else {
                    let _replacement = owner.replace_child(
                        &old,
                        managed(factory, ManagedRestartMode::Temporary),
                    );
                    panic!("original owner unwind");
                }
            }))
            .unwrap_err();
            assert_eq!(caught.downcast_ref::<&str>(), Some(&"original owner unwind"));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(owner.len(), 1);
            assert!(!owner.child(&old).unwrap().stop_requested);
            assert!(owner.wait_child(&old).await.unwrap().close.is_ok());
            assert!(owner.shutdown().await.close.is_ok());
        });
    }
    std::process::exit(CHILD_PASS_EXIT);
}

#[test]
fn direct_worker_restarts_real_generations_without_restarting_an_independent_tree() {
    run_case(|cx| async move {
        let mut owner = cx
            .open_dynamic_supervisor(DynamicSupervisorConfig::new(2))
            .await
            .unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicUsize::new(0));
        let sibling = owner
            .start_child(
                "sibling",
                parked(Arc::clone(&started), Arc::clone(&stopped)),
            )
            .await
            .unwrap();
        wait_count(&started, 1).await;
        let generations = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&generations);
        let worker = owner
            .start_worker(
                "retrying-worker",
                worker_config(ManagedRestartMode::Transient),
                move |child: Cx, generation: ManagedGeneration| {
                    log.lock().push(generation);
                    assert_eq!(child.task_id(), generation.task);
                    assert_eq!(child.region_id(), generation.region);
                    async move {
                        if generation.number < 3 {
                            Outcome::Err(String::from("retryable failure"))
                        } else {
                            Outcome::Ok(())
                        }
                    }
                },
            )
            .await
            .unwrap();
        let completion = owner.wait_child(&worker).await.unwrap();
        let report = completion.supervisor.unwrap();
        assert!(completion.close.is_ok());
        assert!(report.outcome.is_ok());
        assert_eq!(report.started, 3);
        assert_eq!(report.joined, 3);
        assert_eq!(report.restart_batches, 2);
        assert_eq!(report.children.len(), 1);
        assert_eq!(report.children[0].name, "retrying-worker");
        assert_eq!(report.children[0].generation.number, 3);
        assert!(report.children[0].outcome.is_ok());
        {
            let log = generations.lock();
            assert_eq!(log.iter().map(|g| g.number).collect::<Vec<_>>(), [1, 2, 3]);
            for pair in log.windows(2) {
                assert_ne!(pair[0].region, pair[1].region);
                assert_ne!(pair[0].task, pair[1].task);
            }
        }
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(stopped.load(Ordering::SeqCst), 0);
        let sibling_report = owner
            .terminate_child(&sibling)
            .await
            .unwrap()
            .supervisor
            .unwrap();
        assert_eq!(sibling_report.restart_batches, 0);
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert!(owner.shutdown().await.close.is_ok());
    });
}

#[test]
fn invalid_worker_configuration_is_refused_before_factory_or_region_admission() {
    run_case(|cx| async move {
        let mut owner = cx
            .open_dynamic_supervisor::<()>(DynamicSupervisorConfig::new(1))
            .await
            .unwrap();
        let mut config = worker_config(ManagedRestartMode::Transient);
        config.supervision.storm_threshold = Some(f64::NAN);
        let result = owner
            .start_worker("bad-policy", config, |_: Cx, _: ManagedGeneration| {
                panic!("invalid configuration must never invoke this factory");
                #[allow(unreachable_code)]
                std::future::ready(Outcome::Ok(()))
            })
            .await;
        assert!(matches!(
            result,
            Err(DynamicSupervisorError::WorkerConfiguration(
                crate::supervision::ManagedSupervisorBindError::InvalidStormThreshold
            ))
        ));
        assert!(owner.is_empty());
        assert_eq!(owner.generation, 0, "no admission sequence was allocated");
        assert!(owner.shutdown().await.close.is_ok());
    });
}

#[test]
fn group_termination_validates_all_ids_before_stopping_any_member() {
    run_case(|cx| async move {
        let mut owner = cx
            .open_dynamic_supervisor(DynamicSupervisorConfig::new(2))
            .await
            .unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicUsize::new(0));
        let a = owner
            .start_child("a", parked(Arc::clone(&started), Arc::clone(&stopped)))
            .await
            .unwrap();
        let b = owner
            .start_child("b", parked(Arc::clone(&started), Arc::clone(&stopped)))
            .await
            .unwrap();
        wait_count(&started, 2).await;
        assert!(matches!(
            owner.terminate_children(&[a.clone(), a.clone()]).await,
            Err(DynamicSupervisorError::DuplicateChild)
        ));
        let mut stale = b.clone();
        stale.generation += 1;
        assert!(matches!(
            owner.terminate_children(&[a.clone(), stale]).await,
            Err(DynamicSupervisorError::StaleChild)
        ));
        assert!(
            owner
                .children()
                .iter()
                .all(|entry| entry.state == DynamicChildState::Submitted)
        );
        assert_eq!(stopped.load(Ordering::SeqCst), 0);
        let results = owner
            .terminate_children(&[b.clone(), a.clone()])
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().id, b);
        assert_eq!(results[1].as_ref().unwrap().id, a);
        assert!(
            results
                .iter()
                .all(|result| result.as_ref().unwrap().close.is_ok())
        );
        assert_eq!(stopped.load(Ordering::SeqCst), 2);
        assert!(owner.is_empty());
        assert!(
            !owner.is_closing(),
            "group termination does not shut down the owner"
        );
        assert!(owner.terminate_children(&[]).await.unwrap().is_empty());
        let new = owner.start_child("new", done()).await.unwrap();
        let completion = owner.wait_child(&new).await.unwrap();
        assert!(completion.close.is_ok());
        assert!(completion.supervisor.unwrap().outcome.is_ok());
        assert!(owner.shutdown().await.close.is_ok());
    });
}

#[test]
fn task_only_owner_cancellation_wakes_next_completed_and_drains_parked_children() {
    let mut lab = LabRuntime::new(LabConfig::new(0xd1_0002).max_steps(16384));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let published = Arc::new(Mutex::new(None));
    let publication = Arc::clone(&published);
    let started = Arc::new(AtomicUsize::new(0));
    let stopped = Arc::new(AtomicUsize::new(0));
    let child_started = Arc::clone(&started);
    let child_stopped = Arc::clone(&stopped);
    let (task, mut join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            let mut owner = cx
                .open_dynamic_supervisor(DynamicSupervisorConfig::new(1))
                .await
                .unwrap();
            owner
                .start_child("parked", parked(child_started, child_stopped))
                .await
                .unwrap();
            let completion = owner
                .next_completed()
                .await
                .unwrap()
                .expect("cancelled child was drained");
            assert!(completion.stop_requested);
            assert!(completion.close.is_ok());
            assert!(owner.is_closing());
            *publication.lock() = Some(owner.shutdown().await);
        })
        .unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    assert_eq!(started.load(Ordering::SeqCst), 1);
    assert_eq!(stopped.load(Ordering::SeqCst), 0);
    assert!(published.lock().is_none());
    assert!(join.try_join().unwrap().is_none());
    // Cancel only the task, not its owning root region. The registered owner
    // cancellation waker must initiate the dynamic children's stop protocol.
    join.abort();
    lab.run_until_idle();
    assert!(matches!(join.try_join(), Err(JoinError::Cancelled(_))));
    let report = published
        .lock()
        .take()
        .expect("cancelled owner still completed its drain");
    assert!(report.close.is_ok());
    assert_eq!(stopped.load(Ordering::SeqCst), 1);
    clean(&mut lab, root);
}

#[test]
fn dropped_waits_retain_a_joined_report_and_one_pending_boundary_finalizer() {
    let mut lab = LabRuntime::new(LabConfig::new(0xd1_0003).max_steps(16384));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let identity = Arc::new(Mutex::new(None));
    let publication = Arc::clone(&identity);
    let (continue_tx, mut continue_rx) = mpsc::channel::<()>(1);
    let (release, mut wait) = oneshot::channel::<()>();
    let finalizer_started = Arc::new(AtomicUsize::new(0));
    let finalizer_done = Arc::new(AtomicUsize::new(0));
    let owner_finalizer_started = Arc::clone(&finalizer_started);
    let dropped_wait = Arc::new(AtomicBool::new(false));
    let owner_dropped_wait = Arc::clone(&dropped_wait);
    let result = Arc::new(Mutex::new(None));
    let returned = Arc::clone(&result);
    let (task, mut join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            let mut owner = cx
                .open_dynamic_supervisor(DynamicSupervisorConfig::new(1))
                .await
                .unwrap();
            let id = owner.start_child("reusable", done()).await.unwrap();
            *publication.lock() = Some(id.clone());
            continue_rx.recv(&cx).await.unwrap();
            {
                let mut waiting = std::pin::pin!(owner.wait_child(&id));
                poll_fn(|cx| {
                    assert!(
                        waiting.as_mut().poll(cx).is_pending(),
                        "finalizer is still gated"
                    );
                    if owner_finalizer_started.load(Ordering::SeqCst) == 1 {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
            }
            assert_eq!(owner.len(), 1);
            assert_eq!(owner.children()[0].state, DynamicChildState::Draining);
            assert!(matches!(owner.child_result(&id).unwrap(), Some(Ok(_))));
            for _ in 0..3 {
                let mut waiting = std::pin::pin!(owner.wait_child(&id));
                poll_fn(|cx| {
                    assert!(waiting.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            assert!(matches!(
                owner.start_child("reusable", done()).await,
                Err(DynamicSupervisorError::DuplicateName)
            ));
            owner_dropped_wait.store(true, Ordering::SeqCst);
            let completion = owner.wait_child(&id).await.unwrap();
            let replacement = owner.start_child("reusable", done()).await.unwrap();
            assert_ne!(replacement.region_id(), id.region_id());
            assert!(replacement.generation() > id.generation());
            assert!(matches!(
                owner.request_stop(&id),
                Err(DynamicSupervisorError::StaleChild)
            ));
            let replacement_completion = owner.wait_child(&replacement).await.unwrap();
            assert!(replacement_completion.close.is_ok());
            assert!(replacement_completion.supervisor.unwrap().outcome.is_ok());
            let shutdown = owner.shutdown().await;
            *returned.lock() = Some((completion, shutdown));
        })
        .unwrap();
    let task_cx = lab.state.task(task).unwrap().cx.clone().unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    let id = identity.lock().clone().expect("real admitted boundary");
    let started = Arc::clone(&finalizer_started);
    let done = Arc::clone(&finalizer_done);
    assert!(
        lab.state
            .register_async_finalizer(id.region_id(), async move {
                started.fetch_add(1, Ordering::SeqCst);
                wait.recv_uninterruptible().await.unwrap();
                done.fetch_add(1, Ordering::SeqCst);
            })
    );
    continue_tx.try_send(()).unwrap();
    lab.run_until_idle();
    assert!(dropped_wait.load(Ordering::SeqCst));
    assert_eq!(finalizer_started.load(Ordering::SeqCst), 1);
    assert_eq!(finalizer_done.load(Ordering::SeqCst), 0);
    assert!(lab.state.region(id.region_id()).is_some());
    assert!(result.lock().is_none());
    release.send(&task_cx, ()).unwrap();
    lab.run_until_idle();
    assert!(join.try_join().unwrap().is_some());
    assert_eq!(
        finalizer_started.load(Ordering::SeqCst),
        1,
        "re-poll never restarts cleanup"
    );
    assert_eq!(finalizer_done.load(Ordering::SeqCst), 1);
    let (completion, shutdown) = result.lock().take().expect("resumed wait finishes");
    assert_eq!(completion.id, id);
    assert!(completion.close.is_ok());
    assert!(shutdown.close.is_ok());
    assert!(lab.state.region(id.region_id()).is_none());
    clean(&mut lab, root);
}

#[test]
fn group_and_owner_shutdown_drive_interdependent_boundary_finalizers_concurrently() {
    for group in [false, true] {
        let mut lab = LabRuntime::new(LabConfig::new(0xd1_0004).max_steps(16384));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let identities = Arc::new(Mutex::new(Vec::new()));
        let publication = Arc::clone(&identities);
        let completed = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&completed);
        let (continue_tx, mut continue_rx) = mpsc::channel::<()>(1);
        let (unblock_a, mut await_b) = oneshot::channel::<()>();
        let (task, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let mut owner = cx
                    .open_dynamic_supervisor(DynamicSupervisorConfig::new(2))
                    .await
                    .unwrap();
                let a = owner.start_child("a", super::done()).await.unwrap();
                let b = owner.start_child("b", super::done()).await.unwrap();
                *publication.lock() = vec![a.clone(), b.clone()];
                continue_rx.recv(&cx).await.unwrap();
                if group {
                    let reports = owner.terminate_children(&[a, b]).await.unwrap();
                    assert!(
                        reports
                            .into_iter()
                            .all(|report| report.unwrap().close.is_ok())
                    );
                }
                let report = owner.shutdown().await;
                assert!(report.close.is_ok());
                assert!(report.children.iter().all(|child| child.close.is_ok()));
                done.store(true, Ordering::SeqCst);
            })
            .unwrap();
        let task_cx = lab.state.task(task).unwrap().cx.clone().unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        let ids = identities.lock().clone();
        assert_eq!(ids.len(), 2);
        let a_done = Arc::new(AtomicBool::new(false));
        let a_flag = Arc::clone(&a_done);
        assert!(
            lab.state
                .register_async_finalizer(ids[0].region_id(), async move {
                    await_b.recv_uninterruptible().await.unwrap();
                    a_flag.store(true, Ordering::SeqCst);
                })
        );
        assert!(
            lab.state
                .register_async_finalizer(ids[1].region_id(), async move {
                    unblock_a.send(&task_cx, ()).unwrap();
                })
        );
        continue_tx.try_send(()).unwrap();
        lab.run_until_idle();
        assert!(
            completed.load(Ordering::SeqCst),
            "sequential close parks forever on boundary a before starting b"
        );
        assert!(a_done.load(Ordering::SeqCst));
        assert!(join.try_join().unwrap().is_some());
        clean(&mut lab, root);
    }
}
