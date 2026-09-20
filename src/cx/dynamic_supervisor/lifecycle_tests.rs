use super::*;
use crate::channel::oneshot;
use parking_lot::Mutex;
use std::sync::atomic::AtomicBool;

fn worker_config(mode: ManagedRestartMode) -> DynamicWorkerConfig {
    DynamicWorkerConfig::new(
        mode,
        SupervisionConfig::new(3, std::time::Duration::from_secs(60))
            .with_restart_policy(RestartPolicy::OneForOne)
            .with_backoff(BackoffStrategy::None),
    )
}

#[test]
fn direct_worker_restarts_real_generations_without_restarting_an_independent_tree() {
    run_case(|cx| async move {
        let mut owner = cx.open_dynamic_supervisor(DynamicSupervisorConfig::new(2)).await.unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicUsize::new(0));
        let sibling = owner.start_child("sibling", parked(Arc::clone(&started), Arc::clone(&stopped))).await.unwrap();
        wait_count(&started, 1).await;
        let generations = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&generations);
        let worker = owner.start_worker(
            "retrying-worker", worker_config(ManagedRestartMode::Transient),
            move |child: Cx, generation: ManagedGeneration| {
                log.lock().push(generation);
                assert_eq!(child.task_id(), generation.task);
                assert_eq!(child.region_id(), generation.region);
                async move {
                    if generation.number < 3 { Outcome::Err(String::from("retryable failure")) }
                    else { Outcome::Ok(()) }
                }
            },
        ).await.unwrap();
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
        let sibling_report = owner.terminate_child(&sibling).await.unwrap().supervisor.unwrap();
        assert_eq!(sibling_report.restart_batches, 0);
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert!(owner.shutdown().await.close.is_ok());
    });
}

#[test]
fn invalid_worker_configuration_is_refused_before_factory_or_region_admission() {
    run_case(|cx| async move {
        let mut owner = cx.open_dynamic_supervisor::<()>(DynamicSupervisorConfig::new(1)).await.unwrap();
        let mut config = worker_config(ManagedRestartMode::Transient);
        config.supervision.storm_threshold = Some(f64::NAN);
        let result = owner.start_worker("bad-policy", config, |_: Cx, _: ManagedGeneration| {
            panic!("invalid configuration must never invoke this factory");
            #[allow(unreachable_code)]
            std::future::ready(Outcome::Ok(()))
        }).await;
        assert!(matches!(result, Err(DynamicSupervisorError::WorkerConfiguration(
            crate::supervision::ManagedSupervisorBindError::InvalidStormThreshold
        ))));
        assert!(owner.is_empty());
        assert_eq!(owner.generation, 0, "no admission sequence was allocated");
        assert!(owner.shutdown().await.close.is_ok());
    });
}

#[test]
fn group_termination_validates_all_ids_before_stopping_any_member() {
    run_case(|cx| async move {
        let mut owner = cx.open_dynamic_supervisor(DynamicSupervisorConfig::new(2)).await.unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicUsize::new(0));
        let a = owner.start_child("a", parked(Arc::clone(&started), Arc::clone(&stopped))).await.unwrap();
        let b = owner.start_child("b", parked(Arc::clone(&started), Arc::clone(&stopped))).await.unwrap();
        wait_count(&started, 2).await;
        assert!(matches!(owner.terminate_children(&[a.clone(), a.clone()]).await,
            Err(DynamicSupervisorError::DuplicateChild)));
        let mut stale = b.clone();
        stale.generation += 1;
        assert!(matches!(owner.terminate_children(&[a.clone(), stale]).await,
            Err(DynamicSupervisorError::StaleChild)));
        assert!(owner.children().iter().all(|entry| entry.state == DynamicChildState::Submitted));
        assert_eq!(stopped.load(Ordering::SeqCst), 0);
        let results = owner.terminate_children(&[b.clone(), a.clone()]).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().id, b);
        assert_eq!(results[1].as_ref().unwrap().id, a);
        assert!(results.iter().all(|result| result.as_ref().unwrap().close.is_ok()));
        assert_eq!(stopped.load(Ordering::SeqCst), 2);
        assert!(owner.is_empty());
        assert!(!owner.is_closing(), "group termination does not shut down the owner");
        assert!(owner.terminate_children(&[]).await.unwrap().is_empty());
        let new = owner.start_child("new", done()).await.unwrap();
        owner.wait_child(&new).await.unwrap();
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
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        let cx = Cx::current().unwrap();
        let mut owner = cx.open_dynamic_supervisor(DynamicSupervisorConfig::new(1)).await.unwrap();
        owner.start_child("parked", parked(child_started, child_stopped)).await.unwrap();
        let completion = owner.next_completed().await.unwrap().expect("cancelled child was drained");
        assert!(completion.stop_requested);
        assert!(completion.close.is_ok());
        assert!(owner.is_closing());
        *publication.lock() = Some(owner.shutdown().await);
    }).unwrap();
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
    let report = published.lock().take().expect("cancelled owner still completed its drain");
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
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        let cx = Cx::current().unwrap();
        let mut owner = cx.open_dynamic_supervisor(DynamicSupervisorConfig::new(1)).await.unwrap();
        let id = owner.start_child("reusable", done()).await.unwrap();
        *publication.lock() = Some(id.clone());
        continue_rx.recv(&cx).await.unwrap();
        {
            let mut waiting = std::pin::pin!(owner.wait_child(&id));
            poll_fn(|cx| {
                assert!(waiting.as_mut().poll(cx).is_pending(), "finalizer is still gated");
                if owner_finalizer_started.load(Ordering::SeqCst) == 1 {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }).await;
        }
        assert_eq!(owner.len(), 1);
        assert_eq!(owner.children()[0].state, DynamicChildState::Draining);
        assert!(matches!(owner.child_result(&id).unwrap(), Some(Ok(_))));
        for _ in 0..3 {
            let mut waiting = std::pin::pin!(owner.wait_child(&id));
            poll_fn(|cx| {
                assert!(waiting.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            }).await;
        }
        assert!(matches!(owner.start_child("reusable", done()).await,
            Err(DynamicSupervisorError::DuplicateName)));
        owner_dropped_wait.store(true, Ordering::SeqCst);
        let completion = owner.wait_child(&id).await.unwrap();
        let replacement = owner.start_child("reusable", done()).await.unwrap();
        assert_ne!(replacement.region_id(), id.region_id());
        assert!(replacement.generation() > id.generation());
        assert!(matches!(owner.request_stop(&id), Err(DynamicSupervisorError::StaleChild)));
        owner.wait_child(&replacement).await.unwrap();
        let shutdown = owner.shutdown().await;
        *returned.lock() = Some((completion, shutdown));
    }).unwrap();
    let task_cx = lab.state.task(task).unwrap().cx.clone().unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    let id = identity.lock().clone().expect("real admitted boundary");
    let started = Arc::clone(&finalizer_started);
    let done = Arc::clone(&finalizer_done);
    assert!(lab.state.register_async_finalizer(id.region_id(), async move {
        started.fetch_add(1, Ordering::SeqCst);
        wait.recv_uninterruptible().await.unwrap();
        done.fetch_add(1, Ordering::SeqCst);
    }));
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
    assert_eq!(finalizer_started.load(Ordering::SeqCst), 1, "re-poll never restarts cleanup");
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
        let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            let mut owner = cx.open_dynamic_supervisor(DynamicSupervisorConfig::new(2)).await.unwrap();
            let a = owner.start_child("a", super::done()).await.unwrap();
            let b = owner.start_child("b", super::done()).await.unwrap();
            *publication.lock() = vec![a.clone(), b.clone()];
            continue_rx.recv(&cx).await.unwrap();
            if group {
                let reports = owner.terminate_children(&[a, b]).await.unwrap();
                assert!(reports.into_iter().all(|report| report.unwrap().close.is_ok()));
            }
            let report = owner.shutdown().await;
            assert!(report.close.is_ok());
            assert!(report.children.iter().all(|child| child.close.is_ok()));
            done.store(true, Ordering::SeqCst);
        }).unwrap();
        let task_cx = lab.state.task(task).unwrap().cx.clone().unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        let ids = identities.lock().clone();
        assert_eq!(ids.len(), 2);
        let a_done = Arc::new(AtomicBool::new(false));
        let a_flag = Arc::clone(&a_done);
        assert!(lab.state.register_async_finalizer(ids[0].region_id(), async move {
            await_b.recv_uninterruptible().await.unwrap();
            a_flag.store(true, Ordering::SeqCst);
        }));
        assert!(lab.state.register_async_finalizer(ids[1].region_id(), async move {
            unblock_a.send(&task_cx, ()).unwrap();
        }));
        continue_tx.try_send(()).unwrap();
        lab.run_until_idle();
        assert!(completed.load(Ordering::SeqCst), "sequential close parks forever on boundary a before starting b");
        assert!(a_done.load(Ordering::SeqCst));
        assert!(join.try_join().unwrap().is_some());
        clean(&mut lab, root);
    }
}
