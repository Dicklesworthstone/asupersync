fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build()?;
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);

    assert_eq!(cx.budget(), asupersync::Budget::INFINITE);
    assert_eq!(
        asupersync_downstream_consumer_proof::public_surface_smoke_value(),
        2
    );

    drop(runtime);
    for sharded in [false, true] {
        let (finished, completion) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(|| exercise_executing_combinators(sharded));
            let _ = finished.send(result);
        });
        let result = completion
            .recv_timeout(std::time::Duration::from_secs(45))
            .expect("external consumer did not finish its actual runtime work within 45 seconds");
        worker
            .join()
            .expect("external consumer supervisor finished");
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    Ok(())
}

fn exercise_executing_combinators(sharded: bool) {
    use asupersync::runtime::RuntimeBuilder;
    use std::time::{Duration, Instant};

    let runtime = if sharded {
        RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .with_sharded_state(true)
    } else {
        RuntimeBuilder::current_thread()
    }
    .build()
    .expect("external consumer can build the public native runtime");
    assert_eq!(runtime.config().worker_threads, if sharded { 2 } else { 1 });
    assert_eq!(
        runtime.config().runtime_state_shape,
        if sharded {
            asupersync::runtime::config::RuntimeStateShape::Sharded
        } else {
            asupersync::runtime::config::RuntimeStateShape::Unified
        }
    );
    let future: std::pin::Pin<Box<dyn std::future::Future<Output = (usize, usize, usize)> + Send>> =
        Box::pin(execute_public_journeys(sharded));
    let (map_in_flight, retained_maps, pipeline_window) =
        runtime.block_on(runtime.handle().spawn(future));
    runtime.block_on(async {
        let started = Instant::now();
        while !runtime.is_quiescent() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "children failed to drain"
            );
            asupersync::runtime::yield_now().await;
        }
    });
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    let backend = if sharded {
        "native_two_worker_sharded"
    } else {
        "native_current_thread"
    };
    println!(
        "ASUPERSYNC_DOWNSTREAM_EXECUTING_COMBINATORS {{\"backend\":\"{backend}\",\"mapped\":16,\"reduced\":16,\"map_max_in_flight\":{map_in_flight},\"max_retained\":{retained_maps},\"admitted\":16,\"consumed\":16,\"max_in_flight\":{pipeline_window},\"stages\":2,\"expected_outputs\":16,\"observed_outputs\":16,\"exact_order_and_bytes\":true,\"live_tasks\":0,\"leaks\":0,\"shutdown_completed\":true}}"
    );
}

async fn execute_public_journeys(sharded: bool) -> (usize, usize, usize) {
    use asupersync::combinator::{MapReduceLimits, PipelineExecutionConfig};
    use asupersync::runtime::yield_now;
    use asupersync::{Cx, Outcome};
    use std::num::NonZeroUsize;
    use std::sync::{Arc, Mutex};

    let cx = Cx::current().expect("actual native task installs its public Cx");
    let scope = cx.scope();
    let expected_fold = (0..16)
        .map(|n| n.to_string())
        .reduce(|left, right| format!("({left}|{right})"))
        .unwrap();
    let mapped = scope
        .map_reduce(
            &cx,
            MapReduceLimits::new(NonZeroUsize::new(2).unwrap(), NonZeroUsize::new(3).unwrap()),
            0..16,
            |_child, n| async move {
                yield_now().await;
                Outcome::<_, ()>::Ok(n.to_string())
            },
            |left, right| format!("({left}|{right})"),
        )
        .await;
    match &mapped.outcome {
        Outcome::Ok(Some(value)) => assert_eq!(value, &expected_fold),
        other => panic!("public map-reduce did not deliver the ordered fold: {other:?}"),
    }
    assert_eq!(
        (mapped.admitted, mapped.completed, mapped.reduced),
        (16, 16, 16)
    );
    assert!((1..=2).contains(&mapped.max_in_flight));
    assert!((1..=3).contains(&mapped.max_retained));

    let observed = Arc::new(Mutex::new(Vec::new()));
    let sink_observed = Arc::clone(&observed);
    let pipeline = scope
        .pipeline::<_, ()>(
            &cx,
            PipelineExecutionConfig::new(
                NonZeroUsize::new(1).unwrap(),
                NonZeroUsize::new(3).unwrap(),
            ),
            0..16,
        )
        .then(NonZeroUsize::new(1).unwrap(), |_child, n| async move {
            yield_now().await;
            Outcome::Ok(format!("wire:{}", n * 7))
        })
        .then(NonZeroUsize::new(1).unwrap(), |_child, text| async move {
            yield_now().await;
            Outcome::Ok(format!("{text}:ready").into_bytes())
        })
        .run(move |_child, bytes| {
            let observed = Arc::clone(&sink_observed);
            async move {
                yield_now().await;
                observed.lock().unwrap().push(bytes);
                Outcome::Ok(())
            }
        })
        .await;
    assert!(matches!(&pipeline.outcome, Outcome::Ok(summary) if summary == &pipeline.summary));
    assert!(pipeline.error().is_none());
    assert_eq!(
        (
            pipeline.summary.admitted,
            pipeline.summary.consumed,
            pipeline.summary.stages
        ),
        (16, 16, 2)
    );
    assert!((1..=3).contains(&pipeline.summary.max_in_flight));
    let expected: Vec<Vec<u8>> = (0..16)
        .map(|n| format!("wire:{}:ready", n * 7).into_bytes())
        .collect();
    assert_eq!(*observed.lock().unwrap(), expected);
    execute_owned_transfer(sharded).await;
    (
        mapped.max_in_flight,
        mapped.max_retained,
        pipeline.summary.max_in_flight,
    )
}

async fn execute_owned_transfer(sharded: bool) {
    use asupersync::Cx;
    use asupersync::channel::oneshot;
    use asupersync::net::atp::protocol::AtpOutcome;
    use asupersync::net::atp::sdk::{
        ActiveTransfer, ActiveTransferState, TransferId, TransferOptions, TransferPhase,
        TransferProgress, TransferProgressReporter, TransferTerminal,
    };
    use std::future::{Future, poll_fn};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Waker};

    fn public_traits<T: Send + Sync + Unpin + std::fmt::Debug>() {}
    public_traits::<ActiveTransfer>();
    public_traits::<TransferProgressReporter>();
    public_traits::<TransferTerminal>();

    struct WorkerResource(Arc<AtomicUsize>);
    impl Drop for WorkerResource {
        fn drop(&mut self) {
            assert_eq!(self.0.fetch_add(1, Ordering::SeqCst), 0);
        }
    }
    fn progress(bytes: u64, phase: TransferPhase) -> TransferProgress {
        TransferProgress {
            transfer_id: TransferId::new("external-owned-worker"),
            bytes_transferred: bytes,
            total_bytes: 32,
            speed_bytes_per_sec: 0,
            eta_ms: None,
            phase,
            active_paths: 0,
            repair_symbols_active: false,
        }
    }

    let cx = Cx::current().expect("public native coordinator context");
    let scope = cx.scope();
    let input: Vec<u8> = (0u8..32).map(|byte| byte * 3).collect();
    let expected: Vec<u8> = input.iter().map(|byte| byte + 7).collect();
    let published = Arc::new(Mutex::new(None));
    let publication = Arc::clone(&published);
    let drops = Arc::new(AtomicUsize::new(0));
    let resource = WorkerResource(Arc::clone(&drops));
    let (ready, mut parked) = oneshot::channel();
    let (release, mut commit) = oneshot::channel::<()>();
    let mut transfer = ActiveTransfer::spawn_worker(
        &cx,
        &scope,
        TransferId::new("external-owned-worker"),
        TransferOptions::default(),
        move |child, reporter| async move {
            let _resource = resource;
            let mut output = Vec::with_capacity(input.len());
            for byte in input {
                output.push(byte.wrapping_add(7));
                reporter
                    .report(progress(output.len() as u64, TransferPhase::DataTransfer))
                    .expect("public progress reporter accepts actual processed bytes");
            }
            let mut waiting = std::pin::pin!(commit.recv(&child));
            let mut ready = Some(ready);
            poll_fn(|ctx| {
                let result = waiting.as_mut().poll(ctx);
                if result.is_pending() {
                    if let Some(ready) = ready.take() {
                        ready
                            .send_blocking((child.task_id(), child.region_id()))
                            .unwrap();
                    }
                }
                result
            })
            .await
            .expect("caller released the real publication gate");
            assert!(publication.lock().unwrap().replace(output).is_none());
            AtpOutcome::Ok(progress(32, TransferPhase::Completed))
        },
    )
    .expect("public Scope admits the owned worker");

    let (worker_task, worker_region) = parked.recv(&cx).await.unwrap();
    assert_ne!(worker_task, cx.task_id());
    assert_eq!(worker_region, scope.region_id());
    assert_eq!(transfer.state(), ActiveTransferState::Running);
    for _ in 0..3 {
        assert!(!transfer.is_complete().await);
    }
    assert!(published.lock().unwrap().is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let snapshot = transfer.next_progress_snapshot().await.unwrap();
    assert_eq!((snapshot.sequence, snapshot.skipped), (32, 31));
    assert_eq!(snapshot.progress, progress(32, TransferPhase::DataTransfer));
    {
        let mut empty = std::pin::pin!(transfer.next_progress());
        assert!(
            empty
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert!(published.lock().unwrap().is_none());
    release.send_blocking(()).unwrap();
    let terminal: TransferTerminal = transfer.wait_for_terminal().await.clone();
    assert_eq!(terminal.worker_join, Ok(()));
    assert_eq!(terminal.cleanup_panic, None);
    assert_eq!(
        terminal.outcome,
        AtpOutcome::Ok(progress(32, TransferPhase::Completed))
    );
    assert_eq!(terminal.worker_outcome, Some(terminal.outcome.clone()));
    assert_eq!(published.lock().unwrap().as_ref(), Some(&expected));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    for _ in 0..3 {
        assert!(transfer.is_complete().await);
        assert_eq!(transfer.terminal(), Some(&terminal));
    }
    assert_eq!(
        transfer.next_progress().await,
        Some(progress(32, TransferPhase::Completed))
    );
    assert_eq!(transfer.next_progress().await, None);
    assert_eq!(transfer.next_progress_snapshot().await, None);
    assert_eq!(transfer.terminal(), Some(&terminal));
    assert_eq!(transfer.state(), ActiveTransferState::Terminal);
    let backend = if sharded {
        "native_two_worker_sharded"
    } else {
        "native_current_thread"
    };
    println!(
        "ASUPERSYNC_DOWNSTREAM_ATP_WORKER {{\"backend\":\"{backend}\",\"scope\":\"owned-local-worker-only\",\"bytes\":32,\"observations\":32,\"sequence\":32,\"skipped\":31,\"worker_task\":\"{worker_task:?}\",\"worker_region\":\"{worker_region:?}\",\"published_exact_bytes\":true,\"drops\":1,\"canonical_joined\":true,\"terminal_retained\":true}}"
    );
}
