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
        Box::pin(execute_public_journeys());
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

async fn execute_public_journeys() -> (usize, usize, usize) {
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
    (
        mapped.max_in_flight,
        mapped.max_retained,
        pipeline.summary.max_in_flight,
    )
}
