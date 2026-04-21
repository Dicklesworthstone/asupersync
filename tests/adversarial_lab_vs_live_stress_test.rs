#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

mod common;

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::sleep;
use asupersync::types::Budget;
use std::collections::BTreeSet;
use std::time::Duration;

const SEND_DELAY: Duration = Duration::from_millis(5);
const RECV_TIMEOUT: Duration = Duration::from_millis(2);
const LIVE_RUNS: usize = 8;
const LAB_SEEDS: u64 = 32;

// This scenario is intentionally timeout-dominated today: the receive-side
// timeout is shorter than the sender delay, so both live and lab executions
// should converge on the same semantic result.
async fn adversarial_scenario(cx: Cx) -> String {
    let (tx, rx) = mpsc::channel(2);

    let tx_clone = tx.clone();
    let cx1 = cx.clone();
    let fut1 = Box::pin(async move {
        sleep(cx1.now(), SEND_DELAY).await;
        if let Ok(permit) = tx_clone.reserve(&cx1).await {
            permit.send("T1_WIN");
        }
        "FUT1_DONE".to_string()
    }) as std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send>>;

    let cx2 = cx.clone();
    let fut2 = Box::pin(async move {
        let mut rx = rx;
        let cx2_recv = cx2.clone();
        let recv_fut = Box::pin(async move { rx.recv(&cx2_recv).await.unwrap_or("RX_CLOSED") })
            as std::pin::Pin<Box<dyn std::future::Future<Output = &'static str> + Send>>;

        let cx2_timeout = cx2.clone();
        let timeout_fut = Box::pin(async move {
            sleep(cx2_timeout.now(), RECV_TIMEOUT).await;
            "TIMEOUT"
        })
            as std::pin::Pin<Box<dyn std::future::Future<Output = &'static str> + Send>>;

        let res = cx2.race(vec![recv_fut, timeout_fut]).await;
        res.unwrap_or("CANCELLED").to_string()
    }) as std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send>>;

    let res = cx.race(vec![fut1, fut2]).await;
    res.unwrap_or_else(|_| "JOIN_ERROR".to_string())
}

fn run_live_outcome(runtime: &asupersync::runtime::Runtime) -> String {
    runtime.block_on(runtime.handle().spawn(async {
        let cx = Cx::current().expect("runtime task context");
        adversarial_scenario(cx).await
    }))
}

fn run_lab_outcome(seed: u64) -> String {
    let mut lab = LabRuntime::new(LabConfig::new(seed).with_auto_advance());
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut handle) = lab
        .state
        .create_task(root, Budget::INFINITE, async {
            let cx = Cx::current().expect("lab task context");
            adversarial_scenario(cx).await
        })
        .expect("create lab task");

    lab.scheduler.lock().schedule(task, 0);
    let _report = lab.run_with_auto_advance();
    let violations = lab.check_invariants();
    assert!(
        violations.is_empty(),
        "lab invariants violated during scenario run: {violations:?}"
    );

    match handle.try_join() {
        Ok(Some(outcome)) => outcome,
        Ok(None) => panic!("lab scenario remained pending after auto-advance"),
        Err(err) => panic!("lab scenario join failed: {err:?}"),
    }
}

#[test]
fn test_lab_simulates_all_live_outcomes() {
    common::init_test_logging();
    let mut live_outcomes = BTreeSet::new();

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    for _ in 0..LIVE_RUNS {
        live_outcomes.insert(run_live_outcome(&runtime));
    }
    assert!(
        !live_outcomes.is_empty(),
        "live runtime should produce at least one observable outcome"
    );

    let mut lab_outcomes = BTreeSet::new();
    for seed in 0..LAB_SEEDS {
        lab_outcomes.insert(run_lab_outcome(seed));
    }
    assert!(
        !lab_outcomes.is_empty(),
        "lab runtime should produce at least one observable outcome"
    );

    for live_outcome in &live_outcomes {
        assert!(
            lab_outcomes.contains(live_outcome),
            "Lab failed to simulate an outcome that occurred in live runtime: {live_outcome}",
        );
    }

    let expected = BTreeSet::from(["TIMEOUT".to_string()]);
    assert_eq!(
        live_outcomes, expected,
        "timeout-dominated live scenario should stay semantically stable"
    );
    assert_eq!(
        lab_outcomes, expected,
        "lab scenario should match the live timeout-dominated semantics"
    );
}
