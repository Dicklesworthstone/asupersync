//! Lab/native differential harness for kernel semantics
//! (br-asupersync-bi2462.148).
//!
//! Several defects existed only because a behavior was proven on `LabRuntime`
//! and assumed on the production runtime. One was the panic-path loser drain
//! in `Scope::race` (bi2462.101, R29c): the lab took a "no scheduler" branch
//! and recorded a drain that never happened. Each scenario here is one
//! program, `fn(Cx) -> Observation`, run on
//! - `LabRuntime` under several seeds,
//! - the native current-thread runtime, repeated,
//! - the native multi-thread runtime with four workers, repeated.
//! Every run must produce the same observation, except fields a scenario
//! declares schedule-dependent. A divergence fails with every run's
//! observation printed side by side.
//!
//! Observations are facts a program can see through the public API: outcome
//! kinds, cancellation kinds, whether a cancelled loser finished its cleanup
//! before the combinator returned, and whether capacity, locks and permits
//! are usable again afterwards. Runtime-internal accounting is not compared.
//! The lab additionally must report no invariant violation.
//!
//! Not differential: region finalizers registered with `Scope::defer_*` need
//! `&mut RuntimeState`, which only the lab exposes, and `#[main]`'s root
//! drain (`Runtime::drain_root_region`) has no lab counterpart.
//! `region_close_waits_for_pending_cleanup` covers the semantics they share:
//! closing a region waits for a cancelled task's pending cleanup.

use std::collections::BTreeMap;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::mpsc;
use asupersync::combinator::PipelineExecutionConfig;
use asupersync::combinator::map_reduce::MapReduceLimits;
use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::cx::ChildRegionSpec;
use asupersync::runtime::{JoinError, RuntimeBuilder, yield_now};
use asupersync::sync::{Mutex, OwnedMutexGuard, Semaphore};
use asupersync::types::Outcome;

type Observation = BTreeMap<&'static str, String>;
type ScenarioFuture = Pin<Box<dyn Future<Output = Observation> + Send>>;

struct Scenario {
    name: &'static str,
    run: fn(Cx) -> ScenarioFuture,
    /// Fields whose value may legitimately depend on the schedule.
    schedule_dependent: &'static [&'static str],
}

const LAB_SEEDS: [u64; 6] = [1, 2, 3, 0x5EED, 0xBEEF, 0xC0FFEE];
const NATIVE_REPEATS: usize = 3;
const NATIVE_WORKERS: usize = 4;

// ---------------------------------------------------------------------------
// Runners
// ---------------------------------------------------------------------------

fn run_lab(seed: u64, scenario: &Scenario) -> Observation {
    let config = TestConfig {
        rng_seed: Some(seed),
        ..TestConfig::default()
    };
    let mut runtime = LabRuntimeTarget::create_runtime(config);
    let run = scenario.run;
    let observation = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");
        run(cx).await
    });
    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "{}: LabRuntime invariants violated (seed {seed}): {violations:?}",
        scenario.name
    );
    observation
}

fn run_native(builder: RuntimeBuilder, scenario: &Scenario) -> Observation {
    let runtime = builder.build().expect("build native runtime");
    let run = scenario.run;
    let handle = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task installs Cx");
        run(cx).await
    });
    let observation = runtime.block_on(handle);
    assert!(
        runtime.shutdown_timeout(Duration::from_secs(10)),
        "{}: native runtime must reach quiescence and shut down",
        scenario.name
    );
    observation
}

/// Run `scenario` everywhere and require one observation, modulo the
/// scenario's schedule-dependent fields.
fn check(scenario: &Scenario) {
    let mut runs: Vec<(String, Observation)> = Vec::new();
    for seed in LAB_SEEDS {
        runs.push((format!("lab seed {seed:#x}"), run_lab(seed, scenario)));
    }
    for repeat in 0..NATIVE_REPEATS {
        runs.push((
            format!("native current-thread #{repeat}"),
            run_native(RuntimeBuilder::current_thread(), scenario),
        ));
        runs.push((
            format!("native {NATIVE_WORKERS} workers #{repeat}"),
            run_native(
                RuntimeBuilder::multi_thread().worker_threads(NATIVE_WORKERS),
                scenario,
            ),
        ));
    }
    let compared = |observation: &Observation| -> Observation {
        observation
            .iter()
            .filter(|(key, _)| !scenario.schedule_dependent.contains(key))
            .map(|(key, value)| (*key, value.clone()))
            .collect()
    };
    let reference = compared(&runs[0].1);
    let diverged: Vec<&(String, Observation)> = runs
        .iter()
        .filter(|(_, observation)| compared(observation) != reference)
        .collect();
    if !diverged.is_empty() {
        let table: Vec<String> = runs
            .iter()
            .map(|(runtime, observation)| format!("  {runtime:<28} {observation:?}"))
            .collect();
        panic!(
            "{}: lab and native disagree ({} of {} runs differ from {}):\n{}",
            scenario.name,
            diverged.len(),
            runs.len(),
            runs[0].0,
            table.join("\n")
        );
    }
    eprintln!(
        "differential scenario={} runs={} observation={reference:?}",
        scenario.name,
        runs.len()
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn observe<const N: usize>(facts: [(&'static str, String); N]) -> Observation {
    facts.into_iter().collect()
}

fn outcome<T: std::fmt::Debug>(result: &Result<T, JoinError>) -> String {
    match result {
        Ok(value) => format!("ok:{value:?}"),
        Err(JoinError::Cancelled(reason)) => format!("cancelled:{:?}", reason.kind),
        Err(JoinError::Panicked(_)) => "panicked".to_string(),
        Err(JoinError::PolledAfterCompletion) => "polled-after-completion".to_string(),
    }
}

async fn wait_for(flag: &AtomicBool) {
    while !flag.load(Ordering::SeqCst) {
        yield_now().await;
    }
}

/// Parks on a receive that nothing satisfies. Once cancelled, it needs one
/// more poll (a cleanup yield) before it records that it finished. A runtime
/// that really drains a cancelled loser sees `done` set before the combinator
/// returns; a single best-effort poll does not (bi2462.101).
async fn parked_loser(cx: Cx, started: Arc<AtomicBool>, done: Arc<AtomicBool>) -> u32 {
    let (_hold, mut never) = mpsc::channel::<u32>(1);
    started.store(true, Ordering::SeqCst);
    let _ = never.recv(&cx).await;
    yield_now().await;
    done.store(true, Ordering::SeqCst);
    0
}

fn flags() -> (Arc<AtomicBool>, Arc<AtomicBool>) {
    (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)))
}

fn nonzero(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("nonzero")
}

fn outcome_kind<T, E>(outcome: &Outcome<T, E>) -> String {
    match outcome {
        Outcome::Ok(_) => "ok",
        Outcome::Err(_) => "err",
        Outcome::Cancelled(_) => "cancelled",
        Outcome::Panicked(_) => "panicked",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

fn spawn_join(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut handle = cx.spawn(|_cx| async { 7u32 }).expect("spawn");
        let joined = handle.join(&cx).await;
        observe([("join", outcome(&joined))])
    })
}

fn race_winner_drains_parked_loser(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, done) = flags();
        let gate = Arc::clone(&started);
        let winner = cx
            .spawn(move |_cx| async move {
                wait_for(&gate).await;
                1u32
            })
            .expect("spawn winner");
        let (s, d) = (Arc::clone(&started), Arc::clone(&done));
        let loser = cx
            .spawn(move |cx| parked_loser(cx, s, d))
            .expect("spawn loser");
        let result = cx.scope().race(&cx, winner, loser).await;
        observe([
            ("race", outcome(&result)),
            ("loser_drained_before_return", done.load(Ordering::SeqCst).to_string()),
        ])
    })
}

/// R29c (bi2462.101): a panicking winner must still drain the loser.
fn race_panicking_winner_still_drains_loser(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, done) = flags();
        let gate = Arc::clone(&started);
        let winner = cx
            .spawn(move |_cx| async move {
                wait_for(&gate).await;
                if gate.load(Ordering::SeqCst) {
                    panic!("differential: race winner panics");
                }
                1u32
            })
            .expect("spawn winner");
        let (s, d) = (Arc::clone(&started), Arc::clone(&done));
        let loser = cx
            .spawn(move |cx| parked_loser(cx, s, d))
            .expect("spawn loser");
        let result = cx.scope().race(&cx, winner, loser).await;
        observe([
            ("race", outcome(&result)),
            ("loser_drained_before_return", done.load(Ordering::SeqCst).to_string()),
        ])
    })
}

fn race_all_drains_every_loser(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let started = [
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ];
        let done = [
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ];
        let gates = started.clone();
        let winner = cx
            .spawn(move |_cx| async move {
                for gate in &gates {
                    wait_for(gate).await;
                }
                1u32
            })
            .expect("spawn winner");
        let mut handles = vec![winner];
        for index in 0..2 {
            let (s, d) = (Arc::clone(&started[index]), Arc::clone(&done[index]));
            handles.push(
                cx.spawn(move |cx| parked_loser(cx, s, d))
                    .expect("spawn loser"),
            );
        }
        let result = cx.scope().race_all(&cx, handles).await;
        observe([
            ("race_all", outcome(&result)),
            (
                "losers_drained_before_return",
                format!(
                    "{},{}",
                    done[0].load(Ordering::SeqCst),
                    done[1].load(Ordering::SeqCst)
                ),
            ),
        ])
    })
}

fn quorum_two_of_three_drains_the_straggler(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, done) = flags();
        let branches: Vec<_> = (0..3u32)
            .map(|index| {
                let (s, d) = (Arc::clone(&started), Arc::clone(&done));
                move |cx: Cx| async move {
                    if index < 2 {
                        wait_for(&s).await;
                        Ok::<u32, String>(index)
                    } else {
                        Ok(parked_loser(cx, s, d).await + 99)
                    }
                }
            })
            .collect();
        let result = cx.scope().quorum(&cx, 2, branches).await;
        observe([
            ("quorum", format!("{result:?}")),
            ("straggler_drained_before_return", done.load(Ordering::SeqCst).to_string()),
        ])
    })
}

/// The backup waits until the primary is parked, then wins; the parked
/// primary must be cancelled and finish its cleanup before `hedge` returns.
fn hedge_backup_wins_and_drains_the_primary(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, done) = flags();
        let (s, d, gate) = (Arc::clone(&started), Arc::clone(&done), Arc::clone(&started));
        let result = cx
            .hedge_drained_with(
                Duration::ZERO,
                move |cx| parked_loser(cx, s, d),
                move |_cx| async move {
                    wait_for(&gate).await;
                    2u32
                },
            )
            .await;
        observe([
            ("hedge", outcome(&result)),
            ("primary_drained_before_return", done.load(Ordering::SeqCst).to_string()),
        ])
    })
}

/// The R29c shape on `hedge`: a panicking backup still drains the primary.
fn hedge_panicking_backup_still_drains_the_primary(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, done) = flags();
        let (s, d, gate) = (Arc::clone(&started), Arc::clone(&done), Arc::clone(&started));
        let result = cx
            .hedge_drained_with(
                Duration::ZERO,
                move |cx| parked_loser(cx, s, d),
                move |_cx| async move {
                    wait_for(&gate).await;
                    if gate.load(Ordering::SeqCst) {
                        panic!("differential: hedge backup panics");
                    }
                    2u32
                },
            )
            .await;
        observe([
            ("hedge", outcome(&result)),
            ("primary_drained_before_return", done.load(Ordering::SeqCst).to_string()),
        ])
    })
}

fn first_ok_stops_at_the_first_success(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let invoked = Arc::new(AtomicUsize::new(0));
        let factories: Vec<_> = (0..3u32)
            .map(|index| {
                let invoked = Arc::clone(&invoked);
                move |_cx: Cx| async move {
                    invoked.fetch_add(1, Ordering::SeqCst);
                    match index {
                        0 => Err::<u32, String>("first attempt fails".to_string()),
                        1 => Ok(7),
                        _ => Ok(99),
                    }
                }
            })
            .collect();
        let result = cx.scope().first_ok(&cx, factories).await;
        observe([
            ("first_ok", format!("{result:?}")),
            ("attempts", invoked.load(Ordering::SeqCst).to_string()),
        ])
    })
}

fn map_reduce_stops_at_a_failing_item(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let limits = MapReduceLimits::new(
            NonZeroUsize::new(2).expect("nonzero"),
            NonZeroUsize::new(4).expect("nonzero"),
        );
        let execution = cx
            .scope()
            .map_reduce(
                &cx,
                limits,
                0..6u32,
                |_cx, item| async move {
                    if item == 3 {
                        Outcome::Err(format!("item {item} fails"))
                    } else {
                        Outcome::Ok(item)
                    }
                },
                |a, b| a + b,
            )
            .await;
        observe([
            ("outcome", format!("{:?}", execution.outcome)),
            ("failure_index", format!("{:?}", execution.failure_index)),
            ("admitted", execution.admitted.to_string()),
            ("completed", execution.completed.to_string()),
        ])
    })
}

/// Two transforms and a sink; the second transform rejects input 3. The
/// initiating typed error must name that stage and input everywhere. The
/// outer outcome kind is schedule-dependent by design: draining a sibling
/// that was cancelled mid-work strengthens `Err` into `Cancelled`, and
/// `PipelineExecutionReport::error` keeps the typed error (see its docs). The
/// first multi-worker runs observed both `err` and `cancelled`.
fn pipeline_error_in_the_second_stage(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let report = cx
            .scope()
            .pipeline::<_, String>(
                &cx,
                PipelineExecutionConfig::new(nonzero(2), nonzero(4)),
                0..6u32,
            )
            .then(nonzero(2), |_cx, item: u32| async move { Outcome::Ok(item * 2) })
            .then(nonzero(2), |_cx, item: u32| async move {
                if item == 6 {
                    Outcome::Err(format!("stage 1 rejects {item}"))
                } else {
                    Outcome::Ok(item)
                }
            })
            .run(|_cx, _item: u32| async { Outcome::Ok(()) })
            .await;
        let kind = outcome_kind(&report.outcome);
        observe([
            ("initiating_error", format!("{:?}", report.error())),
            ("outcome_is_err_or_cancelled", (kind == "err" || kind == "cancelled").to_string()),
            ("outcome_kind", kind),
            ("admitted", report.summary.admitted.to_string()),
            ("consumed", report.summary.consumed.to_string()),
        ])
    })
}

fn scope_join_reports_both_outcomes(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let ok = cx.spawn(|_cx| async { 1u32 }).expect("spawn ok");
        let panics = cx
            .spawn(|_cx| async {
                yield_now().await;
                if std::hint::black_box(true) {
                    panic!("differential: joined task panics");
                }
                2u32
            })
            .expect("spawn panicking");
        let (first, second) = cx.scope().join(&cx, ok, panics).await;
        observe([("first", outcome(&first)), ("second", outcome(&second))])
    })
}

fn region_close_releases_a_permit_held_inside_it(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let child = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("open child region");
        let (tx, _rx) = mpsc::channel::<u8>(1);
        let (started, _) = flags();
        let (child_tx, signal) = (tx.clone(), Arc::clone(&started));
        let (_gate_tx, mut gate_rx) = mpsc::channel::<u8>(1);
        let _handle = child
            .cx()
            .spawn(move |task_cx| async move {
                let _permit = child_tx.reserve(&task_cx).await.expect("reserve capacity");
                signal.store(true, Ordering::SeqCst);
                let _ = gate_rx.recv(&task_cx).await;
            })
            .expect("spawn inside the child region");
        wait_for(&started).await;
        let capacity_held = tx.try_reserve().is_err();
        let closed = child.close().await;
        let capacity_restored = tx.try_reserve().is_ok();
        observe([
            ("capacity_held_before_close", capacity_held.to_string()),
            ("close", format!("{closed:?}")),
            ("capacity_restored_after_close", capacity_restored.to_string()),
        ])
    })
}

/// Region close with cleanup still pending: after cancellation the task
/// inside the region needs further polls to finish its cleanup, and it keeps
/// its reserved permit until then. `close` must return only after that.
fn region_close_waits_for_pending_cleanup(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let child = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("open child region");
        let (tx, _rx) = mpsc::channel::<u8>(1);
        let (started, cleaned) = flags();
        let (child_tx, s, c) = (tx.clone(), Arc::clone(&started), Arc::clone(&cleaned));
        let (_gate_tx, mut gate_rx) = mpsc::channel::<u8>(1);
        let _handle = child
            .cx()
            .spawn(move |task_cx| async move {
                let permit = child_tx.reserve(&task_cx).await.expect("reserve capacity");
                s.store(true, Ordering::SeqCst);
                let _ = gate_rx.recv(&task_cx).await;
                for _ in 0..3 {
                    yield_now().await;
                }
                c.store(true, Ordering::SeqCst);
                drop(permit);
            })
            .expect("spawn inside the child region");
        wait_for(&started).await;
        let closed = child.close().await;
        observe([
            ("close", format!("{closed:?}")),
            ("cleanup_ran_before_close_returned", cleaned.load(Ordering::SeqCst).to_string()),
            ("capacity_restored_after_close", tx.try_reserve().is_ok().to_string()),
        ])
    })
}

/// A task aborted right after spawn is cancelled, whether or not it had begun.
fn abort_right_after_spawn_cancels(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let ran = Arc::new(AtomicBool::new(false));
        let body_ran = Arc::clone(&ran);
        let (_gate_tx, mut gate_rx) = mpsc::channel::<u8>(1);
        let mut handle = cx
            .spawn(move |task_cx| async move {
                body_ran.store(true, Ordering::SeqCst);
                let _ = gate_rx.recv(&task_cx).await;
                task_cx.checkpoint().map_err(|_| "cancelled")?;
                Ok::<u32, &'static str>(5)
            })
            .expect("spawn");
        handle.abort();
        let joined = handle.join(&cx).await;
        let class = match &joined {
            Err(JoinError::Cancelled(_)) => "cancelled".to_string(),
            Ok(Err(reason)) if *reason == "cancelled" => "cancelled".to_string(),
            other => outcome(other),
        };
        observe([
            ("join_class", class),
            ("body_ran", ran.load(Ordering::SeqCst).to_string()),
        ])
    })
}

fn abort_task_parked_on_mutex(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mutex = Arc::new(Mutex::new(0u32));
        // The parent holds the lock across awaits, so it needs the owned guard.
        let guard = OwnedMutexGuard::lock(Arc::clone(&mutex), &cx)
            .await
            .expect("parent locks");
        let (started, _) = flags();
        let (m, s) = (Arc::clone(&mutex), Arc::clone(&started));
        let mut handle = cx
            .spawn(move |task_cx| async move {
                s.store(true, Ordering::SeqCst);
                m.lock(&task_cx).await.map(|_| ()).map_err(|error| format!("{error:?}"))
            })
            .expect("spawn waiter");
        wait_for(&started).await;
        yield_now().await;
        handle.abort();
        let joined = handle.join(&cx).await;
        drop(guard);
        let relocked = mutex.lock(&cx).await.is_ok();
        observe([("join", outcome(&joined)), ("relock_after_abort", relocked.to_string())])
    })
}

fn abort_task_parked_on_mpsc_recv(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (tx, rx) = mpsc::channel::<u8>(1);
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let mut handle = cx
            .spawn(move |task_cx| async move {
                let mut rx = rx;
                s.store(true, Ordering::SeqCst);
                rx.recv(&task_cx).await.map_err(|error| format!("{error:?}"))
            })
            .expect("spawn receiver");
        wait_for(&started).await;
        yield_now().await;
        handle.abort();
        let joined = handle.join(&cx).await;
        observe([
            ("join", outcome(&joined)),
            ("sender_sees_closed_after_abort", tx.is_closed().to_string()),
        ])
    })
}

fn abort_task_parked_on_semaphore(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.acquire(&cx, 1).await.expect("parent acquires");
        let (started, _) = flags();
        let (sem, s) = (Arc::clone(&semaphore), Arc::clone(&started));
        let mut handle = cx
            .spawn(move |task_cx| async move {
                s.store(true, Ordering::SeqCst);
                sem.acquire(&task_cx, 1)
                    .await
                    .map(|_| ())
                    .map_err(|error| format!("{error:?}"))
            })
            .expect("spawn waiter");
        wait_for(&started).await;
        yield_now().await;
        handle.abort();
        let joined = handle.join(&cx).await;
        drop(held);
        observe([
            ("join", outcome(&joined)),
            ("permits_after_abort", semaphore.available_permits().to_string()),
        ])
    })
}

// ---------------------------------------------------------------------------
// Tests: one per scenario
// ---------------------------------------------------------------------------

macro_rules! differential {
    ($test:ident, $scenario:ident, [$($dependent:literal),*]) => {
        #[test]
        fn $test() {
            check(&Scenario {
                name: stringify!($scenario),
                run: $scenario,
                schedule_dependent: &[$($dependent),*],
            });
        }
    };
}

differential!(differential_spawn_join, spawn_join, []);
differential!(differential_race_parked_loser, race_winner_drains_parked_loser, []);
differential!(
    differential_race_panicking_winner,
    race_panicking_winner_still_drains_loser,
    []
);
differential!(differential_race_all, race_all_drains_every_loser, []);
differential!(differential_quorum, quorum_two_of_three_drains_the_straggler, []);
differential!(differential_hedge, hedge_backup_wins_and_drains_the_primary, []);
differential!(
    differential_hedge_panicking_backup,
    hedge_panicking_backup_still_drains_the_primary,
    []
);
differential!(
    differential_pipeline_error,
    pipeline_error_in_the_second_stage,
    ["admitted", "consumed", "outcome_kind"]
);
differential!(differential_first_ok, first_ok_stops_at_the_first_success, []);
differential!(
    differential_map_reduce_error,
    map_reduce_stops_at_a_failing_item,
    ["admitted", "completed"]
);
differential!(differential_scope_join, scope_join_reports_both_outcomes, []);
differential!(
    differential_region_close_permit,
    region_close_releases_a_permit_held_inside_it,
    []
);
differential!(
    differential_region_close_pending_cleanup,
    region_close_waits_for_pending_cleanup,
    []
);
differential!(
    differential_abort_after_spawn,
    abort_right_after_spawn_cancels,
    ["body_ran"]
);
differential!(differential_abort_mutex_waiter, abort_task_parked_on_mutex, []);
differential!(differential_abort_mpsc_receiver, abort_task_parked_on_mpsc_recv, []);
differential!(differential_abort_semaphore_waiter, abort_task_parked_on_semaphore, []);
