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
//! The lab additionally must report no invariant violation, and every native
//! run must leave no live reservation and no confirmed obligation leak behind
//! (`Runtime::diagnostics`).
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

use asupersync::channel::{broadcast, mpsc, oneshot, watch};
use asupersync::combinator::map_reduce::MapReduceLimits;
use asupersync::combinator::timeout::TimedResult;
use asupersync::combinator::{JoinSet, PipelineExecutionConfig, bracket};
use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::cx::ChildRegionSpec;
use asupersync::runtime::{JoinError, RuntimeBuilder, SpawnError, yield_now};
use asupersync::sync::{Barrier, Mutex, Notify, OnceCell, OwnedMutexGuard, RwLock, Semaphore};
use asupersync::time::{sleep, timeout};
use asupersync::types::{Budget, Outcome};
use asupersync::{CancelReason, Cx};

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
const NATIVE_HANG_LIMIT: Duration = Duration::from_secs(60);

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

/// Runs the scenario on its own thread so that a hang fails the test with a
/// message instead of stalling the whole lane. `workers: None` is the
/// current-thread runtime.
fn run_native(workers: Option<usize>, scenario: &Scenario) -> Observation {
    let (name, run) = (scenario.name, scenario.run);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let builder = match workers {
            None => RuntimeBuilder::current_thread(),
            Some(count) => RuntimeBuilder::multi_thread().worker_threads(count),
        };
        let runtime = builder.build().expect("build native runtime");
        let handle = runtime.handle().spawn(async move {
            let cx = Cx::current().expect("runtime task installs Cx");
            run(cx).await
        });
        let observation = runtime.block_on(handle);
        // No obligation may outlive the scenario. Obligation posts settle
        // asynchronously, so drive the runtime briefly before judging.
        let settle = std::time::Instant::now();
        let mut live = runtime.diagnostics().find_leaked_obligations();
        while !live.is_empty() && settle.elapsed() < Duration::from_secs(2) {
            runtime.block_on(yield_now());
            live = runtime.diagnostics().find_leaked_obligations();
        }
        let confirmed = runtime.diagnostics().find_confirmed_obligation_leaks();
        let obligations =
            (live.is_empty() && confirmed.is_empty()).then_some(()).ok_or_else(|| {
                format!("live reservations {live:?}; confirmed leaks {confirmed:?}")
            });
        let quiescent = runtime.shutdown_timeout(Duration::from_secs(10));
        let _ = done_tx.send((observation, quiescent, obligations));
    });
    match done_rx.recv_timeout(NATIVE_HANG_LIMIT) {
        Ok((observation, quiescent, obligations)) => {
            assert!(quiescent, "{name}: native runtime must reach quiescence and shut down");
            if let Err(detail) = obligations {
                panic!("{name}: native run ({workers:?} workers) left obligations behind: {detail}");
            }
            observation
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("{name}: native run ({workers:?} workers) hung for {NATIVE_HANG_LIMIT:?}")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{name}: native run ({workers:?} workers) panicked; see its message above")
        }
    }
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
            run_native(None, scenario),
        ));
        runs.push((
            format!("native {NATIVE_WORKERS} workers #{repeat}"),
            run_native(Some(NATIVE_WORKERS), scenario),
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
    // Show which values each schedule-dependent field actually took, and on
    // which runtime, so a declared dependence that never varies, or one that
    // varies between lab and native rather than within native, is visible in
    // a passing log.
    let mut varied: BTreeMap<&str, BTreeMap<&str, BTreeMap<&str, usize>>> = BTreeMap::new();
    for key in scenario.schedule_dependent {
        for (runtime, observation) in &runs {
            if let Some(value) = observation.get(key) {
                let class = runtime.split(" #").next().and_then(|class| class.split(" seed").next());
                *varied
                    .entry(*key)
                    .or_default()
                    .entry(value.as_str())
                    .or_default()
                    .entry(class.unwrap_or(runtime.as_str()))
                    .or_default() += 1;
            }
        }
    }
    eprintln!(
        "differential scenario={} runs={} observation={reference:?} schedule_dependent={varied:?}",
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
                // Panics on purpose: the gate is always set here.
                assert!(!gate.load(Ordering::SeqCst), "differential: race winner panics");
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
                    // Panics on purpose: the gate is always set here.
                    assert!(!gate.load(Ordering::SeqCst), "differential: hedge backup panics");
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
                // Panics on purpose; black_box keeps the value opaque.
                assert!(!std::hint::black_box(true), "differential: joined task panics");
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

/// Three sender tasks each send five tagged messages; one receiver collects
/// all fifteen. Per-sender FIFO order must hold on every runtime.
fn mpsc_per_sender_order_under_contention(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (tx, mut rx) = mpsc::channel::<(u32, u32)>(2);
        let mut senders = Vec::new();
        for sender in 0..3u32 {
            let tx = tx.clone();
            senders.push(
                cx.spawn(move |task_cx| async move {
                    for sequence in 0..5u32 {
                        tx.send(&task_cx, (sender, sequence)).await.expect("receiver alive");
                        yield_now().await;
                    }
                })
                .expect("spawn sender"),
            );
        }
        drop(tx);
        let mut next = [0u32; 3];
        let mut in_order = true;
        let mut received = 0;
        while let Ok((sender, sequence)) = rx.recv(&cx).await {
            in_order &= next[sender as usize] == sequence;
            next[sender as usize] += 1;
            received += 1;
        }
        for handle in &mut senders {
            handle.join(&cx).await.expect("sender finishes");
        }
        observe([
            ("received", received.to_string()),
            ("per_sender_fifo", in_order.to_string()),
        ])
    })
}

/// Four tasks increment under a mutex, yielding inside the critical section.
/// No two holders may ever overlap, and no increment may be lost.
fn mutex_excludes_across_yields(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mutex = Arc::new(Mutex::new(0u32));
        let holders = Arc::new(AtomicUsize::new(0));
        let overlapped = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let (m, h, o) = (Arc::clone(&mutex), Arc::clone(&holders), Arc::clone(&overlapped));
            handles.push(
                cx.spawn(move |task_cx| async move {
                    for _ in 0..10 {
                        let mut guard = OwnedMutexGuard::lock(Arc::clone(&m), &task_cx)
                            .await
                            .expect("lock");
                        if h.fetch_add(1, Ordering::SeqCst) != 0 {
                            o.store(true, Ordering::SeqCst);
                        }
                        yield_now().await;
                        *guard += 1;
                        h.fetch_sub(1, Ordering::SeqCst);
                    }
                })
                .expect("spawn incrementer"),
            );
        }
        for handle in &mut handles {
            handle.join(&cx).await.expect("incrementer finishes");
        }
        let total = *mutex.lock(&cx).await.expect("final lock");
        observe([
            ("total", total.to_string()),
            ("holders_overlapped", overlapped.load(Ordering::SeqCst).to_string()),
        ])
    })
}

/// Writers and readers share an RwLock, yielding while they hold it. A reader
/// must never see a writer inside, and every write must land.
fn rwlock_excludes_writers_from_readers(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let lock = Arc::new(RwLock::new(0u32));
        let writing = Arc::new(AtomicBool::new(false));
        let violated = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        for index in 0..6u32 {
            let (l, w, v) = (Arc::clone(&lock), Arc::clone(&writing), Arc::clone(&violated));
            handles.push(
                cx.spawn(move |task_cx| async move {
                    for _ in 0..5 {
                        if index % 2 == 0 {
                            let mut guard = l.write(&task_cx).await.expect("write");
                            w.store(true, Ordering::SeqCst);
                            yield_now().await;
                            *guard += 1;
                            w.store(false, Ordering::SeqCst);
                        } else {
                            let _guard = l.read(&task_cx).await.expect("read");
                            if w.load(Ordering::SeqCst) {
                                v.store(true, Ordering::SeqCst);
                            }
                            yield_now().await;
                        }
                    }
                })
                .expect("spawn lock user"),
            );
        }
        for handle in &mut handles {
            handle.join(&cx).await.expect("lock user finishes");
        }
        let total = *lock.read(&cx).await.expect("final read");
        observe([
            ("writes", total.to_string()),
            ("reader_saw_writer", violated.load(Ordering::SeqCst).to_string()),
        ])
    })
}

/// A receiver parked on a oneshot sees `Closed` when the sender's task drops
/// the sender, and a dropped reserved permit also closes the channel.
fn oneshot_sender_and_permit_drop_close_the_receiver(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (tx, mut rx) = oneshot::channel::<u32>();
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let mut dropper = cx
            .spawn(move |_cx| async move {
                wait_for(&s).await;
                drop(tx);
            })
            .expect("spawn dropper");
        let (ready_tx, mut ready_rx) = oneshot::channel::<u32>();
        let mut receiver = cx
            .spawn(move |task_cx| async move {
                started.store(true, Ordering::SeqCst);
                format!("{:?}", rx.recv(&task_cx).await)
            })
            .expect("spawn receiver");
        let after_sender_drop = receiver.join(&cx).await.expect("receiver finishes");
        dropper.join(&cx).await.expect("dropper finishes");
        let permit = ready_tx.reserve(&cx).expect("reserve the only send");
        drop(permit);
        let after_permit_drop = format!("{:?}", ready_rx.recv(&cx).await);
        observe([
            ("after_sender_drop", after_sender_drop),
            ("after_permit_drop", after_permit_drop),
        ])
    })
}

/// Two subscribers each receive every message in order, then `Closed` once
/// the sender is gone and the buffer is drained.
fn broadcast_subscribers_drain_then_see_closed(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (tx, first) = broadcast::channel::<u32>(4);
        let second = tx.subscribe();
        let mut handles = Vec::new();
        for mut rx in [first, second] {
            handles.push(
                cx.spawn(move |task_cx| async move {
                    let mut seen = Vec::new();
                    loop {
                        match rx.recv(&task_cx).await {
                            Ok(value) => seen.push(value),
                            Err(error) => return format!("{seen:?} then {error:?}"),
                        }
                    }
                })
                .expect("spawn subscriber"),
            );
        }
        for value in 1..=3u32 {
            tx.send(&cx, value).expect("subscribers alive");
            yield_now().await;
        }
        drop(tx);
        let mut outcomes = Vec::new();
        for handle in &mut handles {
            outcomes.push(handle.join(&cx).await.expect("subscriber finishes"));
        }
        observe([("first", outcomes[0].clone()), ("second", outcomes[1].clone())])
    })
}

/// A receiver parked on `changed` wakes for a new value, and sees `Closed`
/// once the sender is dropped with nothing unseen.
fn watch_changed_wakes_then_closes(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (tx, mut rx) = watch::channel(0u32);
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let mut watcher = cx
            .spawn(move |task_cx| async move {
                s.store(true, Ordering::SeqCst);
                let first = rx.changed(&task_cx).await;
                let value = *rx.borrow_and_update();
                let second = rx.changed(&task_cx).await;
                format!("{first:?}/{value}/{second:?}")
            })
            .expect("spawn watcher");
        wait_for(&started).await;
        yield_now().await;
        tx.send(5).expect("receiver alive");
        yield_now().await;
        drop(tx);
        let seen = watcher.join(&cx).await.expect("watcher finishes");
        observe([("changed_value_then_close", seen)])
    })
}

/// Two waiters are registered; each `notify_one` releases exactly one. A
/// notification with no waiter is stored for the next `notified`.
fn notify_one_releases_exactly_one_waiter(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let notify = Arc::new(Notify::new());
        let woken = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let (n, w) = (Arc::clone(&notify), Arc::clone(&woken));
            handles.push(
                cx.spawn(move |_cx| async move {
                    n.notified().await;
                    w.fetch_add(1, Ordering::SeqCst);
                })
                .expect("spawn waiter"),
            );
        }
        while notify.waiter_count() < 2 {
            yield_now().await;
        }
        let first_woke_a_waiter = notify.notify_one();
        while woken.load(Ordering::SeqCst) < 1 {
            yield_now().await;
        }
        for _ in 0..4 {
            yield_now().await;
        }
        let after_first = woken.load(Ordering::SeqCst);
        notify.notify_one();
        for handle in &mut handles {
            handle.join(&cx).await.expect("waiter finishes");
        }
        let stored = !notify.notify_one();
        notify.notified().await;
        observe([
            ("first_notify_woke_a_waiter", first_woke_a_waiter.to_string()),
            ("woken_after_first_notify", after_first.to_string()),
            ("woken_after_second_notify", woken.load(Ordering::SeqCst).to_string()),
            ("notify_without_waiter_is_stored", stored.to_string()),
        ])
    })
}

/// Three parties meet at a barrier: all are released and exactly one leads.
fn barrier_releases_all_with_one_leader(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..3 {
            let b = Arc::clone(&barrier);
            handles.push(
                cx.spawn(move |task_cx| async move {
                    b.wait(&task_cx).await.map(|result| result.is_leader())
                })
                .expect("spawn party"),
            );
        }
        let mut leaders = 0;
        let mut released = 0;
        for handle in &mut handles {
            if let Ok(Ok(is_leader)) = handle.join(&cx).await {
                released += 1;
                leaders += usize::from(is_leader);
            }
        }
        observe([("released", released.to_string()), ("leaders", leaders.to_string())])
    })
}

/// `cancel_all` cancels three parked members and reports every outcome, in
/// spawn order, as cancelled with the user reason.
fn join_set_cancel_all_reports_every_member(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut set = JoinSet::in_cx(&cx);
        let started = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let s = Arc::clone(&started);
            set.spawn(&cx, move |task_cx| async move {
                let (_hold, mut never) = mpsc::channel::<u32>(1);
                s.fetch_add(1, Ordering::SeqCst);
                never.recv(&task_cx).await.map_err(|error| format!("{error:?}"))
            })
            .expect("spawn member");
        }
        while started.load(Ordering::SeqCst) < 3 {
            yield_now().await;
        }
        let outcomes: Vec<String> = set
            .cancel_all(&cx)
            .await
            .iter()
            .map(|outcome| match outcome {
                Outcome::Cancelled(reason) => format!("cancelled:{:?}", reason.kind),
                other => outcome_kind(other),
            })
            .collect();
        observe([("outcomes", outcomes.join(","))])
    })
}

/// A zero-length `Scope::timeout` around a parked operation. Whether the
/// operation was polled before the deadline depends on the schedule, and the
/// classification follows the acknowledged-value rule (`Scope::timeout`
/// docs). An operation polled before the cancel observes it and returns
/// `Completed(Ok(0))`. One cancelled before its first poll is `TimedOut`, even
/// though its body may still run once for cleanup (so "the body started"
/// does not witness "polled before the cancel"). Either way, cleanup has run
/// before `timeout` returns.
fn scope_timeout_drains_the_timed_out_operation(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, done) = flags();
        let (s, d) = (Arc::clone(&started), Arc::clone(&done));
        let result = cx
            .scope()
            .timeout(&cx, Duration::ZERO, move |task_cx| async move {
                Ok::<u32, String>(parked_loser(task_cx, s, d).await)
            })
            .await;
        let started = started.load(Ordering::SeqCst);
        let shape = match &result {
            Ok(TimedResult::Completed(Outcome::Ok(0))) => "completed:ok(0)".to_string(),
            Ok(TimedResult::Completed(other)) => format!("completed:{}", outcome_kind(other)),
            Ok(TimedResult::TimedOut(_)) => "timed_out".to_string(),
            Err(error) => format!("spawn_error:{error:?}"),
        };
        let expected = shape == "timed_out" || (shape == "completed:ok(0)" && started);
        observe([
            ("completed_ok_after_start_or_timed_out", expected.to_string()),
            ("started_implies_cleaned_up", (!started || done.load(Ordering::SeqCst)).to_string()),
            ("result", shape),
            ("operation_started", started.to_string()),
        ])
    })
}

/// The reason given to `abort_with_reason` is the one the task observes.
fn abort_reason_reaches_the_task(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let mut handle = cx
            .spawn(move |task_cx| async move {
                let (_hold, mut never) = mpsc::channel::<u32>(1);
                s.store(true, Ordering::SeqCst);
                let _ = never.recv(&task_cx).await;
                task_cx.cancel_reason().map(|reason| format!("{:?}", reason.kind))
            })
            .expect("spawn");
        wait_for(&started).await;
        yield_now().await;
        handle.abort_with_reason(CancelReason::shutdown());
        let joined = handle.join(&cx).await;
        observe([("join", outcome(&joined))])
    })
}

/// Cancelling a child region reaches a parked task inside it with the given
/// reason; the region then closes cleanly.
fn child_region_cancel_reason_reaches_its_task(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let child = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("open child region");
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let mut handle = child
            .cx()
            .spawn(move |task_cx| async move {
                let (_hold, mut never) = mpsc::channel::<u32>(1);
                s.store(true, Ordering::SeqCst);
                let _ = never.recv(&task_cx).await;
                task_cx.cancel_reason().map(|reason| format!("{:?}", reason.kind))
            })
            .expect("spawn inside the child region");
        wait_for(&started).await;
        let cancelled = child.cancel(CancelReason::shutdown());
        let joined = handle.join(&cx).await;
        let closed = child.close().await;
        observe([
            ("cancel", format!("{cancelled:?}")),
            ("join", outcome(&joined)),
            ("close", format!("{closed:?}")),
        ])
    })
}

/// Closing a region closes the region nested inside it, and a task parked
/// in the grandchild finishes its cleanup before the outer close returns.
fn nested_region_close_drains_the_grandchild(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let child = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("open child region");
        let grandchild = child
            .cx()
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("open grandchild region");
        let (started, done) = flags();
        let (s, d) = (Arc::clone(&started), Arc::clone(&done));
        let _handle = grandchild
            .cx()
            .spawn(move |task_cx| parked_loser(task_cx, s, d))
            .expect("spawn inside the grandchild region");
        wait_for(&started).await;
        let closed = child.close().await;
        let drained = done.load(Ordering::SeqCst);
        drop(grandchild);
        observe([
            ("close", format!("{closed:?}")),
            ("grandchild_task_drained_before_close_returned", drained.to_string()),
        ])
    })
}

/// Three tasks sleep for different lengths. On every clock (lab virtual
/// time, native timer driver) no sleep ends before its deadline. Completion
/// order is not compared: a stalled native worker can release several
/// expired sleeps at once.
fn sleeps_never_end_early(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut handles = Vec::new();
        for millis in [30u64, 10, 20] {
            handles.push(
                cx.spawn(move |task_cx| async move {
                    let start = task_cx.now();
                    sleep(start, Duration::from_millis(millis)).await;
                    task_cx.now().duration_since(start) >= millis * 1_000_000
                })
                .expect("spawn sleeper"),
            );
        }
        let mut on_time = true;
        for handle in &mut handles {
            on_time &= handle.join(&cx).await.expect("sleeper finishes");
        }
        observe([("no_sleep_ended_early", on_time.to_string())])
    })
}

/// `time::timeout` elapses for a parked future, and not before its
/// deadline; a future that is already ready beats a long timeout.
fn time_timeout_elapses_only_for_the_parked_future(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (_hold, mut never) = mpsc::channel::<u32>(1);
        let start = cx.now();
        let parked = timeout(start, Duration::from_millis(20), never.recv(&cx))
            .await
            .map(|received| received.is_ok())
            .map_err(|_elapsed| "elapsed");
        let waited = cx.now().duration_since(start);
        let fast = timeout(cx.now(), Duration::from_secs(30), async { 7u32 })
            .await
            .map_err(|_elapsed| "elapsed");
        observe([
            ("parked", format!("{parked:?}")),
            ("not_before_deadline", (waited >= 20_000_000).to_string()),
            ("fast", format!("{fast:?}")),
        ])
    })
}

/// `Scope::timeout` with a real 50 ms deadline around a parked operation.
/// Normally the operation is polled first, so it observes the timeout,
/// cleans up and returns: `Completed(Ok(0))`. A native worker stalled past the
/// deadline can cancel it before its first poll instead (`TimedOut`), so the
/// shape is schedule-dependent; the invariants are not.
fn scope_timeout_with_a_real_deadline(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, done) = flags();
        let (s, d) = (Arc::clone(&started), Arc::clone(&done));
        let result = cx
            .scope()
            .timeout(&cx, Duration::from_millis(50), move |task_cx| async move {
                Ok::<u32, String>(parked_loser(task_cx, s, d).await)
            })
            .await;
        let started = started.load(Ordering::SeqCst);
        let shape = match &result {
            Ok(TimedResult::Completed(Outcome::Ok(0))) => "completed:ok(0)".to_string(),
            Ok(TimedResult::Completed(other)) => format!("completed:{}", outcome_kind(other)),
            Ok(TimedResult::TimedOut(_)) => "timed_out".to_string(),
            Err(error) => format!("spawn_error:{error:?}"),
        };
        let expected = shape == "timed_out" || (shape == "completed:ok(0)" && started);
        observe([
            ("completed_ok_after_start_or_timed_out", expected.to_string()),
            ("started_implies_cleaned_up", (!started || done.load(Ordering::SeqCst)).to_string()),
            ("result", shape),
        ])
    })
}

/// A child region with a 50 ms deadline: the task parked inside it must be
/// cancelled once the deadline passes, with the deadline as its reason, on
/// either clock (lab virtual time, native timer driver).
fn region_deadline_cancels_a_parked_task(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut spec = ChildRegionSpec::inherit();
        spec.budget = Some(Budget::new().with_timeout(cx.now(), Duration::from_millis(50)));
        let child = cx
            .open_child_region(spec)
            .await
            .expect("open child region with a deadline");
        let mut handle = child
            .cx()
            .spawn(|task_cx| async move {
                let (_hold, mut never) = mpsc::channel::<u32>(1);
                let received = never.recv(&task_cx).await.map_err(|error| format!("{error:?}"));
                (
                    format!("{received:?}"),
                    task_cx.cancel_reason().map(|reason| format!("{:?}", reason.kind)),
                )
            })
            .expect("spawn inside the child region");
        let joined = handle.join(&cx).await;
        let closed = child.close().await;
        observe([("join", outcome(&joined)), ("close", format!("{closed:?}"))])
    })
}

/// A child region with a 50 ms deadline and a task that checkpoints every
/// 5 ms: both runtimes enforce the deadline at the first checkpoint after it
/// passes, with the deadline as the reason. (A task parked across the deadline
/// is never woken; see `region_deadline_cancels_a_parked_task`.)
fn region_deadline_stops_a_checkpointing_task(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut spec = ChildRegionSpec::inherit();
        spec.budget = Some(Budget::new().with_timeout(cx.now(), Duration::from_millis(50)));
        let child = cx
            .open_child_region(spec)
            .await
            .expect("open child region with a deadline");
        let mut handle = child
            .cx()
            .spawn(|task_cx| async move {
                for round in 0..400u32 {
                    if task_cx.checkpoint().is_err() {
                        let reason = task_cx.cancel_reason().map(|reason| format!("{:?}", reason.kind));
                        return (Some(round > 0), reason);
                    }
                    sleep(task_cx.now(), Duration::from_millis(5)).await;
                }
                (None, None)
            })
            .expect("spawn inside the child region");
        let joined = handle.join(&cx).await;
        let closed = child.close().await;
        observe([("join", outcome(&joined)), ("close", format!("{closed:?}"))])
    })
}

/// A child region with a poll quota of 8: a task that keeps yielding must be
/// stopped by the quota, at the same round and with the same reason on every
/// runtime (poll accounting is the thing compared).
fn region_poll_quota_stops_a_busy_task(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut spec = ChildRegionSpec::inherit();
        spec.budget = Some(Budget::new().with_poll_quota(8));
        let child = cx
            .open_child_region(spec)
            .await
            .expect("open child region with a poll quota");
        let mut handle = child
            .cx()
            .spawn(|task_cx| async move {
                for round in 0..1_000u32 {
                    if task_cx.checkpoint().is_err() {
                        let reason = task_cx.cancel_reason().map(|reason| format!("{:?}", reason.kind));
                        return (Some(round), reason);
                    }
                    yield_now().await;
                }
                (None, None)
            })
            .expect("spawn inside the child region");
        let joined = handle.join(&cx).await;
        let closed = child.close().await;
        observe([("join", outcome(&joined)), ("close", format!("{closed:?}"))])
    })
}

/// The same quota stops a task that never calls `checkpoint()` and only reads
/// its cancellation flag between yields. Nothing in the task notices the spent
/// quota, so the scheduler itself must request cancellation: polls 1 to 3
/// spend a quota of 3, and the request lands before poll 4
/// (br-asupersync-0fvvq9).
fn region_poll_quota_cancels_a_task_that_never_checkpoints(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut spec = ChildRegionSpec::inherit();
        spec.budget = Some(Budget::new().with_poll_quota(3));
        let child = cx
            .open_child_region(spec)
            .await
            .expect("open child region with a poll quota");
        let mut handle = child
            .cx()
            .spawn(|task_cx| async move {
                for round in 0..1_000u32 {
                    if task_cx.is_cancel_requested() {
                        let reason = task_cx
                            .cancel_reason()
                            .map(|reason| format!("{:?}", reason.kind));
                        return (Some(round), reason);
                    }
                    yield_now().await;
                }
                (None, None)
            })
            .expect("spawn inside the child region");
        let joined = handle.join(&cx).await;
        let closed = child.close().await;
        let joined = outcome(&joined);
        assert_ne!(
            joined, "ok:(None, None)",
            "the spent quota must request cancellation"
        );
        observe([("join", joined), ("close", format!("{closed:?}"))])
    })
}

/// A task cancelled through its handle acknowledges and enters cleanup, where
/// its live budget becomes the User cleanup budget of 1000 polls. It then
/// spawns a helper that yields 1100 times. The cleanup quota bounds only the
/// cancelled task's own drain, so the helper must finish every round instead
/// of being cancelled with `PollQuota` (br-asupersync-0fvvq9).
fn cleanup_spawned_helper_is_not_bound_by_the_cleanup_quota(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let (result_tx, mut result_rx) = oneshot::channel::<Result<u32, (u32, Option<String>)>>();
        let mut handle = cx
            .spawn(move |task_cx| async move {
                s.store(true, Ordering::SeqCst);
                while task_cx.checkpoint().is_ok() {
                    yield_now().await;
                }
                // Acknowledged. One more poll lets the runtime install the
                // cleanup budget before the helper is spawned.
                yield_now().await;
                // The lab also charges cleanup polls; production does not.
                let cleanup_quota = task_cx.budget().poll_quota;
                let in_cleanup = cleanup_quota > 900 && cleanup_quota <= 1_000;
                let spawned = task_cx.spawn(move |helper_cx| async move {
                    let mut result = Ok(1_100);
                    for round in 0..1_100u32 {
                        if helper_cx.checkpoint().is_err() {
                            let reason = helper_cx
                                .cancel_reason()
                                .map(|reason| format!("{:?}", reason.kind));
                            result = Err((round, reason));
                            break;
                        }
                        yield_now().await;
                    }
                    let _ = result_tx.send_blocking(result);
                });
                (in_cleanup, spawned.is_ok())
            })
            .expect("spawn");
        wait_for(&started).await;
        yield_now().await;
        handle.abort_with_reason(CancelReason::user("drain"));
        let helper = format!("{:?}", result_rx.recv(&cx).await);
        let joined = outcome(&handle.join(&cx).await);
        assert_eq!(
            joined, "ok:(true, true)",
            "the cancelled task reached its User cleanup budget before spawning"
        );
        assert_eq!(
            helper, "Ok(Ok(1100))",
            "the helper is not bound by the cleanup quota"
        );
        observe([("join", joined), ("helper", helper)])
    })
}

fn spawn_blocking_returns_its_value(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut handle = cx.spawn_blocking(|_cx| 41u32 + 1).expect("spawn_blocking");
        let joined = handle.join(&cx).await;
        observe([("join", outcome(&joined))])
    })
}

fn send_waiters(tx: &mpsc::Sender<u32>) -> usize {
    tx.telemetry_snapshot(0).send_waiter_count
}

/// Two senders park on a full channel and the first is aborted. Freeing the
/// slot must wake the survivor, whose message is delivered; the aborted
/// sender's message never appears. A cancelled waiter that keeps its place
/// in the queue swallows the wakeup instead.
fn aborted_parked_sender_hands_the_slot_to_the_next(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (tx, mut rx) = mpsc::channel::<u32>(1);
        tx.try_send(1).expect("fill the only slot");
        let spawn_sender = |value: u32| {
            let sender = tx.clone();
            cx.spawn(move |task_cx| async move {
                sender
                    .send(&task_cx, value)
                    .await
                    .map_err(|error| format!("{error:?}"))
            })
            .expect("spawn sender")
        };
        let mut first = spawn_sender(2);
        while send_waiters(&tx) < 1 {
            yield_now().await;
        }
        let mut second = spawn_sender(3);
        while send_waiters(&tx) < 2 {
            yield_now().await;
        }
        first.abort();
        let first_joined = first.join(&cx).await;
        let waiters_after_abort = send_waiters(&tx);
        let received = rx.recv(&cx).await.map_err(|error| format!("{error:?}"));
        let second_joined = second.join(&cx).await;
        let next = rx.try_recv().map_err(|error| format!("{error:?}"));
        let then = rx.try_recv().map_err(|error| format!("{error:?}"));
        observe([
            ("first_join", outcome(&first_joined)),
            ("send_waiters_after_abort", waiters_after_abort.to_string()),
            ("received", format!("{received:?}")),
            ("second_join", outcome(&second_joined)),
            ("next", format!("{next:?}")),
            ("then", format!("{then:?}")),
        ])
    })
}

/// Two tasks park on a held mutex and the first is aborted. Unlocking must
/// hand the lock to the second.
fn aborted_mutex_waiter_hands_the_lock_to_the_next(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mutex = Arc::new(Mutex::new(0u32));
        let guard = OwnedMutexGuard::lock(Arc::clone(&mutex), &cx)
            .await
            .expect("parent locks");
        let spawn_waiter = |value: u32| {
            let lock = Arc::clone(&mutex);
            cx.spawn(move |task_cx| async move {
                let mut held = lock.lock(&task_cx).await.map_err(|error| format!("{error:?}"))?;
                *held = value;
                Ok::<u32, String>(value)
            })
            .expect("spawn waiter")
        };
        let mut first = spawn_waiter(1);
        while mutex.waiters() < 1 {
            yield_now().await;
        }
        let mut second = spawn_waiter(2);
        while mutex.waiters() < 2 {
            yield_now().await;
        }
        first.abort();
        let first_joined = first.join(&cx).await;
        drop(guard);
        let second_joined = second.join(&cx).await;
        let value = *mutex.lock(&cx).await.expect("relock");
        observe([
            ("first_join", outcome(&first_joined)),
            ("second_join", outcome(&second_joined)),
            ("value", value.to_string()),
        ])
    })
}

/// Two tasks park on an exhausted semaphore and the first is aborted.
/// Releasing the permit must hand it to the second.
fn aborted_semaphore_waiter_hands_the_permit_to_the_next(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.acquire(&cx, 1).await.expect("parent acquires");
        let waiters = |semaphore: &Semaphore| semaphore.telemetry_snapshot(0).waiter_count;
        let spawn_waiter = || {
            let sem = Arc::clone(&semaphore);
            cx.spawn(move |task_cx| async move {
                sem.acquire(&task_cx, 1)
                    .await
                    .map(|_| ())
                    .map_err(|error| format!("{error:?}"))
            })
            .expect("spawn waiter")
        };
        let mut first = spawn_waiter();
        while waiters(&semaphore) < 1 {
            yield_now().await;
        }
        let mut second = spawn_waiter();
        while waiters(&semaphore) < 2 {
            yield_now().await;
        }
        first.abort();
        let first_joined = first.join(&cx).await;
        drop(held);
        let second_joined = second.join(&cx).await;
        observe([
            ("first_join", outcome(&first_joined)),
            ("second_join", outcome(&second_joined)),
            ("permits_after", semaphore.available_permits().to_string()),
        ])
    })
}

/// An aborted task that holds a reserved send permit gives it back: capacity
/// returns, nothing is sent and no reservation stays live.
fn abort_releases_a_held_send_permit(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (tx, mut rx) = mpsc::channel::<u32>(1);
        let (started, _) = flags();
        let (task_tx, s) = (tx.clone(), Arc::clone(&started));
        let mut handle = cx
            .spawn(move |task_cx| async move {
                let _permit = task_tx
                    .reserve(&task_cx)
                    .await
                    .map_err(|error| format!("{error:?}"))?;
                let (_hold, mut never) = mpsc::channel::<u32>(1);
                s.store(true, Ordering::SeqCst);
                never.recv(&task_cx).await.map_err(|error| format!("{error:?}"))
            })
            .expect("spawn");
        wait_for(&started).await;
        let reserved_while_parked = tx.telemetry_snapshot(0).reserved_uncommitted_obligations;
        handle.abort();
        let joined = handle.join(&cx).await;
        let reserved_after_join = tx.telemetry_snapshot(0).reserved_uncommitted_obligations;
        observe([
            ("join", outcome(&joined)),
            ("reserved_while_parked", reserved_while_parked.to_string()),
            ("reserved_after_join", reserved_after_join.to_string()),
            ("nothing_sent", rx.try_recv().is_err().to_string()),
            ("capacity_restored", tx.try_reserve().is_ok().to_string()),
        ])
    })
}

/// A message sent right at a receive's timeout is delivered exactly once:
/// either to the timed receive or, if that was abandoned, to the next one.
/// Which of the two gets it depends on the schedule.
fn message_racing_a_receive_timeout_is_delivered_once(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (tx, mut rx) = mpsc::channel::<u32>(1);
        let start = cx.now();
        let mut sender = cx
            .spawn(move |task_cx| async move {
                sleep(start, Duration::from_millis(10)).await;
                tx.send(&task_cx, 9).await.map_err(|error| format!("{error:?}"))
            })
            .expect("spawn sender");
        let timed = timeout(start, Duration::from_millis(10), rx.recv(&cx)).await;
        let sent = sender.join(&cx).await;
        let (taken_by, deliveries) = match timed {
            Ok(Ok(value)) => ("timed_receive", vec![value]),
            _ => ("next_receive", rx.recv(&cx).await.into_iter().collect()),
        };
        let leftover = rx.try_recv().is_ok();
        observe([
            ("sent", outcome(&sent)),
            ("deliveries", format!("{deliveries:?}")),
            ("leftover", leftover.to_string()),
            ("taken_by", taken_by.to_string()),
        ])
    })
}

/// `bracket` runs its release when the use phase is cancelled by an abort,
/// and the release has finished by the time the join returns.
fn bracket_release_runs_when_the_use_is_aborted(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, released) = flags();
        let (s, r) = (Arc::clone(&started), Arc::clone(&released));
        let mut handle = cx
            .spawn(move |task_cx| async move {
                bracket(
                    async { Ok::<u32, String>(7) },
                    move |resource| async move {
                        let (_hold, mut never) = mpsc::channel::<u32>(1);
                        s.store(true, Ordering::SeqCst);
                        never
                            .recv(&task_cx)
                            .await
                            .map(|_| resource)
                            .map_err(|error| format!("{error:?}"))
                    },
                    move |_resource| async move {
                        yield_now().await;
                        r.store(true, Ordering::SeqCst);
                    },
                )
                .await
            })
            .expect("spawn");
        wait_for(&started).await;
        yield_now().await;
        handle.abort();
        let joined = handle.join(&cx).await;
        observe([
            ("join", outcome(&joined)),
            ("released_before_join_returned", released.load(Ordering::SeqCst).to_string()),
        ])
    })
}

/// Inside `Cx::masked` a delivered abort is invisible to `checkpoint`;
/// the first checkpoint after the masked section observes it.
fn masked_section_defers_an_abort_until_it_ends(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let mut handle = cx
            .spawn(move |task_cx| async move {
                s.store(true, Ordering::SeqCst);
                while !task_cx.is_cancel_requested() {
                    yield_now().await;
                }
                let masked = task_cx.masked(|| task_cx.checkpoint().is_ok());
                let unmasked = task_cx.checkpoint().is_ok();
                format!("masked_checkpoint_ok={masked} unmasked_checkpoint_ok={unmasked}")
            })
            .expect("spawn");
        wait_for(&started).await;
        handle.abort();
        let joined = handle.join(&cx).await;
        observe([("join", outcome(&joined))])
    })
}

/// A region that has closed admits no new task, and the refusal is an
/// error from `spawn` or a join that reports it, never a hang.
fn spawn_into_a_closed_region_is_refused(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let child = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("open child region");
        let region_cx = child.cx().clone();
        let closed = child.close().await;
        let late = match region_cx.spawn(|_cx| async { 1u32 }) {
            Err(SpawnError::RegionClosed(_)) => "refused:region_closed".to_string(),
            Err(SpawnError::RegionNotFound(_)) => "refused:region_not_found".to_string(),
            Err(other) => format!("refused:{other:?}"),
            Ok(mut handle) => format!("admitted:{}", outcome(&handle.join(&cx).await)),
        };
        observe([("close", format!("{closed:?}")), ("spawn_after_close", late)])
    })
}

/// `JoinSet::join_next` yields every member exactly once, then `None`.
fn join_set_join_next_yields_every_member_once(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut set = JoinSet::in_cx(&cx);
        for value in 0..4u32 {
            set.spawn(&cx, move |_task_cx| async move {
                for _ in 0..value {
                    yield_now().await;
                }
                Ok::<u32, String>(value)
            })
            .expect("spawn member");
        }
        let mut members = Vec::new();
        while let Some(joined) = set.join_next(&cx).await {
            members.push(match joined {
                Outcome::Ok(value) => value.to_string(),
                other => outcome_kind(&other),
            });
        }
        members.sort();
        observe([
            ("members", members.join(",")),
            ("empty_afterwards", set.try_join_next().is_none().to_string()),
        ])
    })
}

/// A task that panics while holding a mutex poisons it: the join reports the
/// panic and every later locker sees `Poisoned`.
fn panic_while_holding_a_mutex_poisons_it(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mutex = Arc::new(Mutex::new(0u32));
        let lock = Arc::clone(&mutex);
        let mut handle = cx
            .spawn(move |task_cx| async move {
                let held = lock.lock(&task_cx).await.map_err(|error| format!("{error:?}"))?;
                // Panics on purpose: the value is still 0 here.
                assert!(*held != 0, "differential: panic while holding the lock");
                Ok::<u32, String>(*held)
            })
            .expect("spawn");
        let joined = handle.join(&cx).await;
        let relock = mutex
            .lock(&cx)
            .await
            .map(|_| ())
            .map_err(|error| format!("{error:?}"));
        observe([
            ("join", outcome(&joined)),
            ("poisoned", mutex.is_poisoned().to_string()),
            ("relock", format!("{relock:?}")),
        ])
    })
}

/// A watcher sees values in send order, never one twice or out of order,
/// ends on the last value, and then sees `Closed`. How many intermediate
/// values it observes depends on the schedule.
fn watch_values_arrive_in_order_and_end_on_the_last(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (tx, mut rx) = watch::channel(0u32);
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let mut watcher = cx
            .spawn(move |task_cx| async move {
                let mut seen = Vec::new();
                s.store(true, Ordering::SeqCst);
                let end = loop {
                    match rx.changed(&task_cx).await {
                        Ok(()) => seen.push(*rx.borrow_and_update()),
                        Err(error) => break format!("{error:?}"),
                    }
                };
                (seen, end)
            })
            .expect("spawn watcher");
        wait_for(&started).await;
        for value in 1..=5u32 {
            tx.send(value).expect("receiver alive");
            if value % 2 == 0 {
                yield_now().await;
            }
        }
        yield_now().await;
        drop(tx);
        let (seen, end) = watcher.join(&cx).await.expect("watcher finishes");
        let increasing = seen.windows(2).all(|pair| pair[0] < pair[1]);
        observe([
            ("strictly_increasing", increasing.to_string()),
            ("last", format!("{:?}", seen.last())),
            ("end", end),
            ("seen", format!("{seen:?}")),
        ])
    })
}

/// Sixty-four tasks sleep to the same deadline. Every one wakes, none early:
/// a timer lost to coalescing or wheel promotion hangs the scenario.
fn sixty_four_sleepers_with_one_deadline_all_wake(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let start = cx.now();
        let mut handles = Vec::new();
        for _ in 0..64 {
            handles.push(
                cx.spawn(move |task_cx| async move {
                    sleep(start, Duration::from_millis(10)).await;
                    task_cx.now().duration_since(start) >= 10_000_000
                })
                .expect("spawn sleeper"),
            );
        }
        let mut woke = 0usize;
        let mut on_time = true;
        for handle in &mut handles {
            on_time &= handle.join(&cx).await.expect("sleeper finishes");
            woke += 1;
        }
        observe([
            ("woke", woke.to_string()),
            ("none_early", on_time.to_string()),
        ])
    })
}

/// Closing a semaphore wakes every parked acquirer with `Closed`.
fn semaphore_close_wakes_every_waiter(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.acquire(&cx, 1).await.expect("parent acquires");
        let mut handles = Vec::new();
        for _ in 0..3 {
            let sem = Arc::clone(&semaphore);
            handles.push(
                cx.spawn(move |task_cx| async move {
                    sem.acquire(&task_cx, 1)
                        .await
                        .map(|_| ())
                        .map_err(|error| format!("{error:?}"))
                })
                .expect("spawn waiter"),
            );
        }
        while semaphore.telemetry_snapshot(0).waiter_count < 3 {
            yield_now().await;
        }
        semaphore.close();
        let mut results = Vec::new();
        for handle in &mut handles {
            results.push(outcome(&handle.join(&cx).await));
        }
        drop(held);
        observe([("waiters", results.join(","))])
    })
}

/// Aborting a task does not cancel a task it spawned: the child belongs to
/// the region, not to its spawner, and keeps running until it finishes.
fn aborting_a_spawner_leaves_its_child_running(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (child_started, _) = flags();
        let child_result = Arc::new(std::sync::Mutex::new(None::<String>));
        let (tx, rx) = mpsc::channel::<u32>(1);
        let (started, result) = (Arc::clone(&child_started), Arc::clone(&child_result));
        let mut spawner = cx
            .spawn(move |task_cx| async move {
                let _child = task_cx
                    .spawn(move |child_cx| async move {
                        let mut rx = rx;
                        started.store(true, Ordering::SeqCst);
                        let received = rx.recv(&child_cx).await;
                        *result.lock().expect("result lock") = Some(format!("{received:?}"));
                    })
                    .expect("spawn child");
                let (_hold, mut never) = mpsc::channel::<u32>(1);
                never.recv(&task_cx).await.map_err(|error| format!("{error:?}"))
            })
            .expect("spawn spawner");
        wait_for(&child_started).await;
        spawner.abort();
        let spawner_joined = spawner.join(&cx).await;
        let sent = tx.send(&cx, 9).await.map_err(|error| format!("{error:?}"));
        let child = loop {
            if let Some(received) = child_result.lock().expect("result lock").clone() {
                break received;
            }
            yield_now().await;
        };
        observe([
            ("spawner", outcome(&spawner_joined)),
            ("send_to_child", format!("{sent:?}")),
            ("child_received", child),
        ])
    })
}

/// A oneshot whose receiving task was aborted is closed: the send hands the
/// value back instead of losing it.
fn oneshot_send_after_the_receiver_was_aborted_returns_the_value(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (tx, rx) = oneshot::channel::<u32>();
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let mut receiver = cx
            .spawn(move |task_cx| async move {
                let mut rx = rx;
                s.store(true, Ordering::SeqCst);
                rx.recv(&task_cx).await.map_err(|error| format!("{error:?}"))
            })
            .expect("spawn receiver");
        wait_for(&started).await;
        yield_now().await;
        receiver.abort();
        let joined = receiver.join(&cx).await;
        let sent = tx.send(&cx, 5).map_err(|error| format!("{error:?}"));
        observe([("receiver", outcome(&joined)), ("send", format!("{sent:?}"))])
    })
}

/// A weaker cancel reason arriving after a stronger one does not weaken it:
/// a task aborted with `Shutdown` and then `User` observes `Shutdown`.
fn a_weaker_abort_does_not_weaken_the_reason(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let mut handle = cx
            .spawn(move |task_cx| async move {
                let (_hold, mut never) = mpsc::channel::<u32>(1);
                s.store(true, Ordering::SeqCst);
                let _ = never.recv(&task_cx).await;
                task_cx.cancel_reason().map(|reason| format!("{:?}", reason.kind))
            })
            .expect("spawn");
        wait_for(&started).await;
        yield_now().await;
        handle.abort_with_reason(CancelReason::shutdown());
        handle.abort_with_reason(CancelReason::user("differential: weaker second reason"));
        let joined = handle.join(&cx).await;
        observe([("join", outcome(&joined))])
    })
}

/// A region with a 50 ms deadline holds a child region that asks for 10 s.
/// Budgets combine by taking the tighter deadline, so a checkpointing task in
/// the inner region is cancelled with `Deadline` long before 10 s.
fn nested_region_deadline_is_the_tighter_one(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut outer_spec = ChildRegionSpec::inherit();
        outer_spec.budget = Some(Budget::new().with_timeout(cx.now(), Duration::from_millis(50)));
        let outer = cx
            .open_child_region(outer_spec)
            .await
            .expect("open outer region");
        let mut inner_spec = ChildRegionSpec::inherit();
        inner_spec.budget = Some(Budget::new().with_timeout(cx.now(), Duration::from_secs(10)));
        let inner = outer
            .cx()
            .open_child_region(inner_spec)
            .await
            .expect("open inner region");
        let start = cx.now();
        let mut handle = inner
            .cx()
            .spawn(move |task_cx| async move {
                for _ in 0..400u32 {
                    if task_cx.checkpoint().is_err() {
                        let early = task_cx.now().duration_since(start) < 5_000_000_000;
                        let reason = task_cx.cancel_reason().map(|reason| format!("{:?}", reason.kind));
                        return (reason, early);
                    }
                    sleep(task_cx.now(), Duration::from_millis(5)).await;
                }
                (None, false)
            })
            .expect("spawn inside the inner region");
        let joined = handle.join(&cx).await;
        let inner_closed = inner.close().await;
        let outer_closed = outer.close().await;
        observe([
            ("join", outcome(&joined)),
            ("inner_close", format!("{inner_closed:?}")),
            ("outer_close", format!("{outer_closed:?}")),
        ])
    })
}

/// Cancelling a region reaches a task parked two levels down, and the task
/// observes one well-defined reason on every runtime.
fn cancelling_a_region_reaches_its_grandchild_task(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let outer = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("open outer region");
        let inner = outer
            .cx()
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("open inner region");
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let mut handle = inner
            .cx()
            .spawn(move |task_cx| async move {
                let (_hold, mut never) = mpsc::channel::<u32>(1);
                s.store(true, Ordering::SeqCst);
                let _ = never.recv(&task_cx).await;
                task_cx.cancel_reason().map(|reason| format!("{:?}", reason.kind))
            })
            .expect("spawn inside the inner region");
        wait_for(&started).await;
        let cancelled = outer.cancel(CancelReason::shutdown());
        let joined = handle.join(&cx).await;
        let inner_closed = inner.close().await;
        let outer_closed = outer.close().await;
        observe([
            ("cancel", format!("{cancelled:?}")),
            ("join", outcome(&joined)),
            ("inner_close", format!("{inner_closed:?}")),
            ("outer_close", format!("{outer_closed:?}")),
        ])
    })
}

/// A task whose abort was requested can still spawn into its region (the
/// region is not cancelled), and it joins what it spawned.
fn a_task_spawns_after_its_own_abort_was_requested(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (started, _) = flags();
        let s = Arc::clone(&started);
        let mut handle = cx
            .spawn(move |task_cx| async move {
                s.store(true, Ordering::SeqCst);
                while !task_cx.is_cancel_requested() {
                    yield_now().await;
                }
                match task_cx.spawn(|_cx| async { 7u32 }) {
                    Ok(mut child) => format!("spawned:{}", outcome(&child.join(&task_cx).await)),
                    Err(SpawnError::RegionClosed(_)) => "refused:region_closed".to_string(),
                    Err(other) => format!("refused:{other:?}"),
                }
            })
            .expect("spawn");
        wait_for(&started).await;
        handle.abort();
        let joined = handle.join(&cx).await;
        observe([("join", outcome(&joined))])
    })
}

/// A 10 s `Scope::timeout` inside a region whose deadline is 50 ms: the
/// region deadline, the tighter bound, stops the checkpointing operation.
fn scope_timeout_inside_a_tighter_region_deadline(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut spec = ChildRegionSpec::inherit();
        spec.budget = Some(Budget::new().with_timeout(cx.now(), Duration::from_millis(50)));
        let child = cx
            .open_child_region(spec)
            .await
            .expect("open child region with a deadline");
        let mut handle = child
            .cx()
            .spawn(|task_cx| async move {
                let result = task_cx
                    .scope()
                    .timeout(&task_cx, Duration::from_secs(10), |op_cx| async move {
                        for _ in 0..400u32 {
                            if op_cx.checkpoint().is_err() {
                                return Err(op_cx
                                    .cancel_reason()
                                    .map_or_else(|| "cancelled".to_string(), |reason| {
                                        format!("{:?}", reason.kind)
                                    }));
                            }
                            sleep(op_cx.now(), Duration::from_millis(5)).await;
                        }
                        Ok::<u32, String>(0)
                    })
                    .await;
                match &result {
                    Ok(TimedResult::Completed(Outcome::Err(reason))) => {
                        format!("completed:err:{reason}")
                    }
                    Ok(TimedResult::Completed(other)) => format!("completed:{}", outcome_kind(other)),
                    Ok(TimedResult::TimedOut(_)) => "timed_out".to_string(),
                    Err(error) => format!("spawn_error:{error:?}"),
                }
            })
            .expect("spawn inside the child region");
        let joined = handle.join(&cx).await;
        let closed = child.close().await;
        observe([("join", outcome(&joined)), ("close", format!("{closed:?}"))])
    })
}

/// A writer parks behind a held read lock, so later readers queue behind it
/// (writer preference). Aborting the writer must admit the queued reader
/// while the first read lock is still held.
fn aborted_rwlock_writer_admits_the_queued_reader(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let lock = Arc::new(RwLock::new(5u32));
        let held = lock.read(&cx).await.expect("parent reads");
        let l = Arc::clone(&lock);
        let mut writer = cx
            .spawn(move |task_cx| async move {
                let mut guard = l.write(&task_cx).await.map_err(|error| format!("{error:?}"))?;
                *guard = 9;
                Ok::<(), String>(())
            })
            .expect("spawn writer");
        // A waiting writer makes try_read refuse.
        while lock.try_read().is_ok() {
            yield_now().await;
        }
        let queued = Arc::new(AtomicBool::new(false));
        let (l, q) = (Arc::clone(&lock), Arc::clone(&queued));
        let mut reader = cx
            .spawn(move |task_cx| async move {
                q.store(true, Ordering::SeqCst);
                let guard = l.read(&task_cx).await.map_err(|error| format!("{error:?}"))?;
                Ok::<u32, String>(*guard)
            })
            .expect("spawn reader");
        wait_for(&queued).await;
        for _ in 0..4 {
            yield_now().await;
        }
        writer.abort();
        let writer_joined = writer.join(&cx).await;
        let reader_joined = reader.join(&cx).await;
        drop(held);
        let value = *lock.read(&cx).await.expect("final read");
        observe([
            ("writer_join", outcome(&writer_joined)),
            ("reader_join_while_read_held", outcome(&reader_joined)),
            ("value", value.to_string()),
        ])
    })
}

/// `notify_one` picks a parked waiter, which is then aborted. Each waiter
/// checks for cancellation before the notification and drops its `Notified`
/// when cancelled. The other waiter must still finish: the dropped waiter
/// passes the notification on, or, if it consumed the notification before
/// the abort landed, a second notification wakes the other.
fn aborted_notified_waiter_passes_the_notification_on(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let notify = Arc::new(Notify::new());
        let spawn_waiter = || {
            let n = Arc::clone(&notify);
            cx.spawn(move |task_cx| async move {
                let (_hold, mut never) = mpsc::channel::<u32>(1);
                let mut cancelled = Box::pin(never.recv(&task_cx));
                let mut notified = Box::pin(n.notified());
                std::future::poll_fn(|poll_cx| {
                    if cancelled.as_mut().poll(poll_cx).is_ready() {
                        return std::task::Poll::Ready("cancelled");
                    }
                    if notified.as_mut().poll(poll_cx).is_ready() {
                        return std::task::Poll::Ready("notified");
                    }
                    std::task::Poll::Pending
                })
                .await
            })
            .expect("spawn waiter")
        };
        let mut first = spawn_waiter();
        while notify.waiter_count() < 1 {
            yield_now().await;
        }
        let mut second = spawn_waiter();
        while notify.waiter_count() < 2 {
            yield_now().await;
        }
        notify.notify_one();
        first.abort();
        let first_joined = first.join(&cx).await;
        if matches!(first_joined, Ok("notified")) {
            notify.notify_one();
        }
        let second_joined = second.join(&cx).await;
        observe([
            ("second_join", outcome(&second_joined)),
            ("waiters_after", notify.waiter_count().to_string()),
            ("first_join", outcome(&first_joined)),
        ])
    })
}

/// An initializer is abandoned mid-initialization (its timeout drops it)
/// while a second caller waits for it. The waiter must take over and
/// initialize the cell.
fn abandoned_once_cell_initializer_lets_the_waiter_initialize(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let cell = Arc::new(OnceCell::<u32>::new());
        let start = cx.now();
        let c = Arc::clone(&cell);
        let mut initializer = cx
            .spawn(move |_cx| async move {
                timeout(
                    start,
                    Duration::from_millis(20),
                    c.get_or_init(std::future::pending::<u32>),
                )
                .await
                .is_err()
            })
            .expect("spawn initializer");
        while cell.telemetry_snapshot(0).state != "initializing" {
            yield_now().await;
        }
        let c = Arc::clone(&cell);
        let mut waiter = cx
            .spawn(move |task_cx| async move {
                c.get_or_init_cx(&task_cx, || async { 7u32 })
                    .await
                    .copied()
                    .map_err(|error| format!("{error:?}"))
            })
            .expect("spawn waiter");
        let initializer_joined = initializer.join(&cx).await;
        let waiter_joined = waiter.join(&cx).await;
        observe([
            ("initializer_timed_out", outcome(&initializer_joined)),
            ("waiter_join", outcome(&waiter_joined)),
            ("value", format!("{:?}", cell.get())),
        ])
    })
}

/// Two parties wait at a three-party barrier and the first is aborted. Its
/// arrival is withdrawn: a third arrival does not trip the barrier, and it
/// trips with one leader only when a replacement (the parent) arrives.
fn aborted_barrier_waiter_is_withdrawn(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let barrier = Arc::new(Barrier::new(3));
        let released = Arc::new(AtomicUsize::new(0));
        let arrived = |b: &Barrier| b.telemetry_snapshot(0).occupied_units;
        let spawn_party = || {
            let (b, r) = (Arc::clone(&barrier), Arc::clone(&released));
            cx.spawn(move |task_cx| async move {
                let result = b.wait(&task_cx).await;
                r.fetch_add(1, Ordering::SeqCst);
                result
                    .map(|result| result.is_leader())
                    .map_err(|error| format!("{error:?}"))
            })
            .expect("spawn party")
        };
        let mut first = spawn_party();
        while arrived(&barrier) < 1 {
            yield_now().await;
        }
        let mut second = spawn_party();
        while arrived(&barrier) < 2 {
            yield_now().await;
        }
        first.abort();
        let first_joined = first.join(&cx).await;
        let arrived_after_abort = arrived(&barrier);
        if arrived_after_abort != 1 {
            // The aborted arrival still counts; report it rather than wait
            // on a barrier whose count can no longer be trusted.
            second.abort();
            let second_joined = second.join(&cx).await;
            return observe([
                ("first_join", outcome(&first_joined)),
                ("arrived_after_abort", arrived_after_abort.to_string()),
                ("second_join", outcome(&second_joined)),
            ]);
        }
        let mut third = spawn_party();
        while arrived(&barrier) < 2 && released.load(Ordering::SeqCst) < 2 {
            yield_now().await;
        }
        let tripped_without_replacement = released.load(Ordering::SeqCst) >= 2;
        let parent = if tripped_without_replacement {
            "not-needed".to_string()
        } else {
            format!(
                "{:?}",
                barrier
                    .wait(&cx)
                    .await
                    .map(|result| result.is_leader())
                    .map_err(|error| format!("{error:?}"))
            )
        };
        let second_joined = second.join(&cx).await;
        let third_joined = third.join(&cx).await;
        let leaders = [&second_joined, &third_joined]
            .into_iter()
            .filter(|joined| matches!(joined, Ok(Ok(true))))
            .count()
            + usize::from(parent == "Ok(true)");
        observe([
            ("first_join", outcome(&first_joined)),
            ("arrived_after_abort", arrived_after_abort.to_string()),
            ("tripped_without_replacement", tripped_without_replacement.to_string()),
            ("leaders", leaders.to_string()),
        ])
    })
}

/// A sender parks on a full channel and the receiver is dropped. The sender
/// must wake with the disconnect error instead of staying parked.
fn dropping_the_receiver_wakes_a_parked_sender(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let (tx, rx) = mpsc::channel::<u32>(1);
        tx.send(&cx, 1).await.expect("fill the only slot");
        let parked = tx.clone();
        let mut sender = cx
            .spawn(move |task_cx| async move {
                parked
                    .send(&task_cx, 2)
                    .await
                    .map_err(|error| format!("{error:?}"))
            })
            .expect("spawn sender");
        while send_waiters(&tx) < 1 {
            yield_now().await;
        }
        drop(rx);
        let joined = sender.join(&cx).await;
        observe([
            ("sender_join", outcome(&joined)),
            ("closed", tx.is_closed().to_string()),
        ])
    })
}

// ---------------------------------------------------------------------------
// Lab-only invariants the differential runs surfaced
// ---------------------------------------------------------------------------

/// A task spawned just before its parent sleeps is polled before virtual time
/// moves. `LabRuntimeTarget::block_on` used to jump to the parent's deadline
/// while the spawn still awaited admission, so the child first ran after the
/// parent's timer had fired; the production runtime does that only under a
/// stall. Found by `scope_timeout_with_a_real_deadline`: the lab reported
/// `TimedOut` in 4 of 6 seeds, the native runtime never.
#[test]
fn lab_time_does_not_advance_past_a_pending_spawn() {
    for seed in 0..32u64 {
        let config = TestConfig {
            rng_seed: Some(seed),
            ..TestConfig::default()
        };
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let (spawned_at, first_polled_at) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");
            let spawned_at = cx.now();
            let mut child = cx.spawn(|task_cx| async move { task_cx.now() }).expect("spawn");
            sleep(cx.now(), Duration::from_millis(50)).await;
            let first_polled_at = child.join(&cx).await.expect("child finishes");
            (spawned_at, first_polled_at)
        });
        assert_eq!(
            first_polled_at.as_nanos(),
            spawned_at.as_nanos(),
            "seed {seed}: virtual time moved before the spawned task's first poll"
        );
    }
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
    // A known lab/native gap, tracked by the bead named in the reason. The
    // scenario is the regression test for that bead: un-ignore it with the fix.
    ($test:ident, $scenario:ident, [$($dependent:literal),*], ignore = $reason:literal) => {
        #[test]
        #[ignore = $reason]
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
differential!(
    differential_mpsc_per_sender_order,
    mpsc_per_sender_order_under_contention,
    []
);
differential!(differential_mutex_exclusion, mutex_excludes_across_yields, []);
differential!(differential_rwlock_exclusion, rwlock_excludes_writers_from_readers, []);
differential!(
    differential_oneshot_close,
    oneshot_sender_and_permit_drop_close_the_receiver,
    []
);
differential!(
    differential_broadcast_close,
    broadcast_subscribers_drain_then_see_closed,
    []
);
differential!(differential_watch_changed, watch_changed_wakes_then_closes, []);
differential!(differential_notify_one, notify_one_releases_exactly_one_waiter, []);
differential!(differential_barrier, barrier_releases_all_with_one_leader, []);
differential!(
    differential_join_set_cancel_all,
    join_set_cancel_all_reports_every_member,
    []
);
differential!(
    differential_scope_timeout,
    scope_timeout_drains_the_timed_out_operation,
    ["result", "operation_started"]
);
differential!(differential_abort_reason, abort_reason_reaches_the_task, []);
differential!(
    differential_child_region_cancel_reason,
    child_region_cancel_reason_reaches_its_task,
    []
);
differential!(
    differential_nested_region_close,
    nested_region_close_drains_the_grandchild,
    []
);
differential!(differential_spawn_blocking, spawn_blocking_returns_its_value, []);
differential!(differential_sleeps_never_early, sleeps_never_end_early, []);
differential!(
    differential_region_deadline_checkpointing,
    region_deadline_stops_a_checkpointing_task,
    []
);
differential!(
    differential_region_deadline_parked,
    region_deadline_cancels_a_parked_task,
    [],
    ignore = "asupersync-pev2xi: neither runtime wakes a parked task at a region deadline (lab runs out of steps, native hangs)"
);
differential!(
    differential_region_poll_quota,
    region_poll_quota_stops_a_busy_task,
    []
);
differential!(
    differential_region_poll_quota_without_checkpoints,
    region_poll_quota_cancels_a_task_that_never_checkpoints,
    []
);
differential!(
    differential_cleanup_spawned_helper_quota,
    cleanup_spawned_helper_is_not_bound_by_the_cleanup_quota,
    []
);
differential!(
    differential_time_timeout,
    time_timeout_elapses_only_for_the_parked_future,
    []
);
differential!(
    differential_scope_timeout_real_deadline,
    scope_timeout_with_a_real_deadline,
    ["result"]
);
differential!(differential_abort_mpsc_receiver, abort_task_parked_on_mpsc_recv, []);
differential!(differential_abort_semaphore_waiter, abort_task_parked_on_semaphore, []);
differential!(
    differential_aborted_sender_handoff,
    aborted_parked_sender_hands_the_slot_to_the_next,
    []
);
differential!(
    differential_aborted_mutex_waiter_handoff,
    aborted_mutex_waiter_hands_the_lock_to_the_next,
    []
);
differential!(
    differential_aborted_semaphore_waiter_handoff,
    aborted_semaphore_waiter_hands_the_permit_to_the_next,
    []
);
differential!(differential_abort_held_permit, abort_releases_a_held_send_permit, []);
differential!(
    differential_receive_timeout_race,
    message_racing_a_receive_timeout_is_delivered_once,
    ["taken_by"]
);
differential!(
    differential_bracket_release_on_abort,
    bracket_release_runs_when_the_use_is_aborted,
    []
);
differential!(
    differential_masked_checkpoint,
    masked_section_defers_an_abort_until_it_ends,
    []
);
differential!(
    differential_spawn_into_closed_region,
    spawn_into_a_closed_region_is_refused,
    []
);
differential!(
    differential_join_set_join_next,
    join_set_join_next_yields_every_member_once,
    []
);
differential!(
    differential_panic_poisons_mutex,
    panic_while_holding_a_mutex_poisons_it,
    []
);
differential!(
    differential_watch_order,
    watch_values_arrive_in_order_and_end_on_the_last,
    ["seen"]
);
differential!(
    differential_sleep_storm,
    sixty_four_sleepers_with_one_deadline_all_wake,
    []
);
differential!(
    differential_semaphore_close,
    semaphore_close_wakes_every_waiter,
    []
);
differential!(
    differential_spawner_abort_child,
    aborting_a_spawner_leaves_its_child_running,
    []
);
differential!(
    differential_oneshot_after_receiver_abort,
    oneshot_send_after_the_receiver_was_aborted_returns_the_value,
    []
);
differential!(
    differential_abort_reason_strength,
    a_weaker_abort_does_not_weaken_the_reason,
    []
);
differential!(
    differential_nested_region_deadline,
    nested_region_deadline_is_the_tighter_one,
    []
);
differential!(
    differential_region_cancel_grandchild,
    cancelling_a_region_reaches_its_grandchild_task,
    []
);
differential!(
    differential_spawn_after_own_abort,
    a_task_spawns_after_its_own_abort_was_requested,
    []
);
differential!(
    differential_scope_timeout_in_region_deadline,
    scope_timeout_inside_a_tighter_region_deadline,
    []
);
differential!(
    differential_aborted_rwlock_writer,
    aborted_rwlock_writer_admits_the_queued_reader,
    []
);
differential!(
    differential_aborted_notified_waiter,
    aborted_notified_waiter_passes_the_notification_on,
    ["first_join"]
);
differential!(
    differential_abandoned_once_cell_initializer,
    abandoned_once_cell_initializer_lets_the_waiter_initialize,
    []
);
differential!(
    differential_aborted_barrier_waiter,
    aborted_barrier_waiter_is_withdrawn,
    []
);
differential!(
    differential_receiver_drop_wakes_parked_sender,
    dropping_the_receiver_wakes_a_parked_sender,
    []
);
