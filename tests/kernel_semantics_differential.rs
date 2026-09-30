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

use asupersync::channel::{broadcast, mpsc, oneshot, watch};
use asupersync::combinator::map_reduce::MapReduceLimits;
use asupersync::combinator::timeout::TimedResult;
use asupersync::combinator::{JoinSet, PipelineExecutionConfig};
use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::cx::ChildRegionSpec;
use asupersync::runtime::{JoinError, RuntimeBuilder, yield_now};
use asupersync::sync::{Barrier, Mutex, Notify, OwnedMutexGuard, RwLock, Semaphore};
use asupersync::time::{sleep, timeout};
use asupersync::types::Outcome;
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
        let quiescent = runtime.shutdown_timeout(Duration::from_secs(10));
        let _ = done_tx.send((observation, quiescent));
    });
    match done_rx.recv_timeout(NATIVE_HANG_LIMIT) {
        Ok((observation, quiescent)) => {
            assert!(quiescent, "{name}: native runtime must reach quiescence and shut down");
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

fn spawn_blocking_returns_its_value(cx: Cx) -> ScenarioFuture {
    Box::pin(async move {
        let mut handle = cx.spawn_blocking(|_cx| 41u32 + 1).expect("spawn_blocking");
        let joined = handle.join(&cx).await;
        observe([("join", outcome(&joined))])
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
