//! A race drains a losing branch's descendants, not only the branch task
//! (br-asupersync-issue65-criticisms-kpmoy5.2.2).
//!
//! Before this change every branch ran in the caller's region, so a task the
//! losing branch spawned through its own `Cx` was a sibling of the race in the
//! caller's region: the race cancelled and drained the branch task and
//! returned while that grandchild was still parked. Each branch now runs in a
//! sealed child region. A loser's region is cancelled and awaited before the
//! race returns; the winner's region is left running and closes by itself
//! once the winner's descendants finish.
//!
//! Every descendant here parks on a receive whose sender the test keeps
//! alive, so only a real cancellation can release it. Each records that it
//! parked (the formerly failing state is reached before the race resolves),
//! whether it observed cancellation, and when its future was dropped.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::Cx;
use asupersync::channel::mpsc;
use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::cx::RaceFactory;
use asupersync::runtime::{JoinError, RuntimeBuilder};
use asupersync::sync::Notify;
use asupersync::types::{CancelKind, RegionId};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct Witness {
    parked: AtomicBool,
    cancelled: AtomicBool,
    finished: AtomicBool,
    retired: AtomicBool,
    kind: Mutex<Option<CancelKind>>,
    region: Mutex<Option<RegionId>>,
    changed: Notify,
}

impl Witness {
    fn note(&self, flag: &AtomicBool) {
        flag.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    async fn wait(&self, flag: impl Fn(&Self) -> bool) {
        self.changed.wait_until(|| flag(self)).await;
    }
}

struct Retire(Arc<Witness>);

impl Drop for Retire {
    fn drop(&mut self) {
        self.0.note(&self.0.retired);
    }
}

fn boxed<T, F, Fut>(factory: F) -> RaceFactory<T>
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
{
    Box::new(move |child| Box::pin(factory(child)))
}

fn native<F, Fut>(workers: usize, body: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::new().worker_threads(workers).build().unwrap()
    };
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("real admitted native task");
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), body(cx.clone()))
            .await
            .expect("race descendant drain watchdog");
    }));
    assert!(
        runtime.shutdown_timeout(Duration::from_secs(3)),
        "the runtime quiesces: no branch region outlives its work"
    );
}

/// Parks on `receiver` until it is cancelled (the sender stays alive) or the
/// sender delivers, recording what happened.
async fn descendant(cx: Cx, mut receiver: mpsc::Receiver<()>, seen: Arc<Witness>) {
    let _retire = Retire(Arc::clone(&seen));
    *seen.region.lock().unwrap() = Some(cx.region_id());
    let received = {
        let mut receive = std::pin::pin!(receiver.recv(&cx));
        poll_fn(|task| {
            let progress = receive.as_mut().poll(task);
            if progress.is_pending() && !seen.parked.load(Ordering::Acquire) {
                seen.note(&seen.parked);
            }
            progress
        })
        .await
    };
    if received.is_err() && cx.is_cancel_requested() {
        *seen.kind.lock().unwrap() = cx.cancel_reason().map(|reason| reason.kind);
        seen.note(&seen.cancelled);
        return;
    }
    seen.note(&seen.finished);
}

/// A branch that never finishes on its own: it parks until cancelled.
async fn park_forever(cx: Cx, mut receiver: mpsc::Receiver<()>) -> u8 {
    let _ = receiver.recv(&cx).await;
    0
}

fn assert_drained(seen: &Witness, what: &str) {
    assert!(seen.parked.load(Ordering::Acquire), "{what} never parked");
    assert!(
        seen.cancelled.load(Ordering::Acquire),
        "{what} was still running when the race returned"
    );
    assert!(
        seen.retired.load(Ordering::Acquire),
        "{what} observed cancellation but was not terminal when the race returned"
    );
    let kind = *seen.kind.lock().unwrap();
    assert!(
        matches!(
            kind,
            Some(CancelKind::RaceLost | CancelKind::ParentCancelled)
        ),
        "{what} was cancelled as a race loser, not {kind:?}"
    );
}

fn loser_grandchild_is_drained_with_factories(workers: usize) {
    native(workers, |owner| async move {
        let grandchild = Arc::new(Witness::default());
        let (_grandchild_sender, grandchild_receiver) = mpsc::channel::<()>(1);
        let (_loser_sender, loser_receiver) = mpsc::channel::<()>(1);
        let spawned = Arc::clone(&grandchild);
        let awaited = Arc::clone(&grandchild);
        let result = owner
            .race_drained_with(vec![
                boxed(move |child: Cx| async move {
                    child
                        .spawn(move |gcx| descendant(gcx, grandchild_receiver, spawned))
                        .expect("the losing branch spawns a grandchild");
                    park_forever(child, loser_receiver).await
                }),
                boxed(move |_child| async move {
                    awaited.wait(|seen| seen.parked.load(Ordering::Acquire)).await;
                    7_u8
                }),
            ])
            .await;
        assert_eq!(result.expect("the second branch wins"), 7);
        assert_drained(&grandchild, "the losing branch's grandchild");
        assert_ne!(
            *grandchild.region.lock().unwrap(),
            Some(owner.region_id()),
            "the grandchild ran in the branch's own region, not the caller's"
        );
    });
}

#[test]
fn factory_race_drains_a_losing_branchs_grandchild_current_thread() {
    loser_grandchild_is_drained_with_factories(1);
}

#[test]
fn factory_race_drains_a_losing_branchs_grandchild_multi_thread() {
    loser_grandchild_is_drained_with_factories(4);
}

/// The prebuilt-future engine behind `race!`: the branch reaches its own
/// context through `Cx::current()`.
fn loser_grandchild_is_drained_with_prebuilt_futures(workers: usize) {
    native(workers, |owner| async move {
        let grandchild = Arc::new(Witness::default());
        let great = Arc::new(Witness::default());
        let (_grandchild_sender, grandchild_receiver) = mpsc::channel::<()>(1);
        let (_great_sender, great_receiver) = mpsc::channel::<()>(1);
        let (_loser_sender, loser_receiver) = mpsc::channel::<()>(1);
        let spawned = Arc::clone(&grandchild);
        let spawned_great = Arc::clone(&great);
        let awaited = Arc::clone(&great);
        let branches: Vec<Pin<Box<dyn Future<Output = u8> + Send>>> = vec![
            Box::pin(async move {
                let child = Cx::current().expect("the branch runs as an admitted task");
                // Two generations: the grandchild spawns a great-grandchild
                // before parking, so the drain must reach a nested descendant.
                child
                    .spawn(move |gcx| async move {
                        gcx.spawn(move |ggcx| descendant(ggcx, great_receiver, spawned_great))
                            .expect("the grandchild spawns a great-grandchild");
                        descendant(gcx, grandchild_receiver, spawned).await;
                    })
                    .expect("the losing branch spawns a grandchild");
                park_forever(child, loser_receiver).await
            }),
            Box::pin(async move {
                awaited.wait(|seen| seen.parked.load(Ordering::Acquire)).await;
                9_u8
            }),
        ];
        let result = owner.race_drained(branches).await;
        assert_eq!(result.expect("the second branch wins"), 9);
        assert_drained(&grandchild, "the losing branch's grandchild");
        assert_drained(&great, "the losing branch's great-grandchild");
    });
}

#[test]
fn prebuilt_race_drains_a_losing_branchs_descendants_current_thread() {
    loser_grandchild_is_drained_with_prebuilt_futures(1);
}

#[test]
fn prebuilt_race_drains_a_losing_branchs_descendants_multi_thread() {
    loser_grandchild_is_drained_with_prebuilt_futures(4);
}

/// Only losers are drained: work the winner started keeps running after the
/// race returns, can still spawn, and its region closes once it finishes.
fn winner_grandchild_outlives_the_race(workers: usize) {
    native(workers, |owner| async move {
        let grandchild = Arc::new(Witness::default());
        let late = Arc::new(Witness::default());
        let (grandchild_sender, grandchild_receiver) = mpsc::channel::<()>(1);
        let (_loser_sender, loser_receiver) = mpsc::channel::<()>(1);
        let spawned = Arc::clone(&grandchild);
        let spawned_late = Arc::clone(&late);
        let awaited = Arc::clone(&grandchild);
        let result = owner
            .race_drained_with(vec![
                boxed(move |child: Cx| async move {
                    child
                        .spawn(move |gcx| async move {
                            descendant(gcx.clone(), grandchild_receiver, spawned).await;
                            // Spawning after the race returned: the winner's
                            // region is still open for its own tasks.
                            gcx.spawn(move |_late_cx| async move {
                                let _retire = Retire(Arc::clone(&spawned_late));
                                spawned_late.note(&spawned_late.finished);
                            })
                            .expect("a winner descendant can spawn after the race");
                        })
                        .expect("the winning branch spawns a grandchild");
                    awaited.wait(|seen| seen.parked.load(Ordering::Acquire)).await;
                    5_u8
                }),
                boxed(move |child| park_forever(child, loser_receiver)),
            ])
            .await;
        assert_eq!(result.expect("the first branch wins"), 5);
        assert!(grandchild.parked.load(Ordering::Acquire));
        assert!(
            !grandchild.cancelled.load(Ordering::Acquire) && !grandchild.retired.load(Ordering::Acquire),
            "the winner's grandchild must keep running after the race returns"
        );
        grandchild_sender
            .send(&owner, ())
            .await
            .expect("the winner's grandchild is still receiving");
        late.wait(|seen| seen.retired.load(Ordering::Acquire)).await;
        assert!(late.finished.load(Ordering::Acquire));
        grandchild.wait(|seen| seen.retired.load(Ordering::Acquire)).await;
        assert!(grandchild.finished.load(Ordering::Acquire));
        assert!(!grandchild.cancelled.load(Ordering::Acquire));
    });
}

#[test]
fn winner_grandchild_outlives_the_race_current_thread() {
    winner_grandchild_outlives_the_race(1);
}

#[test]
fn winner_grandchild_outlives_the_race_multi_thread() {
    winner_grandchild_outlives_the_race(4);
}

/// An owner cancelled mid-race fails the race: every branch lost, so every
/// branch's descendants are drained before the owner's race returns.
#[test]
fn owner_cancellation_drains_every_branchs_descendants() {
    native(4, |owner| async move {
        let first = Arc::new(Witness::default());
        let second = Arc::new(Witness::default());
        let (_first_sender, first_receiver) = mpsc::channel::<()>(1);
        let (_second_sender, second_receiver) = mpsc::channel::<()>(1);
        let (_a_sender, a_receiver) = mpsc::channel::<()>(1);
        let (_b_sender, b_receiver) = mpsc::channel::<()>(1);
        let (first_spawned, second_spawned) = (Arc::clone(&first), Arc::clone(&second));
        let mut racer = owner
            .spawn(move |racer: Cx| async move {
                racer
                    .race_drained_with(vec![
                        boxed(move |child: Cx| async move {
                            child
                                .spawn(move |gcx| descendant(gcx, first_receiver, first_spawned))
                                .expect("first branch spawns");
                            park_forever(child, a_receiver).await
                        }),
                        boxed(move |child: Cx| async move {
                            child
                                .spawn(move |gcx| descendant(gcx, second_receiver, second_spawned))
                                .expect("second branch spawns");
                            park_forever(child, b_receiver).await
                        }),
                    ])
                    .await
            })
            .expect("spawn the racing task");
        first.wait(|seen| seen.parked.load(Ordering::Acquire)).await;
        second.wait(|seen| seen.parked.load(Ordering::Acquire)).await;
        racer.abort();
        let outcome = racer.join(&owner).await;
        assert!(
            matches!(outcome, Err(JoinError::Cancelled(_)) | Ok(Err(JoinError::Cancelled(_)))),
            "the cancelled race reports cancellation, got {outcome:?}"
        );
        for (seen, what) in [(&first, "first branch's grandchild"), (&second, "second branch's grandchild")] {
            assert!(seen.cancelled.load(Ordering::Acquire), "{what} still running after the race failed");
            assert!(seen.retired.load(Ordering::Acquire), "{what} not terminal after the race failed");
        }
    });
}

/// Branch regions under the lab's full oracle suite and refinement firewall,
/// across seeds: the loser's grandchild is drained, the winner's grandchild
/// outlives the race and finishes, and the run ends quiescent with every
/// oracle passing and no invariant violation.
#[test]
fn lab_oracles_accept_branch_regions_across_seeds() {
    for seed in 0..12_u64 {
        let ((value, loser_drained, winner_finished), report) =
            asupersync::lab::run_async_under_lab(0x5EA1_0000 + seed, |owner| async move {
                let lost = Arc::new(Witness::default());
                let kept = Arc::new(Witness::default());
                let (_lost_sender, lost_receiver) = mpsc::channel::<()>(1);
                let (kept_sender, kept_receiver) = mpsc::channel::<()>(1);
                let (_loser_sender, loser_receiver) = mpsc::channel::<()>(1);
                let (lost_spawned, kept_spawned) = (Arc::clone(&lost), Arc::clone(&kept));
                let (lost_awaited, kept_awaited) = (Arc::clone(&lost), Arc::clone(&kept));
                let value = owner
                    .race_drained_with(vec![
                        boxed(move |child: Cx| async move {
                            child
                                .spawn(move |gcx| descendant(gcx, lost_receiver, lost_spawned))
                                .expect("the losing branch spawns");
                            park_forever(child, loser_receiver).await
                        }),
                        boxed(move |child: Cx| async move {
                            child
                                .spawn(move |gcx| descendant(gcx, kept_receiver, kept_spawned))
                                .expect("the winning branch spawns");
                            lost_awaited.wait(|seen| seen.parked.load(Ordering::Acquire)).await;
                            kept_awaited.wait(|seen| seen.parked.load(Ordering::Acquire)).await;
                            11_u8
                        }),
                    ])
                    .await
                    .expect("the second branch wins");
                let loser_drained = lost.cancelled.load(Ordering::Acquire)
                    && lost.retired.load(Ordering::Acquire)
                    && !kept.cancelled.load(Ordering::Acquire)
                    && !kept.retired.load(Ordering::Acquire);
                kept_sender.send(&owner, ()).await.expect("the winner's grandchild still receives");
                kept.wait(|seen| seen.retired.load(Ordering::Acquire)).await;
                (value, loser_drained, kept.finished.load(Ordering::Acquire))
            });
        assert_eq!(value, 11, "seed {seed}");
        assert!(loser_drained, "seed {seed}: loser drained, winner untouched at return");
        assert!(winner_finished, "seed {seed}: the winner's grandchild finished normally");
        assert!(report.quiescent, "seed {seed}: the lab run ends quiescent");
        assert!(
            report.oracle_report.all_passed(),
            "seed {seed}: every lab oracle passes"
        );
        assert!(
            report.invariant_violations.is_empty(),
            "seed {seed}: invariant violations {:?}",
            report.invariant_violations
        );
    }
}

/// The same loser-descendant drain under the deterministic lab runtime.
#[test]
fn lab_race_drains_a_losing_branchs_grandchild() {
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
    let grandchild = Arc::new(Witness::default());
    let checked = Arc::clone(&grandchild);
    let value = LabRuntimeTarget::block_on(&mut runtime, async move {
        let owner = Cx::current().expect("lab root task installs Cx");
        let (_grandchild_sender, grandchild_receiver) = mpsc::channel::<()>(1);
        let (_loser_sender, loser_receiver) = mpsc::channel::<()>(1);
        let spawned = Arc::clone(&grandchild);
        let awaited = Arc::clone(&grandchild);
        let value = owner
            .race_drained_with(vec![
                boxed(move |child: Cx| async move {
                    child
                        .spawn(move |gcx| descendant(gcx, grandchild_receiver, spawned))
                        .expect("the losing branch spawns a grandchild");
                    park_forever(child, loser_receiver).await
                }),
                boxed(move |_child| async move {
                    awaited.wait(|seen| seen.parked.load(Ordering::Acquire)).await;
                    3_u8
                }),
            ])
            .await
            .expect("the second branch wins");
        assert_drained(&grandchild, "the lab loser's grandchild");
        value
    });
    assert_eq!(value, 3);
    assert!(checked.retired.load(Ordering::Acquire));
}

/// A losing branch that waits for a task it spawned through
/// `Scope::join_all_owned`, which passes the branch's cancellation to that
/// task, is drained (br-asupersync-inleqi). A plain `TaskHandle::join` does
/// not observe the branch's cancellation, and the branch's region is cancelled
/// only after the branch finishes, so such a race would wait for the task.
fn loser_joining_its_own_child_owned_is_drained(workers: usize) {
    native(workers, |owner| async move {
        let grandchild = Arc::new(Witness::default());
        let (_sender, receiver) = mpsc::channel::<()>(1);
        let spawned = Arc::clone(&grandchild);
        let awaited = Arc::clone(&grandchild);
        let result = owner
            .race_drained_with(vec![
                boxed(move |child: Cx| async move {
                    let handle = child
                        .spawn(move |gcx| descendant(gcx, receiver, spawned))
                        .expect("the losing branch spawns a child");
                    let _ = child.scope().join_all_owned(&child, vec![handle]).await;
                    0_u8
                }),
                boxed(move |_child| async move {
                    awaited
                        .wait(|seen| seen.parked.load(Ordering::Acquire))
                        .await;
                    5_u8
                }),
            ])
            .await;
        assert_eq!(result.expect("the second branch wins"), 5);
        assert_drained(&grandchild, "the child the losing branch was joining");
    });
}

#[test]
fn a_loser_joining_its_own_child_owned_is_drained_current_thread() {
    loser_joining_its_own_child_owned_is_drained(1);
}

#[test]
fn a_loser_joining_its_own_child_owned_is_drained_multi_thread() {
    loser_joining_its_own_child_owned_is_drained(4);
}

/// A timed race's branch that completes at or after the deadline lost to it,
/// even when the race engine selects it as the first finished branch: its
/// descendants are cancelled and drained before the race returns, as when the
/// deadline is selected (br-asupersync-inleqi M1). The branch sleeps exactly
/// to the race's deadline on the lab's virtual clock, so the branch and the
/// deadline become ready together and the seed picks the one the engine
/// selects.
#[test]
fn a_timed_race_drains_a_branch_that_finished_at_its_deadline() {
    for seed in 0..32_u64 {
        let config = asupersync::LabConfig::new(0x7173_0000 + seed).with_auto_advance();
        let ((result, parked, at_return), report) =
            asupersync::lab::run_async_under_lab_with_config(config, |owner| async move {
                let grandchild = Arc::new(Witness::default());
                let (_grandchild_sender, grandchild_receiver) = mpsc::channel::<()>(1);
                let spawned = Arc::clone(&grandchild);
                let duration = Duration::from_millis(10);
                let result = owner
                    .race_drained_with_timeout(
                        duration,
                        vec![boxed(move |child: Cx| async move {
                            child
                                .spawn(move |gcx| descendant(gcx, grandchild_receiver, spawned))
                                .expect("the branch spawns a grandchild");
                            asupersync::time::sleep(child.now(), duration).await;
                            1_u8
                        })],
                    )
                    .await;
                let at_return = (
                    grandchild.cancelled.load(Ordering::Acquire),
                    grandchild.retired.load(Ordering::Acquire),
                    *grandchild.kind.lock().unwrap(),
                );
                (result, grandchild.parked.load(Ordering::Acquire), at_return)
            });
        assert!(
            matches!(&result, Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::Timeout),
            "seed {seed}: a value at the deadline is not a timely winner, got {result:?}"
        );
        assert!(
            parked,
            "seed {seed}: the grandchild parked before the deadline"
        );
        let (cancelled, retired, kind) = at_return;
        assert!(
            cancelled && retired,
            "seed {seed}: the late branch's grandchild was still running when the race returned"
        );
        assert!(
            matches!(
                kind,
                Some(CancelKind::RaceLost | CancelKind::ParentCancelled)
            ),
            "seed {seed}: the grandchild was cancelled as a race loser, not {kind:?}"
        );
        assert!(report.quiescent, "seed {seed}: the lab run ends quiescent");
        assert!(
            report.oracle_report.all_passed(),
            "seed {seed}: every lab oracle passes"
        );
    }
}
