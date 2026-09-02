//! End-to-end proof that `Scope::quorum` (M-of-N completion) and
//! `Scope::first_ok` (sequential fallback) actually EXECUTE branches on the
//! runtime — they are not just outcome-vector folders.
//!
//! Every scenario is written once as an `async fn(Cx) -> Report` and run on
//! two targets:
//!
//! - the **production runtime** (`RuntimeBuilder::new().build()`), where the
//!   report is asserted after `block_on` and the runtime is then required to
//!   shut down quiescent within a bounded timeout;
//! - the **LabRuntime** (via `LabRuntimeTarget`), where the same report is
//!   asserted and `LabRuntime::check_invariants()` — the obligation-leak,
//!   task-leak, quiescence, futurelock, and cancellation-protocol oracles —
//!   must come back empty.
//!
//! # What discriminates drain from drop
//!
//! Each quorum loser parks (self-waking) until *its own task* observes
//! cancellation through `Cx::checkpoint`, then performs a deliberately
//! **blocking** 150 ms cleanup (a cancellation-aware async sleep would complete
//! immediately in a cancelled task, so it cannot stand in for cleanup work),
//! bumps a shared counter, and returns. A loser that is merely dropped at its
//! suspend point never advances past it, and a loser that is aborted but *not
//! joined* is still inside its cleanup when a non-draining combinator would
//! have returned. The counter is sampled at the instant `quorum` resolves —
//! before any sleep or extra scheduling — so it can only carry its expected
//! value if every loser was protocol-cancelled AND joined to termination.
//! (A deliberate drop-abandon control on the multi-thread production runtime
//! showed that without the blocking cleanup the aborted losers can race ahead
//! of the sampling thread; the blocking cleanup closes that window.)
//!
//! # No-claim line
//!
//! Green here does not prove fairness, timing bounds, or behavior under
//! runtime shutdown. It proves: the winners' values are returned; losers are
//! cancelled and driven to completion before return; an impossible quorum
//! reports failure only after every branch terminated; `first_ok` never
//! invokes a later factory after a success; invalid `needed` values are
//! rejected without spawning; and the region is quiescent afterwards on both
//! targets.

#![allow(missing_docs)]

use asupersync::combinator::{FirstOkError, QuorumError};
use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::cx::Cx;
use asupersync::runtime::RuntimeBuilder;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

/// A boxed, heterogeneous branch factory of the shape both combinators accept.
type Branch<T, E> =
    Box<dyn FnOnce(Cx) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send>> + Send>;

/// Parks (self-waking) until `task_cx` — the branch's own task context — has
/// been cancelled. Only a real cancel + re-poll drives this to `Ready`; the
/// future never completes on its own.
async fn park_until_cancelled(task_cx: &Cx) {
    std::future::poll_fn(|poll_cx| {
        if task_cx.checkpoint().is_err() {
            Poll::Ready(())
        } else {
            poll_cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

/// Post-cancellation cleanup that takes real time and is NOT a cancellation
/// point: a blocking sleep on the task's thread. `asupersync::time::sleep`
/// deliberately resolves at once inside a cancel-requested task, so it cannot
/// model "cleanup still in progress"; blocking can, and in a test that is
/// exactly the point.
fn blocking_cleanup_work() {
    std::thread::sleep(Duration::from_millis(150));
}

// ---------------------------------------------------------------------------
// Harness: run one scenario on the production runtime or on LabRuntime.
// ---------------------------------------------------------------------------

fn run_on_production<F, Fut, R>(scenario: F) -> R
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let runtime = RuntimeBuilder::new()
        .build()
        .expect("production runtime build");
    let handle = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task installs ambient Cx");
        scenario(cx).await
    });
    let report = runtime.block_on(handle);
    assert!(
        runtime.shutdown_timeout(Duration::from_secs(10)),
        "production runtime must reach quiescence and shut down within the timeout"
    );
    report
}

fn run_on_lab<F, Fut, R>(scenario: F) -> R
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
    let report = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("LabRuntimeTarget root task installs Cx");
        scenario(cx).await
    });
    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "LabRuntime oracles must be clean after the scenario: {violations:?}"
    );
    report
}

// ---------------------------------------------------------------------------
// Scenario 1: quorum(2 of 4) — winners returned, losers cancelled AND drained.
// ---------------------------------------------------------------------------

struct QuorumMetReport {
    result: Result<Vec<u32>, QuorumError<String>>,
    /// Number of losers that observed cancellation and ran to completion,
    /// sampled at the instant `quorum` resolved.
    losers_drained_at_return: usize,
}

async fn quorum_two_of_four(cx: Cx) -> QuorumMetReport {
    let losers_drained = Arc::new(AtomicUsize::new(0));
    let branches = (0..4_u32).map(|index| {
        let drained = Arc::clone(&losers_drained);
        move |child: Cx| async move {
            if index % 2 == 0 {
                // Branches 0 and 2 succeed immediately.
                Ok::<u32, String>(index * 10)
            } else {
                // Branches 1 and 3 can never win: they park until their own
                // task is cancelled, then run their post-cancel cleanup.
                park_until_cancelled(&child).await;
                blocking_cleanup_work();
                drained.fetch_add(1, Ordering::SeqCst);
                Err(format!("branch {index} observed cancellation"))
            }
        }
    });

    let result = cx.scope().quorum(&cx, 2, branches).await;
    let losers_drained_at_return = losers_drained.load(Ordering::SeqCst);
    QuorumMetReport {
        result,
        losers_drained_at_return,
    }
}

fn assert_quorum_two_of_four(report: QuorumMetReport) {
    let values = match report.result {
        Ok(values) => values,
        Err(error) => panic!("quorum(2 of 4) must succeed, got {error}"),
    };
    assert_eq!(
        values,
        vec![0, 20],
        "exactly the two immediately-successful branches (spawn order) must be returned"
    );
    assert_eq!(
        report.losers_drained_at_return, 2,
        "both losers must observe cancellation and RUN TO COMPLETION before quorum returns"
    );
}

#[test]
fn production_quorum_two_of_four_returns_winners_and_drains_losers() {
    assert_quorum_two_of_four(run_on_production(quorum_two_of_four));
}

#[test]
fn lab_quorum_two_of_four_returns_winners_and_drains_losers() {
    assert_quorum_two_of_four(run_on_lab(quorum_two_of_four));
}

// ---------------------------------------------------------------------------
// Scenario 2 (planted negative): quorum(3 of 4) where at most 2 can succeed.
// ---------------------------------------------------------------------------

struct QuorumImpossibleReport {
    result: Result<Vec<u32>, QuorumError<String>>,
    /// Number of branches that reached their final statement, sampled at the
    /// instant `quorum` resolved.
    completed_at_return: usize,
}

async fn quorum_three_of_four_impossible(cx: Cx) -> QuorumImpossibleReport {
    let completed = Arc::new(AtomicUsize::new(0));
    let branches = (0..4_u32).map(|index| {
        let completed = Arc::clone(&completed);
        move |child: Cx| async move {
            let outcome = match index {
                // Two immediate failures make 3-of-4 impossible.
                0 | 2 => Err(format!("branch {index} failed")),
                // One immediate success.
                1 => Ok(10_u32),
                // The fourth branch never completes on its own; it only
                // terminates after quorum cancels it, so a completion count
                // of 4 proves the failure was reported after a real drain.
                _ => {
                    park_until_cancelled(&child).await;
                    blocking_cleanup_work();
                    Ok(30_u32)
                }
            };
            completed.fetch_add(1, Ordering::SeqCst);
            outcome
        }
    });

    let result = cx.scope().quorum(&cx, 3, branches).await;
    let completed_at_return = completed.load(Ordering::SeqCst);
    QuorumImpossibleReport {
        result,
        completed_at_return,
    }
}

fn assert_quorum_three_of_four_impossible(report: QuorumImpossibleReport) {
    match report.result {
        Err(QuorumError::InsufficientSuccesses {
            required,
            total,
            achieved,
            errors,
        }) => {
            assert_eq!(required, 3);
            assert_eq!(total, 4);
            assert!(
                achieved <= 2,
                "at most branch 1 (and never the cancelled branch 3) can count as a success, got {achieved}"
            );
            assert_eq!(
                errors.len(),
                2,
                "both planted application errors must be reported, got {errors:?}"
            );
        }
        Ok(values) => panic!("quorum(3 of 4) with two failures must not succeed, got {values:?}"),
        Err(other) => panic!("expected InsufficientSuccesses, got {other}"),
    }
    assert_eq!(
        report.completed_at_return, 4,
        "the failure must be reported only after ALL four branches terminated \
         (including the parked branch, which terminates only when cancelled and drained)"
    );
}

#[test]
fn production_quorum_three_of_four_fails_only_after_every_branch_terminated() {
    assert_quorum_three_of_four_impossible(run_on_production(quorum_three_of_four_impossible));
}

#[test]
fn lab_quorum_three_of_four_fails_only_after_every_branch_terminated() {
    assert_quorum_three_of_four_impossible(run_on_lab(quorum_three_of_four_impossible));
}

// ---------------------------------------------------------------------------
// Scenario 3: first_ok over [Err, Err, Ok, Ok] — third wins, fourth never runs.
// ---------------------------------------------------------------------------

struct FirstOkReport {
    result: Result<u32, FirstOkError<String>>,
    factories_invoked: usize,
}

async fn first_ok_third_succeeds(cx: Cx) -> FirstOkReport {
    let invoked = Arc::new(AtomicUsize::new(0));
    let mut factories: Vec<Branch<u32, String>> = Vec::new();
    for index in 0..4_usize {
        let invoked = Arc::clone(&invoked);
        factories.push(Box::new(
            move |_child: Cx| -> Pin<Box<dyn Future<Output = Result<u32, String>> + Send>> {
                invoked.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    match index {
                        0 | 1 => Err(format!("attempt {index} failed")),
                        2 => Ok(42_u32),
                        _ => Ok(99_u32),
                    }
                })
            },
        ));
    }

    let result = cx.scope().first_ok(&cx, factories).await;
    FirstOkReport {
        result,
        factories_invoked: invoked.load(Ordering::SeqCst),
    }
}

fn assert_first_ok_third_succeeds(report: FirstOkReport) {
    match report.result {
        Ok(value) => assert_eq!(value, 42, "the third factory's value must be returned"),
        Err(error) => panic!("first_ok over [Err, Err, Ok, Ok] must succeed, got {error}"),
    }
    assert_eq!(
        report.factories_invoked, 3,
        "the fourth factory must never be invoked after the third attempt succeeded"
    );
}

#[test]
fn production_first_ok_returns_third_value_and_never_invokes_fourth_factory() {
    assert_first_ok_third_succeeds(run_on_production(first_ok_third_succeeds));
}

#[test]
fn lab_first_ok_returns_third_value_and_never_invokes_fourth_factory() {
    assert_first_ok_third_succeeds(run_on_lab(first_ok_third_succeeds));
}

// ---------------------------------------------------------------------------
// Scenario 3b: first_ok where every attempt fails — all errors, in order.
// ---------------------------------------------------------------------------

async fn first_ok_all_fail(cx: Cx) -> FirstOkReport {
    let invoked = Arc::new(AtomicUsize::new(0));
    let factories = (0..3_u32).map(|index| {
        let invoked = Arc::clone(&invoked);
        move |_child: Cx| {
            invoked.fetch_add(1, Ordering::SeqCst);
            async move { Err::<u32, String>(format!("e{index}")) }
        }
    });
    let result = cx.scope().first_ok(&cx, factories).await;
    FirstOkReport {
        result,
        factories_invoked: invoked.load(Ordering::SeqCst),
    }
}

fn assert_first_ok_all_fail(report: FirstOkReport) {
    match report.result {
        Err(FirstOkError::AllFailed { errors, attempted }) => {
            assert_eq!(
                errors,
                vec!["e0".to_string(), "e1".to_string(), "e2".to_string()]
            );
            assert_eq!(attempted, 3);
        }
        Ok(value) => panic!("all-failing chain must not succeed, got {value}"),
        Err(other) => panic!("expected AllFailed, got {other}"),
    }
    assert_eq!(
        report.factories_invoked, 3,
        "every factory must be tried once"
    );
}

#[test]
fn production_first_ok_all_fail_reports_every_error_in_order() {
    assert_first_ok_all_fail(run_on_production(first_ok_all_fail));
}

#[test]
fn lab_first_ok_all_fail_reports_every_error_in_order() {
    assert_first_ok_all_fail(run_on_lab(first_ok_all_fail));
}

// ---------------------------------------------------------------------------
// Scenario 4: rejection of needed == 0 / needed > len, without spawning.
// ---------------------------------------------------------------------------

struct RejectionReport {
    zero: Result<Vec<u32>, QuorumError<String>>,
    too_many: Result<Vec<u32>, QuorumError<String>>,
    empty_first_ok: Result<u32, FirstOkError<String>>,
    /// Number of branch bodies that ever ran across both rejected calls.
    branches_run: usize,
}

async fn quorum_rejections(cx: Cx) -> RejectionReport {
    let ran = Arc::new(AtomicUsize::new(0));
    let make_branches = |ran: &Arc<AtomicUsize>| {
        let ran = Arc::clone(ran);
        (0..3_u32).map(move |index| {
            let ran = Arc::clone(&ran);
            move |_child: Cx| async move {
                ran.fetch_add(1, Ordering::SeqCst);
                Ok::<u32, String>(index)
            }
        })
    };

    let scope = cx.scope();
    let zero = scope.quorum(&cx, 0, make_branches(&ran)).await;
    let too_many = scope.quorum(&cx, 4, make_branches(&ran)).await;
    let empty_first_ok = scope.first_ok(&cx, Vec::<Branch<u32, String>>::new()).await;
    RejectionReport {
        zero,
        too_many,
        empty_first_ok,
        branches_run: ran.load(Ordering::SeqCst),
    }
}

fn assert_quorum_rejections(report: RejectionReport) {
    assert!(
        matches!(
            report.zero,
            Err(QuorumError::InvalidQuorum {
                required: 0,
                total: 3
            })
        ),
        "needed == 0 must be rejected as InvalidQuorum, got {:?}",
        report.zero
    );
    assert!(
        matches!(
            report.too_many,
            Err(QuorumError::InvalidQuorum {
                required: 4,
                total: 3
            })
        ),
        "needed > len must be rejected as InvalidQuorum, got {:?}",
        report.too_many
    );
    assert!(
        matches!(report.empty_first_ok, Err(FirstOkError::Empty)),
        "first_ok over no factories must report Empty, got {:?}",
        report.empty_first_ok
    );
    assert_eq!(
        report.branches_run, 0,
        "a rejected quorum must not spawn or run any branch"
    );
}

#[test]
fn production_quorum_rejects_zero_and_oversized_needed_without_spawning() {
    assert_quorum_rejections(run_on_production(quorum_rejections));
}

#[test]
fn lab_quorum_rejects_zero_and_oversized_needed_without_spawning() {
    assert_quorum_rejections(run_on_lab(quorum_rejections));
}
