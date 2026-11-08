use super::*;
use crate::combinator::retry::{AlwaysRetry, RetryIf, RetryTokenBucket};
use crate::lab::{LabConfig, LabRuntime};
use crate::record::RegionLimits;
use crate::runtime::state::SpawnAdmission;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, TaskId, Time};
use parking_lot::Mutex;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};

#[derive(Clone, Default)]
struct Gate(Arc<GateState>);

#[derive(Default)]
struct GateState {
    open: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Gate {
    fn release(&self) {
        self.0.open.store(true, Ordering::SeqCst);
        let waker = self.0.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Future for Gate {
    type Output = ();

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<()> {
        if self.0.open.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }
        *self.0.waker.lock() = Some(task.waker().clone());
        if self.0.open.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn fixture(seed: u64) -> (LabRuntime, Cx, RegionId, Gate) {
    let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(10_000));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let gate = Gate::default();
    let (task, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, gate.clone())
        .unwrap();
    let owner = lab.state.task(task).unwrap().cx.clone().unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    (lab, owner, root, gate)
}

fn finish_fixture(lab: &mut LabRuntime, root: RegionId, gate: &Gate) {
    gate.release();
    lab.run_until_idle();
    lab.state
        .close_region_command(root, &CancelReason::user("test complete"));
    lab.run_until_idle();
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.state.region(root).is_none());
}

fn drive<T, E, F>(lab: &mut LabRuntime, mut future: Pin<&mut F>) -> ScopedRetryReport<T, E>
where
    F: Future<Output = Result<ScopedRetryReport<T, E>, ScopedRetryError>>,
{
    for _ in 0..2_048 {
        match poll_once(future.as_mut()) {
            Poll::Ready(Ok(report)) => return report,
            Poll::Ready(Err(error)) => panic!("unexpected budgeted retry refusal: {error}"),
            Poll::Pending => {
                lab.run_until_idle();
            }
        }
    }
    panic!("budgeted retry did not complete after its gates and timers were released");
}

fn budget(owner: &Cx, tokens: u32) -> RetryBudget {
    RetryBudget::new(RetryTokenBucket::new(
        tokens,
        0.0,
        owner.timer_driver().unwrap().now(),
    ))
}

#[test]
fn scoped_retry_budget_is_shared_first_attempts_are_free_and_exhaustion_keeps_errors() {
    let (mut lab, owner, root, gate) = fixture(0x5E_B100);
    let shared = budget(&owner, 2);
    for max_attempts in [2_u32, 3] {
        let mut retry = Box::pin(owner.retry_scoped_with_budget(
            RetryPolicy::immediate(max_attempts),
            shared.clone(),
            AlwaysRetry,
            |_, attempt| std::future::ready(Err::<u32, _>(attempt)),
        ));
        let report = drive(&mut lab, retry.as_mut());
        assert_eq!(report.attempts.len(), 2);
        if max_attempts == 2 {
            assert!(matches!(report.stop, ScopedRetryStop::Exhausted));
            assert_eq!(shared.available(), 1);
        } else {
            assert!(matches!(
                report.stop,
                ScopedRetryStop::BudgetExhausted { attempt: 2 }
            ));
            assert_eq!(shared.available(), 0);
        }
        for (index, attempt) in report.attempts.iter().enumerate() {
            assert_eq!(attempt.attempt as usize, index + 1);
            assert!(matches!(
                &attempt.task,
                ScopedRetryTask::Joined(Ok(Err(error))) if *error == attempt.attempt
            ));
            assert!(lab.state.region(attempt.region_id.unwrap()).is_none());
            let close = attempt.close.as_ref().unwrap().as_ref().unwrap();
            assert!(close.cleanup_outcome.is_none());
            assert!(close.descendant_panic.is_none());
        }
        assert_eq!(report.total_delay, Duration::ZERO);
        assert!(report.owner_cancellation.is_none());
    }
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_retry_budget_uses_owner_clock_for_refill_under_foreign_ambient() {
    let (mut lab, owner, root, gate) = fixture(0x5E_B200);
    let start = Time::from_secs(100);
    lab.advance_time_to(start);
    let shared = RetryBudget::new(RetryTokenBucket::new(1, 1.0, start));
    assert!(shared.try_acquire(start));
    let foreign = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::starting_at(
        Time::from_secs(10_000),
    )));
    let ambient = Cx::new_with_drivers(
        RegionId::new_for_test(900, 1),
        TaskId::new_for_test(900, 1),
        Budget::INFINITE,
        None,
        None,
        None,
        Some(foreign.clone()),
        None,
    );
    for refilled in [false, true] {
        if refilled {
            lab.advance_time_to(start + Duration::from_secs(1));
        }
        let mut retry = Box::pin(owner.retry_scoped_with_budget(
            RetryPolicy::immediate(2),
            shared.clone(),
            AlwaysRetry,
            |_, attempt| {
                std::future::ready(if attempt == 1 { Err(1_u32) } else { Ok(42_u32) })
            },
        ));
        let report = {
            let _ambient = Cx::set_current(Some(ambient.clone()));
            drive(&mut lab, retry.as_mut())
        };
        if refilled {
            assert!(matches!(report.stop, ScopedRetryStop::Succeeded { attempt: 2 }));
            assert_eq!(report.attempts.len(), 2);
        } else {
            assert!(matches!(
                report.stop,
                ScopedRetryStop::BudgetExhausted { attempt: 1 }
            ));
            assert_eq!(report.attempts.len(), 1);
        }
        assert_eq!(shared.available(), 0);
        assert!(foreign.is_empty());
    }
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_retry_budget_checks_clock_authority_and_precancel_before_work() {
    type SpawnOnly = cap::CapSet<true, false, false, false, false>;
    let (mut lab, mut owner, root, gate) = fixture(0x5E_B300);
    let shared = budget(&owner, 1);
    owner.runtime_mask = <SpawnOnly as cap::CapSetRuntimeMask>::MASK;
    for cancelled in [false, true] {
        let reason = CancelReason::user("budget owner already stopped");
        if cancelled {
            owner.set_cancel_reason(reason.clone());
        }
        let mut retry = Box::pin(owner.retry_scoped_with_budget(
            RetryPolicy::immediate(2),
            shared.clone(),
            AlwaysRetry,
            |_, _| -> std::future::Ready<Result<(), ()>> {
                panic!("missing clock or precancellation must refuse before invocation");
            },
        ));
        if cancelled {
            let Poll::Ready(Ok(report)) = poll_once(retry.as_mut()) else {
                panic!("precancellation needs no timer authority");
            };
            assert!(matches!(&report.stop, ScopedRetryStop::Cancelled(actual) if actual == &reason));
            assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
            assert!(report.attempts.is_empty());
        } else {
            assert!(matches!(
                poll_once(retry.as_mut()),
                Poll::Ready(Err(ScopedRetryError::TimerUnavailable))
            ));
        }
        assert_eq!(shared.available(), 1);
        assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    }
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_retry_budget_cancel_or_drop_during_backoff_refunds_and_retires_timer() {
    for cancelled in [false, true] {
        let (mut lab, owner, root, gate) = fixture(0x5E_B400 + u64::from(cancelled));
        let shared = budget(&owner, 1);
        let timer = owner.timer_driver().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let invoked = Arc::clone(&calls);
        let delay = Duration::from_secs(60);
        let mut retry = Box::pin(owner.retry_scoped_with_budget(
            RetryPolicy::fixed_delay(delay, 2),
            shared.clone(),
            AlwaysRetry,
            move |_, _| {
                invoked.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err::<u32, _>("retryable"))
            },
        ));
        for _ in 0..32 {
            assert!(poll_once(retry.as_mut()).is_pending());
            if timer.next_deadline().is_some() {
                break;
            }
            lab.run_until_idle();
        }
        assert!(timer.next_deadline().is_some());
        assert_eq!(shared.available(), 0, "the next attempt has a reservation");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        if cancelled {
            let reason = CancelReason::user("stop during budgeted backoff");
            owner.masked(|| {
                owner.set_cancel_reason(reason.clone());
                let report = drive(&mut lab, retry.as_mut());
                assert!(matches!(&report.stop, ScopedRetryStop::Cancelled(actual) if actual == &reason));
                assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
                assert_eq!(report.attempts.len(), 1);
                assert_eq!(report.total_delay, delay, "scheduled is not elapsed");
                assert_eq!(owner.inner.read().mask_depth, 1);
                assert!(!owner.inner.read().cancel_acknowledged);
            });
            assert_eq!(owner.inner.read().mask_depth, 0);
        }
        drop(retry);
        assert_eq!(shared.available(), 1);
        assert!(timer.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_retry_budget_cancel_or_drop_before_late_admission_refunds_without_invocation() {
    for cancelled in [false, true] {
        let (mut lab, owner, root, gate) = fixture(0x5E_B500 + u64::from(cancelled));
        let shared = budget(&owner, 1);
        let calls = Arc::new(AtomicUsize::new(0));
        let invoked = Arc::clone(&calls);
        let mut retry = Box::pin(owner.retry_scoped_with_budget(
            RetryPolicy::immediate(2),
            shared.clone(),
            AlwaysRetry,
            move |_, attempt| {
                assert_eq!(attempt, 1, "the second factory must never be invoked");
                invoked.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err::<u32, _>("first failed"))
            },
        ));
        let pending = owner.pending_spawn_counter_handle().unwrap();
        for _ in 0..32 {
            assert!(poll_once(retry.as_mut()).is_pending());
            if shared.available() == 0 && pending.count() == 1 {
                break;
            }
            lab.run_until_idle();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(shared.available(), 0);
        assert_eq!(pending.count(), 1);
        let gateway = owner.spawn_gateway_handle().unwrap();
        let parts = gateway.mailbox().dequeue().unwrap().into_parts();
        let slot = Arc::clone(parts.admitted_slot.as_ref().unwrap().branch_region().unwrap());
        let reason = CancelReason::user("stop before retry admission");
        let mut retry = if cancelled {
            owner.set_cancel_reason(reason.clone());
            assert!(poll_once(retry.as_mut()).is_pending());
            Some(retry)
        } else {
            drop(retry);
            None
        };
        assert!(slot.close_requested());
        let SpawnAdmission::Admitted {
            task_id,
            priority,
            cancel_publication,
            spawn_effects,
        } = lab.state.admit_spawn_request(parts) else {
            panic!("dequeued retry must reach the publication seam");
        };
        let region = slot.get().unwrap().region_id;
        let (wakes, observer) = cancel_publication.publish_with_spawn_effects(
            spawn_effects,
            |cancel_priority| {
                if let Some(priority) = cancel_priority {
                    lab.scheduler.lock().schedule_cancel(task_id, priority);
                } else {
                    lab.scheduler.lock().schedule(task_id, priority);
                }
            },
        );
        if let Some(observer) = observer {
            observer.dispatch();
        }
        wakes.dispatch();
        lab.run_until_idle();
        if let Some(retry) = retry.as_mut() {
            let report = drive(&mut lab, retry.as_mut());
            assert!(matches!(&report.stop, ScopedRetryStop::Cancelled(actual) if actual == &reason));
            assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
            assert_eq!(report.attempts.len(), 2);
            assert!(matches!(
                report.attempts[0].task,
                ScopedRetryTask::Joined(Ok(Err("first failed")))
            ));
        }
        drop(retry);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(shared.available(), 1);
        assert_eq!(pending.count(), 0);
        assert!(lab.state.region(region).is_none());
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_retry_budget_refunds_when_runtime_refuses_a_reserved_retry() {
    let (mut lab, owner, root, gate) = fixture(0x5E_B600);
    let shared = budget(&owner, 1);
    let mut retry = Box::pin(owner.retry_scoped_with_budget(
        RetryPolicy::immediate(3),
        shared.clone(),
        AlwaysRetry,
        |_, attempt| {
            assert_eq!(attempt, 1, "refused retry cannot invoke user code");
            std::future::ready(Err::<u32, _>("first failed"))
        },
    ));
    let pending = owner.pending_spawn_counter_handle().unwrap();
    for _ in 0..32 {
        assert!(poll_once(retry.as_mut()).is_pending());
        if shared.available() == 0 && pending.count() == 1 {
            break;
        }
        lab.run_until_idle();
    }
    assert_eq!(shared.available(), 0);
    assert_eq!(pending.count(), 1);
    assert!(lab.state.set_region_limits(root, RegionLimits {
        max_tasks: Some(1),
        ..RegionLimits::default()
    }));
    let report = drive(&mut lab, retry.as_mut());
    assert!(matches!(report.stop, ScopedRetryStop::NotAdmitted { attempt: 2 }));
    assert_eq!(report.attempts.len(), 2);
    assert!(matches!(
        report.attempts[0].task,
        ScopedRetryTask::Joined(Ok(Err("first failed")))
    ));
    assert!(report.attempts[1].region_id.is_none());
    assert!(report.attempts[1].close.is_none());
    assert_eq!(shared.available(), 1);
    assert_eq!(pending.count(), 0);
    drop(retry);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_retry_budget_fairness_yield_keeps_next_reservation_refundable() {
    let (mut lab, owner, root, gate) = fixture(0x5E_B700);
    let shared = budget(&owner, 64);
    let calls = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::clone(&calls);
    let mut retry = Box::pin(owner.retry_scoped_with_budget(
        RetryPolicy::immediate(1_000),
        shared.clone(),
        AlwaysRetry,
        move |_, _| {
            invoked.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err::<u32, _>("ready failure"))
        },
    ));
    let pending = owner.pending_spawn_counter_handle().unwrap();
    for _ in 0..512 {
        assert!(poll_once(retry.as_mut()).is_pending());
        if shared.available() == 0 {
            break;
        }
        lab.run_until_idle();
    }
    assert_eq!(shared.available(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 64);
    assert_eq!(pending.count(), 0, "fairness yields before the next submission");
    let reason = CancelReason::user("cancel at retry fairness yield");
    owner.set_cancel_reason(reason.clone());
    let report = drive(&mut lab, retry.as_mut());
    assert!(matches!(&report.stop, ScopedRetryStop::Cancelled(actual) if actual == &reason));
    assert_eq!(report.attempts.len(), 64);
    assert_eq!(calls.load(Ordering::SeqCst), 64);
    assert_eq!(shared.available(), 1, "63 retries spent, one reservation returned");
    drop(retry);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_retry_budget_spends_an_invoked_factory_token_even_when_the_factory_panics() {
    let (mut lab, owner, root, gate) = fixture(0x5E_B800);
    let shared = budget(&owner, 1);
    let mut retry = Box::pin(owner.retry_scoped_with_budget(
        RetryPolicy::immediate(3),
        shared.clone(),
        AlwaysRetry,
        |_, attempt| {
            assert_eq!(attempt, 1, "invoked retry factory panicked");
            std::future::ready(Err::<u32, _>("first failed"))
        },
    ));
    let report = drive(&mut lab, retry.as_mut());
    assert!(matches!(report.stop, ScopedRetryStop::TaskFailed { attempt: 2 }));
    assert_eq!(report.attempts.len(), 2);
    assert!(matches!(
        &report.attempts[1].task,
        ScopedRetryTask::Joined(Err(crate::runtime::JoinError::Panicked(_)))
    ));
    assert_eq!(shared.available(), 0, "the second factory really started");
    drop(retry);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_retry_budget_predicate_decline_or_cancellation_never_reserves() {
    for cancelled in [false, true] {
        let (mut lab, owner, root, gate) = fixture(0x5E_B900 + u64::from(cancelled));
        let shared = budget(&owner, 1);
        let predicate_owner = owner.clone();
        let reason = CancelReason::user("predicate stopped budgeted retry");
        let sent_reason = reason.clone();
        let mut retry = Box::pin(owner.retry_scoped_with_budget(
            RetryPolicy::fixed_delay(Duration::from_secs(60), 3),
            shared.clone(),
            RetryIf(move |_: &&'static str, _: u32| {
                if cancelled {
                    predicate_owner.set_cancel_reason(sent_reason.clone());
                }
                cancelled
            }),
            |_, attempt| {
                assert_eq!(attempt, 1);
                std::future::ready(Err::<u32, _>("first failed"))
            },
        ));
        let report = drive(&mut lab, retry.as_mut());
        if cancelled {
            assert!(matches!(&report.stop, ScopedRetryStop::Cancelled(actual) if actual == &reason));
        } else {
            assert!(matches!(
                report.stop,
                ScopedRetryStop::PredicateRejected { attempt: 1 }
            ));
        }
        assert_eq!(report.attempts.len(), 1);
        assert_eq!(report.total_delay, Duration::ZERO);
        assert_eq!(shared.available(), 1);
        assert!(owner.timer_driver().unwrap().is_empty());
        drop(retry);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_retry_budget_native_cancellation_refunds_reserved_backoff_and_drains() {
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};

    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for (current_thread, sharded) in
                [(true, false), (true, true), (false, false), (false, true)]
            {
                let builder = if current_thread {
                    RuntimeBuilder::current_thread()
                } else {
                    RuntimeBuilder::multi_thread().worker_threads(2)
                };
                let timer = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::new()));
                let runtime = builder
                    .with_sharded_state(sharded)
                    .with_timer_driver(timer)
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let owner = Cx::current().expect("native root context");
                    let shared = budget(&owner, 1);
                    let retry_budget = shared.clone();
                    let predicate_budget = shared.clone();
                    let calls = Arc::new(AtomicUsize::new(0));
                    let invoked = Arc::clone(&calls);
                    let registered = Gate::default();
                    let observed = registered.clone();
                    let mut retrying = owner.spawn(move |retry_owner| async move {
                        let timer = retry_owner.timer_driver().unwrap();
                        let mut retry = Box::pin(retry_owner.retry_scoped_with_budget(
                            RetryPolicy::fixed_delay(Duration::from_secs(60), 3),
                            retry_budget,
                            RetryIf(move |_: &&'static str, _: u32| {
                                assert_eq!(predicate_budget.available(), 1);
                                true
                            }),
                            move |_, attempt| {
                                assert_eq!(attempt, 1);
                                invoked.fetch_add(1, Ordering::SeqCst);
                                std::future::ready(Err::<u32, _>("try later"))
                            },
                        ));
                        let report = poll_fn(|task| {
                            let progress = retry.as_mut().poll(task);
                            if progress.is_pending() && !timer.is_empty() {
                                observed.release();
                            }
                            progress
                        }).await.unwrap();
                        assert!(timer.is_empty());
                        assert!(!retry_owner.inner.read().cancel_acknowledged);
                        assert!(retry_owner.checkpoint().is_err());
                        report
                    }).unwrap();
                    registered.await;
                    assert_eq!(shared.available(), 0, "backoff holds one reservation");
                    let reason = CancelReason::shutdown()
                        .with_cause(CancelReason::user("stop native budgeted retry"));
                    retrying.abort_with_reason(reason.clone());
                    let report = retrying.join(&owner).await.unwrap();
                    assert!(matches!(&report.stop, ScopedRetryStop::Cancelled(actual) if actual == &reason));
                    assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
                    assert_eq!(report.attempts.len(), 1);
                    assert_eq!(report.total_delay, Duration::from_secs(60));
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                    assert_eq!(shared.available(), 1);
                    assert!(matches!(
                        report.attempts[0].task,
                        ScopedRetryTask::Joined(Ok(Err("try later")))
                    ));
                    let close = report.attempts[0].close.as_ref().unwrap().as_ref().unwrap();
                    assert!(close.cleanup_outcome.is_none());
                    assert!(close.descendant_panic.is_none());
                    assert!(!owner.is_cancel_requested());
                });
                let report = runtime.shutdown_drained(Duration::from_secs(5));
                assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                assert_eq!(report.live_tasks, 0);
                assert_eq!(report.live_regions, 0);
                assert_eq!(report.pending_spawns, 0);
                assert_eq!(report.pending_obligations, 0);
            }
        }));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(45))
        .expect("budgeted retry must finish native cancellation and drain");
    worker.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}
