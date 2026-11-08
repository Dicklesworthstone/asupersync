use super::*;
use crate::combinator::retry::{AlwaysRetry, RetryIf};
use crate::lab::{LabConfig, LabRuntime};
use crate::record::RegionLimits;
use crate::record::region::RegionState;
use crate::runtime::JoinError;
use crate::runtime::state::SpawnAdmission;
use crate::time::TimerDriverHandle;
use crate::types::{Budget, Outcome, Time};
use parking_lot::Mutex;
use std::cell::Cell;
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

fn fixture(seed: u64, start: Time) -> (LabRuntime, Cx, RegionId, Gate) {
    let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(10_000));
    lab.advance_time_to(start);
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

fn drive<T: std::fmt::Debug, E: std::fmt::Debug, F>(
    lab: &mut LabRuntime,
    mut future: Pin<&mut F>,
) -> ScopedRetryReport<T, E>
where
    F: Future<Output = Result<ScopedRetryReport<T, E>, ScopedRetryError>>,
{
    for _ in 0..128 {
        match poll_once(future.as_mut()) {
            Poll::Ready(Ok(report)) => return report,
            Poll::Ready(Err(error)) => panic!("unexpected scoped retry refusal: {error}"),
            Poll::Pending => {
                lab.run_until_idle();
            }
        }
    }
    panic!("scoped retry did not complete after its gates were released");
}

fn wait_for_timer<F: Future>(
    lab: &mut LabRuntime,
    mut future: Pin<&mut F>,
    timer: &TimerDriverHandle,
) -> Time {
    for _ in 0..128 {
        assert!(poll_once(future.as_mut()).is_pending());
        lab.run_until_idle();
        if let Some(deadline) = timer.next_deadline() {
            return deadline;
        }
    }
    panic!("retry never reached its registered backoff timer");
}

#[test]
fn scoped_retry_preserves_mutable_factory_errors_and_strategy_stops() {
    for (max, selected, decline) in [
        (4_u32, Some(3_u32), false),
        (3, None, false),
        (5, None, true),
    ] {
        let (mut lab, owner, root, gate) = fixture(0x52_E101 + u64::from(max), Time::ZERO);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let called = Arc::clone(&calls);
        let predicates = Arc::new(AtomicUsize::new(0));
        let checked = Arc::clone(&predicates);
        let mut generation = 0;
        let mut retry = Box::pin(owner.retry_scoped(
            RetryPolicy::immediate(max),
            RetryIf(move |error: &String, attempt| {
                checked.fetch_add(1, Ordering::SeqCst);
                assert_eq!(error, &format!("attempt {attempt}"));
                !decline
            }),
            move |body, attempt| {
                generation += 1;
                assert_eq!(generation, attempt, "FnMut state travels between tasks");
                called.lock().push((attempt, body.region_id()));
                async move {
                    if selected == Some(attempt) {
                        Ok(attempt * 10)
                    } else {
                        Err(format!("attempt {attempt}"))
                    }
                }
            },
        ));
        let report = drive(&mut lab, retry.as_mut());
        let count = if decline { 1 } else { selected.unwrap_or(max) };
        assert_eq!(report.attempts.len(), count as usize);
        assert_eq!(calls.lock().len(), count as usize);
        assert_eq!(
            predicates.load(Ordering::SeqCst),
            if decline { 1 } else { count as usize - 1 }
        );
        if decline {
            assert!(matches!(
                report.stop,
                ScopedRetryStop::PredicateRejected { attempt: 1 }
            ));
        } else if let Some(selected) = selected {
            assert!(matches!(
                report.stop,
                ScopedRetryStop::Succeeded { attempt } if attempt == selected
            ));
        } else {
            assert!(matches!(report.stop, ScopedRetryStop::Exhausted));
        }
        for (index, receipt) in report.attempts.iter().enumerate() {
            assert_eq!(receipt.attempt as usize, index + 1);
            let region = receipt.region_id.expect("each attempt has its own region");
            assert_eq!(calls.lock()[index], (receipt.attempt, region));
            assert_ne!(region, root);
            assert!(
                report.attempts[..index]
                    .iter()
                    .all(|earlier| earlier.region_id != Some(region))
            );
            assert!(lab.state.region(region).is_none());
            let close = receipt.close.as_ref().unwrap().as_ref().unwrap();
            assert!(close.cleanup_outcome.is_none());
            assert!(close.descendant_panic.is_none());
            if selected == Some(receipt.attempt) {
                assert!(matches!(&receipt.task,
                    ScopedRetryTask::Joined(Ok(Ok(value))) if *value == receipt.attempt * 10));
            } else {
                assert!(matches!(&receipt.task,
                    ScopedRetryTask::Joined(Ok(Err(error))) if error == &format!("attempt {}", receipt.attempt)));
            }
        }
        assert_eq!(report.total_delay, Duration::ZERO);
        assert!(report.owner_cancellation.is_none());
        assert!(owner.timer_driver().unwrap().is_empty());
        drop(retry);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_retry_normalizes_zero_attempts_and_requires_only_used_runtime_authority() {
    type SpawnOnly = cap::CapSet<true, false, false, false, false>;
    for zero_attempts in [false, true] {
        let (mut lab, mut owner, root, gate) =
            fixture(0x52_E200 + u64::from(zero_attempts), Time::ZERO);
        owner.runtime_mask = <SpawnOnly as cap::CapSetRuntimeMask>::MASK;
        let mut policy = RetryPolicy::new().with_max_delay(Duration::ZERO);
        policy.max_attempts = if zero_attempts { 0 } else { 2 };
        let mut retry = Box::pin(owner.retry_scoped(policy, AlwaysRetry, |body, attempt| {
            assert!(body.timer_driver().is_none());
            assert!(!body.capabilities().entropy);
            std::future::ready(Err::<(), _>(attempt))
        }));
        let report = drive(&mut lab, retry.as_mut());
        assert!(matches!(report.stop, ScopedRetryStop::Exhausted));
        assert_eq!(report.attempts.len(), if zero_attempts { 1 } else { 2 });
        assert_eq!(report.total_delay, Duration::ZERO);
        drop(retry);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_retry_refuses_missing_authority_before_invoking_factory() {
    type SpawnOnly = cap::CapSet<true, false, false, false, false>;
    type SpawnTime = cap::CapSet<true, true, false, false, false>;
    for refusal in 0..3 {
        let (mut lab, mut owner, root, gate) = fixture(0x52_E300 + refusal, Time::ZERO);
        match refusal {
            0 => owner = owner.with_spawn_gateway(None),
            1 => owner.runtime_mask = <SpawnOnly as cap::CapSetRuntimeMask>::MASK,
            _ => owner.runtime_mask = <SpawnTime as cap::CapSetRuntimeMask>::MASK,
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let invoked = Arc::clone(&calls);
        let mut retry =
            Box::pin(
                owner.retry_scoped(RetryPolicy::new(), AlwaysRetry, move |_, _| {
                    invoked.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok::<_, ()>(42))
                }),
            );
        let result = poll_once(retry.as_mut());
        match refusal {
            0 => assert!(matches!(
                result,
                Poll::Ready(Err(ScopedRetryError::Spawn(SpawnError::RuntimeUnavailable)))
            )),
            1 => assert!(matches!(
                result,
                Poll::Ready(Err(ScopedRetryError::TimerUnavailable))
            )),
            _ => assert!(matches!(
                result,
                Poll::Ready(Err(ScopedRetryError::EntropyUnavailable))
            )),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.live_task_count(), 1);
        drop(retry);
        finish_fixture(&mut lab, root, &gate);
    }

    let owner = Cx::for_testing();
    let reason = CancelReason::shutdown().with_cause(CancelReason::user("already stopped"));
    owner.set_cancel_reason(reason.clone());
    let mut retry = Box::pin(owner.retry_scoped(RetryPolicy::new(), AlwaysRetry, |_, _| {
        panic!("pre-cancelled owner must not invoke the factory");
        #[allow(unreachable_code)]
        std::future::ready(Ok::<(), ()>(()))
    }));
    let Poll::Ready(Ok(report)) = poll_once(retry.as_mut()) else {
        panic!("pre-cancelled retry needs no runtime authority");
    };
    assert!(matches!(&report.stop, ScopedRetryStop::Cancelled(actual) if actual == &reason));
    assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
    assert!(report.attempts.is_empty());
    assert!(!owner.inner.read().cancel_acknowledged);
}

fn backoff_schedule(jitter: f64, ambient_draws: u32) -> (Vec<Time>, Duration) {
    let start = Time::from_millis(100);
    let (mut lab, owner, root, gate) = fixture(0x52_E400, start);
    let timer = owner.timer_driver().unwrap();
    let ambient = Cx::for_testing();
    for _ in 0..ambient_draws {
        let _ = ambient.random_u64();
    }
    ambient.set_cancel_reason(CancelReason::shutdown());
    let _foreign_context = Cx::set_current(Some(ambient.clone()));
    let starts = Arc::new(Mutex::new(Vec::new()));
    let called = Arc::clone(&starts);
    let policy = RetryPolicy::new()
        .with_max_attempts(3)
        .with_initial_delay(Duration::from_millis(10))
        .with_max_delay(Duration::from_millis(100))
        .with_multiplier(2.0)
        .with_jitter(jitter);
    let mut retry = Box::pin(
        owner.retry_scoped(policy, AlwaysRetry, move |body, attempt| {
            called.lock().push(body.timer_driver().unwrap().now());
            std::future::ready(if attempt == 3 { Ok(42) } else { Err(attempt) })
        }),
    );
    let first = wait_for_timer(&mut lab, retry.as_mut(), &timer);
    assert_eq!(*starts.lock(), vec![start]);
    lab.advance_time_to(Time::from_nanos(first.as_nanos() - 1));
    let _ = timer.process_timers();
    assert!(poll_once(retry.as_mut()).is_pending());
    lab.run_until_idle();
    assert_eq!(starts.lock().len(), 1, "no retry before the exact deadline");
    lab.advance_time_to(first);
    let _ = timer.process_timers();
    let second = wait_for_timer(&mut lab, retry.as_mut(), &timer);
    assert_eq!(*starts.lock(), vec![start, first]);
    lab.advance_time_to(second);
    let _ = timer.process_timers();
    let report = drive(&mut lab, retry.as_mut());
    assert!(matches!(
        report.stop,
        ScopedRetryStop::Succeeded { attempt: 3 }
    ));
    assert_eq!(*starts.lock(), vec![start, first, second]);
    assert!(report.owner_cancellation.is_none());
    assert!(timer.is_empty());
    assert!(!owner.is_cancel_requested());
    let total_delay = report.total_delay;
    drop(retry);
    finish_fixture(&mut lab, root, &gate);
    (vec![first, second], total_delay)
}

#[test]
fn scoped_retry_backoff_uses_explicit_virtual_clock_and_exponential_delays() {
    let (deadlines, total) = backoff_schedule(0.0, 5);
    assert_eq!(
        deadlines,
        vec![Time::from_millis(110), Time::from_millis(130)]
    );
    assert_eq!(total, Duration::from_millis(30));
}

#[test]
fn scoped_retry_jitter_replays_from_owner_entropy_despite_foreign_context() {
    let first = backoff_schedule(0.5, 0);
    let second = backoff_schedule(0.5, 37);
    assert_eq!(first, second);
    let (deadlines, total) = first;
    let first_delay = deadlines[0].as_nanos() - Time::from_millis(100).as_nanos();
    let second_delay = deadlines[1].as_nanos() - deadlines[0].as_nanos();
    assert!((10_000_000..=15_000_000).contains(&first_delay));
    assert!((20_000_000..=30_000_000).contains(&second_delay));
    assert_eq!(total, Duration::from_nanos(first_delay + second_delay));
}

#[test]
fn scoped_retry_predicate_cancellation_wins_without_backoff_or_new_attempt() {
    for accepted in [false, true] {
        let (mut lab, owner, root, gate) = fixture(0x52_E500 + u64::from(accepted), Time::ZERO);
        let cancelled_owner = owner.clone();
        let reason =
            CancelReason::user("predicate stopped retry").with_cause(CancelReason::timeout());
        let sent_reason = reason.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let invoked = Arc::clone(&calls);
        let mut retry = Box::pin(owner.retry_scoped(
            RetryPolicy::fixed_delay(Duration::from_secs(60), 3),
            RetryIf(move |error: &&str, attempt| {
                assert_eq!(*error, "keep this failure");
                assert_eq!(attempt, 1);
                cancelled_owner.set_cancel_reason(sent_reason.clone());
                accepted
            }),
            move |_, _| {
                invoked.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err::<(), _>("keep this failure"))
            },
        ));
        let report = drive(&mut lab, retry.as_mut());
        assert!(matches!(&report.stop, ScopedRetryStop::Cancelled(actual) if actual == &reason));
        assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(report.attempts.len(), 1);
        assert!(matches!(
            report.attempts[0].task,
            ScopedRetryTask::Joined(Ok(Err("keep this failure")))
        ));
        assert_eq!(report.total_delay, Duration::ZERO);
        assert!(owner.timer_driver().unwrap().is_empty());
        assert!(!owner.inner.read().cancel_acknowledged);
        drop(retry);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_retry_cancel_or_drop_during_backoff_retires_timer_and_no_extra_attempt() {
    for cancel in [false, true] {
        let (mut lab, owner, root, gate) = fixture(0x52_E600 + u64::from(cancel), Time::ZERO);
        let timer = owner.timer_driver().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let invoked = Arc::clone(&calls);
        let mut retry = Box::pin(owner.retry_scoped(
            RetryPolicy::fixed_delay(Duration::from_secs(60), 3),
            AlwaysRetry,
            move |_, _| {
                invoked.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err::<(), _>("not yet"))
            },
        ));
        assert_eq!(
            wait_for_timer(&mut lab, retry.as_mut(), &timer),
            Time::from_secs(60)
        );
        assert_eq!(
            lab.state.live_task_count(),
            1,
            "backoff has no live attempt"
        );
        if cancel {
            let reason = CancelReason::shutdown().with_cause(CancelReason::user("stop backoff"));
            owner.set_cancel_reason(reason.clone());
            let report = drive(&mut lab, retry.as_mut());
            assert!(
                matches!(&report.stop, ScopedRetryStop::Cancelled(actual) if actual == &reason)
            );
            assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
            assert_eq!(report.attempts.len(), 1);
            assert_eq!(report.total_delay, Duration::from_secs(60));
        }
        drop(retry);
        assert!(timer.is_empty());
        lab.advance_time_to(Time::from_secs(120));
        let _ = timer.process_timers();
        lab.run_until_idle();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_retry_refuses_parent_fallback_without_running_factory() {
    for limit in [1, 10] {
        let (mut lab, owner, root, gate) = fixture(0x52_E700 + limit as u64, Time::ZERO);
        assert!(lab.state.set_region_limits(
            root,
            RegionLimits {
                max_tasks: Some(limit),
                ..RegionLimits::default()
            }
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let invoked = Arc::clone(&calls);
        let mut retry =
            Box::pin(
                owner.retry_scoped(RetryPolicy::immediate(3), AlwaysRetry, move |_, _| {
                    invoked.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok::<_, ()>(42))
                }),
            );
        let report = drive(&mut lab, retry.as_mut());
        assert!(matches!(
            report.stop,
            ScopedRetryStop::NotAdmitted { attempt: 1 }
        ));
        assert_eq!(report.attempts.len(), 1);
        assert!(report.attempts[0].region_id.is_none());
        assert!(report.attempts[0].close.is_none());
        if limit == 1 {
            assert!(matches!(
                report.attempts[0].task,
                ScopedRetryTask::Joined(Err(JoinError::Cancelled(_)))
            ));
        } else {
            assert!(matches!(
                report.attempts[0].task,
                ScopedRetryTask::NotStarted
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
        drop(retry);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_retry_drop_before_admission_closes_late_private_region() {
    let (mut lab, owner, root, gate) = fixture(0x52_E800, Time::ZERO);
    let unused = owner.retry_scoped(RetryPolicy::new(), AlwaysRetry, |_, _| {
        panic!("an unpolled factory cannot run");
        #[allow(unreachable_code)]
        std::future::ready(Ok::<(), ()>(()))
    });
    drop(unused);
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    let calls = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::clone(&calls);
    let mut retry =
        Box::pin(
            owner.retry_scoped(RetryPolicy::immediate(3), AlwaysRetry, move |_, _| {
                invoked.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok::<_, ()>(42))
            }),
        );
    assert!(poll_once(retry.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
    let parts = gateway.mailbox().dequeue().unwrap().into_parts();
    let slot = Arc::clone(
        parts
            .admitted_slot
            .as_ref()
            .unwrap()
            .branch_region()
            .unwrap(),
    );
    assert!(slot.get().is_none());
    drop(retry);
    assert!(slot.close_requested());
    let SpawnAdmission::Admitted {
        task_id,
        priority,
        cancel_publication,
        spawn_effects,
    } = lab.state.admit_spawn_request(parts)
    else {
        panic!("the dequeued request must reach late publication");
    };
    let region = slot.get().unwrap().region_id;
    let (wakes, observer) =
        cancel_publication.publish_with_spawn_effects(spawn_effects, |cancel_priority| {
            if let Some(priority) = cancel_priority {
                lab.scheduler.lock().schedule_cancel(task_id, priority);
            } else {
                lab.scheduler.lock().schedule(task_id, priority);
            }
        });
    if let Some(observer) = observer {
        observer.dispatch();
    }
    wakes.dispatch();
    lab.run_until_idle();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(slot.get().unwrap().close_outcome().is_some());
    assert!(lab.state.region(region).is_none());
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_retry_cleanup_failure_stops_errors_but_preserves_selected_success() {
    for success in [false, true] {
        let (mut lab, owner, root, gate) = fixture(0x52_E900 + u64::from(success), Time::ZERO);
        let release = Gate::default();
        let body_release = release.clone();
        let region = Arc::new(Mutex::new(None));
        let published = Arc::clone(&region);
        let mut retry = Box::pin(owner.retry_scoped(
            RetryPolicy::immediate(3),
            RetryIf(|_: &&str, _| panic!("cleanup failure must not invoke a retry predicate")),
            move |body, attempt| {
                assert_eq!(attempt, 1);
                let release = body_release.clone();
                *published.lock() = Some(body.region_id());
                async move {
                    release.await;
                    if success {
                        Ok(42)
                    } else {
                        Err("preserve error")
                    }
                }
            },
        ));
        assert!(poll_once(retry.as_mut()).is_pending());
        lab.run_until_idle();
        let region = region.lock().expect("attempt was invoked");
        assert!(
            lab.state
                .register_sync_finalizer(region, || panic!("retry cleanup failed"))
        );
        release.release();
        lab.run_until_idle();
        let report = drive(&mut lab, retry.as_mut());
        assert_eq!(report.attempts.len(), 1);
        if success {
            assert!(matches!(
                report.stop,
                ScopedRetryStop::Succeeded { attempt: 1 }
            ));
            assert!(matches!(
                report.attempts[0].task,
                ScopedRetryTask::Joined(Ok(Ok(42)))
            ));
        } else {
            assert!(matches!(
                report.stop,
                ScopedRetryStop::CleanupFailed { attempt: 1 }
            ));
            assert!(matches!(
                report.attempts[0].task,
                ScopedRetryTask::Joined(Ok(Err("preserve error")))
            ));
        }
        let close = report.attempts[0].close.as_ref().unwrap().as_ref().unwrap();
        assert!(
            matches!(&close.cleanup_outcome, Some(Outcome::Panicked(payload)) if payload.message() == "retry cleanup failed")
        );
        assert!(close.descendant_panic.is_some());
        assert!(lab.state.region(region).is_none());
        drop(retry);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_retry_catches_factory_and_future_panics_as_task_failures() {
    for synchronous in [false, true] {
        let (mut lab, owner, root, gate) = fixture(0x52_EA00 + u64::from(synchronous), Time::ZERO);
        let mut retry = Box::pin(owner.retry_scoped(
            RetryPolicy::immediate(3),
            RetryIf(|_: &(), _| panic!("task failure cannot be retried")),
            move |_, attempt| {
                assert_eq!(attempt, 1);
                assert!(!synchronous, "retry factory panicked");
                async {
                    panic!("retry future panicked");
                    #[allow(unreachable_code)]
                    Ok::<(), ()>(())
                }
            },
        ));
        let report = drive(&mut lab, retry.as_mut());
        assert!(matches!(
            report.stop,
            ScopedRetryStop::TaskFailed { attempt: 1 }
        ));
        assert_eq!(report.attempts.len(), 1);
        let expected = if synchronous {
            "retry factory panicked"
        } else {
            "retry future panicked"
        };
        assert!(matches!(&report.attempts[0].task,
            ScopedRetryTask::Joined(Err(JoinError::Panicked(payload))) if payload.message() == expected));
        drop(retry);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_retry_preserves_typed_caps_and_send_without_sync_or_unpin_results() {
    type RetryCaps = cap::CapSet<true, true, true, false, false>;
    #[derive(Debug)]
    struct Value(Cell<u32>, std::marker::PhantomPinned);
    fn assert_send<T: Send>(_: &T) {}

    let (mut lab, owner, root, gate) = fixture(0x52_EB00, Time::ZERO);
    let restricted: Cx<RetryCaps> = owner.restrict();
    let generation = Cell::new(0);
    let mut retry = Box::pin(restricted.retry_scoped(
        RetryPolicy::immediate(2),
        AlwaysRetry,
        move |body: Cx<RetryCaps>, attempt| {
            generation.set(generation.get() + 1);
            assert_eq!(generation.get(), attempt);
            assert!(!body.capabilities().io);
            assert!(!body.capabilities().remote);
            async move {
                if attempt == 1 {
                    Err(Cell::new(7))
                } else {
                    Ok(Value(Cell::new(42), std::marker::PhantomPinned))
                }
            }
        },
    ));
    assert_send(&retry);
    let report = drive(&mut lab, retry.as_mut());
    assert!(matches!(
        report.stop,
        ScopedRetryStop::Succeeded { attempt: 2 }
    ));
    assert!(matches!(&report.attempts[0].task,
        ScopedRetryTask::Joined(Ok(Err(error))) if error.get() == 7));
    assert!(matches!(&report.attempts[1].task,
        ScopedRetryTask::Joined(Ok(Ok(Value(value, _)))) if value.get() == 42));
    drop(retry);
    finish_fixture(&mut lab, root, &gate);
}
