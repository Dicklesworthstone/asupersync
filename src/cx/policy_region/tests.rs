//! br-asupersync-mfqmcs: typed policy ownership, bounded retention and Lab drain.

use super::*;
use crate::error::{Error, ErrorKind};
use crate::lab::{LabConfig, LabRuntime};
use crate::types::policy::{CollectAll, FailFast};
use crate::types::Budget;
use std::cell::Cell;
use std::marker::PhantomPinned;
use std::sync::atomic::AtomicUsize;
use std::task::Waker;

#[derive(Debug)]
struct CellValue {
    value: Cell<u8>,
    _pinned: PhantomPinned,
}

impl CellValue {
    fn new(value: u8) -> Self {
        Self { value: Cell::new(value), _pinned: PhantomPinned }
    }
}

#[test]
fn terminal_mapping_preserves_non_clone_values_and_each_join_failure() {
    let mapped = member_outcome::<CellValue, CellValue>(Ok(Outcome::Err(CellValue::new(7))));
    match mapped {
        Outcome::Err(error) => assert_eq!(error.value.get(), 7),
        other => panic!("typed error was changed: {other:?}"),
    }
    let reason = CancelReason::user("policy mapping fixture");
    assert!(matches!(
        member_outcome::<(), ()>(Err(JoinError::Cancelled(reason.clone()))),
        Outcome::Cancelled(actual) if actual == reason
    ));
    assert!(matches!(
        member_outcome::<(), ()>(Err(JoinError::Panicked(PanicPayload::new("member panic")))),
        Outcome::Panicked(actual) if actual.message() == "member panic"
    ));
    assert!(matches!(
        member_outcome::<(), ()>(Err(JoinError::PolledAfterCompletion)),
        Outcome::Panicked(actual) if actual.message() == "policy region member polled after completion"
    ));
}

#[test]
fn caught_payload_destructor_cannot_escape_terminal_normalization() {
    struct HostilePayload;
    impl Drop for HostilePayload {
        fn drop(&mut self) {
            panic!("payload destructor");
        }
    }
    let normalized = contained_panic_payload(Box::new(HostilePayload));
    assert_eq!(normalized.message(), "unknown panic");
    let normalized = contained_panic_payload(Box::new(String::from("original panic")));
    assert_eq!(normalized.message(), "original panic");
}

#[derive(Clone)]
struct RecordedPolicy {
    fail_fast: bool,
    observed: Arc<Mutex<Vec<(TaskId, u8)>>>,
}

impl Policy for RecordedPolicy {
    type Error = Error;

    fn on_child_outcome<T>(&self, child: TaskId, outcome: &Outcome<T, Error>) -> PolicyAction {
        self.observed.lock().push((child, outcome.severity().as_u8()));
        if self.fail_fast {
            FailFast.on_child_outcome(child, outcome)
        } else {
            CollectAll.on_child_outcome(child, outcome)
        }
    }

    fn aggregate_outcomes<T>(&self, outcomes: &[Outcome<T, Error>]) -> AggregateDecision<Error> {
        CollectAll.aggregate_outcomes(outcomes)
    }
}

struct ParkedMember {
    parked: AtomicBool,
    released: AtomicBool,
    cleaned: AtomicBool,
    waker: Mutex<Option<Waker>>,
    context: Mutex<Option<Cx>>,
}

impl ParkedMember {
    fn new() -> Self {
        Self {
            parked: AtomicBool::new(false),
            released: AtomicBool::new(false),
            cleaned: AtomicBool::new(false),
            waker: Mutex::new(None),
            context: Mutex::new(None),
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        let waker = self.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
    for _ in 0..10_000 {
        if predicate() {
            return;
        }
        crate::runtime::yield_now().await;
    }
    panic!("Lab policy fixture did not reach the required state");
}

#[test]
fn lab_policy_failure_cancels_parked_sibling_before_owner_join_but_collect_all_does_not() {
    for seed in [0x50_11_C0_u64, 0x50_11_C1, 0x50_11_C2] {
        for fail_fast in [false, true] {
            let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let result = Arc::new(Mutex::new(None));
            let slot = Arc::clone(&result);
            let observed = Arc::new(Mutex::new(Vec::new()));
            let callbacks = Arc::clone(&observed);
            let gate = Arc::new(ParkedMember::new());
            let gate_in_owner = Arc::clone(&gate);
            let (owner, _join) = lab.state.create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("Lab owner context");
                let mut region = cx.open_policy_region::<u8, _>(
                    ChildRegionSpec::inherit(),
                    RecordedPolicy { fail_fast, observed: callbacks },
                    NonZeroUsize::new(2).unwrap(),
                ).await.expect("policy region opens");
                let member_gate = Arc::clone(&gate_in_owner);
                assert_eq!(region.spawn(move |child| async move {
                    *member_gate.context.lock() = Some(child.clone());
                    let mut cancelled = pin!(child.cancelled());
                    let was_cancelled = poll_fn(|task| {
                        if cancelled.as_mut().poll(task).is_ready() {
                            return Poll::Ready(true);
                        }
                        *member_gate.waker.lock() = Some(task.waker().clone());
                        if member_gate.released.load(Ordering::Acquire) {
                            return Poll::Ready(false);
                        }
                        // This witness is published only after the cancellation
                        // registration exists and this poll is returning Pending.
                        member_gate.parked.store(true, Ordering::Release);
                        Poll::Pending
                    }).await;
                    let outcome = if was_cancelled {
                        assert!(child.checkpoint().is_err());
                        let reason = child.cancel_reason().expect("attributed cancellation");
                        crate::runtime::yield_now().await;
                        Outcome::Cancelled(reason)
                    } else {
                        Outcome::Ok(41)
                    };
                    member_gate.cleaned.store(true, Ordering::Release);
                    outcome
                }).unwrap(), 0);
                wait_for(|| gate_in_owner.parked.load(Ordering::Acquire)).await;
                assert_eq!(region.spawn(|_| async {
                    Outcome::Err(Error::new(ErrorKind::InvalidInput).with_message("later member"))
                }).unwrap(), 1);
                // Deliberately do other work instead of joining: a later
                // failure must activate the policy at the member's boundary.
                wait_for(|| !observed.lock().is_empty()).await;
                if fail_fast {
                    wait_for(|| gate_in_owner.cleaned.load(Ordering::Acquire)).await;
                } else {
                    assert!(!gate_in_owner.context.lock().as_ref().unwrap().is_cancel_requested());
                    assert!(!gate_in_owner.cleaned.load(Ordering::Acquire));
                    gate_in_owner.release();
                }
                *slot.lock() = Some(region.join().await);
            }).expect("create Lab owner");
            lab.scheduler.lock().schedule(owner, 0);
            let run = lab.run_with_auto_advance();
            let report = result.lock().take()
                .unwrap_or_else(|| panic!("seed={seed:#x} fail_fast={fail_fast}: {run:?}"));
            assert_eq!(report.outcomes.len(), 2);
            assert!(matches!(&report.outcomes[1], Outcome::Err(error)
                if error.message() == Some("later member")));
            if fail_fast {
                assert!(matches!(&report.outcomes[0], Outcome::Cancelled(reason)
                    if reason.kind == CancelReason::sibling_failed().kind));
                assert!(matches!(&report.first_action, Some((_, PolicyAction::CancelSiblings(_)))));
            } else {
                assert!(matches!(&report.outcomes[0], Outcome::Ok(41)));
                assert!(report.first_action.is_none());
                assert!(matches!(&report.decision, Ok(AggregateDecision::FirstError(error))
                    if error.message() == Some("later member")));
            }
            assert!(gate.cleaned.load(Ordering::Acquire));
            assert!(report.close.is_ok());
            assert!(!report.cancellation_dispatch_failed);
            assert!(!report.escalated);
            assert_eq!(lab.state.live_task_count(), 0);
            assert_eq!(lab.state.pending_obligation_count(), 0);
            assert!(lab.state.region(report.region).is_none(), "closed region reclaimed");
        }
    }
}

#[derive(Clone)]
struct CellPolicy {
    calls: Arc<AtomicUsize>,
}

impl Policy for CellPolicy {
    type Error = CellValue;

    fn on_child_outcome<T>(&self, _child: TaskId, _outcome: &Outcome<T, CellValue>) -> PolicyAction {
        self.calls.fetch_add(1, Ordering::Relaxed);
        PolicyAction::Continue
    }

    fn aggregate_outcomes<T>(&self, outcomes: &[Outcome<T, CellValue>]) -> AggregateDecision<CellValue> {
        match outcomes.iter().enumerate().max_by_key(|(_, outcome)| outcome.severity()) {
            Some((index, Outcome::Panicked(payload))) => AggregateDecision::Panicked {
                payload: payload.clone(),
                first_panic_index: index,
            },
            Some((_, Outcome::Cancelled(reason))) => AggregateDecision::Cancelled(reason.clone()),
            Some((_, Outcome::Err(error))) => AggregateDecision::FirstError(CellValue::new(error.value.get())),
            Some((_, Outcome::Ok(_))) | None => AggregateDecision::AllOk,
        }
    }
}

fn require_send<F: Future + Send>(future: F) -> F {
    future
}

#[test]
fn lab_retained_cap_and_send_future_allow_non_sync_non_clone_non_unpin_results() {
    let mut lab = LabRuntime::new(LabConfig::new(0x50_11_D0).max_steps(100_000));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let slot = Arc::new(Mutex::new(None));
    let result = Arc::clone(&slot);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let refused_factory_ran = Arc::new(AtomicBool::new(false));
    let refused = Arc::clone(&refused_factory_ran);
    let (owner, _join) = lab.state.create_task(root, Budget::INFINITE, async move {
        let cx = Cx::current().expect("Lab owner context");
        let mut region = cx.open_policy_region::<CellValue, _>(
            ChildRegionSpec::inherit(),
            CellPolicy { calls: Arc::clone(&observed) },
            NonZeroUsize::new(2).unwrap(),
        ).await.unwrap();
        region.spawn(|_| async { Outcome::Ok(CellValue::new(3)) }).unwrap();
        region.spawn(|_| async { Outcome::Err(CellValue::new(7)) }).unwrap();
        wait_for(|| observed.load(Ordering::Relaxed) == 2).await;
        // Completed values still occupy both retained slots.
        assert_eq!(region.len(), 2);
        assert!(matches!(region.spawn(move |_| {
            refused.store(true, Ordering::Release);
            async { Outcome::Ok(CellValue::new(9)) }
        }), Err(PolicyRegionSpawnError::AtCapacity { limit: 2 })));
        *result.lock() = Some(require_send(region.join()).await);
    }).unwrap();
    lab.scheduler.lock().schedule(owner, 0);
    lab.run_until_quiescent();
    let report = slot.lock().take().expect("owner finishes");
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert!(!refused_factory_ran.load(Ordering::Acquire));
    assert!(matches!(&report.outcomes[0], Outcome::Ok(value) if value.value.get() == 3));
    assert!(matches!(&report.outcomes[1], Outcome::Err(error) if error.value.get() == 7));
    assert!(matches!(&report.decision, Ok(AggregateDecision::FirstError(error))
        if error.value.get() == 7));
    assert!(report.close.is_ok());
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
}


#[test]
fn lab_suppressed_value_drop_panic_is_one_typed_policy_completion() {
    struct SuppressedValue(Arc<AtomicUsize>);
    impl Drop for SuppressedValue {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("suppressed value destructor");
        }
    }

    let mut lab = LabRuntime::new(LabConfig::new(0x50_11_E0).max_steps(100_000));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let result = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&result);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let callbacks = Arc::clone(&observed);
    let gate = Arc::new(ParkedMember::new());
    let member_gate = Arc::clone(&gate);
    let drops = Arc::new(AtomicUsize::new(0));
    let value_drops = Arc::clone(&drops);
    let panicking_id = Arc::new(Mutex::new(None));
    let identity = Arc::clone(&panicking_id);
    let (owner, _join) = lab.state.create_task(root, Budget::INFINITE, async move {
        let cx = Cx::current().expect("Lab owner context");
        let mut region = cx.open_policy_region::<SuppressedValue, _>(
            ChildRegionSpec::inherit(),
            RecordedPolicy { fail_fast: true, observed: callbacks },
            NonZeroUsize::new(2).unwrap(),
        ).await.unwrap();
        let sibling_gate = Arc::clone(&member_gate);
        region.spawn(move |child| async move {
            let mut cancelled = pin!(child.cancelled());
            poll_fn(|task| match cancelled.as_mut().poll(task) {
                Poll::Ready(()) => Poll::Ready(()),
                Poll::Pending => {
                    sibling_gate.parked.store(true, Ordering::Release);
                    Poll::Pending
                }
            }).await;
            assert!(child.checkpoint().is_err());
            let reason = child.cancel_reason().expect("sibling cancellation");
            crate::runtime::yield_now().await;
            sibling_gate.cleaned.store(true, Ordering::Release);
            Outcome::Cancelled(reason)
        }).unwrap();
        wait_for(|| member_gate.parked.load(Ordering::Acquire)).await;
        region.spawn(move |child| async move {
            *identity.lock() = Some(child.task_id());
            // The terminal poll returns a value without acknowledging this
            // request. Ordinary spawn classification must suppress that value;
            // this adapter catches its destructor panic before typed observation.
            child.cancel_with(crate::types::CancelKind::User, Some("terminal fixture cancel"));
            Outcome::Ok(SuppressedValue(value_drops))
        }).unwrap();
        *slot.lock() = Some(region.join().await);
    }).unwrap();
    lab.scheduler.lock().schedule(owner, 0);
    lab.run_until_quiescent();
    let report = result.lock().take().expect("owner finishes");
    assert!(matches!(&report.outcomes[0], Outcome::Cancelled(reason)
        if reason.kind == CancelReason::sibling_failed().kind));
    assert!(matches!(&report.outcomes[1], Outcome::Panicked(payload)
        if payload.message() == "suppressed value destructor"));
    assert!(matches!(&report.decision, Ok(AggregateDecision::Panicked {
        payload, first_panic_index: 1,
    }) if payload.message() == "suppressed value destructor"));
    let panicking = panicking_id.lock().expect("admitted panic member");
    let callbacks = observed.lock();
    assert_eq!(callbacks.len(), 2, "one callback for each admitted member");
    assert_eq!(
        callbacks.iter().filter(|(task, severity)| *task == panicking && *severity == 3).count(),
        1,
        "classification panic is observed once with the admitted identity",
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(gate.cleaned.load(Ordering::Acquire));
    assert!(report.close.is_ok());
    assert!(!report.cancellation_dispatch_failed);
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
}
