use super::*;
use crate::cx::RaceFactory;
use crate::cx::io_gate::require_ambient_io;
use crate::lab::{LabConfig, LabRuntime};
use crate::record::region::{RegionLimits, RegionState};
use crate::runtime::spawn_mailbox::SpawnRequestParts;
use crate::runtime::state::SpawnAdmission;
use crate::types::{Budget, TaskId};
use parking_lot::Mutex;
use std::cell::Cell;
use std::marker::PhantomPinned;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;

#[derive(Clone, Default)]
struct Gate(Arc<GateState>);

#[derive(Default)]
struct GateState {
    open: AtomicBool,
    polls: AtomicUsize,
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
        self.0.polls.fetch_add(1, Ordering::SeqCst);
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

fn limit(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}

fn poll_once<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn fixture(seed: u64) -> (LabRuntime, Cx, RegionId, Gate) {
    let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
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

fn finish(lab: &mut LabRuntime, root: RegionId, gate: Gate) {
    gate.release();
    lab.run_until_idle();
    lab.state.close_region_command(
        root,
        &CancelReason::user("bounded scoped join test complete"),
    );
    lab.run_until_idle();
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.state.region(root).is_none());
}

fn complete<T, F>(lab: &mut LabRuntime, mut future: Pin<&mut F>) -> ScopedJoinBoundedReport<T>
where
    F: Future<Output = Result<ScopedJoinBoundedReport<T>, ScopedJoinError>> + ?Sized,
{
    for _ in 0..2_048 {
        match poll_once(future.as_mut()) {
            Poll::Ready(Ok(report)) => return report,
            Poll::Ready(Err(error)) => panic!("unexpected bounded join refusal: {error}"),
            Poll::Pending => {
                lab.run_until_idle();
            }
        }
    }
    panic!("bounded join did not finish within the lab turn budget");
}

fn assert_closed<T>(lab: &LabRuntime, attempt: &ScopedJoinAttempt<T>) {
    let region = attempt.region_id.expect("private region admitted");
    assert!(
        matches!(&attempt.close, Some(Ok(_))),
        "actual close evidence is required"
    );
    assert!(lab.state.region(region).is_none());
}

fn admit(lab: &mut LabRuntime, parts: SpawnRequestParts) {
    let SpawnAdmission::Admitted {
        task_id,
        priority,
        cancel_publication,
        spawn_effects,
    } = lab.state.admit_spawn_request(parts)
    else {
        panic!("expected authoritative admission");
    };
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
}

struct Counted<I> {
    inner: I,
    next_calls: Arc<AtomicUsize>,
}

impl<I: Iterator> Iterator for Counted<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.next()
    }
}

#[derive(Debug)]
struct MoveOnly {
    index: usize,
    value: Cell<usize>,
    _pinned: PhantomPinned,
}

#[test]
fn bounded_join_collects_more_than_64_inputs_without_losing_order_errors_or_send() {
    let (mut lab, owner, root, gate) = fixture(0x5C_B001);
    let next_calls = Arc::new(AtomicUsize::new(0));
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&factory_calls);
    let factories = Counted {
        inner: (0..150).map(move |index| {
            let calls = Arc::clone(&calls);
            move |body: Cx| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_ne!(index, 37, "bounded join factory construction panic");
                async move {
                    assert!(
                        !body.is_cancel_requested(),
                        "other input failures are all-settled"
                    );
                    assert_ne!(index, 103, "bounded join future polling panic");
                    if index == 19 {
                        Err("typed application failure")
                    } else {
                        Ok(MoveOnly {
                            index,
                            value: Cell::new(index * 2),
                            _pinned: PhantomPinned,
                        })
                    }
                }
            }
        }),
        next_calls: Arc::clone(&next_calls),
    };
    // Cell and PhantomPinned make this result !Sync and !Unpin. The owned
    // coordinator must still be Send without borrowing those retained values.
    let mut group: Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ScopedJoinBoundedReport<Result<MoveOnly, &'static str>>,
                        ScopedJoinError,
                    >,
                > + Send,
        >,
    > = Box::pin(owner.join_all_scoped_bounded(limit(7), factories));
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedJoinBoundedStop::Completed));
    assert!(report.input_exhausted && report.input_panic.is_none());
    assert!(report.owner_cancellation.is_none());
    assert_eq!(report.max_active, 7);
    assert_eq!(report.attempts.len(), 150);
    assert_eq!(next_calls.load(Ordering::SeqCst), 151);
    assert_eq!(factory_calls.load(Ordering::SeqCst), 150);
    for (index, attempt) in report.attempts.iter().enumerate() {
        assert_eq!(attempt.index, index);
        match (index, &attempt.task) {
            (19, ScopedJoinTask::Joined(Ok(Err("typed application failure")))) => {}
            (37, ScopedJoinTask::Joined(Err(JoinError::Panicked(payload)))) => {
                assert!(payload.message().contains("factory construction panic"));
            }
            (103, ScopedJoinTask::Joined(Err(JoinError::Panicked(payload)))) => {
                assert!(payload.message().contains("future polling panic"));
            }
            (_, ScopedJoinTask::Joined(Ok(Ok(value)))) => {
                assert_eq!(value.index, index);
                assert_eq!(value.value.get(), index * 2);
            }
            _ => panic!(
                "unexpected all-settled receipt at {index}: {:?}",
                attempt.task
            ),
        }
        assert_closed(&lab, attempt);
    }
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    drop(group);
    finish(&mut lab, root, gate);
}

struct PreflightSource {
    entered: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    panic_on_conversion: bool,
    panic_on_drop: bool,
}

impl IntoIterator for PreflightSource {
    type Item = RaceFactory<usize>;
    type IntoIter = std::iter::Empty<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.entered.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.panic_on_conversion,
            "bounded join source conversion panic"
        );
        std::iter::empty()
    }
}

impl Drop for PreflightSource {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic_on_drop, "bounded join unused source drop panic");
    }
}

#[test]
fn bounded_join_preflight_and_precancel_do_not_enter_source_and_preserve_drop_panic() {
    for cancelled in [false, true] {
        let owner = Cx::for_testing();
        let reason = CancelReason::user("bounded join already stopped");
        if cancelled {
            owner.set_cancel_reason(reason.clone());
        }
        let entered = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut group = Box::pin(owner.join_all_scoped_bounded(
            limit(usize::MAX),
            PreflightSource {
                entered: Arc::clone(&entered),
                dropped: Arc::clone(&dropped),
                panic_on_conversion: false,
                panic_on_drop: cancelled,
            },
        ));
        let Poll::Ready(result) = poll_once(group.as_mut()) else {
            panic!("preflight is immediate")
        };
        if cancelled {
            let report = result.unwrap();
            assert!(
                matches!(&report.stop, ScopedJoinBoundedStop::Cancelled(actual) if *actual == reason)
            );
            assert!(report.attempts.is_empty() && !report.input_exhausted);
            assert_eq!(report.max_active, 0);
            assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
            assert!(
                report
                    .input_panic
                    .unwrap()
                    .message()
                    .contains("unused source drop panic")
            );
            assert!(!owner.inner.read().cancel_acknowledged);
        } else {
            assert!(matches!(
                result,
                Err(ScopedJoinError::Spawn(SpawnError::RuntimeUnavailable))
            ));
        }
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
    let (mut lab, owner, root, gate) = fixture(0x5C_B002);
    for (denied, panic_on_conversion) in [(true, false), (false, false), (false, true)] {
        let mut principal = owner.clone();
        if denied {
            principal.runtime_mask = cap::CapMask::none();
        }
        let entered = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut group = Box::pin(principal.join_all_scoped_bounded(
            limit(usize::MAX),
            PreflightSource {
                entered: Arc::clone(&entered),
                dropped: Arc::clone(&dropped),
                panic_on_conversion,
                panic_on_drop: false,
            },
        ));
        let Poll::Ready(result) = poll_once(group.as_mut()) else {
            panic!("empty source is immediate")
        };
        if denied {
            assert!(matches!(
                result,
                Err(ScopedJoinError::Spawn(SpawnError::RuntimeUnavailable))
            ));
            assert_eq!(entered.load(Ordering::SeqCst), 0);
        } else {
            let report = result.unwrap();
            assert!(report.attempts.is_empty());
            assert_eq!(report.max_active, 0);
            if panic_on_conversion {
                assert!(matches!(
                    report.stop,
                    ScopedJoinBoundedStop::InputPanicked { next_index: 0 }
                ));
                assert!(!report.input_exhausted);
                assert!(
                    report
                        .input_panic
                        .unwrap()
                        .message()
                        .contains("source conversion panic")
                );
            } else {
                assert!(matches!(report.stop, ScopedJoinBoundedStop::Completed));
                assert!(report.input_exhausted && report.input_panic.is_none());
            }
            assert_eq!(entered.load(Ordering::SeqCst), 1);
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    finish(&mut lab, root, gate);
}

#[test]
fn bounded_join_strict_admission_refusal_stops_pulling_the_lazy_tail() {
    let (mut lab, owner, root, gate) = fixture(0x5C_B003);
    assert!(lab.state.set_region_limits(
        root,
        RegionLimits {
            max_tasks: Some(10),
            ..RegionLimits::default()
        }
    ));
    let next_calls = Arc::new(AtomicUsize::new(0));
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&factory_calls);
    let source = Counted {
        inner: (0..1_000).map(move |index| {
            let counted = Arc::clone(&counted);
            move |_: Cx| {
                counted.fetch_add(1, Ordering::SeqCst);
                async move { index }
            }
        }),
        next_calls: Arc::clone(&next_calls),
    };
    let mut group = Box::pin(owner.join_all_scoped_bounded(limit(1), source));
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(
        report.stop,
        ScopedJoinBoundedStop::NotAdmitted { index: 0 }
    ));
    assert_eq!(report.attempts.len(), 1);
    assert!(matches!(
        report.attempts[0].task,
        ScopedJoinTask::NotStarted
    ));
    assert!(report.attempts[0].region_id.is_none() && report.attempts[0].close.is_none());
    assert!(!report.input_exhausted && report.input_panic.is_none());
    assert_eq!(next_calls.load(Ordering::SeqCst), 1);
    assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
    assert_eq!(report.max_active, 1);
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    drop(group);
    finish(&mut lab, root, gate);
}

struct UnusedFactoryDrop {
    owner: TaskId,
    slots: Arc<Mutex<Vec<Arc<BranchRegionSlot>>>>,
    dropped: Arc<AtomicUsize>,
}

impl Drop for UnusedFactoryDrop {
    fn drop(&mut self) {
        assert_eq!(Cx::current().unwrap().task_id(), self.owner);
        assert!(
            self.slots.lock().iter().all(|slot| slot.close_requested()),
            "unused input destruction must follow the complete subtree cancellation fanout"
        );
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

struct GuardedTail<I> {
    inner: I,
    _retire: UnusedFactoryDrop,
}

impl<I: Iterator> Iterator for GuardedTail<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

#[test]
fn bounded_join_abandonment_closes_pending_slots_before_source_drop_and_late_publication() {
    let (mut lab, owner, root, gate) = fixture(0x5C_B007);
    let slots = Arc::new(Mutex::new(Vec::new()));
    let dropped = Arc::new(AtomicUsize::new(0));
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&factory_calls);
    let source = GuardedTail {
        inner: (0..100).map(move |index| {
            let calls = Arc::clone(&calls);
            move |_: Cx| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move { index }
            }
        }),
        _retire: UnusedFactoryDrop {
            owner: owner.task_id(),
            slots: Arc::clone(&slots),
            dropped: Arc::clone(&dropped),
        },
    };
    let mut group = Box::pin(owner.join_all_scoped_bounded(limit(2), source));
    assert!(poll_once(group.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
    let queued: Vec<_> = (0..2)
        .map(|_| gateway.mailbox().dequeue().unwrap().into_parts())
        .collect();
    slots.lock().extend(queued.iter().map(|parts| {
        Arc::clone(
            parts
                .admitted_slot
                .as_ref()
                .unwrap()
                .branch_region()
                .unwrap(),
        )
    }));
    let foreign = foreign_context();
    {
        let _foreign = Cx::set_current(Some(foreign.clone()));
        drop(group);
        assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
    }
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(
        slots
            .lock()
            .iter()
            .all(|slot| slot.close_requested() && slot.get().is_none())
    );
    for parts in queued {
        admit(&mut lab, parts);
    }
    lab.run_until_idle();
    for slot in slots.lock().iter() {
        let region = slot.get().expect("late private region publication");
        assert!(region.close_notify().lock().closed);
        assert!(region.close_outcome().is_some());
        assert!(lab.state.region(region.region_id).is_none());
    }
    assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    finish(&mut lab, root, gate);
}

struct CancellingSource {
    owner: Cx,
    reason: CancelReason,
    next_calls: Arc<AtomicUsize>,
    factory_calls: Arc<AtomicUsize>,
    unused_drops: Arc<AtomicUsize>,
    source_drops: Arc<AtomicUsize>,
    slots: Arc<Mutex<Vec<Arc<BranchRegionSlot>>>>,
}

impl Iterator for CancellingSource {
    type Item = RaceFactory<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next_calls.fetch_add(1, Ordering::SeqCst);
        assert!(index < 3, "cancelled source tail must not be pulled");
        let calls = Arc::clone(&self.factory_calls);
        let held = if index == 2 {
            self.owner.set_cancel_reason(self.reason.clone());
            Some(UnusedFactoryDrop {
                owner: self.owner.task_id(),
                slots: Arc::clone(&self.slots),
                dropped: Arc::clone(&self.unused_drops),
            })
        } else {
            None
        };
        Some(Box::new(move |body: Cx| {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if index == 0 {
                    body.cancelled().await;
                    assert!(body.checkpoint().is_err());
                }
                drop(held);
                index
            })
        }))
    }
}

impl Drop for CancellingSource {
    fn drop(&mut self) {
        assert_eq!(Cx::current().unwrap().task_id(), self.owner.task_id());
        assert!(self.slots.lock().iter().all(|slot| slot.close_requested()));
        self.source_drops.fetch_add(1, Ordering::SeqCst);
        panic!("bounded join source retirement after cancellation");
    }
}

#[test]
fn bounded_join_next_cancellation_keeps_uninvoked_input_and_retires_it_after_fanout() {
    let (mut lab, owner, root, gate) = fixture(0x5C_B004);
    let next_calls = Arc::new(AtomicUsize::new(0));
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let unused_drops = Arc::new(AtomicUsize::new(0));
    let source_drops = Arc::new(AtomicUsize::new(0));
    let slots = Arc::new(Mutex::new(Vec::new()));
    let reason =
        CancelReason::user("source cancelled explicit owner").with_cause(CancelReason::shutdown());
    let source = CancellingSource {
        owner: owner.clone(),
        reason: reason.clone(),
        next_calls: Arc::clone(&next_calls),
        factory_calls: Arc::clone(&factory_calls),
        unused_drops: Arc::clone(&unused_drops),
        source_drops: Arc::clone(&source_drops),
        slots: Arc::clone(&slots),
    };
    let mut group = Box::pin(owner.join_all_scoped_bounded(limit(2), source));
    assert!(poll_once(group.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
    let queued: Vec<_> = (0..2)
        .map(|_| gateway.mailbox().dequeue().unwrap().into_parts())
        .collect();
    slots.lock().extend(queued.iter().map(|parts| {
        Arc::clone(
            parts
                .admitted_slot
                .as_ref()
                .unwrap()
                .branch_region()
                .unwrap(),
        )
    }));
    for parts in queued {
        admit(&mut lab, parts);
    }
    lab.run_until_idle();
    assert_eq!(factory_calls.load(Ordering::SeqCst), 2);
    assert_eq!(next_calls.load(Ordering::SeqCst), 2);
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(&report.stop, ScopedJoinBoundedStop::Cancelled(actual) if *actual == reason));
    assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
    assert!(!report.input_exhausted);
    assert!(
        report
            .input_panic
            .as_ref()
            .unwrap()
            .message()
            .contains("retirement after cancellation")
    );
    assert_eq!(report.attempts.len(), 3);
    for index in 0..2 {
        assert!(
            matches!(&report.attempts[index].task, ScopedJoinTask::Joined(Ok(value)) if *value == index)
        );
        assert_closed(&lab, &report.attempts[index]);
    }
    assert!(matches!(
        report.attempts[2].task,
        ScopedJoinTask::NotStarted
    ));
    assert!(report.attempts[2].region_id.is_none() && report.attempts[2].close.is_none());
    assert_eq!(next_calls.load(Ordering::SeqCst), 3);
    assert_eq!(factory_calls.load(Ordering::SeqCst), 2);
    assert_eq!(unused_drops.load(Ordering::SeqCst), 1);
    assert_eq!(source_drops.load(Ordering::SeqCst), 1);
    assert_eq!(report.max_active, 2);
    assert!(!owner.inner.read().cancel_acknowledged);
    drop(group);
    finish(&mut lab, root, gate);
}

#[derive(Default)]
struct Scheduled {
    queued: AtomicBool,
    wakes: AtomicUsize,
}

impl Wake for Scheduled {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
        self.queued.store(true, Ordering::SeqCst);
    }
}

fn poll_scheduled<F: Future + ?Sized>(
    future: Pin<&mut F>,
    scheduled: &Arc<Scheduled>,
) -> Poll<F::Output> {
    assert!(
        scheduled.queued.swap(false, Ordering::SeqCst),
        "an actual wake must justify this poll"
    );
    future.poll(&mut Context::from_waker(&Waker::from(Arc::clone(
        scheduled,
    ))))
}

fn park_scheduled<F: Future + ?Sized>(
    lab: &mut LabRuntime,
    mut future: Pin<&mut F>,
    scheduled: &Arc<Scheduled>,
) {
    for _ in 0..2_048 {
        if !scheduled.queued.load(Ordering::SeqCst) {
            return;
        }
        assert!(poll_scheduled(future.as_mut(), scheduled).is_pending());
        lab.run_until_idle();
    }
    panic!("parked join kept self-waking without progress");
}

#[test]
fn bounded_join_keeps_an_already_scanned_close_wake_across_more_than_64_slots() {
    const TOTAL: usize = 130;
    let (mut lab, owner, root, gate) = fixture(0x5C_B005);
    let body_gates: Vec<_> = (0..TOTAL).map(|_| Gate::default()).collect();
    let finalizer_gates: Vec<_> = (0..TOTAL).map(|_| Gate::default()).collect();
    let regions = Arc::new(Mutex::new(vec![None; TOTAL]));
    let ids = Arc::clone(&regions);
    let releases = body_gates.clone();
    let next_calls = Arc::new(AtomicUsize::new(0));
    let source = Counted {
        inner: (0..TOTAL).map(move |index| {
            let release = releases[index].clone();
            let ids = Arc::clone(&ids);
            move |body: Cx| async move {
                ids.lock()[index] = Some(body.region_id());
                release.await;
                index
            }
        }),
        next_calls: Arc::clone(&next_calls),
    };
    let mut group = Box::pin(owner.join_all_scoped_bounded(limit(TOTAL + 1), source));
    let scheduled = Arc::new(Scheduled::default());
    scheduled.queued.store(true, Ordering::SeqCst);
    park_scheduled(&mut lab, group.as_mut(), &scheduled);
    assert_eq!(next_calls.load(Ordering::SeqCst), TOTAL + 1);
    let regions: Vec<_> = regions
        .lock()
        .iter()
        .map(|region| region.expect("body actually parked"))
        .collect();
    for (region, release) in regions.iter().zip(&finalizer_gates) {
        assert!(lab.state.register_async_finalizer(*region, release.clone()));
    }
    for release in &body_gates {
        release.release();
    }
    lab.run_until_idle();
    park_scheduled(&mut lab, group.as_mut(), &scheduled);
    assert!(
        finalizer_gates
            .iter()
            .all(|release| release.0.polls.load(Ordering::SeqCst) > 0),
        "every body has joined and every real region close is parked in cleanup"
    );
    assert!(
        regions
            .iter()
            .all(|region| lab.state.region(*region).is_some())
    );
    assert!(
        !scheduled.queued.load(Ordering::SeqCst),
        "idle close watches must not spin"
    );

    // All high-index closes become ready first. One quantum consumes 1..=64
    // and leaves a self-wake queued while its scan cursor is beyond index zero.
    for release in &finalizer_gates[1..] {
        release.release();
    }
    lab.run_until_idle();
    assert!(poll_scheduled(group.as_mut(), &scheduled).is_pending());
    assert!(scheduled.queued.load(Ordering::SeqCst));
    let previous_wakes = scheduled.wakes.load(Ordering::SeqCst);
    assert!(lab.state.region(regions[0]).is_some());
    finalizer_gates[0].release();
    lab.run_until_idle();
    assert!(
        scheduled.wakes.load(Ordering::SeqCst) > previous_wakes,
        "the behind-cursor close wake was coalesced with an already queued poll"
    );
    assert!(
        regions
            .iter()
            .all(|region| lab.state.region(*region).is_none())
    );

    // No runtime work or external stimulus follows this point. Poll only when
    // the collector itself has retained a wake; a lost close wake parks forever.
    let mut report = None;
    for _ in 0..8 {
        match poll_scheduled(group.as_mut(), &scheduled) {
            Poll::Ready(result) => {
                report = Some(result.unwrap());
                break;
            }
            Poll::Pending => {}
        }
    }
    let report = report.expect("all closed regions must retire without an unrelated wake");
    assert!(matches!(report.stop, ScopedJoinBoundedStop::Completed));
    assert_eq!(report.attempts.len(), TOTAL);
    assert_eq!(report.max_active, TOTAL);
    for (index, attempt) in report.attempts.iter().enumerate() {
        assert!(matches!(&attempt.task, ScopedJoinTask::Joined(Ok(value)) if *value == index));
        assert_closed(&lab, attempt);
    }
    drop(group);
    finish(&mut lab, root, gate);
}

struct SourceAuthority<'a> {
    owner: TaskId,
    converted: &'a Cell<usize>,
    next: &'a Cell<usize>,
    dropped: &'a Cell<usize>,
    borrowed: Rc<()>,
    panic_on_drop: bool,
}

impl SourceAuthority<'_> {
    fn assert_owner(&self) {
        assert_eq!(Cx::current().unwrap().task_id(), self.owner);
        assert!(require_ambient_io("bounded join source callback").is_err());
    }
}

impl Drop for SourceAuthority<'_> {
    fn drop(&mut self) {
        self.assert_owner();
        self.dropped.set(self.dropped.get() + 1);
        assert!(
            !self.panic_on_drop,
            "bounded join unpolled source drop panic"
        );
    }
}

struct AuthoritySource<'a>(SourceAuthority<'a>);
struct AuthorityIter<'a>(SourceAuthority<'a>);

impl<'a> IntoIterator for AuthoritySource<'a> {
    type Item = RaceFactory<usize>;
    type IntoIter = AuthorityIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.assert_owner();
        self.0.converted.set(self.0.converted.get() + 1);
        AuthorityIter(SourceAuthority {
            owner: self.0.owner,
            converted: self.0.converted,
            next: self.0.next,
            dropped: self.0.dropped,
            borrowed: Rc::clone(&self.0.borrowed),
            panic_on_drop: false,
        })
    }
}

impl Iterator for AuthorityIter<'_> {
    type Item = RaceFactory<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.assert_owner();
        let index = self.0.next.get();
        self.0.next.set(index + 1);
        (index == 0).then(|| {
            Box::new(|body: Cx| {
                Box::pin(async move {
                    assert_eq!(Cx::current().unwrap().task_id(), body.task_id());
                    assert!(require_ambient_io("bounded join factory authority").is_err());
                    41
                }) as Pin<Box<dyn Future<Output = usize> + Send>>
            }) as RaceFactory<usize>
        })
    }
}

fn foreign_context() -> Cx {
    Cx::new(
        RegionId::new_for_test(901, 2),
        TaskId::new_for_test(902, 3),
        Budget::INFINITE,
    )
}

#[test]
fn bounded_join_borrowed_nonsend_source_uses_explicit_owner_and_restores_foreign_context() {
    let (mut lab, mut owner, root, gate) = fixture(0x5C_B006);
    owner.runtime_mask =
        <cap::CapSet<true, false, false, false, false> as cap::CapSetRuntimeMask>::MASK;
    let converted = Cell::new(0);
    let next = Cell::new(0);
    let dropped = Cell::new(0);
    let source = AuthoritySource(SourceAuthority {
        owner: owner.task_id(),
        converted: &converted,
        next: &next,
        dropped: &dropped,
        borrowed: Rc::new(()),
        panic_on_drop: false,
    });
    let foreign = foreign_context();
    let _foreign = Cx::set_current(Some(foreign.clone()));
    let mut group = Box::pin(owner.join_all_scoped_bounded(limit(1), source));
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedJoinBoundedStop::Completed));
    assert!(matches!(
        report.attempts[0].task,
        ScopedJoinTask::Joined(Ok(41))
    ));
    assert_closed(&lab, &report.attempts[0]);
    drop(group);
    assert_eq!((converted.get(), next.get(), dropped.get()), (1, 2, 2));
    assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
    assert!(require_ambient_io("foreign after borrowed source").is_ok());
    finish(&mut lab, root, gate);
}

#[test]
fn bounded_join_unpolled_borrowed_source_drop_is_owner_scoped_even_when_it_panics() {
    for panic_on_drop in [false, true] {
        let mut owner = Cx::for_testing();
        owner.runtime_mask = cap::CapMask::none();
        let converted = Cell::new(0);
        let next = Cell::new(0);
        let dropped = Cell::new(0);
        let source = AuthoritySource(SourceAuthority {
            owner: owner.task_id(),
            converted: &converted,
            next: &next,
            dropped: &dropped,
            borrowed: Rc::new(()),
            panic_on_drop,
        });
        let foreign = foreign_context();
        let _foreign = Cx::set_current(Some(foreign.clone()));
        let group = owner.join_all_scoped_bounded(limit(1), source);
        assert_eq!((converted.get(), next.get(), dropped.get()), (0, 0, 0));
        assert_eq!(
            catch_unwind(AssertUnwindSafe(|| drop(group))).is_err(),
            panic_on_drop
        );
        assert_eq!((converted.get(), next.get(), dropped.get()), (0, 0, 1));
        assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
        assert!(require_ambient_io("foreign after unpolled source").is_ok());
    }
}
