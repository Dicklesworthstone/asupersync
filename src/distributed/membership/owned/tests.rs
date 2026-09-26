use super::*;
use crate::distributed::membership::{MembershipEvent, authority::MembershipUpdate};
use crate::lab::{LabConfig, LabRuntime};
use crate::runtime::obligation_mailbox::{ObligationMailbox, apply_obligation_posts};
use crate::time::{TimerDriver, VirtualClock};
use crate::types::Budget;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Wake, Waker};

struct Fixture {
    runtime: LabRuntime, cx: Cx, controller: OwnedMembershipController,
    clock: Arc<VirtualClock>, driver: Arc<TimerDriver<VirtualClock>>,
    mailbox: Arc<ObligationMailbox>,
}
impl Fixture {
    fn new(limit: usize, quota: usize) -> Self {
        let mut runtime = LabRuntime::new(LabConfig::new(83));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime.state.create_task(region, Budget::INFINITE,
            std::future::pending::<()>()).unwrap();
        let record = runtime.state.region(region).unwrap();
        let mut limits = record.limits(); limits.max_obligations = Some(quota); record.set_limits(limits);
        let cx = runtime.state.task(task).unwrap().cx.clone().unwrap();
        let mailbox = Arc::clone(runtime.state.obligation_gateway().unwrap().mailbox());
        let clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(Arc::clone(&clock)));
        let controller = OwnedMembershipController::new(NodeId::new("authority"), 7, AuthKey::from_seed(42),
            vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 0, sequence: 0 }],
            MembershipControllerLimits { max_members: 1, max_lease_ids: limit },
            TimerDriverHandle::new(Arc::clone(&driver))).unwrap();
        controller.apply_authenticated(&NodeId::new("authority"), &update(1, 1, MembershipKind::Alive)).unwrap();
        Self { runtime, cx, controller, clock, driver, mailbox }
    }
    fn grant(&self, ms: u64) -> OwnedMembershipLease {
        self.controller.try_grant(&self.cx, &NodeId::new("worker"), 1, Duration::from_millis(ms)).unwrap()
    }
    fn drain(&mut self) { apply_obligation_posts(&mut self.runtime.state, &self.mailbox, 1024); }
    fn advance(&self, ms: u64) { self.clock.advance(ms * 1_000_000); self.driver.process_timers(); }
}
fn update(incarnation: u64, sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate { event: MembershipEvent { node: NodeId::new("worker"), incarnation, kind }, sequence }
        .authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42)).unwrap()
}
fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(waker))
}
#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn clean_release_commits_a_real_runtime_reservation() {
    let mut f = Fixture::new(8, 8);
    let guard = f.grant(100);
    assert_eq!(f.controller.live_leases(), 1);
    assert_eq!(f.mailbox.stats().posted, 1);
    f.drain(); assert_eq!(f.mailbox.open_tickets(), 1);
    guard.release().unwrap(); f.drain();
    let stats = f.mailbox.stats();
    assert_eq!((stats.reserved, stats.committed, stats.aborted, stats.leaked, stats.refused), (1, 1, 0, 0, 0));
    assert_eq!(f.mailbox.open_tickets(), 0);
}

#[test]
fn drop_aborts_instead_of_reporting_an_obligation_leak() {
    let mut f = Fixture::new(8, 8);
    let guard = f.grant(100); f.drain(); drop(guard); f.drain();
    let stats = f.mailbox.stats();
    assert_eq!((stats.reserved, stats.aborted, stats.leaked, stats.refused), (1, 1, 0, 0));
    assert_eq!(f.controller.live_leases(), 0);
}

#[test]
fn authority_revocation_settles_before_waking_and_cannot_be_committed_again() {
    let mut f = Fixture::new(8, 8); let lease = f.grant(100); f.drain();
    let counter = Arc::new(Counter::default()); let waker = Waker::from(Arc::clone(&counter));
    let mut ended = Box::pin(lease.ended()); assert!(poll(ended.as_mut(), &waker).is_pending());
    assert_eq!(f.controller.apply_authenticated(&NodeId::new("authority"), &update(1, 2, MembershipKind::Dead)).unwrap(),
        MembershipApplied::Applied { revoked: 1 });
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    assert_eq!(poll(ended.as_mut(), &waker), Poll::Ready(OwnedLeaseStatus::Revoked)); drop(ended);
    assert!(matches!(lease.release(), Err(OwnedMembershipError::Ended(OwnedLeaseStatus::Revoked))));
    f.drain(); assert_eq!(f.mailbox.stats().aborted, 1); assert_eq!(f.mailbox.stats().committed, 0);
}

#[test]
fn higher_incarnation_retires_old_tokens_without_touching_fresh_ones() {
    let mut f = Fixture::new(8, 8); let old = f.grant(100); f.drain();
    f.controller.apply_authenticated(&NodeId::new("authority"), &update(2, 2, MembershipKind::Alive)).unwrap();
    assert_eq!(old.status(), OwnedLeaseStatus::Superseded);
    let new = f.controller.try_grant(&f.cx, &NodeId::new("worker"), 2, Duration::from_millis(100)).unwrap();
    assert_ne!(old.ticket(), new.ticket());
    assert!(f.controller.apply_authenticated(&NodeId::new("authority"), &update(1, 3, MembershipKind::Dead)).is_err());
    assert_eq!(new.status(), OwnedLeaseStatus::Active); f.drain();
    new.release().unwrap(); drop(old); f.drain();
    let stats = f.mailbox.stats(); assert_eq!((stats.reserved, stats.aborted, stats.committed, stats.leaked), (2, 1, 1, 0));
}

#[test]
fn suspicion_pauses_new_grants_but_does_not_end_or_forbid_renewal() {
    let mut f = Fixture::new(8, 8); let guard = f.grant(100); f.drain();
    f.controller.apply_authenticated(&NodeId::new("authority"), &update(1, 2, MembershipKind::Suspect)).unwrap();
    assert!(matches!(f.controller.try_grant(&f.cx, &NodeId::new("worker"), 1, Duration::from_secs(1)),
        Err(OwnedMembershipError::Control(MembershipControlError::GrantDenied))));
    guard.renew(Duration::from_millis(200)).unwrap(); assert_eq!(guard.status(), OwnedLeaseStatus::Active);
    assert_eq!(f.mailbox.stats().posted, 1); guard.release().unwrap(); f.drain();
    assert_eq!(f.mailbox.stats().committed, 1);
}

#[test]
fn untracked_context_and_runtime_quota_never_return_untracked_guards() {
    let mut f = Fixture::new(8, 1);
    assert!(matches!(f.controller.try_grant(&Cx::for_testing(), &NodeId::new("worker"), 1, Duration::from_secs(1)),
        Err(OwnedMembershipError::NoRuntime)));
    assert_eq!(f.controller.live_leases(), 0);
    let guard = f.grant(100);
    assert!(matches!(f.controller.try_grant(&f.cx, &NodeId::new("worker"), 1, Duration::from_secs(1)),
        Err(OwnedMembershipError::Admission(ObligationAdmissionError::LimitReached { .. }))));
    assert_eq!(f.controller.live_leases(), 1); f.drain(); drop(guard); f.drain();
    assert_eq!(f.mailbox.stats().reserved, 1); assert_eq!(f.mailbox.stats().leaked, 0);
}

#[test]
fn lifetime_limit_and_closed_owner_refuse_before_runtime_registration() {
    let mut f = Fixture::new(1, 8); let guard = f.grant(100); f.drain(); guard.release().unwrap(); f.drain();
    let posted = f.mailbox.stats().posted;
    assert!(matches!(f.controller.try_grant(&f.cx, &NodeId::new("worker"), 1, Duration::from_secs(1)),
        Err(OwnedMembershipError::Control(MembershipControlError::Capacity))));
    f.controller.close();
    assert!(matches!(f.controller.try_grant(&f.cx, &NodeId::new("worker"), 1, Duration::from_secs(1)),
        Err(OwnedMembershipError::Closed)));
    assert_eq!(f.mailbox.stats().posted, posted);
}

#[test]
fn expiry_driver_rearms_earlier_deadlines_and_retires_all_timers_on_drop() {
    let mut f = Fixture::new(8, 8); let a = f.grant(100); f.drain();
    let counter = Arc::new(Counter::default()); let waker = Waker::from(Arc::clone(&counter));
    let driver_owner = f.controller.clone(); let driver_cx = f.cx.clone();
    let mut run = Box::pin(driver_owner.run(&driver_cx));
    assert!(poll(run.as_mut(), &waker).is_pending());
    let b = f.grant(10); f.drain();
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    assert!(poll(run.as_mut(), &waker).is_pending());
    f.advance(10); assert!(poll(run.as_mut(), &waker).is_pending());
    assert_eq!(b.status(), OwnedLeaseStatus::Expired); assert_eq!(a.status(), OwnedLeaseStatus::Active);
    f.drain(); assert_eq!(f.mailbox.stats().aborted, 1);
    drop(run); assert_eq!(a.status(), OwnedLeaseStatus::Closed);
    assert_eq!(TimerDriverHandle::new(Arc::clone(&f.driver)).pending_count(), 0);
    drop(a); drop(b); f.drain();
    assert_eq!(f.mailbox.stats().aborted, 2); assert_eq!(f.mailbox.stats().leaked, 0);
}

#[test]
fn expiry_driver_ignores_unrelated_ambient_cancel_without_spinning() {
    #[derive(Debug)]
    struct PollBudgetClock(AtomicUsize);
    impl crate::time::TimeSource for PollBudgetClock {
        fn now(&self) -> Time {
            // Fail deterministically if one poll loops without time or owner
            // progress; the old implementation otherwise never returns.
            assert!(self.0.fetch_sub(1, Ordering::SeqCst) > 0, "expiry driver spun within one poll");
            Time::ZERO
        }
    }

    let mut f = Fixture::new(8, 8);
    let clock = Arc::new(PollBudgetClock(AtomicUsize::new(64)));
    let driver = Arc::new(TimerDriver::with_clock(Arc::clone(&clock)));
    let timer = TimerDriverHandle::new(driver);
    Arc::get_mut(&mut f.controller.shared).unwrap().clock = timer.clone();
    let lease = f.grant(100);
    f.drain();
    let owner = f.controller.clone();
    let driver_cx = f.cx.clone();
    let mut run = Box::pin(owner.run(&driver_cx));
    assert!(poll(run.as_mut(), Waker::noop()).is_pending());
    assert_eq!(timer.pending_count(), 1);
    let unrelated = Cx::for_testing();
    unrelated.cancel_with(crate::types::CancelKind::User, Some("unrelated ambient task"));
    clock.0.store(64, Ordering::SeqCst);
    eprintln!("scenario=membership_expiry_unrelated_ambient_cancel state=parked clock_ns=0 deadline_ns=100000000");
    {
        let _ambient = Cx::set_current(Some(unrelated));
        assert!(poll(run.as_mut(), Waker::noop()).is_pending());
        assert!(poll(run.as_mut(), Waker::noop()).is_pending());
    }
    assert_eq!(lease.status(), OwnedLeaseStatus::Active);
    assert_eq!(timer.pending_count(), 1);
    assert!(!driver_cx.is_cancel_requested());

    driver_cx.cancel_with(crate::types::CancelKind::User, Some("actual lease owner"));
    assert!(matches!(poll(run.as_mut(), Waker::noop()), Poll::Ready(Err(OwnedMembershipError::Cancelled))));
    drop(run);
    assert_eq!(lease.status(), OwnedLeaseStatus::Closed);
    assert_eq!(timer.pending_count(), 0);
    drop(lease);
    f.drain();
    assert_eq!(f.mailbox.stats().aborted, 1);
    assert_eq!(f.mailbox.stats().leaked, 0);
    eprintln!("scenario=membership_expiry_unrelated_ambient_cancel poll_count=2 terminal=Cancelled lease=Closed aborted=1 leaked=0 pending_timers=0");
}

#[test]
fn deadline_ties_cannot_renew_or_cleanly_release_expired_leases() {
    let mut f = Fixture::new(8, 8); let a = f.grant(10); let b = f.grant(10); f.drain();
    f.advance(10);
    assert!(matches!(a.renew(Duration::from_secs(1)), Err(OwnedMembershipError::Ended(OwnedLeaseStatus::Expired))));
    assert!(matches!(b.release(), Err(OwnedMembershipError::Ended(OwnedLeaseStatus::Expired))));
    drop(a); f.drain(); assert_eq!(f.mailbox.stats().aborted, 2); assert_eq!(f.mailbox.stats().committed, 0);
}

#[test]
fn duplicate_driver_refusal_does_not_close_the_actual_owner() {
    let mut f = Fixture::new(8, 8); let lease = f.grant(100); f.drain();
    let controller = f.controller.clone(); let cx = f.cx.clone();
    let mut first = Box::pin(controller.run(&cx)); let mut second = Box::pin(controller.run(&cx));
    assert!(poll(first.as_mut(), Waker::noop()).is_pending());
    assert!(matches!(poll(second.as_mut(), Waker::noop()), Poll::Ready(Err(OwnedMembershipError::DriverRunning))));
    drop(second); assert_eq!(lease.status(), OwnedLeaseStatus::Active);
    controller.close(); assert!(matches!(poll(first.as_mut(), Waker::noop()), Poll::Ready(Ok(()))));
    drop(first); drop(lease); f.drain(); assert_eq!(f.mailbox.stats().aborted, 1);
}

struct Reenter { controller: OwnedMembershipController, calls: AtomicUsize, panic: bool }
impl Wake for Reenter {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) {
        assert_eq!(self.controller.live_leases(), 0); // Deadlocks if invoked under the policy lock.
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic, "waker sentinel");
    }
}

#[test]
fn callback_panic_cannot_strand_other_revoked_obligations_or_waiters() {
    let mut f = Fixture::new(8, 8); let a = f.grant(100); let b = f.grant(100); f.drain();
    let first = Arc::new(Reenter { controller: f.controller.clone(), calls: AtomicUsize::new(0), panic: true });
    let second = Arc::new(Reenter { controller: f.controller.clone(), calls: AtomicUsize::new(0), panic: false });
    let mut wa = Box::pin(a.ended()); let mut wb = Box::pin(b.ended());
    assert!(poll(wa.as_mut(), &Waker::from(Arc::clone(&first))).is_pending());
    assert!(poll(wb.as_mut(), &Waker::from(Arc::clone(&second))).is_pending());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.controller.close())).is_err());
    assert_eq!(second.calls.load(Ordering::SeqCst), 1);
    drop(wa); drop(wb); drop(a); drop(b); f.drain();
    assert_eq!(f.mailbox.stats().aborted, 2); assert_eq!(f.mailbox.stats().leaked, 0);
}

#[test]
fn bad_authority_or_mac_cannot_retire_real_leases() {
    let mut f = Fixture::new(8, 8); let lease = f.grant(100); f.drain();
    let mut bytes = update(1, 2, MembershipKind::Dead);
    assert!(f.controller.apply_authenticated(&NodeId::new("observer"), &bytes).is_err());
    let last = bytes.len() - 1; bytes[last] ^= 1;
    assert!(f.controller.apply_authenticated(&NodeId::new("authority"), &bytes).is_err());
    assert_eq!(lease.status(), OwnedLeaseStatus::Active);
    lease.release().unwrap(); f.drain(); assert_eq!(f.mailbox.stats().aborted, 0);
}

#[test]
fn invalidation_publishes_checked_terminal_before_holder_can_finish() {
    let mut f = Fixture::new(8, 8); let lease = f.grant(100); f.drain();
    let mut state = f.controller.shared.state.lock();
    let retired = remove(&mut state, lease.id, OwnedLeaseStatus::Revoked).unwrap();
    assert_eq!(lease.status(), OwnedLeaseStatus::Revoked);
    assert!(retired.settlement_accepted);
    assert_eq!(f.mailbox.stats().posted, 2, "abort must be posted before terminal status is observable");
    assert!(retired.token.is_none());
    drop(state);
    finish(&f.controller.shared, vec![retired]);
    drop(lease); f.drain();
    assert_eq!(f.mailbox.stats().aborted, 1); assert_eq!(f.mailbox.stats().leaked, 0);
}
