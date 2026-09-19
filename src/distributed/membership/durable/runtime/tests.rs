use super::*;
use crate::distributed::membership::authority::{MembershipControllerLimits, MembershipFloor, MembershipUpdate};
use crate::distributed::membership::{MembershipEvent, MembershipKind};
use crate::distributed::membership::durable::MembershipJournalConfig;
use crate::distributed::membership::owned::OwnedLeaseStatus;
use crate::lab::{LabConfig, LabRuntime};
use crate::runtime::obligation_mailbox::apply_obligation_posts;
use crate::security::AuthKey;
use crate::types::Budget;
use std::fs::OpenOptions;
use std::sync::atomic::AtomicU64;
use std::task::{Context, Wake, Waker};

fn config() -> MembershipJournalConfig {
    MembershipJournalConfig {
        authority: NodeId::new("authority"), epoch: 7, statement_key: AuthKey::from_seed(42),
        journal_key: AuthKey::from_seed(99), floors: vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 0, sequence: 0 }],
        controller_limits: MembershipControllerLimits { max_members: 1, max_lease_ids: 8 }, max_journal_bytes: 65536,
    }
}
fn statement(incarnation: u64, sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate { event: MembershipEvent { node: NodeId::new("worker"), incarnation, kind }, sequence }
        .authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42)).unwrap()
}
fn journal() -> (std::path::PathBuf, MembershipJournal) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!("asupersync-membership-runtime-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        match OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
            Ok(file) => return (path, MembershipJournal::create(file, config()).unwrap()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(error) => panic!("owned file: {error}"),
        }
    }
}
fn holder() -> (LabRuntime, Cx) {
    let mut lab = LabRuntime::new(LabConfig::new(712));
    let region = lab.state.create_root_region(Budget::INFINITE);
    let (id, _handle) = lab.state.create_task(region, Budget::INFINITE, std::future::pending::<()>()).unwrap();
    let cx = lab.state.task(id).unwrap().cx.clone().unwrap();
    (lab, cx)
}
fn controller(cx: &Cx) -> (std::path::PathBuf, Arc<PersistentMembershipController>) {
    let (path, journal) = journal();
    let owner = Arc::new(PersistentMembershipController::new(journal, cx.timer_driver().unwrap()).unwrap());
    (path, owner)
}
fn apply(owner: &Arc<PersistentMembershipController>, incarnation: u64, sequence: u64, kind: MembershipKind) {
    owner.apply_blocking(&NodeId::new("authority"), &statement(incarnation, sequence, kind)).unwrap();
}

#[test]
fn durable_decision_aborts_real_checked_obligation_before_reopen() {
    let (mut lab, cx) = holder(); let (path, owner) = controller(&cx);
    apply(&owner, 1, 1, MembershipKind::Alive);
    let guard = owner.try_grant(&cx, &NodeId::new("worker"), 1, Duration::from_secs(5)).unwrap();
    let mailbox = Arc::clone(lab.state.obligation_gateway().unwrap().mailbox());
    apply_obligation_posts(&mut lab.state, &mailbox, 64);
    assert_eq!(mailbox.stats().reserved, 1);
    apply(&owner, 1, 2, MembershipKind::Dead);
    assert_eq!(guard.status(), OwnedLeaseStatus::Revoked);
    apply_obligation_posts(&mut lab.state, &mailbox, 64);
    assert_eq!(mailbox.stats().aborted, 1); assert_eq!(mailbox.stats().leaked, 0);
    drop(guard); drop(owner);
    let file = OpenOptions::new().read(true).write(true).open(path).unwrap();
    let restored = Arc::new(PersistentMembershipController::new(MembershipJournal::open(file, config()).unwrap(), cx.timer_driver().unwrap()).unwrap());
    assert!(restored.try_grant(&cx, &NodeId::new("worker"), 1, Duration::from_secs(5)).is_err());
    apply(&restored, 2, 3, MembershipKind::Alive);
    let fresh = restored.try_grant(&cx, &NodeId::new("worker"), 2, Duration::from_secs(5)).unwrap();
    fresh.release().unwrap(); apply_obligation_posts(&mut lab.state, &mailbox, 64);
    assert_eq!(mailbox.stats().committed, 1); assert_eq!(mailbox.stats().leaked, 0);
}

#[test]
fn queued_update_owns_admission_and_drop_does_not_write() {
    let (_lab, cx) = holder(); let (path, owner) = controller(&cx);
    let bytes = statement(1, 1, MembershipKind::Alive); let before = std::fs::metadata(path).unwrap().len();
    let job = owner.prepare(&NodeId::new("authority"), &bytes).unwrap();
    assert!(owner.update_in_flight());
    assert!(matches!(owner.prepare(&NodeId::new("authority"), &bytes), Err(PersistentMembershipError::Busy)));
    assert!(owner.stamp(&NodeId::new("worker")).is_none());
    drop(job);
    assert!(!owner.update_in_flight());
    assert_eq!(owner.journal.lock().as_ref().unwrap().committed_bytes(), before);
    apply(&owner, 1, 1, MembershipKind::Alive);
}

#[test]
fn observer_and_forged_statement_do_not_persist_or_close_healthy_grants() {
    let (_lab, cx) = holder(); let (_, owner) = controller(&cx);
    apply(&owner, 1, 1, MembershipKind::Alive);
    let guard = owner.try_grant(&cx, &NodeId::new("worker"), 1, Duration::from_secs(5)).unwrap();
    let mut bytes = statement(1, 2, MembershipKind::Dead);
    assert!(owner.apply_blocking(&NodeId::new("observer"), &bytes).is_err());
    let n = bytes.len(); bytes[n-1] ^= 1;
    assert!(owner.apply_blocking(&NodeId::new("authority"), &bytes).is_err());
    assert_eq!(guard.status(), OwnedLeaseStatus::Active); assert!(!owner.closed.load(Ordering::Acquire));
    assert_eq!(owner.journal.lock().as_ref().unwrap().records(), 1);
    guard.release().unwrap();
}

#[test]
fn poisoned_storage_closes_existing_guards_and_never_admits_more() {
    let (_lab, cx) = holder(); let (_, owner) = controller(&cx);
    apply(&owner, 1, 1, MembershipKind::Alive);
    let guard = owner.try_grant(&cx, &NodeId::new("worker"), 1, Duration::from_secs(5)).unwrap();
    owner.journal.lock().as_mut().unwrap().core.status = MembershipJournalStatus::Poisoned;
    assert!(owner.apply_blocking(&NodeId::new("authority"), &statement(1, 2, MembershipKind::Dead)).is_err());
    assert_eq!(guard.status(), OwnedLeaseStatus::Closed);
    assert!(owner.try_grant(&cx, &NodeId::new("worker"), 1, Duration::from_secs(5)).is_err());
    assert!(!owner.update_in_flight());
}

struct Reenter { owner: std::sync::Weak<PersistentMembershipController>, busy: AtomicBool, panic: bool }
impl Wake for Reenter {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) {
        let owner = self.owner.upgrade().unwrap();
        assert_eq!(owner.stamp(&NodeId::new("worker")).unwrap().kind, MembershipKind::Dead);
        let result = owner.apply_blocking(&NodeId::new("authority"), &statement(1, 2, MembershipKind::Dead));
        self.busy.store(matches!(result, Err(PersistentMembershipError::Busy)), Ordering::Release);
        assert!(!self.panic, "hostile waiter");
    }
}
#[test]
fn callbacks_can_reenter_but_cannot_overtake_the_persisted_projection() {
    let (_lab, cx) = holder(); let (_, owner) = controller(&cx); apply(&owner, 1, 1, MembershipKind::Alive);
    let guard = owner.try_grant(&cx, &NodeId::new("worker"), 1, Duration::from_secs(5)).unwrap();
    let witness = Arc::new(Reenter { owner: Arc::downgrade(&owner), busy: AtomicBool::new(false), panic: false });
    let waker = Waker::from(Arc::clone(&witness));
    let mut wait = Box::pin(guard.ended()); assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    apply(&owner, 1, 2, MembershipKind::Dead);
    assert!(witness.busy.load(Ordering::Acquire)); assert!(!owner.update_in_flight()); drop(wait);
}
#[test]
fn projection_callback_panic_closes_owner_but_returns_journal_for_recovery() {
    let (_lab, cx) = holder(); let (path, owner) = controller(&cx); apply(&owner, 1, 1, MembershipKind::Alive);
    let guard = owner.try_grant(&cx, &NodeId::new("worker"), 1, Duration::from_secs(5)).unwrap();
    let waker = Waker::from(Arc::new(Reenter { owner: Arc::downgrade(&owner), busy: AtomicBool::new(false), panic: true }));
    let mut wait = Box::pin(guard.ended()); assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| apply(&owner, 1, 2, MembershipKind::Dead))).is_err());
    assert!(owner.closed.load(Ordering::Acquire)); assert!(!owner.update_in_flight());
    drop(wait); drop(guard); drop(owner);
    let file = OpenOptions::new().read(true).write(true).open(path).unwrap();
    assert_eq!(MembershipJournal::open(file, config()).unwrap().stamp(&NodeId::new("worker")).unwrap().kind, MembershipKind::Dead);
}

#[test]
fn dropping_expiry_driver_closes_persistent_admission_without_appending() {
    let (_lab, cx) = holder(); let (_, owner) = controller(&cx); apply(&owner, 1, 1, MembershipKind::Alive);
    let mut driver = Box::pin(owner.run(&cx));
    assert!(driver.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    let mut duplicate = Box::pin(owner.run(&cx));
    assert!(matches!(duplicate.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        std::task::Poll::Ready(Err(OwnedMembershipError::DriverRunning))));
    assert!(!owner.closed.load(Ordering::Acquire)); drop(duplicate); drop(driver);
    assert!(matches!(owner.apply_blocking(&NodeId::new("authority"), &statement(1, 2, MembershipKind::Dead)), Err(PersistentMembershipError::Closed)));
    assert_eq!(owner.journal.lock().as_ref().unwrap().records(), 1);
}
