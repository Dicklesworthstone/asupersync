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

#[cfg(unix)]
mod native {
    use super::*;
    use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
    use crate::types::CancelReason;
    use std::fs::File;
    use std::future::poll_fn;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::task::Poll;
    use std::time::Instant;

    fn runtime(workers: usize) -> Runtime {
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers) };
        builder.blocking_threads(1, 1).build().unwrap()
    }

    fn linked_controller(runtime: &Runtime) -> (PathBuf, Arc<PersistentMembershipController>) {
        let (path, journal) = journal();
        File::open(path.parent().unwrap()).unwrap().sync_all().unwrap();
        let clock = runtime.block_on(async { Cx::current().unwrap().timer_driver().unwrap() });
        let owner = Arc::new(PersistentMembershipController::new(journal, clock).unwrap());
        apply(&owner, 1, 1, MembershipKind::Alive);
        (path, owner)
    }

    fn assert_drained(runtime: &Runtime) {
        let report = runtime.shutdown_drained(Duration::from_secs(10));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.live_regions, 0);
        assert_eq!(report.pending_obligations, 0);
        assert_eq!(report.pending_spawns, 0);
        assert_eq!(report.queued_finalizers, 0);
        assert!(!report.has_pending_obligation_posts);
    }

    fn assert_locked(path: &std::path::Path) {
        let file = OpenOptions::new().read(true).write(true).open(path).unwrap();
        assert!(matches!(MembershipJournal::open(file, config()), Err(MembershipJournalError::Locked)));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn dropped_membership_handler_retains_queued_journal_until_worker_retirement() {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let (path, owner) = linked_controller(&runtime);
            let inode = std::fs::metadata(&path).unwrap();
            let before = owner.journal.lock().as_ref().unwrap().committed_bytes();
            let weak = Arc::downgrade(&owner);
            let pool = runtime.blocking_handle().unwrap();
            let (entered, parked) = mpsc::sync_channel(1);
            let (release, hold) = mpsc::sync_channel(1);
            let occupying = runtime.spawn_blocking(move || {
                entered.send(()).unwrap();
                hold.recv_timeout(Duration::from_secs(30)).unwrap();
            }).unwrap();
            parked.recv_timeout(Duration::from_secs(10)).expect("real blocking worker is occupied");
            let bytes = statement(1, 2, MembershipKind::Dead);
            let authority = NodeId::new("authority");

            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let mut handler = Box::pin(dispatch(&cx, Arc::clone(&owner), &authority, &bytes));
                poll_fn(|task| {
                    assert!(handler.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                let deadline = Instant::now() + Duration::from_secs(10);
                while pool.pending_count() != 1 {
                    assert!(Instant::now() < deadline, "authority update must reach the real pool queue");
                    yield_now().await;
                }
                drop(handler); // The registered handler awaits this exact future.
                assert!(owner.update_in_flight());
                assert_eq!(Arc::strong_count(&owner), 2, "the queued job retains the controller and journal");
                assert!(matches!(dispatch(&cx, Arc::clone(&owner), &authority, &bytes).await,
                    RemoteOutcome::Failed(message) if message == "persistent membership update is busy"));
                assert_eq!(owner.stamp(&NodeId::new("worker")).unwrap().kind, MembershipKind::Alive);
            });
            drop(owner); // The cancelled, still-queued job is now the sole journal owner.
            let report = runtime.shutdown_drained(Duration::from_millis(20));
            assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
            assert!(report.live_tasks > 0, "the queued authority update must retain a runtime task");
            assert_eq!(weak.strong_count(), 1);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), before);
            assert_locked(&path);

            release.send(()).unwrap();
            assert_drained(&runtime);
            assert!(occupying.wait_timeout(Duration::from_secs(1)));
            assert!(weak.upgrade().is_none(), "worker retirement must release the final file owner");
            assert_eq!(std::fs::metadata(&path).unwrap().len(), before,
                "the cancelled queued decision must not append or project");
            assert!(runtime.shutdown_timeout(Duration::from_secs(5)));

            // Reopen the original journal: no cancelled decision was fabricated,
            // and an explicit retry can still persist and project the revocation.
            let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
            let journal = MembershipJournal::open(file, config()).unwrap();
            assert_eq!(journal.stamp(&NodeId::new("worker")).unwrap().kind, MembershipKind::Alive);
            let retry_runtime = self::runtime(workers);
            let clock = retry_runtime.block_on(async { Cx::current().unwrap().timer_driver().unwrap() });
            let owner = Arc::new(PersistentMembershipController::new(journal, clock).unwrap());
            retry_runtime.block_on(async {
                let cx = Cx::current().unwrap();
                assert!(matches!(dispatch(&cx, Arc::clone(&owner), &authority, &bytes).await,
                    RemoteOutcome::Success(echo) if echo == bytes));
            });
            assert!(!owner.update_in_flight());
            assert_eq!(owner.stamp(&NodeId::new("worker")).unwrap().kind, MembershipKind::Dead);
            assert_eq!(owner.journal.lock().as_ref().unwrap().records(), 2);
            let after = std::fs::metadata(&path).unwrap();
            assert!(after.len() > before);
            assert_eq!((after.dev(), after.ino()), (inode.dev(), inode.ino()));
            owner.close();
            assert_drained(&retry_runtime);
            assert!(retry_runtime.shutdown_timeout(Duration::from_secs(5)));
        }
    }

    struct ProjectionPause {
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        notified: AtomicBool,
    }
    impl Wake for ProjectionPause {
        fn wake(self: Arc<Self>) { self.wake_by_ref(); }
        fn wake_by_ref(self: &Arc<Self>) {
            if !self.notified.swap(true, Ordering::AcqRel) {
                self.entered.send(()).unwrap();
                self.release.lock().recv_timeout(Duration::from_secs(30)).unwrap();
            }
        }
    }

    #[test]
    fn dropped_membership_handler_drains_a_started_revocation_projection() {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let (path, owner) = linked_controller(&runtime);
            let before = owner.journal.lock().as_ref().unwrap().committed_bytes();
            let (entered, projecting) = mpsc::sync_channel(1);
            let (release, hold) = mpsc::sync_channel(1);
            let waker = Waker::from(Arc::new(ProjectionPause {
                entered, release: Mutex::new(hold), notified: AtomicBool::new(false),
            }));
            let bytes = statement(1, 2, MembershipKind::Dead);
            let authority = NodeId::new("authority");

            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let guard = owner.try_grant(&cx, &NodeId::new("worker"), 1, Duration::from_secs(60)).unwrap();
                let mut ended = Box::pin(guard.ended());
                assert!(ended.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
                let mut handler = Box::pin(dispatch(&cx, Arc::clone(&owner), &authority, &bytes));
                poll_fn(|task| {
                    assert!(handler.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    match projecting.try_recv() {
                        Ok(()) => break,
                        Err(mpsc::TryRecvError::Empty) => {
                            assert!(Instant::now() < deadline, "durable revocation must reach its real lease callback");
                            yield_now().await;
                        }
                        Err(error) => panic!("projection witness disconnected: {error}"),
                    }
                }
                assert_eq!(guard.status(), OwnedLeaseStatus::Revoked);
                assert!(std::fs::metadata(&path).unwrap().len() > before);
                assert!(owner.update_in_flight(), "the persisted projection has not retired");
                drop(handler);
                drop(ended);
                drop(guard);
            });
            let report = runtime.shutdown_drained(Duration::from_millis(20));
            assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
            assert!(report.live_tasks > 0, "a started projection cannot outlive its runtime owner");
            assert!(owner.update_in_flight());
            assert_locked(&path);
            release.send(()).unwrap();
            assert_drained(&runtime);
            assert!(!owner.update_in_flight());
            assert!(!owner.closed.load(Ordering::Acquire), "a completed revocation is not rolled back by handler drop");
            assert_eq!(owner.live_leases(), 0);
            assert_eq!(owner.stamp(&NodeId::new("worker")).unwrap().kind, MembershipKind::Dead);
            assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
            drop(owner);
            let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
            let reopened = MembershipJournal::open(file, config()).unwrap();
            assert_eq!(reopened.records(), 2);
            assert_eq!(reopened.stamp(&NodeId::new("worker")).unwrap().kind, MembershipKind::Dead);
        }
    }

    #[test]
    fn completed_membership_revocation_preserves_echo_after_late_invocation_cancellation() {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            let (path, owner) = linked_controller(&runtime);
            let before = owner.journal.lock().as_ref().unwrap().committed_bytes();
            let pool = runtime.blocking_handle().unwrap();
            let (entered, parked) = mpsc::sync_channel(1);
            let (release, hold) = mpsc::sync_channel(1);
            let occupying = runtime.spawn_blocking(move || {
                entered.send(()).unwrap();
                hold.recv_timeout(Duration::from_secs(30)).unwrap();
            }).unwrap();
            parked.recv_timeout(Duration::from_secs(10)).expect("real blocking worker is occupied");
            let bytes = statement(1, 2, MembershipKind::Dead);
            let authority = NodeId::new("authority");

            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let guard = owner.try_grant(&cx, &NodeId::new("worker"), 1, Duration::from_secs(60)).unwrap();
                let handler_owner = Arc::clone(&owner);
                let handler_bytes = bytes.clone();
                let (invocation_started, mut invocation_pending) = crate::channel::oneshot::channel();
                let (resume_invocation, mut resume_handler) = crate::channel::oneshot::channel();
                let mut handler = cx.spawn(move |invocation_cx| async move {
                    let mut invocation = Box::pin(dispatch(
                        &invocation_cx, handler_owner, &authority, &handler_bytes,
                    ));
                    poll_fn(|task| {
                        assert!(invocation.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    }).await;
                    invocation_started.send_blocking(invocation_cx.clone()).unwrap();
                    // Hold the actual spawned handler before it consumes the
                    // worker's result. This wait must not acknowledge its
                    // cancellation on behalf of the dispatch being tested.
                    poll_fn(|task| resume_handler.poll_recv_uninterruptible(task)).await.unwrap();
                    invocation.await
                }).unwrap();
                let invocation_cx = crate::time::timeout(
                    cx.now(), Duration::from_secs(10), invocation_pending.recv(&cx),
                ).await.expect("the spawned handler must reach its real pending dispatch").unwrap();
                assert_eq!(invocation_cx.task_id(), handler.task_id());
                assert_eq!(invocation_cx.region_id(), cx.region_id());
                let deadline = Instant::now() + Duration::from_secs(10);
                while pool.pending_count() != 1 {
                    assert!(Instant::now() < deadline, "authority update must enter the real pool queue");
                    yield_now().await;
                }
                assert!(owner.update_in_flight());
                assert_eq!(guard.status(), OwnedLeaseStatus::Active);
                release.send(()).unwrap();
                let deadline = Instant::now() + Duration::from_secs(10);
                while owner.update_in_flight() {
                    assert!(Instant::now() < deadline, "the real journal append and projection must finish");
                    yield_now().await;
                }
                assert_eq!(guard.status(), OwnedLeaseStatus::Revoked);
                assert_eq!(owner.stamp(&NodeId::new("worker")).unwrap().kind, MembershipKind::Dead);
                // No second handler poll has consumed the completed result.
                handler.abort_with_reason(CancelReason::user("late authority invocation cancellation"));
                let deadline = Instant::now() + Duration::from_secs(10);
                while !invocation_cx.is_cancel_requested() {
                    assert!(Instant::now() < deadline, "the real handler must observe its deferred abort");
                    yield_now().await;
                }
                assert!(!handler.is_finished(), "the unconsumed dispatch still belongs to the task");
                resume_invocation.send_blocking(()).unwrap();
                let terminal = crate::time::timeout(
                    cx.now(), Duration::from_secs(10), poll_fn(|task| handler.poll_join(task)),
                ).await.expect("the completed handler must retire after its abort is acknowledged");
                assert!(matches!(terminal, Ok(RemoteOutcome::Success(echo)) if echo == bytes),
                    "the native task completion policy must preserve the synced, projected receipt");
                drop(guard);
            });
            assert!(occupying.wait_timeout(Duration::from_secs(1)));
            assert!(!owner.update_in_flight());
            assert_eq!(owner.live_leases(), 0);
            assert_eq!(owner.journal.lock().as_ref().unwrap().records(), 2);
            assert!(std::fs::metadata(&path).unwrap().len() > before);
            owner.close();
            assert_drained(&runtime);
            assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        }
    }
}
