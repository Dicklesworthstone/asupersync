//! Shared probes for native obligation-mailbox observer boundaries.
use super::*;
use crate::runtime::obligation_mailbox::{ObligationGateway, ObligationMailbox};
use crate::sync::ContendedMutex;
use std::sync::{Mutex, Weak};

/// Records a failed reentry instead of blocking forever on the old locked path.
pub(crate) struct MailboxLifecycleMetrics {
    target: Mutex<Option<(Weak<ContendedMutex<RuntimeState>>, Arc<ObligationMailbox>)>>,
    events: Mutex<Vec<&'static str>>,
    unlocked: AtomicUsize,
    applied: AtomicUsize,
    panic_callbacks: bool,
}

impl MailboxLifecycleMetrics {
    pub(crate) fn new(panic_callbacks: bool) -> Arc<Self> {
        Arc::new(Self {
            target: Mutex::new(None),
            events: Mutex::new(Vec::new()),
            unlocked: AtomicUsize::new(0),
            applied: AtomicUsize::new(0),
            panic_callbacks,
        })
    }

    pub(crate) fn arm(
        &self,
        state: &Arc<ContendedMutex<RuntimeState>>,
        mailbox: &Arc<ObligationMailbox>,
    ) {
        *self.target.lock().unwrap() = Some((Arc::downgrade(state), Arc::clone(mailbox)));
    }

    fn observe(&self, event: &'static str) {
        let Some((state, mailbox)) = self.target.lock().unwrap().clone() else {
            return;
        };
        self.events.lock().unwrap().push(event);
        if let Some(state) = state.upgrade()
            && let Ok(_state) = state.try_lock()
        {
            self.unlocked.fetch_add(1, Ordering::SeqCst);
        }
        let stats = mailbox.stats();
        if stats.applied == stats.posted && mailbox.is_empty() {
            self.applied.fetch_add(1, Ordering::SeqCst);
        }
        assert!(!self.panic_callbacks, "mailbox lifecycle observer sentinel");
    }

    pub(crate) fn assert_observed(&self, expected: &[&'static str]) {
        assert_eq!(&*self.events.lock().unwrap(), expected);
        assert_eq!(
            self.unlocked.load(Ordering::SeqCst),
            expected.len(),
            "every callback can reenter the outer runtime mutex"
        );
        assert_eq!(
            self.applied.load(Ordering::SeqCst),
            expected.len(),
            "callbacks see the applied mailbox receipts, not half-applied posts"
        );
    }
}

impl MetricsProvider for MailboxLifecycleMetrics {
    fn task_spawned(&self, _: RegionId, _: TaskId) {}
    fn task_completed(&self, _: TaskId, _: OutcomeKind, _: Duration) {}
    fn region_created(&self, _: RegionId, _: Option<RegionId>) {}
    fn region_closed(&self, _: RegionId, _: Duration) {}
    fn cancellation_requested(&self, _: RegionId, _: CancelKind) {}
    fn drain_completed(&self, _: RegionId, _: Duration) {}
    fn deadline_set(&self, _: RegionId, _: Duration) {}
    fn deadline_exceeded(&self, _: RegionId) {}
    fn deadline_warning(&self, _: &str, _: &'static str, _: Duration) {}
    fn deadline_violation(&self, _: &str, _: Duration) {}
    fn deadline_remaining(&self, _: &str, _: Duration) {}
    fn checkpoint_interval(&self, _: &str, _: Duration) {}
    fn task_stuck_detected(&self, _: &str) {}
    fn obligation_created(&self, _: RegionId) {
        self.observe("created");
    }
    fn obligation_discharged(&self, _: RegionId) {
        self.observe("discharged");
    }
    fn obligation_leaked(&self, _: RegionId) {
        self.observe("leaked");
    }
    fn scheduler_tick(&self, _: usize, _: Duration) {}
}

/// Retain the returned liveness token until the fixture has finished.
pub(crate) fn mailbox_runtime(
    panic_callbacks: bool,
) -> (
    RuntimeState,
    Arc<MailboxLifecycleMetrics>,
    Arc<ObligationMailbox>,
    Arc<()>,
) {
    let metrics = MailboxLifecycleMetrics::new(panic_callbacks);
    let mut state = RuntimeState::new_with_metrics(metrics.clone());
    let mailbox = Arc::new(ObligationMailbox::new());
    let liveness = Arc::new(());
    state.set_obligation_gateway(Arc::new(ObligationGateway::new(
        Arc::clone(&mailbox),
        Arc::new(|| {}),
        Arc::downgrade(&liveness),
    )));
    (state, metrics, mailbox, liveness)
}

/// All reservations originate from an admitted task's actual installed Cx.
/// An optional real oneshot wait separates bounded Pending delivery from the
/// completion sweep. The task panic happens only after both tokens settle.
pub(crate) async fn post_work(
    mut release: Option<crate::channel::oneshot::Receiver<()>>,
    panic_task: bool,
) -> u8 {
    let cx = crate::cx::Cx::current().expect("native task context");
    let committed = cx
        .try_register_obligation_checked(ObligationKind::SendPermit, cx.task_id())
        .expect("checked admission")
        .expect("tracked runtime");
    assert!(committed.commit());
    let aborted = cx
        .try_register_obligation_checked(ObligationKind::SendPermit, cx.task_id())
        .expect("second checked admission")
        .expect("tracked runtime");
    if let Some(receive) = release.as_mut() {
        receive.recv_uninterruptible().await.expect("real wake");
    }
    assert!(aborted.abort(ObligationAbortReason::Explicit));
    assert!(!panic_task, "mailbox task panic sentinel");
    73
}

pub(crate) fn assert_settled(mailbox: &ObligationMailbox) {
    let stats = mailbox.stats();
    assert_eq!(stats.posted, 4);
    assert_eq!(stats.applied, 4);
    assert_eq!(stats.reserved, 2);
    assert_eq!(stats.committed, 1);
    assert_eq!(stats.aborted, 1);
    assert_eq!(stats.leaked, 0);
    assert_eq!(stats.refused, 0);
    assert_eq!(mailbox.open_tickets(), 0);
    assert!(mailbox.is_empty());
}
