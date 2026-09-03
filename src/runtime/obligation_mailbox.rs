//! Obligation mailbox: how a primitive holding only a `&Cx` mints and
//! resolves a runtime-tracked obligation (br-asupersync-bi2462.13).
//!
//! # Why a mailbox
//!
//! Every reserved permit is meant to be a tracked obligation, so region close
//! can prove "no leaked permits" and the lab's obligation-leak oracle sees it.
//! The obligation table lives inside [`RuntimeState`]: in Unified mode it is
//! embedded (`RuntimeState::obligations`), the production runtime reaches it
//! only through `Arc<Mutex<RuntimeState>>`, and the [`LabRuntime`] owns its
//! state by value and polls task futures from inside its own step. A future
//! being polled therefore has no path to `&mut RuntimeState`, and neither has
//! a `Cx`. The spawn path solves exactly this with the
//! [`SpawnGateway`](crate::runtime::spawn_mailbox::SpawnGateway) mailbox that
//! the runtime drains at step start; obligations use the same shape.
//!
//! # Shape
//!
//! * [`ObligationGateway`] (crate-private, attached to every task `Cx` by the
//!   runtime) posts Copy-sized [`ObligationPost`] messages onto an unbounded
//!   lock-free FIFO ([`ObligationMailbox`]); no `Box`, no per-message `Arc`.
//! * [`Cx::try_register_obligation`](crate::cx::Cx::try_register_obligation)
//!   mints a ticket, reserves one credit on the region's pending-post counter
//!   (so `is_quiescent` / drain gating see the reservation BEFORE the runtime
//!   drains it, the way `PendingSpawnCounter` works for spawns), posts
//!   `Reserve`, and returns an [`ObligationToken`].
//! * [`ObligationToken::commit`] / [`ObligationToken::abort`] post the
//!   resolution; dropping an unresolved token posts `Leak` (never panics).
//! * The runtime drains the mailbox where it drains spawn admissions
//!   ([`apply_obligation_posts`]): `Reserve` -> `RuntimeState::create_obligation`
//!   (holder / region checks, region accounting, trace event, oracle hooks),
//!   `Commit` / `Abort` / `Leak` -> the matching `RuntimeState` method through
//!   the ticket table. Drain order is post order, so a resolution never
//!   overtakes its reservation. Everything visible to the oracle flows through
//!   the one authoritative implementation in `RuntimeState`.
//!
//! # What "zero-alloc" means here
//!
//! A post is a `Copy` value pushed onto the same segmented lock-free queue the
//! spawn mailbox uses: no per-message heap object; the queue amortizes its
//! block allocations over 32 messages and frees them as it drains. The ticket
//! table the drainer keeps is a hash map that grows to the number of
//! obligations in flight, never per post.
//!
//! # Not covered (no-claim)
//!
//! No primitive uses the seam yet (D2: channel permits, D3: semaphore
//! permits, D4: remote leases). A `Cx` built without a runtime (`Cx::new`,
//! `Cx::for_testing`) has no gateway and `try_register_obligation` returns
//! `None`, preserving today's untracked behaviour.

use crate::record::{ObligationAbortReason, ObligationKind};
use crate::runtime::scheduler::global_queue::GlobalFifoQueue;
use crate::runtime::state::RuntimeState;
use crate::types::{ObligationId, RegionId, TaskId};
use crate::util::det_hash::DetHashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// What a post asks the runtime to do with an obligation ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationOp {
    /// Mint the obligation record (`RuntimeState::create_obligation`).
    Reserve,
    /// Resolve it successfully (`RuntimeState::commit_obligation`).
    Commit,
    /// Resolve it as aborted (`RuntimeState::abort_obligation`).
    Abort,
    /// The token was dropped unresolved (`RuntimeState::mark_obligation_leaked`).
    Leak,
}

/// One Copy-sized message on the obligation mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObligationPost {
    /// The operation.
    pub op: ObligationOp,
    /// Ticket minted by the gateway; the drainer maps it to the
    /// [`ObligationId`] the `Reserve` produced.
    pub ticket: u64,
    /// Obligation kind (only meaningful on `Reserve`).
    pub kind: ObligationKind,
    /// Holder task.
    pub holder: TaskId,
    /// Owning region.
    pub region: RegionId,
    /// Abort reason (only meaningful on `Abort`).
    pub abort_reason: ObligationAbortReason,
}

/// Counters the drainer keeps so tests and diagnostics can prove every post
/// was applied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObligationMailboxStats {
    /// Posts pushed by gateways.
    pub posted: u64,
    /// Posts the runtime applied.
    pub applied: u64,
    /// `Reserve` posts that produced an obligation record.
    pub reserved: u64,
    /// `Commit` posts applied.
    pub committed: u64,
    /// `Abort` posts applied.
    pub aborted: u64,
    /// `Leak` posts applied.
    pub leaked: u64,
    /// Posts the runtime could not apply.
    ///
    /// A `Reserve` the state refused (closed region, admission limit) or a
    /// resolution whose ticket had no record. Each is counted, never dropped
    /// silently.
    pub refused: u64,
}

/// The unbounded lock-free FIFO of obligation posts plus the drainer's
/// ticket table.
#[derive(Debug, Default)]
pub struct ObligationMailbox {
    queue: GlobalFifoQueue<ObligationPost>,
    next_ticket: AtomicU64,
    posted: AtomicU64,
    applied: AtomicU64,
    reserved: AtomicU64,
    committed: AtomicU64,
    aborted: AtomicU64,
    leaked: AtomicU64,
    refused: AtomicU64,
    /// ticket -> obligation id for reservations the runtime has applied and
    /// not yet resolved. Only the drainer touches it (under the state lock),
    /// so an uncontended mutex is enough.
    tickets: Mutex<DetHashMap<u64, ObligationId>>,
}

impl ObligationMailbox {
    /// A new, empty mailbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn mint_ticket(&self) -> u64 {
        self.next_ticket.fetch_add(1, Ordering::Relaxed)
    }

    fn push(&self, post: ObligationPost) {
        // Count before publishing so observers see posted >= applied.
        self.posted.fetch_add(1, Ordering::Relaxed);
        self.queue.push(post);
    }

    /// Whether no post is waiting to be applied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Posts waiting to be applied.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Snapshot of the counters.
    #[must_use]
    pub fn stats(&self) -> ObligationMailboxStats {
        ObligationMailboxStats {
            posted: self.posted.load(Ordering::Relaxed),
            applied: self.applied.load(Ordering::Relaxed),
            reserved: self.reserved.load(Ordering::Relaxed),
            committed: self.committed.load(Ordering::Relaxed),
            aborted: self.aborted.load(Ordering::Relaxed),
            leaked: self.leaked.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
        }
    }

    /// Reservations applied and not yet resolved.
    #[must_use]
    pub fn open_tickets(&self) -> usize {
        self.tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// Producer-side handle attached to every task `Cx` built by a runtime
/// (mirrors [`SpawnGateway`](crate::runtime::spawn_mailbox::SpawnGateway)).
pub struct ObligationGateway {
    mailbox: Arc<ObligationMailbox>,
    notify: Arc<dyn Fn() + Send + Sync>,
    runtime_liveness: Weak<()>,
}

impl std::fmt::Debug for ObligationGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObligationGateway")
            .field("pending_posts", &self.mailbox.len())
            .field("runtime_available", &self.is_runtime_available())
            .finish_non_exhaustive()
    }
}

impl ObligationGateway {
    /// A gateway over `mailbox`; `notify` wakes the runtime's drain loop and
    /// `runtime_liveness` is the same liveness token the spawn gateway uses.
    #[must_use]
    pub(crate) fn new(
        mailbox: Arc<ObligationMailbox>,
        notify: Arc<dyn Fn() + Send + Sync>,
        runtime_liveness: Weak<()>,
    ) -> Self {
        Self {
            mailbox,
            notify,
            runtime_liveness,
        }
    }

    /// The mailbox this gateway posts to.
    #[must_use]
    pub fn mailbox(&self) -> &Arc<ObligationMailbox> {
        &self.mailbox
    }

    /// Whether the owning runtime is still alive.
    #[must_use]
    pub fn is_runtime_available(&self) -> bool {
        self.runtime_liveness.upgrade().is_some()
    }

    /// Post one message and wake the drain loop. Returns `false` (and posts
    /// nothing) once the runtime is gone.
    fn post(&self, post: ObligationPost) -> bool {
        let Some(_liveness) = self.runtime_liveness.upgrade() else {
            return false;
        };
        self.mailbox.push(post);
        (self.notify)();
        true
    }

    /// Mint a ticket and post its reservation.
    ///
    /// `pending` is the owning region's pending-post counter, reserved for
    /// the token's lifetime so drain gating sees the obligation before the
    /// runtime applies it.
    pub(crate) fn register(
        self: &Arc<Self>,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        pending: Option<&Arc<crate::record::region::PendingSpawnCounter>>,
    ) -> Option<ObligationToken> {
        let ticket = self.mailbox.mint_ticket();
        let pending = pending.map(crate::record::region::PendingSpawnCounter::reserve);
        let posted = self.post(ObligationPost {
            op: ObligationOp::Reserve,
            ticket,
            kind,
            holder,
            region,
            abort_reason: ObligationAbortReason::Explicit,
        });
        if !posted {
            return None;
        }
        Some(ObligationToken {
            ticket,
            kind,
            holder,
            region,
            gateway: Arc::downgrade(self),
            _pending: pending,
            resolved: false,
        })
    }
}

/// A runtime-tracked obligation minted through the obligation mailbox.
///
/// Created by
/// [`Cx::try_register_obligation`](crate::cx::Cx::try_register_obligation).
/// Resolve it with [`commit`](Self::commit) or [`abort`](Self::abort);
/// dropping it unresolved posts a leak, which the runtime records through its
/// obligation-leak policy (and the lab's obligation-leak oracle reports). The
/// token keeps one pending-post credit on its region for as long as it lives,
/// so region close and `is_quiescent` never observe a window in which the
/// reservation is neither posted nor applied.
#[must_use = "an unresolved ObligationToken is reported as a leak when dropped"]
#[derive(Debug)]
pub struct ObligationToken {
    ticket: u64,
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
    gateway: Weak<ObligationGateway>,
    _pending: Option<crate::record::region::PendingSpawnReservation>,
    resolved: bool,
}

impl ObligationToken {
    /// The gateway ticket (stable for the token's life; the drainer maps it
    /// to the runtime's [`ObligationId`]).
    #[must_use]
    pub fn ticket(&self) -> u64 {
        self.ticket
    }

    /// The obligation kind.
    #[must_use]
    pub fn kind(&self) -> ObligationKind {
        self.kind
    }

    /// The holder task.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.holder
    }

    /// The owning region.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.region
    }

    fn resolve(mut self, op: ObligationOp, abort_reason: ObligationAbortReason) -> bool {
        self.resolved = true;
        let post = ObligationPost {
            op,
            ticket: self.ticket,
            kind: self.kind,
            holder: self.holder,
            region: self.region,
            abort_reason,
        };
        self.gateway
            .upgrade()
            .is_some_and(|gateway| gateway.post(post))
    }

    /// Resolve the obligation as committed. Returns `false` when the runtime
    /// is already gone (nothing is tracked any more).
    pub fn commit(self) -> bool {
        self.resolve(ObligationOp::Commit, ObligationAbortReason::Explicit)
    }

    /// Resolve the obligation as aborted for `reason`.
    pub fn abort(self, reason: ObligationAbortReason) -> bool {
        self.resolve(ObligationOp::Abort, reason)
    }
}

impl Drop for ObligationToken {
    fn drop(&mut self) {
        if self.resolved {
            return;
        }
        self.resolved = true;
        let post = ObligationPost {
            op: ObligationOp::Leak,
            ticket: self.ticket,
            kind: self.kind,
            holder: self.holder,
            region: self.region,
            abort_reason: ObligationAbortReason::Explicit,
        };
        if let Some(gateway) = self.gateway.upgrade() {
            let _ = gateway.post(post);
        }
    }
}

/// Apply up to `max` waiting posts to `state` in post order.
///
/// Called by the runtime where it drains spawn admissions (under the state
/// lock). Returns how many posts were applied.
pub(crate) fn apply_obligation_posts(
    state: &mut RuntimeState,
    mailbox: &ObligationMailbox,
    max: usize,
) -> usize {
    if mailbox.is_empty() {
        return 0;
    }
    let mut posts = Vec::with_capacity(max.min(64));
    let drained = mailbox.queue.pop_batch_into(max, &mut posts);
    if drained == 0 {
        return 0;
    }
    let mut tickets = mailbox
        .tickets
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for post in posts {
        match post.op {
            ObligationOp::Reserve => {
                match state.create_obligation(post.kind, post.holder, post.region, None) {
                    Ok(id) => {
                        tickets.insert(post.ticket, id);
                        mailbox.reserved.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        mailbox.refused.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            ObligationOp::Commit => match tickets.remove(&post.ticket) {
                Some(id) if state.commit_obligation(id).is_ok() => {
                    mailbox.committed.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    mailbox.refused.fetch_add(1, Ordering::Relaxed);
                }
            },
            ObligationOp::Abort => match tickets.remove(&post.ticket) {
                Some(id) if state.abort_obligation(id, post.abort_reason).is_ok() => {
                    mailbox.aborted.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    mailbox.refused.fetch_add(1, Ordering::Relaxed);
                }
            },
            ObligationOp::Leak => match tickets.remove(&post.ticket) {
                Some(id) if state.mark_obligation_leaked(id).is_ok() => {
                    mailbox.leaked.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    mailbox.refused.fetch_add(1, Ordering::Relaxed);
                }
            },
        }
        mailbox.applied.fetch_add(1, Ordering::Relaxed);
    }
    drained
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::lab::{LabConfig, LabRuntime};
    use crate::runtime::config::ObligationLeakResponse;
    use crate::types::Budget;
    use std::sync::atomic::AtomicUsize;

    fn lab() -> LabRuntime {
        let mut runtime = LabRuntime::new(LabConfig::new(0xD1_0001).max_steps(4_096));
        runtime
            .state
            .set_obligation_leak_response(ObligationLeakResponse::Silent);
        runtime
    }

    fn mailbox_of(runtime: &LabRuntime) -> Arc<ObligationMailbox> {
        Arc::clone(
            runtime
                .state
                .obligation_gateway()
                .expect("lab runtime installs an obligation gateway")
                .mailbox(),
        )
    }

    #[test]
    fn register_then_commit_is_applied_through_runtime_state() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let observed = Arc::new(AtomicUsize::new(0));
        let observed_in_task = Arc::clone(&observed);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");
                let token = cx
                    .try_register_obligation(ObligationKind::SendPermit, cx.task_id())
                    .expect("runtime-built cx carries the gateway");
                assert_eq!(token.kind(), ObligationKind::SendPermit);
                assert!(token.commit());
                observed_in_task.fetch_add(1, Ordering::Relaxed);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        assert_eq!(observed.load(Ordering::Relaxed), 1, "task body ran");
        let stats = mailbox.stats();
        assert_eq!(stats.posted, 2, "reserve + commit");
        assert_eq!(stats.applied, 2);
        assert_eq!(stats.reserved, 1);
        assert_eq!(stats.committed, 1);
        assert_eq!(stats.refused, 0);
        assert_eq!(mailbox.open_tickets(), 0);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert!(runtime.is_quiescent());
        assert_eq!(runtime.state.leak_count(), 0);
    }

    #[test]
    fn register_then_abort_is_applied_with_the_reason() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");
                let token = cx
                    .try_register_obligation(ObligationKind::SemaphorePermit, cx.task_id())
                    .expect("gateway");
                assert!(token.abort(ObligationAbortReason::Cancel));
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        let stats = mailbox.stats();
        assert_eq!(stats.reserved, 1);
        assert_eq!(stats.aborted, 1);
        assert_eq!(stats.refused, 0);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert_eq!(runtime.state.leak_count(), 0);
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn dropping_an_unresolved_token_is_recorded_as_a_leak() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");
                let token = cx
                    .try_register_obligation(ObligationKind::SendPermit, cx.task_id())
                    .expect("gateway");
                // Forgotten on purpose: the drop must post a Leak, never panic.
                drop(token);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        let stats = mailbox.stats();
        assert_eq!(stats.reserved, 1);
        assert_eq!(stats.leaked, 1, "{stats:?}");
        assert_eq!(stats.refused, 0, "{stats:?}");
        assert!(
            runtime.state.leak_count() >= 1,
            "the runtime's leak policy saw the token"
        );
        assert_eq!(mailbox.open_tickets(), 0);
    }

    #[test]
    fn a_cx_without_a_runtime_returns_none_and_tracks_nothing() {
        let cx = Cx::for_testing();
        assert!(
            cx.try_register_obligation(ObligationKind::SendPermit, cx.task_id())
                .is_none(),
            "hand-built Cx has no gateway: today's untracked behaviour is preserved"
        );
    }

    /// br-asupersync-bi2462.14: the stock channel permits go through the
    /// seam.
    ///
    /// mpsc reserve+send commits, reserve+abort aborts explicitly,
    /// reserve+drop aborts as a cancellation; oneshot reserve+send commits;
    /// broadcast reserve+send commits and reserve+drop aborts.
    #[test]
    fn channel_permits_register_and_resolve_runtime_obligations() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");

                let (tx, rx) = crate::channel::mpsc::channel::<u8>(4);
                let permit = tx.reserve(&cx).await.expect("mpsc reserve");
                let _ = permit.send(1);
                let permit = tx.reserve(&cx).await.expect("mpsc reserve");
                permit.abort();
                let permit = tx.reserve(&cx).await.expect("mpsc reserve");
                drop(permit);
                drop(rx);

                let (otx, orx) = crate::channel::oneshot::channel::<u8>();
                let permit = otx.reserve(&cx).expect("oneshot reserve");
                permit.send(7).expect("oneshot send");
                drop(orx);

                let (btx, brx) = crate::channel::broadcast::channel::<u8>(4);
                let permit = btx.reserve(&cx).expect("broadcast reserve");
                let _ = permit.send(3);
                let permit = btx.reserve(&cx).expect("broadcast reserve");
                drop(permit);
                drop(brx);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        let stats = mailbox.stats();
        assert_eq!(stats.reserved, 6, "{stats:?}");
        assert_eq!(
            stats.committed, 3,
            "mpsc send, oneshot send, broadcast send: {stats:?}"
        );
        assert_eq!(
            stats.aborted, 3,
            "mpsc abort, mpsc drop, broadcast drop: {stats:?}"
        );
        assert_eq!(stats.leaked, 0, "{stats:?}");
        assert_eq!(stats.refused, 0, "{stats:?}");
        assert_eq!(mailbox.open_tickets(), 0);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert_eq!(runtime.state.leak_count(), 0);
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn many_register_commit_rounds_apply_exactly_and_leave_nothing_pending() {
        const ROUNDS: u64 = 10_000;
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");
                for _ in 0..ROUNDS {
                    let token = cx
                        .try_register_obligation(ObligationKind::SendPermit, cx.task_id())
                        .expect("gateway");
                    assert!(token.commit());
                }
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        let stats = mailbox.stats();
        assert_eq!(stats.posted, 2 * ROUNDS);
        assert_eq!(stats.applied, 2 * ROUNDS);
        assert_eq!(stats.reserved, ROUNDS);
        assert_eq!(stats.committed, ROUNDS);
        assert_eq!(stats.refused, 0);
        assert!(mailbox.is_empty());
        assert_eq!(
            mailbox.open_tickets(),
            0,
            "the ticket table does not grow per post"
        );
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert!(runtime.is_quiescent());
    }

    /// Completes once `flag` is set; parks its waker otherwise so the task
    /// stays parked (not re-scheduled) until the test wakes it.
    struct WaitForFlag {
        flag: Arc<std::sync::atomic::AtomicBool>,
        waker: Arc<parking_lot::Mutex<Option<std::task::Waker>>>,
    }

    impl std::future::Future for WaitForFlag {
        type Output = ();

        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.flag.load(Ordering::Acquire) {
                std::task::Poll::Ready(())
            } else {
                *self.waker.lock() = Some(cx.waker().clone());
                std::task::Poll::Pending
            }
        }
    }

    #[test]
    fn a_posted_reservation_keeps_the_region_from_looking_quiescent_until_applied() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker: Arc<parking_lot::Mutex<Option<std::task::Waker>>> =
            Arc::new(parking_lot::Mutex::new(None));
        let (task, _handle) = {
            let flag = Arc::clone(&flag);
            let waker = Arc::clone(&waker);
            runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().expect("lab task has a current cx");
                    let token = cx
                        .try_register_obligation(ObligationKind::SendPermit, cx.task_id())
                        .expect("gateway");
                    // Hold the token while parked, so the reservation is
                    // outstanding with no poll able to resolve it.
                    WaitForFlag { flag, waker }.await;
                    assert!(token.commit());
                })
                .expect("create task")
        };
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);
        let post_credits = |runtime: &LabRuntime| {
            runtime
                .state
                .region(root)
                .map_or(u32::MAX, |region| region.pending_obligation_post_count())
        };

        // The task polls once, posts Reserve, parks. The reservation is
        // visible as an undrained post, an applied pending obligation, or the
        // region's held credit; the runtime is NOT quiescent.
        runtime.run_until_idle();
        assert_eq!(post_credits(&runtime), 1, "the live token holds one credit");
        assert!(
            !mailbox.is_empty() || runtime.state.pending_obligation_count() >= 1,
            "reservation must be posted or applied while the token lives"
        );
        assert!(!runtime.is_quiescent());

        flag.store(true, Ordering::Release);
        if let Some(waker) = waker.lock().take() {
            waker.wake();
        }
        runtime.run_until_quiescent();
        assert_eq!(mailbox.stats().committed, 1);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert_eq!(post_credits(&runtime), 0, "credit released with the token");
        assert!(runtime.is_quiescent());
    }
}
