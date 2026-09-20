//! Bounded, multi-producer control of a region-owned dynamic supervisor.
//!
//! The owned-receipt entry point is [`Cx::spawn_dynamic_supervisor_mailbox`].
//! The existing `dynamic_service` request-credit API and its
//! `Cx::spawn_dynamic_supervisor_service` entry point are unchanged.
//!
//! A service owns the mutable [`DynamicSupervisor`]; independent tasks receive
//! cloneable submission capabilities. Admission is bounded and nonblocking:
//! a full mailbox refuses rather than retaining an unbounded population of
//! waiting requests. Every admitted child gets a separate stop channel and a
//! single-consumer completion handle. Stop/drop never competes for mailbox space.
//!
//! Dropping an admission receipt before dispatch prevents its factory from
//! running. Dropping it during admission can race with submission: any resulting
//! child is stopped and drained, not detached. Dropping a child handle requests
//! stop and relinquishes its result; only joining establishes completed cleanup.
//!
//! Successful completions belong to their child handles. The service retains no
//! unbounded completion history. Failed cleanup keeps the owner's reservation
//! quarantined and its full report is returned by service shutdown. Caller-held
//! factories, unread results and tasks within a supplied tree have separate
//! ownership/bounds; mailbox and child counts are not a byte-memory guarantee.

use super::{CancelWakerToken, Cx, DynamicChildCompletion, DynamicChildId,
    DynamicChildResult, DynamicSupervisor, DynamicSupervisorConfig, DynamicSupervisorError,
    DynamicSupervisorReport, DynamicWorkerConfig};
use crate::channel::{mpsc, oneshot};
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::supervision::{ChildName, ManagedChildFactory, ManagedSupervisor};
use crate::types::{CancelReason, PanicPayload};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};

/// Submission/observation failure, distinct from a child's application outcome.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DynamicServiceError {
    /// A service must have at least one queued-command slot.
    #[error("dynamic supervisor mailbox capacity must be nonzero")]
    InvalidCapacity,
    /// No command was enqueued; the supplied factory/tree was not invoked.
    #[error("dynamic supervisor mailbox is full")]
    MailboxFull,
    /// The service exited, sealed admission, or the receipt was already consumed.
    #[error("dynamic supervisor service or receipt is closed")]
    Closed,
    /// This caller's cancellation prevented submission or interrupted observation.
    #[error("dynamic supervisor service request cancelled: {0:?}")]
    Cancelled(CancelReason),
    /// Original dynamic admission or child cleanup refusal.
    #[error(transparent)]
    Supervisor(#[from] DynamicSupervisorError),
    /// The owning context could not submit the actual controller task.
    #[error("dynamic supervisor service task admission failed: {0:?}")]
    Spawn(SpawnError),
}

fn cancellation(cx: &Cx) -> DynamicServiceError {
    DynamicServiceError::Cancelled(cx.cancel_reason()
        .unwrap_or_else(|| CancelReason::user("dynamic service caller cancelled")))
}

enum Start<E> {
    Tree(ManagedSupervisor<E>),
    Worker(DynamicWorkerConfig, Arc<dyn ManagedChildFactory<E>>),
}

struct Command<E> {
    name: ChildName,
    start: Start<E>,
    reply: oneshot::Sender<Result<DynamicServiceChild<E>, DynamicServiceError>>,
}

/// A delegated admission capability. Clones share ONE bounded command mailbox.
///
/// Possession grants submission into the service owner's region and budgets.
/// The per-call Cx controls the caller's cancellation, not the service's authority.
/// Dropping the last client closes admission and stops/drains remaining children.
/// Retain a client while child handles are still intended to run.
pub struct DynamicSupervisorClient<E> {
    sender: mpsc::Sender<Command<E>>,
    control: Arc<Control>,
}

impl<E> Clone for DynamicSupervisorClient<E> {
    fn clone(&self) -> Self {
        Self { sender: self.sender.clone(), control: Arc::clone(&self.control) }
    }
}

impl<E> fmt::Debug for DynamicSupervisorClient<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicSupervisorClient").finish_non_exhaustive()
    }
}

/// A submitted request, not evidence of region admission or application readiness.
///
/// Dropping a borrowing `admitted` future retains the request in this receipt.
/// Dropping the receipt itself abandons admission; the service either skips it
/// or stops/drains any child admitted concurrently. No result history is retained.
#[must_use = "await admission; dropping this receipt abandons and cancels the request"]
pub struct DynamicAdmission<E> {
    reply: oneshot::Receiver<Result<DynamicServiceChild<E>, DynamicServiceError>>,
}

impl<E> fmt::Debug for DynamicAdmission<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicAdmission").finish_non_exhaustive()
    }
}

impl<E> DynamicAdmission<E> {
    /// Observe actual admission. Cancellation leaves this receipt resumable.
    /// Successful admission still does not assert that a worker factory is ready.
    pub async fn admitted(&mut self, cx: &Cx) -> Result<DynamicServiceChild<E>, DynamicServiceError> {
        match self.reply.recv(cx).await {
            Ok(result) => result,
            Err(oneshot::RecvError::Cancelled) => Err(cancellation(cx)),
            Err(_) => Err(DynamicServiceError::Closed),
        }
    }
}

/// Exact, non-cloneable child ownership and its eventual quiescent completion.
///
/// Drop requests cancellation through a dedicated channel even with a saturated
/// admission mailbox. It does not synchronously drain. `join` is uninterruptible
/// with respect to caller cancellation; drop the borrowing wait to pause it, or
/// request stop and then join to wait for cleanup. No global name lookup is used.
#[must_use = "retain and join the child; dropping it requests cancellation"]
pub struct DynamicServiceChild<E> {
    id: DynamicChildId,
    stop: Option<oneshot::Sender<()>>,
    completion: oneshot::Receiver<DynamicChildResult<E>>,
}

impl<E> fmt::Debug for DynamicServiceChild<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicServiceChild").field("id", &self.id)
            .field("stop_requested", &self.stop.is_none()).finish_non_exhaustive()
    }
}

impl<E> DynamicServiceChild<E> {
    /// Exact owner/region/admission generation; a reused name is a different ID.
    #[must_use]
    pub fn id(&self) -> &DynamicChildId { &self.id }

    /// Idempotent, nonblocking stop signal, independent of the admission queue.
    pub fn request_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            // This existing sync bridge only commits an in-memory notification.
            // It performs no blocking wait or ambient I/O, and remains available
            // after the caller's cancellation. The driver owns actual cleanup.
            let _ = stop.send_blocking(());
        }
    }

    /// Wait for this controller AND its enclosing child region to finish.
    /// Cleanup refusal retains the full result in the service's shutdown report.
    pub async fn join(&mut self) -> Result<DynamicChildCompletion<E>, DynamicServiceError> {
        self.completion.recv_uninterruptible().await
            .map_err(|_| DynamicServiceError::Closed)?
            .map_err(DynamicServiceError::Supervisor)
    }
}

// Sender::drop wakes the service's retained receiver even without an explicit send.
impl<E> Drop for DynamicServiceChild<E> {
    fn drop(&mut self) { drop(self.stop.take()); }
}

impl<E: Send + 'static> DynamicSupervisorClient<E> {
    fn submit(&self, cx: &Cx, name: ChildName, start: Start<E>)
        -> Result<DynamicAdmission<E>, DynamicServiceError>
    {
        if cx.checkpoint().is_err() { return Err(cancellation(cx)); }
        if self.control.mode.load(Ordering::Acquire) != RUNNING {
            return Err(DynamicServiceError::Closed);
        }
        if name.is_empty() || name.len() > 255 {
            return Err(DynamicSupervisorError::InvalidName.into());
        }
        let (reply, receiver) = oneshot::channel();
        let command = Command { name, start, reply };
        match self.sender.try_send(command) {
            Ok(()) => Ok(DynamicAdmission { reply: receiver }),
            Err(mpsc::SendError::Full(_)) => Err(DynamicServiceError::MailboxFull),
            Err(_) => Err(DynamicServiceError::Closed),
        }
    }

    /// Submit an already-bound tree without waiting for mailbox capacity.
    /// Errors consume the supplied tree but never invoke its factories.
    pub fn submit_child(&self, cx: &Cx, name: impl Into<ChildName>, tree: ManagedSupervisor<E>)
        -> Result<DynamicAdmission<E>, DynamicServiceError>
    {
        self.submit(cx, name.into(), Start::Tree(tree))
    }

    /// Submit a real managed worker factory with its existing restart policy.
    /// The factory is retained, never invoked on the calling task's stack.
    /// Errors consume the factory without invoking it. Mailbox admission and
    /// dynamic child admission are separate checks; await the returned receipt.
    pub fn submit_worker(
        &self, cx: &Cx, name: impl Into<ChildName>, config: DynamicWorkerConfig,
        factory: impl ManagedChildFactory<E>,
    ) -> Result<DynamicAdmission<E>, DynamicServiceError> {
        self.submit(cx, name.into(), Start::Worker(config, Arc::new(factory)))
    }
}

/// Retained terminal evidence for the service task and its dynamic owner.
#[derive(Debug)]
#[must_use = "inspect both task termination and supervisor/root cleanup"]
pub struct DynamicServiceReport<E> {
    /// Root admission failure or the actual final dynamic-owner shutdown report.
    /// Clean child completions were sent to their individual handles, not copied.
    pub supervision: Result<DynamicSupervisorReport<E>, DynamicSupervisorError>,
    /// Actual controller join outcome, independent of a previously published report.
    pub task_outcome: Result<(), JoinError>,
}

type ReportSlot<E> = Arc<Mutex<Option<Result<DynamicSupervisorReport<E>, DynamicSupervisorError>>>>;

/// Region-owned service controller, outside every child region it drains.
/// Dropping this handle requests cancellation; joining is the cleanup barrier.
#[must_use = "retain and join the service to observe completed shutdown"]
pub struct DynamicSupervisorService<E> {
    task: TaskHandle<()>,
    report: ReportSlot<E>,
    control: Arc<Control>,
}

impl<E> fmt::Debug for DynamicSupervisorService<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicSupervisorService").field("task", &self.task.task_id())
            .finish_non_exhaustive()
    }
}

impl<E> DynamicSupervisorService<E> {
    /// Request service cancellation, sealing admission and stopping all children.
    /// This does not wait for quiescence or consume the final report.
    pub fn abort(&self) {
        self.control.request(STOPPING);
        self.task.abort();
    }

    /// Seal admission and let already-dispatched children finish naturally.
    ///
    /// Queued requests that have not been dispatched are refused. An admission
    /// already being processed may finish and belongs to this drain. Requesters
    /// racing with this call must still inspect their admission receipts.
    /// Existing children are NOT stopped. Permanent workers can therefore keep
    /// a drain pending indefinitely; `abort` escalates it to cancellation.
    /// Neither this signal nor `abort` waits for the actual root close.
    pub fn begin_drain(&self) { self.control.request(DRAINING); }

    /// Await the actual service task terminal, then return its retained report.
    /// Caller cancellation does not bypass the child/root drain. Dropping this
    /// borrowing future leaves both the task handle and report available.
    pub async fn join(&mut self) -> Result<DynamicServiceReport<E>, JoinError> {
        let task_outcome = poll_fn(|cx| self.task.poll_join(cx)).await;
        let report = self.report.lock().take();
        if let Some(supervision) = report {
            return Ok(DynamicServiceReport { supervision, task_outcome });
        }
        match task_outcome {
            Err(error) => Err(error),
            Ok(()) => Err(JoinError::Panicked(PanicPayload::new("dynamic service omitted its report"))),
        }
    }
}

impl<E> Drop for DynamicSupervisorService<E> {
    fn drop(&mut self) { self.abort(); }
}

impl Cx {
    /// Spawn an actual bounded service in this context's region.
    ///
    /// The service opens its own dynamic root and generation subtrees. Root
    /// admission can still fail asynchronously; the service report preserves that
    /// original refusal. No runtime/authority is manufactured for detached Cx.
    pub fn spawn_dynamic_supervisor_mailbox<E: Send + 'static>(
        &self, config: DynamicSupervisorConfig, mailbox_capacity: usize,
    ) -> Result<(DynamicSupervisorClient<E>, DynamicSupervisorService<E>), DynamicServiceError> {
        if mailbox_capacity == 0 { return Err(DynamicServiceError::InvalidCapacity); }
        if self.checkpoint().is_err() { return Err(cancellation(self)); }
        let (sender, receiver) = mpsc::channel(mailbox_capacity);
        let (notify, control_rx) = mpsc::channel(1);
        let control = Arc::new(Control { mode: AtomicU8::new(RUNNING), notify });
        let driver_control = Arc::clone(&control);
        let report = Arc::new(Mutex::new(None));
        let publication = Arc::clone(&report);
        let task = self.spawn(move |cx| async move {
            let result = drive(cx, config, receiver, driver_control, control_rx).await;
            *publication.lock() = Some(result);
        }).map_err(DynamicServiceError::Spawn)?;
        Ok((DynamicSupervisorClient { sender, control: Arc::clone(&control) },
            DynamicSupervisorService { task, report, control }))
    }
}

const RUNNING: u8 = 0;
const DRAINING: u8 = 1;
const STOPPING: u8 = 2;

struct Control {
    mode: AtomicU8,
    notify: mpsc::Sender<()>,
}

impl Control {
    fn request(&self, mode: u8) {
        // Publish monotone state before its coalescible wake. A full notification
        // channel already contains a wake; the driver reads the newest mode
        // after consuming it. A concurrent consume leaves space for this wake.
        self.mode.fetch_max(mode, Ordering::AcqRel);
        let _ = self.notify.try_send(());
    }
}

struct Ticket<E> {
    id: DynamicChildId,
    stop: oneshot::Receiver<()>,
    stopped: bool,
    completion: Option<oneshot::Sender<DynamicChildResult<E>>>,
}

// This is an owned registration, not a transient receive-future registration.
// It wakes an idle service even when it has no children and no incoming commands.
struct Cancellation {
    cx: Cx,
    token: Option<CancelWakerToken>,
    observed: bool,
}

impl Cancellation {
    fn requested(&mut self, cx: &Context<'_>) -> bool {
        if self.observed { return true; }
        self.token = Some(self.cx.refresh_cancel_waker(self.token, cx.waker()));
        self.observed = self.cx.checkpoint().is_err();
        self.observed
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() { self.cx.clear_cancel_waker(token); }
    }
}

fn poll_children<E: Send + 'static>(
    owner: &mut DynamicSupervisor<E>, tickets: &mut BTreeMap<ChildName, Ticket<E>>,
    cx: &mut Context<'_>,
) {
    // Do not return on the first Pending or quarantine. A different boundary's
    // finalizer may be precisely what the pending child is waiting for.
    tickets.retain(|_, ticket| {
        if !ticket.stopped && ticket.stop.poll_recv_uninterruptible(cx).is_ready() {
            ticket.stopped = true;
            let _ = owner.request_stop(&ticket.id);
        }
        let terminal = {
            let mut wait = std::pin::pin!(owner.wait_child(&ticket.id));
            wait.as_mut().poll(cx)
        };
        if let Poll::Ready(result) = terminal {
            // Publication is nonblocking, with no service lock held. A dropped
            // handle explicitly relinquished its outcome, but only AFTER the
            // owner has attempted cleanup. Unclean children remain quarantined
            // in `owner` with their full report and reserved capacity intact.
            let _ = ticket.completion.take().expect("one terminal publication").send_blocking(result);
            false
        } else {
            true
        }
    });
}

async fn drive<E: Send + 'static>(
    cx: Cx, config: DynamicSupervisorConfig, receiver: mpsc::Receiver<Command<E>>,
    control: Arc<Control>, mut control_rx: mpsc::Receiver<()>,
) -> Result<DynamicSupervisorReport<E>, DynamicSupervisorError> {
    let mut owner = cx.open_dynamic_supervisor::<E>(config).await?;
    let mut cancellation = Cancellation { cx: cx.clone(), token: None, observed: false };
    let mut receiver = Some(receiver);
    let mut tickets = BTreeMap::new();
    loop {
        let command = poll_fn(|task_cx| {
            if cancellation.requested(task_cx) || owner.is_closing() {
                control.mode.fetch_max(STOPPING, Ordering::AcqRel);
            }
            // Drain one coalesced notification, then register for the next.
            // Never poll a cancellation-rejecting receiver once stopping: that
            // would manufacture perpetual readiness while cleanup is Pending.
            if control.mode.load(Ordering::Acquire) != STOPPING {
                match control_rx.poll_recv(&cx, task_cx) {
                    Poll::Ready(Ok(())) => match control_rx.poll_recv(&cx, task_cx) {
                        Poll::Ready(Ok(())) => task_cx.waker().wake_by_ref(),
                        Poll::Ready(Err(_)) => {
                            control.mode.fetch_max(STOPPING, Ordering::AcqRel);
                        }
                        Poll::Pending => {}
                    },
                    Poll::Ready(Err(_)) => {
                        control.mode.fetch_max(STOPPING, Ordering::AcqRel);
                    }
                    Poll::Pending => {}
                }
            }
            let mode = control.mode.load(Ordering::Acquire);
            if mode != RUNNING {
                drop(receiver.take());
                if mode == STOPPING { owner.begin_shutdown(); }
            }
            poll_children(&mut owner, &mut tickets, task_cx);
            let Some(incoming) = &mut receiver else {
                return if tickets.is_empty() { Poll::Ready(None) } else { Poll::Pending };
            };
            match incoming.poll_recv(&cx, task_cx) {
                Poll::Ready(Ok(command)) => Poll::Ready(Some(command)),
                Poll::Ready(Err(_)) => {
                    control.mode.fetch_max(STOPPING, Ordering::AcqRel);
                    owner.begin_shutdown();
                    drop(receiver.take());
                    // Stop was published after this sweep: rescan to register
                    // every relevant child/close wake before parking.
                    task_cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Pending => Poll::Pending,
            }
        }).await;
        let Some(command) = command else { break; };
        if !command.reply.is_closed() {
            let result = match command.start {
                Start::Tree(tree) => owner.start_child(command.name.clone(), tree).await,
                Start::Worker(config, factory) => {
                    owner.start_worker(command.name.clone(), config,
                        move |cx: Cx, generation| factory.start(cx, generation)).await
                }
            };
            let reply = match result {
                Ok(id) => {
                    let (stop, stop_rx) = oneshot::channel();
                    let (completion, completion_rx) = oneshot::channel();
                    let child = DynamicServiceChild { id: id.clone(), stop: Some(stop), completion: completion_rx };
                    tickets.insert(command.name, Ticket { id, stop: stop_rx, stopped: false, completion: Some(completion) });
                    Ok(child)
                }
                Err(error) => Err(DynamicServiceError::Supervisor(error)),
            };
            // If abandoned during admission, the returned child handle is
            // dropped here. Its independent stop signal is observed next sweep.
            let _ = command.reply.send_blocking(reply);
        }
        // Bound a flood of immediately rejected/abandoned commands, as well as
        // successful admissions, without depending on a command's inner await.
        crate::runtime::yield_now().await;
    }
    // All issued completion tickets have reached terminal publication. Only
    // quarantined entries remain, and shutdown retains their actual evidence.
    Ok(owner.shutdown().await)
}

#[cfg(test)]
mod tests;
