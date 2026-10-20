//! Region-owned lifetime and cancellation-safe observation for queued OTLP.

use super::{
    ExportError, ExportQueue, OtlpCancelWakerGuard, OtlpExportQueueStats,
    OtlpHttpExporter, OtlpLogsHttpExporter, Payload,
};
use crate::cx::{ChildRegion, ChildRegionError, ChildRegionSpec, Cx};
use crate::record::region::RegionCloseOutcome;
use crate::record::task::TaskOutcome;
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::types::{CancelKind, CancelReason, PanicPayload, RegionId, TaskId};
use parking_lot::Mutex;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};

/// Why the managed delivery loop stopped.
///
/// Acknowledgements are recorded only after the existing OTLP response
/// validation succeeds. An interrupted request may already have reached its
/// collector and must not be blindly replayed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ManagedOtlpOutcome {
    /// Admission was sealed and every retained batch was acknowledged.
    Drained,
    /// Explicit abort discarded the remaining delivery work.
    Aborted,
    /// The owning task or region requested cancellation.
    Cancelled(CancelReason),
    /// The owning context's effective deadline elapsed.
    DeadlineExceeded,
    /// The existing encoding, transport, retry, or acknowledgement path failed.
    Failed(ExportError),
}

/// Receipt returned only after the delivery task retires and its region closes.
///
/// A successful `join` means this receipt is complete. Inspect `delivery`,
/// `task`, and the region/cleanup outcomes before treating export as successful.
/// Queue counters cover the shared queue's entire lifetime, including work
/// delivered before this service started. Failed batches include interrupted
/// requests and unattempted backlog; they are not an exact count of lost spans,
/// because collector acceptance may precede a lost acknowledgement.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect delivery and cleanup outcomes before accepting shutdown"]
pub struct ManagedOtlpReport {
    /// Real child region that owned the service and any descendants.
    pub region_id: RegionId,
    /// Canonical admitted task identity, resolved after actual retirement.
    pub task_id: TaskId,
    /// Loop outcome; absent if admission, panic, or cancellation prevented it.
    pub delivery: Option<ManagedOtlpOutcome>,
    /// Actual task join result, including panic or pre-first-poll cancellation.
    pub task: Result<(), JoinError>,
    /// Retained terminal outcome of the closed region.
    pub region_outcome: TaskOutcome,
    /// Outcome of finalizer work, distinct from ordinary child cancellation.
    pub cleanup_outcome: Option<TaskOutcome>,
    /// First panic retained by this region or a descendant region.
    pub descendant_panic: Option<PanicPayload>,
    /// Terminal queue counters; admission is sealed and retained bytes are zero.
    pub queue: OtlpExportQueueStats,
}

/// Admission, observation, or region-close error for a managed exporter.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ManagedOtlpError {
    /// A live spawn gateway and runtime timer are required.
    #[error("managed OTLP export requires a runtime spawn gateway and timer")]
    RuntimeRequired,
    /// Configuration or shared-queue admission was refused.
    #[error(transparent)]
    Admission(#[from] ExportError),
    /// Child-region admission or its actual close failed.
    #[error(transparent)]
    Region(#[from] ChildRegionError),
    /// Synchronous task submission was refused; the queue remains reusable.
    #[error("managed OTLP task submission failed: {0:?}")]
    Spawn(SpawnError),
    /// Only this join observation was cancelled; the service remains owned.
    #[error("managed OTLP observation cancelled: {0:?}")]
    ObservationCancelled(CancelReason),
    /// Only this join observation reached its deadline.
    #[error("managed OTLP observation deadline elapsed")]
    ObservationDeadline,
    /// The complete receipt has already been returned once.
    #[error("managed OTLP exporter was already joined")]
    AlreadyJoined,
}

const STARTING: u8 = 0;
const ACTIVE: u8 = 1;
const EXITED: u8 = 2;

struct Shared {
    queue: Arc<ExportQueue>,
    lifecycle: AtomicU8,
    outcome: Mutex<Option<ManagedOtlpOutcome>>,
}

impl Shared {
    fn activate(&self) {
        // A worker may finish before the submitting thread receives its
        // handle. Conversely, synchronous spawn rejection drops the factory
        // without accepting ownership of the existing queue. Commit this
        // handoff only after submission succeeds.
        if self.lifecycle.compare_exchange(
            STARTING, ACTIVE, Ordering::AcqRel, Ordering::Acquire,
        ) == Err(EXITED) {
            self.retire_queue();
        }
    }

    fn retire_queue(&self) {
        let pending = {
            let mut state = self.queue.state.lock();
            state.sealed = true;
            state.stats.queued_batches = 0;
            std::mem::take(&mut state.pending)
        };
        let count = pending.len();
        let bytes: usize = pending.iter().map(|batch| batch.bytes).sum();
        // Drop snapshots and captured credentials before returning their
        // accounting credit. The in-flight Delivery has already retired.
        drop(pending);
        let mut state = self.queue.state.lock();
        state.stats.retained_batches -= count;
        state.stats.retained_bytes -= bytes;
        state.stats.failed_batches = state.stats.failed_batches.saturating_add(count as u64);
        state.stats.consumer_active = false;
    }

    fn request(&self, abort: bool) {
        let mut state = self.queue.state.lock();
        if !state.stats.consumer_active {
            return;
        }
        state.sealed = true;
        state.aborted |= abort;
        drop(state);
        self.queue.ready.notify_one();
    }

    fn aborted(&self) -> bool {
        self.queue.state.lock().aborted
    }
}

struct ExitGuard(Arc<Shared>);

impl Drop for ExitGuard {
    fn drop(&mut self) {
        if self.0.lifecycle.swap(EXITED, Ordering::AcqRel) == ACTIVE {
            self.0.retire_queue();
        }
    }
}

/// Rolls back an uncommitted consumer claim even when a rejected factory's
/// captured clock panics during Drop. No queue lock survives user destruction.
struct AdmissionClaim<'a> {
    queue: &'a ExportQueue,
    submitted: bool,
}

impl<'a> AdmissionClaim<'a> {
    fn new(queue: &'a ExportQueue) -> Result<Self, ExportError> {
        let mut state = queue.state.lock();
        if state.sealed {
            return Err(ExportError::new("otlp.queue.closed"));
        }
        if state.managed || state.stats.consumer_active {
            return Err(ExportError::new("otlp.queue.consumer_busy"));
        }
        state.managed = true;
        state.stats.consumer_active = true;
        Ok(Self { queue, submitted: false })
    }

    fn commit(mut self) {
        self.submitted = true;
    }
}

impl Drop for AdmissionClaim<'_> {
    fn drop(&mut self) {
        if !self.submitted {
            let mut state = self.queue.state.lock();
            state.managed = false;
            state.stats.consumer_active = false;
        }
    }
}

/// Cloneable shutdown control, separate from the single owned join receipt.
#[derive(Clone)]
pub struct ManagedOtlpControl {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for ManagedOtlpControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ManagedOtlpControl")
            .field("sealed", &self.is_sealed())
            .finish_non_exhaustive()
    }
}

impl ManagedOtlpControl {
    /// Permanently seal every producer clone, then drain the accepted backlog.
    /// This is a request; only the owner's `join` proves retirement and close.
    pub fn begin_drain(&self) {
        self.shared.request(false);
    }

    /// Seal admission and interrupt delivery without cancelling the parent Cx.
    /// Already observed acknowledgements win a simultaneous abort. Remaining
    /// work is abandoned and counted; an uncertain request is never requeued.
    pub fn abort(&self) {
        self.shared.request(true);
    }

    /// Whether all producer clones have been permanently sealed.
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.shared.queue.state.lock().sealed
    }
}

type Closing =
    Pin<Box<dyn Future<Output = Result<RegionCloseOutcome, ChildRegionError>> + Send>>;

/// Owns the actual queued-export task and its child region until quiescence.
///
/// Dropping a `join` future only stops observation. Dropping this handle seals
/// and aborts delivery and requests region close; the enclosing region remains
/// the cleanup backstop. Synchronous Drop never claims quiescence. Call
/// `begin_drain`, then `join`, for an acknowledged finite graceful shutdown.
#[must_use = "drain and join the exporter, or let its enclosing region drain cleanup"]
pub struct ManagedOtlpExporter {
    control: ManagedOtlpControl,
    region_id: RegionId,
    task_id: TaskId,
    region: Option<ChildRegion>,
    task: Option<TaskHandle<()>>,
    joined: Option<Result<(), JoinError>>,
    closing: Option<Closing>,
    completed: bool,
}

impl std::fmt::Debug for ManagedOtlpExporter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ManagedOtlpExporter")
            .field("region_id", &self.region_id)
            .field("task_id", &self.task_id)
            .field("completed", &self.completed)
            .finish_non_exhaustive()
    }
}

impl ManagedOtlpExporter {
    /// Clone shutdown control while retaining the unique join receipt here.
    #[must_use]
    pub fn control(&self) -> ManagedOtlpControl {
        self.control.clone()
    }

    /// Seal admission before starting a finite graceful drain.
    pub fn begin_drain(&self) {
        self.control.begin_drain();
    }

    /// Interrupt delivery and abandon the remaining accepted work.
    pub fn abort(&self) {
        self.control.abort();
    }

    /// Wait for actual task retirement and region/descendant/finalizer close.
    ///
    /// Cancellation or expiry of `cx` stops this observation without requesting
    /// service cancellation. A later join resumes the same retained task result
    /// and close future. The service's own inherited budget and parent-region
    /// lifetime still apply independently. A complete receipt wins a late
    /// observer cancellation and may be returned exactly once.
    pub async fn join(&mut self, cx: &Cx) -> Result<ManagedOtlpReport, ManagedOtlpError> {
        let mut cancel = OtlpCancelWakerGuard::new(cx);
        let mut deadline = cx.budget().deadline.map(|deadline| {
            cx.timer_driver().map_or_else(
                || crate::time::sleep_until(deadline),
                |driver| crate::time::Sleep::with_timer_driver(deadline, driver),
            )
        });
        poll_fn(|task| {
            if let Poll::Ready(result) = self.poll_terminal(task) {
                return Poll::Ready(result);
            }
            cancel.refresh(task.waker());
            if cx.checkpoint().is_err() {
                let reason = cancel_reason(cx);
                return Poll::Ready(Err(if reason.kind == CancelKind::Deadline {
                    ManagedOtlpError::ObservationDeadline
                } else {
                    ManagedOtlpError::ObservationCancelled(reason)
                }));
            }
            if let Some(deadline) = deadline.as_mut()
                && Pin::new(deadline).poll_deadline(task).is_ready()
            {
                return Poll::Ready(Err(ManagedOtlpError::ObservationDeadline));
            }
            Poll::Pending
        })
        .await
    }

    fn poll_terminal(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ManagedOtlpReport, ManagedOtlpError>> {
        if self.completed {
            return Poll::Ready(Err(ManagedOtlpError::AlreadyJoined));
        }
        if self.joined.is_none() {
            let task = self.task.as_mut().expect("owned OTLP task before retirement");
            let joined = std::task::ready!(task.poll_join(cx));
            self.task_id = task.task_id();
            self.joined = Some(joined);
            drop(self.task.take());
        }
        if self.closing.is_none() {
            let region = self.region.take().expect("owned OTLP child region");
            self.closing = Some(Box::pin(region.close_with_outcome()));
        }
        let closed = std::task::ready!(
            self.closing.as_mut().expect("retained OTLP region close").as_mut().poll(cx)
        );
        drop(self.closing.take());
        self.completed = true;
        let closed = match closed {
            Ok(closed) => closed,
            Err(error) => return Poll::Ready(Err(ManagedOtlpError::Region(error))),
        };
        Poll::Ready(Ok(ManagedOtlpReport {
            region_id: self.region_id,
            task_id: self.task_id,
            delivery: self.control.shared.outcome.lock().take(),
            task: self.joined.take().expect("actual OTLP task retirement"),
            region_outcome: closed.outcome,
            cleanup_outcome: closed.cleanup_outcome,
            descendant_panic: closed.descendant_panic,
            queue: self.control.shared.queue.state.lock().stats,
        }))
    }
}

impl Drop for ManagedOtlpExporter {
    fn drop(&mut self) {
        if !self.completed {
            self.control.abort();
            if let Some(task) = &self.task {
                task.abort();
            }
            // ChildRegion Drop requests close; a retained close future has
            // already done so. Neither path detaches accepted descendants.
        }
    }
}

impl OtlpHttpExporter {
    /// Admit one managed delivery task in a real child region of `cx`.
    ///
    /// Existing backlog and future admissions through exporter clones share
    /// this one consumer until it seals. Manual flush/run consumers and a
    /// second managed service are refused. Every terminal service path seals
    /// the queue permanently; create a new exporter to start a new service.
    ///
    /// `unix_time_nanos` runs only for metrics, outside all queue locks and
    /// under the actual admitted task's Cx. Logs/traces retain their timestamps.
    /// The supplied owner Cx remains a live cancellation boundary even if this
    /// handle moves to another task. An already cancelled/expired owner refuses
    /// startup without consuming the backlog or acknowledging that owner's
    /// cancellation. Join observations have their own independent Cx.
    /// A zero timestamp, delivery failure, or panic stops the service and
    /// abandons its remaining backlog. Transport, finite retry/backoff and
    /// partial-success validation use the same path as `flush_queued`.
    pub async fn spawn_queued(
        &self,
        cx: &Cx,
        unix_time_nanos: impl FnMut() -> u64 + Send + 'static,
    ) -> Result<ManagedOtlpExporter, ManagedOtlpError> {
        if cx.spawn_gateway_handle().is_none() || cx.timer_driver().is_none() {
            return Err(ManagedOtlpError::RuntimeRequired);
        }
        check_owner_admission(cx)?;
        self.validate_for_export().map_err(ExportError::from)?;
        let region = cx.open_child_region(ChildRegionSpec::inherit()).await?;
        if let Err(error) = check_owner_admission(cx) {
            region.close().await?;
            return Err(ManagedOtlpError::Admission(error));
        }
        let claim = match AdmissionClaim::new(&self.export_queue) {
            Ok(claim) => claim,
            Err(error) => {
                region.close().await?;
                return Err(ManagedOtlpError::Admission(error));
            }
        };
        let shared = Arc::new(Shared {
            queue: Arc::clone(&self.export_queue),
            lifecycle: AtomicU8::new(STARTING),
            outcome: Mutex::new(None),
        });
        let task_shared = Arc::clone(&shared);
        let owner = cx.clone();
        // Capture outside the factory so pre-first-poll cancellation also
        // retires accepted backlog, without needing the user loop to execute.
        let exit = ExitGuard(Arc::clone(&shared));
        let task = region.cx().spawn(move |task_cx| async move {
            let _exit = exit;
            let outcome = run(&task_shared, &task_cx, &owner, unix_time_nanos).await;
            *task_shared.outcome.lock() = Some(outcome);
        });
        let task = match task {
            Ok(task) => task,
            Err(error) => {
                drop(claim);
                region.close().await?;
                return Err(ManagedOtlpError::Spawn(error));
            }
        };
        claim.commit();
        shared.activate();
        Ok(ManagedOtlpExporter {
            control: ManagedOtlpControl { shared },
            region_id: region.region_id(),
            task_id: task.task_id(),
            region: Some(region),
            task: Some(task),
            joined: None,
            closing: None,
            completed: false,
        })
    }
}

impl OtlpLogsHttpExporter {
    /// Own the log delivery consumer inside an admitted task and child region.
    /// All log timestamps are retained; no external metrics clock is required.
    pub async fn spawn_queued(&self, cx: &Cx) -> Result<ManagedOtlpExporter, ManagedOtlpError> {
        self.http.spawn_queued(cx, || 1).await
    }
}

fn cancel_reason(cx: &Cx) -> CancelReason {
    cx.cancel_reason().unwrap_or_else(|| CancelReason::user("managed OTLP owner cancelled"))
}

fn cancelled_outcome(cx: &Cx) -> ManagedOtlpOutcome {
    let reason = cancel_reason(cx);
    if reason.kind == CancelKind::Deadline {
        ManagedOtlpOutcome::DeadlineExceeded
    } else {
        ManagedOtlpOutcome::Cancelled(reason)
    }
}

fn owner_outcome(owner: &Cx) -> Option<ManagedOtlpOutcome> {
    // Observing a different task must not acknowledge its cancellation or
    // consume its poll budget. Its inherited deadline also bounds our task.
    if owner.is_cancel_requested() {
        Some(cancelled_outcome(owner))
    } else if owner.budget().is_past_deadline(owner.now()) {
        Some(ManagedOtlpOutcome::DeadlineExceeded)
    } else {
        None
    }
}

fn check_owner_admission(owner: &Cx) -> Result<(), ExportError> {
    match owner_outcome(owner) {
        Some(ManagedOtlpOutcome::DeadlineExceeded) => {
            Err(ExportError::new("otlp.queue.deadline_exceeded"))
        }
        Some(_) => Err(ExportError::new("otlp.queue.cancelled")),
        None => Ok(()),
    }
}

async fn run(
    shared: &Shared,
    cx: &Cx,
    owner: &Cx,
    mut unix_time_nanos: impl FnMut() -> u64,
) -> ManagedOtlpOutcome {
    let mut cancel = OtlpCancelWakerGuard::new(cx);
    let mut owner_cancel = OtlpCancelWakerGuard::new(owner);
    let mut deadline = cx.budget().deadline.map(|deadline| {
        cx.timer_driver().map_or_else(
            || crate::time::sleep_until(deadline),
            |driver| crate::time::Sleep::with_timer_driver(deadline, driver),
        )
    });
    loop {
        let mut ready = std::pin::pin!(shared.queue.ready.wait_until(|| {
            let state = shared.queue.state.lock();
            state.sealed || !state.pending.is_empty()
        }));
        let ready = poll_fn(|task| {
            cancel.refresh(task.waker());
            owner_cancel.refresh(task.waker());
            if let Some(outcome) = owner_outcome(owner) {
                return Poll::Ready(Err(outcome));
            }
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(cancelled_outcome(cx)));
            }
            if let Some(deadline) = deadline.as_mut()
                && Pin::new(deadline).poll_deadline(task).is_ready()
            {
                return Poll::Ready(Err(ManagedOtlpOutcome::DeadlineExceeded));
            }
            ready.as_mut().poll(task).map(Ok)
        }).await;
        if let Err(outcome) = ready {
            return outcome;
        }
        if shared.aborted() {
            return ManagedOtlpOutcome::Aborted;
        }
        let Some(mut delivery) = shared.queue.take() else {
            return ManagedOtlpOutcome::Drained;
        };
        let timestamp = match &delivery.batch.as_ref().expect("owned delivery").payload {
            Payload::Metrics(_) => unix_time_nanos(),
            Payload::Logs(_) | Payload::Traces(_) => 1,
        };
        if timestamp == 0 {
            return ManagedOtlpOutcome::Failed(ExportError::new("otlp.queue.invalid_timestamp"));
        }
        // A caller-supplied clock can request cancellation or abort itself.
        // Refuse that already-stopped work before starting any transport; once
        // delivery starts, a validated acknowledgement keeps its precedence.
        if let Some(outcome) = owner_outcome(owner) {
            return outcome;
        }
        if cx.checkpoint().is_err() {
            return cancelled_outcome(cx);
        }
        if shared.aborted() {
            return ManagedOtlpOutcome::Aborted;
        }
        let mut aborted = std::pin::pin!(shared.queue.ready.wait_until(|| shared.aborted()));
        let mut send = std::pin::pin!(delivery.send(cx, timestamp));
        let sent = poll_fn(|task| {
            // Register before observing the explicit owner; its task can be
            // cancelled independently while our transport is parked.
            owner_cancel.refresh(task.waker());
            // Preserve a validated acknowledgement before a simultaneous abort.
            if let Poll::Ready(result) = send.as_mut().poll(task) {
                return Poll::Ready(result.map_err(|error| {
                    if let Some(outcome) = owner_outcome(owner) {
                        outcome
                    } else if cx.is_cancel_requested() {
                        cancelled_outcome(cx)
                    } else if cx.budget().is_past_deadline(cx.now()) {
                        ManagedOtlpOutcome::DeadlineExceeded
                    } else {
                        ManagedOtlpOutcome::Failed(error)
                    }
                }));
            }
            if let Some(outcome) = owner_outcome(owner) {
                return Poll::Ready(Err(outcome));
            }
            if aborted.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(ManagedOtlpOutcome::Aborted));
            }
            Poll::Pending
        }).await;
        if let Err(outcome) = sent {
            return outcome;
        }
    }
}

#[cfg(test)]
#[path = "queued_managed_tests.rs"]
mod tests;
