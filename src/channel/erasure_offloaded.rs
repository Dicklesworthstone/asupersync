//! Owner-bound, resumable work for the authenticated whole-message channel.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use super::{
    AuthenticatedEcEnvelope, AuthenticatedEcError, AuthenticatedEcPermit, AuthenticatedEcSender,
    EcError, serialize_bounded,
};
use crate::channel::OwnedCancelRegistration;
use crate::cx::Cx;
use crate::runtime::spawn_blocking::DrainedBlockingHandle;
use crate::runtime::{JoinError, SpawnError};
use crate::sync::semaphore::{OwnedAcquireFuture, OwnedSemaphorePermit};
use crate::time::Sleep;

type EncodeWork =
    Box<dyn FnOnce(Cx) -> Result<AuthenticatedEcEnvelope, AuthenticatedEcError> + Send>;

// Declaration order is intentional: abandoned input/results must be destroyed
// before releasing the slot and waking the next admitted operation. Capture
// this entire object through run(), not its fields as independent captures.
struct LeasedWork<F> {
    work: F,
    lease: OwnedSemaphorePermit,
}

struct LeasedResult<T> {
    result: T,
    _lease: OwnedSemaphorePermit,
}

impl<F, T> LeasedWork<F>
where
    F: FnOnce(Cx) -> T,
{
    fn run(self, cx: Cx) -> LeasedResult<T> {
        LeasedResult {
            result: (self.work)(cx),
            _lease: self.lease,
        }
    }
}

/// A checked whole-message send whose coding runs on a blocking worker.
///
/// Create one with [`AuthenticatedEcSender::start_send_offloaded`] or
/// [`AuthenticatedEcPermit::start_send_offloaded`], then await [`run`](Self::run).
/// Dropping a borrowing wait retains the reserved capacity, worker and result;
/// another wait resumes the same operation without encoding or publishing twice.
/// Dropping the session aborts the send obligation and requests worker abort.
/// Nothing is published until the complete envelope is ready and the original
/// context passes its final checkpoint. Success means local atomic publication,
/// not receiver acknowledgement or durable storage.
///
/// A private slot allows at most one offloaded encoding input/workspace/result
/// per sender, including abandoned work. A successor waits for that slot even
/// if cancellation has returned the previous message's queue reservation.
/// Queue entries, caller-owned input waiting for admission, and inline coding
/// are separate memory costs. A running matrix solve or serializer cannot be
/// preempted; its region retains ownership through actual worker retirement.
///
/// The original explicit [`Cx`] owns waits, cancellation and the absolute
/// deadline. Workers inherit its budget, but not its cancellation mask.
/// Cancellation, failure, completion and caught provider panics are terminal.
pub struct AuthenticatedEcSendSession<'a> {
    worker: Option<
        DrainedBlockingHandle<LeasedResult<Result<AuthenticatedEcEnvelope, AuthenticatedEcError>>>,
    >,
    work: Option<EncodeWork>,
    slot: Option<OwnedAcquireFuture>,
    permit: Option<AuthenticatedEcPermit<'a>>,
    state: SessionState,
}

impl std::fmt::Debug for AuthenticatedEcSendSession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedEcSendSession")
            .field("worker", &self.worker)
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

impl AuthenticatedEcSender {
    /// Reserves a message slot and prepares an owned, offloaded send.
    ///
    /// Capacity and the send obligation are admitted before any encoding.
    /// Construction does not dispatch a worker; [`AuthenticatedEcSendSession::run`]
    /// does. Dropping this constructor while it waits for capacity publishes
    /// nothing and drops the supplied input. Keep the returned session to pause
    /// and resume a send by dropping its borrowing wait.
    pub async fn start_send_offloaded<'a>(
        &'a mut self,
        cx: &'a Cx,
        message: Vec<u8>,
    ) -> Result<AuthenticatedEcSendSession<'a>, AuthenticatedEcError> {
        checkpoint(cx)?;
        self.config.plan(message.len())?;
        require_worker(cx)?;
        self.reserve(cx).await?.start_send_offloaded(message)
    }

    /// Encodes owned bytes off-thread and atomically publishes one message.
    ///
    /// Dropping this convenience future abandons the operation. Use
    /// [`Self::start_send_offloaded`] when a dropped wait must be resumable.
    pub async fn send_offloaded(
        &mut self,
        cx: &Cx,
        message: Vec<u8>,
    ) -> Result<u64, AuthenticatedEcError> {
        self.start_send_offloaded(cx, message).await?.run().await
    }

    /// Reserves capacity before serializing and encoding an owned value off-thread.
    ///
    /// The same bounded JSON writer as [`Self::send_value`] enforces the message
    /// size limit. Neither serialization nor encoding runs while capacity or the
    /// endpoint's previous worker is being awaited.
    pub async fn start_send_value_offloaded<'a, T: serde::Serialize + Send + 'static>(
        &'a mut self,
        cx: &'a Cx,
        value: T,
    ) -> Result<AuthenticatedEcSendSession<'a>, AuthenticatedEcError> {
        checkpoint(cx)?;
        require_worker(cx)?;
        self.reserve(cx).await?.start_send_value_offloaded(value)
    }

    /// Serializes and encodes an owned value on a worker, then publishes it.
    pub async fn send_value_offloaded<T: serde::Serialize + Send + 'static>(
        &mut self,
        cx: &Cx,
        value: T,
    ) -> Result<u64, AuthenticatedEcError> {
        self.start_send_value_offloaded(cx, value)
            .await?
            .run()
            .await
    }
}

impl<'a> AuthenticatedEcPermit<'a> {
    /// Prepares an offloaded send under this existing checked reservation.
    ///
    /// The input moves into the session without a whole-message copy. A missing
    /// or forbidden blocking pool is an error; there is no inline fallback.
    pub fn start_send_offloaded(
        self,
        message: Vec<u8>,
    ) -> Result<AuthenticatedEcSendSession<'a>, AuthenticatedEcError> {
        checkpoint(self.cx)?;
        self.config.plan(message.len())?;
        require_worker(self.cx)?;
        let config = self.config;
        let auth = self.auth.clone();
        let message_id = self.message_id;
        Ok(self.with_work(Box::new(move |child| {
            checkpoint(&child)?;
            let (header, symbols) =
                config.encode_message_authenticated(message_id, &message, &auth)?;
            checkpoint(&child)?;
            Ok(AuthenticatedEcEnvelope { header, symbols })
        })))
    }

    /// Moves serialization and authenticated encoding onto the worker.
    pub fn start_send_value_offloaded<T: serde::Serialize + Send + 'static>(
        self,
        value: T,
    ) -> Result<AuthenticatedEcSendSession<'a>, AuthenticatedEcError> {
        checkpoint(self.cx)?;
        require_worker(self.cx)?;
        let config = self.config;
        let auth = self.auth.clone();
        let message_id = self.message_id;
        Ok(self.with_work(Box::new(move |child| {
            checkpoint(&child)?;
            let message = serialize_bounded(&value, config.max_message_size)?;
            checkpoint(&child)?;
            let (header, symbols) =
                config.encode_message_authenticated(message_id, &message, &auth)?;
            checkpoint(&child)?;
            Ok(AuthenticatedEcEnvelope { header, symbols })
        })))
    }

    fn with_work(self, work: EncodeWork) -> AuthenticatedEcSendSession<'a> {
        let state = SessionState::new(self.cx);
        // This private resource lease is not a second user-visible obligation.
        // The checked MPSC permit owns publication, the runtime owns the worker,
        // and SessionWait supplies cancellation/deadline wakeups for this slot.
        let slot = OwnedAcquireFuture::new_uncancelable(Arc::clone(self.offload), 1);
        AuthenticatedEcSendSession {
            worker: None,
            work: Some(work),
            slot: Some(slot),
            permit: Some(self),
            state,
        }
    }
}

impl AuthenticatedEcSendSession<'_> {
    /// Continues the original send; dropping the wait retains its progress.
    pub fn run(&mut self) -> impl Future<Output = Result<u64, AuthenticatedEcError>> + '_ {
        SessionWait::new(self)
    }

    /// Whether the session has completed, failed, acknowledged cancellation or panicked.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_finished()
    }
}

impl SessionOperation for AuthenticatedEcSendSession<'_> {
    type Output = u64;

    fn state(&mut self) -> &mut SessionState {
        &mut self.state
    }

    fn on_terminal(&mut self) {
        self.worker = None;
        self.work = None;
        self.slot = None;
        self.permit = None;
    }

    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, AuthenticatedEcError>> {
        if self.worker.is_none() {
            let slot = self
                .slot
                .as_mut()
                .expect("an unstarted send owns its worker-slot wait");
            let lease = match Pin::new(slot).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result.map_err(|_| {
                    AuthenticatedEcError::WorkerFailed("encoding slot closed unexpectedly")
                })?,
            };
            self.slot = None;
            checkpoint(&self.state.owner)?;
            require_worker(&self.state.owner)?;
            let work = LeasedWork {
                work: self
                    .work
                    .take()
                    .expect("an unstarted send owns its encoding input"),
                lease,
            };
            self.worker = Some(
                self.state
                    .owner
                    .spawn_blocking_drained(move |child| work.run(child))
                    .map_err(AuthenticatedEcError::WorkerAdmission)?,
            );
        }
        let joined = {
            let job = self.worker.as_mut().expect("encoding was dispatched once");
            let mut waiting = std::pin::pin!(job.join());
            waiting.as_mut().poll(cx)
        };
        let result = match joined {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result.map_err(worker_join_error)?,
        };
        self.worker = None;
        // The partially moved result retains its lease through publication or
        // destruction of the envelope on a failed final checkpoint.
        let envelope = result.result?;
        checkpoint(&self.state.owner)?;
        let permit = self
            .permit
            .take()
            .expect("publication consumes the reservation once");
        Poll::Ready(permit.publish(envelope))
    }
}

fn checkpoint(cx: &Cx) -> Result<(), AuthenticatedEcError> {
    cx.checkpoint().map_err(|_| EcError::Cancelled.into())
}

fn require_worker(cx: &Cx) -> Result<(), AuthenticatedEcError> {
    let available = cx
        .blocking_pool_handle()
        .is_some_and(|pool| !pool.is_shutdown() && !pool.forbids_blocking());
    if available
        && cx.spawn_gateway_handle().is_some()
        && cx.pending_spawn_counter_handle().is_some()
    {
        Ok(())
    } else {
        Err(AuthenticatedEcError::WorkerAdmission(
            SpawnError::RuntimeUnavailable,
        ))
    }
}

fn worker_join_error(error: JoinError) -> AuthenticatedEcError {
    match error {
        JoinError::Cancelled(_) => EcError::Cancelled.into(),
        JoinError::Panicked(_) => AuthenticatedEcError::WorkerFailed("coding worker panicked"),
        JoinError::PolledAfterCompletion => {
            AuthenticatedEcError::InvalidSession("worker result already consumed")
        }
    }
}

struct SessionState {
    owner: Cx,
    error: Option<AuthenticatedEcError>,
    complete: bool,
    poisoned: bool,
}

impl SessionState {
    fn new(owner: &Cx) -> Self {
        Self {
            owner: owner.clone(),
            error: None,
            complete: false,
            poisoned: false,
        }
    }

    fn is_finished(&self) -> bool {
        self.complete || self.error.is_some() || self.poisoned
    }

    fn previous_error(&self) -> Option<AuthenticatedEcError> {
        self.error.clone().or_else(|| {
            if self.poisoned {
                Some(AuthenticatedEcError::InvalidSession(
                    "a session callback panicked",
                ))
            } else if self.complete {
                Some(AuthenticatedEcError::InvalidSession(
                    "session already completed",
                ))
            } else {
                None
            }
        })
    }
}

trait SessionOperation {
    type Output;
    fn state(&mut self) -> &mut SessionState;
    fn poll_progress(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Output, AuthenticatedEcError>>;
    fn on_terminal(&mut self);
}

struct SessionWait<'a, O: SessionOperation> {
    operation: &'a mut O,
    cancellation: OwnedCancelRegistration,
    deadline: Option<Pin<Box<Sleep>>>,
    completed: bool,
}

impl<'a, O: SessionOperation> SessionWait<'a, O> {
    fn new(operation: &'a mut O) -> Self {
        let owner = operation.state().owner.clone();
        let deadline = owner.budget_deadline_sleep().map(Box::pin);
        Self {
            operation,
            cancellation: OwnedCancelRegistration::new(owner),
            deadline,
            completed: false,
        }
    }
}

impl<O: SessionOperation> Future for SessionWait<'_, O> {
    type Output = Result<O::Output, AuthenticatedEcError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(AuthenticatedEcError::InvalidSession(
                "wait already completed",
            )));
        }
        if let Some(error) = this.operation.state().previous_error() {
            this.completed = true;
            this.operation.on_terminal();
            this.cancellation.clear();
            this.deadline = None;
            return Poll::Ready(Err(error));
        }
        // An arbitrary callback may unwind after an effect. Keep this poisoned
        // through all provider calls so a caught panic can never replay it.
        this.operation.state().poisoned = true;
        let owner = this.cancellation.cx().clone();
        let _current = owner.clone().set_current_restricted();
        this.cancellation.refresh(cx.waker());
        if let Some(deadline) = &mut this.deadline {
            if deadline.as_mut().poll_deadline(cx).is_ready() {
                this.deadline = None;
            }
        }
        let result = match checkpoint(&owner) {
            Ok(()) => this.operation.poll_progress(cx),
            Err(error) => Poll::Ready(Err(error)),
        };
        let state = this.operation.state();
        state.poisoned = false;
        match &result {
            Poll::Ready(Ok(_)) => state.complete = true,
            Poll::Ready(Err(error)) => state.error = Some(error.clone()),
            Poll::Pending => {}
        }
        if result.is_ready() {
            this.completed = true;
            this.operation.on_terminal();
            this.cancellation.clear();
            this.deadline = None;
        }
        result
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "erasure_offloaded_tests.rs"]
mod tests;
