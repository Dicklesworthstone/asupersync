//! Owner-bound, resumable work for the authenticated whole-message channel.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use super::{
    AuthenticatedEcEnvelope, AuthenticatedEcError, AuthenticatedEcPermit, AuthenticatedEcReceiver,
    AuthenticatedEcSender, EcError, decode_authenticated_envelope, serialize_bounded,
};
use crate::channel::{OwnedCancelRegistration, mpsc};
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

// A completed codec/deserializer result consumes its envelope when delivered.
// Admission, cancellation and worker failures are outside this tagged result,
// leaving the receiver's retained envelope available to a subsequent receive.
struct DecodeCompletion<T> {
    result: Result<T, AuthenticatedEcError>,
}

type DecodeTransform<T> = fn(Vec<u8>) -> Result<T, AuthenticatedEcError>;

/// An authenticated receive whose verification and coding run on a worker.
///
/// Create one with [`AuthenticatedEcReceiver::start_recv_offloaded`] or
/// [`AuthenticatedEcReceiver::start_recv_value_offloaded`]. Dropping the
/// borrowing [`run`](Self::run) wait retains its worker and result; another
/// wait continues the same operation. Dropping the session requests worker
/// abort and leaves an accepted envelope in the receiver. Cancellation, worker
/// admission failure and worker panic also retain that envelope for the next
/// inline or offloaded receive, ahead of later messages.
///
/// A completed authentication, coding or JSON error consumes the rejected
/// envelope when delivered, allowing subsequent messages to proceed. Delivery
/// checks the original explicit [`Cx`] and its absolute deadline after joining
/// the worker. Workers inherit its budget but not its cancellation mask. A
/// session is terminal after completion, failure, cancellation or a panic.
///
/// One private worker slot bounds each receiver's offloaded decode workspace
/// and undelivered result, including abandoned work. The slot is acquired
/// before dequeuing, and retained until the worker's resources retire. A
/// running matrix solve or deserializer cannot be preempted. The retained
/// envelope shares its symbol storage with that worker; queue entries, inline
/// decoding and returned values are separate memory costs.
///
/// Retrying through a new session can repeat verification, decoding and user
/// deserialization. Only a dropped borrowing wait preserves the same work;
/// deserializer side effects do not have an exactly-once guarantee.
#[must_use = "run the receive session or drop it to leave the message available"]
pub struct AuthenticatedEcReceiveSession<'a, T = Vec<u8>> {
    worker: Option<
        DrainedBlockingHandle<LeasedResult<Result<DecodeCompletion<T>, AuthenticatedEcError>>>,
    >,
    slot: Option<OwnedAcquireFuture>,
    lease: Option<OwnedSemaphorePermit>,
    receiver: &'a mut AuthenticatedEcReceiver,
    transform: DecodeTransform<T>,
    state: SessionState,
}

impl<T> std::fmt::Debug for AuthenticatedEcReceiveSession<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedEcReceiveSession")
            .field("worker", &self.worker)
            .field("pending", &self.receiver.pending.is_some())
            .field("finished", &self.state.is_finished())
            .finish_non_exhaustive()
    }
}

impl AuthenticatedEcReceiver {
    /// Prepares an offloaded receive without dequeuing or dispatching work.
    ///
    /// Verification, authenticated geometry checks and decoding all run on the
    /// explicit context's blocking pool. A missing or forbidden pool is an
    /// error; decoding never falls back to the polling thread. Retain the
    /// returned session to pause and resume a wait without repeating work.
    pub fn start_recv_offloaded(
        &mut self,
        cx: &Cx,
    ) -> Result<AuthenticatedEcReceiveSession<'_>, AuthenticatedEcError> {
        self.with_decode(cx, Ok)
    }

    /// Receives verified bytes using the context's blocking pool.
    ///
    /// Dropping this convenience future requests worker abort and retains an
    /// accepted envelope for the next receive. Use [`Self::start_recv_offloaded`]
    /// when the current decoding work must survive a dropped wait.
    pub async fn recv_offloaded(&mut self, cx: &Cx) -> Result<Vec<u8>, AuthenticatedEcError> {
        self.start_recv_offloaded(cx)?.run().await
    }

    /// Prepares verification, decoding and JSON deserialization on one worker.
    ///
    /// Deserialization runs only after authentication and payload-digest
    /// verification succeed. Dropping a borrowing session wait never repeats
    /// it, but abandoning an entire session can cause a later receive to invoke
    /// it again. Returned values and user deserializer allocations are outside
    /// the encoded-message storage bound.
    pub fn start_recv_value_offloaded<T: serde::de::DeserializeOwned + Send + 'static>(
        &mut self,
        cx: &Cx,
    ) -> Result<AuthenticatedEcReceiveSession<'_, T>, AuthenticatedEcError> {
        self.with_decode(cx, |bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|error| EcError::Serialization(error.to_string()).into())
        })
    }

    /// Receives and deserializes an authenticated value on a blocking worker.
    pub async fn recv_value_offloaded<T: serde::de::DeserializeOwned + Send + 'static>(
        &mut self,
        cx: &Cx,
    ) -> Result<T, AuthenticatedEcError> {
        self.start_recv_value_offloaded(cx)?.run().await
    }

    fn with_decode<T: Send + 'static>(
        &mut self,
        cx: &Cx,
        transform: DecodeTransform<T>,
    ) -> Result<AuthenticatedEcReceiveSession<'_, T>, AuthenticatedEcError> {
        checkpoint(cx)?;
        require_worker(cx)?;
        let slot = OwnedAcquireFuture::new_uncancelable(Arc::clone(&self.offload), 1);
        Ok(AuthenticatedEcReceiveSession {
            worker: None,
            slot: Some(slot),
            lease: None,
            receiver: self,
            transform,
            state: SessionState::new(cx),
        })
    }
}

impl<T> AuthenticatedEcReceiveSession<'_, T> {
    /// Whether completion, failure, cancellation or a panic made this session terminal.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_finished()
    }

    fn clear_operation(&mut self) {
        // Detach state before any waker or result destructor can call user code.
        // The receiver retains the envelope unless delivery already consumed it.
        let worker = self.worker.take();
        let slot = self.slot.take();
        let lease = self.lease.take();
        self.receiver.rx.clear_recv_waker();
        drop(slot);
        drop(lease);
        drop(worker);
    }
}

impl<T: Send + 'static> AuthenticatedEcReceiveSession<'_, T> {
    /// Continues the original receive without losing work when this wait is dropped.
    pub fn run(&mut self) -> impl Future<Output = Result<T, AuthenticatedEcError>> + '_ {
        SessionWait::new(self)
    }
}

impl<T> Drop for AuthenticatedEcReceiveSession<'_, T> {
    fn drop(&mut self) {
        self.clear_operation();
    }
}

impl<T: Send + 'static> SessionOperation for AuthenticatedEcReceiveSession<'_, T> {
    type Output = T;

    fn state(&mut self) -> &mut SessionState {
        &mut self.state
    }

    fn on_terminal(&mut self) {
        self.clear_operation();
    }

    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, AuthenticatedEcError>> {
        if self.worker.is_none() {
            if self.lease.is_none() {
                let slot = self
                    .slot
                    .as_mut()
                    .expect("an unstarted receive owns its worker-slot wait");
                let lease = match Pin::new(slot).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result.map_err(|_| {
                        AuthenticatedEcError::WorkerFailed("decoding slot closed unexpectedly")
                    })?,
                };
                self.slot = None;
                self.lease = Some(lease);
            }
            checkpoint(&self.state.owner)?;
            require_worker(&self.state.owner)?;
            if self.receiver.pending.is_none() {
                let message = match self.receiver.rx.poll_recv(&self.state.owner, cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result.map_err(|error| match error {
                        mpsc::RecvError::Cancelled => EcError::Cancelled,
                        mpsc::RecvError::Disconnected | mpsc::RecvError::Empty => {
                            EcError::TransportClosed
                        }
                    })?,
                };
                self.receiver.pending = Some(Arc::new(message));
            }
            checkpoint(&self.state.owner)?;
            let message = Arc::clone(
                self.receiver
                    .pending
                    .as_ref()
                    .expect("an admitted receive retains its envelope until delivery"),
            );
            let config = self.receiver.config;
            let auth = self.receiver.auth.clone();
            let transform = self.transform;
            let work = LeasedWork {
                work: move |child: Cx| {
                    checkpoint(&child)?;
                    let decoded = decode_authenticated_envelope(&config, &auth, &message);
                    checkpoint(&child)?;
                    let result = decoded.and_then(transform);
                    checkpoint(&child)?;
                    Ok(DecodeCompletion { result })
                },
                lease: self
                    .lease
                    .take()
                    .expect("a receive dispatch owns its worker slot"),
            };
            self.worker = Some(
                self.state
                    .owner
                    .spawn_blocking_drained(move |child| work.run(child))
                    .map_err(AuthenticatedEcError::WorkerAdmission)?,
            );
        }
        let joined = {
            let job = self.worker.as_mut().expect("decoding was dispatched once");
            let mut waiting = std::pin::pin!(job.join());
            waiting.as_mut().poll(cx)
        };
        let result = match joined {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result.map_err(worker_join_error)?,
        };
        self.worker = None;
        // Outer errors preserve the envelope. A completed codec/JSON result
        // consumes it only after the receiving owner's final checkpoint, so a
        // cancellation result can never silently advance to the next message.
        let completion = result.result?;
        checkpoint(&self.state.owner)?;
        self.receiver.pending = None;
        Poll::Ready(completion.result)
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
