//! Resumable authenticated decoding over asynchronous symbol streams.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::session::{SYMBOLS_PER_POLL, SessionOperation, SessionState, SessionWait};
use super::{
    Cx, Error, ErrorKind, Metrics, ObjectParams, RaptorQReceiver, ReceiveOutcome, ReceiveState,
    SymbolStream, map_stream_error,
};
use crate::decoding::{BlockDecodeJob, BlockDecodeOutcome, run_block_decode_job};
use crate::runtime::JoinError;
use crate::runtime::spawn_blocking::DrainedBlockingHandle;

/// An authenticated receive whose decode progress survives a dropped wait.
///
/// [`run`](Self::run) borrows this session. Dropping the wait retains accepted
/// symbols and the decoder; a later wait continues with the same original [`Cx`]
/// and absolute deadline. Completion, cancellation, errors, and caught provider
/// panics are terminal. A successful result is delivered once.
///
/// All incoming symbols are verified before decode or object filtering. Up to
/// 32 stream items, including duplicates and other objects, are processed per
/// poll. By default, individual decoding steps remain synchronous on the polling
/// thread. [`RaptorQReceiver::start_receive_object_offloaded`] instead sends block
/// solves through the owner's blocking pool, with at most one job in flight.
pub struct RaptorQReceiveSession<'a, S> {
    source: &'a mut S,
    metrics: &'a mut Option<Metrics>,
    decode_job: Option<DrainedBlockingHandle<BlockDecodeOutcome>>,
    receive: Option<ReceiveState>,
    state: SessionState,
    symbols_received: usize,
    offloaded: bool,
}

impl<S: SymbolStream + Unpin> RaptorQReceiver<S> {
    /// Starts an authenticated asynchronous receive without polling the source.
    ///
    /// An explicit security context or configured authentication key is required;
    /// permissive and disabled modes do not weaken this API. The object parameters
    /// must describe the sender's object and be supplied through a trusted path.
    ///
    /// The session stops as soon as this object decodes. Extra repair symbols or
    /// subsequent objects remain in the source for the caller to route or drain.
    #[allow(clippy::result_large_err)]
    pub fn start_receive_object<'a>(
        &'a mut self,
        cx: &Cx,
        params: &ObjectParams,
    ) -> Result<RaptorQReceiveSession<'a, S>, Error> {
        let receive = ReceiveState::new(&self.config, self.security.as_ref(), params, true)?;
        Ok(RaptorQReceiveSession {
            source: &mut self.source,
            metrics: &mut self.metrics,
            decode_job: None,
            receive: Some(receive),
            state: SessionState::new(cx),
            symbols_received: 0,
            offloaded: false,
        })
    }

    /// Starts an authenticated receive that offloads block solves to the owning
    /// runtime's blocking pool.
    ///
    /// At most one owned decode job is admitted at a time. Source polling pauses
    /// while that job runs, bounding additional solve workspace and applying
    /// backpressure to the transport. Authentication, symbol intake, and final
    /// byte assembly still run on the polling thread. This does not parallelize
    /// independent blocks or change the full-object buffering contract.
    ///
    /// Dropping a borrowing wait retains the job and its result. Cancellation or
    /// dropping the session requests abort; a queued job can be fenced before
    /// execution. A matrix solve that has already started is not interruptible
    /// and runs to completion. Its runtime region continues to own the job until
    /// the closure and its captures retire, even after this session returns an
    /// error. Successful receive joins the actual job retirement.
    ///
    /// Requires a live blocking pool and runtime spawn authority on the original
    /// explicit `Cx`. Missing resources, forbidden blocking, or spawn/admission
    /// failure produce an error; decoding never falls back to running inline.
    #[allow(clippy::result_large_err)]
    pub fn start_receive_object_offloaded<'a>(
        &'a mut self,
        cx: &Cx,
        params: &ObjectParams,
    ) -> Result<RaptorQReceiveSession<'a, S>, Error> {
        let available = cx
            .blocking_pool_handle()
            .is_some_and(|pool| !pool.is_shutdown() && !pool.forbids_blocking());
        if !available
            || cx.spawn_gateway_handle().is_none()
            || cx.pending_spawn_counter_handle().is_none()
        {
            return Err(Error::new(ErrorKind::ConfigError).with_message(
                "offloaded RaptorQ receive requires an available runtime blocking pool and spawn authority",
            ));
        }
        let mut session = self.start_receive_object(cx, params)?;
        session.offloaded = true;
        Ok(session)
    }
}

impl<S: SymbolStream + Unpin> RaptorQReceiveSession<'_, S> {
    /// Continues this receive; dropping the wait retains all accepted decode state.
    pub fn run(&mut self) -> impl Future<Output = Result<ReceiveOutcome, Error>> + '_ {
        SessionWait::new(self)
    }

    /// Number of symbols accepted into the decode set so far.
    #[must_use]
    pub const fn symbols_received(&self) -> usize {
        self.symbols_received
    }

    /// Whether completion, failure, cancellation, or a panic made this session terminal.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.state.is_finished()
    }

    #[allow(clippy::result_large_err)]
    fn start_decode(&mut self, job: BlockDecodeJob) -> Result<(), Error> {
        debug_assert!(self.decode_job.is_none(), "one owned decode job per session");
        self.decode_job = Some(
            self.state
                .owner
                .spawn_blocking_drained(move |_child| run_block_decode_job(job))
                .map_err(|error| {
                    Error::new(ErrorKind::DispatchFailed)
                        .with_message(format!("RaptorQ decode worker admission failed: {error}"))
                        .with_source(error)
                })?,
        );
        Ok(())
    }
}

impl<S: SymbolStream + Unpin> SessionOperation for RaptorQReceiveSession<'_, S> {
    type Output = ReceiveOutcome;

    fn state(&mut self) -> &mut SessionState {
        &mut self.state
    }

    fn on_terminal(&mut self) {
        // Handle Drop requests abort, but the admitted runtime task still owns
        // queued/running work until actual pool retirement. Retaining a terminal
        // session must not postpone that cancellation request.
        self.decode_job = None;
    }

    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<ReceiveOutcome, Error>> {
        for _ in 0..SYMBOLS_PER_POLL {
            self.state.owner.checkpoint()?;
            if let Some(job) = &mut self.decode_job {
                // The handle owns all join state. Its documented borrowing join
                // may be dropped while pending, so a stack-pinned wait can be
                // recreated on the next session poll without losing the result.
                let result = {
                    let mut joining = std::pin::pin!(job.join());
                    joining.as_mut().poll(cx)
                };
                let outcome = match result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result.map_err(map_decode_join_error)?,
                };
                self.decode_job = None;
                let retry = self
                    .receive
                    .as_mut()
                    .expect("an active receive session owns a decoder")
                    .finish_deferred(outcome, self.metrics)?;
                if let Some(retry) = retry {
                    self.start_decode(retry)?;
                    continue;
                }
            }
            let receive = self
                .receive
                .as_mut()
                .expect("an active receive session owns a decoder");
            if receive.is_complete() {
                return Poll::Ready(
                    self.receive
                        .take()
                        .expect("completed decoder is consumed once")
                        .finish(self.metrics),
                );
            }
            match Pin::new(&mut *self.source).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Err(receive.insufficient_symbols())),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(map_stream_error(error))),
                Poll::Ready(Some(Ok(symbol))) => {
                    // Preserve a delivered symbol through verification/decode
                    // before checking cancellation at the next boundary.
                    let job = if self.offloaded {
                        receive.accept_deferred(symbol, self.metrics)?
                    } else {
                        receive.accept(symbol, self.metrics)?;
                        None
                    };
                    self.symbols_received = receive.symbols_received();
                    if let Some(job) = job {
                        self.start_decode(job)?;
                    }
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

fn map_decode_join_error(error: JoinError) -> Error {
    let kind = match &error {
        JoinError::Cancelled(reason) => return Error::cancelled(reason).with_source(error),
        JoinError::Panicked(_) => ErrorKind::OperationFailed,
        JoinError::PolledAfterCompletion => ErrorKind::InvalidStateTransition,
    };
    Error::new(kind)
        .with_message(format!("RaptorQ decode worker failed: {error}"))
        .with_source(error)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "receive_offload_tests.rs"]
mod offload_tests;
