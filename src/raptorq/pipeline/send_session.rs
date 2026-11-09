//! Resumable sends over asynchronous symbol sinks.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::session::{SYMBOLS_PER_POLL, SessionOperation, SessionState, SessionWait};
use super::{
    AuthenticatedSymbol, Cx, Error, ErrorKind, Metrics, ObjectId, RaptorQSender, SecurityContext,
    SendOutcome, SymbolSink, prepare_encoder, required_security,
};
use crate::config::RaptorQConfig;
use crate::encoding::{EncodingIterator, OwnedEncodingIterator};
use crate::runtime::JoinError;
use crate::runtime::spawn_blocking::DrainedBlockingHandle;
use crate::transport::error::SinkError;
use crate::types::symbol::SymbolKind;

// Bound generated payload waiting on the transport independently of the
// configured symbol size. Input, the pool, and matrix workspace are separate.
const ENCODE_BATCH_BYTES: usize = 64 * 1024;

/// An authenticated object send whose progress survives dropping a borrowing wait.
///
/// Obtain this session with [`RaptorQSender::start_send_object`] and await
/// [`run`](Self::run). Dropping that wait pauses the operation; another `run`
/// continues the same encoder, pending symbol, and flush. Dropping the session
/// abandons the remaining work; symbols already accepted by the sink cannot be
/// retracted. The sender remains exclusively borrowed until the session drops.
///
/// The original explicit [`Cx`] owns cancellation and its absolute deadline.
/// Cancellation, an error, successful completion, or a caught provider panic is
/// terminal. A later wait cannot replace that owner or replay the operation.
/// Progress is bounded to 32 symbols per poll; each encoding step still runs
/// synchronously on the polling thread. Use
/// [`RaptorQSender::start_send_object_offloaded`] to move encoding and signing
/// to owned blocking jobs instead.
pub struct RaptorQSendSession<'a, T> {
    encoder: EncodingIterator<'a>,
    core: SendCore<'a, T>,
    object_id: ObjectId,
    source_symbols: usize,
    repair_symbols: usize,
}

/// A resumable send of pre-encoded symbols, strictly verified before dispatch.
///
/// The iterator and any pending symbol belong to this session, so dropping
/// [`run`](Self::run) does not advance or reconstruct them. The same owner,
/// terminal-state, and flush guarantees as [`RaptorQSendSession`] apply.
pub struct RaptorQSymbolSendSession<'a, T, I> {
    symbols: I,
    core: SendCore<'a, T>,
}

/// An authenticated send that encodes and signs bounded batches off-thread.
///
/// Created by [`RaptorQSender::start_send_object_offloaded`]. The session owns
/// the input and retains one incremental encoder across worker jobs. At most
/// one job is in flight; no new job starts until the current batch has been
/// accepted by the sink. A blocked sink therefore retains at most 32 symbols
/// and 64 KiB of encoded payload without occupying a blocking worker.
///
/// Dropping [`run`](Self::run) pauses the wait, preserving the job, batch,
/// pending symbol, counters, and flush. Dropping the session or reaching a
/// terminal error requests abort of any queued/running job. An active matrix
/// solve cannot be interrupted; its region owns the work through retirement.
/// The original explicit [`Cx`] owns every wait, deadline, and worker job.
/// Workers inherit its budget but have their own cancellation state: a mask
/// on the session owner does not mask a child worker's deadline or cancellation.
///
/// The output bound does not bound the owned input, configured symbol pool,
/// or current block's matrix workspace. No remote acknowledgement is implied
/// by successful local sink acceptance and flush.
pub struct RaptorQOffloadedSendSession<'a, T> {
    encode_job: Option<DrainedBlockingHandle<Result<EncodeBatch, Error>>>,
    encoder: Option<OwnedEncodingIterator>,
    initial: Option<(RaptorQConfig, Vec<u8>)>,
    batch: VecDeque<Result<AuthenticatedSymbol, Error>>,
    batch_limit: usize,
    core: SendCore<'a, T>,
    object_id: ObjectId,
    source_symbols: usize,
    repair_symbols: usize,
}

struct EncodeBatch {
    encoder: OwnedEncodingIterator,
    symbols: VecDeque<Result<AuthenticatedSymbol, Error>>,
    exhausted: bool,
}

struct SendCore<'a, T> {
    transport: &'a mut T,
    metrics: &'a mut Option<Metrics>,
    security: SecurityContext,
    state: SessionState,
    pending: Option<AuthenticatedSymbol>,
    exhausted: bool,
    sent: usize,
}

impl<T: SymbolSink + Unpin> RaptorQSender<T> {
    /// Starts an asynchronous authenticated object send without polling the sink.
    ///
    /// Requires an explicit security context or a configured authentication key.
    /// The session signs every symbol regardless of the legacy authentication
    /// mode. Production callers should supply externally generated key material
    /// through the builder's security context.
    ///
    /// Awaiting [`RaptorQSendSession::run`] succeeds only after all symbols have
    /// been accepted and the sink has flushed. This is local transport completion;
    /// it does not acknowledge remote decoding or durable storage. Object
    /// parameters must be communicated to the receiver separately.
    #[allow(clippy::result_large_err)]
    pub fn start_send_object<'a>(
        &'a mut self,
        cx: &Cx,
        object_id: ObjectId,
        data: &'a [u8],
    ) -> Result<RaptorQSendSession<'a, T>, Error> {
        let security = required_security(&self.config, self.security.as_ref())?;
        self.async_encoder = Some(prepare_encoder(&self.config, data.len())?);
        let encoder = self
            .async_encoder
            .as_mut()
            .expect("encoder installed before creating a send session")
            .encode(object_id, data);
        Ok(RaptorQSendSession {
            encoder,
            core: SendCore::new(&mut self.transport, &mut self.metrics, security, cx),
            object_id,
            source_symbols: 0,
            repair_symbols: 0,
        })
    }

    /// Starts a send with encoding and signing on the owner's blocking pool.
    ///
    /// Consumes the input buffer without copying it. Construction is inert:
    /// pool buffers, the block plan, repair matrices, and authenticated batches
    /// are created only after a worker is admitted by the first `run` wait.
    /// Subsequent jobs resume the same encoder instead of rebuilding its current
    /// matrix. Each job generates at most 32 symbols and 64 KiB of payload.
    ///
    /// A live blocking pool and runtime spawn authority are required. Forbidden
    /// blocking, unavailable resources, authorization refusal, or admission
    /// failure return an error; there is no inline or detached-thread fallback.
    /// Authentication is mandatory even when legacy modes are permissive.
    ///
    /// Dropped waits retain progress. Observed cancellation stops further
    /// dispatch and requests abort; a worker checks cancellation between symbols,
    /// while a matrix solve already in progress must return before its region
    /// can drain. Workers inherit the budget, not the owner's cancellation mask:
    /// a masked owner can still observe a cancelled or deadline-expired worker.
    /// Success joins each worker's retirement and then flushes the local sink.
    /// It does not prove receiver decoding or durable storage. Supply matching
    /// object parameters to the receiver through a trusted path.
    #[allow(clippy::result_large_err)]
    pub fn start_send_object_offloaded<'a>(
        &'a mut self,
        cx: &Cx,
        object_id: ObjectId,
        data: Vec<u8>,
    ) -> Result<RaptorQOffloadedSendSession<'a, T>, Error> {
        let available = cx
            .blocking_pool_handle()
            .is_some_and(|pool| !pool.is_shutdown() && !pool.forbids_blocking());
        if !available
            || cx.spawn_gateway_handle().is_none()
            || cx.pending_spawn_counter_handle().is_none()
        {
            return Err(Error::new(ErrorKind::ConfigError).with_message(
                "offloaded RaptorQ send requires an available runtime blocking pool and spawn authority",
            ));
        }
        let security = required_security(&self.config, self.security.as_ref())?;
        let symbol_bytes = usize::from(self.config.encoding.symbol_size).max(1);
        let batch_limit = SYMBOLS_PER_POLL.min(ENCODE_BATCH_BYTES / symbol_bytes);
        Ok(RaptorQOffloadedSendSession {
            encode_job: None,
            encoder: None,
            initial: Some((self.config.clone(), data)),
            batch: VecDeque::new(),
            batch_limit,
            core: SendCore::new(&mut self.transport, &mut self.metrics, security, cx),
            object_id,
            source_symbols: 0,
            repair_symbols: 0,
        })
    }

    /// Starts an asynchronous send of already encoded, authenticated symbols.
    ///
    /// Every input tag is verified against this sender's configured or explicit
    /// key, even if the symbol claims it was previously verified. Invalid or
    /// zero tags fail before that symbol reaches the sink. The input iterator is
    /// consumed incrementally; the returned count includes only sink acceptance,
    /// and success additionally requires a successful flush.
    #[allow(clippy::result_large_err)]
    pub fn start_send_symbols<'a, I>(
        &'a mut self,
        cx: &Cx,
        symbols: I,
    ) -> Result<RaptorQSymbolSendSession<'a, T, I::IntoIter>, Error>
    where
        I: IntoIterator<Item = AuthenticatedSymbol>,
    {
        let security = required_security(&self.config, self.security.as_ref())?;
        Ok(RaptorQSymbolSendSession {
            symbols: symbols.into_iter(),
            core: SendCore::new(&mut self.transport, &mut self.metrics, security, cx),
        })
    }
}

impl<T: SymbolSink + Unpin> RaptorQSendSession<'_, T> {
    /// Continues this session, retaining all progress if the returned wait drops.
    pub fn run(&mut self) -> impl Future<Output = Result<SendOutcome, Error>> + '_ {
        SessionWait::new(self)
    }

    /// Number of symbols accepted by the sink, including a partially sent object.
    #[must_use]
    pub const fn symbols_sent(&self) -> usize {
        self.core.sent
    }

    /// Whether completion, failure, cancellation, or a panic made this session terminal.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.core.state.is_finished()
    }
}

impl<T, I> RaptorQSymbolSendSession<'_, T, I>
where
    T: SymbolSink + Unpin,
    I: Iterator<Item = AuthenticatedSymbol>,
{
    /// Continues this session, retaining iterator and transport progress on drop.
    pub fn run(&mut self) -> impl Future<Output = Result<usize, Error>> + '_ {
        SessionWait::new(self)
    }

    /// Number of symbols accepted by the sink so far.
    #[must_use]
    pub const fn symbols_sent(&self) -> usize {
        self.core.sent
    }

    /// Whether completion, failure, cancellation, or a panic made this session terminal.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.core.state.is_finished()
    }
}

impl<T: SymbolSink + Unpin> SessionOperation for RaptorQSendSession<'_, T> {
    type Output = SendOutcome;

    fn state(&mut self) -> &mut SessionState {
        &mut self.core.state
    }

    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<SendOutcome, Error>> {
        for _ in 0..SYMBOLS_PER_POLL {
            self.core.state.owner.checkpoint()?;
            if self.core.pending.is_none() && !self.core.exhausted {
                match self.encoder.next() {
                    Some(encoded) => {
                        let symbol = encoded.map_err(Error::from)?.into_symbol();
                        self.core.pending = Some(self.core.security.sign_symbol(&symbol));
                    }
                    None => self.core.exhausted = true,
                }
            }
            if self.core.exhausted {
                return self.core.poll_flush(cx).map_ok(|()| {
                    if let Some(metrics) = self.core.metrics {
                        metrics.counter("raptorq.objects_sent").increment();
                    }
                    SendOutcome {
                        object_id: self.object_id,
                        source_symbols: self.source_symbols,
                        repair_symbols: self.repair_symbols,
                        symbols_sent: self.core.sent,
                    }
                });
            }
            let kind = self.core.pending.as_ref().map(|symbol| symbol.symbol().kind());
            match self.core.poll_pending(cx)? {
                Poll::Ready(()) => match kind {
                    Some(SymbolKind::Source) => self.source_symbols += 1,
                    Some(SymbolKind::Repair) => self.repair_symbols += 1,
                    None => unreachable!("a symbol is staged before polling the sink"),
                },
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<T, I> SessionOperation for RaptorQSymbolSendSession<'_, T, I>
where
    T: SymbolSink + Unpin,
    I: Iterator<Item = AuthenticatedSymbol>,
{
    type Output = usize;

    fn state(&mut self) -> &mut SessionState {
        &mut self.core.state
    }

    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, Error>> {
        for _ in 0..SYMBOLS_PER_POLL {
            self.core.state.owner.checkpoint()?;
            if self.core.pending.is_none() && !self.core.exhausted {
                match self.symbols.next() {
                    Some(mut symbol) => {
                        if let Err(error) = self.core.security.verify_authenticated_symbol(&mut symbol) {
                            if let Some(metrics) = self.core.metrics {
                                metrics.counter("raptorq.auth_rejected").increment();
                            }
                            return Poll::Ready(Err(Error::new(ErrorKind::CorruptedSymbol)
                                .with_message(error.to_string())));
                        }
                        self.core.pending = Some(symbol);
                    }
                    None => self.core.exhausted = true,
                }
            }
            if self.core.exhausted {
                return self.core.poll_flush(cx).map_ok(|()| self.core.sent);
            }
            if self.core.poll_pending(cx)?.is_pending() {
                return Poll::Pending;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<T: SymbolSink + Unpin> RaptorQOffloadedSendSession<'_, T> {
    /// Continues this send; dropping the wait retains worker and transport progress.
    pub fn run(&mut self) -> impl Future<Output = Result<SendOutcome, Error>> + '_ {
        SessionWait::new(self)
    }

    /// Number of symbols accepted by the sink, excluding buffered encoded output.
    #[must_use]
    pub const fn symbols_sent(&self) -> usize {
        self.core.sent
    }

    /// Whether completion, failure, cancellation, or a panic made this session terminal.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.core.state.is_finished()
    }

    #[allow(clippy::result_large_err)]
    fn start_encode(&mut self) -> Result<(), Error> {
        debug_assert!(self.encode_job.is_none(), "one owned encode job per session");
        debug_assert!(self.batch.is_empty() && self.core.pending.is_none());
        let encoder = self.encoder.take();
        let initial = self.initial.take();
        let object_id = self.object_id;
        let security = self.core.security.clone();
        let limit = self.batch_limit;
        self.encode_job = Some(
            self.core
                .state
                .owner
                .spawn_blocking_drained(move |child| {
                    child.checkpoint()?;
                    let mut encoder = if let Some(encoder) = encoder {
                        encoder
                    } else {
                        let (config, data) =
                            initial.expect("the first encode job owns its configuration and input");
                        prepare_encoder(&config, data.len())?.encode_owned(object_id, data)
                    };
                    let mut symbols = VecDeque::with_capacity(limit);
                    let mut exhausted = false;
                    for _ in 0..limit {
                        child.checkpoint()?;
                        match encoder.next() {
                            Some(Ok(symbol)) => {
                                // Matrix construction, symbol generation, and
                                // authentication all stay on the pool worker.
                                symbols.push_back(Ok(security.sign_symbol(&symbol.into_symbol())));
                            }
                            Some(Err(error)) => {
                                // Preserve the successful prefix just as the
                                // inline iterator does; the error ends this send
                                // when that prefix has crossed the sink boundary.
                                symbols.push_back(Err(Error::from(error)));
                                exhausted = true;
                                break;
                            }
                            None => {
                                exhausted = true;
                                break;
                            }
                        }
                    }
                    Ok(EncodeBatch {
                        encoder,
                        symbols,
                        exhausted,
                    })
                })
                .map_err(|error| {
                    Error::new(ErrorKind::DispatchFailed)
                        .with_message(format!("RaptorQ encode worker admission failed: {error}"))
                        .with_source(error)
                })?,
        );
        Ok(())
    }
}

impl<T: SymbolSink + Unpin> SessionOperation for RaptorQOffloadedSendSession<'_, T> {
    type Output = SendOutcome;

    fn state(&mut self) -> &mut SessionState {
        &mut self.core.state
    }

    fn on_terminal(&mut self) {
        // Abort is requested even if the caller retains a terminal session.
        // The runtime continues to own queued/running work until retirement.
        self.encode_job = None;
        self.encoder = None;
        self.initial = None;
        self.batch.clear();
        self.core.pending = None;
    }

    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<SendOutcome, Error>> {
        for _ in 0..SYMBOLS_PER_POLL {
            self.core.state.owner.checkpoint()?;
            if self.core.pending.is_none() {
                if let Some(symbol) = self.batch.pop_front() {
                    self.core.pending = Some(symbol?);
                } else if self.core.exhausted {
                    return self.core.poll_flush(cx).map_ok(|()| {
                        if let Some(metrics) = self.core.metrics {
                            metrics.counter("raptorq.objects_sent").increment();
                        }
                        SendOutcome {
                            object_id: self.object_id,
                            source_symbols: self.source_symbols,
                            repair_symbols: self.repair_symbols,
                            symbols_sent: self.core.sent,
                        }
                    });
                } else {
                    if self.encode_job.is_none() {
                        self.start_encode()?;
                    }
                    let result = {
                        let job = self
                            .encode_job
                            .as_mut()
                            .expect("a job owns encoding before its result is polled");
                        // DrainedBlockingHandle owns the result. Recreating this
                        // borrowing join after Pending cannot consume it twice.
                        let mut joining = std::pin::pin!(job.join());
                        joining.as_mut().poll(cx)
                    };
                    let batch = match result {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result.map_err(map_encode_join_error)??,
                    };
                    self.encode_job = None;
                    self.encoder = Some(batch.encoder);
                    self.batch = batch.symbols;
                    self.core.exhausted = batch.exhausted;
                    continue;
                }
            }
            let kind = self.core.pending.as_ref().map(|symbol| symbol.symbol().kind());
            match self.core.poll_pending(cx)? {
                Poll::Ready(()) => match kind {
                    Some(SymbolKind::Source) => self.source_symbols += 1,
                    Some(SymbolKind::Repair) => self.repair_symbols += 1,
                    None => unreachable!("a symbol is staged before polling the sink"),
                },
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

fn map_encode_join_error(error: JoinError) -> Error {
    let kind = match &error {
        JoinError::Cancelled(reason) => return Error::cancelled(reason).with_source(error),
        JoinError::Panicked(_) => ErrorKind::OperationFailed,
        JoinError::PolledAfterCompletion => ErrorKind::InvalidStateTransition,
    };
    Error::new(kind)
        .with_message(format!("RaptorQ encode worker failed: {error}"))
        .with_source(error)
}

impl<'a, T: SymbolSink + Unpin> SendCore<'a, T> {
    fn new(
        transport: &'a mut T,
        metrics: &'a mut Option<Metrics>,
        security: SecurityContext,
        owner: &Cx,
    ) -> Self {
        Self {
            transport,
            metrics,
            security,
            state: SessionState::new(owner),
            pending: None,
            exhausted: false,
            sent: 0,
        }
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match Pin::new(&mut *self.transport).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(map_sink_error(error))),
            Poll::Ready(Ok(())) => {}
        }
        // A readiness provider may itself request cancellation. Recheck before
        // the symbol crosses the acceptance boundary.
        self.state.owner.checkpoint()?;
        let candidate = self
            .pending
            .as_ref()
            .expect("a pending symbol exists before sink polling")
            .clone();
        match Pin::new(&mut *self.transport).poll_send(cx, candidate) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(map_sink_error(error))),
            Poll::Ready(Ok(())) => {
                self.pending = None;
                self.sent += 1;
                if let Some(metrics) = self.metrics {
                    metrics.counter("raptorq.symbols_sent").increment();
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.state.owner.checkpoint()?;
        Pin::new(&mut *self.transport)
            .poll_flush(cx)
            .map_err(map_sink_error)
    }
}

fn map_sink_error(error: SinkError) -> Error {
    let message = error.to_string();
    let kind = match error {
        SinkError::Cancelled => ErrorKind::Cancelled,
        SinkError::Closed => ErrorKind::ConnectionLost,
        SinkError::Io { source } => match source.kind() {
            std::io::ErrorKind::TimedOut => ErrorKind::ThresholdTimeout,
            std::io::ErrorKind::ConnectionRefused => ErrorKind::ConnectionRefused,
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput => {
                ErrorKind::ProtocolError
            }
            _ => ErrorKind::ConnectionLost,
        },
        SinkError::BufferFull | SinkError::SendFailed { .. } | SinkError::PolledAfterCompletion => {
            ErrorKind::DispatchFailed
        }
    };
    Error::new(kind).with_message(message)
}
