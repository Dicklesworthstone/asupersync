//! Resumable sends over asynchronous symbol sinks.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::session::{SYMBOLS_PER_POLL, SessionOperation, SessionState, SessionWait};
use super::{
    AuthenticatedSymbol, Cx, Error, ErrorKind, Metrics, ObjectId, RaptorQSender, SecurityContext,
    SendOutcome, SymbolSink, prepare_encoder, required_security,
};
use crate::encoding::EncodingIterator;
use crate::transport::error::SinkError;
use crate::types::symbol::SymbolKind;

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
/// synchronously on the polling thread.
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
