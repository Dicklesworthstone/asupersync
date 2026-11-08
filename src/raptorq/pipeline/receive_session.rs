//! Resumable authenticated decoding over asynchronous symbol streams.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::session::{SYMBOLS_PER_POLL, SessionOperation, SessionState, SessionWait};
use super::{
    Cx, Error, Metrics, ObjectParams, RaptorQReceiver, ReceiveOutcome, ReceiveState, SymbolStream,
    map_stream_error,
};

/// An authenticated receive whose decode progress survives a dropped wait.
///
/// [`run`](Self::run) borrows this session. Dropping the wait retains accepted
/// symbols and the decoder; a later wait continues with the same original [`Cx`]
/// and absolute deadline. Completion, cancellation, errors, and caught provider
/// panics are terminal. A successful result is delivered once.
///
/// All incoming symbols are verified before decode or object filtering. Up to
/// 32 stream items, including duplicates and other objects, are processed per
/// poll. Individual decoding steps remain synchronous on the polling thread.
pub struct RaptorQReceiveSession<'a, S> {
    source: &'a mut S,
    metrics: &'a mut Option<Metrics>,
    receive: Option<ReceiveState>,
    state: SessionState,
    symbols_received: usize,
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
            receive: Some(receive),
            state: SessionState::new(cx),
            symbols_received: 0,
        })
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
}

impl<S: SymbolStream + Unpin> SessionOperation for RaptorQReceiveSession<'_, S> {
    type Output = ReceiveOutcome;

    fn state(&mut self) -> &mut SessionState {
        &mut self.state
    }

    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<ReceiveOutcome, Error>> {
        for _ in 0..SYMBOLS_PER_POLL {
            self.state.owner.checkpoint()?;
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
                    receive.accept(symbol, self.metrics)?;
                    self.symbols_received = receive.symbols_received();
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
