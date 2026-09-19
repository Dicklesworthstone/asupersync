use super::{PollMismatch, PollReplayError};
use super::trace::{RecordTrace, ReplayTrace, Request};
use super::super::gate::{RecordOrder, ReplayOrder};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::fmt;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

enum Mode {
    Record(Arc<RecordTrace>, Arc<RecordOrder>),
    Replay(Arc<ReplayTrace>, Arc<ReplayOrder>),
}

/// I/O owned by a poll-session driver. Its inner provider is never exposed.
///
/// Recording forwards original wakers/results. Replay checks every request,
/// including Pending calls, and returns only its recorded poll outcome.
/// The enclosing driver, not this adapter, schedules the next captured poll.
pub struct PolledIo<T> {
    inner: T,
    mode: Mode,
}
impl<T> fmt::Debug for PolledIo<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolledIo").finish_non_exhaustive()
    }
}
impl<T> PolledIo<T> {
    pub(super) fn record(inner: T, trace: Arc<RecordTrace>, order: Arc<RecordOrder>) -> Self {
        Self { inner, mode: Mode::Record(trace, order) }
    }
    pub(super) fn replay(inner: T, trace: Arc<ReplayTrace>, order: Arc<ReplayOrder>) -> Self {
        Self { inner, mode: Mode::Replay(trace, order) }
    }
    pub(super) fn into_inner(self) -> T { self.inner }
    fn poll_with<R>(
        &mut self, cx: &mut Context<'_>, request: Request<'_, '_>,
        poll: impl FnOnce(&mut T, &mut Context<'_>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        match &self.mode {
            Mode::Record(trace, order) => {
                let guard = trace.begin(&request, order.effect_position());
                let result = poll(&mut self.inner, cx);
                if let Some(guard) = guard { guard.finish(result.is_pending()); }
                result
            }
            Mode::Replay(trace, order) => {
                let operation = request.operation();
                if let Err(error) = order.check_polled_io(operation) {
                    trace.refuse(PollMismatch::Outcome);
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
                }
                let pending = match trace.enter(&request, order.effect_position()) {
                    Ok(pending) => pending,
                    Err(error) => {
                        order.refuse_polled_io(operation);
                        return Poll::Ready(Err(as_io_error(error)));
                    }
                };
                if pending { return Poll::Pending; }
                let result = poll(&mut self.inner, cx);
                if result.is_pending() {
                    let error = trace.refuse(PollMismatch::Outcome);
                    order.refuse_polled_io(operation);
                    return Poll::Ready(Err(as_io_error(error)));
                }
                result
            }
        }
    }
}
fn as_io_error(error: PollReplayError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
impl<T: AsyncRead + Unpin> AsyncRead for PolledIo<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, Request::Read(buf.remaining()), |io, cx| Pin::new(io).poll_read(cx, buf))
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for PolledIo<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(cx, Request::Write(bytes), |io, cx| Pin::new(io).poll_write(cx, bytes))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(cx, Request::Vectored(bufs), |io, cx| Pin::new(io).poll_write_vectored(cx, bufs))
    }
    fn is_write_vectored(&self) -> bool { self.inner.is_write_vectored() }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, Request::Flush, |io, cx| Pin::new(io).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, Request::Shutdown, |io, cx| Pin::new(io).poll_shutdown(cx))
    }
}
