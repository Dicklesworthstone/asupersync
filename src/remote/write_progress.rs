//! Write-stall budget for the remote service's encrypted transport.
//!
//! The timer observes actual transport writes underneath TLS, so accepting
//! plaintext into TLS buffers does not count as network progress.

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::time::{Sleep, TimerDriverHandle, wall_now};
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

pub(super) struct RemoteWriteProgress<IO> {
    inner: IO,
    timeout: Option<Duration>,
    clock: Option<TimerDriverHandle>,
    timer: Option<Sleep>,
    timed_out: bool,
}

impl<IO> RemoteWriteProgress<IO> {
    pub(super) fn new(
        inner: IO,
        timeout: Option<Duration>,
        clock: Option<TimerDriverHandle>,
    ) -> Self {
        Self {
            inner,
            timeout,
            clock,
            timer: None,
            timed_out: false,
        }
    }

    fn timeout_error() -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "remote service transport made no write progress before its deadline",
        )
    }

    fn check_timeout(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.timed_out {
            return Err(Self::timeout_error());
        }
        if let Some(timer) = self.timer.as_mut()
            && Pin::new(timer).poll_deadline(cx).is_ready()
        {
            self.timer = None;
            self.timed_out = true;
            return Err(Self::timeout_error());
        }
        Ok(())
    }

    fn stalled<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        let Some(timeout) = self.timeout else {
            return Poll::Pending;
        };
        if self.timer.is_none() {
            self.timer = Some(match self.clock.as_ref() {
                Some(clock) => Sleep::with_timer_driver(clock.now() + timeout, clock.clone()),
                None => Sleep::new(wall_now() + timeout),
            });
        }
        match self.check_timeout(cx) {
            Ok(()) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for RemoteWriteProgress<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check_timeout(cx) {
            return Poll::Ready(Err(error));
        }
        // Incoming traffic cannot keep a blocked response alive. TLS can poll
        // its reader while encrypted writes are pending, so that path also
        // observes the same write deadline without renewing it.
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for RemoteWriteProgress<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.check_timeout(cx) {
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Pending => this.stalled(cx),
            Poll::Ready(result) => {
                if !matches!(result, Ok(0)) {
                    this.timer = None;
                }
                Poll::Ready(result)
            }
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.check_timeout(cx) {
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Pending => this.stalled(cx),
            Poll::Ready(result) => {
                if !matches!(result, Ok(0)) {
                    this.timer = None;
                }
                Poll::Ready(result)
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check_timeout(cx) {
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => this.stalled(cx),
            Poll::Ready(result) => {
                this.timer = None;
                Poll::Ready(result)
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check_timeout(cx) {
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => this.stalled(cx),
            Poll::Ready(result) => {
                this.timer = None;
                Poll::Ready(result)
            }
        }
    }
}

#[cfg(test)]
mod tests;
