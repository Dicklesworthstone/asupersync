//! Unix stream splitting.
//!
//! This module provides borrowed and owned halves for splitting a
//! [`UnixStream`](super::UnixStream) into separate read and write handles.

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

/// Borrowed read half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::split`](super::UnixStream::split).
///
/// This half does not participate in reactor registration - it busy-loops on
/// `WouldBlock` by waking immediately. For proper async I/O with reactor
/// integration, use the owned split via [`UnixStream::into_split`].
#[derive(Debug)]
pub struct ReadHalf<'a> {
    inner: &'a net::UnixStream,
}

impl<'a> ReadHalf<'a> {
    pub(crate) fn new(inner: &'a net::UnixStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for ReadHalf<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.inner;
        match inner.read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// Borrowed write half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::split`](super::UnixStream::split).
///
/// This half does not participate in reactor registration - it busy-loops on
/// `WouldBlock` by waking immediately. For proper async I/O with reactor
/// integration, use the owned split via [`UnixStream::into_split`].
#[derive(Debug)]
pub struct WriteHalf<'a> {
    inner: &'a net::UnixStream,
}

impl<'a> WriteHalf<'a> {
    pub(crate) fn new(inner: &'a net::UnixStream) -> Self {
        Self { inner }
    }
}

impl AsyncWrite for WriteHalf<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner;
        match inner.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner;
        match inner.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.shutdown(Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// Combined waker for split halves
// ---------------------------------------------------------------------------

/// Waker that dispatches to per-direction wakers for owned split halves.
///
/// When `OwnedReadHalf` and `OwnedWriteHalf` are polled from different tasks,
/// each stores its own waker. The shared `IoRegistration` receives this
/// combined waker so that both halves are notified on any I/O readiness event.
struct CombinedWaker {
    read: Option<Waker>,
    write: Option<Waker>,
}

impl Wake for CombinedWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(w) = &self.read {
            w.wake_by_ref();
        }
        if let Some(w) = &self.write {
            w.wake_by_ref();
        }
    }
}

fn combined_waker(read: Option<&Waker>, write: Option<&Waker>) -> Waker {
    Waker::from(Arc::new(CombinedWaker {
        read: read.cloned(),
        write: write.cloned(),
    }))
}

// ---------------------------------------------------------------------------
// Owned split halves
// ---------------------------------------------------------------------------

/// Per-direction waker state for owned split halves.
struct SplitIoState {
    registration: Option<IoRegistration>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

/// Shared state for owned split halves.
///
/// Both owned halves share the same reactor registration. Each half stores
/// its own waker in [`SplitIoState`]; the `IoRegistration` receives a
/// combined waker that dispatches to both, preventing lost wakeups when
/// halves are polled from different tasks.
pub(crate) struct UnixStreamInner {
    stream: Arc<net::UnixStream>,
    state: Mutex<SplitIoState>,
}

impl std::fmt::Debug for UnixStreamInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixStreamInner")
            .field("stream", &self.stream)
            .field("state", &"...")
            .finish()
    }
}

impl UnixStreamInner {
    fn register_interest(&self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        let mut guard = self.state.lock().expect("lock poisoned");

        // Store this direction's waker for combined dispatch.
        if interest.is_readable() {
            guard.read_waker = Some(cx.waker().clone());
        } else {
            guard.write_waker = Some(cx.waker().clone());
        }

        // Destructure to enable independent field borrows through the MutexGuard.
        {
            let SplitIoState {
                registration,
                read_waker,
                write_waker,
            } = &mut *guard;
            if let Some(reg) = registration.as_mut() {
                let combined_interest = reg.interest() | interest;
                // Oneshot registration: always re-arm.
                if let Err(err) = reg.set_interest(combined_interest) {
                    if err.kind() == io::ErrorKind::NotConnected {
                        *registration = None;
                        cx.waker().wake_by_ref();
                        return Ok(());
                    }
                    return Err(err);
                }
                let waker = combined_waker(read_waker.as_ref(), write_waker.as_ref());
                if reg.update_waker(waker) {
                    return Ok(());
                }
                *registration = None;
            }
        }

        // Build combined waker before dropping the lock.
        let waker = combined_waker(guard.read_waker.as_ref(), guard.write_waker.as_ref());
        drop(guard);

        let Some(current) = Cx::current() else {
            cx.waker().wake_by_ref();
            return Ok(());
        };
        let Some(driver) = current.io_driver_handle() else {
            cx.waker().wake_by_ref();
            return Ok(());
        };

        match driver.register(&*self.stream, interest, waker) {
            Ok(registration) => {
                self.state.lock().expect("lock poisoned").registration = Some(registration);
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                cx.waker().wake_by_ref();
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

/// Owned read half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::into_split`](super::UnixStream::into_split).
/// Can be reunited with [`OwnedWriteHalf`] using [`reunite`](Self::reunite).
#[derive(Debug)]
pub struct OwnedReadHalf {
    inner: Arc<UnixStreamInner>,
}

impl OwnedReadHalf {
    pub(crate) fn new_pair(
        stream: Arc<net::UnixStream>,
        registration: Option<IoRegistration>,
    ) -> (Self, OwnedWriteHalf) {
        let inner = Arc::new(UnixStreamInner {
            stream,
            state: Mutex::new(SplitIoState {
                registration,
                read_waker: None,
                write_waker: None,
            }),
        });
        (
            Self {
                inner: inner.clone(),
            },
            OwnedWriteHalf {
                inner,
                shutdown_on_drop: true,
            },
        )
    }

    /// Attempts to reunite with a write half to reform a [`UnixStream`](super::UnixStream).
    ///
    /// # Errors
    ///
    /// Returns an error containing both halves if they originated from
    /// different streams.
    pub fn reunite(self, other: OwnedWriteHalf) -> Result<super::UnixStream, ReuniteError> {
        if Arc::ptr_eq(&self.inner, &other.inner) {
            let mut other = other;
            other.shutdown_on_drop = false;

            let registration = self
                .inner
                .state
                .lock()
                .expect("lock poisoned")
                .registration
                .take();
            Ok(super::UnixStream::from_parts(
                self.inner.stream.clone(),
                registration,
            ))
        } else {
            Err(ReuniteError(self, other))
        }
    }
}

impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner: &net::UnixStream = &self.inner.stream;
        match (&*inner).read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(e) = self.inner.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// Owned write half of a [`UnixStream`](super::UnixStream).
///
/// Created by [`UnixStream::into_split`](super::UnixStream::into_split).
/// Can be reunited with [`OwnedReadHalf`] using
/// [`OwnedReadHalf::reunite`](OwnedReadHalf::reunite).
///
/// By default, the stream's write direction is shut down when this half
/// is dropped. Use [`set_shutdown_on_drop(false)`][Self::set_shutdown_on_drop]
/// to disable this behavior.
#[derive(Debug)]
pub struct OwnedWriteHalf {
    inner: Arc<UnixStreamInner>,
    shutdown_on_drop: bool,
}

impl OwnedWriteHalf {
    /// Shuts down the write side of the stream.
    ///
    /// This is equivalent to calling `shutdown(Shutdown::Write)` on the
    /// original stream.
    pub fn shutdown(&self) -> io::Result<()> {
        self.inner.stream.shutdown(Shutdown::Write)
    }

    /// Controls whether the write direction is shut down when dropped.
    ///
    /// Default is `true`.
    pub fn set_shutdown_on_drop(&mut self, shutdown: bool) {
        self.shutdown_on_drop = shutdown;
    }
}

impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner: &net::UnixStream = &self.inner.stream;
        match (&*inner).write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(e) = self.inner.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner: &net::UnixStream = &self.inner.stream;
        match (&*inner).flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(e) = self.inner.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.stream.shutdown(Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}

impl Drop for OwnedWriteHalf {
    fn drop(&mut self) {
        if self.shutdown_on_drop {
            let _ = self.inner.stream.shutdown(Shutdown::Write);
        }
    }
}

/// Error returned when trying to reunite halves from different streams.
#[derive(Debug)]
pub struct ReuniteError(pub OwnedReadHalf, pub OwnedWriteHalf);

impl std::fmt::Display for ReuniteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tried to reunite halves that are not from the same socket"
        )
    }
}

impl std::error::Error for ReuniteError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_borrowed_halves() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let _read = ReadHalf::new(&s1);
        let _write = WriteHalf::new(&s1);
    }

    #[test]
    fn test_owned_halves() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let stream = super::super::UnixStream::from_std(s1).expect("wrap stream");
        let (_read, _write) = stream.into_split();
    }

    #[test]
    fn test_reunite_success() {
        let (s1, _s2) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");

        let stream = super::super::UnixStream::from_std(s1).expect("wrap stream");
        let (read, write) = stream.into_split();

        // Should succeed - same stream
        let _reunited = read.reunite(write).expect("reunite should succeed");
    }

    #[test]
    fn test_reunite_failure() {
        let (s1, _s2a) = net::UnixStream::pair().expect("pair failed");
        let (s2, _s2b) = net::UnixStream::pair().expect("pair failed");
        s1.set_nonblocking(true).expect("set_nonblocking failed");
        s2.set_nonblocking(true).expect("set_nonblocking failed");

        let stream1 = super::super::UnixStream::from_std(s1).expect("wrap stream1");
        let stream2 = super::super::UnixStream::from_std(s2).expect("wrap stream2");

        let (read1, _write1) = stream1.into_split();
        let (_read2, write2) = stream2.into_split();

        // Should fail - different streams
        let err = read1.reunite(write2).expect_err("reunite should fail");
        assert!(err.to_string().contains("not from the same socket"));
    }
}
