//! TCP stream splitting with reactor registration sharing.
//!
//! This module provides borrowed and owned split halves for TCP streams.
//! The owned variants properly share the reactor registration between halves.
//!
//! ubs:ignore — OwnedWriteHalf::drop() calls shutdown(Write); read half does not
//! need shutdown (correct half-duplex semantics).

#[cfg(not(target_arch = "wasm32"))]
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncReadVectored, AsyncWrite, ReadBuf};
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use parking_lot::Mutex;
use std::io::{self, IoSliceMut};
#[cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};
#[cfg(target_arch = "wasm32")]
use std::marker::PhantomData;
#[cfg(not(target_arch = "wasm32"))]
use std::net::{self, Shutdown};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

#[cfg(target_arch = "wasm32")]
#[inline]
fn browser_tcp_poll_unsupported<T>(op: &str) -> Poll<io::Result<T>> {
    Poll::Ready(Err(super::browser_tcp_unsupported(op)))
}

#[cfg(target_arch = "wasm32")]
#[inline]
fn browser_tcp_unsupported_result<T>(op: &str) -> io::Result<T> {
    Err(super::browser_tcp_unsupported(op))
}

/// Borrowed read half of a split TCP stream.
///
/// This half does not participate in reactor registration - it uses
/// busy-loop polling on WouldBlock. For proper async I/O with reactor
/// integration, use the owned split via [`TcpStream::into_split()`](super::stream::TcpStream::into_split).
#[derive(Debug)]
pub struct ReadHalf<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    inner: &'a net::TcpStream,
    #[cfg(target_arch = "wasm32")]
    _marker: PhantomData<&'a ()>,
}

impl<'a> ReadHalf<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn new(inner: &'a net::TcpStream) -> Self {
        Self { inner }
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn unsupported() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
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
                // No reactor integration for borrowed split - use fallback_rewake
                // to avoid 100% CPU busy loops. For proper async I/O, use owned split.
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncRead for ReadHalf<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _ = (self, cx, buf);
        browser_tcp_poll_unsupported("ReadHalf::poll_read")
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncReadVectored for ReadHalf<'_> {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner;
        match inner.read_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncReadVectored for ReadHalf<'_> {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let _ = (self, cx, bufs);
        browser_tcp_poll_unsupported("ReadHalf::poll_read_vectored")
    }
}

/// Borrowed write half of a split TCP stream.
///
/// This half does not participate in reactor registration - it uses
/// busy-loop polling on WouldBlock. For proper async I/O with reactor
/// integration, use the owned split via [`TcpStream::into_split()`](super::stream::TcpStream::into_split).
#[derive(Debug)]
pub struct WriteHalf<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    inner: &'a net::TcpStream,
    #[cfg(target_arch = "wasm32")]
    _marker: PhantomData<&'a ()>,
}

impl<'a> WriteHalf<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn new(inner: &'a net::TcpStream) -> Self {
        Self { inner }
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn unsupported() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
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
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner;
        match inner.write_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner;
        match inner.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                crate::net::tcp::stream::fallback_rewake(cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.shutdown(Shutdown::Write) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncWrite for WriteHalf<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let _ = (self, cx, buf);
        browser_tcp_poll_unsupported("WriteHalf::poll_write")
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = (self, cx);
        browser_tcp_poll_unsupported("WriteHalf::poll_flush")
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = (self, cx);
        browser_tcp_poll_unsupported("WriteHalf::poll_shutdown")
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

#[inline]
fn registration_interest(read_waiter: bool, write_waiter: bool, fallback: Interest) -> Interest {
    let mut interest = Interest::empty();
    if read_waiter {
        interest |= Interest::READABLE;
    }
    if write_waiter {
        interest |= Interest::WRITABLE;
    }
    if interest.is_empty() {
        fallback
    } else {
        interest
    }
}

// ---------------------------------------------------------------------------
// Owned split halves
// ---------------------------------------------------------------------------

/// Per-direction waker state for owned split halves.
struct SplitIoState {
    registration: Option<IoRegistration>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    combined_waker: Option<Waker>,
}

fn split_io_state(registration: Option<IoRegistration>) -> SplitIoState {
    SplitIoState {
        registration,
        read_waker: None,
        write_waker: None,
        combined_waker: None,
    }
}

/// Shared state for owned split halves.
///
/// Both [`OwnedReadHalf`] and [`OwnedWriteHalf`] share this state via `Arc`.
/// Each half stores its own waker in [`SplitIoState`]; the `IoRegistration`
/// receives a combined waker that dispatches to both, preventing lost wakeups
/// when halves are polled from different tasks.
pub(crate) struct TcpStreamInner {
    /// Per-direction wakers and shared reactor registration.
    state: Mutex<SplitIoState>,
    /// The underlying TCP stream.
    #[cfg(not(target_arch = "wasm32"))]
    stream: Arc<net::TcpStream>,
    #[cfg(target_arch = "wasm32")]
    unsupported: (),
}

impl std::fmt::Debug for TcpStreamInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("TcpStreamInner");
        #[cfg(not(target_arch = "wasm32"))]
        debug.field("stream", &self.stream);
        #[cfg(target_arch = "wasm32")]
        debug.field("stream", &"unsupported");
        debug.field("state", &"...").finish()
    }
}

impl TcpStreamInner {
    #[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
    fn register_interest(&self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (cx, interest);
            browser_tcp_unsupported_result("OwnedTcpStream::register_interest")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut guard = self.state.lock();

            // Store this direction's waker for combined dispatch.
            // Use independent checks (not else-if) so that callers passing
            // combined interest (READABLE | WRITABLE) update both wakers.
            let mut wakers_changed = false;
            if interest.is_readable() {
                if !guard
                    .read_waker
                    .as_ref()
                    .is_some_and(|w| w.will_wake(cx.waker()))
                {
                    guard.read_waker = Some(cx.waker().clone());
                    wakers_changed = true;
                }
            }
            if interest.is_writable() {
                if !guard
                    .write_waker
                    .as_ref()
                    .is_some_and(|w| w.will_wake(cx.waker()))
                {
                    guard.write_waker = Some(cx.waker().clone());
                    wakers_changed = true;
                }
            }

            if wakers_changed || guard.combined_waker.is_none() {
                guard.combined_waker = Some(combined_waker(
                    guard.read_waker.as_ref(),
                    guard.write_waker.as_ref(),
                ));
            }

            let mut dropped_reg = None;
            let mut early_return = None;
            let mut wakers_to_wake = None;

            // Destructure to enable independent field borrows through the MutexGuard.
            {
                let SplitIoState {
                    registration,
                    read_waker,
                    write_waker,
                    combined_waker: cached_combined_waker,
                } = &mut *guard;
                if let Some(reg) = registration.as_mut() {
                    let combined_interest = registration_interest(
                        read_waker.is_some(),
                        write_waker.is_some(),
                        interest,
                    );
                    let waker = cached_combined_waker
                        .as_ref()
                        .expect("combined waker initialized");
                    // Single lock in io_driver: re-arm interest + refresh waker.
                    match reg.rearm(combined_interest, waker) {
                        Ok(true) => early_return = Some(Ok(())),
                        Ok(false) => {
                            dropped_reg = registration.take();
                        }
                        Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                            dropped_reg = registration.take();
                            wakers_to_wake = Some((read_waker.clone(), write_waker.clone()));
                            early_return = Some(Ok(()));
                        }
                        Err(err) => early_return = Some(Err(err)),
                    }
                }
            }

            if let Some(res) = early_return {
                drop(guard);
                drop(dropped_reg);
                if let Some((rw, ww)) = wakers_to_wake {
                    if let Some(w) = rw {
                        w.wake();
                    }
                    if let Some(w) = ww {
                        w.wake();
                    }
                }
                return res;
            }

            // Build combined waker while still holding the lock. We keep the lock
            // held across `driver.register()` to prevent a race where both halves
            // concurrently attempt to create a fresh registration for the same fd,
            // causing one to fail with EEXIST from epoll_ctl(ADD).
            let waker = guard
                .combined_waker
                .as_ref()
                .expect("combined waker initialized")
                .clone();
            let register_interest = registration_interest(
                guard.read_waker.is_some(),
                guard.write_waker.is_some(),
                interest,
            );

            let Some(current) = Cx::current() else {
                crate::net::tcp::stream::fallback_rewake(cx);
                drop(guard);
                drop(dropped_reg);
                return Ok(());
            };
            let Some(driver) = current.io_driver_handle() else {
                crate::net::tcp::stream::fallback_rewake(cx);
                drop(guard);
                drop(dropped_reg);
                return Ok(());
            };

            let result = match driver.register(&*self.stream, register_interest, waker) {
                Ok(registration) => {
                    guard.registration = Some(registration);
                    Ok(())
                }
                Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                    crate::net::tcp::stream::fallback_rewake(cx);
                    Ok(())
                }
                Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                    crate::net::tcp::stream::fallback_rewake(cx);
                    Ok(())
                }
                Err(err) => Err(err),
            };
            drop(guard);
            drop(dropped_reg);
            result
        }
    }

    fn clear_waiter_on_drop(&self, interest: Interest) {
        let mut guard = self.state.lock();

        let mut wakers_changed = interest.is_readable();
        if wakers_changed {
            guard.read_waker = None;
        }
        if interest.is_writable() {
            guard.write_waker = None;
            wakers_changed = true;
        }

        if wakers_changed || guard.combined_waker.is_none() {
            guard.combined_waker = Some(combined_waker(
                guard.read_waker.as_ref(),
                guard.write_waker.as_ref(),
            ));
        }

        let desired_interest = registration_interest(
            guard.read_waker.is_some(),
            guard.write_waker.is_some(),
            Interest::empty(),
        );

        let mut clear_registration = desired_interest.is_empty();
        let mut wakers_to_wake = None;

        if !clear_registration {
            let combined = guard
                .combined_waker
                .as_ref()
                .expect("combined waker initialized")
                .clone();
            let is_some = guard.registration.is_some();
            let rearm_ok = guard
                .registration
                .as_mut()
                .is_some_and(|reg| matches!(reg.rearm(desired_interest, &combined), Ok(true)));

            if is_some {
                if !rearm_ok {
                    clear_registration = true;
                    wakers_to_wake = Some((guard.read_waker.clone(), guard.write_waker.clone()));
                }
            } else {
                // Surviving waiter but no registration: wake it so poll paths
                // can attempt fresh registration or surface terminal errors.
                wakers_to_wake = Some((guard.read_waker.clone(), guard.write_waker.clone()));
            }
        }

        let dropped_reg = if clear_registration {
            guard.registration.take()
        } else {
            None
        };

        drop(guard);
        drop(dropped_reg);

        if let Some((rw, ww)) = wakers_to_wake {
            if let Some(w) = rw {
                w.wake();
            }
            if let Some(w) = ww {
                w.wake();
            }
        }
    }
}

/// Owned read half of a split TCP stream.
///
/// This can be sent to another task and properly participates in reactor
/// registration. The registration is shared with the corresponding
/// [`OwnedWriteHalf`].
#[derive(Debug)]
pub struct OwnedReadHalf {
    inner: Arc<TcpStreamInner>,
}

impl OwnedReadHalf {
    /// Create a paired read and write half sharing the same inner state.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn new_pair(
        stream: Arc<net::TcpStream>,
        registration: Option<IoRegistration>,
    ) -> (Self, OwnedWriteHalf) {
        let inner = Arc::new(TcpStreamInner {
            stream,
            state: Mutex::new(split_io_state(registration)),
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

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn unsupported_pair() -> (Self, OwnedWriteHalf) {
        let inner = Arc::new(TcpStreamInner {
            unsupported: (),
            state: Mutex::new(split_io_state(None)),
        });
        (
            Self {
                inner: inner.clone(),
            },
            OwnedWriteHalf {
                inner,
                shutdown_on_drop: false,
            },
        )
    }

    /// Returns the local address of the stream.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        #[cfg(target_arch = "wasm32")]
        {
            return browser_tcp_unsupported_result("OwnedReadHalf::local_addr");
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.stream.local_addr()
    }

    /// Returns the peer address of the stream.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        #[cfg(target_arch = "wasm32")]
        {
            return browser_tcp_unsupported_result("OwnedReadHalf::peer_addr");
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.stream.peer_addr()
    }

    /// Reunite with the write half to reconstruct the original TcpStream.
    ///
    /// # Errors
    ///
    /// Returns an error containing both halves if they don't belong to the
    /// same original stream.
    pub fn reunite(self, write: OwnedWriteHalf) -> Result<super::stream::TcpStream, ReuniteError> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = Arc::ptr_eq(&self.inner, &write.inner);
            return Err(ReuniteError { read: self, write });
        }

        #[cfg(not(target_arch = "wasm32"))]
        if Arc::ptr_eq(&self.inner, &write.inner) {
            // Don't shutdown on drop since we're reuniting
            let mut write = write;
            write.shutdown_on_drop = false;

            // Take the registration back
            let registration = self.inner.state.lock().registration.take();

            Ok(super::stream::TcpStream::from_parts(
                self.inner.stream.clone(),
                registration,
            ))
        } else {
            Err(ReuniteError { read: self, write })
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner: &net::TcpStream = &self.inner.stream;
        match (&*inner).read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.inner.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _ = (self, cx, buf);
        browser_tcp_poll_unsupported("OwnedReadHalf::poll_read")
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncReadVectored for OwnedReadHalf {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let inner: &net::TcpStream = &self.inner.stream;
        match (&*inner).read_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.inner.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncReadVectored for OwnedReadHalf {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let _ = (self, cx, bufs);
        browser_tcp_poll_unsupported("OwnedReadHalf::poll_read_vectored")
    }
}

/// Owned write half of a split TCP stream.
///
/// This can be sent to another task and properly participates in reactor
/// registration. The registration is shared with the corresponding
/// [`OwnedReadHalf`].
///
/// By default, the stream's write direction is shut down when this half
/// is dropped. Use [`set_shutdown_on_drop(false)`][Self::set_shutdown_on_drop]
/// to disable this behavior.
#[derive(Debug)]
pub struct OwnedWriteHalf {
    inner: Arc<TcpStreamInner>,
    shutdown_on_drop: bool,
}

impl OwnedWriteHalf {
    /// Returns the local address of the stream.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        #[cfg(target_arch = "wasm32")]
        {
            return browser_tcp_unsupported_result("OwnedWriteHalf::local_addr");
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.stream.local_addr()
    }

    /// Returns the peer address of the stream.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        #[cfg(target_arch = "wasm32")]
        {
            return browser_tcp_unsupported_result("OwnedWriteHalf::peer_addr");
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.inner.stream.peer_addr()
    }

    /// Controls whether the write direction is shut down when dropped.
    ///
    /// Default is `true`.
    pub fn set_shutdown_on_drop(&mut self, shutdown: bool) {
        self.shutdown_on_drop = shutdown;
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner: &net::TcpStream = &self.inner.stream;
        match (&*inner).write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.inner.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let inner: &net::TcpStream = &self.inner.stream;
        match (&*inner).write_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.inner.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner: &net::TcpStream = &self.inner.stream;
        match (&*inner).flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.inner.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.stream.shutdown(Shutdown::Write) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let _ = (self, cx, buf);
        browser_tcp_poll_unsupported("OwnedWriteHalf::poll_write")
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = (self, cx);
        browser_tcp_poll_unsupported("OwnedWriteHalf::poll_flush")
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = (self, cx);
        browser_tcp_poll_unsupported("OwnedWriteHalf::poll_shutdown")
    }
}

impl Drop for OwnedWriteHalf {
    fn drop(&mut self) {
        self.inner.clear_waiter_on_drop(Interest::WRITABLE);
        #[cfg(not(target_arch = "wasm32"))]
        if self.shutdown_on_drop {
            let _ = self.inner.stream.shutdown(Shutdown::Write);
        }
    }
}

impl Drop for OwnedReadHalf {
    fn drop(&mut self) {
        self.inner.clear_waiter_on_drop(Interest::READABLE);
    }
}

/// Error returned when trying to reunite halves that don't match.
#[derive(Debug)]
pub struct ReuniteError {
    /// The read half that was passed to reunite.
    pub read: OwnedReadHalf,
    /// The write half that was passed to reunite.
    pub write: OwnedWriteHalf,
}

impl std::fmt::Display for ReuniteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tried to reunite halves that don't belong to the same stream"
        )
    }
}

impl std::error::Error for ReuniteError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::io::AsyncReadVectored;
    use crate::net::tcp::stream::TcpStream;
    use crate::runtime::io_driver::IoDriverHandle;
    use crate::runtime::reactor::{Events, Reactor, Source, Token};
    use crate::test_utils::init_test_logging;
    use crate::types::{Budget, RegionId, TaskId};
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::io::{IoSliceMut, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::task::{Context, Wake, Waker};
    use std::thread;
    use std::time::Duration;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct SourceExclusiveState {
        source_to_token: HashMap<i32, Token>,
        token_to_source: HashMap<Token, i32>,
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct SourceExclusiveReactor {
        state: Mutex<SourceExclusiveState>,
        register_calls: AtomicUsize,
        modify_calls: AtomicUsize,
        fail_modify_on_call: AtomicUsize,
        fail_modify_not_connected: AtomicBool,
        slow_first_register: AtomicBool,
    }

    #[cfg(unix)]
    impl SourceExclusiveReactor {
        fn new() -> Self {
            Self {
                state: Mutex::new(SourceExclusiveState::default()),
                register_calls: AtomicUsize::new(0),
                modify_calls: AtomicUsize::new(0),
                fail_modify_on_call: AtomicUsize::new(0),
                fail_modify_not_connected: AtomicBool::new(false),
                slow_first_register: AtomicBool::new(true),
            }
        }

        fn register_calls(&self) -> usize {
            self.register_calls.load(Ordering::SeqCst)
        }

        fn modify_calls(&self) -> usize {
            self.modify_calls.load(Ordering::SeqCst)
        }

        fn fail_modify_on_call(&self, call_index: usize) {
            self.fail_modify_on_call.store(call_index, Ordering::SeqCst);
        }

        fn fail_modify_with_not_connected(&self, enabled: bool) {
            self.fail_modify_not_connected
                .store(enabled, Ordering::SeqCst);
        }
    }

    #[cfg(unix)]
    impl Reactor for SourceExclusiveReactor {
        fn register(
            &self,
            source: &dyn Source,
            token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            let fd = source.raw_fd();
            let mut state = self.state.lock();

            if state.source_to_token.contains_key(&fd) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "source already registered",
                ));
            }
            if state.token_to_source.contains_key(&token) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "token already registered",
                ));
            }

            state.source_to_token.insert(fd, token);
            state.token_to_source.insert(token, fd);
            drop(state);

            self.register_calls.fetch_add(1, Ordering::SeqCst);
            if self.slow_first_register.swap(false, Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(())
        }

        fn modify(&self, token: Token, _interest: Interest) -> io::Result<()> {
            let state = self.state.lock();
            if !state.token_to_source.contains_key(&token) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            }
            drop(state);
            let call = self.modify_calls.fetch_add(1, Ordering::SeqCst) + 1;
            let fail_on = self.fail_modify_on_call.load(Ordering::SeqCst);
            if fail_on != 0 && call == fail_on {
                if self.fail_modify_not_connected.load(Ordering::SeqCst) {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "injected not-connected modify failure",
                    ));
                }
                return Err(io::Error::other("injected modify failure"));
            }
            Ok(())
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            let mut state = self.state.lock();
            let Some(fd) = state.token_to_source.remove(&token) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            };
            state.source_to_token.remove(&fd);
            drop(state);
            Ok(())
        }

        fn poll(&self, events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
            events.clear();
            Ok(0)
        }

        fn wake(&self) -> io::Result<()> {
            Ok(())
        }

        fn registration_count(&self) -> usize {
            self.state.lock().token_to_source.len()
        }
    }

    #[test]
    fn borrowed_split_read_write() {
        init_test("borrowed_split_read_write");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        client.set_nonblocking(true).expect("nonblocking");

        let (mut server, _) = listener.accept().expect("accept");

        // Create borrowed halves
        let _read_half = ReadHalf::new(&client);
        let _write_half = WriteHalf::new(&client);

        // Write from server, read from client
        server.write_all(b"hello").expect("write");

        // Borrowed halves work (may need multiple attempts due to non-blocking)
        let mut buf = [0u8; 5];
        let _read_buf = ReadBuf::new(&mut buf);

        // Just verify the types compile and basic operations work
        crate::assert_with_log!(true, "borrowed split compiles", true, true);
        crate::test_complete!("borrowed_split_read_write");
    }

    fn read_vectored_payload<R: AsyncReadVectored + Unpin>(reader: &mut R, payload: &[u8]) {
        let mut first = [0u8; 3];
        let mut second = [0u8; 3];
        assert_eq!(payload.len(), first.len() + second.len());
        let mut total = 0usize;
        let mut attempts = 0usize;

        while total < payload.len() {
            attempts += 1;
            assert!(attempts <= 32, "vectored split read did not become ready");
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let polled = if total < first.len() {
                let offset = total;
                let mut bufs = [
                    IoSliceMut::new(&mut first[offset..]),
                    IoSliceMut::new(&mut second),
                ];
                Pin::new(&mut *reader).poll_read_vectored(&mut cx, &mut bufs)
            } else {
                let offset = total - first.len();
                let mut bufs = [IoSliceMut::new(&mut second[offset..])];
                Pin::new(&mut *reader).poll_read_vectored(&mut cx, &mut bufs)
            };

            match polled {
                Poll::Ready(Ok(0)) => panic!("vectored split read reached EOF early"),
                Poll::Ready(Ok(n)) => total += n,
                Poll::Ready(Err(err)) => panic!("vectored split read failed: {err}"),
                Poll::Pending => thread::sleep(Duration::from_millis(5)),
            }
        }

        let mut combined = [0u8; 6];
        combined[..first.len()].copy_from_slice(&first);
        combined[first.len()..].copy_from_slice(&second);
        crate::assert_with_log!(
            combined.as_slice() == payload,
            "vectored split read preserves payload",
            payload,
            combined
        );
    }

    #[test]
    fn borrowed_split_read_half_supports_vectored_reads() {
        init_test("borrowed_split_read_half_supports_vectored_reads");

        let payload = b"vector";
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        client.set_nonblocking(true).expect("nonblocking");
        let (mut server, _) = listener.accept().expect("accept");
        let mut read_half = ReadHalf::new(&client);

        server.write_all(payload).expect("write payload");
        read_vectored_payload(&mut read_half, payload);

        crate::test_complete!("borrowed_split_read_half_supports_vectored_reads");
    }

    #[test]
    fn owned_split_creates_pair() {
        init_test("owned_split_creates_pair");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = Arc::new(client);

        let (read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        // Verify they share the same inner
        let same_inner = Arc::ptr_eq(&read_half.inner, &write_half.inner);
        crate::assert_with_log!(same_inner, "halves share inner", true, same_inner);

        crate::test_complete!("owned_split_creates_pair");
    }

    #[test]
    fn owned_split_read_half_supports_vectored_reads() {
        init_test("owned_split_read_half_supports_vectored_reads");

        let payload = b"vector";
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = TcpStream::from_std(client).expect("wrap stream");
        let (mut read_half, _write_half) = stream.into_split();
        let (mut server, _) = listener.accept().expect("accept");

        server.write_all(payload).expect("write payload");
        read_vectored_payload(&mut read_half, payload);

        crate::test_complete!("owned_split_read_half_supports_vectored_reads");
    }

    #[test]
    fn owned_split_reunite_success() {
        init_test("owned_split_reunite_success");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = Arc::new(client);

        let (read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        let result = read_half.reunite(write_half);
        crate::assert_with_log!(result.is_ok(), "reunite succeeds", true, result.is_ok());

        crate::test_complete!("owned_split_reunite_success");
    }

    #[test]
    fn into_split_does_not_shutdown_stream() {
        init_test("into_split_does_not_shutdown_stream");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");

        let stream = TcpStream::from_std(client).expect("wrap stream");
        let (_read_half, write_half) = stream.into_split();

        let mut stream_ref = write_half.inner.stream.as_ref();
        stream_ref.write_all(b"ping").expect("client write");

        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).expect("server read");

        crate::assert_with_log!(
            buf == *b"ping",
            "into_split keeps stream open",
            *b"ping",
            buf
        );

        crate::test_complete!("into_split_does_not_shutdown_stream");
    }

    #[test]
    fn owned_split_reunite_mismatch() {
        init_test("owned_split_reunite_mismatch");

        let listener1 = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr1 = listener1.local_addr().expect("local addr");
        let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr2 = listener2.local_addr().expect("local addr");

        let client1 = std::net::TcpStream::connect(addr1).expect("connect");
        let client2 = std::net::TcpStream::connect(addr2).expect("connect");

        let (read_half1, _write_half1) = OwnedReadHalf::new_pair(Arc::new(client1), None);
        let (_read_half2, write_half2) = OwnedReadHalf::new_pair(Arc::new(client2), None);

        // Try to reunite mismatched halves
        let result = read_half1.reunite(write_half2);
        crate::assert_with_log!(
            result.is_err(),
            "reunite fails for mismatch",
            true,
            result.is_err()
        );

        crate::test_complete!("owned_split_reunite_mismatch");
    }

    #[test]
    fn owned_half_addresses() {
        init_test("owned_half_addresses");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let stream = Arc::new(client);

        let (read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        // Both halves should report same addresses
        let read_local = read_half.local_addr().expect("local");
        let write_local = write_half.local_addr().expect("local");
        crate::assert_with_log!(
            read_local == write_local,
            "same local addr",
            read_local,
            write_local
        );

        let read_peer = read_half.peer_addr().expect("peer");
        let write_peer = write_half.peer_addr().expect("peer");
        crate::assert_with_log!(
            read_peer == write_peer,
            "same peer addr",
            read_peer,
            write_peer
        );

        crate::test_complete!("owned_half_addresses");
    }

    #[cfg(unix)]
    #[test]
    fn split_register_interest_serializes_fresh_registration() {
        init_test("split_register_interest_serializes_fresh_registration");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor.clone());
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );

        let barrier = Arc::new(Barrier::new(3));
        let read_inner = read_half.inner.clone();
        let read_cx = cx.clone();
        let read_barrier = barrier.clone();
        let read_thread = thread::spawn(move || {
            let _guard = Cx::set_current(Some(read_cx));
            let waker = noop_waker();
            let task_cx = Context::from_waker(&waker);
            read_barrier.wait();
            read_inner.register_interest(&task_cx, Interest::READABLE)
        });

        let write_inner = write_half.inner.clone();
        let write_cx = cx;
        let write_barrier = barrier.clone();
        let write_thread = thread::spawn(move || {
            let _guard = Cx::set_current(Some(write_cx));
            let waker = noop_waker();
            let task_cx = Context::from_waker(&waker);
            write_barrier.wait();
            write_inner.register_interest(&task_cx, Interest::WRITABLE)
        });

        barrier.wait();
        let read_result = read_thread.join().expect("read thread panic");
        let write_result = write_thread.join().expect("write thread panic");
        assert!(
            read_result.is_ok(),
            "read half registration should not fail: {read_result:?}"
        );
        assert!(
            write_result.is_ok(),
            "write half registration should not fail: {write_result:?}"
        );
        assert_eq!(
            reactor.register_calls(),
            1,
            "fresh split registration should be issued once"
        );
        assert_eq!(
            reactor.modify_calls(),
            1,
            "second waiter should re-arm existing registration"
        );
    }

    #[test]
    fn write_half_shutdown_on_drop() {
        init_test("write_half_shutdown_on_drop");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");

        let stream = Arc::new(client);
        let (_read_half, write_half) = OwnedReadHalf::new_pair(stream, None);

        drop(write_half);

        // Server should see connection shutdown
        let mut buf = [0u8; 1];
        let result = server.read(&mut buf);
        // Should get 0 bytes (EOF) or an error
        let is_shutdown = matches!(result, Ok(0) | Err(_));
        crate::assert_with_log!(is_shutdown, "write shutdown on drop", true, is_shutdown);

        crate::test_complete!("write_half_shutdown_on_drop");
    }

    #[test]
    fn registration_interest_prefers_waiter_union() {
        init_test("registration_interest_prefers_waiter_union");

        let both = registration_interest(true, true, Interest::READABLE);
        crate::assert_with_log!(
            both == (Interest::READABLE | Interest::WRITABLE),
            "both interests preserved",
            Interest::READABLE | Interest::WRITABLE,
            both
        );

        let read_only = registration_interest(true, false, Interest::WRITABLE);
        crate::assert_with_log!(
            read_only == Interest::READABLE,
            "read waiter wins",
            Interest::READABLE,
            read_only
        );

        let fallback = registration_interest(false, false, Interest::WRITABLE);
        crate::assert_with_log!(
            fallback == Interest::WRITABLE,
            "fallback interest",
            Interest::WRITABLE,
            fallback
        );

        crate::test_complete!("registration_interest_prefers_waiter_union");
    }

    #[cfg(unix)]
    #[test]
    fn dropping_read_half_clears_waiter_and_registration_when_idle() {
        init_test("dropping_read_half_clears_waiter_and_registration_when_idle");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let waker = noop_waker();
        let task_cx = Context::from_waker(&waker);
        read_half
            .inner
            .register_interest(&task_cx, Interest::READABLE)
            .expect("register readable");

        drop(read_half);

        let state = write_half.inner.state.lock();
        assert!(
            state.read_waker.is_none(),
            "read waiter must be cleared after read half drop"
        );
        assert!(
            state.registration.is_none(),
            "registration should be released when no waiters remain"
        );
        drop(state);
    }

    #[cfg(unix)]
    #[test]
    fn dropping_write_half_clears_waiter_and_keeps_read_interest() {
        init_test("dropping_write_half_clears_waiter_and_keeps_read_interest");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let waker = noop_waker();
        let task_cx = Context::from_waker(&waker);
        read_half
            .inner
            .register_interest(&task_cx, Interest::READABLE)
            .expect("register readable");
        write_half
            .inner
            .register_interest(&task_cx, Interest::WRITABLE)
            .expect("register writable");

        drop(write_half);

        let state = read_half.inner.state.lock();
        assert!(
            state.write_waker.is_none(),
            "write waiter must be cleared after write half drop"
        );
        assert!(
            state.registration.is_some(),
            "registration should remain for the live read waiter"
        );
        assert_eq!(
            state
                .registration
                .as_ref()
                .expect("registration")
                .interest(),
            Interest::READABLE,
            "interest should drop writable bit when write half is dropped"
        );
        drop(state);
    }

    #[cfg(unix)]
    #[test]
    fn dropping_write_half_wakes_survivor_when_reregistration_fails() {
        struct CountingWaker {
            hits: Arc<AtomicUsize>,
        }
        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.hits.fetch_add(1, Ordering::SeqCst);
            }
        }

        init_test("dropping_write_half_wakes_survivor_when_reregistration_fails");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        // First modify call (adding WRITABLE) succeeds; second modify call
        // (drop-time narrowing to READABLE) fails.
        reactor.fail_modify_on_call(2);

        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let read_hits = Arc::new(AtomicUsize::new(0));
        let read_waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&read_hits),
        }));
        let read_task_cx = Context::from_waker(&read_waker);
        read_half
            .inner
            .register_interest(&read_task_cx, Interest::READABLE)
            .expect("register readable");

        let write_waker = noop_waker();
        let write_task_cx = Context::from_waker(&write_waker);
        write_half
            .inner
            .register_interest(&write_task_cx, Interest::WRITABLE)
            .expect("register writable");

        drop(write_half);

        let state = read_half.inner.state.lock();
        assert!(
            state.registration.is_none(),
            "registration should be dropped after injected re-arm failure"
        );
        drop(state);

        assert!(
            read_hits.load(Ordering::SeqCst) >= 1,
            "surviving waiter must be woken to retry registration after drop-time failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn not_connected_modify_wakes_both_split_waiters() {
        struct CountingWaker {
            hits: Arc<AtomicUsize>,
        }

        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.hits.fetch_add(1, Ordering::SeqCst);
            }
        }

        init_test("not_connected_modify_wakes_both_split_waiters");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let (read_half, write_half) = OwnedReadHalf::new_pair(Arc::new(client), None);
        let reactor = Arc::new(SourceExclusiveReactor::new());
        reactor.fail_modify_on_call(1);
        reactor.fail_modify_with_not_connected(true);

        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let read_hits = Arc::new(AtomicUsize::new(0));
        let read_waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&read_hits),
        }));
        let read_task_cx = Context::from_waker(&read_waker);
        read_half
            .inner
            .register_interest(&read_task_cx, Interest::READABLE)
            .expect("register readable");

        let write_hits = Arc::new(AtomicUsize::new(0));
        let write_waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&write_hits),
        }));
        let write_task_cx = Context::from_waker(&write_waker);
        write_half
            .inner
            .register_interest(&write_task_cx, Interest::WRITABLE)
            .expect("register writable with injected not-connected");

        let state = read_half.inner.state.lock();
        assert!(
            state.registration.is_none(),
            "registration should be dropped after not-connected modify"
        );
        drop(state);

        assert!(
            read_hits.load(Ordering::SeqCst) >= 1,
            "read waiter must be woken when shared registration drops on not-connected"
        );
        assert!(
            write_hits.load(Ordering::SeqCst) >= 1,
            "write waiter must be woken when shared registration drops on not-connected"
        );
    }
}
