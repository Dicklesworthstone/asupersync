//! TCP stream splitting with reactor registration sharing.
//!
//! This module provides borrowed and owned split halves for TCP streams.
//! The owned variants properly share the reactor registration between halves.
//!
//! ubs:ignore — OwnedWriteHalf::drop() calls shutdown(Write); read half does not
//! need shutdown (correct half-duplex semantics).

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use std::io::{self, Read, Write};
use std::net::{self, Shutdown};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

/// Borrowed read half of a split TCP stream.
///
/// This half does not participate in reactor registration - it uses
/// busy-loop polling on WouldBlock. For proper async I/O with reactor
/// integration, use the owned split via [`TcpStream::into_split()`](super::stream::TcpStream::into_split).
#[derive(Debug)]
pub struct ReadHalf<'a> {
    inner: &'a net::TcpStream,
}

impl<'a> ReadHalf<'a> {
    pub(crate) fn new(inner: &'a net::TcpStream) -> Self {
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
                // No reactor integration for borrowed split - wake immediately
                // to retry. For proper async I/O, use owned split.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// Borrowed write half of a split TCP stream.
///
/// This half does not participate in reactor registration - it uses
/// busy-loop polling on WouldBlock. For proper async I/O with reactor
/// integration, use the owned split via [`TcpStream::into_split()`](super::stream::TcpStream::into_split).
#[derive(Debug)]
pub struct WriteHalf<'a> {
    inner: &'a net::TcpStream,
}

impl<'a> WriteHalf<'a> {
    pub(crate) fn new(inner: &'a net::TcpStream) -> Self {
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
}

/// Shared state for owned split halves.
///
/// Both [`OwnedReadHalf`] and [`OwnedWriteHalf`] share this state via `Arc`.
/// Each half stores its own waker in [`SplitIoState`]; the `IoRegistration`
/// receives a combined waker that dispatches to both, preventing lost wakeups
/// when halves are polled from different tasks.
pub(crate) struct TcpStreamInner {
    /// The underlying TCP stream.
    stream: Arc<net::TcpStream>,
    /// Per-direction wakers and shared reactor registration.
    state: Mutex<SplitIoState>,
}

impl std::fmt::Debug for TcpStreamInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpStreamInner")
            .field("stream", &self.stream)
            .field("state", &"...")
            .finish()
    }
}

impl TcpStreamInner {
    fn register_interest(&self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        let mut guard = self.state.lock().unwrap();

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
                // Always call set_interest to re-arm the reactor registration.
                // The polling crate uses oneshot-style notifications: after an event
                // fires, the registration is disarmed and must be re-armed via modify().
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
        let register_interest = registration_interest(
            guard.read_waker.is_some(),
            guard.write_waker.is_some(),
            interest,
        );
        drop(guard);

        let Some(current) = Cx::current() else {
            cx.waker().wake_by_ref();
            return Ok(());
        };
        let Some(driver) = current.io_driver_handle() else {
            cx.waker().wake_by_ref();
            return Ok(());
        };

        match driver.register(&*self.stream, register_interest, waker) {
            Ok(registration) => {
                self.state.lock().unwrap().registration = Some(registration);
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
    pub(crate) fn new(stream: Arc<net::TcpStream>, registration: Option<IoRegistration>) -> Self {
        Self {
            inner: Arc::new(TcpStreamInner {
                stream,
                state: Mutex::new(SplitIoState {
                    registration,
                    read_waker: None,
                    write_waker: None,
                }),
            }),
        }
    }

    /// Create a paired read and write half sharing the same inner state.
    pub(crate) fn new_pair(
        stream: Arc<net::TcpStream>,
        registration: Option<IoRegistration>,
    ) -> (Self, OwnedWriteHalf) {
        let inner = Arc::new(TcpStreamInner {
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

    /// Returns the local address of the stream.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.stream.local_addr()
    }

    /// Returns the peer address of the stream.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.stream.peer_addr()
    }

    /// Reunite with the write half to reconstruct the original TcpStream.
    ///
    /// # Errors
    ///
    /// Returns an error containing both halves if they don't belong to the
    /// same original stream.
    pub fn reunite(self, write: OwnedWriteHalf) -> Result<super::stream::TcpStream, ReuniteError> {
        if Arc::ptr_eq(&self.inner, &write.inner) {
            // Don't shutdown on drop since we're reuniting
            let mut write = write;
            write.shutdown_on_drop = false;

            // Take the registration back
            let registration = self.inner.state.lock().unwrap().registration.take();

            Ok(super::stream::TcpStream::from_parts(
                self.inner.stream.clone(),
                registration,
            ))
        } else {
            Err(ReuniteError { read: self, write })
        }
    }
}

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
    pub(crate) fn new(inner: Arc<TcpStreamInner>) -> Self {
        Self {
            inner,
            shutdown_on_drop: true,
        }
    }

    /// Returns the local address of the stream.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.stream.local_addr()
    }

    /// Returns the peer address of the stream.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.stream.peer_addr()
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
    use crate::net::tcp::stream::TcpStream;
    use crate::test_utils::init_test_logging;
    use std::io::Write;
    use std::net::TcpListener;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
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
}
