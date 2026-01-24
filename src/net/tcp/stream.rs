//! TCP stream implementation.
//!
//! This module provides a TCP stream for reading and writing data over a connection.
//! The stream implements [`TcpStreamApi`] for use with generic code and frameworks.

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncReadVectored, AsyncWrite, ReadBuf};
use crate::net::lookup_one;
use crate::net::tcp::split::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf};
use crate::net::tcp::traits::TcpStreamApi;
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{self, IoSlice, IoSliceMut};
use std::net::{self, Shutdown, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// A TCP stream.
#[derive(Debug)]
pub struct TcpStream {
    inner: Arc<net::TcpStream>,
    registration: Option<IoRegistration>,
}

impl TcpStream {
    /// Create a TcpStream from a standard library TcpStream.
    ///
    /// This is used for testing to wrap a synchronous stream into an async one.
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) fn from_std(stream: net::TcpStream) -> Self {
        Self {
            inner: Arc::new(stream),
            registration: None,
        }
    }

    /// Reconstruct a TcpStream from its parts (used by reunite).
    pub(crate) fn from_parts(
        inner: Arc<net::TcpStream>,
        registration: Option<IoRegistration>,
    ) -> Self {
        Self {
            inner,
            registration,
        }
    }

    /// Connect to address.
    pub async fn connect<A: ToSocketAddrs + Send + 'static>(addr: A) -> io::Result<Self> {
        // 1. Resolve and create socket
        let addr = lookup_one(addr).await?;
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;

        // 2. Attempt connect (non-blocking)
        let sock_addr = SockAddr::from(addr);
        let registration = match socket.connect(&sock_addr) {
            Ok(()) => None,
            Err(err) if connect_in_progress(&err) => wait_for_connect(&socket).await?,
            Err(err) => return Err(err),
        };

        let stream: net::TcpStream = socket.into();
        stream.set_nonblocking(true)?;
        Ok(Self::from_parts(Arc::new(stream), registration))
    }

    /// Connect with timeout.
    pub async fn connect_timeout(addr: SocketAddr, timeout: Duration) -> io::Result<Self> {
        let stream = net::TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_nonblocking(true)?;
        Ok(Self::from_std(stream))
    }

    /// Get peer address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Get local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Shutdown.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    /// Set TCP_NODELAY.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    /// Set keepalive.
    pub fn set_keepalive(&self, _keepalive: Option<Duration>) -> io::Result<()> {
        // Not supported in std
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "set_keepalive not supported",
        ))
    }

    /// Split into borrowed halves.
    #[must_use]
    pub fn split(&self) -> (ReadHalf<'_>, WriteHalf<'_>) {
        (ReadHalf::new(&self.inner), WriteHalf::new(&self.inner))
    }

    /// Split into owned halves.
    ///
    /// The owned halves share the reactor registration, allowing proper
    /// async I/O with wakeup notifications. Use [`reunite`] to reconstruct
    /// the original stream.
    ///
    /// [`reunite`]: OwnedReadHalf::reunite
    #[must_use]
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        OwnedReadHalf::new_pair(self.inner, self.registration)
    }

    fn register_interest(&mut self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        if let Some(registration) = &mut self.registration {
            let combined = registration.interest() | interest;
            if combined != registration.interest() {
                if let Err(err) = registration.set_interest(combined) {
                    if err.kind() == io::ErrorKind::NotConnected {
                        self.registration = None;
                        cx.waker().wake_by_ref();
                        return Ok(());
                    }
                    return Err(err);
                }
            }
            if registration.update_waker(cx.waker().clone()) {
                return Ok(());
            }
            self.registration = None;
        }

        let Some(current) = Cx::current() else {
            cx.waker().wake_by_ref();
            return Ok(());
        };
        let Some(driver) = current.io_driver_handle() else {
            cx.waker().wake_by_ref();
            return Ok(());
        };

        match driver.register(&*self.inner, interest, cx.waker().clone()) {
            Ok(registration) => {
                self.registration = Some(registration);
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

fn connect_in_progress(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) || err.raw_os_error() == Some(libc::EINPROGRESS)
}

async fn wait_for_connect(socket: &Socket) -> io::Result<Option<IoRegistration>> {
    let Some(driver) = Cx::current().and_then(|cx| cx.io_driver_handle()) else {
        wait_for_connect_fallback(socket).await?;
        return Ok(None);
    };

    let mut registration: Option<IoRegistration> = None;
    let mut fallback = false;
    std::future::poll_fn(|cx| {
        if let Some(err) = socket.take_error()? {
            return Poll::Ready(Err(err));
        }

        match socket.peer_addr() {
            Ok(_) => Poll::Ready(Ok(())),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                if let Some(existing) = registration.as_ref() {
                    if !existing.update_waker(cx.waker().clone()) {
                        registration = None;
                    }
                }

                if registration.is_none() {
                    match driver.register(socket, Interest::WRITABLE, cx.waker().clone()) {
                        Ok(new_reg) => registration = Some(new_reg),
                        Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                            fallback = true;
                            return Poll::Ready(Ok(()));
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    }
                }

                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    })
    .await?;

    if fallback {
        wait_for_connect_fallback(socket).await?;
        return Ok(None);
    }

    Ok(registration)
}

async fn wait_for_connect_fallback(socket: &Socket) -> io::Result<()> {
    loop {
        if let Some(err) = socket.take_error()? {
            return Err(err);
        }

        match socket.peer_addr() {
            Ok(_) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                // Sleep briefly to avoid busy loop when no reactor is available.
                std::thread::sleep(Duration::from_millis(1));
                crate::runtime::yield_now().await;
            }
            Err(err) => return Err(err),
        }
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use std::io::Read;
        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        // std::net::TcpStream implements Read for &TcpStream
        match (&*inner).read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncReadVectored for TcpStream {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        use std::io::Read;

        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        match (&*inner).read_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use std::io::Write;
        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        match (&*inner).write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::WRITABLE) {
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
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        use std::io::Write;

        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        match (&*inner).write_vectored(bufs) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::WRITABLE) {
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
        use std::io::Write;
        let this = self.get_mut();
        let inner: &net::TcpStream = &this.inner;
        match (&*inner).flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = this.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
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

// Implement the TcpStreamApi trait for TcpStream
impl TcpStreamApi for TcpStream {
    fn connect<A: ToSocketAddrs + Send + 'static>(
        addr: A,
    ) -> impl std::future::Future<Output = io::Result<Self>> + Send {
        Self::connect(addr)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        TcpStream::set_nodelay(self, nodelay)
    }

    fn nodelay(&self) -> io::Result<bool> {
        self.inner.nodelay()
    }

    fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId};
    use futures_lite::future;
    use std::future::poll_fn;
    use std::future::Future;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    #[test]
    fn tcp_connect_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let handle = std::thread::spawn(move || future::block_on(TcpStream::connect(addr)));

        let _ = listener.accept().expect("accept");
        let stream = handle.join().expect("join").expect("connect");
        assert!(stream.peer_addr().is_ok());
    }

    #[test]
    fn tcp_connect_refused() {
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("local addr")
        };

        let result = future::block_on(TcpStream::connect(addr));
        assert!(result.is_err());
    }

    #[test]
    fn tcp_connect_cancel_does_not_deadlock() {
        let addr: SocketAddr = "192.0.2.1:81".parse().expect("addr");
        let mut fut = Box::pin(TcpStream::connect(addr));

        future::block_on(poll_fn(|cx| match fut.as_mut().poll(cx) {
            Poll::Pending | Poll::Ready(_) => Poll::Ready(()),
        }));

        drop(fut);
    }

    #[test]
    fn tcp_stream_registers_on_wouldblock() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        server.set_nonblocking(true).expect("nonblocking");

        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
        );
        let _guard = Cx::set_current(Some(cx));

        let mut stream = TcpStream::from_std(client);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Pending));
        assert!(stream.registration.is_some());
    }
}
