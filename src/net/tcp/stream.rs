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
use crate::time::timeout;
use crate::types::Time;
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
    shutdown_on_drop: bool,
}

/// Builder for configuring TCP stream options before connecting.
///
/// This mirrors [`TcpListenerBuilder`](super::traits::TcpListenerBuilder) for client connections.
/// Options are applied after a successful connect.
#[derive(Debug, Clone)]
pub struct TcpStreamBuilder<A> {
    addr: A,
    connect_timeout: Option<Duration>,
    nodelay: Option<bool>,
    keepalive: Option<Duration>,
}

impl<A> TcpStreamBuilder<A>
where
    A: ToSocketAddrs + Send + 'static,
{
    /// Create a new builder for the given address.
    #[must_use]
    pub fn new(addr: A) -> Self {
        Self {
            addr,
            connect_timeout: None,
            nodelay: None,
            keepalive: None,
        }
    }

    /// Set a connection timeout.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Enable or disable TCP_NODELAY.
    #[must_use]
    pub fn nodelay(mut self, enable: bool) -> Self {
        self.nodelay = Some(enable);
        self
    }

    /// Configure TCP keepalive.
    ///
    /// Note: Phase 0 does not support keepalive on all platforms; enabling
    /// this may return `io::ErrorKind::Unsupported`.
    #[must_use]
    pub fn keepalive(mut self, keepalive: Option<Duration>) -> Self {
        self.keepalive = keepalive;
        self
    }

    /// Connect using the configured options.
    pub async fn connect(self) -> io::Result<TcpStream> {
        let Self {
            addr,
            connect_timeout,
            nodelay,
            keepalive,
        } = self;

        let stream = if let Some(timeout) = connect_timeout {
            let addr = lookup_one(addr).await?;
            TcpStream::connect_timeout(addr, timeout).await?
        } else {
            TcpStream::connect(addr).await?
        };

        if let Some(enable) = nodelay {
            stream.set_nodelay(enable)?;
        }

        if let Some(keepalive) = keepalive {
            stream.set_keepalive(Some(keepalive))?;
        }

        Ok(stream)
    }
}

impl TcpStream {
    /// Create a TcpStream from a standard library TcpStream.
    ///
    /// This is used for testing to wrap a synchronous stream into an async one.
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) fn from_std(stream: net::TcpStream) -> io::Result<Self> {
        // Ensure async poll paths do not inherit blocking sockets.
        stream.set_nonblocking(true)?;
        Ok(Self {
            inner: Arc::new(stream),
            registration: None,
            shutdown_on_drop: true,
        })
    }

    /// Reconstruct a TcpStream from its parts (used by reunite).
    pub(crate) fn from_parts(
        inner: Arc<net::TcpStream>,
        registration: Option<IoRegistration>,
    ) -> Self {
        Self {
            inner,
            registration,
            shutdown_on_drop: true,
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

        Self::connect_from_socket(socket, addr).await
    }

    /// Connects using an existing configured socket.
    pub(crate) async fn connect_from_socket(socket: Socket, addr: SocketAddr) -> io::Result<Self> {
        socket.set_nonblocking(true)?;

        // 2. Attempt connect (non-blocking)
        let sock_addr = SockAddr::from(addr);
        let registration = match socket.connect(&sock_addr) {
            Ok(()) => None,
            Err(err) if connect_in_progress(&err) => wait_for_connect(&socket).await?,
            Err(err) => return Err(err),
        };

        // socket.into() preserves the nonblocking flag set above; no need to set again.
        let stream: net::TcpStream = socket.into();
        Ok(Self::from_parts(Arc::new(stream), registration))
    }

    /// Connect with timeout.
    pub async fn connect_timeout(addr: SocketAddr, timeout_duration: Duration) -> io::Result<Self> {
        let connect_future = Box::pin(Self::connect(addr));
        match timeout(timeout_now(), timeout_duration, connect_future).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tcp connect timeout",
            )),
        }
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
    ///
    /// Uses `socket2` to configure `SO_KEEPALIVE` and platform-specific
    /// keepalive idle time. Pass `None` to disable keepalive.
    pub fn set_keepalive(&self, keepalive: Option<Duration>) -> io::Result<()> {
        let socket = socket2::SockRef::from(&*self.inner);
        match keepalive {
            Some(interval) => {
                let params = socket2::TcpKeepalive::new().with_time(interval);
                socket.set_tcp_keepalive(&params)?;
            }
            None => {
                socket.set_keepalive(false)?;
            }
        }
        Ok(())
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
        let mut this = self;
        this.shutdown_on_drop = false;
        let registration = this.registration.take();
        let inner = this.inner.clone();
        OwnedReadHalf::new_pair(inner, registration)
    }

    fn register_interest(&mut self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        if let Some(registration) = &mut self.registration {
            let combined = registration.interest() | interest;
            // Always call set_interest to re-arm the reactor registration.
            // The polling crate uses oneshot-style notifications: after an event
            // fires, the registration is disarmed and must be re-armed via modify()
            // before new events will be delivered.
            if let Err(err) = registration.set_interest(combined) {
                if err.kind() == io::ErrorKind::NotConnected {
                    self.registration = None;
                    cx.waker().wake_by_ref();
                    return Ok(());
                }
                return Err(err);
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

fn timeout_now() -> Time {
    Cx::current()
        .and_then(|current| current.timer_driver())
        // Outside an active runtime context we still want timeouts to behave
        // correctly using wall time. Using `Time::ZERO` here is subtly wrong
        // because `Sleep`'s fallback clock is `wall_now()` (module-relative),
        // so a zero "now" can cause premature timeouts if `wall_now()` has
        // already advanced due to prior time ops in the same process.
        .map_or_else(crate::time::wall_now, |driver| driver.now())
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
                if let Err(err) = rearm_connect_registration(&mut registration, cx) {
                    return Poll::Ready(Err(err));
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

/// Re-arm a pending connect registration that uses oneshot reactor semantics.
///
/// The polling backend disarms registrations after each readiness event. Even
/// when the interest flags are unchanged (`WRITABLE` during connect), we must
/// call `set_interest` again to ensure subsequent connect progress events are
/// delivered.
fn rearm_connect_registration(
    registration: &mut Option<IoRegistration>,
    cx: &Context<'_>,
) -> io::Result<()> {
    let Some(existing) = registration.as_mut() else {
        return Ok(());
    };

    if let Err(err) = existing.set_interest(Interest::WRITABLE) {
        if err.kind() == io::ErrorKind::NotConnected {
            *registration = None;
            cx.waker().wake_by_ref();
            return Ok(());
        }
        return Err(err);
    }

    if !existing.update_waker(cx.waker().clone()) {
        *registration = None;
    }

    Ok(())
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

// ubs:ignore — TcpStream performs a best-effort shutdown on drop for deterministic teardown.
// into_split() disables shutdown_on_drop to avoid closing the shared stream; callers should
// still prefer explicit shutdown() for protocol-aware half-close behavior.

impl Drop for TcpStream {
    fn drop(&mut self) {
        if self.shutdown_on_drop {
            let _ = self.inner.shutdown(Shutdown::Both);
        }
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
        Self::peer_addr(self)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        Self::shutdown(self, how)
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        Self::set_nodelay(self, nodelay)
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
    use crate::runtime::reactor::{Events, Reactor, Token};
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId, Time};
    use futures_lite::future;
    #[cfg(unix)]
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use std::future::poll_fn;
    use std::future::Future;
    use std::io;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    struct CountingReactor {
        inner: LabReactor,
        modify_calls: AtomicUsize,
    }

    impl CountingReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: LabReactor::new(),
                modify_calls: AtomicUsize::new(0),
            })
        }

        fn modify_calls(&self) -> usize {
            self.modify_calls.load(Ordering::SeqCst)
        }
    }

    impl Reactor for CountingReactor {
        fn register(
            &self,
            source: &dyn crate::runtime::reactor::Source,
            token: Token,
            interest: Interest,
        ) -> io::Result<()> {
            self.inner.register(source, token, interest)
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            self.modify_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.modify(token, interest)
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            self.inner.deregister(token)
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            self.inner.poll(events, timeout)
        }

        fn wake(&self) -> io::Result<()> {
            self.inner.wake()
        }

        fn registration_count(&self) -> usize {
            self.inner.registration_count()
        }
    }

    #[test]
    fn tcp_stream_builder_defaults() {
        let builder = TcpStreamBuilder::new("127.0.0.1:0");
        assert!(builder.connect_timeout.is_none());
        assert!(builder.nodelay.is_none());
        assert!(builder.keepalive.is_none());
    }

    #[test]
    fn tcp_stream_builder_chain() {
        let builder = TcpStreamBuilder::new("127.0.0.1:0")
            .connect_timeout(Duration::from_secs(1))
            .nodelay(true)
            .keepalive(Some(Duration::from_secs(30)));

        assert_eq!(builder.connect_timeout, Some(Duration::from_secs(1)));
        assert_eq!(builder.nodelay, Some(true));
        assert_eq!(builder.keepalive, Some(Duration::from_secs(30)));
    }

    #[test]
    fn timeout_now_uses_wall_now_when_no_runtime_is_active() {
        assert!(
            Cx::current().is_none(),
            "test must run without an active Cx"
        );

        let t0 = crate::time::wall_now();
        std::thread::sleep(Duration::from_millis(20));
        let now = super::timeout_now();

        assert!(
            now >= t0,
            "timeout_now must be consistent with wall_now outside a runtime"
        );
        assert!(
            now > Time::ZERO,
            "wall time should have advanced; timeout_now should not be hard-coded to ZERO"
        );
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
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut stream = TcpStream::from_std(client).expect("wrap stream");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Pending));
        assert!(stream.registration.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn tcp_stream_from_std_forces_nonblocking_mode() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");

        let stream = TcpStream::from_std(client).expect("wrap stream");
        let flags = fcntl(stream.inner.as_ref(), FcntlArg::F_GETFL).expect("read stream flags");
        let is_nonblocking = OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK);
        assert!(
            is_nonblocking,
            "TcpStream::from_std should force nonblocking mode"
        );
    }

    #[test]
    fn connect_waiter_rearms_existing_registration_with_unchanged_interest() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let reactor = CountingReactor::new();
        let driver = IoDriverHandle::new(reactor.clone());
        let registration = driver
            .register(&client, Interest::WRITABLE, noop_waker())
            .expect("register");
        let mut registration = Some(registration);

        let waker = noop_waker();
        let cx = Context::from_waker(&waker);

        rearm_connect_registration(&mut registration, &cx).expect("re-arm once");
        rearm_connect_registration(&mut registration, &cx).expect("re-arm twice");

        assert_eq!(
            reactor.modify_calls(),
            2,
            "connect waiter must re-arm on every poll, even when interest is unchanged"
        );
        assert!(registration.is_some(), "registration should remain active");
    }

    #[test]
    fn connect_waiter_clears_registration_when_driver_drops() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let reactor = CountingReactor::new();
        let driver = IoDriverHandle::new(reactor);
        let registration = driver
            .register(&client, Interest::WRITABLE, noop_waker())
            .expect("register");
        let mut registration = Some(registration);
        drop(driver);

        let waker = noop_waker();
        let cx = Context::from_waker(&waker);
        rearm_connect_registration(&mut registration, &cx).expect("re-arm with dropped driver");

        assert!(
            registration.is_none(),
            "stale connect registration should be cleared when driver is gone"
        );
    }
}
