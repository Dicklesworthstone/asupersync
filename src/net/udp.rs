//! UDP networking primitives.
//!
//! Provides async UDP socket operations with reactor-based wakeup.
//!
//! # Cancel Safety
//!
//! - `send_to`/`send`: atomic datagrams, cancel-safe.
//! - `recv_from`/`recv`: cancel discards the datagram (UDP is unreliable).
//! - `connect`: cancel-safe (stateless).

use crate::cx::Cx;
use crate::net::lookup_all;
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use crate::stream::Stream;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket as StdUdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// A UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    inner: Arc<StdUdpSocket>,
    registration: Option<IoRegistration>,
}

impl UdpSocket {
    /// Bind to the given address.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(addr: A) -> io::Result<Self> {
        let addrs = lookup_all(addr).await?;
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no socket addresses found",
            ));
        }

        let mut last_err = None;
        for addr in addrs {
            match StdUdpSocket::bind(addr) {
                Ok(socket) => {
                    socket.set_nonblocking(true)?;
                    return Ok(Self {
                        inner: Arc::new(socket),
                        registration: None,
                    });
                }
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or_else(|| io::Error::other("failed to bind any address")))
    }

    /// Connect to a remote address (for send/recv).
    pub async fn connect<A: ToSocketAddrs + Send + 'static>(&self, addr: A) -> io::Result<()> {
        let addrs = lookup_all(addr).await?;
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no socket addresses found",
            ));
        }

        let mut last_err = None;
        for addr in addrs {
            match self.inner.connect(addr) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or_else(|| io::Error::other("failed to connect to any address")))
    }

    /// Send a datagram to the specified target.
    pub async fn send_to<A: ToSocketAddrs + Send + 'static>(
        &mut self,
        buf: &[u8],
        target: A,
    ) -> io::Result<usize> {
        let addrs = lookup_all(target).await?;
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no socket addresses found",
            ));
        }

        std::future::poll_fn(|cx| self.poll_send_to(cx, buf, &addrs)).await
    }

    /// Poll for send_to readiness.
    fn poll_send_to(
        &mut self,
        cx: &Context<'_>,
        buf: &[u8],
        addrs: &[SocketAddr],
    ) -> Poll<io::Result<usize>> {
        let mut last_err = None;
        for addr in addrs {
            match self.inner.send_to(buf, addr) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Socket not ready; register and wait.
                    if let Err(err) = self.register_interest(cx, Interest::WRITABLE) {
                        return Poll::Ready(Err(err));
                    }
                    return Poll::Pending;
                }
                Err(e) => last_err = Some(e),
            }
        }
        // All addresses failed with non-WouldBlock errors; return last error.
        Poll::Ready(Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no addresses to send to")
        })))
    }

    /// Receive a datagram and its source address.
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }

    /// Poll for recv_from readiness.
    pub fn poll_recv_from(
        &mut self,
        cx: &Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        match self.inner.recv_from(buf) {
            Ok(res) => Poll::Ready(Ok(res)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Send a datagram to the connected peer.
    pub async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        std::future::poll_fn(|cx| self.poll_send(cx, buf)).await
    }

    /// Poll for send readiness.
    pub fn poll_send(&mut self, cx: &Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.inner.send(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Receive a datagram from the connected peer.
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        std::future::poll_fn(|cx| self.poll_recv(cx, buf)).await
    }

    /// Poll for recv readiness.
    pub fn poll_recv(&mut self, cx: &Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match self.inner.recv(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Peek at the next datagram without consuming it.
    pub async fn peek_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::poll_fn(|cx| self.poll_peek_from(cx, buf)).await
    }

    /// Poll for peek_from readiness.
    pub fn poll_peek_from(
        &mut self,
        cx: &Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        match self.inner.peek_from(buf) {
            Ok(res) => Poll::Ready(Ok(res)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.register_interest(cx, Interest::READABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Returns the local address of this socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the peer address, if connected.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Sets the broadcast option.
    pub fn set_broadcast(&self, on: bool) -> io::Result<()> {
        self.inner.set_broadcast(on)
    }

    /// Sets the multicast loopback option for IPv4.
    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.inner.set_multicast_loop_v4(on)
    }

    /// Join an IPv4 multicast group.
    pub fn join_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.inner.join_multicast_v4(&multiaddr, &interface)
    }

    /// Leave an IPv4 multicast group.
    pub fn leave_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.inner.leave_multicast_v4(&multiaddr, &interface)
    }

    /// Set the time-to-live for this socket.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Join an IPv6 multicast group.
    pub fn join_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        self.inner.join_multicast_v6(multiaddr, interface)
    }

    /// Leave an IPv6 multicast group.
    pub fn leave_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        self.inner.leave_multicast_v6(multiaddr, interface)
    }

    /// Set the IPv4 multicast TTL.
    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_multicast_ttl_v4(ttl)
    }

    /// Returns a stream of incoming datagrams.
    #[must_use]
    pub fn recv_stream(&mut self, buf_size: usize) -> RecvStream<'_> {
        RecvStream::new(self, buf_size)
    }

    /// Returns a sink-like wrapper for sending datagrams.
    #[must_use]
    pub fn send_sink(&mut self) -> SendSink<'_> {
        SendSink::new(self)
    }

    /// Clone this socket via the underlying OS handle.
    ///
    /// The new socket gets its own reactor registration.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: Arc::new(self.inner.try_clone()?),
            registration: None,
        })
    }

    /// Consume this wrapper and return the underlying std socket if unique.
    pub fn into_std(self) -> io::Result<StdUdpSocket> {
        match Arc::try_unwrap(self.inner) {
            Ok(socket) => Ok(socket),
            Err(shared) => shared.try_clone(),
        }
    }

    /// Register interest with the reactor.
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

impl From<StdUdpSocket> for UdpSocket {
    fn from(socket: StdUdpSocket) -> Self {
        Self {
            inner: Arc::new(socket),
            registration: None,
        }
    }
}

/// Stream of incoming datagrams.
#[derive(Debug)]
pub struct RecvStream<'a> {
    socket: &'a mut UdpSocket,
    buf: Vec<u8>,
}

impl<'a> RecvStream<'a> {
    /// Create a new datagram stream with the given buffer size.
    #[must_use]
    pub fn new(socket: &'a mut UdpSocket, buf_size: usize) -> Self {
        Self {
            socket,
            buf: vec![0u8; buf_size],
        }
    }
}

impl Stream for RecvStream<'_> {
    type Item = io::Result<(Vec<u8>, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.socket.poll_recv_from(cx, &mut this.buf) {
            Poll::Ready(Ok((n, addr))) => Poll::Ready(Some(Ok((this.buf[..n].to_vec(), addr)))),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Sink-like wrapper for sending datagrams.
#[derive(Debug)]
pub struct SendSink<'a> {
    socket: &'a mut UdpSocket,
}

impl<'a> SendSink<'a> {
    /// Create a new send sink for the given socket.
    #[must_use]
    pub fn new(socket: &'a mut UdpSocket) -> Self {
        Self { socket }
    }

    /// Send a datagram to the specified target.
    pub async fn send_to<A: ToSocketAddrs + Send + 'static>(
        &mut self,
        buf: &[u8],
        target: A,
    ) -> io::Result<usize> {
        self.socket.send_to(buf, target).await
    }

    /// Send a datagram tuple.
    pub async fn send_datagram(&mut self, datagram: (Vec<u8>, SocketAddr)) -> io::Result<usize> {
        self.socket.send_to(&datagram.0, datagram.1).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::stream::StreamExt;
    use crate::types::{Budget, RegionId, TaskId};
    use futures_lite::future;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    #[test]
    fn udp_send_recv_from() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();

            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let payload = b"ping";

            let sent = client.send_to(payload, server_addr).await.unwrap();
            assert_eq!(sent, payload.len());

            let mut buf = [0u8; 16];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], payload);
            assert_eq!(peer, client.local_addr().unwrap());
        });
    }

    #[test]
    fn udp_connected_send_recv() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();

            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();

            server.connect(client_addr).await.unwrap();
            client.connect(server_addr).await.unwrap();

            let sent = client.send(b"hello").await.unwrap();
            assert_eq!(sent, 5);

            let mut buf = [0u8; 16];
            let n = server.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello");

            let sent = server.send(b"world").await.unwrap();
            assert_eq!(sent, 5);

            let n = client.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"world");
        });
    }

    #[test]
    fn udp_recv_stream_yields_datagram() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            client.send_to(b"stream", server_addr).await.unwrap();

            let mut stream = server.recv_stream(32);
            let item = stream.next().await.unwrap().unwrap();
            assert_eq!(item.0, b"stream");
        });
    }

    #[test]
    fn udp_peek_does_not_consume() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            client.send_to(b"peek", server_addr).await.unwrap();

            let mut buf = [0u8; 16];
            let (n, _) = server.peek_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"peek");

            let (n, _) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"peek");
        });
    }

    #[test]
    fn udp_socket_registers_on_wouldblock() {
        // Create a socket pair
        let std_server = StdUdpSocket::bind("127.0.0.1:0").expect("bind server");
        std_server.set_nonblocking(true).expect("nonblocking");

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

        let mut socket = UdpSocket::from(std_server);
        let waker = noop_waker();
        let cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];

        // poll_recv_from should return Pending and register with reactor
        let poll = socket.poll_recv_from(&cx, &mut buf);
        assert!(matches!(poll, Poll::Pending));
        assert!(socket.registration.is_some());
    }

    #[test]
    fn udp_try_clone_creates_independent_socket() {
        future::block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let cloned = socket.try_clone().unwrap();

            // Both should have same local address
            assert_eq!(socket.local_addr().unwrap(), cloned.local_addr().unwrap());

            // Cloned socket should have no registration
            assert!(cloned.registration.is_none());
        });
    }

    #[test]
    fn udp_large_datagram() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // Send a larger datagram (8KB)
            let payload = vec![0xAB; 8192];
            let sent = client.send_to(&payload, server_addr).await.unwrap();
            assert_eq!(sent, 8192);

            let mut buf = vec![0u8; 16384];
            let (n, _) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 8192);
            assert!(buf[..n].iter().all(|&b| b == 0xAB));
        });
    }
}
