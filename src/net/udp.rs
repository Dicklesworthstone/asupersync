//! UDP networking primitives.
//!
//! Phase 0 wraps `std::net::UdpSocket` with async-looking methods that
//! execute synchronous calls.
//!
//! # Cancel Safety
//!
//! - `send_to`/`send`: atomic datagrams, cancel-safe.
//! - `recv_from`/`recv`: cancel discards the datagram (UDP is unreliable).
//! - `connect`: cancel-safe (stateless).

#![allow(clippy::unused_async)]

use crate::stream::Stream;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket as StdUdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// A UDP socket.
#[derive(Debug, Clone)]
pub struct UdpSocket {
    pub(crate) inner: Arc<StdUdpSocket>,
}

impl UdpSocket {
    /// Bind to the given address.
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = StdUdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self::from(socket))
    }

    /// Connect to a remote address (for send/recv).
    pub async fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        self.inner.connect(addr)
    }

    /// Send a datagram to the specified target.
    pub async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> io::Result<usize> {
        // TODO: Async send
        match self.inner.send_to(buf, target) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => std::future::pending().await,
            Err(e) => Err(e),
        }
    }

    /// Receive a datagram and its source address.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // TODO: Async recv
        loop {
            match self.inner.recv_from(buf) {
                Ok(res) => return Ok(res),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::future::pending::<()>().await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Send a datagram to the connected peer.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.send(buf) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => std::future::pending().await,
            Err(e) => Err(e),
        }
    }

    /// Receive a datagram from the connected peer.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.inner.recv(buf) {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::future::pending::<()>().await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Peek at the next datagram without consuming it.
    pub async fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            match self.inner.peek_from(buf) {
                Ok(res) => return Ok(res),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::future::pending::<()>().await;
                }
                Err(e) => return Err(e),
            }
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
    pub fn recv_stream(&self, buf_size: usize) -> RecvStream<'_> {
        RecvStream::new(self, buf_size)
    }

    /// Returns a sink-like wrapper for sending datagrams.
    #[must_use]
    pub fn send_sink(&self) -> SendSink<'_> {
        SendSink::new(self)
    }

    /// Clone this socket via the underlying OS handle.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self::from(self.inner.try_clone()?))
    }

    /// Consume this wrapper and return the underlying std socket if unique.
    pub fn into_std(self) -> io::Result<StdUdpSocket> {
        match Arc::try_unwrap(self.inner) {
            Ok(socket) => Ok(socket),
            Err(shared) => shared.try_clone(),
        }
    }
}

impl From<StdUdpSocket> for UdpSocket {
    fn from(socket: StdUdpSocket) -> Self {
        Self {
            inner: Arc::new(socket),
        }
    }
}

/// Stream of incoming datagrams.
#[derive(Debug)]
pub struct RecvStream<'a> {
    socket: &'a UdpSocket,
    buf_size: usize,
}

impl<'a> RecvStream<'a> {
    /// Create a new datagram stream with the given buffer size.
    #[must_use]
    pub fn new(socket: &'a UdpSocket, buf_size: usize) -> Self {
        Self { socket, buf_size }
    }
}

impl Stream for RecvStream<'_> {
    type Item = io::Result<(Vec<u8>, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut buf = vec![0u8; this.buf_size];
        match this.socket.inner.recv_from(&mut buf) {
            Ok((n, addr)) => {
                buf.truncate(n);
                Poll::Ready(Some(Ok((buf, addr))))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Some(Err(err))),
        }
    }
}

/// Sink-like wrapper for sending datagrams.
#[derive(Debug)]
pub struct SendSink<'a> {
    socket: &'a UdpSocket,
}

impl<'a> SendSink<'a> {
    /// Create a new send sink for the given socket.
    #[must_use]
    pub fn new(socket: &'a UdpSocket) -> Self {
        Self { socket }
    }

    /// Send a datagram to the specified target.
    pub async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> io::Result<usize> {
        self.socket.send_to(buf, target).await
    }

    /// Send a datagram tuple.
    pub async fn send_datagram(&self, datagram: (Vec<u8>, SocketAddr)) -> io::Result<usize> {
        self.socket.send_to(&datagram.0, datagram.1).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::StreamExt;
    use futures_lite::future;

    #[test]
    fn udp_send_recv_from() {
        future::block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();

            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
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
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();

            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
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
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            client.send_to(b"stream", server_addr).await.unwrap();

            let mut stream = server.recv_stream(32);
            let item = stream.next().await.unwrap().unwrap();
            assert_eq!(item.0, b"stream");
        });
    }

    #[test]
    fn udp_peek_does_not_consume() {
        future::block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            client.send_to(b"peek", server_addr).await.unwrap();

            let mut buf = [0u8; 16];
            let (n, _) = server.peek_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"peek");

            let (n, _) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"peek");
        });
    }
}
