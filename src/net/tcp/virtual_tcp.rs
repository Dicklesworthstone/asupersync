//! Virtual TCP implementations for deterministic testing.
//!
//! This module provides [`VirtualTcpListener`] and [`VirtualTcpStream`] that
//! implement [`TcpListenerApi`] and [`TcpStreamApi`] respectively, using
//! in-memory buffers instead of real sockets.
//!
//! # Usage
//!
//! ```rust,ignore
//! use asupersync::net::tcp::virtual_tcp::{VirtualTcpListener, VirtualTcpStream};
//!
//! // Create a listener
//! let listener = VirtualTcpListener::new("127.0.0.1:8080".parse().unwrap());
//!
//! // Inject a connection (simulating an incoming client)
//! let (client_stream, server_stream) = VirtualTcpStream::pair(
//!     "127.0.0.1:9000".parse().unwrap(),
//!     "127.0.0.1:8080".parse().unwrap(),
//! );
//! listener.inject_connection(server_stream, "127.0.0.1:9000".parse().unwrap());
//!
//! // Accept the connection
//! let (stream, addr) = listener.accept().await?;
//! ```

use super::traits::{TcpListenerApi, TcpStreamApi};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::collections::VecDeque;
use std::io;
use std::net::{Shutdown, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

// =============================================================================
// VirtualTcpStream
// =============================================================================

/// Shared half of a virtual TCP connection's byte channel.
struct ChannelHalf {
    buf: VecDeque<u8>,
    waker: Option<Waker>,
    closed: bool,
    read_shutdown: bool,
}

impl ChannelHalf {
    fn new() -> Self {
        Self {
            buf: VecDeque::new(),
            waker: None,
            closed: false,
            read_shutdown: false,
        }
    }
}

/// A virtual TCP stream backed by in-memory buffers.
///
/// Created via [`VirtualTcpStream::pair`], which returns two connected streams
/// (one for each side of the connection). Data written to one stream can be
/// read from the other.
///
/// # Cancel-Safety
///
/// All read/write operations are cancel-safe. Partial reads discard unread
/// data from the caller's perspective, and partial writes are valid.
pub struct VirtualTcpStream {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    /// Channel from which this stream reads (the other side writes here).
    read_half: Arc<Mutex<ChannelHalf>>,
    /// Channel to which this stream writes (the other side reads from here).
    write_half: Arc<Mutex<ChannelHalf>>,
    nodelay: AtomicBool,
    ttl: AtomicU32,
    write_shutdown: AtomicBool,
}

impl std::fmt::Debug for VirtualTcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualTcpStream")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

impl VirtualTcpStream {
    /// Create a connected pair of virtual TCP streams.
    ///
    /// Data written to one stream can be read from the other.
    /// `a_addr` is the local address of the first stream (and peer of the second),
    /// `b_addr` is the local address of the second stream (and peer of the first).
    #[must_use]
    pub fn pair(a_addr: SocketAddr, b_addr: SocketAddr) -> (Self, Self) {
        let a_to_b = Arc::new(Mutex::new(ChannelHalf::new()));
        let b_to_a = Arc::new(Mutex::new(ChannelHalf::new()));

        let stream_a = Self {
            local_addr: a_addr,
            peer_addr: b_addr,
            read_half: Arc::clone(&b_to_a),
            write_half: Arc::clone(&a_to_b),
            nodelay: AtomicBool::new(false),
            ttl: AtomicU32::new(64),
            write_shutdown: AtomicBool::new(false),
        };

        let stream_b = Self {
            local_addr: b_addr,
            peer_addr: a_addr,
            read_half: a_to_b,
            write_half: b_to_a,
            nodelay: AtomicBool::new(false),
            ttl: AtomicU32::new(64),
            write_shutdown: AtomicBool::new(false),
        };

        (stream_a, stream_b)
    }
}

impl AsyncRead for VirtualTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut half = this.read_half.lock().expect("channel lock poisoned");

        if half.read_shutdown {
            return Poll::Ready(Ok(()));
        }

        if half.buf.is_empty() {
            if half.closed {
                // EOF: peer closed their write side
                return Poll::Ready(Ok(()));
            }
            half.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let unfilled = buf.unfilled();
        let to_read = unfilled.len().min(half.buf.len());
        let drained: Vec<u8> = half.buf.drain(..to_read).collect();
        drop(half);
        unfilled[..to_read].copy_from_slice(&drained);
        buf.advance(to_read);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for VirtualTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_shutdown.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write half shutdown",
            )));
        }

        let mut half = this.write_half.lock().expect("channel lock poisoned");
        if half.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "peer closed",
            )));
        }

        if half.read_shutdown {
            // Peer shut down their read side; accept data but discard it.
            return Poll::Ready(Ok(buf.len()));
        }

        half.buf.extend(buf);
        let wake = half.waker.take();
        drop(half);
        if let Some(waker) = wake {
            waker.wake();
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_shutdown.store(true, Ordering::Relaxed);

        // Signal EOF to the reader
        let mut half = this.write_half.lock().expect("channel lock poisoned");
        half.closed = true;
        let wake = half.waker.take();
        drop(half);
        if let Some(waker) = wake {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl Unpin for VirtualTcpStream {}

impl Drop for VirtualTcpStream {
    fn drop(&mut self) {
        *self.write_shutdown.get_mut() = true;

        let read_wake = self.read_half.lock().map_or_else(
            |_| None,
            |mut half| {
                half.read_shutdown = true;
                half.buf.clear();
                half.waker.take()
            },
        );
        if let Some(waker) = read_wake {
            waker.wake();
        }

        let write_wake = self.write_half.lock().map_or_else(
            |_| None,
            |mut half| {
                half.closed = true;
                half.waker.take()
            },
        );
        if let Some(waker) = write_wake {
            waker.wake();
        }
    }
}

#[allow(clippy::manual_async_fn)] // trait signature uses `impl Future`, not `async fn`
impl TcpStreamApi for VirtualTcpStream {
    fn connect<A: ToSocketAddrs + Send + 'static>(
        _addr: A,
    ) -> impl std::future::Future<Output = io::Result<Self>> + Send {
        async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "VirtualTcpStream::connect not supported; use VirtualTcpStream::pair()",
            ))
        }
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match how {
            Shutdown::Read | Shutdown::Both => {
                let mut half = self.read_half.lock().expect("lock poisoned");
                half.read_shutdown = true;
                half.buf.clear();
                let wake = half.waker.take();
                drop(half);
                if let Some(waker) = wake {
                    waker.wake();
                }
            }
            Shutdown::Write => {}
        }
        match how {
            Shutdown::Write | Shutdown::Both => {
                self.write_shutdown.store(true, Ordering::Relaxed);
                let mut half = self.write_half.lock().expect("lock poisoned");
                half.closed = true;
                let wake = half.waker.take();
                drop(half);
                if let Some(waker) = wake {
                    waker.wake();
                }
            }
            Shutdown::Read => {}
        }
        Ok(())
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.nodelay.store(nodelay, Ordering::Relaxed);
        Ok(())
    }

    fn nodelay(&self) -> io::Result<bool> {
        Ok(self.nodelay.load(Ordering::Relaxed))
    }

    fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.ttl.store(ttl, Ordering::Relaxed);
        Ok(())
    }

    fn ttl(&self) -> io::Result<u32> {
        Ok(self.ttl.load(Ordering::Relaxed))
    }
}

// =============================================================================
// VirtualTcpListener
// =============================================================================

/// Internal state for the virtual listener.
struct VirtualListenerState {
    connections: VecDeque<(VirtualTcpStream, SocketAddr)>,
    waker: Option<Waker>,
    closed: bool,
}

/// A virtual TCP listener for deterministic testing.
///
/// Instead of binding to a real network address, this listener accepts
/// connections that are injected via [`VirtualTcpListener::inject_connection`].
///
/// # Usage
///
/// ```rust,ignore
/// let listener = VirtualTcpListener::new("127.0.0.1:8080".parse().unwrap());
///
/// // From test code: inject a connection
/// let (client, server) = VirtualTcpStream::pair(
///     "127.0.0.1:9000".parse().unwrap(),
///     "127.0.0.1:8080".parse().unwrap(),
/// );
/// listener.inject_connection(server, "127.0.0.1:9000".parse().unwrap());
///
/// // From server code: accept the connection
/// let (stream, addr) = listener.accept().await?;
/// assert_eq!(addr, "127.0.0.1:9000".parse::<SocketAddr>().unwrap());
/// ```
pub struct VirtualTcpListener {
    addr: SocketAddr,
    state: Arc<Mutex<VirtualListenerState>>,
}

impl Drop for VirtualTcpListener {
    fn drop(&mut self) {
        self.close();
    }
}

impl std::fmt::Debug for VirtualTcpListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualTcpListener")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl VirtualTcpListener {
    /// Create a new virtual listener bound to the given address.
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            state: Arc::new(Mutex::new(VirtualListenerState {
                connections: VecDeque::new(),
                waker: None,
                closed: false,
            })),
        }
    }

    /// Inject a connection into the listener's accept queue.
    ///
    /// The stream will be returned by the next `accept()` call.
    /// `remote_addr` is the address reported as the peer address.
    pub fn inject_connection(&self, stream: VirtualTcpStream, remote_addr: SocketAddr) {
        let mut state = self.state.lock().expect("lock poisoned");
        if state.closed {
            // Listener is closed: do not enqueue new virtual connections.
            return;
        }
        state.connections.push_back((stream, remote_addr));
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }

    /// Returns the number of pending (injected but not yet accepted) connections.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.state.lock().expect("lock poisoned").connections.len()
    }

    /// Close the listener, causing future `accept()` calls to return an error.
    pub fn close(&self) {
        let mut state = self.state.lock().expect("lock poisoned");
        state.closed = true;
        state.connections.clear();
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }

    /// Returns a handle that can inject connections from another thread.
    #[must_use]
    pub fn injector(&self) -> VirtualConnectionInjector {
        VirtualConnectionInjector {
            state: Arc::clone(&self.state),
        }
    }
}

/// A thread-safe handle for injecting connections into a [`VirtualTcpListener`].
///
/// This is useful when test harness code runs on a different thread from the
/// server accept loop.
#[derive(Clone)]
pub struct VirtualConnectionInjector {
    state: Arc<Mutex<VirtualListenerState>>,
}

impl VirtualConnectionInjector {
    /// Inject a connection into the listener's accept queue.
    pub fn inject(&self, stream: VirtualTcpStream, remote_addr: SocketAddr) {
        let mut state = self.state.lock().expect("lock poisoned");
        if state.closed {
            // Listener is closed: do not enqueue new virtual connections.
            return;
        }
        state.connections.push_back((stream, remote_addr));
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}

#[allow(clippy::manual_async_fn)] // trait signature uses `impl Future`, not `async fn`
impl TcpListenerApi for VirtualTcpListener {
    type Stream = VirtualTcpStream;

    fn bind<A: ToSocketAddrs + Send + 'static>(
        addr: A,
    ) -> impl std::future::Future<Output = io::Result<Self>> + Send {
        async move {
            let socket_addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "no socket addresses found")
            })?;
            Ok(Self::new(socket_addr))
        }
    }

    fn accept(
        &self,
    ) -> impl std::future::Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send {
        let state = Arc::clone(&self.state);
        async move {
            std::future::poll_fn(|cx| {
                let mut guard = state.lock().expect("lock poisoned");
                if guard.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "virtual listener closed",
                    )));
                }
                if let Some(conn) = guard.connections.pop_front() {
                    return Poll::Ready(Ok(conn));
                }
                guard.waker = Some(cx.waker().clone());
                Poll::Pending
            })
            .await
        }
    }

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(Self::Stream, SocketAddr)>> {
        let mut state = self.state.lock().expect("lock poisoned");
        if state.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "virtual listener closed",
            )));
        }
        if let Some(conn) = state.connections.pop_front() {
            return Poll::Ready(Ok(conn));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }

    fn pending_connections(&self) -> Option<usize> {
        Some(self.pending_count())
    }

    fn set_ttl(&self, _ttl: u32) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn virtual_stream_pair_read_write() {
        let (mut a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write from A
        let data = b"hello";
        let result = Pin::new(&mut a).poll_write(&mut cx, data);
        assert!(matches!(result, Poll::Ready(Ok(5))));

        // Read from B
        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut b).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"hello");
    }

    #[test]
    fn virtual_stream_addresses() {
        let (a, b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        assert_eq!(a.local_addr().unwrap(), addr("127.0.0.1:1000"));
        assert_eq!(a.peer_addr().unwrap(), addr("127.0.0.1:2000"));
        assert_eq!(b.local_addr().unwrap(), addr("127.0.0.1:2000"));
        assert_eq!(b.peer_addr().unwrap(), addr("127.0.0.1:1000"));
    }

    #[test]
    fn virtual_stream_eof_on_write_shutdown() {
        let (mut a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Shutdown A's write side
        let result = Pin::new(&mut a).poll_shutdown(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(()))));

        // B should see EOF when reading
        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut b).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 0); // EOF
    }

    #[test]
    fn virtual_stream_eof_on_drop() {
        let (a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        drop(a);

        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut b).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 0); // EOF
    }

    #[test]
    fn virtual_stream_write_after_shutdown_errors() {
        let (mut a, _b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut a).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));

        let result = Pin::new(&mut a).poll_write(&mut cx, b"data");
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn virtual_stream_pending_when_empty() {
        let (_a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut b).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Pending));
    }

    #[test]
    fn virtual_listener_bind_and_accept() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        assert_eq!(listener.local_addr().unwrap(), addr("127.0.0.1:8080"));
        assert_eq!(listener.pending_count(), 0);
        assert_eq!(listener.pending_connections(), Some(0));

        // Inject a connection
        let (client, server) =
            VirtualTcpStream::pair(addr("127.0.0.1:9000"), addr("127.0.0.1:8080"));
        let _ = client; // Client side (not used in this test)
        listener.inject_connection(server, addr("127.0.0.1:9000"));

        assert_eq!(listener.pending_count(), 1);

        // Accept it
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = listener.poll_accept(&mut cx);
        match &result {
            Poll::Ready(Ok((stream, remote_addr))) => {
                assert_eq!(*remote_addr, addr("127.0.0.1:9000"));
                assert_eq!(stream.local_addr().unwrap(), addr("127.0.0.1:8080"));
            }
            other => {
                assert!(
                    matches!(other, Poll::Ready(Ok(_))),
                    "expected Ready(Ok(...)), got: {other:?}",
                );
            }
        }
    }

    #[test]
    fn virtual_listener_pending_when_no_connections() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = listener.poll_accept(&mut cx);
        assert!(matches!(result, Poll::Pending));
    }

    #[test]
    fn virtual_listener_closed_returns_error() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        listener.close();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = listener.poll_accept(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn virtual_listener_close_drops_pending_connections() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        let (_client, server) =
            VirtualTcpStream::pair(addr("127.0.0.1:9000"), addr("127.0.0.1:8080"));
        listener.inject_connection(server, addr("127.0.0.1:9000"));
        assert_eq!(listener.pending_count(), 1);

        listener.close();
        assert_eq!(listener.pending_count(), 0);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = listener.poll_accept(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn virtual_listener_inject_after_close_is_ignored() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        listener.close();

        let (_client, server) =
            VirtualTcpStream::pair(addr("127.0.0.1:9001"), addr("127.0.0.1:8080"));
        listener.inject_connection(server, addr("127.0.0.1:9001"));
        assert_eq!(listener.pending_count(), 0);

        let injector = listener.injector();
        let (_client2, server2) =
            VirtualTcpStream::pair(addr("127.0.0.1:9002"), addr("127.0.0.1:8080"));
        injector.inject(server2, addr("127.0.0.1:9002"));
        assert_eq!(listener.pending_count(), 0);
    }

    #[test]
    fn virtual_listener_injector_works() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        let injector = listener.injector();

        let (_client, server) =
            VirtualTcpStream::pair(addr("127.0.0.1:9000"), addr("127.0.0.1:8080"));
        injector.inject(server, addr("127.0.0.1:9000"));

        assert_eq!(listener.pending_count(), 1);
    }

    #[test]
    fn virtual_listener_drop_marks_closed() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        let state = Arc::clone(&listener.state);
        drop(listener);

        let closed = state.lock().expect("lock poisoned").closed;
        assert!(closed);
    }

    #[test]
    fn virtual_listener_bind_via_trait() {
        futures_lite::future::block_on(async {
            let listener = VirtualTcpListener::bind("127.0.0.1:0").await.expect("bind");
            // VirtualTcpListener resolves the address; port 0 maps to port 0
            assert!(listener.local_addr().is_ok());
        });
    }

    #[test]
    fn virtual_stream_bidirectional() {
        let (mut a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // A writes, B reads
        assert!(matches!(
            Pin::new(&mut a).poll_write(&mut cx, b"from-a"),
            Poll::Ready(Ok(6))
        ));
        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        assert!(matches!(
            Pin::new(&mut b).poll_read(&mut cx, &mut read_buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read_buf.filled(), b"from-a");

        // B writes, A reads
        assert!(matches!(
            Pin::new(&mut b).poll_write(&mut cx, b"from-b"),
            Poll::Ready(Ok(6))
        ));
        let mut buf2 = [0u8; 16];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        assert!(matches!(
            Pin::new(&mut a).poll_read(&mut cx, &mut read_buf2),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read_buf2.filled(), b"from-b");
    }

    #[test]
    fn virtual_stream_nodelay_and_ttl() {
        let (a, b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        // Defaults
        assert!(!a.nodelay().unwrap());
        assert_eq!(a.ttl().unwrap(), 64);
        assert!(!b.nodelay().unwrap());
        assert_eq!(b.ttl().unwrap(), 64);

        // set_nodelay/set_ttl should be reflected by getters.
        assert!(a.set_nodelay(true).is_ok());
        assert!(a.set_ttl(128).is_ok());
        assert!(a.nodelay().unwrap());
        assert_eq!(a.ttl().unwrap(), 128);

        // Stream-local options should not bleed into the peer handle.
        assert!(!b.nodelay().unwrap());
        assert_eq!(b.ttl().unwrap(), 64);
    }

    #[test]
    fn virtual_stream_shutdown_both() {
        let (a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        a.shutdown(Shutdown::Both).unwrap();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // B reads EOF
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut b).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 0);
    }

    #[test]
    fn virtual_stream_shutdown_read_allows_peer_write() {
        let (mut a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        a.shutdown(Shutdown::Read).unwrap();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Peer write should succeed but be discarded.
        let result = Pin::new(&mut b).poll_write(&mut cx, b"discarded");
        assert!(matches!(result, Poll::Ready(Ok(9))));

        // Reader sees EOF immediately.
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut a).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 0);
    }

    #[test]
    fn virtual_stream_connect_returns_unsupported() {
        futures_lite::future::block_on(async {
            let result = VirtualTcpStream::connect("127.0.0.1:8080").await;
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        });
    }
}
