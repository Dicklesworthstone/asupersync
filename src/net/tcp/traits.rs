//! TCP listener and stream traits for framework integration.
//!
//! This module defines abstract traits that frameworks like fastapi_rust can depend on,
//! allowing different implementations for production (real I/O) and testing (virtual I/O).
//!
//! # Design Principles
//!
//! 1. **Cancel-correct**: All operations can be cancelled cleanly
//! 2. **Two-phase**: Bind and accept as separate, controllable operations
//! 3. **Budget-aware**: Timeouts via budget system through `Cx`
//! 4. **Testable**: Virtual implementations for lab runtime
//!
//! # Cancel-Safety
//!
//! - `bind()`: Idempotent, can be retried on cancellation
//! - `accept()`: Cancel-safe; if cancelled after accept, connection is still valid
//!   for the next `accept()` call
//!
//! # Example
//!
//! ```rust,ignore
//! use asupersync::net::tcp::{TcpListenerApi, TcpStreamApi};
//! use asupersync::cx::Cx;
//!
//! async fn run_server<L: TcpListenerApi>(cx: &Cx, addr: &str) -> std::io::Result<()> {
//!     let listener = L::bind(addr).await?;
//!     loop {
//!         let (stream, addr) = listener.accept().await?;
//!         // Handle connection...
//!     }
//! }
//! ```

use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::io::{AsyncRead, AsyncWrite};

/// A TCP listener for accepting incoming connections.
///
/// Created via [`TcpListenerApi::bind`], accepts connections via [`TcpListenerApi::accept`].
///
/// # Cancel-Correctness
///
/// - `bind()`: Idempotent, can be retried on cancellation
/// - `accept()`: Two-phase; if cancelled after accept but before returning,
///   the accepted connection remains in the queue for the next accept.
///
/// # Budget Enforcement
///
/// Operations respect the budget from the current `Cx` context. If budget is
/// exhausted before completion, operations return `Err` with `WouldBlock` or
/// a timeout error.
pub trait TcpListenerApi: Sized + Send {
    /// The stream type returned by accept.
    type Stream: TcpStreamApi;

    /// Bind to the given socket address.
    ///
    /// # Errors
    ///
    /// - `AddrInUse`: Address already bound
    /// - `AddrNotAvailable`: Cannot bind to address
    /// - `PermissionDenied`: Privileged port without permission
    fn bind<A: ToSocketAddrs + Send + 'static>(
        addr: A,
    ) -> impl Future<Output = io::Result<Self>> + Send;

    /// Accept a new incoming connection.
    ///
    /// This is a cancel-safe operation: if cancelled, no connection is lost.
    /// Any connection that was accepted but not returned will be available
    /// on the next `accept()` call.
    ///
    /// Returns the stream and the remote address.
    fn accept(&self) -> impl Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send;

    /// Polls for an incoming connection.
    ///
    /// This is the low-level polling interface. Most code should use `accept()` instead.
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(Self::Stream, SocketAddr)>>;

    /// Returns the local socket address of the listener.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Returns the number of pending connections in the accept queue.
    ///
    /// Returns `None` if the platform doesn't support this.
    fn pending_connections(&self) -> Option<usize> {
        None
    }

    /// Set the TTL for the socket.
    fn set_ttl(&self, ttl: u32) -> io::Result<()>;
}

/// A TCP stream for reading and writing data.
///
/// Represents an established TCP connection. Implements [`AsyncRead`] and
/// [`AsyncWrite`] for async I/O operations.
///
/// # Cancel-Safety
///
/// - `poll_read`: Cancel-safe (partial data is discarded by caller)
/// - `poll_write`: Cancel-safe (partial writes are OK)
/// - `shutdown`: Cancel-safe (can retry)
pub trait TcpStreamApi: AsyncRead + AsyncWrite + Sized + Send + Unpin {
    /// Connect to the given socket address.
    ///
    /// # Errors
    ///
    /// - `ConnectionRefused`: No server listening at address
    /// - `TimedOut`: Connection attempt timed out
    /// - `AddrNotAvailable`: Cannot connect to address
    fn connect<A: ToSocketAddrs + Send + 'static>(
        addr: A,
    ) -> impl Future<Output = io::Result<Self>> + Send;

    /// Get the peer (remote) address of this stream.
    fn peer_addr(&self) -> io::Result<SocketAddr>;

    /// Get the local address of this stream.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Shutdown the connection.
    fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()>;

    /// Set the TCP_NODELAY option.
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;

    /// Get the TCP_NODELAY option.
    fn nodelay(&self) -> io::Result<bool>;

    /// Set the TTL for the socket.
    fn set_ttl(&self, ttl: u32) -> io::Result<()>;

    /// Get the TTL for the socket.
    fn ttl(&self) -> io::Result<u32>;
}

/// Builder for configuring and binding a TCP listener.
///
/// Provides a fluent interface for setting socket options before binding.
///
/// # Example
///
/// ```rust,ignore
/// use asupersync::net::tcp::TcpListenerBuilder;
///
/// let listener = TcpListenerBuilder::new("0.0.0.0:8080")
///     .backlog(128)
///     .reuse_addr(true)
///     .bind()
///     .await?;
/// ```
pub struct TcpListenerBuilder<A> {
    addr: A,
    backlog: Option<u32>,
    reuse_addr: bool,
    reuse_port: bool,
    only_v6: bool,
}

impl<A: ToSocketAddrs + Send + 'static> TcpListenerBuilder<A> {
    /// Create a new builder with the given address.
    pub fn new(addr: A) -> Self {
        Self {
            addr,
            backlog: None,
            reuse_addr: false,
            reuse_port: false,
            only_v6: false,
        }
    }

    /// Set the listen backlog (max pending connections).
    #[must_use]
    pub fn backlog(mut self, n: u32) -> Self {
        self.backlog = Some(n);
        self
    }

    /// Set the SO_REUSEADDR option.
    #[must_use]
    pub fn reuse_addr(mut self, enable: bool) -> Self {
        self.reuse_addr = enable;
        self
    }

    /// Set the SO_REUSEPORT option (Linux/BSD only).
    #[must_use]
    pub fn reuse_port(mut self, enable: bool) -> Self {
        self.reuse_port = enable;
        self
    }

    /// Set IPV6_V6ONLY option for IPv6 sockets.
    #[must_use]
    pub fn only_v6(mut self, enable: bool) -> Self {
        self.only_v6 = enable;
        self
    }

    /// Bind to the configured address with the specified options.
    pub async fn bind(self) -> io::Result<super::listener::TcpListener> {
        use crate::net::lookup_all;
        use socket2::{Domain, Protocol, Socket, Type};

        let addrs = lookup_all(self.addr).await?;
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no socket addresses found",
            ));
        }

        let mut last_err = None;
        for addr in addrs {
            let domain = if addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };

            let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            // Apply socket options
            if self.reuse_addr {
                if let Err(e) = socket.set_reuse_address(true) {
                    last_err = Some(e);
                    continue;
                }
            }

            #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
            if self.reuse_port {
                if let Err(e) = socket.set_reuse_port(true) {
                    last_err = Some(e);
                    continue;
                }
            }

            if addr.is_ipv6() && self.only_v6 {
                if let Err(e) = socket.set_only_v6(true) {
                    last_err = Some(e);
                    continue;
                }
            }

            // Bind the socket
            if let Err(e) = socket.bind(&addr.into()) {
                last_err = Some(e);
                continue;
            }

            // Listen with backlog
            let backlog = i32::try_from(self.backlog.unwrap_or(128)).unwrap_or(i32::MAX);
            if let Err(e) = socket.listen(backlog) {
                last_err = Some(e);
                continue;
            }

            // Set non-blocking
            if let Err(e) = socket.set_nonblocking(true) {
                last_err = Some(e);
                continue;
            }

            let listener: std::net::TcpListener = socket.into();
            return super::listener::TcpListener::from_std(listener);
        }

        Err(last_err.unwrap_or_else(|| io::Error::other("failed to bind any address")))
    }
}

/// Extension trait for TCP listeners with accept loop helpers.
///
/// Provides convenient methods for common accept loop patterns.
pub trait TcpListenerExt: TcpListenerApi {
    /// Accept connections and handle them sequentially.
    ///
    /// This method runs an infinite accept loop and awaits the handler for each
    /// incoming connection. The loop continues until cancelled or an error occurs.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// listener.serve(|stream, addr| async move {
    ///     println!("Connection from {}", addr);
    ///     // Handle the connection...
    /// }).await;
    /// ```
    fn serve<F, Fut>(&self, handler: F) -> impl Future<Output = io::Result<()>> + Send
    where
        F: Fn(Self::Stream, SocketAddr) -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = ()> + Send + 'static,
        Self::Stream: 'static,
        Self: Sync,
    {
        async move {
            loop {
                let (stream, addr) = self.accept().await?;
                let handler = handler.clone();
                handler(stream, addr).await;
            }
        }
    }

    /// Accept connections as an async stream.
    ///
    /// Returns an iterator that yields connections as they arrive.
    fn incoming_stream(&self) -> IncomingStream<'_, Self>
    where
        Self: Sized,
    {
        IncomingStream::new(self)
    }
}

// Blanket implementation for all types implementing TcpListenerApi
impl<T: TcpListenerApi> TcpListenerExt for T {}

/// An async iterator over incoming connections.
///
/// This is a generic incoming stream that works with any `TcpListenerApi` implementation.
pub struct IncomingStream<'a, L: TcpListenerApi> {
    listener: &'a L,
}

impl<'a, L: TcpListenerApi> IncomingStream<'a, L> {
    /// Create a new incoming stream from a listener.
    pub fn new(listener: &'a L) -> Self {
        Self { listener }
    }
}

impl<L: TcpListenerApi> std::fmt::Debug for IncomingStream<'_, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingStream").finish_non_exhaustive()
    }
}

impl<L: TcpListenerApi> crate::stream::Stream for IncomingStream<'_, L> {
    type Item = io::Result<L::Stream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.listener.poll_accept(cx) {
            Poll::Ready(Ok((stream, _addr))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_creates_with_defaults() {
        let builder = TcpListenerBuilder::new("127.0.0.1:0");
        assert_eq!(builder.backlog, None);
        assert!(!builder.reuse_addr);
        assert!(!builder.reuse_port);
    }

    #[test]
    fn builder_chain_works() {
        let builder = TcpListenerBuilder::new("127.0.0.1:0")
            .backlog(256)
            .reuse_addr(true)
            .reuse_port(true);

        assert_eq!(builder.backlog, Some(256));
        assert!(builder.reuse_addr);
        assert!(builder.reuse_port);
    }
}
