//! TCP listener implementation.

use crate::net::tcp::stream::TcpStream;
use crate::stream::Stream;
use std::io;
use std::net::{self, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A TCP listener.
#[derive(Debug)]
pub struct TcpListener {
    pub(crate) inner: net::TcpListener,
}

impl TcpListener {
    /// Bind to address.
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let inner = net::TcpListener::bind(addr)?;
        inner.set_nonblocking(true)?;

        // TODO: Register with reactor
        // let handle = Handle::current().expect("no runtime");
        // handle.reactor().register(&inner, Token::new(...), Interest::READABLE)?;

        Ok(Self { inner })
    }

    /// Accept connection.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        // TODO: Wait for readability using reactor
        // self.registration.async_readable().await?;

        match self.inner.accept() {
            Ok((stream, addr)) => {
                stream.set_nonblocking(true)?;
                Ok((TcpStream::from_std(stream), addr))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Pending
                std::future::pending().await
            }
            Err(e) => Err(e),
        }
    }

    /// Get local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Set TTL.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Incoming connections as stream.
    #[must_use]
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }
}

/// Stream of incoming connections.
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a TcpListener,
}

impl Stream for Incoming<'_> {
    type Item = io::Result<TcpStream>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // TODO: proper polling
        let _fut = self.listener.accept();
        // We can't poll a future easily here without boxing or storing it.
        // For Phase 0 wrappers, we might need a different approach.
        // But `accept` is async.
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_bind() {
        // We can't await in a sync test without a runtime, but we can check if bind returns a future.
        // Or we can use `futures_lite::future::block_on`.

        futures_lite::future::block_on(async {
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = TcpListener::bind(addr).await.expect("bind failed");
            assert!(listener.local_addr().is_ok());
        });
    }
}
