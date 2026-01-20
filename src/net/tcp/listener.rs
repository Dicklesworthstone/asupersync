//! TCP listener implementation.

use crate::cx::Cx;
use crate::net::lookup_all;
use crate::net::tcp::stream::TcpStream;
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use crate::stream::Stream;
use std::io;
use std::future::poll_fn;
use std::net::{self, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

/// A TCP listener.
#[derive(Debug)]
pub struct TcpListener {
    pub(crate) inner: net::TcpListener,
    registration: Mutex<Option<IoRegistration>>,
}

impl TcpListener {
    pub(crate) fn from_std(inner: net::TcpListener) -> Self {
        Self {
            inner,
            registration: Mutex::new(None),
        }
    }

    /// Bind to address.
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
            match net::TcpListener::bind(addr) {
                Ok(inner) => {
                    inner.set_nonblocking(true)?;
                    return Ok(Self::from_std(inner));
                }
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "failed to bind any address")
        }))
    }

    /// Accept connection.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }

    /// Polls for an incoming connection using reactor wakeups.
    pub fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        match self.inner.accept() {
            Ok((stream, addr)) => {
                stream.set_nonblocking(true)?;
                Poll::Ready(Ok((TcpStream::from_std(stream), addr)))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.register_interest(cx) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
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

    fn register_interest(&self, cx: &Context<'_>) -> io::Result<()> {
        let mut registration = self.registration.lock().expect("lock poisoned");

        if let Some(existing) = registration.as_mut() {
            if existing.update_waker(cx.waker().clone()) {
                return Ok(());
            }
            *registration = None;
        }

        let Some(current) = Cx::current() else {
            drop(registration);
            cx.waker().wake_by_ref();
            return Ok(());
        };
        let Some(driver) = current.io_driver_handle() else {
            drop(registration);
            cx.waker().wake_by_ref();
            return Ok(());
        };

        match driver.register(&self.inner, Interest::READABLE, cx.waker().clone()) {
            Ok(new_reg) => {
                *registration = Some(new_reg);
                drop(registration);
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                drop(registration);
                cx.waker().wake_by_ref();
                Ok(())
            }
            Err(err) => {
                drop(registration);
                Err(err)
            }
        }
    }
}

/// Stream of incoming connections.
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a TcpListener,
}

impl Stream for Incoming<'_> {
    type Item = io::Result<TcpStream>;

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
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::task::{Context, Wake, Waker};

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

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    #[test]
    fn listener_registers_on_wouldblock() {
        let raw = net::TcpListener::bind("127.0.0.1:0").expect("bind");
        raw.set_nonblocking(true).expect("nonblocking");

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

        let listener = TcpListener::from_std(raw);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = listener.poll_accept(&mut cx);
        assert!(matches!(poll, Poll::Pending));
        let registered = listener
            .registration
            .lock()
            .expect("lock poisoned")
            .is_some();
        assert!(registered);
    }
}
