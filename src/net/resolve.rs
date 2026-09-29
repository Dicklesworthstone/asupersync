//! Async DNS resolution helpers.
//!
//! Phase 0 offloads `ToSocketAddrs` to a dedicated thread per lookup to avoid
//! blocking the async runtime.

use crate::cx::Cx;
use crate::runtime::spawn_blocking;
use crate::runtime::spawn_blocking::spawn_blocking_on_thread;
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::task::Poll;

const NO_SOCKET_ADDRESSES_FOUND: &str = "no socket addresses found";

/// Resolve a hostname to the first available socket address.
///
/// # Cancel Safety
///
/// If this future is cancelled, the DNS resolution continues on the blocking
/// thread, and the result is dropped. If the calling task is cancelled while
/// the lookup is blocked, this returns an [`io::ErrorKind::Interrupted`] error
/// without waiting for it.
pub async fn lookup_one<A>(addr: A) -> io::Result<SocketAddr>
where
    A: ToSocketAddrs + Send + 'static,
{
    let any_ref = &addr as &dyn std::any::Any;
    if let Some(s) = any_ref.downcast_ref::<SocketAddr>() {
        return Ok(*s);
    }
    if let Some(s) = any_ref.downcast_ref::<(std::net::IpAddr, u16)>() {
        return Ok(SocketAddr::new(s.0, s.1));
    }
    if let Some(s) = any_ref.downcast_ref::<(std::net::Ipv4Addr, u16)>() {
        return Ok(SocketAddr::new(std::net::IpAddr::V4(s.0), s.1));
    }
    if let Some(s) = any_ref.downcast_ref::<(std::net::Ipv6Addr, u16)>() {
        return Ok(SocketAddr::new(std::net::IpAddr::V6(s.0), s.1));
    }
    if let Some(s) = any_ref.downcast_ref::<Vec<SocketAddr>>() {
        if let Some(first) = s.first() {
            return Ok(*first);
        }
    }

    spawn_blocking_resolve(move || {
        let mut addrs = resolve_socket_addrs(addr)?;
        Ok(addrs.swap_remove(0))
    })
    .await
}

/// Resolve a hostname to all available socket addresses.
///
/// # Cancel Safety
///
/// If this future is cancelled, the DNS resolution continues on the blocking
/// thread, and the result is dropped. If the calling task is cancelled while
/// the lookup is blocked, this returns an [`io::ErrorKind::Interrupted`] error
/// without waiting for it.
pub async fn lookup_all<A>(addr: A) -> io::Result<Vec<SocketAddr>>
where
    A: ToSocketAddrs + Send + 'static,
{
    let any_ref = &addr as &dyn std::any::Any;
    if let Some(s) = any_ref.downcast_ref::<SocketAddr>() {
        return Ok(vec![*s]);
    }
    if let Some(s) = any_ref.downcast_ref::<(std::net::IpAddr, u16)>() {
        return Ok(vec![SocketAddr::new(s.0, s.1)]);
    }
    if let Some(s) = any_ref.downcast_ref::<(std::net::Ipv4Addr, u16)>() {
        return Ok(vec![SocketAddr::new(std::net::IpAddr::V4(s.0), s.1)]);
    }
    if let Some(s) = any_ref.downcast_ref::<(std::net::Ipv6Addr, u16)>() {
        return Ok(vec![SocketAddr::new(std::net::IpAddr::V6(s.0), s.1)]);
    }
    if let Some(s) = any_ref.downcast_ref::<Vec<SocketAddr>>() {
        return Ok(s.clone());
    }

    spawn_blocking_resolve(move || resolve_socket_addrs(addr)).await
}

async fn spawn_blocking_resolve<F, T>(f: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    if let Some(cx) = Cx::current() {
        if cx.blocking_pool_handle().is_some() {
            return unless_cancelled(&cx, spawn_blocking(f)).await;
        }
        return unless_cancelled(&cx, spawn_blocking_on_thread(f)).await;
    }

    // No pool available? Force a background thread to avoid blocking the reactor.
    // This maintains the original behavior (dedicated thread per lookup) but
    // uses the optimized Waker-based notification mechanism.
    spawn_blocking_on_thread(f).await
}

/// Waits for a blocking lookup unless the calling task is cancelled first
/// (asupersync-bi2462.119). A cancelled caller gets `Interrupted` at once; the
/// lookup finishes on its thread and its result is dropped.
async fn unless_cancelled<T>(
    cx: &Cx,
    resolution: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let mut resolution = std::pin::pin!(resolution);
    let mut cancelled = std::pin::pin!(cx.cancelled());
    std::future::poll_fn(|task| {
        if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "dns resolution cancelled",
            )));
        }
        resolution.as_mut().poll(task)
    })
    .await
}

fn resolve_socket_addrs<A>(addr: A) -> io::Result<Vec<SocketAddr>>
where
    A: ToSocketAddrs,
{
    let addrs: Vec<_> = addr.to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            NO_SOCKET_ADDRESSES_FOUND,
        ));
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use futures_lite::future;
    use parking_lot::{Condvar, Mutex};
    use std::future::Future;
    use std::future::poll_fn;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::task::Poll;

    #[test]
    fn lookup_one_passthrough_socket_addr() {
        future::block_on(async {
            let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let resolved = lookup_one(addr).await.unwrap();
            assert_eq!(resolved, addr);
        });
    }

    #[test]
    fn lookup_all_passthrough_socket_addr() {
        future::block_on(async {
            let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let resolved = lookup_all(addr).await.unwrap();
            assert_eq!(resolved, vec![addr]);
        });
    }

    #[test]
    fn lookup_one_resolves_localhost() {
        future::block_on(async {
            let resolved = lookup_all("localhost:80").await.unwrap();
            assert!(!resolved.is_empty());
        });
    }

    #[test]
    fn lookup_one_rejects_invalid_port() {
        future::block_on(async {
            let err = lookup_one("127.0.0.1:bogus").await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn lookup_one_rejects_empty_resolution() {
        struct EmptyAddrs;

        impl ToSocketAddrs for EmptyAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                Ok(Vec::new().into_iter())
            }
        }

        future::block_on(async {
            let err = lookup_one(EmptyAddrs).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(err.to_string(), NO_SOCKET_ADDRESSES_FOUND);
        });
    }

    #[test]
    fn lookup_all_rejects_empty_resolution() {
        struct EmptyAddrs;

        impl ToSocketAddrs for EmptyAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                Ok(Vec::new().into_iter())
            }
        }

        future::block_on(async {
            let err = lookup_all(EmptyAddrs).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(err.to_string(), NO_SOCKET_ADDRESSES_FOUND);
        });
    }

    #[test]
    fn lookup_one_cancel_does_not_deadlock() {
        struct BlockingAddrs {
            gate: Arc<(Mutex<bool>, Condvar)>,
            addr: SocketAddr,
        }

        impl ToSocketAddrs for BlockingAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                let (lock, cvar) = &*self.gate;
                let mut ready = lock.lock();
                while !*ready {
                    cvar.wait(&mut ready);
                }
                drop(ready);
                Ok(vec![self.addr].into_iter())
            }
        }

        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let addr = BlockingAddrs {
            gate: Arc::clone(&gate),
            addr: "127.0.0.1:9090".parse().unwrap(),
        };

        let mut fut = Box::pin(lookup_one(addr));
        future::block_on(poll_fn(|cx| match fut.as_mut().poll(cx) {
            Poll::Pending | Poll::Ready(_) => Poll::Ready(()),
        }));

        drop(fut);

        let (lock, cvar) = &*gate;
        let mut ready = lock.lock();
        *ready = true;
        cvar.notify_one();
        drop(ready);
    }

    /// asupersync-bi2462.119: a caller cancelled while its lookup is blocked
    /// in the resolver gets `Interrupted` at once instead of waiting for it.
    #[test]
    fn lookup_all_returns_promptly_when_the_caller_is_cancelled() {
        struct BlockingAddrs {
            gate: Arc<(Mutex<bool>, Condvar)>,
        }

        impl ToSocketAddrs for BlockingAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                let (lock, cvar) = &*self.gate;
                let mut ready = lock.lock();
                while !*ready {
                    cvar.wait(&mut ready);
                }
                drop(ready);
                Ok(vec!["127.0.0.1:9091".parse().unwrap()].into_iter())
            }
        }

        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let cx = Cx::for_testing();
        let _current = Cx::set_current(Some(cx.clone()));
        let mut fut = Box::pin(lookup_all(BlockingAddrs {
            gate: Arc::clone(&gate),
        }));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(
            fut.as_mut().poll(&mut task).is_pending(),
            "the lookup is blocked in the resolver"
        );

        cx.cancel_with(crate::types::CancelKind::User, Some("dns caller cancelled"));
        let result = fut.as_mut().poll(&mut task);
        assert!(
            matches!(&result, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Interrupted),
            "a cancelled caller returns Interrupted without waiting, got {result:?}"
        );

        drop(fut);
        let (lock, cvar) = &*gate;
        *lock.lock() = true;
        cvar.notify_one();
    }
}
