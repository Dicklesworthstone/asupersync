//! Async DNS resolution helpers.
//!
//! Phase 0 offloads `ToSocketAddrs` to a dedicated thread per lookup to avoid
//! blocking the async runtime.

use crate::cx::Cx;
use crate::runtime::SpawnError;
use crate::runtime::spawn_blocking::{
    refused_io_error, try_spawn_blocking, try_spawn_blocking_on_thread,
};
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::task::Poll;

const NO_SOCKET_ADDRESSES_FOUND: &str = "no socket addresses found";

/// Resolve a hostname to the first available socket address.
///
/// Refuses with [`IoCapabilityDenied`](crate::cx::IoCapabilityDenied) when
/// the calling task's `Cx` lacks the IO capability.
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
    crate::cx::io_gate::require_ambient_io("net::lookup_one")?;
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
/// Refuses with [`IoCapabilityDenied`](crate::cx::IoCapabilityDenied) when
/// the calling task's `Cx` lacks the IO capability.
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
    crate::cx::io_gate::require_ambient_io("net::lookup_all")?;
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
    // A runtime that forbids blocking work resolves nothing: the lookup would run on a dedicated thread.
    if crate::runtime::spawn_blocking::current_pool_forbids_blocking() {
        return Err(crate::runtime::spawn_blocking::forbidden_io_error());
    }
    // Placement is strict: a closed pool or a thread that cannot be started is an error, never a lookup run inline
    // on the polling thread (the lookup can block for as long as the resolver takes).
    if let Some(cx) = Cx::current() {
        // The stored handle decides, as in `try_spawn_blocking`. The public getter is `None` under a spawn-restricted
        // mask even when the context inherited a pool, which would send a restricted context's lookup to a dedicated
        // thread past its open pool, or past the refusal of its closed one.
        if cx.blocking_pool_handle_for_inheritance().is_some() {
            return unless_cancelled(&cx, async { admitted(try_spawn_blocking(f).await) }).await;
        }
        return unless_cancelled(&cx, async {
            admitted(try_spawn_blocking_on_thread(f).await)
        })
        .await;
    }

    // No pool available? Force a background thread to avoid blocking the reactor.
    // This maintains the original behavior (dedicated thread per lookup) but
    // uses the optimized Waker-based notification mechanism.
    admitted(try_spawn_blocking_on_thread(f).await)
}

/// The lookup's own result, or the refusal worded as an I/O error (the forbidden-policy error under a forbidden pool).
fn admitted<T>(placed: Result<io::Result<T>, SpawnError>) -> io::Result<T> {
    placed.unwrap_or_else(|_refused| Err(refused_io_error()))
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
#[path = "resolve_inline_tests.rs"]
mod tests;
