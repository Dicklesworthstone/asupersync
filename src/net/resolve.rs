//! Async DNS resolution helpers.
//!
//! Phase 0 offloads `ToSocketAddrs` to a dedicated thread per lookup to avoid
//! blocking the async runtime.

use crate::runtime::yield_now;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;

/// Resolve a hostname to the first available socket address.
///
/// # Cancel Safety
///
/// If this future is cancelled, the DNS resolution continues on the blocking
/// thread, and the result is dropped.
pub async fn lookup_one<A>(addr: A) -> io::Result<SocketAddr>
where
    A: ToSocketAddrs + Send + 'static,
{
    spawn_blocking_resolve(move || {
        let mut addrs = addr.to_socket_addrs()?;
        addrs
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no socket addresses found"))
    })
    .await
}

/// Resolve a hostname to all available socket addresses.
///
/// # Cancel Safety
///
/// If this future is cancelled, the DNS resolution continues on the blocking
/// thread, and the result is dropped.
pub async fn lookup_all<A>(addr: A) -> io::Result<Vec<SocketAddr>>
where
    A: ToSocketAddrs + Send + 'static,
{
    spawn_blocking_resolve(move || addr.to_socket_addrs().map(std::iter::Iterator::collect)).await
}

async fn spawn_blocking_resolve<F, T>(f: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let thread_result = thread::Builder::new()
        .name("asupersync-resolve".to_string())
        .spawn(move || {
            let _ = tx.send(f());
        });
    if let Err(err) = thread_result {
        return Err(io::Error::other(
            format!("failed to spawn resolver thread: {err}"),
        ));
    }

    loop {
        match rx.try_recv() {
            Ok(result) => return result,
            Err(mpsc::TryRecvError::Empty) => {
                yield_now().await;
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(io::Error::other(
                    "resolver thread dropped without sending",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future;
    use std::future::poll_fn;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::sync::{Arc, Condvar, Mutex};
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
    fn lookup_one_cancel_does_not_deadlock() {
        struct BlockingAddrs {
            gate: Arc<(Mutex<bool>, Condvar)>,
            addr: SocketAddr,
        }

        impl ToSocketAddrs for BlockingAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                let (lock, cvar) = &*self.gate;
                let mut ready = lock.lock().expect("lock poisoned");
                while !*ready {
                    ready = cvar.wait(ready).expect("condvar wait failed");
                }
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
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => Poll::Ready(()),
        }));

        drop(fut);

        let (lock, cvar) = &*gate;
        let mut ready = lock.lock().expect("lock poisoned");
        *ready = true;
        cvar.notify_one();
    }
}
