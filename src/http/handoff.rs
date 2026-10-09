//! Connections handed from one accept loop to a listener's serve path.
//!
//! [`HttpAutoListener`](super::auto::HttpAutoListener) accepts each
//! connection once, decides its protocol, and pushes it into the queue of the
//! HTTP/1.1 or HTTP/2 listener that serves it. The receiving listener's
//! accept loop takes connections from the queue instead of a socket, so its
//! connection limits, drain and statistics apply unchanged.

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::sync::Notify;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A transport a listener can serve: TCP, TLS over TCP, or a stream that
/// replays bytes read during protocol detection.
pub trait HandoffIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> HandoffIo for T {}

/// A handed-off connection.
pub type HandoffStream = Box<dyn HandoffIo>;

/// Connections waiting for a listener's accept loop.
#[derive(Default)]
pub struct HandoffQueue {
    state: parking_lot::Mutex<HandoffState>,
    // `notify_one` stores a permit when no task waits, so a push between the
    // accept loop's empty check and its wait is never lost.
    arrived: Notify,
}

#[derive(Default)]
struct HandoffState {
    connections: VecDeque<(HandoffStream, Option<SocketAddr>)>,
    closed: bool,
}

impl HandoffQueue {
    pub fn push(&self, stream: HandoffStream, peer: Option<SocketAddr>) {
        let mut state = self.state.lock();
        if state.closed {
            // Transport destructors may re-enter the queue. Never run them
            // while holding its gate, including on a rejected handoff.
            drop(state);
            return;
        }
        state.connections.push_back((stream, peer));
        drop(state);
        self.arrived.notify_one();
    }

    /// Refuses further handoffs and closes connections not yet accepted.
    /// Admission and close share a gate, so a racing push cannot strand a
    /// transport in a queue whose listener has stopped accepting.
    pub fn close(&self) {
        let pending = {
            let mut state = self.state.lock();
            state.closed = true;
            std::mem::take(&mut state.connections)
        };
        self.arrived.notify_waiters();
        drop(pending);
    }

    /// The next handed-off connection; waits until one arrives, or returns
    /// `BrokenPipe` once the queue is closed.
    pub async fn accept(&self) -> io::Result<(HandoffStream, Option<SocketAddr>)> {
        loop {
            let mut notified = std::pin::pin!(self.arrived.notified());
            let result = std::future::poll_fn(|cx| {
                // Register before checking state: notify_waiters does not
                // retain a permit for an acceptor that has not polled yet.
                let notified_ready = notified.as_mut().poll(cx).is_ready();
                let mut state = self.state.lock();
                if state.closed {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "HTTP handoff queue is closed",
                    ))));
                }
                if let Some(connection) = state.connections.pop_front() {
                    return Poll::Ready(Some(Ok(connection)));
                }
                if notified_ready {
                    // Another acceptor may have taken the connection. Create
                    // a fresh notification future rather than repolling one
                    // that has already completed.
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                }
            })
            .await;
            if let Some(result) = result {
                return result;
            }
        }
    }
}

/// Bytes read from a connection to identify its protocol, served again
/// before the rest of the stream.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub const fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let pending = &this.prefix[this.offset..];
        if !pending.is_empty() {
            let take = pending.len().min(buf.remaining());
            buf.put_slice(&pending[..take]);
            this.offset += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Weak};
    use std::task::{Wake, Waker};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn close_wakes_all_parked_acceptors_and_refuses_new_ones() {
        let queue = HandoffQueue::default();
        let counts = [Arc::new(WakeCount::default()), Arc::new(WakeCount::default())];
        let wakers = counts.each_ref().map(|count| Waker::from(Arc::clone(count)));
        let mut first = std::pin::pin!(queue.accept());
        let mut second = std::pin::pin!(queue.accept());
        assert!(
            first
                .as_mut()
                .poll(&mut Context::from_waker(&wakers[0]))
                .is_pending()
        );
        assert!(
            second
                .as_mut()
                .poll(&mut Context::from_waker(&wakers[1]))
                .is_pending()
        );
        queue.close();
        for count in &counts {
            assert!(count.0.load(Ordering::Relaxed) > 0);
        }
        let mut cx = Context::from_waker(Waker::noop());
        for result in [first.as_mut().poll(&mut cx), second.as_mut().poll(&mut cx)] {
            match result {
                Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::BrokenPipe),
                _ => panic!("closed queue must finish every parked accept"),
            }
        }
        let mut late = std::pin::pin!(queue.accept());
        assert!(matches!(late.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
    }

    struct DropProbe {
        queue: Weak<HandoffQueue>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            let queue = self.queue.upgrade().expect("queue still owned");
            assert!(
                queue.state.try_lock().is_some(),
                "transport dropped under queue lock"
            );
            queue.close(); // A transport destructor may re-enter close.
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl AsyncRead for DropProbe {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for DropProbe {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn close_releases_queued_and_late_transports_outside_the_gate() {
        let queue = Arc::new(HandoffQueue::default());
        let drops = Arc::new(AtomicUsize::new(0));
        let stream = || {
            Box::new(DropProbe {
                queue: Arc::downgrade(&queue),
                drops: Arc::clone(&drops),
            })
        };
        queue.push(stream(), None);
        queue.push(stream(), None);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        queue.close();
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        queue.push(stream(), None);
        assert_eq!(drops.load(Ordering::Relaxed), 3);
        queue.close();
        assert!(queue.state.lock().connections.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn open_queue_keeps_fifo_and_peer_addresses() {
        let queue = HandoffQueue::default();
        let mut peers = Vec::new();
        for port in [1234, 5678] {
            let (stream, peer) = crate::io::duplex(8);
            peers.push(peer);
            queue.push(
                Box::new(stream),
                Some(SocketAddr::from(([127, 0, 0, 1], port))),
            );
        }
        let mut cx = Context::from_waker(Waker::noop());
        for port in [1234, 5678] {
            let mut accept = std::pin::pin!(queue.accept());
            match accept.as_mut().poll(&mut cx) {
                Poll::Ready(Ok((_, peer))) => {
                    assert_eq!(peer, Some(SocketAddr::from(([127, 0, 0, 1], port))));
                }
                _ => panic!("queued connection must be ready"),
            }
        }
        let mut accept = std::pin::pin!(queue.accept());
        assert!(accept.as_mut().poll(&mut cx).is_pending());
    }
}
