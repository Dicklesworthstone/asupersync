//! Task-movable read/write halves for any owned duplex stream.
//!
//! Unlike the borrowing [`super::SplitStream`], [`split_owned`] permits the two
//! halves to move into separate tasks when the stream is `Send`. Polls of the
//! underlying stream remain serialized, but no mutex is held while invoking the
//! stream or a waker callback. A contending half registers a wake and returns
//! `Pending`; it never blocks a worker waiting for the other half's poll.
//!
//! # Ownership and cancellation
//!
//! Splitting does not spawn work, duplicate an OS handle, or grant capabilities.
//! Each poll inherits the stream's cancellation semantics. A pending lock
//! acquisition has performed no I/O. Dropping a half removes its lock waiter;
//! the stream is dropped when its last half is dropped. In particular, dropping
//! the writer does not perform an asynchronous shutdown: explicitly call
//! [`super::AsyncWriteExt::shutdown`] when a write-side close is required.
//!
//! The inner poll must return for the other half to progress. This adapter
//! cannot make a blocking or non-cooperative stream cooperative.

use super::{AsyncRead, AsyncReadVectored, AsyncWrite, ReadBuf};
use std::fmt;
use std::io::{self, IoSlice, IoSliceMut};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

/// Split an owned duplex stream into independently movable halves.
///
/// The halves are `Send + Sync` when `T: Send`; `T: Sync` is not required.
/// There is one shared allocation and no allocation on uncontended polls.
/// The stream's vectored-write capability is sampled once at construction.
#[must_use]
pub fn split_owned<T>(stream: T) -> (OwnedReadHalf<T>, OwnedWriteHalf<T>)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let write_vectored = stream.is_write_vectored();
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            stream: Some(stream),
            waiter: None,
        }),
        write_vectored,
    });
    (
        OwnedReadHalf {
            shared: Arc::clone(&shared),
        },
        OwnedWriteHalf { shared },
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Read,
    Write,
}

struct State<T> {
    stream: Option<T>,
    // There are exactly two non-cloneable halves. While one owns the stream,
    // only the other can contend, so a single replaceable waiter suffices.
    waiter: Option<(Side, Waker)>,
}

struct Shared<T> {
    state: Mutex<State<T>>,
    write_vectored: bool,
}

impl<T> Shared<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn poll_acquire(&self, side: Side, cx: &Context<'_>) -> Poll<StreamGuard<'_, T>> {
        let stream = self.lock().stream.take();
        if let Some(stream) = stream {
            return Poll::Ready(StreamGuard {
                shared: self,
                stream: Some(stream),
            });
        }

        // Clone before locking: RawWaker callbacks are arbitrary user code.
        let mut replacement = Some((side, cx.waker().clone()));
        let (stream, stale) = {
            let mut state = self.lock();
            let stream = state.stream.take();
            let stale = if stream.is_none() {
                std::mem::replace(&mut state.waiter, replacement.take())
            } else {
                state.waiter.take()
            };
            (stream, stale)
        };
        // Recheck and registration above are atomic with the owner's release.
        // Build the guard before dropping wakers so even a panicking destructor
        // cannot strand a stream taken by the recheck.
        let guard = stream.map(|stream| StreamGuard {
            shared: self,
            stream: Some(stream),
        });
        drop(stale);
        drop(replacement);
        guard.map_or(Poll::Pending, Poll::Ready)
    }

    fn clear_waiter(&self, side: Side) {
        let stale = {
            let mut state = self.lock();
            if state.waiter.as_ref().is_some_and(|(owner, _)| *owner == side) {
                state.waiter.take()
            } else {
                None
            }
        };
        drop(stale);
    }
}

struct StreamGuard<'a, T> {
    shared: &'a Shared<T>,
    stream: Option<T>,
}

impl<T> StreamGuard<'_, T> {
    fn stream_mut(&mut self) -> &mut T {
        self.stream.as_mut().expect("owned split guard has a stream")
    }
}

impl<T> Drop for StreamGuard<'_, T> {
    fn drop(&mut self) {
        let Some(stream) = self.stream.take() else {
            return;
        };
        let waiter = {
            let mut state = self.shared.lock();
            state.stream = Some(stream);
            state.waiter.take()
        };
        if let Some((_, waker)) = waiter {
            if std::thread::panicking() {
                // Preserve an in-flight stream panic rather than double-panicking
                // merely because its peer's wake callback also panics.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()));
            } else {
                waker.wake();
            }
        }
    }
}

/// Owned read half returned by [`split_owned`].
pub struct OwnedReadHalf<T> {
    shared: Arc<Shared<T>>,
}

/// Owned write half returned by [`split_owned`].
pub struct OwnedWriteHalf<T> {
    shared: Arc<Shared<T>>,
}

impl<T> fmt::Debug for OwnedReadHalf<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedReadHalf").finish_non_exhaustive()
    }
}

impl<T> fmt::Debug for OwnedWriteHalf<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedWriteHalf").finish_non_exhaustive()
    }
}

impl<T> OwnedReadHalf<T> {
    /// Whether these halves were created by the same call to [`split_owned`].
    #[must_use]
    pub fn is_pair_of(&self, other: &OwnedWriteHalf<T>) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    /// Recover the original stream, including all buffered and protocol state.
    ///
    /// No flush or shutdown is performed.
    ///
    /// # Errors
    ///
    /// A mismatched pair returns both halves unchanged in the error.
    pub fn reunite(self, other: OwnedWriteHalf<T>) -> Result<T, OwnedReuniteError<T>> {
        if !self.is_pair_of(&other) {
            return Err(OwnedReuniteError(self, other));
        }
        let shared = Arc::clone(&self.shared);
        drop(self);
        drop(other);
        // Only the two halves own strong references. Owning both halves also
        // excludes an outstanding poll guard borrowing either one.
        let shared = Arc::try_unwrap(shared)
            .ok()
            .expect("reunited halves exclusively own their stream");
        let state = shared
            .state
            .into_inner()
            .unwrap_or_else(|error| error.into_inner());
        Ok(state.stream.expect("reunited stream is not being polled"))
    }
}

impl<T> OwnedWriteHalf<T> {
    /// Whether these halves were created by the same call to [`split_owned`].
    #[must_use]
    pub fn is_pair_of(&self, other: &OwnedReadHalf<T>) -> bool {
        other.is_pair_of(self)
    }

    /// Recover the original stream, or return both mismatched halves unchanged.
    ///
    /// # Errors
    ///
    /// Returns both halves if they came from different calls to [`split_owned`].
    pub fn reunite(self, other: OwnedReadHalf<T>) -> Result<T, OwnedReuniteError<T>> {
        other.reunite(self)
    }
}

impl<T> Drop for OwnedReadHalf<T> {
    fn drop(&mut self) {
        self.shared.clear_waiter(Side::Read);
    }
}

impl<T> Drop for OwnedWriteHalf<T> {
    fn drop(&mut self) {
        self.shared.clear_waiter(Side::Write);
    }
}

/// Halves from different streams, returned without losing either stream owner.
pub struct OwnedReuniteError<T>(
    /// The original read half.
    pub OwnedReadHalf<T>,
    /// The original write half.
    pub OwnedWriteHalf<T>,
);

impl<T> fmt::Debug for OwnedReuniteError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OwnedReuniteError")
            .field(&self.0)
            .field(&self.1)
            .finish()
    }
}

impl<T> fmt::Display for OwnedReuniteError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cannot reunite halves from different streams")
    }
}

impl<T> std::error::Error for OwnedReuniteError<T> {}

impl<T: AsyncRead + Unpin> AsyncRead for OwnedReadHalf<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut guard = std::task::ready!(self.shared.poll_acquire(Side::Read, cx));
        Pin::new(guard.stream_mut()).poll_read(cx, buf)
    }
}

impl<T: AsyncReadVectored + Unpin> AsyncReadVectored for OwnedReadHalf<T> {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut guard = std::task::ready!(self.shared.poll_acquire(Side::Read, cx));
        Pin::new(guard.stream_mut()).poll_read_vectored(cx, bufs)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for OwnedWriteHalf<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut guard = std::task::ready!(self.shared.poll_acquire(Side::Write, cx));
        Pin::new(guard.stream_mut()).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut guard = std::task::ready!(self.shared.poll_acquire(Side::Write, cx));
        Pin::new(guard.stream_mut()).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.shared.write_vectored
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = std::task::ready!(self.shared.poll_acquire(Side::Write, cx));
        Pin::new(guard.stream_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = std::task::ready!(self.shared.poll_acquire(Side::Write, cx));
        Pin::new(guard.stream_mut()).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "owned_split_tests.rs"]
mod tests;
