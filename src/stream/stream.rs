//! The core Stream trait for asynchronous iteration.
//!
//! # Cancellation boundary
//!
//! [`Stream`] defines a polling protocol, not a blanket losslessness promise.
//! Dropping a stream is memory-safe, but may discard buffered items, abandon
//! protocol progress, or trigger implementation-specific cleanup. Each stream
//! must document stronger cancellation guarantees where they exist.

use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Asynchronous iterator producing a sequence of values.
///
/// This is the async equivalent of `Iterator`. Each call to `poll_next`
/// attempts to pull out the next value, returning `Poll::Pending` if the
/// value is not yet ready, `Poll::Ready(Some(item))` if a value is available,
/// or `Poll::Ready(None)` if the stream has terminated.
///
/// # Examples
///
/// ```
/// use asupersync::stream::{Stream, StreamExt};
///
/// async fn sum<S: Stream<Item = i32> + Unpin>(mut stream: S) -> i32 {
///     let mut total = 0;
///     while let Some(item) = stream.next().await {
///         total += item;
///     }
///     total
/// }
/// ```
///
/// # Pinning
///
/// [`poll_next`](Stream::poll_next) receives `Pin<&mut Self>`, so an
/// implementation may rely on a stable address.
/// [`StreamExt::next`](super::StreamExt::next) requires `Unpin`; a `!Unpin`
/// stream must instead be pinned and polled through the trait. The forwarding
/// implementation for `Pin<P>` supports pinned pointer containers without
/// requiring `P::Target: Unpin`.
///
/// # Wake and termination contract
///
/// When returning `Poll::Pending`, an implementation must arrange for the
/// current task to be woken when another poll may make progress. Code that
/// stores a waker must account for a later poll arriving with a different
/// waker. `Poll::Ready(None)` reports termination, but this trait does not
/// require subsequent polls to keep returning `None`; use
/// [`StreamExt::fuse`](super::StreamExt::fuse) when that property is needed.
///
/// # Cancellation and drop
///
/// The trait does not promise that cancelling an in-flight consumer or
/// dropping the stream is lossless. A poll may advance internal protocol state
/// before returning `Pending`, and dropping the stream may discard buffered
/// items or invoke implementation-specific cleanup. Implementations that own
/// obligations must state how drop resolves them.
///
/// # Marker traits, lifetimes, and errors
///
/// `Stream` itself adds no `Send`, `Sync`, `Unpin`, or `'static` requirement,
/// and places no bound on [`Item`](Stream::Item). Those properties are inherited
/// from the implementation and captured values. Fallible streams conventionally
/// use `Item = Result<T, E>`; the trait has no separate error channel.
///
/// # Forwarding adapters
///
/// `Pin<P>` forwards polling and `size_hint` to its pinned target when the
/// pointer container is mutable and `Unpin`; the target itself may be
/// `!Unpin`. `Box<S>` and `&mut S` also forward both operations, but their
/// implementations require `S: Unpin` so they can safely create a fresh pin.
pub trait Stream {
    /// The type of values yielded by the stream.
    type Item;

    /// Attempt to pull out the next value of this stream.
    ///
    /// # Return value
    ///
    /// - `Poll::Pending` means the next value is not ready yet.
    /// - `Poll::Ready(Some(val))` means `val` is ready and the stream may have more.
    /// - `Poll::Ready(None)` means the stream has terminated.
    ///
    /// # Contract
    ///
    /// A `Pending` result must register or otherwise account for the current
    /// task's waker before progress can depend on an external event. It does not
    /// promise that internal work is rolled back if the caller then cancels its
    /// wait. Callers must also honor pinning and must not poll the same stream
    /// concurrently through aliased mutable access.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>>;

    /// Returns the bounds on the remaining length of the stream.
    ///
    /// The lower bound must not exceed the number of items still yieldable; an
    /// upper bound, when present, must not be smaller than that number. The hint
    /// may change after every poll and must not be used for correctness. The
    /// default `(0, None)` makes no claim and is valid for finite or unbounded
    /// streams.
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

// Implement Stream for Pin<P> where P derefs to a Stream
impl<P> Stream for Pin<P>
where
    P: DerefMut + Unpin,
    P::Target: Stream,
{
    type Item = <P::Target as Stream>::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // self is Pin<&mut Pin<P>>
        // self.get_mut() returns &mut Pin<P>
        // as_mut() returns Pin<&mut P::Target>
        self.get_mut().as_mut().poll_next(cx)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (**self).size_hint()
    }
}

// Implement Stream for Box<S> where S is a Stream
impl<S: Stream + Unpin + ?Sized> Stream for Box<S> {
    type Item = S::Item;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut **self).poll_next(cx)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (**self).size_hint()
    }
}

// Implement Stream for &mut S where S is a Stream
impl<S: Stream + Unpin + ?Sized> Stream for &mut S {
    type Item = S::Item;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut **self).poll_next(cx)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (**self).size_hint()
    }
}

#[cfg(test)]
#[path = "stream_inline_tests.rs"]
mod tests;
