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

    use std::task::Waker;

    #[inline]
    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct TestStream {
        items: Vec<i32>,
        index: usize,
    }

    impl TestStream {
        #[inline]
        fn new(items: Vec<i32>) -> Self {
            Self { items, index: 0 }
        }
    }

    impl Stream for TestStream {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<i32>> {
            if self.index < self.items.len() {
                let item = self.items[self.index];
                self.index += 1;
                Poll::Ready(Some(item))
            } else {
                Poll::Ready(None)
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.items.len() - self.index;
            (remaining, Some(remaining))
        }
    }

    #[inline]
    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn stream_produces_items() {
        init_test("stream_produces_items");
        let mut stream = TestStream::new(vec![1, 2, 3]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(1)));
        crate::assert_with_log!(ok, "poll 1", "Poll::Ready(Some(1))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(2)));
        crate::assert_with_log!(ok, "poll 2", "Poll::Ready(Some(2))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(3)));
        crate::assert_with_log!(ok, "poll 3", "Poll::Ready(Some(3))", poll);
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(ok, "poll done", "Poll::Ready(None)", poll);
        crate::test_complete!("stream_produces_items");
    }

    #[test]
    fn stream_size_hint() {
        init_test("stream_size_hint");
        let stream = TestStream::new(vec![1, 2, 3]);
        let hint = stream.size_hint();
        let ok = hint == (3, Some(3));
        crate::assert_with_log!(ok, "size hint", (3, Some(3)), hint);
        crate::test_complete!("stream_size_hint");
    }

    #[test]
    fn boxed_stream() {
        init_test("boxed_stream");
        let mut stream: Box<TestStream> = Box::new(TestStream::new(vec![42]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(42)));
        crate::assert_with_log!(ok, "poll boxed", "Poll::Ready(Some(42))", poll);
        crate::test_complete!("boxed_stream");
    }

    /// Invariant: `&mut S` implements Stream by forwarding to the underlying stream.
    #[test]
    fn ref_mut_stream() {
        init_test("ref_mut_stream");
        let mut stream = TestStream::new(vec![7, 8]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Poll via &mut reference.
        let stream_ref: &mut TestStream = &mut stream;
        let poll = Pin::new(stream_ref).poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(7)));
        crate::assert_with_log!(ok, "ref_mut poll 1", true, ok);

        // size_hint forwarding via &mut.
        let stream_ref: &mut TestStream = &mut stream;
        let hint = Stream::size_hint(stream_ref);
        let ok = hint == (1, Some(1));
        crate::assert_with_log!(ok, "ref_mut size_hint", (1, Some(1)), hint);

        crate::test_complete!("ref_mut_stream");
    }

    struct NoHint;
    impl Stream for NoHint {
        type Item = ();
        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<()>> {
            Poll::Ready(None)
        }
    }

    /// Invariant: default size_hint returns (0, None).
    #[test]
    fn default_size_hint() {
        init_test("default_size_hint");

        let stream = NoHint;
        let hint = stream.size_hint();
        let ok = hint == (0, None);
        crate::assert_with_log!(ok, "default size_hint", (0, None::<usize>), hint);

        crate::test_complete!("default_size_hint");
    }
}
