//! The core Stream trait for asynchronous iteration.
//!
//! # Cancel Safety
//!
//! The Stream trait is inherently cancel-safe at yield points. Dropping a
//! stream mid-iteration is safe, though any buffered items may be lost.

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
/// ```ignore
/// use asupersync::stream::{Stream, StreamExt};
///
/// async fn process<S: Stream<Item = i32> + Unpin>(mut stream: S) {
///     while let Some(item) = stream.next().await {
///         println!("got: {}", item);
///     }
/// }
/// ```
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
    /// # Cancel Safety
    ///
    /// This method is cancel-safe. If `poll_next` returns `Poll::Pending`,
    /// no data has been lost.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>>;

    /// Returns the bounds on the remaining length of the stream.
    ///
    /// The default implementation returns `(0, None)` which is correct for any
    /// stream.
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

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // self is Pin<&mut Pin<P>>
        // self.get_mut() returns &mut Pin<P>
        // as_mut() returns Pin<&mut P::Target>
        self.get_mut().as_mut().poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (**self).size_hint()
    }
}

// Implement Stream for Box<S> where S is a Stream
impl<S: Stream + Unpin + ?Sized> Stream for Box<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut **self).poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (**self).size_hint()
    }
}

// Implement Stream for &mut S where S is a Stream
impl<S: Stream + Unpin + ?Sized> Stream for &mut S {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut **self).poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (**self).size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    struct TestStream {
        items: Vec<i32>,
        index: usize,
    }

    impl TestStream {
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

    /// Invariant: default size_hint returns (0, None).
    #[test]
    fn default_size_hint() {
        init_test("default_size_hint");

        struct NoHint;
        impl Stream for NoHint {
            type Item = ();
            fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<()>> {
                Poll::Ready(None)
            }
        }

        let stream = NoHint;
        let hint = stream.size_hint();
        let ok = hint == (0, None);
        crate::assert_with_log!(ok, "default size_hint", (0, None::<usize>), hint);

        crate::test_complete!("default_size_hint");
    }
}
