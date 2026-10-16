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
