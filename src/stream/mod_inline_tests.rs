    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::channel::{broadcast, mpsc, watch};
    use crate::cx::Cx;
    use std::cell::RefCell;
    use std::future::Future;
    use std::pin::Pin;

    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn stream_ext_chaining() {
        init_test("stream_ext_chaining");

        // Test that combinators can be chained
        let stream = iter(vec![1i32, 2, 3, 4, 5, 6])
            .filter(|&x: &i32| x % 2 == 0)
            .map(|x: i32| x * 10);

        let mut collect = stream.collect::<Vec<_>>();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut collect).poll(&mut cx) {
            Poll::Ready(result) => {
                let ok = result == vec![20, 40, 60];
                crate::assert_with_log!(ok, "collected", vec![20, 40, 60], result);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("stream_ext_chaining");
    }

    #[test]
    fn stream_ext_fold_chain() {
        init_test("stream_ext_fold_chain");

        let stream = iter(vec![1i32, 2, 3, 4, 5]).map(|x: i32| x * 2);

        let mut fold = stream.fold(0i32, |acc, x| acc + x);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut fold).poll(&mut cx) {
            Poll::Ready(sum) => {
                let ok = sum == 30;
                crate::assert_with_log!(ok, "sum", 30, sum);
            }
            Poll::Pending => panic!("expected Ready"),
        }
        crate::test_complete!("stream_ext_fold_chain");
    }

    #[test]
    fn test_stream_next() {
        init_test("test_stream_next");
        let mut stream = iter(vec![1, 2, 3]);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut next = stream.next();
        let poll = Pin::new(&mut next).poll(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "next 1",
            Poll::Ready(Some(1)),
            poll
        );

        let mut next = stream.next();
        let poll = Pin::new(&mut next).poll(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "next 2",
            Poll::Ready(Some(2)),
            poll
        );

        let mut next = stream.next();
        let poll = Pin::new(&mut next).poll(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "next 3",
            Poll::Ready(Some(3)),
            poll
        );

        let mut next = stream.next();
        let poll = Pin::new(&mut next).poll(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "next done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_next");
    }

    #[test]
    fn test_stream_map() {
        init_test("test_stream_map");
        let stream = iter(vec![1, 2, 3]);
        let mut mapped = stream.map(|x| x * 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut mapped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "map 1",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut mapped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(4)),
            "map 2",
            Poll::Ready(Some(4)),
            poll
        );
        let poll = Pin::new(&mut mapped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(6)),
            "map 3",
            Poll::Ready(Some(6)),
            poll
        );
        let poll = Pin::new(&mut mapped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "map done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_map");
    }

    #[test]
    fn test_stream_filter() {
        init_test("test_stream_filter");
        let stream = iter(vec![1, 2, 3, 4, 5, 6]);
        let mut filtered = stream.filter(|x| x % 2 == 0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut filtered).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "filter 1",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut filtered).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(4)),
            "filter 2",
            Poll::Ready(Some(4)),
            poll
        );
        let poll = Pin::new(&mut filtered).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(6)),
            "filter 3",
            Poll::Ready(Some(6)),
            poll
        );
        let poll = Pin::new(&mut filtered).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "filter done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_filter");
    }

    #[test]
    fn test_stream_filter_map() {
        init_test("test_stream_filter_map");
        let stream = iter(vec!["1", "two", "3", "four"]);
        let mut parsed = stream.filter_map(|s| s.parse::<i32>().ok());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut parsed).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "filter_map 1",
            Poll::Ready(Some(1)),
            poll
        );
        let poll = Pin::new(&mut parsed).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "filter_map 2",
            Poll::Ready(Some(3)),
            poll
        );
        let poll = Pin::new(&mut parsed).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "filter_map done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_filter_map");
    }

    #[test]
    fn test_stream_take() {
        init_test("test_stream_take");
        let stream = iter(vec![1, 2, 3, 4, 5]);
        let mut taken = stream.take(3);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut taken).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "take 1",
            Poll::Ready(Some(1)),
            poll
        );
        let poll = Pin::new(&mut taken).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "take 2",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut taken).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "take 3",
            Poll::Ready(Some(3)),
            poll
        );
        let poll = Pin::new(&mut taken).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "take done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_take");
    }

    #[test]
    fn test_stream_skip() {
        init_test("test_stream_skip");
        let stream = iter(vec![1, 2, 3, 4, 5]);
        let mut skipped = stream.skip(2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut skipped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "skip 1",
            Poll::Ready(Some(3)),
            poll
        );
        let poll = Pin::new(&mut skipped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(4)),
            "skip 2",
            Poll::Ready(Some(4)),
            poll
        );
        let poll = Pin::new(&mut skipped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(5)),
            "skip 3",
            Poll::Ready(Some(5)),
            poll
        );
        let poll = Pin::new(&mut skipped).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "skip done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_skip");
    }

    #[test]
    fn test_stream_enumerate() {
        init_test("test_stream_enumerate");
        let stream = iter(vec!["a", "b", "c"]);
        let mut enumerated = stream.enumerate();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut enumerated).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some((0, "a"))),
            "enum 0",
            Poll::Ready(Some((0, "a"))),
            poll
        );
        let poll = Pin::new(&mut enumerated).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some((1, "b"))),
            "enum 1",
            Poll::Ready(Some((1, "b"))),
            poll
        );
        let poll = Pin::new(&mut enumerated).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some((2, "c"))),
            "enum 2",
            Poll::Ready(Some((2, "c"))),
            poll
        );
        let poll = Pin::new(&mut enumerated).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<(usize, &str)>),
            "enum done",
            Poll::Ready(None::<(usize, &str)>),
            poll
        );
        crate::test_complete!("test_stream_enumerate");
    }

    #[test]
    fn test_stream_then() {
        init_test("test_stream_then");
        // We need a runtime or manual polling for async map.
        // But Then combinator returns a Stream.
        // We can poll it manually.

        let stream = iter(vec![1, 2]);
        let mut processed = Box::pin(stream.then(|x| async move { x * 10 }));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First item
        let poll = processed.as_mut().poll_next(&mut cx);
        let ok = matches!(poll, Poll::Ready(Some(10)));
        crate::assert_with_log!(ok, "then 1", "Poll::Ready(Some(10))", poll);

        // Second item
        let poll = processed.as_mut().poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(20)),
            "then 2",
            Poll::Ready(Some(20)),
            poll
        );

        // End
        let poll = processed.as_mut().poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "then done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_then");
    }

    #[test]
    fn test_stream_inspect() {
        init_test("test_stream_inspect");
        let stream = iter(vec![1, 2, 3]);
        let items = RefCell::new(Vec::new());
        let mut inspected = stream.inspect(|x| items.borrow_mut().push(*x));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut inspected).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "inspect 1",
            Poll::Ready(Some(1)),
            poll
        );
        let items_now = items.borrow().clone();
        crate::assert_with_log!(items_now == vec![1], "items", vec![1], items_now);

        let poll = Pin::new(&mut inspected).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "inspect 2",
            Poll::Ready(Some(2)),
            poll
        );
        let items_now = items.borrow().clone();
        crate::assert_with_log!(items_now == vec![1, 2], "items", vec![1, 2], items_now);

        let poll = Pin::new(&mut inspected).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "inspect 3",
            Poll::Ready(Some(3)),
            poll
        );
        let items_now = items.borrow().clone();
        crate::assert_with_log!(
            items_now == vec![1, 2, 3],
            "items",
            vec![1, 2, 3],
            items_now
        );

        let poll = Pin::new(&mut inspected).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "inspect done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_inspect");
    }

    #[test]
    fn test_receiver_stream() {
        init_test("test_receiver_stream");

        let cx: Cx = Cx::for_testing();
        let (tx, rx) = mpsc::channel(10);
        let mut stream = ReceiverStream::new(cx, rx);

        tx.try_send(1).unwrap();
        tx.try_send(2).unwrap();
        drop(tx);

        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "recv 1",
            Poll::Ready(Some(1)),
            poll
        );
        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "recv 2",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "recv done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_receiver_stream");
    }

    #[test]
    fn test_watch_stream() {
        init_test("test_watch_stream");

        let cx: Cx = Cx::for_testing();
        let (tx, rx) = watch::channel(0);
        let mut stream = WatchStream::new(cx, rx);
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);

        // Initial value
        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(0)),
            "watch 0",
            Poll::Ready(Some(0)),
            poll
        );

        // Update value
        tx.send(1).unwrap();
        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "watch 1",
            Poll::Ready(Some(1)),
            poll
        );
        crate::test_complete!("test_watch_stream");
    }

    #[test]
    fn test_broadcast_stream() {
        init_test("test_broadcast_stream");

        let cx: Cx = Cx::for_testing();
        let (tx, rx) = broadcast::channel(10);
        let mut stream = BroadcastStream::new(cx.clone(), rx);
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);

        tx.send(&cx, 1).unwrap();
        tx.send(&cx, 2).unwrap();

        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(Ok::<i32, BroadcastStreamRecvError>(1))),
            "broadcast 1",
            Poll::Ready(Some(Ok::<i32, BroadcastStreamRecvError>(1))),
            poll
        );
        let poll = Pin::new(&mut stream).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(Ok::<i32, BroadcastStreamRecvError>(2))),
            "broadcast 2",
            Poll::Ready(Some(Ok::<i32, BroadcastStreamRecvError>(2))),
            poll
        );
        crate::test_complete!("test_broadcast_stream");
    }

    #[test]
    fn test_forward() {
        init_test("test_forward");

        let cx: Cx = Cx::for_testing();
        let (tx_out, rx_out) = mpsc::channel(10);
        let input = iter(vec![1, 2, 3]);

        futures_lite::future::block_on(async {
            forward(&cx, input, tx_out).await.unwrap();
        });

        let mut output = ReceiverStream::new(cx, rx_out);
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);

        let poll = Pin::new(&mut output).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "forward 1",
            Poll::Ready(Some(1)),
            poll
        );
        let poll = Pin::new(&mut output).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "forward 2",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut output).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "forward 3",
            Poll::Ready(Some(3)),
            poll
        );
        let poll = Pin::new(&mut output).poll_next(&mut cx_task);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "forward done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_forward");
    }

    #[test]
    fn test_stream_merge_method() {
        init_test("test_stream_merge_method");

        let mut merged = iter(vec![1, 2, 3]).merge(iter(vec![10, 20, 30]));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(1)),
            "merge first",
            Poll::Ready(Some(1)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(10)),
            "merge second",
            Poll::Ready(Some(10)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(2)),
            "merge third",
            Poll::Ready(Some(2)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(20)),
            "merge fourth",
            Poll::Ready(Some(20)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(3)),
            "merge fifth",
            Poll::Ready(Some(3)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(Some(30)),
            "merge sixth",
            Poll::Ready(Some(30)),
            poll
        );
        let poll = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            poll == Poll::Ready(None::<i32>),
            "merge done",
            Poll::Ready(None::<i32>),
            poll
        );
        crate::test_complete!("test_stream_merge_method");
    }
