#[cfg(test)]
mod tests {
    use crate::security::authenticated::AuthenticatedSymbol;
    use crate::security::tag::AuthenticationTag;
    use crate::transport::error::{SinkError, StreamError};
    use crate::transport::stream::{MergedStream, VecStream};
    use crate::transport::{channel, SymbolSet, SymbolSink, SymbolSinkExt, SymbolStreamExt};
    use crate::types::{Symbol, SymbolId, SymbolKind};
    use crate::Cx;
    use futures_lite::future;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWake))
    }

    fn create_symbol(i: u32) -> AuthenticatedSymbol {
        let id = SymbolId::new_for_test(1, 0, i);
        let data = vec![i as u8];
        let symbol = Symbol::new(id, data, SymbolKind::Source);
        // Fake tag for testing transport (we don't check validity here, just transport)
        let tag = AuthenticationTag::zero();
        AuthenticatedSymbol::new_verified(symbol, tag)
    }

    fn create_symbol_with_sbn(sbn: u8, esi: u32) -> AuthenticatedSymbol {
        let id = SymbolId::new_for_test(1, sbn, esi);
        let data = vec![sbn, esi as u8];
        let symbol = Symbol::new(id, data, SymbolKind::Source);
        let tag = AuthenticationTag::zero();
        AuthenticatedSymbol::new_verified(symbol, tag)
    }

    #[test]
    fn test_channel_stream_receive() {
        let (mut sink, mut stream) = channel(10);
        let s1 = create_symbol(1);
        let s2 = create_symbol(2);

        future::block_on(async {
            sink.send(s1.clone()).await.unwrap();
            sink.send(s2.clone()).await.unwrap();

            let r1 = stream.next().await.unwrap().unwrap();
            let r2 = stream.next().await.unwrap().unwrap();

            assert_eq!(r1, s1);
            assert_eq!(r2, s2);
        });
    }

    #[test]
    fn test_stream_exhaustion() {
        let (mut sink, mut stream) = channel(10);

        future::block_on(async {
            sink.close().await.unwrap();
            let res = stream.next().await;
            assert!(res.is_none());
        });
    }

    #[test]
    fn test_sink_backpressure() {
        let (mut sink, mut stream) = channel(1);
        let s1 = create_symbol(1);
        let s2 = create_symbol(2);

        future::block_on(async {
            sink.send(s1).await.unwrap();

            // Channel full (capacity 1). Next send should block or return pending?
            // futures_lite::future::poll_fn ... poll_ready ...
            // In our ChannelSink, poll_ready checks len < capacity.
            // So if len == 1, poll_ready returns Pending.
            // We can't easily test blocking in single-thread block_on without spawning.
            // But we can test that we can receive then send.

            let recv_task = async {
                stream.next().await.unwrap().unwrap();
            };

            let send_task = async {
                sink.send(s2).await.unwrap();
            };

            // Join them
            futures_lite::future::zip(recv_task, send_task).await;
        });
    }

    #[test]
    fn test_sink_backpressure_pending() {
        let (mut sink, mut stream) = channel(1);
        let s1 = create_symbol(1);
        let s2 = create_symbol(2);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = Pin::new(&mut sink).poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let send = Pin::new(&mut sink).poll_send(&mut cx, s1);
        assert!(matches!(send, Poll::Ready(Ok(()))));

        let ready = Pin::new(&mut sink).poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Pending));

        future::block_on(async {
            let _ = stream.next().await;
        });

        let ready = Pin::new(&mut sink).poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let send = Pin::new(&mut sink).poll_send(&mut cx, s2);
        assert!(matches!(send, Poll::Ready(Ok(()))));
    }

    #[test]
    fn test_collect_to_set() {
        let (mut sink, mut stream) = channel(10);

        future::block_on(async {
            for i in 0..5 {
                sink.send(create_symbol(i)).await.unwrap();
            }
            sink.close().await.unwrap();

            let mut set = SymbolSet::new();
            let count = stream.collect_to_set(&mut set).await.unwrap();

            assert_eq!(count, 5);
            assert_eq!(set.len(), 5);
        });
    }

    #[test]
    fn test_stream_map() {
        let (mut sink, stream) = channel(10);
        let s1 = create_symbol(1);

        future::block_on(async {
            sink.send(s1).await.unwrap();
            sink.close().await.unwrap();

            let mut mapped = stream.map(|s| s); // Identity map for now
            let r1 = mapped.next().await.unwrap().unwrap();
            assert_eq!(r1.symbol().id().esi(), 1);
        });
    }

    #[test]
    fn test_stream_filter() {
        let (mut sink, stream) = channel(10);

        future::block_on(async {
            sink.send(create_symbol(1)).await.unwrap(); // Keep
            sink.send(create_symbol(2)).await.unwrap(); // Drop
            sink.send(create_symbol(3)).await.unwrap(); // Keep
            sink.close().await.unwrap();

            let mut filtered = stream.filter(|s| s.symbol().id().esi() % 2 != 0);

            let r1 = filtered.next().await.unwrap().unwrap();
            assert_eq!(r1.symbol().id().esi(), 1);

            let r2 = filtered.next().await.unwrap().unwrap();
            assert_eq!(r2.symbol().id().esi(), 3);

            assert!(filtered.next().await.is_none());
        });
    }

    #[test]
    fn test_stream_for_block() {
        let (mut sink, stream) = channel(10);

        future::block_on(async {
            sink.send(create_symbol_with_sbn(0, 1)).await.unwrap();
            sink.send(create_symbol_with_sbn(1, 2)).await.unwrap();
            sink.send(create_symbol_with_sbn(1, 3)).await.unwrap();
            sink.close().await.unwrap();

            let mut filtered = stream.for_block(1);
            let r1 = filtered.next().await.unwrap().unwrap();
            assert_eq!(r1.symbol().sbn(), 1);
            let r2 = filtered.next().await.unwrap().unwrap();
            assert_eq!(r2.symbol().sbn(), 1);
            assert!(filtered.next().await.is_none());
        });
    }

    #[test]
    fn test_stream_timeout() {
        let (_sink, stream) = channel(10);
        let mut timed = stream.timeout(Duration::ZERO);

        future::block_on(async {
            let res = timed.next().await;
            assert!(matches!(res, Some(Err(StreamError::Timeout))));
        });
    }

    #[test]
    fn test_merged_stream() {
        let s1 = VecStream::new(vec![create_symbol(1), create_symbol(3)]);
        let s2 = VecStream::new(vec![create_symbol(2), create_symbol(4)]);
        let mut merged = MergedStream::new(vec![s1, s2]);

        future::block_on(async {
            let mut out = Vec::new();
            while let Some(item) = merged.next().await {
                out.push(item.unwrap().symbol().esi());
            }
            assert_eq!(out, vec![1, 2, 3, 4]);
        });
    }

    #[test]
    fn test_stream_cancellation() {
        let (_sink, mut stream) = channel(10);
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        future::block_on(async {
            let res = stream.next_with_cancel(&cx).await;
            assert!(matches!(res, Err(StreamError::Cancelled)));
        });
    }

    #[test]
    fn test_stream_cancellation_after_pending() {
        let (_sink, mut stream) = channel(10);
        let cx = Cx::for_testing();

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let mut fut = stream.next_with_cancel(&cx);
        let mut fut = Pin::new(&mut fut);

        let first = fut.as_mut().poll(&mut context);
        assert!(matches!(first, Poll::Pending));

        cx.set_cancel_requested(true);
        let second = fut.as_mut().poll(&mut context);
        assert!(matches!(second, Poll::Ready(Err(StreamError::Cancelled))));
    }

    #[test]
    fn test_sink_buffer() {
        let (sink, mut stream) = channel(10);
        // Buffer capacity 5. Inner capacity 10.
        let mut buffered = sink.buffer(5);

        future::block_on(async {
            // Send 3 items (should be buffered)
            for i in 0..3 {
                buffered.send(create_symbol(i)).await.unwrap();
            }

            // Should not be in stream yet?
            // Our BufferedSink flushes if inner is ready.
            // ChannelSink is always ready if not full.
            // poll_send in BufferedSink:
            // if buffer >= capacity -> flush.
            // else push to buffer.
            // It does NOT flush aggressively unless we call flush().
            // But wait, my implementation:
            // fn poll_send(...) { ... self.get_mut().buffer.push(symbol); Poll::Ready(Ok(())) }
            // It only pushes to buffer. It does NOT flush to inner unless buffer is full.
            // So stream should be empty.

            // Verify stream empty?
            // Can't check is_empty synchronously easily on stream.
            // We can check if next() hangs. But we don't want to hang.

            // Flush
            buffered.flush().await.unwrap();

            // Now stream should have items
            let r1 = stream.next().await.unwrap().unwrap();
            assert_eq!(r1.symbol().id().esi(), 0);
        });
    }

    #[test]
    fn test_sink_send_all() {
        let (mut sink, mut stream) = channel(10);
        let symbols = vec![create_symbol(1), create_symbol(2), create_symbol(3)];

        future::block_on(async {
            let count = sink.send_all(symbols.clone()).await.unwrap();
            assert_eq!(count, symbols.len());
            sink.close().await.unwrap();

            for expected in symbols {
                let got = stream.next().await.unwrap().unwrap();
                assert_eq!(got, expected);
            }
        });
    }

    #[test]
    fn test_sink_after_close() {
        let (mut sink, _stream) = channel(10);

        future::block_on(async {
            sink.close().await.unwrap();
            let err = sink.send(create_symbol(1)).await.unwrap_err();
            assert!(matches!(err, SinkError::Closed));
        });
    }
}
