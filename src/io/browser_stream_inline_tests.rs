    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::io::cap::HostApiAuthority;
    use std::io::Cursor;

    // A simple in-memory AsyncWrite for testing
    #[derive(Debug, Default)]
    struct MemSink {
        data: Vec<u8>,
        flush_count: u32,
        shutdown: bool,
    }

    impl AsyncWrite for MemSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.data.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flush_count += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown = true;
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Default)]
    struct PartialSink {
        data: Vec<u8>,
        max_chunk: usize,
    }

    impl AsyncWrite for PartialSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let chunk = buf.len().min(self.max_chunk.max(1));
            self.data.extend_from_slice(&buf[..chunk]);
            Poll::Ready(Ok(chunk))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn strict_message_host_cap() -> BrowserHostApiIoCap {
        BrowserHostApiIoCap::new(
            HostApiAuthority::deny_all().grant_surface(HostApiSurface::MessageChannel),
            true,
        )
    }

    fn degraded_message_host_cap() -> BrowserHostApiIoCap {
        BrowserHostApiIoCap::new(
            HostApiAuthority::deny_all()
                .grant_surface(HostApiSurface::MessageChannel)
                .with_degraded_mode_allowed(),
            true,
        )
    }

    // -- BrowserStreamState --

    #[test]
    fn stream_state_display() {
        assert_eq!(BrowserStreamState::Open.to_string(), "open");
        assert_eq!(BrowserStreamState::Closing.to_string(), "closing");
        assert_eq!(BrowserStreamState::Closed.to_string(), "closed");
        assert_eq!(BrowserStreamState::Errored.to_string(), "errored");
    }

    // -- BackpressureStrategy --

    #[test]
    fn backpressure_default_is_64kb_hwm() {
        let bp = BackpressureStrategy::default();
        assert_eq!(bp, BackpressureStrategy::HighWaterMark(65_536));
    }

    // -- BrowserStreamConfig --

    #[test]
    fn config_defaults_are_reasonable() {
        let config = BrowserStreamConfig::default();
        assert_eq!(config.max_read_chunk, 65_536);
        assert_eq!(config.max_total_read_bytes, 16 << 20); // 16MB
        assert_eq!(config.max_total_write_bytes, 4 << 20); // 4MB
        assert!(config.allow_partial_writes);
    }

    // -- BrowserStreamError --

    #[test]
    fn stream_error_display() {
        let err = BrowserStreamError::Aborted("user navigated".into());
        assert!(err.to_string().contains("user navigated"));

        let err = BrowserStreamError::ReadLimitExceeded {
            read: 100,
            limit: 50,
        };
        assert!(err.to_string().contains("100/50"));

        let err = BrowserStreamError::ClosedDuringOperation;
        assert!(err.to_string().contains("closed during"));
    }

    #[test]
    fn stream_error_to_io_error() {
        let aborted: io::Error = BrowserStreamError::Aborted("nav".into()).into();
        assert_eq!(aborted.kind(), io::ErrorKind::ConnectionAborted);

        let closed: io::Error = BrowserStreamError::ClosedDuringOperation.into();
        assert_eq!(closed.kind(), io::ErrorKind::BrokenPipe);

        let bp: io::Error = BrowserStreamError::BackpressureFull.into();
        assert_eq!(bp.kind(), io::ErrorKind::WouldBlock);
    }

    // -- BrowserReadableStream --

    #[test]
    fn readable_stream_reads_from_source() {
        let source = Cursor::new(b"hello browser world".to_vec());
        let mut stream = BrowserReadableStream::with_defaults(source);

        assert_eq!(stream.state(), BrowserStreamState::Open);
        assert_eq!(stream.total_read(), 0);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);

        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"hello browser world");
        assert_eq!(stream.total_read(), 19);
    }

    #[test]
    fn readable_stream_reaches_eof() {
        let source = Cursor::new(b"short".to_vec());
        let mut stream = BrowserReadableStream::with_defaults(source);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First read
        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);
        let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert_eq!(read_buf.filled(), b"short");

        // Second read: EOF
        let mut buf2 = [0u8; 64];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf2);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf2.filled().len(), 0);
        assert_eq!(stream.state(), BrowserStreamState::Closed);
    }

    #[test]
    fn readable_stream_cancel_produces_error() {
        let source = Cursor::new(b"data".to_vec());
        let mut stream = BrowserReadableStream::with_defaults(source);

        stream.cancel("user navigated away");
        assert_eq!(stream.state(), BrowserStreamState::Errored);
        assert_eq!(stream.cancel_reason(), Some("user navigated away"));

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);

        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn readable_stream_enforces_read_limit() {
        let source = Cursor::new(vec![0u8; 1000]);
        let config = BrowserStreamConfig {
            max_total_read_bytes: 10,
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserReadableStream::new(source, config);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First read: ok (reads up to 10 bytes)
        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 10); // Capped at budget

        // Second read: limit exceeded
        let mut buf2 = [0u8; 64];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf2);
        assert!(matches!(result, Poll::Ready(Err(_))));
        assert_eq!(stream.state(), BrowserStreamState::Errored);
    }

    #[test]
    fn readable_stream_inner_access() {
        let source = Cursor::new(b"data".to_vec());
        let stream = BrowserReadableStream::with_defaults(source);

        assert_eq!(stream.get_ref().position(), 0);
        let inner = stream.into_inner();
        assert_eq!(inner.position(), 0);
    }

    // -- BrowserWritableStream --

    #[test]
    fn writable_stream_writes_to_sink() {
        let sink = MemSink::default();
        let mut stream = BrowserWritableStream::with_defaults(sink);

        assert_eq!(stream.state(), BrowserStreamState::Open);
        assert_eq!(stream.total_written(), 0);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"hello");
        assert!(matches!(result, Poll::Ready(Ok(5))));
        assert_eq!(stream.total_written(), 5);
        assert_eq!(stream.get_ref().data, b"hello");
    }

    #[test]
    fn writable_stream_flush_resets_buffer() {
        let sink = MemSink::default();
        let mut stream = BrowserWritableStream::with_defaults(sink);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = Pin::new(&mut stream).poll_write(&mut cx, b"data");
        assert!(stream.buffered() > 0);

        let _ = Pin::new(&mut stream).poll_flush(&mut cx);
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.get_ref().flush_count, 1);
    }

    #[test]
    fn writable_stream_shutdown_transitions_to_closed() {
        let sink = MemSink::default();
        let mut stream = BrowserWritableStream::with_defaults(sink);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut stream).poll_shutdown(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(stream.state(), BrowserStreamState::Closed);
        assert!(stream.get_ref().shutdown);
    }

    #[test]
    fn writable_stream_abort_transitions_to_errored() {
        let sink = MemSink::default();
        let mut stream = BrowserWritableStream::with_defaults(sink);

        stream.abort("AbortController.abort()");
        assert_eq!(stream.state(), BrowserStreamState::Errored);
        assert_eq!(stream.abort_reason(), Some("AbortController.abort()"));
        assert_eq!(stream.buffered(), 0); // Buffer cleared on abort

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"nope");
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn writable_stream_enforces_write_limit() {
        let sink = MemSink::default();
        let config = BrowserStreamConfig {
            max_total_write_bytes: 8,
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserWritableStream::new(sink, config);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First write: ok (8 bytes budget)
        let result = Pin::new(&mut stream).poll_write(&mut cx, b"12345678");
        assert!(matches!(result, Poll::Ready(Ok(8))));

        // Second write: limit exceeded
        let result = Pin::new(&mut stream).poll_write(&mut cx, b"X");
        assert!(matches!(result, Poll::Ready(Err(_))));
        assert_eq!(stream.state(), BrowserStreamState::Errored);
    }

    #[test]
    fn writable_stream_write_after_close_fails() {
        let sink = MemSink::default();
        let mut stream = BrowserWritableStream::with_defaults(sink);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"too late");
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn writable_stream_inner_access() {
        let sink = MemSink::default();
        let stream = BrowserWritableStream::with_defaults(sink);
        assert!(stream.get_ref().data.is_empty());
        let inner = stream.into_inner();
        assert!(inner.data.is_empty());
    }

    #[test]
    fn writable_stream_backpressure_detection() {
        let sink = MemSink::default();
        let config = BrowserStreamConfig {
            write_backpressure: BackpressureStrategy::HighWaterMark(4),
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserWritableStream::new(sink, config);

        assert!(!stream.is_backpressured());

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write 4 bytes → at high water mark
        let _ = Pin::new(&mut stream).poll_write(&mut cx, b"1234");
        assert!(stream.is_backpressured());

        // Flush → buffer cleared
        let _ = Pin::new(&mut stream).poll_flush(&mut cx);
        assert!(!stream.is_backpressured());
    }

    #[test]
    fn writable_stream_abort_clears_backpressure_state() {
        let sink = MemSink::default();
        let config = BrowserStreamConfig {
            write_backpressure: BackpressureStrategy::HighWaterMark(4),
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserWritableStream::new(sink, config);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = Pin::new(&mut stream).poll_write(&mut cx, b"1234");
        assert!(stream.is_backpressured());

        stream.abort("route change");
        assert_eq!(stream.abort_reason(), Some("route change"));
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.state(), BrowserStreamState::Errored);
        assert!(!stream.is_backpressured());

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"5");
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn writable_stream_allows_partial_write_when_configured() {
        let sink = PartialSink {
            data: Vec::new(),
            max_chunk: 2,
        };
        let config = BrowserStreamConfig {
            allow_partial_writes: true,
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserWritableStream::new(sink, config);
        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"hello");
        assert!(matches!(result, Poll::Ready(Ok(2))));
        assert_eq!(stream.total_written(), 2);
    }

    #[test]
    fn writable_stream_partial_write_when_disallowed_surfaces_prefix_and_errors_later() {
        let sink = PartialSink {
            data: Vec::new(),
            max_chunk: 2,
        };
        let config = BrowserStreamConfig {
            allow_partial_writes: false,
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserWritableStream::new(sink, config);
        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"hello");
        assert!(matches!(result, Poll::Ready(Ok(2))));
        assert_eq!(stream.state(), BrowserStreamState::Errored);
        assert_eq!(stream.total_written(), 2);
        assert_eq!(stream.get_ref().data, b"he");

        let retry = Pin::new(&mut stream).poll_write(&mut cx, b"llo");
        assert!(matches!(retry, Poll::Ready(Err(_))));
        assert_eq!(stream.get_ref().data, b"he");
    }

    // -- BrowserStreamIoCap --

    #[test]
    fn stream_io_cap_tracks_stats() {
        let cap = BrowserStreamIoCap::new(BrowserStreamConfig::default());

        cap.record_open();
        cap.record_open();
        cap.record_close();
        cap.record_abort();

        let stats = cap.stream_stats();
        assert_eq!(
            stats
                .streams_opened
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            stats
                .streams_closed
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .streams_aborted
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn stream_io_cap_opens_bridges_with_config() {
        let cap = BrowserStreamIoCap::new(BrowserStreamConfig {
            max_read_chunk: 8,
            max_total_read_bytes: 128,
            ..BrowserStreamConfig::default()
        });
        let reader = cap.open_readable(Cursor::new(b"abc".to_vec()));
        assert_eq!(reader.state(), BrowserStreamState::Open);
        assert_eq!(reader.total_read(), 0);
        assert_eq!(
            cap.stream_stats()
                .streams_opened
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn stream_io_cap_readable_bridge_updates_bytes_and_close_stats() {
        let cap = BrowserStreamIoCap::new(BrowserStreamConfig::default());
        let mut reader = cap.open_readable(Cursor::new(b"abc".to_vec()));
        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"abc");

        let mut eof_buf = [0u8; 8];
        let mut eof_read_buf = ReadBuf::new(&mut eof_buf);
        let eof = Pin::new(&mut reader).poll_read(&mut cx, &mut eof_read_buf);
        assert!(matches!(eof, Poll::Ready(Ok(()))));
        assert_eq!(reader.state(), BrowserStreamState::Closed);

        let stats = cap.stream_stats();
        assert_eq!(
            stats
                .total_bytes_read
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
        assert_eq!(
            stats
                .streams_closed
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .streams_aborted
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn stream_io_cap_writable_bridge_updates_bytes_and_close_stats() {
        let cap = BrowserStreamIoCap::new(BrowserStreamConfig::default());
        let mut writer = cap.open_writable(MemSink::default());
        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let wrote = Pin::new(&mut writer).poll_write(&mut cx, b"hello");
        assert!(matches!(wrote, Poll::Ready(Ok(5))));
        let shutdown = Pin::new(&mut writer).poll_shutdown(&mut cx);
        assert!(matches!(shutdown, Poll::Ready(Ok(()))));
        assert_eq!(writer.state(), BrowserStreamState::Closed);

        let stats = cap.stream_stats();
        assert_eq!(
            stats
                .total_bytes_written
                .load(std::sync::atomic::Ordering::Relaxed),
            5
        );
        assert_eq!(
            stats
                .streams_closed
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .streams_aborted
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn stream_io_cap_records_abort_from_bridge_abort_path() {
        let cap = BrowserStreamIoCap::new(BrowserStreamConfig::default());
        let mut writer = cap.open_writable(MemSink::default());

        writer.abort("route change");

        let stats = cap.stream_stats();
        assert_eq!(
            stats
                .streams_aborted
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .streams_closed
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    // -- Browser-native messaging wrappers --

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_message_channel_wrapper_requires_degraded_mode_grant() {
        let error = strict_message_host_cap()
            .open_message_channel()
            .expect_err("native fallback should require degraded-mode authority");
        assert_eq!(
            error,
            BrowserMessageError::Policy(HostApiPolicyError::DegradedModeDenied(
                HostApiSurface::MessageChannel
            ))
        );
    }

    #[test]
    fn message_channel_wrapper_transfers_payloads_and_close_rejects_operations() {
        let channel = degraded_message_host_cap()
            .open_message_channel()
            .expect("message channel wrapper should open");
        let (mut left, mut right) = channel.split();

        left.send(&BrowserMessagePayload::Text("hello".to_owned()))
            .expect("send should succeed");
        assert_eq!(
            right.try_recv().expect("receive should succeed"),
            Some(BrowserMessagePayload::Text("hello".to_owned()))
        );

        right.close();
        assert_eq!(right.state(), BrowserMessageState::Closed);
        assert_eq!(
            left.send(&BrowserMessagePayload::Bytes(vec![1, 2, 3])),
            Err(BrowserMessageError::Closed)
        );
    }

    #[test]
    fn message_port_abort_marks_errored_and_rejects_subsequent_operations() {
        let channel = degraded_message_host_cap()
            .open_message_channel()
            .expect("message channel wrapper should open");
        let (mut left, mut right) = channel.split();

        left.abort("route change");
        assert_eq!(left.state(), BrowserMessageState::Errored);
        assert_eq!(
            left.error(),
            Some(&BrowserMessageError::Aborted("route change".to_owned()))
        );
        assert_eq!(
            left.send(&BrowserMessagePayload::Text("late".to_owned())),
            Err(BrowserMessageError::Aborted("route change".to_owned()))
        );
        assert_eq!(
            left.try_recv(),
            Err(BrowserMessageError::Aborted("route change".to_owned()))
        );
        assert_eq!(
            right.send(&BrowserMessagePayload::Text("peer".to_owned())),
            Err(BrowserMessageError::Closed)
        );
    }

    #[test]
    fn broadcast_channel_wrapper_delivers_payloads_and_abort_is_sticky() {
        let cap = degraded_message_host_cap();
        let mut sender = cap
            .open_broadcast_channel("browser-stream-tests")
            .expect("broadcast channel wrapper should open");
        let mut receiver = cap
            .open_broadcast_channel("browser-stream-tests")
            .expect("broadcast channel wrapper should open");

        sender
            .send(&BrowserMessagePayload::Bytes(vec![9, 8, 7]))
            .expect("broadcast send should succeed");
        assert_eq!(
            receiver
                .try_recv()
                .expect("broadcast receive should succeed"),
            Some(BrowserMessagePayload::Bytes(vec![9, 8, 7]))
        );

        sender.abort("page hidden");
        assert_eq!(sender.state(), BrowserMessageState::Errored);
        assert_eq!(
            sender.send(&BrowserMessagePayload::Text("late".to_owned())),
            Err(BrowserMessageError::Aborted("page hidden".to_owned()))
        );
    }

    // -- Helpers --

    /// Construct a no-op waker for synchronous polling in tests.
    fn futures_task_noop_waker() -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable};

        fn noop(_: *const ()) {}
        fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTABLE)
        }

        const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);

        // SAFETY: The no-op waker has no resources and all operations are no-ops.
        #[allow(unsafe_code)]
        unsafe {
            std::task::Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE))
        }
    }

    /// A body exactly `max_total_read_bytes` long reads to EOF; one byte more
    /// fails the stream (asupersync-6n35x5).
    #[test]
    fn readable_stream_accepts_a_body_exactly_at_the_read_limit() {
        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);
        let config = BrowserStreamConfig {
            max_total_read_bytes: 10,
            ..BrowserStreamConfig::default()
        };

        let mut exact = BrowserReadableStream::new(Cursor::new(vec![7u8; 10]), config.clone());
        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);
        let first = Pin::new(&mut exact).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(first, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 10);
        let mut eof = [0u8; 64];
        let mut eof_buf = ReadBuf::new(&mut eof);
        let second = Pin::new(&mut exact).poll_read(&mut cx, &mut eof_buf);
        assert!(
            matches!(second, Poll::Ready(Ok(()))),
            "a body exactly at the limit ends with EOF: {second:?}"
        );
        assert!(eof_buf.filled().is_empty());
        assert_eq!(exact.state(), BrowserStreamState::Closed);

        let mut over = BrowserReadableStream::new(Cursor::new(vec![7u8; 11]), config);
        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);
        assert!(matches!(
            Pin::new(&mut over).poll_read(&mut cx, &mut read_buf),
            Poll::Ready(Ok(()))
        ));
        let mut more = [0u8; 64];
        let mut more_buf = ReadBuf::new(&mut more);
        let past = Pin::new(&mut over).poll_read(&mut cx, &mut more_buf);
        assert!(
            matches!(past, Poll::Ready(Err(_))),
            "one byte past the limit fails: {past:?}"
        );
        assert_eq!(over.state(), BrowserStreamState::Errored);
    }
