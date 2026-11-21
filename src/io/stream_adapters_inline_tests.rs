#![allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::expect_fun_call,
    clippy::map_unwrap_or,
    clippy::cast_possible_wrap,
    clippy::future_not_send
)]
use super::*;
use crate::stream;

use std::task::Waker;

fn noop_waker() -> Waker {
    std::task::Waker::noop().clone()
}

fn init_test(name: &str) {
    crate::test_utils::init_test_logging();
    crate::test_phase!(name);
}

fn poll_read<R: AsyncRead + Unpin>(reader: &mut R, out: &mut [u8]) -> Poll<io::Result<usize>> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut read_buf = ReadBuf::new(out);
    match Pin::new(reader).poll_read(&mut cx, &mut read_buf) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
    }
}

#[test]
fn reader_stream_yields_chunks() {
    init_test("reader_stream_yields_chunks");
    let input: &[u8] = b"abcdef";
    let mut stream = ReaderStream::with_capacity(input, 2);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let first = Pin::new(&mut stream).poll_next(&mut cx);
    let ok = matches!(first, Poll::Ready(Some(Ok(chunk))) if chunk == b"ab");
    crate::assert_with_log!(ok, "first chunk", true, ok);

    let second = Pin::new(&mut stream).poll_next(&mut cx);
    let ok = matches!(second, Poll::Ready(Some(Ok(chunk))) if chunk == b"cd");
    crate::assert_with_log!(ok, "second chunk", true, ok);

    let third = Pin::new(&mut stream).poll_next(&mut cx);
    let ok = matches!(third, Poll::Ready(Some(Ok(chunk))) if chunk == b"ef");
    crate::assert_with_log!(ok, "third chunk", true, ok);

    let done = Pin::new(&mut stream).poll_next(&mut cx);
    let ok = matches!(done, Poll::Ready(None));
    crate::assert_with_log!(ok, "terminal none", true, ok);
    crate::test_complete!("reader_stream_yields_chunks");
}

enum ReaderStep {
    Pending,
    Data(&'static [u8], bool),
    Error(&'static [u8], io::Error),
    Eof,
}

struct ScriptedReader {
    steps: std::collections::VecDeque<ReaderStep>,
    polls: std::rc::Rc<std::cell::Cell<usize>>,
}

impl AsyncRead for ScriptedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.polls.set(self.polls.get() + 1);
        match self
            .steps
            .pop_front()
            .expect("reader polled after terminal state")
        {
            ReaderStep::Pending => Poll::Pending,
            ReaderStep::Data(bytes, pending) => {
                buf.put_slice(bytes);
                if pending {
                    // Deliberately no wake: the adapter already has data.
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            ReaderStep::Error(bytes, error) => {
                buf.put_slice(bytes);
                Poll::Ready(Err(error))
            }
            ReaderStep::Eof => Poll::Ready(Ok(())),
        }
    }
}

#[test]
fn reader_stream_dropped_empty_wait_preserves_later_pending_bytes() {
    use crate::stream::StreamExt;
    use std::future::Future;

    let polls = std::rc::Rc::new(std::cell::Cell::new(0));
    let source = ScriptedReader {
        steps: [
            ReaderStep::Pending,
            ReaderStep::Data(b"ab", true),
            ReaderStep::Data(b"cd", false),
            ReaderStep::Eof,
        ]
        .into(),
        polls: std::rc::Rc::clone(&polls),
    };
    let mut stream = ReaderStream::with_capacity(source, 2);
    let mut task = Context::from_waker(Waker::noop());
    {
        let mut next = std::pin::pin!(stream.next());
        assert!(next.as_mut().poll(&mut task).is_pending());
    }
    for expected in [b"ab", b"cd"] {
        let mut next = std::pin::pin!(stream.next());
        assert!(matches!(
            next.as_mut().poll(&mut task),
            Poll::Ready(Some(Ok(chunk))) if chunk == expected
        ));
    }
    for _ in 0..3 {
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut task),
            Poll::Ready(None)
        ));
    }
    assert_eq!(polls.get(), 4);
}

#[test]
fn reader_stream_round_trip_preserves_prefix_and_error_payload_identity() {
    #[derive(Debug)]
    struct Marker(std::sync::Arc<()>);

    impl std::fmt::Display for Marker {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("original reader error payload")
        }
    }

    impl std::error::Error for Marker {}

    let marker = std::sync::Arc::new(());
    let polls = std::rc::Rc::new(std::cell::Cell::new(0));
    let source = ScriptedReader {
        steps: [ReaderStep::Error(
            b"abc",
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                Marker(std::sync::Arc::clone(&marker)),
            ),
        )]
        .into(),
        polls: std::rc::Rc::clone(&polls),
    };
    let mut reader = StreamReader::new(ReaderStream::with_capacity(source, 4));
    let mut storage = [0xa5; 8];
    assert!(matches!(
        poll_read(&mut reader, &mut storage),
        Poll::Ready(Ok(3))
    ));
    assert_eq!(&storage[..3], b"abc");
    assert_eq!(&storage[3..], &[0xa5; 5]);
    let error = match poll_read(&mut reader, &mut storage) {
        Poll::Ready(Err(error)) => error,
        other => panic!("deferred read error was lost: {other:?}"),
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    let preserved = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<Marker>())
        .expect("original error payload");
    assert!(std::sync::Arc::ptr_eq(&preserved.0, &marker));
    assert!(matches!(
        poll_read(&mut reader, &mut storage),
        Poll::Ready(Ok(0))
    ));
    assert_eq!(polls.get(), 1);
}

#[test]
fn reader_stream_empty_errors_fuse_and_zero_capacity_still_reads() {
    let polls = std::rc::Rc::new(std::cell::Cell::new(0));
    let source = ScriptedReader {
        steps: [ReaderStep::Error(b"", io::ErrorKind::BrokenPipe.into())].into(),
        polls: std::rc::Rc::clone(&polls),
    };
    let mut stream = ReaderStream::with_capacity(source, 0);
    let mut task = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut task),
        Poll::Ready(Some(Err(error))) if error.kind() == io::ErrorKind::BrokenPipe
    ));
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut task),
        Poll::Ready(None)
    ));
    assert_eq!(polls.get(), 1);

    let mut stream = ReaderStream::with_capacity(b"xy".as_slice(), 0);
    for expected in [b"x", b"y"] {
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut task),
            Poll::Ready(Some(Ok(chunk))) if chunk == expected
        ));
    }
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut task),
        Poll::Ready(None)
    ));
}

#[test]
fn stream_reader_reads_across_multiple_chunks() {
    init_test("stream_reader_reads_across_multiple_chunks");
    let chunks = vec![Ok(vec![1_u8, 2]), Ok(vec![3]), Ok(vec![4, 5])];
    let stream = stream::iter(chunks);
    let mut reader = StreamReader::new(stream);

    let mut out = [0_u8; 5];
    let read = poll_read(&mut reader, &mut out);
    let ok = matches!(read, Poll::Ready(Ok(5)));
    crate::assert_with_log!(ok, "read length", true, ok);
    crate::assert_with_log!(out == [1, 2, 3, 4, 5], "content", [1, 2, 3, 4, 5], out);

    let mut eof = [0_u8; 4];
    let read = poll_read(&mut reader, &mut eof);
    let ok = matches!(read, Poll::Ready(Ok(0)));
    crate::assert_with_log!(ok, "eof", true, ok);
    crate::test_complete!("stream_reader_reads_across_multiple_chunks");
}

#[test]
fn stream_reader_defers_error_until_partial_data_consumed() {
    init_test("stream_reader_defers_error_until_partial_data_consumed");
    let chunks = vec![
        Ok(vec![10_u8, 11]),
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream failed")),
        Ok(vec![12]),
    ];
    let stream = stream::iter(chunks);
    let mut reader = StreamReader::new(stream);

    let mut out = [0_u8; 8];
    let read = poll_read(&mut reader, &mut out);
    let ok = matches!(read, Poll::Ready(Ok(2)));
    crate::assert_with_log!(ok, "partial read before error", true, ok);
    crate::assert_with_log!(out[..2] == [10, 11], "partial content", [10, 11], &out[..2]);

    let mut second = [0_u8; 8];
    let read = poll_read(&mut reader, &mut second);
    let ok = matches!(read, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::BrokenPipe);
    crate::assert_with_log!(ok, "error surfaced on next read", true, ok);
    crate::assert_with_log!(
        !reader.done,
        "deferred error is not eof",
        false,
        reader.done
    );

    let mut trailing = [0_u8; 8];
    let read = poll_read(&mut reader, &mut trailing);
    let ok = matches!(read, Poll::Ready(Ok(1)));
    crate::assert_with_log!(ok, "data after deferred error", true, ok);
    crate::assert_with_log!(trailing[0] == 12, "trailing content", 12, trailing[0]);
    crate::assert_with_log!(reader.done, "true eof fuses reader", true, reader.done);

    let mut eof = [0_u8; 1];
    let read = poll_read(&mut reader, &mut eof);
    let ok = matches!(read, Poll::Ready(Ok(0)));
    crate::assert_with_log!(ok, "fused eof", true, ok);
    crate::test_complete!("stream_reader_defers_error_until_partial_data_consumed");
}

#[test]
fn stream_reader_continues_after_immediate_error() {
    init_test("stream_reader_continues_after_immediate_error");
    let chunks = vec![
        Err(io::Error::new(io::ErrorKind::Interrupted, "retry read")),
        Ok(vec![1_u8, 2]),
    ];
    let stream = stream::iter(chunks);
    let mut reader = StreamReader::new(stream);

    let mut first = [0_u8; 2];
    let read = poll_read(&mut reader, &mut first);
    let ok = matches!(read, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Interrupted);
    crate::assert_with_log!(ok, "immediate error", true, ok);
    crate::assert_with_log!(!reader.done, "error is not eof", false, reader.done);

    let mut data = [0_u8; 2];
    let read = poll_read(&mut reader, &mut data);
    let ok = matches!(read, Poll::Ready(Ok(2)));
    crate::assert_with_log!(ok, "data after error", true, ok);
    crate::assert_with_log!(data == [1, 2], "data content", [1, 2], data);

    let mut eof = [0_u8; 1];
    let read = poll_read(&mut reader, &mut eof);
    let ok = matches!(read, Poll::Ready(Ok(0)));
    crate::assert_with_log!(ok, "true eof", true, ok);
    crate::assert_with_log!(reader.done, "true eof fuses reader", true, reader.done);

    let read = poll_read(&mut reader, &mut eof);
    let ok = matches!(read, Poll::Ready(Ok(0)));
    crate::assert_with_log!(ok, "repeated fused eof", true, ok);
    crate::test_complete!("stream_reader_continues_after_immediate_error");
}

struct PendingThenDataStream {
    state: u8,
}

impl PendingThenDataStream {
    fn new() -> Self {
        Self { state: 0 }
    }
}

impl Stream for PendingThenDataStream {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.state {
            0 => {
                self.state = 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            1 => {
                self.state = 2;
                Poll::Ready(Some(Ok(vec![7, 8, 9])))
            }
            _ => Poll::Ready(None),
        }
    }
}

#[test]
fn stream_reader_pending_without_buffered_data() {
    init_test("stream_reader_pending_without_buffered_data");
    let mut reader = StreamReader::new(PendingThenDataStream::new());

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut out = [0_u8; 3];
    let mut read_buf = ReadBuf::new(&mut out);
    let first = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
    let ok = first.is_pending();
    crate::assert_with_log!(ok, "first poll pending", true, ok);

    let mut out = [0_u8; 3];
    let mut read_buf = ReadBuf::new(&mut out);
    let second = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
    let ok = matches!(second, Poll::Ready(Ok(()))) && read_buf.filled() == [7, 8, 9];
    crate::assert_with_log!(ok, "second poll reads data", true, ok);
    crate::test_complete!("stream_reader_pending_without_buffered_data");
}

#[derive(Debug, Default)]
struct ControlledByteSink {
    items: Vec<Vec<u8>>,
    ready_polls: usize,
    flush_polls: usize,
    close_polls: usize,
    admitted: bool,
    ready_pending: bool,
    flush_pending: bool,
    close_pending: bool,
    ready_error: Option<io::ErrorKind>,
    send_error: Option<io::ErrorKind>,
    flush_error: Option<io::ErrorKind>,
    close_error: Option<io::ErrorKind>,
}

impl Sink<Vec<u8>> for ControlledByteSink {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ready_polls += 1;
        if let Some(kind) = self.ready_error.take() {
            return Poll::Ready(Err(kind.into()));
        }
        if self.ready_pending {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.admitted = true;
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> io::Result<()> {
        assert!(self.admitted, "submission must follow readiness");
        self.admitted = false;
        if let Some(kind) = self.send_error.take() {
            return Err(kind.into());
        }
        self.items.push(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_polls += 1;
        if let Some(kind) = self.flush_error.take() {
            return Poll::Ready(Err(kind.into()));
        }
        if self.flush_pending {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.close_polls += 1;
        if let Some(kind) = self.close_error.take() {
            return Poll::Ready(Err(kind.into()));
        }
        if self.close_pending {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

#[test]
fn sink_writer_admits_only_after_readiness_and_bounds_each_chunk() {
    let mut task = Context::from_waker(Waker::noop());
    let sink = ControlledByteSink {
        ready_pending: true,
        ..ControlledByteSink::default()
    };
    let mut writer = SinkWriter::new(sink).with_max_chunk_size(3);
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut task, b""),
        Poll::Ready(Ok(0))
    ));
    assert_eq!(writer.get_ref().ready_polls, 0);

    assert!(
        Pin::new(&mut writer)
            .poll_write(&mut task, b"abcdef")
            .is_pending()
    );
    assert!(writer.get_ref().items.is_empty());
    writer.get_mut().ready_pending = false;
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut task, b"abcdef"),
        Poll::Ready(Ok(3))
    ));
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut task, b"def"),
        Poll::Ready(Ok(3))
    ));
    assert_eq!(writer.get_ref().items, [b"abc".to_vec(), b"def".to_vec()]);
    assert_eq!(writer.get_ref().flush_polls, 0, "writes do not flush");
    assert_eq!(writer.max_chunk_size(), 3);
    let sink = writer.into_inner();
    assert_eq!(sink.items.concat(), b"abcdef");

    let mut one = SinkWriter::new(ControlledByteSink::default()).with_max_chunk_size(0);
    assert_eq!(one.max_chunk_size(), 1);
    assert!(matches!(
        Pin::new(&mut one).poll_write(&mut task, b"xy"),
        Poll::Ready(Ok(1))
    ));
    let mut default = SinkWriter::new(ControlledByteSink::default());
    let input = vec![7; DEFAULT_CHUNK_SIZE + 1];
    assert!(matches!(
        Pin::new(&mut default).poll_write(&mut task, &input),
        Poll::Ready(Ok(DEFAULT_CHUNK_SIZE))
    ));
    assert_eq!(default.get_ref().items[0].len(), DEFAULT_CHUNK_SIZE);
}

#[test]
fn sink_writer_forwards_errors_and_only_latches_successful_shutdown() {
    let mut task = Context::from_waker(Waker::noop());
    let mut writer = SinkWriter::new(ControlledByteSink::default());
    writer.get_mut().ready_error = Some(io::ErrorKind::ConnectionReset);
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut task, b"x"),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset
    ));
    assert!(writer.get_ref().items.is_empty());
    writer.get_mut().send_error = Some(io::ErrorKind::InvalidData);
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut task, b"x"),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
    ));
    assert!(writer.get_ref().items.is_empty());
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut task, b"x"),
        Poll::Ready(Ok(1))
    ));

    writer.get_mut().flush_error = Some(io::ErrorKind::BrokenPipe);
    assert!(matches!(
        Pin::new(&mut writer).poll_flush(&mut task),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe
    ));
    writer.get_mut().flush_pending = true;
    assert!(Pin::new(&mut writer).poll_flush(&mut task).is_pending());
    writer.get_mut().flush_pending = false;
    assert!(matches!(
        Pin::new(&mut writer).poll_flush(&mut task),
        Poll::Ready(Ok(()))
    ));

    writer.get_mut().close_error = Some(io::ErrorKind::ConnectionAborted);
    assert!(matches!(
        Pin::new(&mut writer).poll_shutdown(&mut task),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted
    ));
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut task, b"y"),
        Poll::Ready(Ok(1))
    ));
    writer.get_mut().close_pending = true;
    assert!(Pin::new(&mut writer).poll_shutdown(&mut task).is_pending());
    writer.get_mut().close_pending = false;
    assert!(matches!(
        Pin::new(&mut writer).poll_shutdown(&mut task),
        Poll::Ready(Ok(()))
    ));
    let calls = (
        writer.get_ref().ready_polls,
        writer.get_ref().flush_polls,
        writer.get_ref().close_polls,
    );
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut task, b"z"),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe
    ));
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut task, b""),
        Poll::Ready(Ok(0))
    ));
    assert!(matches!(
        Pin::new(&mut writer).poll_flush(&mut task),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        Pin::new(&mut writer).poll_shutdown(&mut task),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(
        calls,
        (
            writer.get_ref().ready_polls,
            writer.get_ref().flush_polls,
            writer.get_ref().close_polls,
        )
    );
    assert_eq!(writer.get_ref().items.concat(), b"xy");
}

#[test]
fn sink_writer_retains_framed_progress_across_dropped_flush_and_shutdown() {
    use crate::codec::{BytesCodec, FramedWrite};
    use crate::io::AsyncWriteExt;
    use std::future::Future;

    let (local, mut peer) = crate::io::duplex(2);
    let framed = FramedWrite::new(local, BytesCodec::new()).with_backpressure_boundary(1);
    let mut writer = SinkWriter::new(framed).with_max_chunk_size(8);
    let mut task = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut task, b"abcdef"),
        Poll::Ready(Ok(6))
    ));

    {
        let mut flush = std::pin::pin!(writer.flush());
        assert!(flush.as_mut().poll(&mut task).is_pending());
    }
    assert_eq!(&writer.get_ref().write_buffer()[..], b"cdef");
    // Readiness must not admit another chunk while the earlier one is blocked.
    assert!(
        Pin::new(&mut writer)
            .poll_write(&mut task, b"XYZ")
            .is_pending()
    );
    assert_eq!(&writer.get_ref().write_buffer()[..], b"cdef");
    let mut output = [0; 2];
    assert!(matches!(
        poll_read(&mut peer, &mut output),
        Poll::Ready(Ok(2))
    ));
    assert_eq!(&output, b"ab");

    {
        let mut shutdown = std::pin::pin!(writer.shutdown());
        assert!(shutdown.as_mut().poll(&mut task).is_pending());
    }
    assert_eq!(&writer.get_ref().write_buffer()[..], b"ef");
    assert!(matches!(
        poll_read(&mut peer, &mut output),
        Poll::Ready(Ok(2))
    ));
    assert_eq!(&output, b"cd");
    assert!(matches!(
        Pin::new(&mut writer).poll_shutdown(&mut task),
        Poll::Ready(Ok(()))
    ));
    assert!(writer.get_ref().write_buffer().is_empty());
    assert!(matches!(
        poll_read(&mut peer, &mut output),
        Poll::Ready(Ok(2))
    ));
    assert_eq!(&output, b"ef");
    assert!(matches!(
        poll_read(&mut peer, &mut output),
        Poll::Ready(Ok(0))
    ));
}

#[test]
fn sink_writer_framed_round_trip_under_native_backpressure() {
    use crate::codec::{BytesCodec, FramedRead, FramedWrite};
    use crate::io::AsyncWriteExt;
    use crate::runtime::RuntimeBuilder;
    use crate::stream::StreamExt;
    use std::time::Duration;

    for workers in [1, 2] {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread()
                .build()
                .expect("current-thread runtime")
        } else {
            RuntimeBuilder::multi_thread()
                .worker_threads(workers)
                .build()
                .expect("worker runtime")
        };
        runtime.block_on(async {
            let (local, peer) = crate::io::duplex(3);
            let framed = FramedWrite::with_capacity(local, BytesCodec::new(), 4);
            let mut writer = SinkWriter::new(framed).with_max_chunk_size(5);
            let mut reader = FramedRead::new(peer, BytesCodec::new());
            let expected = b"bounded chunks cross native backpressure exactly once";
            let sending = async {
                writer.write_all(expected).await.expect("submit all bytes");
                writer.shutdown().await.expect("flush and half-close");
            };
            let receiving = async {
                let mut bytes = Vec::new();
                while let Some(chunk) = reader.next().await {
                    bytes.extend_from_slice(&chunk.expect("decode chunk"));
                }
                bytes
            };
            let ((), bytes) = futures_lite::future::zip(sending, receiving).await;
            assert_eq!(bytes, expected);
            assert!(writer.get_ref().write_buffer().is_empty());
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    }
}

#[test]
fn sink_writer_supports_borrowed_boxed_and_pinned_sinks() {
    use crate::codec::{BytesCodec, Framed, FramedWrite};

    let mut task = Context::from_waker(Waker::noop());
    let mut framed = FramedWrite::new(Vec::<u8>::new(), BytesCodec::new());
    {
        let mut borrowed = SinkWriter::new(&mut framed);
        assert!(matches!(
            Pin::new(&mut borrowed).poll_write(&mut task, b"borrowed"),
            Poll::Ready(Ok(8))
        ));
        assert!(matches!(
            Pin::new(&mut borrowed).poll_flush(&mut task),
            Poll::Ready(Ok(()))
        ));
    }
    assert_eq!(framed.get_ref(), b"borrowed");

    let boxed: Box<dyn Sink<Vec<u8>, Error = io::Error> + Unpin> =
        Box::new(Framed::new(Vec::<u8>::new(), BytesCodec::new()));
    let mut boxed = SinkWriter::new(boxed);
    assert!(matches!(
        Pin::new(&mut boxed).poll_write(&mut task, b"boxed"),
        Poll::Ready(Ok(5))
    ));
    assert!(matches!(
        Pin::new(&mut boxed).poll_shutdown(&mut task),
        Poll::Ready(Ok(()))
    ));

    // A pinned, non-Send and !Unpin sink demonstrates that the pointer
    // forwarding implementation imposes no such bound on its target.
    struct PinnedByteSink {
        bytes: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
        _pinned: std::marker::PhantomPinned,
    }
    impl Sink<Vec<u8>> for PinnedByteSink {
        type Error = io::Error;

        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> io::Result<()> {
            self.as_ref().get_ref().bytes.borrow_mut().extend(item);
            Ok(())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let bytes = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let sink = Box::pin(PinnedByteSink {
        bytes: std::rc::Rc::clone(&bytes),
        _pinned: std::marker::PhantomPinned,
    });
    let mut pinned = SinkWriter::new(sink);
    assert!(matches!(
        Pin::new(&mut pinned).poll_write(&mut task, b"pinned"),
        Poll::Ready(Ok(6))
    ));
    assert!(matches!(
        Pin::new(&mut pinned).poll_shutdown(&mut task),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(&*bytes.borrow(), b"pinned");
}

#[test]
fn framed_sink_preserves_inbound_frames_while_writing() {
    use crate::codec::{BytesCodec, Framed};
    let (local, mut peer) = crate::io::duplex(8);
    let mut framed = Framed::new(local, BytesCodec::new());
    let mut task = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut peer).poll_write(&mut task, b"inbound"),
        Poll::Ready(Ok(7))
    ));
    assert!(matches!(
        Sink::<Vec<u8>>::poll_ready(Pin::new(&mut framed), &mut task),
        Poll::Ready(Ok(()))
    ));
    Sink::<Vec<u8>>::start_send(Pin::new(&mut framed), b"outbound".to_vec())
        .expect("encode outbound");
    assert!(matches!(
        Sink::<Vec<u8>>::poll_flush(Pin::new(&mut framed), &mut task),
        Poll::Ready(Ok(()))
    ));
    let mut output = [0; 8];
    assert!(matches!(
        poll_read(&mut peer, &mut output),
        Poll::Ready(Ok(8))
    ));
    assert_eq!(&output, b"outbound");
    match Pin::new(&mut framed).poll_next(&mut task) {
        Poll::Ready(Some(Ok(bytes))) => assert_eq!(&bytes[..], b"inbound"),
        other => panic!("expected inbound frame, got {other:?}"),
    }
    assert!(matches!(
        Sink::<Vec<u8>>::poll_close(Pin::new(&mut framed), &mut task),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        poll_read(&mut peer, &mut output),
        Poll::Ready(Ok(0))
    ));
}
