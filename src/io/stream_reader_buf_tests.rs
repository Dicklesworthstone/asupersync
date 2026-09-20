use super::*;
use crate::io::{AsyncWrite, copy_buf};
use crate::stream;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

fn buffered(reader: &mut (impl AsyncBufRead + Unpin)) -> &[u8] {
    match Pin::new(reader).poll_fill_buf(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Ok(bytes)) => bytes,
        other => panic!("expected buffered bytes, got {other:?}"),
    }
}

fn read_once(reader: &mut (impl AsyncRead + Unpin), output: &mut [u8]) -> usize {
    let mut buf = ReadBuf::new(output);
    assert!(matches!(
        Pin::new(reader).poll_read(&mut Context::from_waker(Waker::noop()), &mut buf),
        Poll::Ready(Ok(()))
    ));
    buf.filled().len()
}

#[test]
fn buffered_reads_reuse_the_chunk_allocation_until_consumed() {
    let data = b"abcdef".to_vec();
    let address = data.as_ptr();
    let mut reader = StreamReader::new(stream::iter([Ok(data), Ok(b"next".to_vec())]));
    for _ in 0..3 {
        let bytes = buffered(&mut reader);
        assert_eq!(bytes, b"abcdef");
        assert_eq!(bytes.as_ptr(), address, "fill_buf copied the chunk");
    }
    Pin::new(&mut reader).consume(2);
    let remaining = buffered(&mut reader);
    assert_eq!(remaining, b"cdef");
    assert_eq!(remaining.as_ptr() as usize, address as usize + 2);
    Pin::new(&mut reader).consume(usize::MAX);
    assert_eq!(buffered(&mut reader), b"next");
    Pin::new(&mut reader).consume(usize::MAX);
    assert!(buffered(&mut reader).is_empty());
}

#[test]
fn read_and_buffered_interfaces_share_one_cursor() {
    let mut reader = StreamReader::new(stream::iter([
        Ok(b"abcde".to_vec()),
        Ok(b"fgh".to_vec()),
    ]));
    Pin::new(&mut reader).consume(usize::MAX); // No read-ahead, nothing to consume.
    assert_eq!(buffered(&mut reader), b"abcde");
    Pin::new(&mut reader).consume(0);
    Pin::new(&mut reader).consume(2);
    let mut output = [0; 2];
    assert_eq!(read_once(&mut reader, &mut output), 2);
    assert_eq!(&output, b"cd");
    assert_eq!(buffered(&mut reader), b"e");
    let mut output = [0; 3];
    assert_eq!(read_once(&mut reader, &mut output), 3);
    assert_eq!(&output, b"efg");
    assert_eq!(buffered(&mut reader), b"h");
    Pin::new(&mut reader).consume(1);
    assert!(buffered(&mut reader).is_empty());
}

#[test]
fn switching_to_buffered_reads_preserves_a_deferred_error() {
    let mut reader = StreamReader::new(stream::iter([
        Ok(b"prefix".to_vec()),
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "deferred sentinel")),
        Ok(b"tail".to_vec()),
    ]));
    let mut output = [0; 32];
    assert_eq!(read_once(&mut reader, &mut output), 6);
    assert_eq!(&output[..6], b"prefix");
    // A zero-length ordinary read must not consume the deferred error either.
    assert_eq!(read_once(&mut reader, &mut []), 0);
    let error = Pin::new(&mut reader)
        .poll_fill_buf(&mut Context::from_waker(Waker::noop()));
    assert!(matches!(error, Poll::Ready(Err(ref error))
        if error.kind() == io::ErrorKind::BrokenPipe
            && error.to_string() == "deferred sentinel"));
    assert_eq!(buffered(&mut reader), b"tail");
    assert_eq!(buffered(&mut reader), b"tail");
}

#[test]
fn buffered_errors_do_not_hide_following_data() {
    let mut reader = StreamReader::new(stream::iter([
        Err(io::Error::new(io::ErrorKind::Interrupted, "retry")),
        Ok(b"data".to_vec()),
    ]));
    let error = Pin::new(&mut reader)
        .poll_fill_buf(&mut Context::from_waker(Waker::noop()));
    assert!(matches!(error, Poll::Ready(Err(error))
        if error.kind() == io::ErrorKind::Interrupted));
    let mut output = [0; 8];
    assert_eq!(read_once(&mut reader, &mut output), 4);
    assert_eq!(&output[..4], b"data");
    assert!(buffered(&mut reader).is_empty());
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct EmptyThenData {
    empties: usize,
    polls: usize,
    finished: bool,
}

impl Stream for EmptyThenData {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.polls += 1;
        if self.empties > 0 {
            self.empties -= 1;
            Poll::Ready(Some(Ok(Vec::new())))
        } else if !self.finished {
            self.finished = true;
            Poll::Ready(Some(Ok(b"data".to_vec())))
        } else {
            Poll::Ready(None)
        }
    }
}

#[test]
fn empty_chunks_yield_with_a_wake_instead_of_false_eof() {
    let mut reader = StreamReader::new(EmptyThenData {
        empties: 65,
        polls: 0,
        finished: false,
    });
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut cx = Context::from_waker(&waker);
    for round in 1..=2 {
        assert!(Pin::new(&mut reader).poll_fill_buf(&mut cx).is_pending());
        assert_eq!(reader.get_ref().polls, round * 32);
        assert_eq!(counter.0.load(Ordering::SeqCst), round);
    }
    assert_eq!(buffered(&mut reader), b"data");
    assert_eq!(reader.get_ref().polls, 66);
    assert_eq!(buffered(&mut reader), b"data");
    assert_eq!(reader.get_ref().polls, 66, "buffered data polled the producer");
}

struct PendingThenData(u8);

impl Stream for PendingThenData {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let state = self.0;
        self.0 += 1;
        match state {
            0 => Poll::Ready(Some(Ok(Vec::new()))),
            1 => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            2 => Poll::Ready(Some(Ok(b"data".to_vec()))),
            3 => Poll::Ready(None),
            _ => panic!("producer polled after EOF"),
        }
    }
}

#[test]
fn pending_is_not_eof_and_real_eof_is_fused_across_interfaces() {
    let mut reader = StreamReader::new(PendingThenData(0));
    assert!(Pin::new(&mut reader)
        .poll_fill_buf(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(buffered(&mut reader), b"data");
    Pin::new(&mut reader).consume(4);
    for _ in 0..3 {
        assert!(buffered(&mut reader).is_empty());
        assert_eq!(read_once(&mut reader, &mut [0; 1]), 0);
    }
}

struct PausedWriter {
    output: Vec<u8>,
    allowance: usize,
    fail: bool,
    waiter: Option<Waker>,
}

impl AsyncWrite for PausedWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.allowance == 0 {
            if self.fail {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "paused")));
            }
            self.waiter = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = self.allowance.min(input.len());
        self.allowance -= count;
        self.output.extend_from_slice(&input[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn copy_buf_retains_every_unwritten_suffix_across_drop_or_error() {
    let expected = b"abcdefghijklm";
    for fail in [false, true] {
        for prefix in 0..expected.len() {
            let mut reader = StreamReader::new(stream::iter([
                Ok(b"abc".to_vec()),
                Ok(Vec::new()),
                Ok(b"defgh".to_vec()),
                Ok(b"ijklm".to_vec()),
            ]));
            let mut writer = PausedWriter {
                output: Vec::new(),
                allowance: prefix,
                fail,
                waiter: None,
            };
            let mut cx = Context::from_waker(Waker::noop());
            {
                let mut copy = copy_buf(&mut reader, &mut writer);
                let result = Pin::new(&mut copy).poll(&mut cx);
                if fail {
                    assert!(matches!(result, Poll::Ready(Err(error))
                        if error.kind() == io::ErrorKind::BrokenPipe));
                } else {
                    assert!(result.is_pending());
                }
                // Dropping a pending future must not discard its read-ahead.
            }
            assert_eq!(writer.output, &expected[..prefix]);
            let suffix = buffered(&mut reader);
            assert!(!suffix.is_empty());
            assert!(expected[prefix..].starts_with(suffix));
            writer.allowance = usize::MAX;
            writer.fail = false;
            if let Some(waiter) = writer.waiter.take() {
                waiter.wake();
            }
            let mut copy = copy_buf(&mut reader, &mut writer);
            assert!(matches!(Pin::new(&mut copy).poll(&mut cx), Poll::Ready(Ok(count))
                if count == (expected.len() - prefix) as u64));
            assert_eq!(writer.output, expected, "fail={fail}, prefix={prefix}");
        }
    }
}
