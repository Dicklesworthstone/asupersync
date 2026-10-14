use super::ReadBuf;
use super::copy_read_contract_tests::{ReadStep, ScriptReader, ShortWriter, Status, finish};
use crate::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader, copy_buf};
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

#[test]
fn fill_buf_retains_pending_fill_until_consumed_without_repolling_source() {
    let source = ScriptReader::new([
        ReadStep::Data(b"abcd".to_vec(), Status::Pending),
        ReadStep::Eof,
    ]);
    let polls = Rc::clone(&source.polls);
    let mut reader = BufReader::with_capacity(8, source);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut reader).poll_fill_buf(&mut cx),
        Poll::Ready(Ok(bytes)) if bytes == b"abcd"
    ));
    assert_eq!(reader.buffer(), b"abcd");
    assert_eq!(polls.get(), 1);
    Pin::new(&mut reader).consume(2);
    assert!(matches!(
        Pin::new(&mut reader).poll_fill_buf(&mut cx),
        Poll::Ready(Ok(bytes)) if bytes == b"cd"
    ));
    assert_eq!(polls.get(), 1);
    Pin::new(&mut reader).consume(2);
    assert!(matches!(
        Pin::new(&mut reader).poll_fill_buf(&mut cx),
        Poll::Ready(Ok(bytes)) if bytes.is_empty()
    ));
    assert_eq!(polls.get(), 2);
}

#[test]
fn small_reads_retain_pending_fill_across_every_consumption_boundary() {
    for width in 1..=4 {
        let source = ScriptReader::new([
            ReadStep::Data(b"abcd".to_vec(), Status::Pending),
            ReadStep::Eof,
        ]);
        let polls = Rc::clone(&source.polls);
        let mut reader = BufReader::with_capacity(8, source);
        let mut output = Vec::new();
        let mut cx = Context::from_waker(Waker::noop());
        while output.len() < 4 {
            let mut storage = vec![0; width];
            let mut buffer = ReadBuf::new(&mut storage);
            assert!(matches!(
                Pin::new(&mut reader).poll_read(&mut cx, &mut buffer),
                Poll::Ready(Ok(()))
            ));
            assert!(!buffer.filled().is_empty());
            output.extend_from_slice(buffer.filled());
            assert_eq!(polls.get(), 1);
        }
        assert_eq!(output, b"abcd");
        assert!(reader.buffer().is_empty());
    }
}

#[test]
fn refill_error_retains_reported_bytes_for_buffered_recovery() {
    for use_fill_buf in [true, false] {
        let source = ScriptReader::new([
            ReadStep::Data(b"abcd".to_vec(), Status::Error),
            ReadStep::Data(b"ef".to_vec(), Status::Ready),
            ReadStep::Eof,
        ]);
        let polls = Rc::clone(&source.polls);
        let mut reader = BufReader::with_capacity(8, source);
        let mut cx = Context::from_waker(Waker::noop());
        let error = if use_fill_buf {
            match Pin::new(&mut reader).poll_fill_buf(&mut cx) {
                Poll::Ready(Err(error)) => error,
                _ => panic!("expected the provider's error"),
            }
        } else {
            let mut byte = [0];
            let mut buffer = ReadBuf::new(&mut byte);
            let error = match Pin::new(&mut reader).poll_read(&mut cx, &mut buffer) {
                Poll::Ready(Err(error)) => error,
                _ => panic!("expected the provider's error"),
            };
            assert!(buffer.filled().is_empty());
            error
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(error.to_string(), "scripted read error");
        assert_eq!(reader.buffer(), b"abcd");
        assert_eq!(polls.get(), 1);
        let mut writer = ShortWriter::new(1, true);
        assert_eq!(finish(&mut copy_buf(&mut reader, &mut writer)).unwrap(), 6);
        assert_eq!(writer.bytes, b"abcdef");
        assert_eq!(polls.get(), 3);
    }
}

#[test]
fn shifted_refills_fail_closed_on_both_entry_points_and_all_provider_statuses() {
    for use_fill_buf in [true, false] {
        for status in [Status::Ready, Status::Pending, Status::Error] {
            let source = ScriptReader::new([ReadStep::Shifted(status)]);
            let polls = Rc::clone(&source.polls);
            let mut reader = BufReader::with_capacity(8, source);
            let mut cx = Context::from_waker(Waker::noop());
            if use_fill_buf {
                assert!(matches!(
                    Pin::new(&mut reader).poll_fill_buf(&mut cx),
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
                ));
            } else {
                let mut byte = [0];
                let mut buffer = ReadBuf::new(&mut byte);
                assert!(matches!(
                    Pin::new(&mut reader).poll_read(&mut cx, &mut buffer),
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
                ));
                assert!(buffer.filled().is_empty());
            }
            assert!(reader.buffer().is_empty());
            assert_eq!(polls.get(), 1);
            reader.discard_buffer();
            assert!(matches!(
                Pin::new(&mut reader).poll_fill_buf(&mut cx),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
            ));
            // A large read normally bypasses the buffer. It must not bypass a
            // previously detected invalid provider or re-admit unknown input.
            let mut bytes = [0; 16];
            let mut buffer = ReadBuf::new(&mut bytes);
            assert!(matches!(
                Pin::new(&mut reader).poll_read(&mut cx, &mut buffer),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
            ));
            assert!(buffer.filled().is_empty());
            assert_eq!(polls.get(), 1);
        }
    }
}

#[test]
fn empty_pending_refill_does_not_fabricate_eof() {
    let source = ScriptReader::new([
        ReadStep::Wait,
        ReadStep::Data(b"x".to_vec(), Status::Ready),
        ReadStep::Eof,
    ]);
    let mut reader = BufReader::with_capacity(8, source);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut reader).poll_fill_buf(&mut cx).is_pending());
    assert!(reader.buffer().is_empty());
    assert!(matches!(
        Pin::new(&mut reader).poll_fill_buf(&mut cx),
        Poll::Ready(Ok(bytes)) if bytes == b"x"
    ));
}

struct BlockedWriter;

impl AsyncWrite for BlockedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn dropping_copy_buf_after_pending_refill_preserves_read_ahead_for_restart() {
    let source = ScriptReader::new([
        ReadStep::Data(b"abcd".to_vec(), Status::Pending),
        ReadStep::Data(b"ef".to_vec(), Status::Ready),
        ReadStep::Eof,
    ]);
    let polls = Rc::clone(&source.polls);
    let mut reader = BufReader::with_capacity(8, source);
    let mut blocked = BlockedWriter;
    {
        let mut future = copy_buf(&mut reader, &mut blocked);
        assert!(super::copy_read_contract_tests::poll_once(&mut future).is_pending());
    }
    assert_eq!(reader.buffer(), b"abcd");
    assert_eq!(polls.get(), 1);
    let mut writer = ShortWriter::new(2, true);
    assert_eq!(finish(&mut copy_buf(&mut reader, &mut writer)).unwrap(), 6);
    assert_eq!(writer.bytes, b"abcdef");
}
