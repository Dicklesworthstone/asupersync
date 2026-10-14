//! These tests live under `read_buf` so a deliberately invalid reader can
//! safely move the original backing slice into a shifted ReadBuf. No leaked
//! allocation, unsafe lifetime extension, real I/O, or executor is needed.

use super::ReadBuf;
use crate::io::{AsyncRead, AsyncWrite, copy, copy_bidirectional, copy_with_progress};
use std::cell::Cell;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

#[derive(Clone, Copy)]
pub(super) enum Status {
    Ready,
    Pending,
    Error,
}

pub(super) enum ReadStep {
    Data(Vec<u8>, Status),
    Shifted(Status),
    Wait,
    Eof,
}

pub(super) struct ScriptReader {
    steps: VecDeque<ReadStep>,
    pub(super) polls: Rc<Cell<usize>>,
}

impl ScriptReader {
    pub(super) fn new(steps: impl IntoIterator<Item = ReadStep>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            polls: Rc::new(Cell::new(0)),
        }
    }

    fn chunks(bytes: &[u8], chunk: usize, status: Status) -> Self {
        Self::new(
            bytes
                .chunks(chunk)
                .map(|bytes| ReadStep::Data(bytes.to_vec(), status))
                .chain(std::iter::once(ReadStep::Eof)),
        )
    }
}

impl AsyncRead for ScriptReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.polls.set(this.polls.get() + 1);
        let status = match this.steps.pop_front().unwrap_or(ReadStep::Eof) {
            ReadStep::Data(bytes, status) => {
                buffer.put_slice(&bytes);
                status
            }
            ReadStep::Shifted(status) => {
                // Moving the private backing reference preserves its lifetime.
                // Fill starts one byte beyond the supplied storage's origin,
                // so treating its length as our original buffer's cursor would
                // forward stale bytes. This is legal safe Rust, not UB.
                let storage = std::mem::replace(buffer, ReadBuf::new(&mut [])).buf;
                *buffer = ReadBuf::new(&mut storage[1..]);
                buffer.put_slice(b"bad");
                status
            }
            ReadStep::Wait => return Poll::Pending,
            ReadStep::Eof => return Poll::Ready(Ok(())),
        };
        match status {
            Status::Ready => Poll::Ready(Ok(())),
            // Deliberately do not self-wake. Reported bytes are already
            // available and the adapter must not park while discarding them.
            Status::Pending => Poll::Pending,
            Status::Error => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "scripted read error",
            ))),
        }
    }
}

pub(super) struct ShortWriter {
    pub(super) bytes: Vec<u8>,
    chunk: usize,
    pause: bool,
    polls: usize,
    pub(super) shutdowns: usize,
}

impl ShortWriter {
    pub(super) fn new(chunk: usize, pause: bool) -> Self {
        Self {
            bytes: Vec::new(),
            chunk,
            pause,
            polls: 0,
            shutdowns: 0,
        }
    }
}

impl AsyncWrite for ShortWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.polls += 1;
        if this.pause && this.polls.is_multiple_of(2) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = buffer.len().min(this.chunk);
        this.bytes.extend_from_slice(&buffer[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

struct Peer {
    reader: ScriptReader,
    writer: ShortWriter,
}

impl AsyncRead for Peer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buffer)
    }
}

impl AsyncWrite for Peer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

pub(super) fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
}

pub(super) fn finish<F: Future + Unpin>(future: &mut F) -> F::Output {
    for _ in 0..4096 {
        if let Poll::Ready(result) = poll_once(future) {
            return result;
        }
    }
    panic!("copy exceeded deterministic poll bound");
}

fn assert_invalid<T>(poll: Poll<io::Result<T>>) {
    match poll {
        Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
        _ => panic!("expected a terminal InvalidData error"),
    }
}

#[test]
fn copy_preserves_pending_fills_across_short_writes_and_backpressure() {
    let payload: Vec<u8> = (0..67).collect();
    for read_chunk in 1..=13 {
        for write_chunk in 1..=5 {
            let mut reader = ScriptReader::chunks(&payload, read_chunk, Status::Pending);
            let mut writer = ShortWriter::new(write_chunk, true);
            assert_eq!(finish(&mut copy(&mut reader, &mut writer)).unwrap(), 67);
            assert_eq!(writer.bytes, payload);
        }
    }
}

#[test]
fn progress_copy_accounts_for_pending_fills_only_after_committed_writes() {
    let payload: Vec<u8> = (0..67).collect();
    let mut reader = ScriptReader::chunks(&payload, 3, Status::Pending);
    let mut writer = ShortWriter::new(2, true);
    let mut observed = Vec::new();
    assert_eq!(
        finish(&mut copy_with_progress(&mut reader, &mut writer, |n| {
            observed.push(n);
        }))
        .unwrap(),
        67
    );
    assert_eq!(writer.bytes, payload);
    assert_eq!(observed.last(), Some(&67));
    assert!(observed.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(observed.windows(2).all(|pair| pair[1] - pair[0] <= 2));
}

#[test]
fn duplex_copy_preserves_pending_fills_and_half_closes_both_directions() {
    let left: Vec<u8> = (0..67).collect();
    let right: Vec<u8> = (80..121).collect();
    let mut a = Peer {
        reader: ScriptReader::chunks(&left, 3, Status::Pending),
        writer: ShortWriter::new(1, true),
    };
    let mut b = Peer {
        reader: ScriptReader::chunks(&right, 2, Status::Pending),
        writer: ShortWriter::new(2, true),
    };
    assert_eq!(
        finish(&mut copy_bidirectional(&mut a, &mut b)).unwrap(),
        (67, 41)
    );
    assert_eq!(b.writer.bytes, left);
    assert_eq!(a.writer.bytes, right);
    assert_eq!(a.writer.shutdowns, 1);
    assert_eq!(b.writer.shutdowns, 1);
}

#[test]
fn copy_rejects_shifted_storage_for_every_status_and_remains_terminal() {
    for status in [Status::Ready, Status::Pending, Status::Error] {
        let mut reader = ScriptReader::new([ReadStep::Shifted(status)]);
        let polls = Rc::clone(&reader.polls);
        let mut writer = ShortWriter::new(8, false);
        {
            let mut future = copy(&mut reader, &mut writer);
            assert_invalid(poll_once(&mut future));
            assert_eq!(polls.get(), 1);
            assert!(matches!(poll_once(&mut future), Poll::Ready(Err(_))));
            assert_eq!(polls.get(), 1, "terminal copies must not re-poll I/O");
        }
        assert!(writer.bytes.is_empty());
    }
}

#[test]
fn progress_copy_rejects_shifted_storage_without_reporting_or_writing_it() {
    for status in [Status::Ready, Status::Pending, Status::Error] {
        let mut reader = ScriptReader::new([ReadStep::Shifted(status)]);
        let polls = Rc::clone(&reader.polls);
        let mut writer = ShortWriter::new(8, false);
        let mut observed = Vec::new();
        {
            let mut future = copy_with_progress(&mut reader, &mut writer, |n| observed.push(n));
            assert_invalid(poll_once(&mut future));
            assert!(matches!(poll_once(&mut future), Poll::Ready(Err(_))));
            assert_eq!(polls.get(), 1);
        }
        assert!(observed.is_empty());
        assert!(writer.bytes.is_empty());
    }
}

#[test]
fn duplex_copy_rejects_shifted_storage_in_either_direction() {
    for status in [Status::Ready, Status::Pending, Status::Error] {
        for malformed_left in [true, false] {
            let mut a = Peer {
                reader: ScriptReader::new([if malformed_left {
                    ReadStep::Shifted(status)
                } else {
                    ReadStep::Eof
                }]),
                writer: ShortWriter::new(8, false),
            };
            let mut b = Peer {
                reader: ScriptReader::new([if malformed_left {
                    ReadStep::Eof
                } else {
                    ReadStep::Shifted(status)
                }]),
                writer: ShortWriter::new(8, false),
            };
            let a_polls = Rc::clone(&a.reader.polls);
            let b_polls = Rc::clone(&b.reader.polls);
            {
                let mut future = copy_bidirectional(&mut a, &mut b);
                assert_invalid(poll_once(&mut future));
                let before = (a_polls.get(), b_polls.get());
                assert!(matches!(poll_once(&mut future), Poll::Ready(Err(_))));
                assert_eq!((a_polls.get(), b_polls.get()), before);
            }
            assert!(a.writer.bytes.is_empty());
            assert!(b.writer.bytes.is_empty());
        }
    }
}

#[test]
fn pending_without_bytes_is_not_eof() {
    let mut reader = ScriptReader::new([
        ReadStep::Wait,
        ReadStep::Data(b"ok".to_vec(), Status::Ready),
        ReadStep::Eof,
    ]);
    let mut writer = ShortWriter::new(8, false);
    {
        let mut future = copy(&mut reader, &mut writer);
        assert!(poll_once(&mut future).is_pending());
        assert_eq!(finish(&mut future).unwrap(), 2);
    }
    assert_eq!(writer.bytes, b"ok");
}

#[test]
fn in_place_reader_error_keeps_its_original_kind() {
    let mut reader = ScriptReader::new([ReadStep::Data(Vec::new(), Status::Error)]);
    let mut writer = ShortWriter::new(8, false);
    let error = finish(&mut copy(&mut reader, &mut writer)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(error.to_string(), "scripted read error");
    assert!(writer.bytes.is_empty());
}
