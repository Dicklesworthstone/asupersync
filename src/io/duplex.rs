//! An in-memory, bidirectional byte pipe.
//!
//! [`duplex`] returns two connected [`DuplexStream`]s. Bytes written to one
//! are read from the other, through a buffer of at most `max_buf_size` bytes
//! per direction. A full buffer makes the writer wait for the reader, so a
//! duplex pair has the same backpressure shape as a socket.
//!
//! It connects in-process components that speak a byte protocol, and tests
//! protocol code without a socket: the client side of an HTTP, gRPC or
//! database codec on one end, a scripted server on the other.
//!
//! Closing follows a socket's half-close:
//! - after one end calls `poll_shutdown` (or is dropped), the other end reads
//!   the bytes already buffered and then end-of-file;
//! - writing to an end whose peer was dropped, or after shutting it down,
//!   fails with [`io::ErrorKind::BrokenPipe`].

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// Creates a connected pair of in-memory streams; see the
/// [module documentation](self).
///
/// `max_buf_size` bounds the bytes buffered in each direction. A
/// `max_buf_size` of zero is raised to one byte, so a writer can always make
/// progress once the reader drains.
///
/// ```
/// use asupersync::io::{AsyncReadExt, AsyncWriteExt, duplex};
/// use asupersync::runtime::RuntimeBuilder;
///
/// let runtime = RuntimeBuilder::current_thread().build().unwrap();
/// runtime.block_on(async {
///     let (mut client, mut server) = duplex(64);
///     client.write_all(b"ping").await.unwrap();
///     let mut buf = [0_u8; 4];
///     server.read_exact(&mut buf).await.unwrap();
///     assert_eq!(&buf, b"ping");
///
///     server.write_all(b"pong").await.unwrap();
///     drop(server);
///     let mut reply = Vec::new();
///     client.read_to_end(&mut reply).await.unwrap();
///     assert_eq!(reply, b"pong");
/// });
/// ```
#[must_use]
pub fn duplex(max_buf_size: usize) -> (DuplexStream, DuplexStream) {
    let one = Arc::new(Mutex::new(Pipe::new(max_buf_size)));
    let two = Arc::new(Mutex::new(Pipe::new(max_buf_size)));
    (
        DuplexStream {
            read: Arc::clone(&one),
            write: Arc::clone(&two),
        },
        DuplexStream {
            read: two,
            write: one,
        },
    )
}

/// One end of an in-memory pipe created by [`duplex`].
pub struct DuplexStream {
    read: Arc<Mutex<Pipe>>,
    write: Arc<Mutex<Pipe>>,
}

/// One direction of a duplex pair.
struct Pipe {
    buffer: VecDeque<u8>,
    max_buf_size: usize,
    /// The writing end shut down or was dropped: the reader drains, then sees
    /// end-of-file.
    write_closed: bool,
    /// The reading end was dropped: writes fail.
    read_closed: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl Pipe {
    fn new(max_buf_size: usize) -> Self {
        Self {
            buffer: VecDeque::new(),
            max_buf_size: max_buf_size.max(1),
            write_closed: false,
            read_closed: false,
            read_waker: None,
            write_waker: None,
        }
    }

    fn poll_read(
        &mut self,
        cx: &Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> (Poll<io::Result<()>>, Option<Waker>) {
        if self.buffer.is_empty() {
            if self.write_closed {
                return (Poll::Ready(Ok(())), None);
            }
            store_waker(&mut self.read_waker, cx);
            return (Poll::Pending, None);
        }
        let take = self.buffer.len().min(buf.remaining());
        let (front, back) = self.buffer.as_slices();
        let from_front = take.min(front.len());
        buf.put_slice(&front[..from_front]);
        buf.put_slice(&back[..take - from_front]);
        self.buffer.drain(..take);
        (Poll::Ready(Ok(())), self.write_waker.take())
    }

    fn poll_write(
        &mut self,
        cx: &Context<'_>,
        data: &[u8],
    ) -> (Poll<io::Result<usize>>, Option<Waker>) {
        if self.write_closed || self.read_closed {
            return (Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())), None);
        }
        if data.is_empty() {
            return (Poll::Ready(Ok(0)), None);
        }
        let room = self.max_buf_size - self.buffer.len();
        if room == 0 {
            store_waker(&mut self.write_waker, cx);
            return (Poll::Pending, None);
        }
        let written = room.min(data.len());
        self.buffer.extend(&data[..written]);
        (Poll::Ready(Ok(written)), self.read_waker.take())
    }

    fn close_write(&mut self) -> Option<Waker> {
        self.write_closed = true;
        self.read_waker.take()
    }

    fn close_read(&mut self) -> Option<Waker> {
        self.read_closed = true;
        // Bytes nobody will read no longer hold the writer back.
        self.buffer.clear();
        self.write_waker.take()
    }
}

fn store_waker(slot: &mut Option<Waker>, cx: &Context<'_>) {
    match slot {
        Some(waker) if waker.will_wake(cx.waker()) => {}
        _ => *slot = Some(cx.waker().clone()),
    }
}

/// Wakes outside the pipe's lock, so a woken task never contends with it.
fn wake(waker: Option<Waker>) {
    if let Some(waker) = waker {
        waker.wake();
    }
}

impl AsyncRead for DuplexStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let (poll, waker) = self.read.lock().poll_read(cx, buf);
        wake(waker);
        poll
    }
}

impl AsyncWrite for DuplexStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let (poll, waker) = self.write.lock().poll_write(cx, data);
        wake(waker);
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let waker = self.write.lock().close_write();
        wake(waker);
        Poll::Ready(Ok(()))
    }
}

impl Drop for DuplexStream {
    fn drop(&mut self) {
        let reader = self.write.lock().close_write();
        wake(reader);
        let writer = self.read.lock().close_read();
        wake(writer);
    }
}

impl std::fmt::Debug for DuplexStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let readable = self.read.lock().buffer.len();
        let writable = {
            let pipe = self.write.lock();
            pipe.max_buf_size - pipe.buffer.len()
        };
        f.debug_struct("DuplexStream")
            .field("readable", &readable)
            .field("writable", &writable)
            .finish()
    }
}
