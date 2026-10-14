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
/// [module documentation](crate::io#in-memory-pipes-and-standard-streams).
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

    fn try_read(&mut self, buf: &mut ReadBuf<'_>) -> PipeResult<()> {
        if buf.remaining() == 0 {
            return Some((Ok(()), None));
        }
        if self.buffer.is_empty() {
            if self.write_closed {
                return Some((Ok(()), None));
            }
            return None;
        }
        let take = self.buffer.len().min(buf.remaining());
        let (front, back) = self.buffer.as_slices();
        let from_front = take.min(front.len());
        buf.put_slice(&front[..from_front]);
        buf.put_slice(&back[..take - from_front]);
        self.buffer.drain(..take);
        Some((Ok(()), self.write_waker.take()))
    }

    fn try_write(&mut self, data: &[u8]) -> PipeResult<usize> {
        if self.write_closed || self.read_closed {
            return Some((Err(io::ErrorKind::BrokenPipe.into()), None));
        }
        if data.is_empty() {
            return Some((Ok(0), None));
        }
        let room = self.max_buf_size - self.buffer.len();
        if room == 0 {
            return None;
        }
        let written = room.min(data.len());
        self.buffer.extend(&data[..written]);
        Some((Ok(written), self.read_waker.take()))
    }

    fn close_write(&mut self) -> (Option<Waker>, Option<Waker>) {
        self.write_closed = true;
        (self.read_waker.take(), self.write_waker.take())
    }

    fn close_read(&mut self) -> (Option<Waker>, Option<Waker>) {
        self.read_closed = true;
        // Bytes nobody will read no longer hold the writer back.
        self.buffer.clear();
        (self.write_waker.take(), self.read_waker.take())
    }
}

type PipeResult<T> = Option<(io::Result<T>, Option<Waker>)>;

#[derive(Clone, Copy)]
enum Direction {
    Read,
    Write,
}

impl Direction {
    fn waiter(self, pipe: &mut Pipe) -> &mut Option<Waker> {
        match self {
            Self::Read => &mut pipe.read_waker,
            Self::Write => &mut pipe.write_waker,
        }
    }
}

/// Serialize the condition check and registration, but never run a `Waker`
/// clone, drop, or wake callback while holding the pipe's lock.
fn poll_pipe<T>(
    shared: &Mutex<Pipe>,
    cx: &Context<'_>,
    direction: Direction,
    mut attempt: impl FnMut(&mut Pipe) -> PipeResult<T>,
) -> Poll<io::Result<T>> {
    let mut incoming = None;
    loop {
        let mut pipe = shared.lock();
        if let Some((result, wake)) = attempt(&mut pipe) {
            let retired = direction.waiter(&mut pipe).take();
            drop(pipe);
            finish_callbacks([wake, None], [retired, incoming.take()]);
            return Poll::Ready(result);
        }
        let slot = direction.waiter(&mut pipe);
        if slot.as_ref().is_some_and(|waker| waker.will_wake(cx.waker())) {
            drop(pipe);
            finish_callbacks([None, None], [incoming.take(), None]);
            return Poll::Pending;
        }
        if let Some(waker) = incoming.take() {
            let retired = slot.replace(waker);
            drop(pipe);
            finish_callbacks([None, None], [retired, None]);
            return Poll::Pending;
        }
        drop(pipe);
        incoming = Some(cx.waker().clone());
        // A clone callback may have changed the peer's state. Recheck the
        // condition before parking, so its notification cannot be lost.
    }
}

/// Finish every notification and retirement, even if an arbitrary callback
/// panics. Normal calls preserve the first panic; teardown during an existing
/// unwind must not double-panic. All pipe transitions precede this function.
fn finish_callbacks(wake: [Option<Waker>; 2], retire: [Option<Waker>; 2]) {
    let unwinding = std::thread::panicking();
    let mut first_panic = None;
    for waker in wake.into_iter().flatten() {
        capture_callback_panic(&mut first_panic, || waker.wake());
    }
    for waker in retire.into_iter().flatten() {
        capture_callback_panic(&mut first_panic, || drop(waker));
    }
    if let Some(payload) = first_panic {
        if unwinding {
            std::mem::forget(payload);
        } else {
            std::panic::resume_unwind(payload);
        }
    }
}

fn capture_callback_panic(
    first: &mut Option<Box<dyn std::any::Any + Send>>,
    callback: impl FnOnce(),
) {
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(callback)) {
        if first.is_none() {
            *first = Some(payload);
        } else {
            // Even dropping an arbitrary panic payload may panic again.
            std::mem::forget(payload);
        }
    }
}

impl AsyncRead for DuplexStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        poll_pipe(&self.read, cx, Direction::Read, |pipe| pipe.try_read(buf))
    }
}

impl AsyncWrite for DuplexStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        poll_pipe(&self.write, cx, Direction::Write, |pipe| pipe.try_write(data))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let (reader, retired) = self.write.lock().close_write();
        finish_callbacks([reader, None], [retired, None]);
        Poll::Ready(Ok(()))
    }
}

impl Drop for DuplexStream {
    fn drop(&mut self) {
        // Close BOTH directions before any callback can unwind or re-enter.
        // Lock separately so simultaneous peer drops cannot invert lock order.
        let (reader, own_writer) = self.write.lock().close_write();
        let (writer, own_reader) = self.read.lock().close_read();
        finish_callbacks([reader, writer], [own_writer, own_reader]);
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

#[cfg(test)]
mod tests;
