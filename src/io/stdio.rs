//! Asynchronous handles to the process's standard input, output and error.
//!
//! The standard streams cannot be put in non-blocking mode without changing
//! them for every process that shares them, so each blocking call runs off
//! the async workers: on the runtime's blocking pool, or on a dedicated
//! thread when there is none. A read of standard input can wait
//! indefinitely, and a write can wait on a full pipe, without stalling other
//! tasks.
//!
//! - [`Stdin`] reads in chunks. A read in flight belongs to the handle, so a
//!   cancelled `read` loses no input as long as the handle is kept: the next
//!   read returns those bytes. Dropping the handle while a read waits leaves
//!   that blocking read running until input arrives, and its bytes are lost;
//!   keep one `Stdin` for the life of the program.
//! - [`Stdout`] and [`Stderr`] write behind: `write` copies the bytes and
//!   returns, and the blocking write runs in the background. The next
//!   `write`, `flush` or `shutdown` waits for it and reports its error.
//!   Bytes accepted by `write` are written even if the handle is dropped
//!   first; `flush` before exiting to know they arrived.
//!
//! Each handle orders its own operations. Separate handles to one stream do
//! not coordinate, so concurrent writers can interleave chunks, as with
//! separate `std::io::stdout()` handles.
//!
//! ```no_run
//! use asupersync::io::{AsyncWriteExt, BufReader, Lines, stdin, stdout};
//! use asupersync::stream::StreamExt;
//!
//! # async fn echo() -> std::io::Result<()> {
//! let mut lines = Lines::new(BufReader::new(stdin()));
//! let mut out = stdout();
//! while let Some(line) = lines.next().await {
//!     out.write_all(line?.to_uppercase().as_bytes()).await?;
//!     out.write_all(b"\n").await?;
//! }
//! out.flush().await
//! # }
//! ```

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

/// The most bytes one blocking read or write moves.
const CHUNK_BYTES: usize = 64 * 1024;

type Blocking<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

/// Runs `op` off the async workers: on the current runtime's blocking pool,
/// or on a dedicated thread outside a runtime or in one built without a pool.
fn off_worker<T, Op>(op: Op) -> Blocking<T>
where
    T: Send + 'static,
    Op: FnOnce() -> io::Result<T> + Send + 'static,
{
    match crate::cx::Cx::current().and_then(|cx| cx.blocking_pool_handle_for_inheritance()) {
        Some(pool) => Box::pin(crate::runtime::spawn_blocking::spawn_blocking_on_pool(
            pool, op,
        )),
        None => Box::pin(crate::runtime::spawn_blocking::spawn_blocking_on_thread(op)),
    }
}

/// An asynchronous handle to the process's standard input; see the
/// [module documentation](crate::io#in-memory-pipes-and-standard-streams).
pub struct Stdin {
    state: ReadState,
}

enum ReadState {
    Idle,
    Reading(Blocking<Vec<u8>>),
    /// Bytes read but not yet handed to a caller.
    Buffered {
        bytes: Vec<u8>,
        consumed: usize,
    },
}

/// An asynchronous handle to the process's standard input.
#[must_use]
pub fn stdin() -> Stdin {
    Stdin {
        state: ReadState::Idle,
    }
}

impl AsyncRead for Stdin {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                ReadState::Buffered { bytes, consumed } => {
                    let available = &bytes[*consumed..];
                    let take = available.len().min(buf.remaining());
                    buf.put_slice(&available[..take]);
                    *consumed += take;
                    if *consumed == bytes.len() {
                        this.state = ReadState::Idle;
                    }
                    return Poll::Ready(Ok(()));
                }
                ReadState::Idle => {
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let len = buf.remaining().min(CHUNK_BYTES);
                    this.state = ReadState::Reading(off_worker(move || {
                        let mut bytes = vec![0_u8; len];
                        let read = io::stdin().lock().read(&mut bytes)?;
                        bytes.truncate(read);
                        Ok(bytes)
                    }));
                }
                ReadState::Reading(read) => match read.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        this.state = ReadState::Idle;
                        let bytes = result?;
                        if bytes.is_empty() {
                            // End of input.
                            return Poll::Ready(Ok(()));
                        }
                        this.state = ReadState::Buffered { bytes, consumed: 0 };
                    }
                },
            }
        }
    }
}

impl std::fmt::Debug for Stdin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("Stdin { .. }")
    }
}

#[derive(Clone, Copy)]
enum Target {
    Stdout,
    Stderr,
}

/// Write-behind state shared by [`Stdout`] and [`Stderr`].
struct Writer {
    target: Target,
    state: WriteState,
}

enum WriteState {
    Idle,
    Writing(Blocking<()>),
    Flushing(Blocking<()>),
}

impl Writer {
    const fn new(target: Target) -> Self {
        Self {
            target,
            state: WriteState::Idle,
        }
    }

    /// Waits for the operation in flight, if any, and returns its result.
    fn poll_settle(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let operation = match &mut self.state {
            WriteState::Idle => return Poll::Ready(Ok(())),
            WriteState::Writing(operation) | WriteState::Flushing(operation) => operation,
        };
        let result = std::task::ready!(operation.as_mut().poll(cx));
        self.state = WriteState::Idle;
        Poll::Ready(result)
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        std::task::ready!(self.poll_settle(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = data[..data.len().min(CHUNK_BYTES)].to_vec();
        let written = chunk.len();
        let target = self.target;
        self.state = WriteState::Writing(off_worker(move || match target {
            Target::Stdout => io::stdout().lock().write_all(&chunk),
            Target::Stderr => io::stderr().lock().write_all(&chunk),
        }));
        Poll::Ready(Ok(written))
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.state {
                WriteState::Flushing(_) => return self.poll_settle(cx),
                WriteState::Writing(_) => std::task::ready!(self.poll_settle(cx))?,
                WriteState::Idle => {
                    let target = self.target;
                    self.state = WriteState::Flushing(off_worker(move || match target {
                        Target::Stdout => io::stdout().lock().flush(),
                        Target::Stderr => io::stderr().lock().flush(),
                    }));
                }
            }
        }
    }
}

macro_rules! output_handle {
    ($(#[$attr:meta])* $name:ident, $constructor:ident, $target:expr, $stream:literal) => {
        $(#[$attr])*
        pub struct $name {
            writer: Writer,
        }

        #[doc = concat!("An asynchronous handle to the process's standard ", $stream, ".")]
        #[must_use]
        pub fn $constructor() -> $name {
            $name {
                writer: Writer::new($target),
            }
        }

        impl AsyncWrite for $name {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.get_mut().writer.poll_write(cx, data)
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.get_mut().writer.poll_flush(cx)
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.get_mut().writer.poll_flush(cx)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.pad(concat!(stringify!($name), " { .. }"))
            }
        }
    };
}

output_handle!(
    /// An asynchronous handle to the process's standard output; see the
    /// [module documentation](crate::io#in-memory-pipes-and-standard-streams).
    Stdout,
    stdout,
    Target::Stdout,
    "output"
);

output_handle!(
    /// An asynchronous handle to the process's standard error; see the
    /// [module documentation](crate::io#in-memory-pipes-and-standard-streams).
    Stderr,
    stderr,
    Target::Stderr,
    "error"
);
